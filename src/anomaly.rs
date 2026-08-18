//! Session-scoped anomaly detection.
//!
//! Three rules, all rule-based and explainable (no ML), matching the
//! phased spec exactly:
//!
//! 1. **Size spike** — `bytes_out` for a tool exceeds
//!    `SIZE_SPIKE_MULTIPLIER × running_mean` for the same tool in the same
//!    session. Immune to the first `MIN_SAMPLES_FOR_SIZE_RULE - 1` calls
//!    per tool, so a session's opening samples don't flag each other.
//! 2. **Novel destination** — a **network-shaped** destination
//!    (`url`, `host`, `uri`, `target`) was never seen in this session
//!    before. Filesystem destinations are deliberately excluded: writing
//!    a new note in a note-taking session is the primary use case, so
//!    firing an anomaly on every one produces a 100% false-positive rate
//!    (verified against real vault traffic — see Phase 3 dogfood). The
//!    threat model that motivates this rule is exfiltration, which shows
//!    up as an unexpected network endpoint, not as a new file in a
//!    local vault. Also requires a non-empty prior baseline, so the very
//!    first network destination in a session establishes the set rather
//!    than firing this rule against nothing.
//! 3. **Rapid repeats** — `RAPID_REPEAT_COUNT` calls to the same tool
//!    landed within `RAPID_REPEAT_WINDOW`. Ordinary bursts of a few calls
//!    stay quiet; a chunked exfiltration or an injection loop trips it.
//!    **Fires at most once per burst.** Once the rule fires for a tool,
//!    subsequent calls to that tool inside `RAPID_REPEAT_WINDOW` are
//!    suppressed — a 24-call burst issued in one batch should surface
//!    as one flag, not twenty. When the tool goes quiet for the window
//!    and starts up again, the next burst is eligible to fire once.
//!    (Dogfood-driven: an early real-vault session tripped rule 3 on
//!    20 of 24 rows in one burst, drowning the actual signal.)
//!
//! Anomaly state is per session. There is one `SessionStats` per session
//! id, held for the lifetime of that session, and it is neither serialized
//! nor persisted — rules that mattered enough to survive a restart would
//! live in queries against the durable log, not in this in-memory
//! structure. Scoring runs at write time so a stored row is self-describing
//! and `query --anomalous` reduces to a `WHERE` clause, but a scoring
//! failure has no way to invalidate the row (the caller stores `None`
//! rather than blocking the audit): fail-open, same contract as everything
//! else in this pipeline.

use crate::extract::{Destination, DestinationKind};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Number of prior samples per tool before rule 1 (size spike) is armed.
/// Below this, the running mean is too noisy to anchor a multiplier —
/// samples 2 and 3 of a series are frequently 5× sample 1 for perfectly
/// ordinary reasons, and firing on those is pure noise.
const MIN_SAMPLES_FOR_SIZE_RULE: u64 = 5;

/// How many times larger than the running mean a `bytes_out` value has to
/// be before it flags. Not a stddev-based rule on purpose: bytes_out
/// distributions for real MCP tools are heavy-tailed enough that a
/// 3-sigma threshold either fires constantly (small-mean tools) or never
/// (large-mean tools). A simple multiplier is coarser but more predictable.
const SIZE_SPIKE_MULTIPLIER: f64 = 5.0;

/// How many calls to the same tool must land within
/// `RAPID_REPEAT_WINDOW` before rule 3 fires. Set at 5 rather than 3 so
/// an ordinary interactive burst (open a note, save, re-read, correct,
/// save again) does not trip it.
const RAPID_REPEAT_COUNT: usize = 5;

/// Time window for rule 3. Ten seconds is short enough that a human-driven
/// tool sequence never fills it and long enough that an automated loop
/// running at any interactive rate does.
const RAPID_REPEAT_WINDOW: Duration = Duration::from_secs(10);

/// One rule firing. Stored as a JSON array in the row's `anomaly_reasons`
/// column so `query --anomalous` can show *why* a row was flagged, not
/// just that it was.
#[derive(Debug, Serialize, PartialEq)]
pub struct Reason {
    pub rule: &'static str,
    pub detail: String,
}

/// The score plus the fired reasons for one observed call. Absent when
/// no rule fired — the caller writes `NULL` into both the score and
/// reasons columns, so `WHERE anomaly_score IS NOT NULL` selects exactly
/// the anomalous rows.
#[derive(Debug)]
pub struct AnomalyReport {
    pub score: f64,
    pub reasons: Vec<Reason>,
}

/// Welford's running mean + `M2` (sum of squared deviations from the
/// running mean). `M2` isn't read by rule 1 today, but keeping it makes a
/// future stddev-based refinement free and costs one f64 per tool.
#[derive(Default)]
struct ToolStats {
    count: u64,
    mean: f64,
    m2: f64,
}

impl ToolStats {
    fn observe(&mut self, x: f64) {
        self.count += 1;
        let delta = x - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = x - self.mean;
        self.m2 += delta * delta2;
    }
}

/// Anomaly state for one session. Cheap to construct; keep one per
/// `session_id` for the lifetime of the session.
#[derive(Default)]
pub struct SessionStats {
    /// Running (count, mean, M2) per tool. Rule 1 reads `count` and
    /// `mean`.
    tool_stats: HashMap<String, ToolStats>,
    /// The last few call timestamps per tool. Rule 3 checks whether the
    /// oldest of the last `RAPID_REPEAT_COUNT` sits inside
    /// `RAPID_REPEAT_WINDOW`.
    tool_timestamps: HashMap<String, VecDeque<Instant>>,
    /// Every **network-shaped** destination this session has seen. Rule 2
    /// flags a network destination not in this set (once the set is
    /// non-empty). Filesystem destinations are never inserted or checked
    /// here — they'd be pure noise for this rule.
    seen_network_destinations: HashSet<String>,
    /// Per-tool timestamp of the last time rule 3 fired. Enforces a
    /// per-tool cooldown of `RAPID_REPEAT_WINDOW` so one burst surfaces
    /// as one flag rather than one per call from the fifth onward. Not
    /// updated on suppressed events, so a still-hot burst can't extend
    /// its own cooldown indefinitely.
    last_rapid_fire: HashMap<String, Instant>,
}

impl SessionStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records one completed tool call and reports which rules it tripped.
    ///
    /// `now` is threaded through rather than read from `Instant::now()`
    /// inside so tests can drive time deterministically and so callers
    /// that already have a timestamp (the audit path has one) don't
    /// double-source it. `destination` is what the audit path pulled from
    /// `extract::destination_from_args`, kind and all; `None` means the
    /// tool had no destination to record, not that it had a destination
    /// equal to empty-string.
    pub fn observe(
        &mut self,
        tool_name: &str,
        bytes_out: Option<i64>,
        destination: Option<&Destination>,
        now: Instant,
    ) -> Option<AnomalyReport> {
        let mut reasons = Vec::new();

        // Rule 1: size spike. Check BEFORE updating stats so the current
        // sample is compared against the baseline that predates it — else
        // the sample partly cancels its own outlier-ness.
        if let Some(bytes) = bytes_out {
            if let Some(stats) = self.tool_stats.get(tool_name) {
                if stats.count >= MIN_SAMPLES_FOR_SIZE_RULE
                    && (bytes as f64) > SIZE_SPIKE_MULTIPLIER * stats.mean
                {
                    reasons.push(Reason {
                        rule: "size_spike",
                        detail: format!(
                            "bytes_out={} exceeds {}× running mean ({:.0}) over {} prior calls to {}",
                            bytes, SIZE_SPIKE_MULTIPLIER as u64, stats.mean, stats.count, tool_name
                        ),
                    });
                }
            }
        }

        // Rule 2: novel network destination. Filesystem destinations
        // never reach the baseline set and never fire (see the module
        // doc); network destinations do. Checked BEFORE the insert below,
        // so we can tell "this destination is new" from "this destination
        // is the one we just recorded." Skipped on the empty-baseline
        // case: the first network destination in a session establishes
        // the set rather than flagging against nothing.
        if let Some(dest) = destination {
            if dest.kind == DestinationKind::Network
                && !self.seen_network_destinations.is_empty()
                && !self.seen_network_destinations.contains(&dest.value)
            {
                reasons.push(Reason {
                    rule: "novel_destination",
                    detail: format!(
                        "network destination '{}' not seen in this session ({} prior distinct network destinations)",
                        dest.value,
                        self.seen_network_destinations.len()
                    ),
                });
            }
        }

        // Rule 3: rapid repeats. Push, trim to the last N, then check
        // whether the whole ring fits in the window and the tool isn't
        // still cooling down from a previous fire.
        let ring = self
            .tool_timestamps
            .entry(tool_name.to_string())
            .or_default();
        ring.push_back(now);
        while ring.len() > RAPID_REPEAT_COUNT {
            ring.pop_front();
        }
        if ring.len() == RAPID_REPEAT_COUNT {
            let span = now.saturating_duration_since(*ring.front().unwrap());
            if span <= RAPID_REPEAT_WINDOW {
                // Suppress if we already fired for this tool inside the
                // cooldown window. `last_rapid_fire` is only updated on
                // an actual fire, so a hot burst can't extend its own
                // cooldown by triggering the check repeatedly.
                let cooling_down = self
                    .last_rapid_fire
                    .get(tool_name)
                    .is_some_and(|last| now.saturating_duration_since(*last) < RAPID_REPEAT_WINDOW);
                if !cooling_down {
                    reasons.push(Reason {
                        rule: "rapid_repeats",
                        detail: format!(
                            "{} calls to {} within {:.1}s (window: {}s)",
                            RAPID_REPEAT_COUNT,
                            tool_name,
                            span.as_secs_f64(),
                            RAPID_REPEAT_WINDOW.as_secs()
                        ),
                    });
                    self.last_rapid_fire.insert(tool_name.to_string(), now);
                }
            }
        }

        // Now update the rest of the state: size baseline gets this
        // sample, destination set gets this destination. Ring buffer was
        // already updated above (rule 3 needs to include the current
        // call).
        if let Some(bytes) = bytes_out {
            self.tool_stats
                .entry(tool_name.to_string())
                .or_default()
                .observe(bytes as f64);
        }
        if let Some(dest) = destination {
            if dest.kind == DestinationKind::Network {
                self.seen_network_destinations.insert(dest.value.clone());
            }
        }

        if reasons.is_empty() {
            None
        } else {
            Some(AnomalyReport {
                score: reasons.len() as f64,
                reasons,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    fn net(s: &str) -> Destination {
        Destination {
            value: s.to_string(),
            kind: DestinationKind::Network,
        }
    }

    fn fs(s: &str) -> Destination {
        Destination {
            value: s.to_string(),
            kind: DestinationKind::Filesystem,
        }
    }

    /// A steady baseline that never varies has no anomalies to report.
    #[test]
    fn steady_baseline_never_fires() {
        let mut s = SessionStats::new();
        let t = t0();
        for i in 0..10 {
            let r = s.observe("echo", Some(100), None, t + Duration::from_secs(i * 60));
            assert!(r.is_none(), "call {i} unexpectedly flagged");
        }
    }

    /// A 10× spike after the baseline is armed does fire size_spike. The
    /// baseline (5 calls at 100 bytes) is the minimum sample count.
    #[test]
    fn size_spike_fires_after_baseline_is_armed() {
        let mut s = SessionStats::new();
        let t = t0();
        for i in 0..5 {
            s.observe("echo", Some(100), None, t + Duration::from_secs(i * 60));
        }
        let r = s
            .observe("echo", Some(1000), None, t + Duration::from_secs(600))
            .expect("expected an anomaly on the spike");
        assert_eq!(r.reasons.len(), 1);
        assert_eq!(r.reasons[0].rule, "size_spike");
    }

    /// The pre-armed calls are immune even if each one looks wildly
    /// different from its predecessor: sample 2 is 10× sample 1 for
    /// perfectly ordinary reasons.
    #[test]
    fn first_calls_are_immune_to_the_size_rule() {
        let mut s = SessionStats::new();
        let t = t0();
        // Alternate 10 and 1000 for four samples. Every sample after the
        // first would look like a spike if the rule armed early.
        for (i, bytes) in [10, 1000, 10, 1000].iter().enumerate() {
            let r = s.observe(
                "echo",
                Some(*bytes),
                None,
                t + Duration::from_secs(i as u64 * 60),
            );
            assert!(
                r.is_none(),
                "sample {i} ({bytes} bytes) flagged before rule armed"
            );
        }
    }

    /// Different tools have independent baselines. A first call to a new
    /// tool cannot be a spike, no matter its size, because its baseline is
    /// empty.
    #[test]
    fn tools_have_independent_baselines() {
        let mut s = SessionStats::new();
        let t = t0();
        for i in 0..5 {
            s.observe("echo", Some(100), None, t + Duration::from_secs(i * 60));
        }
        // Now `write_note` sees its first-ever call at a huge size.
        let r = s.observe(
            "write_note",
            Some(1_000_000),
            None,
            t + Duration::from_secs(600),
        );
        assert!(r.is_none(), "new tool's first call was flagged as a spike");
    }

    /// The very first network destination in a session establishes the
    /// baseline rather than firing against an empty set. If the *first*
    /// call were flagged, every session would flag its first call and
    /// the rule would carry no signal.
    #[test]
    fn first_network_destination_in_a_session_does_not_fire() {
        let mut s = SessionStats::new();
        let r = s.observe("http_fetch", None, Some(&net("https://a.test")), t0());
        assert!(r.is_none());
    }

    /// A second, different network destination in the same session fires.
    #[test]
    fn second_distinct_network_destination_fires_novel_destination() {
        let mut s = SessionStats::new();
        let t = t0();
        s.observe("http_fetch", None, Some(&net("https://a.test")), t);
        let r = s
            .observe(
                "http_fetch",
                None,
                Some(&net("https://b.test")),
                t + Duration::from_secs(60),
            )
            .expect("expected novel_destination");
        assert_eq!(r.reasons.len(), 1);
        assert_eq!(r.reasons[0].rule, "novel_destination");
    }

    /// The dogfood-driven fix: writing 24 new notes with novel paths is
    /// ordinary use of a file-oriented tool. Filesystem destinations must
    /// never fire Rule 2, even when every single one is unique.
    #[test]
    fn filesystem_destinations_never_fire_novel_destination() {
        let mut s = SessionStats::new();
        let t = t0();
        for i in 0..24 {
            let path = format!("notes/n{i}.md");
            let r = s.observe(
                "write_note",
                None,
                Some(&fs(&path)),
                t + Duration::from_secs(i * 30),
            );
            assert!(
                r.is_none(),
                "novel filesystem path {path} incorrectly fired Rule 2"
            );
        }
    }

    /// Filesystem destinations also don't *arm* the baseline for network
    /// ones: an all-filesystem session followed by one network destination
    /// still treats the network destination as first-of-its-kind, not novel.
    #[test]
    fn filesystem_destinations_do_not_arm_the_network_baseline() {
        let mut s = SessionStats::new();
        let t = t0();
        for i in 0..5 {
            s.observe(
                "write_note",
                None,
                Some(&fs(&format!("n{i}.md"))),
                t + Duration::from_secs(i),
            );
        }
        let r = s.observe(
            "http_fetch",
            None,
            Some(&net("https://a.test")),
            t + Duration::from_secs(60),
        );
        assert!(
            r.is_none(),
            "first network destination fired against a filesystem-only baseline"
        );
    }

    /// A network destination the session has already seen is not novel,
    /// even the tenth time.
    #[test]
    fn seen_network_destination_does_not_fire_again() {
        let mut s = SessionStats::new();
        let t = t0();
        s.observe("http_fetch", None, Some(&net("https://a.test")), t);
        for i in 1..10 {
            let r = s.observe(
                "http_fetch",
                None,
                Some(&net("https://a.test")),
                t + Duration::from_secs(i * 60),
            );
            assert!(
                r.is_none(),
                "repeat call {i} to the same network destination flagged"
            );
        }
    }

    /// A `None` destination is silent about rule 2 — it doesn't establish
    /// a baseline and it can't be flagged as novel.
    #[test]
    fn none_destination_neither_arms_nor_fires_rule_2() {
        let mut s = SessionStats::new();
        let t = t0();
        s.observe("echo", None, None, t);
        // The baseline is still empty, so a later network destination is not novel.
        let r = s.observe(
            "echo",
            None,
            Some(&net("first")),
            t + Duration::from_secs(60),
        );
        assert!(
            r.is_none(),
            "None destination arm-ed the baseline it shouldn't have"
        );
    }

    /// Five calls to the same tool inside the window fire rapid_repeats
    /// on the fifth. The first four don't have enough history yet.
    #[test]
    fn rapid_repeats_fires_on_the_fifth_call_in_window() {
        let mut s = SessionStats::new();
        let t = t0();
        // Calls at t, t+1s, t+2s, t+3s: none should fire (only 4 in ring).
        for i in 0..4 {
            let r = s.observe("echo", None, None, t + Duration::from_secs(i));
            assert!(r.is_none(), "call {i} in a 4-call burst flagged");
        }
        // Fifth call at t+4s, all five in ring, span = 4s ≤ 10s → fires.
        let r = s
            .observe("echo", None, None, t + Duration::from_secs(4))
            .expect("expected rapid_repeats on the fifth call");
        assert_eq!(r.reasons.len(), 1);
        assert_eq!(r.reasons[0].rule, "rapid_repeats");
    }

    /// The dogfood-driven cooldown: a single 24-call burst produces
    /// exactly one flag, not twenty. Calls 5 through 24 all satisfy
    /// "last 5 within 10s," but the cooldown suppresses everything after
    /// the first fire.
    #[test]
    fn rapid_repeats_only_fires_once_per_burst() {
        let mut s = SessionStats::new();
        let t = t0();
        let mut fire_count = 0;
        for i in 0..24 {
            // 24 calls spread over 8s (~300ms apart), well inside the
            // 10s window from call 5 onward.
            let call_t = t + Duration::from_millis(i * 350);
            if let Some(r) = s.observe("read_note", None, None, call_t) {
                assert_eq!(r.reasons.len(), 1, "expected only rapid_repeats");
                assert_eq!(r.reasons[0].rule, "rapid_repeats");
                fire_count += 1;
            }
        }
        assert_eq!(
            fire_count, 1,
            "one 24-call burst should surface as exactly one flag"
        );
    }

    /// After the cooldown expires and a fresh burst starts, the rule
    /// fires again. This is the "still-a-useful-alarm" side of the
    /// cooldown — one burst, one flag; two bursts, two flags.
    #[test]
    fn rapid_repeats_fires_on_a_second_burst_after_cooldown() {
        let mut s = SessionStats::new();
        let t = t0();
        // First burst at t..t+4s → fires once at t+4s.
        for i in 0..5 {
            s.observe("read_note", None, None, t + Duration::from_secs(i));
        }
        // Long gap, then a second burst at t+30s..t+34s.
        // The cooldown started at t+4s; by t+30s it's 26s > 10s, expired.
        // The ring is refilled by the new burst.
        let mut fire_count = 0;
        for i in 0..5 {
            if s.observe("read_note", None, None, t + Duration::from_secs(30 + i))
                .is_some()
            {
                fire_count += 1;
            }
        }
        assert_eq!(
            fire_count, 1,
            "a second burst after cooldown should fire once"
        );
    }

    /// Cooldown is per-tool: one burst on tool A doesn't suppress a
    /// simultaneous burst on tool B. Otherwise a compromised agent could
    /// hide one tool's burst behind another's alert.
    #[test]
    fn rapid_repeats_cooldown_is_per_tool() {
        let mut s = SessionStats::new();
        let t = t0();
        // Fill tool A's burst so it fires.
        for i in 0..5 {
            s.observe("read_note", None, None, t + Duration::from_millis(i * 200));
        }
        // Immediately fill tool B's burst inside A's cooldown window.
        let mut b_fires = 0;
        for i in 0..5 {
            if s.observe(
                "search_notes",
                None,
                None,
                t + Duration::from_millis(1500 + i * 200),
            )
            .is_some()
            {
                b_fires += 1;
            }
        }
        assert_eq!(
            b_fires, 1,
            "tool B's burst must not be masked by A's cooldown"
        );
    }

    /// Five calls spread across a window wider than 10s do not fire —
    /// steady-state usage of a tool at a slower cadence shouldn't trip it.
    #[test]
    fn calls_outside_the_window_do_not_fire_rapid_repeats() {
        let mut s = SessionStats::new();
        let t = t0();
        for i in 0..5 {
            let r = s.observe("echo", None, None, t + Duration::from_secs(i * 30));
            assert!(r.is_none(), "call {i} in a slow sequence flagged");
        }
    }

    /// After a burst that fires, waiting long enough clears the alert —
    /// the ring's oldest timestamp is now older than the window.
    #[test]
    fn rapid_repeats_resets_after_the_window_passes() {
        let mut s = SessionStats::new();
        let t = t0();
        // Burst of 5 in 4s → fires on the 5th.
        for i in 0..5 {
            s.observe("echo", None, None, t + Duration::from_secs(i));
        }
        // Then wait 60s and call once more. The ring still holds the last
        // 5 timestamps (t+1s through t+60s); the oldest is t+1s, span is
        // 59s, well past the window.
        let r = s.observe("echo", None, None, t + Duration::from_secs(60));
        assert!(r.is_none(), "post-window call flagged as rapid_repeats");
    }

    /// All three rules firing on one call: score = 3.0, three reasons.
    /// Uses network destinations (a hypothetical http_fetch tool),
    /// because Rule 2 now only fires on those. Also has to arm the size
    /// baseline slowly (so the ring buffer clears) — since rule 3's
    /// cooldown, only the *first* burst can fire, so a fast arm-then-
    /// trigger would spend the fire on the arming and leave the trigger
    /// call cooling down.
    #[test]
    fn score_is_the_number_of_fired_reasons() {
        let mut s = SessionStats::new();
        let t = t0();
        // Arm the size baseline at 100 bytes over 5 SLOW calls (60s
        // apart) so the ring buffer clears out between them: rule 3
        // shouldn't fire during arming, or its cooldown suppresses the
        // real trigger below.
        for i in 0..5 {
            s.observe(
                "http_fetch",
                Some(100),
                Some(&net("https://baseline.test")),
                t + Duration::from_secs(i as u64 * 60),
            );
        }
        // Four quick calls to refill the ring right before the trigger —
        // still under the 5-in-10s threshold, so no fire yet.
        let base = t + Duration::from_secs(600);
        for i in 0..4 {
            s.observe(
                "http_fetch",
                Some(100),
                Some(&net("https://baseline.test")),
                base + Duration::from_secs(i),
            );
        }
        // The trigger — 5th quick call, all three rules qualify:
        //   - size spike (10_000 vs mean ~100),
        //   - novel network destination (distinct from baseline),
        //   - rapid_repeats (5 calls in ~4s, cooldown clear).
        let r = s
            .observe(
                "http_fetch",
                Some(10_000),
                Some(&net("https://exfil.test")),
                base + Duration::from_secs(4),
            )
            .expect("all three rules should have fired");
        assert_eq!(r.reasons.len(), 3, "reasons: {:?}", r.reasons);
        assert_eq!(r.score, 3.0);
        let rules: Vec<&str> = r.reasons.iter().map(|x| x.rule).collect();
        assert!(rules.contains(&"size_spike"));
        assert!(rules.contains(&"novel_destination"));
        assert!(rules.contains(&"rapid_repeats"));
    }

    /// Reasons serialize to a stable, compact JSON shape. This is what
    /// `query --anomalous` and future external analysis parse; the shape
    /// is part of the contract, not an internal detail.
    #[test]
    fn reasons_serialize_to_documented_json_shape() {
        let r = Reason {
            rule: "size_spike",
            detail: "bytes_out=1000 exceeds 5× mean".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(
            json,
            r#"{"rule":"size_spike","detail":"bytes_out=1000 exceeds 5× mean"}"#
        );
    }
}
