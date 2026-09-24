//! Session-scoped anomaly detection.
//!
//! Four rules, all rule-based and explainable (no ML):
//!
//! 1. **Size spike** — `bytes_out` exceeds a multiplier of the bounded
//!    median of prior ordinary outputs for that tool. Extreme first
//!    outputs can trip a separate warmup threshold. Outliers do not enter
//!    the baseline, and already-reported nearby size regimes are suppressed.
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
//! 3. **Rapid repeats** — `RAPID_REPEAT_COUNT` identical argument
//!    fingerprints for the same tool landed within `RAPID_REPEAT_WINDOW`.
//!    A high-cardinality burst has its own `rapid_fanout` rule with a
//!    higher threshold so ordinary agent exploration stays quiet.
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
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

/// Number of prior ordinary samples per tool before the median baseline is
/// used. An independent absolute threshold catches extreme warmup outputs.
const MIN_SAMPLES_FOR_SIZE_RULE: usize = 5;

/// How many times larger than the median baseline a `bytes_out` value has
/// to be before it flags.
const SIZE_SPIKE_MULTIPLIER: i64 = 5;
const SIZE_BOOTSTRAP_SPIKE_BYTES: i64 = 1_000_000;
const SIZE_BASELINE_CAPACITY: usize = 31;
const SIZE_BASELINE_FLOOR_BYTES: i64 = 1_024;
const SIZE_BAND_NUMERATOR: i64 = 5;
const SIZE_BAND_DENOMINATOR: i64 = 4;

/// How many calls to the same tool must land within
/// `RAPID_REPEAT_WINDOW` before rule 3 fires. Set at 5 rather than 3 so
/// an ordinary interactive burst (open a note, save, re-read, correct,
/// save again) does not trip it.
const RAPID_REPEAT_COUNT: usize = 5;

/// Time window for rule 3. Ten seconds is short enough that a human-driven
/// tool sequence never fills it and long enough that an automated loop
/// running at any interactive rate does.
const RAPID_REPEAT_WINDOW: Duration = Duration::from_secs(10);
const RAPID_FANOUT_COUNT: usize = 25;
const RAPID_EVENT_CAPACITY: usize = 256;

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

#[derive(Default)]
struct ToolStats {
    baseline: VecDeque<i64>,
    known_spike_bands: Vec<(i64, i64)>,
}

impl ToolStats {
    fn median(&self) -> Option<i64> {
        if self.baseline.len() < MIN_SAMPLES_FOR_SIZE_RULE {
            return None;
        }
        let mut values: Vec<_> = self.baseline.iter().copied().collect();
        values.sort_unstable();
        Some(values[values.len() / 2])
    }

    fn observe(&mut self, bytes: i64) -> Option<Reason> {
        if bytes < 0 {
            return None;
        }
        if self
            .known_spike_bands
            .iter()
            .any(|(low, high)| (*low..=*high).contains(&bytes))
        {
            return None;
        }

        let median = self.median();
        let bootstrap_spike = median.is_none() && bytes >= SIZE_BOOTSTRAP_SPIKE_BYTES;
        let baseline_spike = median.is_some_and(|median| {
            bytes > median.saturating_mul(SIZE_SPIKE_MULTIPLIER)
                && bytes > SIZE_BASELINE_FLOOR_BYTES
        });
        if bootstrap_spike || baseline_spike {
            let low = bytes.saturating_mul(SIZE_BAND_DENOMINATOR) / SIZE_BAND_NUMERATOR;
            let high = bytes.saturating_mul(SIZE_BAND_NUMERATOR) / SIZE_BAND_DENOMINATOR;
            self.known_spike_bands.push((low, high));
            return Some(Reason {
                rule: "size_spike",
                detail: match median {
                    Some(median) => format!(
                        "bytes_out={bytes} exceeds {SIZE_SPIKE_MULTIPLIER}× median baseline ({median} bytes) for this tool; known size band recorded"
                    ),
                    None => format!(
                        "bytes_out={bytes} exceeds the {SIZE_BOOTSTRAP_SPIKE_BYTES}-byte warmup threshold; known size band recorded"
                    ),
                },
            });
        }

        self.baseline.push_back(bytes);
        while self.baseline.len() > SIZE_BASELINE_CAPACITY {
            self.baseline.pop_front();
        }
        None
    }
}

/// Anomaly state for one session. Cheap to construct; keep one per
/// `session_id` for the lifetime of the session.
#[derive(Default)]
pub struct SessionStats {
    /// Bounded robust baseline and already-reported size regimes per tool.
    tool_stats: HashMap<String, ToolStats>,
    /// Recent argument fingerprints and timestamps per tool. Repeats count
    /// identical payloads; fan-out counts distinct payloads.
    tool_events: HashMap<String, VecDeque<(Instant, [u8; 32])>>,
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
    /// Separate cooldown for the high-cardinality fan-out rule.
    last_fanout_fire: HashMap<String, Instant>,
}

impl SessionStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a call with the stable fingerprint of its full arguments.
    /// The compatibility wrapper below treats calls without a supplied
    /// fingerprint as identical, which keeps direct rule tests concise.
    pub fn observe_with_fingerprint(
        &mut self,
        tool_name: &str,
        bytes_out: Option<i64>,
        destination: Option<&Destination>,
        fingerprint: [u8; 32],
        now: Instant,
    ) -> Option<AnomalyReport> {
        let mut reasons = Vec::new();

        if let Some(bytes) = bytes_out {
            if let Some(reason) = self
                .tool_stats
                .entry(tool_name.to_string())
                .or_default()
                .observe(bytes)
            {
                reasons.push(reason);
            }
        }

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

        let events = self.tool_events.entry(tool_name.to_string()).or_default();
        while events
            .front()
            .is_some_and(|(when, _)| now.saturating_duration_since(*when) > RAPID_REPEAT_WINDOW)
        {
            events.pop_front();
        }
        events.push_back((now, fingerprint));
        while events.len() > RAPID_EVENT_CAPACITY {
            events.pop_front();
        }

        let matching: Vec<_> = events
            .iter()
            .filter(|(_, seen)| *seen == fingerprint)
            .map(|(when, _)| *when)
            .collect();
        if matching.len() >= RAPID_REPEAT_COUNT {
            let span = now.saturating_duration_since(matching[matching.len() - RAPID_REPEAT_COUNT]);
            let cooling_down = self
                .last_rapid_fire
                .get(tool_name)
                .is_some_and(|last| now.saturating_duration_since(*last) < RAPID_REPEAT_WINDOW);
            if !cooling_down {
                reasons.push(Reason {
                    rule: "rapid_repeats",
                    detail: format!(
                        "{} identical argument payloads for {} within {:.1}s (window: {}s)",
                        RAPID_REPEAT_COUNT,
                        tool_name,
                        span.as_secs_f64(),
                        RAPID_REPEAT_WINDOW.as_secs()
                    ),
                });
                self.last_rapid_fire.insert(tool_name.to_string(), now);
            }
        }

        let distinct_count = events
            .iter()
            .map(|(_, seen)| *seen)
            .collect::<HashSet<_>>()
            .len();
        let fanout_cooling = self
            .last_fanout_fire
            .get(tool_name)
            .is_some_and(|last| now.saturating_duration_since(*last) < RAPID_REPEAT_WINDOW);
        if distinct_count >= RAPID_FANOUT_COUNT && !fanout_cooling {
            reasons.push(Reason {
                rule: "rapid_fanout",
                detail: format!(
                    "{distinct_count} distinct argument payloads for {tool_name} within {}s",
                    RAPID_REPEAT_WINDOW.as_secs()
                ),
            });
            self.last_fanout_fire.insert(tool_name.to_string(), now);
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

    #[cfg(test)]
    pub fn observe(
        &mut self,
        tool_name: &str,
        bytes_out: Option<i64>,
        destination: Option<&Destination>,
        now: Instant,
    ) -> Option<AnomalyReport> {
        self.observe_with_fingerprint(
            tool_name,
            bytes_out,
            destination,
            no_args_fingerprint(),
            now,
        )
    }
}

/// In-memory-only stable fingerprint. The raw payload never enters
/// anomaly state, and the domain prefix separates these digests from the
/// hashes used by the audit chain.
pub(crate) fn fingerprint_args(args: Option<&Value>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"auditmcp-argument-fingerprint-v1\0");
    match args {
        Some(value) => {
            hasher.update([1]);
            if let Ok(encoded) = serde_json::to_vec(value) {
                hasher.update(encoded);
            }
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

#[cfg(test)]
fn no_args_fingerprint() -> [u8; 32] {
    fingerprint_args(None)
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
            s.observe("echo", Some(1_000), None, t + Duration::from_secs(i * 60));
        }
        let r = s
            .observe("echo", Some(10_000), None, t + Duration::from_secs(600))
            .expect("expected an anomaly on the spike");
        assert_eq!(r.reasons.len(), 1);
        assert_eq!(r.reasons[0].rule, "size_spike");
    }

    #[test]
    fn early_extreme_response_is_detected_without_a_mature_baseline() {
        let mut stats = SessionStats::new();
        let t = t0();
        let first = stats
            .observe("search_strings", Some(1_720_000), None, t)
            .expect("extreme first response should trip the warmup threshold");
        assert_eq!(first.reasons[0].rule, "size_spike");
        let repeated = stats.observe(
            "search_strings",
            Some(1_730_000),
            None,
            t + Duration::from_secs(60),
        );
        assert!(repeated.is_none(), "same large regime should be suppressed");
    }

    #[test]
    fn stable_large_decompile_regime_alerts_once_and_new_magnitude_alerts_again() {
        let mut stats = SessionStats::new();
        let t = t0();
        for i in 0..5 {
            assert!(stats
                .observe(
                    "decompile_function",
                    Some(1_000),
                    None,
                    t + Duration::from_secs(i * 60)
                )
                .is_none());
        }

        let first = stats
            .observe(
                "decompile_function",
                Some(206_000),
                None,
                t + Duration::from_secs(600),
            )
            .expect("new large regime should be reported once");
        assert!(first
            .reasons
            .iter()
            .any(|reason| reason.rule == "size_spike"));

        for (i, bytes) in [210_000, 214_000, 208_000].into_iter().enumerate() {
            let report = stats.observe(
                "decompile_function",
                Some(bytes),
                None,
                t + Duration::from_secs(660 + i as u64 * 60),
            );
            assert!(
                report.is_none(),
                "stable large response fired again: {bytes}"
            );
        }

        let new_regime = stats
            .observe(
                "decompile_function",
                Some(2_000_000),
                None,
                t + Duration::from_secs(900),
            )
            .expect("a genuinely new magnitude must remain visible");
        assert!(new_regime
            .reasons
            .iter()
            .any(|reason| reason.rule == "size_spike"));
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
            Some(999_999),
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

    #[test]
    fn five_distinct_function_addresses_are_not_a_retry_loop() {
        let mut stats = SessionStats::new();
        let t = t0();
        for i in 0..5 {
            let args = serde_json::json!({ "address": format!("0x{:x}", 0x1000 + i) });
            let report = stats.observe_with_fingerprint(
                "decompile_function",
                None,
                None,
                fingerprint_args(Some(&args)),
                t + Duration::from_secs(i),
            );
            assert!(report.is_none(), "distinct address {i} was flagged");
        }
    }

    #[test]
    fn five_identical_requests_are_flagged_as_a_retry_loop() {
        let mut stats = SessionStats::new();
        let args = serde_json::json!({ "address": "0x401000" });
        let fingerprint = fingerprint_args(Some(&args));
        let t = t0();
        for i in 0..4 {
            assert!(stats
                .observe_with_fingerprint(
                    "decompile_function",
                    None,
                    None,
                    fingerprint,
                    t + Duration::from_secs(i),
                )
                .is_none());
        }
        let report = stats
            .observe_with_fingerprint(
                "decompile_function",
                None,
                None,
                fingerprint,
                t + Duration::from_secs(4),
            )
            .expect("identical retry loop should fire");
        assert!(report
            .reasons
            .iter()
            .any(|reason| reason.rule == "rapid_repeats"));
    }

    #[test]
    fn large_distinct_argument_burst_uses_rapid_fanout_rule() {
        let mut stats = SessionStats::new();
        let t = t0();
        let mut fanout_fires = 0;
        for i in 0..30 {
            let args = serde_json::json!({ "address": format!("0x{:x}", 0x1000 + i) });
            let report = stats.observe_with_fingerprint(
                "decompile_function",
                None,
                None,
                fingerprint_args(Some(&args)),
                t + Duration::from_millis(i * 100),
            );
            if let Some(report) = report {
                assert!(report
                    .reasons
                    .iter()
                    .any(|reason| reason.rule == "rapid_fanout"));
                assert!(!report
                    .reasons
                    .iter()
                    .any(|reason| reason.rule == "rapid_repeats"));
                fanout_fires += 1;
            }
        }
        assert_eq!(fanout_fires, 1);
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
        //   - size spike (10_000 vs median ~100),
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
            detail: "bytes_out=1000 exceeds 5× median baseline (100 bytes)".to_string(),
        };
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(
            json,
            r#"{"rule":"size_spike","detail":"bytes_out=1000 exceeds 5× median baseline (100 bytes)"}"#
        );
    }
}
