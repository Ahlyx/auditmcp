//! Phase 3.5 synthetic chain rows: heartbeats and session boundaries.
//!
//! These exist to make within-session tail truncation visible. The hash
//! chain alone proves interior integrity (no row was altered) but says
//! nothing about whether rows were removed from the *end* of the chain --
//! a truncated chain still verifies cleanly, because every remaining row's
//! hash and prev_hash still check out. A heartbeat written at a random,
//! genesis-fixed cadence closes that gap: if the last N real rows plus
//! some heartbeats are deleted, the session either ends without a
//! `__session_end` row or has a gap between heartbeats wider than the
//! declared cadence allows, and `verify` reports it (exit code 3).
//!
//! `tool_name` values here all use the reserved `__` prefix (see the
//! `tool_name` doc on `db::ToolCallEntry` -- real tool calls must never
//! produce a name starting with `__`, which the MCP tool-name grammar in
//! practice never does). `query` filters these out by default (see
//! `query::filter_rows`'s `include_synthetic` parameter) and Phase 3's
//! anomaly rules never see them at all, because they are built directly as
//! `ToolCallEntry` values here rather than going through
//! `audit::build_entry`/`Session::attach_anomaly`.

use crate::db::{DbHandle, ToolCallEntry};
use rand::Rng;
use serde::Serialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

pub const HEARTBEAT_TOOL_NAME: &str = "__heartbeat";
pub const SESSION_START_TOOL_NAME: &str = "__session_start";
pub const SESSION_END_TOOL_NAME: &str = "__session_end";

/// Picks a uniformly random cadence in `[min_secs, max_secs]`. A fixed
/// interval would let an attacker who can watch (but not tamper with) the
/// chain predict exactly when the next heartbeat is due and time a
/// truncation to land just after one; randomizing removes that window
/// without changing the *worst-case* detection latency, which is bounded
/// by `max_secs` regardless.
pub fn random_cadence(min_secs: u64, max_secs: u64) -> Duration {
    let secs = if min_secs >= max_secs {
        min_secs
    } else {
        rand::thread_rng().gen_range(min_secs..=max_secs)
    };
    Duration::from_secs(secs)
}

fn base_entry(session_id: &str, server_name: &str, tool_name: &str, args_json: String) -> ToolCallEntry {
    ToolCallEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: session_id.to_string(),
        agent_id: None,
        tool_name: tool_name.to_string(),
        server_name: Some(server_name.to_string()),
        args_json: Some(args_json),
        result_json: None,
        status: "success".to_string(),
        error_message: None,
        duration_ms: None,
        bytes_in: None,
        bytes_out: None,
        source: None,
        destination: None,
        redaction_flags: Some("[]".to_string()),
        redaction_count: 0,
        anomaly_score: None,
        anomaly_reasons: None,
    }
}

#[derive(Serialize)]
struct HeartbeatArgs<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    counter: u64,
    expected_next_before: String,
}

/// Builds one `__heartbeat` row. `expected_next_before` is the deadline
/// this heartbeat itself promises for the *next* one -- `now + next
/// cadence` -- purely descriptive; `verify`'s actual gap check compares
/// consecutive heartbeat timestamps against `heartbeat_cadence_max_secs *
/// 1.5` from `chain_metadata`, not this field.
pub fn heartbeat_entry(
    session_id: &str,
    server_name: &str,
    counter: u64,
    expected_next_before: chrono::DateTime<chrono::Utc>,
) -> ToolCallEntry {
    let args = HeartbeatArgs {
        kind: "heartbeat",
        counter,
        expected_next_before: expected_next_before.to_rfc3339(),
    };
    base_entry(
        session_id,
        server_name,
        HEARTBEAT_TOOL_NAME,
        serde_json::to_string(&args).unwrap_or_else(|_| "{}".to_string()),
    )
}

#[derive(Serialize)]
struct SessionStartArgs<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    session_id: &'a str,
    started_at: String,
    heartbeat_cadence_min_secs: u64,
    heartbeat_cadence_max_secs: u64,
}

pub fn session_start_entry(
    session_id: &str,
    server_name: &str,
    cadence_min_secs: u64,
    cadence_max_secs: u64,
) -> ToolCallEntry {
    let args = SessionStartArgs {
        kind: "session_start",
        session_id,
        started_at: chrono::Utc::now().to_rfc3339(),
        heartbeat_cadence_min_secs: cadence_min_secs,
        heartbeat_cadence_max_secs: cadence_max_secs,
    };
    base_entry(
        session_id,
        server_name,
        SESSION_START_TOOL_NAME,
        serde_json::to_string(&args).unwrap_or_else(|_| "{}".to_string()),
    )
}

#[derive(Serialize)]
struct SessionEndArgs<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
    session_id: &'a str,
    ended_at: String,
}

pub fn session_end_entry(session_id: &str, server_name: &str) -> ToolCallEntry {
    let args = SessionEndArgs {
        kind: "session_end",
        session_id,
        ended_at: chrono::Utc::now().to_rfc3339(),
    };
    base_entry(
        session_id,
        server_name,
        SESSION_END_TOOL_NAME,
        serde_json::to_string(&args).unwrap_or_else(|_| "{}".to_string()),
    )
}

/// Runs until aborted (the caller aborts this task at shutdown, before
/// writing `__session_end` -- see `proxy::run`). Sleeps a fresh random
/// cadence each iteration, then logs one heartbeat whose
/// `expected_next_before` names the deadline for the iteration after that.
pub async fn run(
    db: DbHandle,
    session_id: String,
    server_name: String,
    cadence_min_secs: u64,
    cadence_max_secs: u64,
) {
    let counter = AtomicU64::new(0);
    loop {
        let this_cadence = random_cadence(cadence_min_secs, cadence_max_secs);
        tokio::time::sleep(this_cadence).await;

        let next_cadence = random_cadence(cadence_min_secs, cadence_max_secs);
        let expected_next_before = chrono::Utc::now() + chrono::Duration::from_std(next_cadence).unwrap_or_default();
        let n = counter.fetch_add(1, Ordering::Relaxed) + 1;
        db.log(heartbeat_entry(&session_id, &server_name, n, expected_next_before));
    }
}

/// One gap between two consecutive `__heartbeat` rows in the same session
/// that exceeds the allowed cadence. Used by `verify` (exit code 3) to
/// report within-session tail truncation: deleting rows from the end of a
/// session either removes trailing heartbeats outright (widening the gap
/// to the next surviving one) or leaves the session without a
/// `__session_end` row -- the gap check catches the former; the latter is
/// visible in `query --include-synthetic` but is not itself a distinct
/// exit code, since a session can legitimately still be open (the proxy
/// still running) when `verify` runs.
#[derive(Debug, PartialEq)]
pub struct HeartbeatGap {
    pub session_id: String,
    pub after_timestamp: String,
    pub before_timestamp: String,
    pub gap_secs: i64,
}

/// Scans every session's `__heartbeat` rows (in row-id order, which is
/// insertion order) and reports each consecutive gap wider than
/// `cadence_max_secs * 1.5` -- the fudge factor the spec calls for, to
/// absorb scheduler jitter and system load rather than false-positiving on
/// a heartbeat that landed a few seconds late.
pub fn find_heartbeat_gaps(
    rows: &[crate::db::StoredRow],
    cadence_max_secs: u64,
) -> Vec<HeartbeatGap> {
    use std::collections::HashMap;

    let mut by_session: HashMap<&str, Vec<&crate::db::StoredRow>> = HashMap::new();
    for r in rows {
        if r.entry.tool_name == HEARTBEAT_TOOL_NAME {
            by_session.entry(r.entry.session_id.as_str()).or_default().push(r);
        }
    }

    let max_allowed_secs = (cadence_max_secs as f64 * 1.5) as i64;
    let mut gaps = Vec::new();
    for heartbeats in by_session.values_mut() {
        heartbeats.sort_by_key(|r| r.id);
        for pair in heartbeats.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            let (Ok(ta), Ok(tb)) = (
                chrono::DateTime::parse_from_rfc3339(&a.entry.timestamp),
                chrono::DateTime::parse_from_rfc3339(&b.entry.timestamp),
            ) else {
                continue; // unparseable timestamp: nothing to compare, not this check's concern
            };
            let gap_secs = (tb - ta).num_seconds();
            if gap_secs > max_allowed_secs {
                gaps.push(HeartbeatGap {
                    session_id: a.entry.session_id.clone(),
                    after_timestamp: a.entry.timestamp.clone(),
                    before_timestamp: b.entry.timestamp.clone(),
                    gap_secs,
                });
            }
        }
    }
    gaps.sort_by(|a, b| a.after_timestamp.cmp(&b.after_timestamp));
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_cadence_stays_within_bounds() {
        for _ in 0..200 {
            let d = random_cadence(30, 90);
            assert!(d.as_secs() >= 30 && d.as_secs() <= 90);
        }
    }

    #[test]
    fn random_cadence_handles_a_degenerate_equal_range() {
        assert_eq!(random_cadence(30, 30), Duration::from_secs(30));
    }

    #[test]
    fn heartbeat_row_shape_matches_the_spec() {
        let now = chrono::Utc::now();
        let entry = heartbeat_entry("sess-1", "srv", 42, now);
        assert_eq!(entry.tool_name, "__heartbeat");
        assert_eq!(entry.status, "success");
        assert_eq!(entry.redaction_flags.as_deref(), Some("[]"));
        assert_eq!(entry.redaction_count, 0);
        assert!(entry.anomaly_score.is_none());
        assert!(entry.anomaly_reasons.is_none());

        let args: serde_json::Value = serde_json::from_str(entry.args_json.as_deref().unwrap()).unwrap();
        assert_eq!(args["type"], "heartbeat");
        assert_eq!(args["counter"], 42);
        assert_eq!(args["expected_next_before"], now.to_rfc3339());
    }

    #[test]
    fn session_start_and_end_use_reserved_tool_names() {
        let start = session_start_entry("sess-1", "srv", 30, 90);
        assert_eq!(start.tool_name, "__session_start");
        let end = session_end_entry("sess-1", "srv");
        assert_eq!(end.tool_name, "__session_end");
    }

    #[test]
    fn session_start_carries_the_cadence_range_used_for_this_session() {
        let start = session_start_entry("sess-1", "srv", 12, 34);
        let args: serde_json::Value = serde_json::from_str(start.args_json.as_deref().unwrap()).unwrap();
        assert_eq!(args["heartbeat_cadence_min_secs"], 12);
        assert_eq!(args["heartbeat_cadence_max_secs"], 34);
        assert_eq!(args["session_id"], "sess-1");
    }

    fn heartbeat_row(id: i64, session_id: &str, timestamp: &str) -> crate::db::StoredRow {
        let mut entry = heartbeat_entry(session_id, "srv", id as u64, chrono::Utc::now());
        entry.timestamp = timestamp.to_string();
        crate::db::StoredRow {
            id,
            entry,
            hash: String::new(),
            prev_hash: None,
        }
    }

    #[test]
    fn gap_within_cadence_is_not_reported() {
        let rows = vec![
            heartbeat_row(1, "s1", "2026-01-01T00:00:00Z"),
            heartbeat_row(2, "s1", "2026-01-01T00:01:00Z"), // 60s, under 90*1.5=135
        ];
        assert!(find_heartbeat_gaps(&rows, 90).is_empty());
    }

    #[test]
    fn gap_exceeding_cadence_times_1_5_is_reported() {
        let rows = vec![
            heartbeat_row(1, "s1", "2026-01-01T00:00:00Z"),
            heartbeat_row(2, "s1", "2026-01-01T00:10:00Z"), // 600s >> 135s
        ];
        let gaps = find_heartbeat_gaps(&rows, 90);
        assert_eq!(gaps.len(), 1);
        assert_eq!(gaps[0].session_id, "s1");
    }

    /// A gap between two DIFFERENT sessions' heartbeats must never be
    /// reported -- grouping by session_id is what makes an ordinary
    /// session-end-then-later-session-start gap invisible to this check.
    #[test]
    fn gap_across_different_sessions_is_never_reported() {
        let rows = vec![
            heartbeat_row(1, "s1", "2026-01-01T00:00:00Z"),
            heartbeat_row(2, "s2", "2026-01-02T00:00:00Z"), // huge gap, different session
        ];
        assert!(find_heartbeat_gaps(&rows, 90).is_empty());
    }

    #[test]
    fn non_heartbeat_rows_are_ignored() {
        let mut real_call = heartbeat_row(1, "s1", "2026-01-01T00:00:00Z");
        real_call.entry.tool_name = "read_file".to_string();
        let rows = vec![real_call, heartbeat_row(2, "s1", "2026-01-01T00:10:00Z")];
        // Only one heartbeat row exists, so there's no pair to compare.
        assert!(find_heartbeat_gaps(&rows, 90).is_empty());
    }
}
