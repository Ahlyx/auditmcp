//! Append-only recovery for sessions with reliable OS-lease evidence.
//!
//! Missing `__session_end`, heartbeat age, and later session starts are not
//! death evidence. A session is eligible only when its `__session_start`
//! contains a lease ID written by this version and a later process can
//! acquire that exact session's exclusive OS lock.

use crate::db::{self, DbHandle};
use crate::heartbeat;
use crate::lease::SessionLease;
use rusqlite::{params, OptionalExtension};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

const RECOVERY_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
struct StartArgs {
    started_at: Option<String>,
    liveness: Option<LivenessArgs>,
}

#[derive(Deserialize)]
struct LivenessArgs {
    mechanism: String,
    lease_id: String,
}

struct Candidate {
    session_id: String,
    lease_id: String,
}

struct SessionState {
    server_name: Option<String>,
    started_at: String,
    last_known_alive_at: String,
    has_clean_end: bool,
    has_abandonment: bool,
    lease_matches: bool,
}

/// Scans only lifecycle rows and appends one recovery marker for each
/// eligible session whose exact OS lease is no longer held. The lease stays
/// locked until the writer confirms the marker's SQLite transaction
/// committed, making recovery idempotent across concurrent starters.
pub(crate) fn recover_abandoned(db_path: &Path, db: &DbHandle) -> anyhow::Result<usize> {
    let candidates = candidates(db_path)?;
    let mut recovered = 0;

    for candidate in candidates {
        let lease = match SessionLease::try_recover(db_path, &candidate.lease_id) {
            Ok(Some(lease)) => lease,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(
                    session_id = %candidate.session_id,
                    "could not establish session liveness; leaving session unknown: {error}"
                );
                continue;
            }
        };

        // Read again only after obtaining the session-specific lock. A
        // concurrent process may have cleanly ended or recovered this
        // session while this process was scanning the lifecycle rows.
        let state = match session_state(db_path, &candidate.session_id, &candidate.lease_id) {
            Ok(Some(state)) => state,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(
                    session_id = %candidate.session_id,
                    "could not recheck session lifecycle; leaving session unknown: {error}"
                );
                continue;
            }
        };
        if state.has_clean_end || state.has_abandonment || !state.lease_matches {
            continue;
        }

        let detected_at = chrono::Utc::now();
        let entry = heartbeat::session_abandoned_entry(
            &candidate.session_id,
            state.server_name.as_deref(),
            &state.started_at,
            &state.last_known_alive_at,
            detected_at,
            lease.id(),
        );
        match db.log_durable(entry, RECOVERY_WRITE_TIMEOUT) {
            Ok(()) => recovered += 1,
            Err(error) => tracing::warn!(
                session_id = %candidate.session_id,
                "could not append session abandonment evidence; it can be retried later: {error}"
            ),
        }
        // `lease` is intentionally still in scope through the durable write.
    }

    Ok(recovered)
}

fn candidates(db_path: &Path) -> anyhow::Result<Vec<Candidate>> {
    let conn = db::open_readonly(db_path)?;
    let mut statement = conn
        .prepare(
            "SELECT session_id, tool_name, args_json
             FROM tool_calls
             WHERE tool_name IN (?1, ?2, ?3)
             ORDER BY id ASC",
        )
        .map_err(|e| anyhow::anyhow!("failed to prepare session recovery scan: {e}"))?;
    let rows = statement
        .query_map(
            params![
                heartbeat::SESSION_START_TOOL_NAME,
                heartbeat::SESSION_END_TOOL_NAME,
                heartbeat::SESSION_ABANDONED_TOOL_NAME,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .map_err(|e| anyhow::anyhow!("failed to scan session starts: {e}"))?;

    let mut starts = HashMap::new();
    let mut closed = HashSet::new();
    for row in rows {
        let (session_id, tool_name, args_json) =
            row.map_err(|e| anyhow::anyhow!("failed to read session start: {e}"))?;
        if tool_name != heartbeat::SESSION_START_TOOL_NAME {
            closed.insert(session_id);
            continue;
        }
        let Some(args) = args_json.and_then(|raw| serde_json::from_str::<StartArgs>(&raw).ok())
        else {
            continue;
        };
        let Some(liveness) = args.liveness else {
            // Pre-upgrade sessions have no trustworthy process-liveness
            // evidence. Never infer abandonment for them.
            continue;
        };
        if liveness.mechanism != "exclusive_os_file_lock_v1" {
            continue;
        }
        starts.entry(session_id.clone()).or_insert(Candidate {
            session_id,
            lease_id: liveness.lease_id,
        });
    }
    Ok(starts
        .into_values()
        .filter(|candidate| !closed.contains(&candidate.session_id))
        .collect())
}

fn session_state(
    db_path: &Path,
    session_id: &str,
    expected_lease_id: &str,
) -> anyhow::Result<Option<SessionState>> {
    let conn = db::open_readonly(db_path)?;
    let mut statement = conn
        .prepare(
            "SELECT timestamp, tool_name, server_name, args_json
             FROM tool_calls
             WHERE session_id = ?1
               AND tool_name IN (?2, ?3, ?4)
             ORDER BY id ASC",
        )
        .map_err(|e| anyhow::anyhow!("failed to prepare session lifecycle recheck: {e}"))?;
    let rows = statement
        .query_map(
            params![
                session_id,
                heartbeat::SESSION_START_TOOL_NAME,
                heartbeat::SESSION_END_TOOL_NAME,
                heartbeat::SESSION_ABANDONED_TOOL_NAME,
            ],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            },
        )
        .map_err(|e| anyhow::anyhow!("failed to recheck session lifecycle: {e}"))?;

    let mut start = None;
    let mut server_name = None;
    let mut has_clean_end = false;
    let mut has_abandonment = false;
    for row in rows {
        let (timestamp, tool_name, name, args_json) =
            row.map_err(|e| anyhow::anyhow!("failed to read session lifecycle row: {e}"))?;
        match tool_name.as_str() {
            heartbeat::SESSION_START_TOOL_NAME => {
                let args = args_json
                    .as_deref()
                    .and_then(|raw| serde_json::from_str::<StartArgs>(raw).ok());
                if let Some(args) = args {
                    let lease_id = args
                        .liveness
                        .filter(|live| live.mechanism == "exclusive_os_file_lock_v1")
                        .map(|live| live.lease_id);
                    start = Some((args.started_at.unwrap_or(timestamp), lease_id));
                    server_name = name;
                }
            }
            heartbeat::SESSION_END_TOOL_NAME => has_clean_end = true,
            heartbeat::SESSION_ABANDONED_TOOL_NAME => has_abandonment = true,
            _ => {}
        }
    }
    let Some((started_at, start_lease_id)) = start else {
        return Ok(None);
    };
    // The lock was acquired for the candidate lease; validate the current
    // start row against that same ID before writing a recovery event.
    let lease_matches = start_lease_id.as_deref() == Some(expected_lease_id);
    let latest_alive: Option<String> = conn
        .query_row(
            "SELECT timestamp FROM tool_calls
             WHERE session_id = ?1
               AND tool_name NOT IN (?2, ?3)
             ORDER BY id DESC LIMIT 1",
            params![
                session_id,
                heartbeat::SESSION_END_TOOL_NAME,
                heartbeat::SESSION_ABANDONED_TOOL_NAME,
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| anyhow::anyhow!("failed to read last known session activity: {e}"))?;
    Ok(Some(SessionState {
        server_name,
        started_at: started_at.clone(),
        last_known_alive_at: latest_alive.unwrap_or(started_at),
        has_clean_end,
        has_abandonment,
        lease_matches,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db;
    use crate::lease::SessionLease;
    use rusqlite::Connection;
    use uuid::Uuid;

    fn db_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("auditmcp-recovery-{label}-{}.db", Uuid::new_v4()))
    }

    #[test]
    fn dead_lease_appends_one_abandonment_and_repeated_recovery_is_idempotent() {
        let path = db_path("idempotent");
        let lease = SessionLease::create(&path).unwrap();
        let lease_id = lease.id().to_string();
        let session_id = Uuid::new_v4().to_string();
        let start =
            heartbeat::session_start_entry_with_lease(&session_id, "fixture", 30, 90, &lease_id);
        let mut conn = db::open_for_write(&path).unwrap();
        db::insert_row(&mut conn, &start).unwrap();
        drop(conn);
        drop(lease);

        let (handle, writer) = db::spawn_writer(&path).unwrap();
        assert_eq!(recover_abandoned(&path, &handle).unwrap(), 1);
        assert_eq!(recover_abandoned(&path, &handle).unwrap(), 0);
        drop(handle);
        assert_eq!(
            writer.wait_for_drain(Duration::from_secs(2)),
            db::DrainOutcome::Drained { dropped: 0 }
        );
        let conn = Connection::open(&path).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM tool_calls WHERE tool_name = ?1",
                [heartbeat::SESSION_ABANDONED_TOOL_NAME],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        let args: String = conn
            .query_row(
                "SELECT args_json FROM tool_calls WHERE tool_name = ?1",
                [heartbeat::SESSION_ABANDONED_TOOL_NAME],
                |row| row.get(0),
            )
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&args).unwrap();
        assert!(parsed["last_known_alive_at"].is_string());
        assert!(parsed["detected_abandoned_at"].is_string());
        assert!(parsed["time_semantics"]
            .as_str()
            .unwrap()
            .contains("no exact"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(format!("{}.leases", path.display()));
    }

    #[test]
    fn a_live_lease_and_a_legacy_start_are_left_unknown() {
        let path = db_path("unknown");
        let live = SessionLease::create(&path).unwrap();
        let legacy_id = Uuid::new_v4().to_string();
        let live_id = Uuid::new_v4().to_string();
        let mut conn = db::open_for_write(&path).unwrap();
        db::insert_row(
            &mut conn,
            &heartbeat::session_start_entry(&legacy_id, "fixture", 30, 90),
        )
        .unwrap();
        let live_start =
            heartbeat::session_start_entry_with_lease(&live_id, "fixture", 30, 90, live.id());
        db::insert_row(&mut conn, &live_start).unwrap();
        drop(conn);
        let (handle, writer) = db::spawn_writer(&path).unwrap();
        assert_eq!(recover_abandoned(&path, &handle).unwrap(), 0);
        drop(handle);
        assert_eq!(
            writer.wait_for_drain(Duration::from_secs(2)),
            db::DrainOutcome::Drained { dropped: 0 }
        );
        drop(live);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(format!("{}.leases", path.display()));
    }
}
