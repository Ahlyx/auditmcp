//! SQLite logging: schema, hash-chained inserts, and the async writer task.

pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS tool_calls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp TEXT NOT NULL,
  session_id TEXT NOT NULL,
  agent_id TEXT,
  tool_name TEXT NOT NULL,
  server_name TEXT,
  args_json TEXT,
  result_json TEXT,
  status TEXT NOT NULL,
  error_message TEXT,
  duration_ms INTEGER,
  bytes_in INTEGER,
  bytes_out INTEGER,
  source TEXT,
  destination TEXT,
  redaction_flags TEXT,
  redaction_count INTEGER DEFAULT 0,
  anomaly_score REAL,
  anomaly_reasons TEXT,
  hash TEXT NOT NULL,
  prev_hash TEXT
);
"#;

use serde::Serialize;
use sha2::{Digest, Sha256};

/// One row's worth of loggable data, *excluding* `id`, `hash`, and
/// `prev_hash` — those three are not part of what gets hashed (`id` is a
/// DB-assigned autoincrement with no semantic meaning; `hash`/`prev_hash`
/// are the output of hashing, not input to it).
///
/// Field order here IS the canonicalization order: `derive(Serialize)` on a
/// struct makes serde_json emit fields in declaration order, always — that
/// guarantee comes from `serialize_struct`, not from the `preserve_order`
/// crate feature (which only governs arbitrary `Map`/`Value`, which we
/// deliberately avoid here). Reordering these fields changes the hash of
/// every row logged from that point on relative to how an older build would
/// have hashed the same data — don't reorder without a good reason, and
/// treat it as a breaking change to the chain format if you do.
#[derive(Serialize)]
pub struct ToolCallEntry {
    pub timestamp: String,
    pub session_id: String,
    pub agent_id: Option<String>,
    pub tool_name: String,
    pub server_name: Option<String>,
    pub args_json: Option<String>,
    pub result_json: Option<String>,
    pub status: String,
    pub error_message: Option<String>,
    pub duration_ms: Option<i64>,
    pub bytes_in: Option<i64>,
    pub bytes_out: Option<i64>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub redaction_flags: Option<String>,
    pub redaction_count: i64,
    pub anomaly_score: Option<f64>,
    pub anomaly_reasons: Option<String>,
}

/// Sentinel written into the `hash` INPUT (never into the `prev_hash`
/// column, which stays SQL NULL) for the first row of a chain. Any fixed,
/// documented string works here as long as `verify` uses the exact same
/// one — its only job is to make row 1's hash depend on *something* so an
/// attacker can't freely pick row 1's content to hit an attacker-chosen
/// hash. We use an explicit marker instead of `""` so a genesis row is not
/// hash-identical to a (hypothetical, currently-impossible) row that
/// somehow had a real empty-string prev_hash.
pub const GENESIS_PREV_HASH: &str = "GENESIS";

/// `hash = SHA256(prev_hash + canonical_json(entry))`, hex-encoded.
///
/// `prev_hash` here is the *input* to the hash function: pass the previous
/// row's stored `hash` value, or `GENESIS_PREV_HASH` for the first row.
/// This is deliberately not `Option<&str>` — the caller must be explicit
/// about which case they're in rather than letting `None` silently become
/// `""`.
pub fn compute_hash(prev_hash: &str, entry: &ToolCallEntry) -> anyhow::Result<String> {
    let canonical = serde_json::to_string(entry)
        .map_err(|e| anyhow::anyhow!("failed to canonicalize entry for hashing: {e}"))?;

    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();

    Ok(hex_encode(&digest))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;

/// Caps the writer queue so a sustained DB slowdown (slow disk, antivirus
/// scanning the file, etc.) drops audit entries instead of growing memory
/// without bound. 10k is generous headroom for a burst while still being a
/// hard ceiling — an unbounded channel would let a stalled writer turn
/// "fail open" into "fail open by exhausting memory," which is its own
/// kind of failure.
const CHANNEL_CAPACITY: usize = 10_000;

const INSERT_SQL: &str = r#"
INSERT INTO tool_calls (
  timestamp, session_id, agent_id, tool_name, server_name, args_json, result_json,
  status, error_message, duration_ms, bytes_in, bytes_out, source, destination,
  redaction_flags, redaction_count, anomaly_score, anomaly_reasons, hash, prev_hash
) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20)
"#;

/// Opens (creating if needed) the audit DB with WAL mode on and the schema
/// applied. Every error here is returned, never panicked on — the caller
/// (the writer thread) decides how to fail open.
fn open_db(path: &Path) -> anyhow::Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!("failed to create db directory {}: {e}", parent.display())
            })?;
        }
    }

    let conn = Connection::open(path)
        .map_err(|e| anyhow::anyhow!("failed to open db {}: {e}", path.display()))?;

    conn.pragma_update(None, "journal_mode", "WAL")
        .map_err(|e| anyhow::anyhow!("failed to enable WAL mode: {e}"))?;
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| anyhow::anyhow!("failed to set synchronous pragma: {e}"))?;
    conn.execute_batch(SCHEMA)
        .map_err(|e| anyhow::anyhow!("failed to apply schema: {e}"))?;

    Ok(conn)
}

/// The `hash` of the most recently inserted row, or `GENESIS_PREV_HASH` if
/// the table is empty. This is the "input" form (see `compute_hash` doc),
/// not the raw nullable `prev_hash` column.
fn last_hash(conn: &Connection) -> anyhow::Result<String> {
    let hash: Option<String> = conn
        .query_row("SELECT hash FROM tool_calls ORDER BY id DESC LIMIT 1", [], |row| {
            row.get(0)
        })
        .optional()
        .map_err(|e| anyhow::anyhow!("failed to read last hash: {e}"))?;

    Ok(hash.unwrap_or_else(|| GENESIS_PREV_HASH.to_string()))
}

/// Computes the row's hash and inserts it. Returns the new hash on success
/// (to become the next row's `prev_hash` input).
fn insert_row(conn: &Connection, prev_hash: &str, entry: &ToolCallEntry) -> anyhow::Result<String> {
    let hash = compute_hash(prev_hash, entry)?;

    // GENESIS_PREV_HASH is a hash *input* sentinel only — the stored
    // prev_hash column stays NULL for the first row, matching the schema's
    // "prev_hash TEXT" (nullable) rather than persisting the sentinel text.
    let prev_hash_col: Option<&str> = if prev_hash == GENESIS_PREV_HASH {
        None
    } else {
        Some(prev_hash)
    };

    conn.execute(
        INSERT_SQL,
        params![
            entry.timestamp,
            entry.session_id,
            entry.agent_id,
            entry.tool_name,
            entry.server_name,
            entry.args_json,
            entry.result_json,
            entry.status,
            entry.error_message,
            entry.duration_ms,
            entry.bytes_in,
            entry.bytes_out,
            entry.source,
            entry.destination,
            entry.redaction_flags,
            entry.redaction_count,
            entry.anomaly_score,
            entry.anomaly_reasons,
            hash,
            prev_hash_col,
        ],
    )
    .map_err(|e| anyhow::anyhow!("failed to insert row: {e}"))?;

    Ok(hash)
}

/// Opens the audit DB read-only, for `query`/`verify`. Uses SQLite's actual
/// read-only open flag rather than `Connection::open`, so a missing DB file
/// fails with a clear error instead of silently creating an empty one.
pub fn open_readonly(path: &Path) -> anyhow::Result<Connection> {
    Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e| {
        anyhow::anyhow!(
            "failed to open db {} read-only: {e} (has `auditmcp run` been used yet?)",
            path.display()
        )
    })
}

/// One row as read back from storage: the same `ToolCallEntry` shape used
/// for hashing, plus the three columns that aren't part of that struct.
pub struct StoredRow {
    pub id: i64,
    pub entry: ToolCallEntry,
    pub hash: String,
    pub prev_hash: Option<String>,
}

const SELECT_ALL_SQL: &str = r#"
SELECT id, timestamp, session_id, agent_id, tool_name, server_name, args_json,
       result_json, status, error_message, duration_ms, bytes_in, bytes_out,
       source, destination, redaction_flags, redaction_count, anomaly_score,
       anomaly_reasons, hash, prev_hash
FROM tool_calls
ORDER BY id ASC
"#;

pub fn read_all_rows(conn: &Connection) -> anyhow::Result<Vec<StoredRow>> {
    let mut stmt = conn
        .prepare(SELECT_ALL_SQL)
        .map_err(|e| anyhow::anyhow!("failed to prepare query: {e}"))?;

    let mapped = stmt
        .query_map([], |row| {
            Ok(StoredRow {
                id: row.get(0)?,
                entry: ToolCallEntry {
                    timestamp: row.get(1)?,
                    session_id: row.get(2)?,
                    agent_id: row.get(3)?,
                    tool_name: row.get(4)?,
                    server_name: row.get(5)?,
                    args_json: row.get(6)?,
                    result_json: row.get(7)?,
                    status: row.get(8)?,
                    error_message: row.get(9)?,
                    duration_ms: row.get(10)?,
                    bytes_in: row.get(11)?,
                    bytes_out: row.get(12)?,
                    source: row.get(13)?,
                    destination: row.get(14)?,
                    redaction_flags: row.get(15)?,
                    redaction_count: row.get(16)?,
                    anomaly_score: row.get(17)?,
                    anomaly_reasons: row.get(18)?,
                },
                hash: row.get(19)?,
                prev_hash: row.get(20)?,
            })
        })
        .map_err(|e| anyhow::anyhow!("failed to query rows: {e}"))?;

    let mut out = Vec::new();
    for row in mapped {
        out.push(row.map_err(|e| anyhow::anyhow!("failed to read row: {e}"))?);
    }
    Ok(out)
}

/// A broken link found while walking the chain. These are deliberately
/// three distinct variants rather than one generic "mismatch" — each
/// corresponds to a different way the log could have been tampered with,
/// and conflating them would lose information a user needs to know what
/// actually happened.
#[derive(Debug, PartialEq)]
pub enum ChainIssue {
    /// The id sequence skips a value. SQLite `AUTOINCREMENT` ids are
    /// monotonic and never reused, so a gap means a row was deleted
    /// outright. This is NOT caught by `ContentTampered` below: a deleted
    /// row's neighbors are individually unchanged, each still hashes
    /// correctly against its own stored `prev_hash` — the chain only
    /// breaks in the sense that a link is now *missing*, not that any
    /// remaining row's own hash is wrong.
    RowMissing { after_id: i64, expected_id: i64, found_id: i64 },
    /// A row's stored `prev_hash` doesn't equal the hash actually produced
    /// by the row immediately before it in the chain we've walked so far.
    /// Catches reordering and direct tampering with the `prev_hash`
    /// column itself.
    LinkBroken { id: i64, expected_prev_hash: String, stored_prev_hash: String },
    /// A row's own hash doesn't match what its stored content (hashed
    /// against its own, valid, prev_hash) recomputes to — i.e. some other
    /// column was edited after the row was written.
    ContentTampered { id: i64, tool_name: String, expected_hash: String, stored_hash: String },
}

impl std::fmt::Display for ChainIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainIssue::RowMissing { after_id, expected_id, found_id } => write!(
                f,
                "row deleted: after id {after_id}, expected next id {expected_id} but found id {found_id}"
            ),
            ChainIssue::LinkBroken { id, expected_prev_hash, stored_prev_hash } => write!(
                f,
                "chain broken at row id {id}: expected prev_hash {expected_prev_hash}, found {stored_prev_hash}"
            ),
            ChainIssue::ContentTampered { id, tool_name, expected_hash, stored_hash } => write!(
                f,
                "row id {id} (tool '{tool_name}') was altered: recomputed hash {expected_hash} does not match stored hash {stored_hash}"
            ),
        }
    }
}

/// Walks the full chain in id order and returns the first broken link
/// found, per the `auditmcp verify` spec ("report first broken link if
/// any"). The outer `Result` is for operational failures (can't read the
/// table at all); the inner `Result` is the actual verification outcome —
/// `Ok(row_count)` means every row checked out.
pub fn verify_chain(conn: &Connection) -> anyhow::Result<Result<usize, ChainIssue>> {
    let rows = read_all_rows(conn)?;

    let mut expected_prev_hash = GENESIS_PREV_HASH.to_string();
    let mut last_id: Option<i64> = None;

    for row in &rows {
        if let Some(prev_id) = last_id {
            let expected_id = prev_id + 1;
            if row.id != expected_id {
                return Ok(Err(ChainIssue::RowMissing {
                    after_id: prev_id,
                    expected_id,
                    found_id: row.id,
                }));
            }
        }

        let stored_prev_hash = row
            .prev_hash
            .clone()
            .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
        if stored_prev_hash != expected_prev_hash {
            return Ok(Err(ChainIssue::LinkBroken {
                id: row.id,
                expected_prev_hash,
                stored_prev_hash,
            }));
        }

        let recomputed = compute_hash(&stored_prev_hash, &row.entry)?;
        if recomputed != row.hash {
            return Ok(Err(ChainIssue::ContentTampered {
                id: row.id,
                tool_name: row.entry.tool_name.clone(),
                expected_hash: recomputed,
                stored_hash: row.hash.clone(),
            }));
        }

        expected_prev_hash = row.hash.clone();
        last_id = Some(row.id);
    }

    Ok(Ok(rows.len()))
}

/// Handle held by the proxy to submit entries for logging without ever
/// blocking on disk I/O. Cloneable and cheap — it's a bounded channel
/// sender plus a shared drop counter.
#[derive(Clone)]
pub struct DbHandle {
    sender: SyncSender<ToolCallEntry>,
    dropped: Arc<AtomicU64>,
}

impl DbHandle {
    /// Fail-open by design, and non-blocking: uses `try_send` rather than
    /// `send`, so a full queue or a dead writer thread results in the entry
    /// being dropped (and counted) immediately rather than this call
    /// blocking the caller until space frees up. It never panics or
    /// propagates an error that could interrupt the proxied session.
    pub fn log(&self, entry: ToolCallEntry) {
        match self.sender.try_send(entry) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                let prev = self.dropped.fetch_add(1, Ordering::Relaxed);
                // Warn on the first drop and then only periodically, so a
                // sustained backlog doesn't itself become a logging-storm
                // performance problem.
                if prev == 0 {
                    tracing::warn!(
                        "audit log queue full (capacity {CHANNEL_CAPACITY}); entries are being dropped until the writer catches up"
                    );
                } else if (prev + 1).is_multiple_of(1000) {
                    tracing::warn!("audit log queue still full; {} entries dropped so far", prev + 1);
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                tracing::warn!("audit log entry dropped, writer unavailable");
            }
        }
    }

    /// Total entries dropped (queue-full or writer-gone) since this
    /// handle's writer was spawned. Not surfaced anywhere yet — intended
    /// for a future "audit gap" marker or `watch` status line.
    pub fn dropped_count(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Spawns the dedicated writer thread and returns a handle to submit
/// entries to it. A plain OS thread (not a tokio task) because rusqlite's
/// `Connection` is synchronous; this keeps blocking disk I/O off the tokio
/// runtime entirely, which is what "async, buffered writes" means in
/// practice here — the proxy never awaits a DB call.
pub fn spawn_writer(db_path: &Path) -> DbHandle {
    let (tx, rx) = sync_channel::<ToolCallEntry>(CHANNEL_CAPACITY);
    let path = db_path.to_path_buf();

    std::thread::spawn(move || writer_loop(&path, rx));

    DbHandle { sender: tx, dropped: Arc::new(AtomicU64::new(0)) }
}

/// Runs on the dedicated writer thread. Every failure mode here is
/// logged-and-continued, never a panic: with `panic = "abort"` set in the
/// release profile, a panic on this thread would abort the *entire*
/// process, taking the proxied session down with it — exactly what
/// fail-open logging must not do.
fn writer_loop(path: &Path, rx: Receiver<ToolCallEntry>) {
    let conn = match open_db(path) {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("audit db unavailable ({e}); all audit log entries will be dropped for this session");
            // Keep draining so `DbHandle::log` sends don't pile up in an
            // ever-growing unbounded channel for the life of the process.
            for _ in rx.iter() {
                tracing::warn!("audit log entry dropped: db unavailable");
            }
            return;
        }
    };

    let mut prev_hash = match last_hash(&conn) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!("failed to read prior chain hash, starting a new chain segment: {e}");
            GENESIS_PREV_HASH.to_string()
        }
    };

    for entry in rx.iter() {
        let tool_name = entry.tool_name.clone();
        match insert_row(&conn, &prev_hash, &entry) {
            Ok(new_hash) => prev_hash = new_hash,
            Err(e) => tracing::warn!("failed to write audit log entry for tool '{tool_name}': {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_entry() -> ToolCallEntry {
        ToolCallEntry {
            timestamp: "2026-07-02T12:00:00Z".to_string(),
            session_id: "sess-1".to_string(),
            agent_id: None,
            tool_name: "echo".to_string(),
            server_name: Some("fake_server".to_string()),
            args_json: Some(r#"{"msg":"hi"}"#.to_string()),
            result_json: Some(r#"{"msg":"hi"}"#.to_string()),
            status: "success".to_string(),
            error_message: None,
            duration_ms: Some(12),
            bytes_in: Some(20),
            bytes_out: Some(20),
            source: None,
            destination: None,
            redaction_flags: None,
            redaction_count: 0,
            anomaly_score: None,
            anomaly_reasons: None,
        }
    }

    /// Known-answer test: the expected digest below was computed
    /// independently of this codebase (via .NET `SHA256` in PowerShell and
    /// cross-checked with `sha256sum`) over the literal bytes
    /// `"GENESIS" + canonical_json`, where `canonical_json` is the exact
    /// string a minimal all-`None`/zero entry is expected to serialize to.
    /// If this test ever breaks, either `compute_hash`'s hex encoding or
    /// its canonical serialization drifted — a bug in `hex_encode` or a
    /// change to field order/serde behavior would show up here even though
    /// the other tests (which only compare this function's output against
    /// itself) would stay green.
    #[test]
    fn known_answer_genesis_hash() {
        let entry = ToolCallEntry {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            session_id: "s1".to_string(),
            agent_id: None,
            tool_name: "echo".to_string(),
            server_name: None,
            args_json: None,
            result_json: None,
            status: "success".to_string(),
            error_message: None,
            duration_ms: None,
            bytes_in: None,
            bytes_out: None,
            source: None,
            destination: None,
            redaction_flags: None,
            redaction_count: 0,
            anomaly_score: None,
            anomaly_reasons: None,
        };

        let expected = "8d16aeafa3d69b740a7c3f293a151753fe3b5b67f0c8620212df6668e0c6ffe0";
        let actual = compute_hash(GENESIS_PREV_HASH, &entry).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn same_entry_same_prev_hashes_identically() {
        let a = compute_hash(GENESIS_PREV_HASH, &sample_entry()).unwrap();
        let b = compute_hash(GENESIS_PREV_HASH, &sample_entry()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_prev_hash_changes_output() {
        let a = compute_hash(GENESIS_PREV_HASH, &sample_entry()).unwrap();
        let b = compute_hash("some-other-prev-hash", &sample_entry()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tampering_any_field_changes_hash() {
        let baseline = compute_hash(GENESIS_PREV_HASH, &sample_entry()).unwrap();

        let mut tampered = sample_entry();
        tampered.status = "error".to_string();
        let changed = compute_hash(GENESIS_PREV_HASH, &tampered).unwrap();

        assert_ne!(baseline, changed);
    }

    /// Unique-per-run temp DB path so parallel `cargo test` threads don't
    /// collide on the same file.
    fn temp_db_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("auditmcp_test_{label}_{}.db", uuid::Uuid::new_v4()))
    }

    #[test]
    fn open_db_creates_schema_and_enables_wal() {
        let path = temp_db_path("open");
        let conn = open_db(&path).unwrap();

        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");

        // Schema applied: table exists and is queryable.
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM tool_calls", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);

        drop(conn);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn last_hash_is_genesis_on_empty_table_and_tracks_inserts() {
        let path = temp_db_path("chain");
        let conn = open_db(&path).unwrap();

        assert_eq!(last_hash(&conn).unwrap(), GENESIS_PREV_HASH);

        let h1 = insert_row(&conn, &last_hash(&conn).unwrap(), &sample_entry()).unwrap();
        assert_eq!(last_hash(&conn).unwrap(), h1);

        let h2 = insert_row(&conn, &last_hash(&conn).unwrap(), &sample_entry()).unwrap();
        assert_eq!(last_hash(&conn).unwrap(), h2);
        assert_ne!(h1, h2, "identical entries chained after a different prev_hash must differ");

        // First row's prev_hash column is NULL, not the "GENESIS" sentinel text.
        let stored_prev: Option<String> = conn
            .query_row(
                "SELECT prev_hash FROM tool_calls ORDER BY id ASC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_prev, None);

        drop(conn);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    fn cleanup(conn: Connection, path: &std::path::Path) {
        drop(conn);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    /// Inserts `n` entries (each with a distinct tool_name so tests can
    /// tell rows apart) and returns the connection plus their ids in order.
    fn seed_chain(conn: &Connection, n: usize) -> Vec<i64> {
        let mut prev = last_hash(conn).unwrap();
        let mut ids = Vec::new();
        for i in 0..n {
            let mut entry = sample_entry();
            entry.tool_name = format!("tool_{i}");
            prev = insert_row(conn, &prev, &entry).unwrap();
            let id: i64 = conn
                .query_row("SELECT id FROM tool_calls ORDER BY id DESC LIMIT 1", [], |r| r.get(0))
                .unwrap();
            ids.push(id);
        }
        ids
    }

    #[test]
    fn verify_succeeds_on_untampered_chain() {
        let path = temp_db_path("verify_ok");
        let conn = open_db(&path).unwrap();
        seed_chain(&conn, 5);

        let result = verify_chain(&conn).unwrap();
        assert_eq!(result, Ok(5));

        cleanup(conn, &path);
    }

    #[test]
    fn verify_fails_and_identifies_tampered_row() {
        let path = temp_db_path("verify_tamper");
        let conn = open_db(&path).unwrap();
        let ids = seed_chain(&conn, 5);
        let tampered_id = ids[2]; // an interior row, not first or last

        conn.execute(
            "UPDATE tool_calls SET status = 'error' WHERE id = ?1",
            params![tampered_id],
        )
        .unwrap();

        let result = verify_chain(&conn).unwrap();
        match result {
            Err(ChainIssue::ContentTampered { id, .. }) => assert_eq!(id, tampered_id),
            other => panic!("expected ContentTampered at id {tampered_id}, got {other:?}"),
        }

        cleanup(conn, &path);
    }

    #[test]
    fn verify_fails_when_a_row_is_deleted() {
        // Deletion is a distinct failure mode from tampering: the
        // remaining rows are each individually self-consistent (their own
        // hash still matches their own stored prev_hash), so a check that
        // only recomputes per-row hashes would NOT catch this. It has to
        // be caught by noticing the id sequence (or the hash link) has a
        // gap where the deleted row used to be.
        let path = temp_db_path("verify_delete");
        let conn = open_db(&path).unwrap();
        let ids = seed_chain(&conn, 5);
        let deleted_id = ids[2];

        conn.execute("DELETE FROM tool_calls WHERE id = ?1", params![deleted_id])
            .unwrap();

        let result = verify_chain(&conn).unwrap();
        match result {
            Err(ChainIssue::RowMissing { found_id, .. }) => {
                // The first row encountered *after* the gap is the next
                // surviving id, ids[3].
                assert_eq!(found_id, ids[3]);
            }
            other => panic!("expected RowMissing after id {deleted_id}, got {other:?}"),
        }

        cleanup(conn, &path);
    }
}
