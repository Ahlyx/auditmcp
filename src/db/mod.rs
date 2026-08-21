//! SQLite logging: schema, connection management, and the allowlist/rows
//! read paths that don't belong to a more specific concern.
//!
//! The hash chain, the derived redactions index, and the async writer
//! thread are each big enough (and distinct enough) to deserve their own
//! file rather than mixing all four concerns in one -- see `chain_hash`,
//! `redaction_repair`, and `writer` below. Everything they export is
//! re-exported here so the rest of the crate keeps addressing all of it as
//! `db::whatever`, unchanged.

mod chain_hash;
mod redaction_repair;
mod writer;

// Some of these re-exports are only ever reached through `db::` from other
// modules' `#[cfg(test)]` test code (integration-style chain/verify/reset
// fixtures that seed a real database), never from this crate's non-test
// code paths. That makes them, correctly, unused imports in a plain
// (non-test) build of this barrel module even though they are load-bearing
// for `cargo test` -- hence the blanket allow, the standard shape for a
// re-export module whose consumers live elsewhere.
#[cfg(test)]
pub use chain_hash::verify_chain;
#[allow(unused_imports)]
pub use chain_hash::{
    compute_hash, read_chain_metadata, verify_chain_metadata_hmac, verify_chain_with_key,
    write_chain_metadata_genesis, ChainIssue, ChainMetadata, GENESIS_PREV_HASH,
};
#[allow(unused_imports)]
pub(crate) use chain_hash::{last_hash, HashKey};

#[allow(unused_imports)]
pub use redaction_repair::{
    apply_redaction_repair, check_redaction_consistency, plan_redaction_repair, RedactionDrift,
    RedactionTriple, RepairAction, RepairPlan,
};

#[allow(unused_imports)]
pub(crate) use writer::insert_row_with_key;
#[cfg(test)]
pub(crate) use writer::{insert_row, spawn_writer};
#[allow(unused_imports)]
pub use writer::{spawn_writer_with_key, DbHandle, DbWriter, DrainOutcome, DropTally};

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

-- SCHEMA CHANGE (Phase 2, secrets detection): confirmed-false-positive
-- allowlist, written by the `auditmcp unmask` subcommand. `unmask` never
-- recovers plaintext of a past redaction (we never store plaintext, by
-- design) -- instead it records that a given secret's sha256 is a
-- confirmed false positive, so future occurrences of that exact value are
-- left unredacted going forward. Rows already written before the
-- allowlisting stay redacted permanently.
CREATE TABLE IF NOT EXISTS secret_allowlist (
  secret_sha256 TEXT PRIMARY KEY,
  added_at TEXT NOT NULL,
  note TEXT
);

-- SCHEMA CHANGE (Phase 2, secrets detection): normalized, indexed
-- projection of `tool_calls.redaction_flags` -- one row per redaction hit
-- rather than a JSON blob per tool_calls row. `redaction_flags` itself is
-- unchanged and still the source of truth (this table is populated by
-- parsing that same JSON right after each insert, never a separate write
-- path); this table exists purely so `unmask`'s hash/prefix resolution and
-- future cross-call secret correlation are indexed lookups instead of a
-- full-table JSON scan+parse as the audit log grows.
CREATE TABLE IF NOT EXISTS redactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tool_call_id INTEGER NOT NULL REFERENCES tool_calls(id),
  pattern TEXT NOT NULL,
  severity TEXT NOT NULL,
  secret_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_redactions_sha256 ON redactions(secret_sha256);
CREATE INDEX IF NOT EXISTS idx_redactions_tool_call_id ON redactions(tool_call_id);

-- SCHEMA CHANGE (Phase 3.5, chain hardening): per-database chain
-- configuration, populated once at genesis and never mutated afterward.
-- Absence of the `hmac_version` key marks the chain as a pre-Phase-3.5
-- (Phase 1-3) legacy chain -- unkeyed SHA-256, no HMAC, no heartbeats, no
-- anchor. A row's presence here is what tells `run`/`verify` which hashing
-- scheme applies to THIS database; see `chain::bootstrap`.
CREATE TABLE IF NOT EXISTS chain_metadata (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"#;

use serde::Serialize;

/// One row's worth of loggable data, *excluding* `id`, `hash`, and
/// `prev_hash` -- those three are decided at the moment a row is inserted
/// (see `writer::insert_row_with_key`), not by the caller building this.
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

use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashSet;
use std::path::Path;
#[cfg(test)]
use std::sync::mpsc::sync_channel;
#[cfg(test)]
use std::sync::Arc;

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

    // Load-bearing for MULTI-PROCESS writers (several `auditmcp run`
    // instances sharing one db_path): without a busy timeout, a second
    // writer's `BEGIN IMMEDIATE` (see `writer::insert_row_with_key`) fails
    // instantly with SQLITE_BUSY while another process holds the write
    // lock — and since logging is fail-open, that entry would be silently
    // dropped rather than briefly waiting its turn. 5s is far beyond any
    // realistic single insert (sub-millisecond), so hitting this timeout
    // means something is genuinely wedged, at which point failing open is
    // the right call.
    conn.busy_timeout(std::time::Duration::from_secs(5))
        .map_err(|e| anyhow::anyhow!("failed to set busy timeout: {e}"))?;

    // Manual retry, because the busy_timeout above does NOT cover this
    // statement: converting a database to WAL needs a brief exclusive lock,
    // and SQLite acquires it without consulting the busy handler — observed
    // empirically (smoke test: two `auditmcp run` processes starting
    // simultaneously against a brand-new shared db_path; the loser got an
    // instant "database is locked" despite the 5s timeout, and fail-open
    // then dropped its whole session's entries). This is the first thing
    // two proxies sharing a db_path race on at startup, so it must wait
    // like every other contended write. Once the file is already in WAL
    // mode the pragma is a no-op read and never contends.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        match conn.pragma_update(None, "journal_mode", "WAL") {
            Ok(()) => break,
            Err(e) if is_busy(&e) && std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) => return Err(anyhow::anyhow!("failed to enable WAL mode: {e}")),
        }
    }
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| anyhow::anyhow!("failed to set synchronous pragma: {e}"))?;
    conn.execute_batch(SCHEMA)
        .map_err(|e| anyhow::anyhow!("failed to apply schema: {e}"))?;

    Ok(conn)
}

/// True for the two "another connection is in the way" error codes:
/// SQLITE_BUSY ("database is locked", cross-connection contention) and
/// SQLITE_LOCKED ("database table is locked"). Used only where SQLite
/// bypasses the busy handler and we must retry ourselves.
fn is_busy(e: &rusqlite::Error) -> bool {
    matches!(
        e.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    )
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

/// Opens the audit DB for a one-off write from a CLI command (currently
/// just `unmask`), reusing the same pragmas/schema setup as the proxy's
/// writer thread. Unlike `open_readonly`, this creates the DB (and applies
/// the schema, which is idempotent) if it doesn't exist yet, since running
/// `unmask` before ever running the proxy is a legitimate if unusual order.
pub fn open_for_write(path: &Path) -> anyhow::Result<Connection> {
    open_db(path)
}

/// All sha256 hashes currently in `secret_allowlist` -- confirmed false
/// positives that should be left unredacted going forward. Used by `query
/// --verbose` to annotate historical redactions that have since been
/// cleared, and (upstream, in `secrets.rs`) by the proxy to skip redacting
/// them at all on future occurrences.
pub fn load_allowlist(conn: &Connection) -> anyhow::Result<HashSet<String>> {
    let mut stmt = conn
        .prepare("SELECT secret_sha256 FROM secret_allowlist")
        .map_err(|e| anyhow::anyhow!("failed to prepare allowlist query: {e}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| anyhow::anyhow!("failed to query allowlist: {e}"))?;

    let mut out = HashSet::new();
    for r in rows {
        out.insert(r.map_err(|e| anyhow::anyhow!("failed to read allowlist row: {e}"))?);
    }
    Ok(out)
}

/// Records `sha256` as a confirmed false positive, with the reasoning a
/// human gave for that call (`note`) -- this is itself a security decision
/// worth an audit trail, not just a bare hash. Re-unmasking an
/// already-allowlisted hash updates its `added_at`/`note` rather than
/// erroring, since a user might reasonably re-confirm or amend their
/// reasoning later. Returns the stored `added_at` timestamp for the
/// caller's confirmation message.
pub fn add_to_allowlist(conn: &Connection, sha256: &str, note: &str) -> anyhow::Result<String> {
    let added_at = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO secret_allowlist (secret_sha256, added_at, note) VALUES (?1, ?2, ?3)
         ON CONFLICT(secret_sha256) DO UPDATE SET added_at = excluded.added_at, note = excluded.note",
        params![sha256, added_at, note],
    )
    .map_err(|e| anyhow::anyhow!("failed to write allowlist entry: {e}"))?;
    Ok(added_at)
}

/// Looks up the pattern name for an exact, full sha256 -- a single indexed
/// point lookup against `redactions.secret_sha256` (see `idx_redactions_sha256`
/// in `SCHEMA`), not a table scan. `None` if this hash has never been
/// recorded (still a valid `unmask` target -- see `unmask.rs`).
pub fn find_secret_hash_exact(conn: &Connection, sha256: &str) -> anyhow::Result<Option<String>> {
    conn.query_row(
        "SELECT pattern FROM redactions WHERE secret_sha256 = ?1 LIMIT 1",
        params![sha256],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| anyhow::anyhow!("failed to look up secret hash: {e}"))
}

/// Resolves a hash prefix against `redactions.secret_sha256`: an exact
/// count of distinct matches (indexed range scan on the `LIKE 'prefix%'`
/// pattern, not a full scan+JSON-parse), plus up to `sample_limit` example
/// (hash, pattern) pairs for an ambiguous-match error message. This is the
/// "known hash" universe `unmask` resolves a prefix against, mirroring how
/// `git` resolves a short commit hash against the hashes that actually
/// exist in the repo -- but as two small indexed queries instead of
/// loading every redaction ever recorded into memory.
pub fn find_secret_hashes_by_prefix(
    conn: &Connection,
    prefix: &str,
    sample_limit: usize,
) -> anyhow::Result<(usize, Vec<(String, String)>)> {
    let like_pattern = format!("{prefix}%");

    let count: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT secret_sha256) FROM redactions WHERE secret_sha256 LIKE ?1",
            params![like_pattern],
            |row| row.get(0),
        )
        .map_err(|e| anyhow::anyhow!("failed to count matching secret hashes: {e}"))?;

    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT secret_sha256, pattern FROM redactions
             WHERE secret_sha256 LIKE ?1 ORDER BY id LIMIT ?2",
        )
        .map_err(|e| anyhow::anyhow!("failed to prepare prefix lookup: {e}"))?;
    let rows = stmt
        .query_map(params![like_pattern, sample_limit as i64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| anyhow::anyhow!("failed to query matching secret hashes: {e}"))?;

    let mut samples = Vec::new();
    for r in rows {
        samples
            .push(r.map_err(|e| anyhow::anyhow!("failed to read matching secret hash row: {e}"))?);
    }

    Ok((count as usize, samples))
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

/// Test-only fixtures shared across module test suites. Lives here, next to
/// the schema and insert path they exercise, so `verify::tests` (and later
/// `proxy`/transport suites) can seed a real hash-chained database without
/// each module reimplementing seeding — and without widening any production
/// function's visibility just to make it testable.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;

    pub(crate) fn sample_entry() -> ToolCallEntry {
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

    /// Unique-per-run temp DB path so parallel `cargo test` threads don't
    /// collide on the same file.
    pub(crate) fn temp_db_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("auditmcp_test_{label}_{}.db", uuid::Uuid::new_v4()))
    }

    /// A fresh, uniquely-named directory under the OS temp root, created
    /// (and thus owned) by this process -- for any test file whose
    /// permissions get tightened after creation (e.g. a Phase 3.5 key via
    /// `KeyFile::save`, which chmods the file's *parent* directory on
    /// Unix). Placing that file directly in the shared OS temp root (as
    /// earlier test helpers did) meant that chmod targeted a directory
    /// (`/tmp`) this process doesn't own, which fails with `EPERM` under a
    /// non-root CI user -- a directory this process created itself doesn't
    /// have that problem.
    pub(crate) fn temp_isolated_dir(label: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("auditmcp_test_{label}_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("failed to create isolated test directory");
        dir
    }

    pub(crate) fn cleanup(conn: Connection, path: &std::path::Path) {
        drop(conn);
        remove_db_files(path);
    }

    /// Removes a temp DB and its WAL sidecars. Separate from `cleanup` for
    /// callers that already dropped (or never held) a `Connection`.
    pub(crate) fn remove_db_files(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    /// Inserts `n` entries (each with a distinct tool_name so tests can
    /// tell rows apart) and returns their ids in order.
    pub(crate) fn seed_chain(conn: &mut Connection, n: usize) -> Vec<i64> {
        let mut ids = Vec::new();
        for i in 0..n {
            let mut entry = sample_entry();
            entry.tool_name = format!("tool_{i}");
            insert_row(conn, &entry).unwrap();
            let id: i64 = conn
                .query_row(
                    "SELECT id FROM tool_calls ORDER BY id DESC LIMIT 1",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            ids.push(id);
        }
        ids
    }

    /// Seeds one row carrying `redaction_flags`, which also populates the
    /// derived `redactions` index. Returns the new row's id. Used by drift
    /// tests, which then delete from the index to simulate the fail-open
    /// gap `verify` is meant to detect.
    pub(crate) fn seed_redacted_row(conn: &mut Connection, sha256: &str) -> i64 {
        let mut entry = sample_entry();
        entry.tool_name = "leak_secret".to_string();
        entry.redaction_flags = Some(format!(
            r#"[{{"pattern":"openai_api_key","severity":"high","sha256":"{sha256}"}}]"#
        ));
        entry.redaction_count = 1;
        insert_row(conn, &entry).unwrap();
        conn.query_row(
            "SELECT id FROM tool_calls ORDER BY id DESC LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
    }
}
#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    /// The minimal all-`None`/zero entry the golden vectors below are
    /// pinned against. Shared by the known-answer hash test and the
    /// canonical-JSON shape test so both describe the same fixture.
    fn golden_entry_minimal() -> ToolCallEntry {
        ToolCallEntry {
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
        }
    }

    /// Every field populated, including a string with a quote, a backslash,
    /// and a multi-byte character — so the golden vector also pins serde's
    /// string escaping and numeric formatting, not just field order.
    fn golden_entry_populated() -> ToolCallEntry {
        ToolCallEntry {
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            session_id: "conn:s1".to_string(),
            agent_id: Some("agent-1".to_string()),
            tool_name: "leak_secret".to_string(),
            server_name: Some("vault".to_string()),
            args_json: Some(r#"{"path":"C:\\tmp\\✓","q":"say \"hi\""}"#.to_string()),
            result_json: Some(r#"{"api_key":"[REDACTED:openai_api_key]"}"#.to_string()),
            status: "error".to_string(),
            error_message: Some("boom".to_string()),
            duration_ms: Some(42),
            bytes_in: Some(120),
            bytes_out: Some(340),
            source: Some("/etc/passwd".to_string()),
            destination: Some("example.com".to_string()),
            redaction_flags: Some(
                r#"[{"pattern":"openai_api_key","severity":"high","sha256":"abc"}]"#.to_string(),
            ),
            redaction_count: 1,
            anomaly_score: Some(0.5),
            anomaly_reasons: Some(r#"["unseen destination"]"#.to_string()),
        }
    }

    /// GOLDEN VECTOR — if this fails, do NOT update the expected string to
    /// make it pass until you have read this comment.
    ///
    /// `ToolCallEntry`'s serialized form is the canonicalization input to
    /// `compute_hash`, and `verify_chain` re-derives every row's hash by
    /// deserializing that row's columns back into a `ToolCallEntry` and
    /// re-serializing it. So the shape pinned here is not an internal
    /// detail — it is the on-disk hash-chain format.
    ///
    /// Consequence, and the reason this test exists: **adding a field to
    /// `ToolCallEntry` retroactively invalidates every row already in every
    /// existing database.** A plain `Option<T>` field serializes as
    /// `"field":null` rather than being omitted, so a row written before
    /// the field existed would canonicalize differently on read than it did
    /// on write, its recomputed hash would not match its stored hash, and
    /// `verify` would report `ContentTampered` on the entire historical log
    /// — telling the user their audit trail was tampered with when it was
    /// not. Reordering or renaming a field does the same.
    ///
    /// If a new field is genuinely required, it MUST be `Option<T>`,
    /// appended last, and carry
    /// `#[serde(skip_serializing_if = "Option::is_none")]` so that `None`
    /// is omitted entirely and pre-existing rows keep canonicalizing to
    /// exactly the bytes they were hashed as. Only rows that populate the
    /// new field hash differently, and those are new rows by definition.
    /// Add a golden vector for the populated case at the same time.
    #[test]
    fn canonical_json_shape_is_frozen() {
        let expected_minimal = concat!(
            r#"{"timestamp":"2026-01-01T00:00:00Z","session_id":"s1","agent_id":null,"#,
            r#""tool_name":"echo","server_name":null,"args_json":null,"result_json":null,"#,
            r#""status":"success","error_message":null,"duration_ms":null,"bytes_in":null,"#,
            r#""bytes_out":null,"source":null,"destination":null,"redaction_flags":null,"#,
            r#""redaction_count":0,"anomaly_score":null,"anomaly_reasons":null}"#
        );
        let actual_minimal = serde_json::to_string(&golden_entry_minimal()).unwrap();
        assert_eq!(
            actual_minimal, expected_minimal,
            "ToolCallEntry's canonical form changed. This is the hash-chain \
             format: every row in every existing database was hashed against \
             the old shape and will now fail `verify` as tampered. Read this \
             test's doc comment before changing the expected value."
        );

        let expected_populated = concat!(
            r#"{"timestamp":"2026-01-01T00:00:00Z","session_id":"conn:s1","agent_id":"agent-1","#,
            r#""tool_name":"leak_secret","server_name":"vault","#,
            r#""args_json":"{\"path\":\"C:\\\\tmp\\\\✓\",\"q\":\"say \\\"hi\\\"\"}","#,
            r#""result_json":"{\"api_key\":\"[REDACTED:openai_api_key]\"}","#,
            r#""status":"error","error_message":"boom","duration_ms":42,"bytes_in":120,"#,
            r#""bytes_out":340,"source":"/etc/passwd","destination":"example.com","#,
            r#""redaction_flags":"[{\"pattern\":\"openai_api_key\",\"severity\":\"high\",\"sha256\":\"abc\"}]","#,
            r#""redaction_count":1,"anomaly_score":0.5,"anomaly_reasons":"[\"unseen destination\"]"}"#
        );
        let actual_populated = serde_json::to_string(&golden_entry_populated()).unwrap();
        assert_eq!(
            actual_populated, expected_populated,
            "ToolCallEntry's canonical form changed for populated fields \
             (escaping or numeric formatting). See this test's doc comment."
        );
    }

    /// Known-answer test: the expected digest below was computed
    /// independently of this codebase (via .NET `SHA256` in PowerShell and
    /// cross-checked with `sha256sum`) over the literal bytes
    /// `"GENESIS" + canonical_json`, where `canonical_json` is the exact
    /// string pinned by `canonical_json_shape_is_frozen` above.
    ///
    /// The two tests fail together on a shape change but catch different
    /// bugs: this one also covers `hex_encode` and the `prev_hash ||
    /// canonical` concatenation order, neither of which the shape test
    /// touches. The other tests only compare this function's output against
    /// itself and would stay green through either defect.
    #[test]
    fn known_answer_genesis_hash() {
        let expected = "8d16aeafa3d69b740a7c3f293a151753fe3b5b67f0c8620212df6668e0c6ffe0";
        let actual = compute_hash(GENESIS_PREV_HASH, &golden_entry_minimal()).unwrap();
        assert_eq!(actual, expected);
    }

    /// The property the golden vector protects, asserted end to end: a row
    /// written to disk and read back through the same path `verify` uses
    /// re-derives its stored hash exactly. This is what breaks silently for
    /// *historical* rows if `ToolCallEntry` gains a field.
    #[test]
    fn stored_row_rehashes_to_its_stored_hash() {
        let path = temp_db_path("rehash");
        let mut conn = open_db(&path).unwrap();
        insert_row(&mut conn, &golden_entry_populated()).unwrap();

        let rows = read_all_rows(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        let recomputed = compute_hash(GENESIS_PREV_HASH, &row.entry).unwrap();
        assert_eq!(
            recomputed, row.hash,
            "a row read back from disk must re-derive its stored hash"
        );

        cleanup(conn, &path);
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
        remove_db_files(&path);
    }

    #[test]
    fn last_hash_is_genesis_on_empty_table_and_tracks_inserts() {
        let path = temp_db_path("chain");
        let mut conn = open_db(&path).unwrap();

        assert_eq!(last_hash(&conn).unwrap(), GENESIS_PREV_HASH);

        let h1 = insert_row(&mut conn, &sample_entry()).unwrap();
        assert_eq!(last_hash(&conn).unwrap(), h1);

        let h2 = insert_row(&mut conn, &sample_entry()).unwrap();
        assert_eq!(last_hash(&conn).unwrap(), h2);
        assert_ne!(
            h1, h2,
            "identical entries chained after a different prev_hash must differ"
        );

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
        remove_db_files(&path);
    }

    /// Writer-side losses must reach the same tally as submit-side ones.
    /// A failed INSERT used to warn and move on, so `dropped_count` read
    /// zero while rows went missing — the alarm covered one of the three
    /// ways entries vanish. Simulated here by removing the table out from
    /// under the writer; in production this is lock contention between
    /// processes sharing a database, which is the recommended deployment.
    #[test]
    fn writer_side_insert_failures_are_counted() {
        let path = temp_db_path("writer_drops");
        let (db, writer) = spawn_writer(&path).unwrap();

        // A second connection, so the writer's own connection stays valid
        // and it is the INSERT that fails rather than the open.
        let saboteur = open_db(&path).unwrap();
        saboteur.execute("DROP TABLE tool_calls", []).unwrap();
        drop(saboteur);

        for _ in 0..5 {
            db.log(sample_entry());
        }
        drop(db);

        let outcome = writer.wait_for_drain(std::time::Duration::from_secs(30));
        assert_eq!(
            outcome,
            DrainOutcome::Drained { dropped: 5 },
            "every entry the writer failed to insert must be counted, not just warned about"
        );

        remove_db_files(&path);
    }

    /// The drain is bounded so a wedged write can't hold shutdown open
    /// while a service manager counts down to a kill.
    #[test]
    fn wait_for_drain_gives_up_instead_of_hanging() {
        let (done_tx, done_rx) = sync_channel::<()>(1);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(30));
            let _ = done_tx.send(());
        });
        let writer = DbWriter {
            handle,
            done: done_rx,
            tally: DropTally::default(),
        };

        let started = std::time::Instant::now();
        let outcome = writer.wait_for_drain(std::time::Duration::from_millis(100));

        assert_eq!(outcome, DrainOutcome::TimedOut { dropped: 0 });
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "must return on the bound, not wait for the writer"
        );
    }

    #[test]
    fn drop_tally_is_shared_between_clones() {
        let a = DropTally::default();
        let b = a.clone();
        assert_eq!(a.record(), 0);
        assert_eq!(b.record(), 1);
        assert_eq!(a.count(), 2, "both sides must increment one tally");
    }

    /// An unopenable database must fail at startup, not become a session
    /// that proxies traffic while recording nothing. The open used to
    /// happen on the writer thread, where its failure was invisible to the
    /// caller and unrecordable anywhere else — there is no way to write "I
    /// could not record anything" into the database that would not open.
    #[test]
    fn spawn_writer_refuses_to_start_when_the_database_cannot_be_opened() {
        // A directory is not a database file, so SQLite cannot open it.
        let dir =
            std::env::temp_dir().join(format!("auditmcp_test_notadb_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();

        assert!(
            spawn_writer(&dir).is_err(),
            "an unopenable db must be a startup error, not a silent degradation"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression test for silent audit-log data loss. Before `DbWriter`
    /// existed the writer thread was detached, so entries still queued when
    /// the process exited were discarded with no error and no warning —
    /// measured at 88 of 500 rows lost in a burst. Every entry accepted by
    /// `log` must reach disk once the writer has been joined.
    #[test]
    fn every_queued_entry_reaches_disk_after_join() {
        let path = temp_db_path("writer_join");
        let (db, writer) = spawn_writer(&path).unwrap();

        const N: usize = 500;
        for i in 0..N {
            let mut entry = sample_entry();
            entry.tool_name = format!("tool_{i}");
            db.log(entry);
        }

        // Exactly the shutdown sequence `proxy::run` performs.
        drop(db);
        assert_eq!(
            writer.wait_for_drain(std::time::Duration::from_secs(30)),
            DrainOutcome::Drained { dropped: 0 }
        );

        let conn = open_db(&path).unwrap();
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM tool_calls", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, N as i64, "no queued entry may be lost at shutdown");

        // The chain must also be intact across the whole burst, not merely
        // the right number of rows.
        assert_eq!(verify_chain(&conn).unwrap(), Ok(N));

        cleanup(conn, &path);
    }

    #[test]
    fn verify_succeeds_on_untampered_chain() {
        let path = temp_db_path("verify_ok");
        let mut conn = open_db(&path).unwrap();
        seed_chain(&mut conn, 5);

        let result = verify_chain(&conn).unwrap();
        assert_eq!(result, Ok(5));

        cleanup(conn, &path);
    }

    #[test]
    fn verify_fails_and_identifies_tampered_row() {
        let path = temp_db_path("verify_tamper");
        let mut conn = open_db(&path).unwrap();
        let ids = seed_chain(&mut conn, 5);
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
        let mut conn = open_db(&path).unwrap();
        let ids = seed_chain(&mut conn, 5);
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

    fn entry_with_flags(flags: &str) -> ToolCallEntry {
        let mut entry = sample_entry();
        entry.redaction_flags = Some(flags.to_string());
        entry.redaction_count = 1;
        entry
    }

    const TEST_FLAGS: &str =
        r#"[{"pattern":"openai_api_key","severity":"high","sha256":"aaaa1111bbbb2222cccc3333"}]"#;

    #[test]
    fn insert_row_projects_redactions_in_same_transaction_and_consistency_passes() {
        let path = temp_db_path("redactions_project");
        let mut conn = open_db(&path).unwrap();

        insert_row(&mut conn, &entry_with_flags(TEST_FLAGS)).unwrap();

        let (pattern, sha): (String, String) = conn
            .query_row("SELECT pattern, secret_sha256 FROM redactions", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(pattern, "openai_api_key");
        assert_eq!(sha, "aaaa1111bbbb2222cccc3333");

        assert!(check_redaction_consistency(&conn).unwrap().is_empty());
        cleanup(conn, &path);
    }

    #[test]
    fn consistency_check_detects_index_row_missing() {
        let path = temp_db_path("drift_missing");
        let mut conn = open_db(&path).unwrap();
        insert_row(&mut conn, &entry_with_flags(TEST_FLAGS)).unwrap();

        conn.execute("DELETE FROM redactions", []).unwrap();

        let drift = check_redaction_consistency(&conn).unwrap();
        assert_eq!(drift.len(), 1);
        assert!(
            drift[0].detail.contains("missing from index"),
            "got: {}",
            drift[0].detail
        );
        cleanup(conn, &path);
    }

    #[test]
    fn consistency_check_detects_extra_index_row() {
        let path = temp_db_path("drift_extra");
        let mut conn = open_db(&path).unwrap();
        // A row with NO redactions at all, plus a stray index entry
        // pointing at it.
        insert_row(&mut conn, &sample_entry()).unwrap();
        let id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO redactions (tool_call_id, pattern, severity, secret_sha256) VALUES (?1, 'x', 'low', 'ffff')",
            params![id],
        )
        .unwrap();

        let drift = check_redaction_consistency(&conn).unwrap();
        assert_eq!(drift.len(), 1);
        assert_eq!(drift[0].tool_call_id, id);
        assert!(
            drift[0]
                .detail
                .contains("in index but not in redaction_flags"),
            "got: {}",
            drift[0].detail
        );
        cleanup(conn, &path);
    }

    #[test]
    fn unparseable_redaction_flags_fails_open_and_is_reported_as_drift() {
        let path = temp_db_path("drift_unparseable");
        let mut conn = open_db(&path).unwrap();

        // Primary insert must still succeed (fail-open) even though the
        // projection can't parse this...
        insert_row(&mut conn, &entry_with_flags("not valid json")).unwrap();
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM tool_calls", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1);
        let idx: i64 = conn
            .query_row("SELECT COUNT(*) FROM redactions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(idx, 0);

        // ...and the resulting drift must be visible to the check.
        let drift = check_redaction_consistency(&conn).unwrap();
        assert_eq!(drift.len(), 1);
        assert!(
            drift[0].detail.contains("not parseable"),
            "got: {}",
            drift[0].detail
        );
        cleanup(conn, &path);
    }

    /// The exact same secret value appearing twice in the SAME field must
    /// come out as "2 expected, 2 found in index" — consistent — not get
    /// deduplicated into false drift. Goes through the real detection path
    /// (`secrets::scan_and_redact_json`) rather than hand-written flags, so
    /// it also pins down that detection reports one hit per occurrence.
    #[test]
    fn duplicate_secret_in_same_field_is_not_false_drift() {
        let path = temp_db_path("dup_secret");
        let mut conn = open_db(&path).unwrap();

        let patterns = crate::secrets::PatternSet::bundled().unwrap();
        let mut args = serde_json::json!({
            "api_key": "primary sk-FAKE1234567890abcdefFAKEKEYFAKE00 backup sk-FAKE1234567890abcdefFAKEKEYFAKE00"
        });
        let hits = crate::secrets::scan_and_redact_json(&mut args, &patterns, &HashSet::new());

        let active: Vec<_> = hits.iter().filter(|h| !h.allowlisted).collect();
        assert_eq!(
            active.len(),
            2,
            "two occurrences must be two hits, got {}",
            active.len()
        );
        assert_eq!(
            active[0].secret_sha256, active[1].secret_sha256,
            "same value must hash identically"
        );

        // Mirror proxy.rs's RedactionRecord shape when building the flags.
        let records: Vec<serde_json::Value> = active
            .iter()
            .map(|h| {
                serde_json::json!({"pattern": h.pattern_name, "severity": &h.severity, "sha256": h.secret_sha256})
            })
            .collect();
        let mut entry = sample_entry();
        entry.args_json = Some(args.to_string());
        entry.redaction_flags = Some(serde_json::to_string(&records).unwrap());
        entry.redaction_count = active.len() as i64;
        insert_row(&mut conn, &entry).unwrap();

        let indexed: i64 = conn
            .query_row("SELECT COUNT(*) FROM redactions", [], |r| r.get(0))
            .unwrap();
        assert_eq!(indexed, 2, "index must hold one row per occurrence");
        assert!(
            check_redaction_consistency(&conn).unwrap().is_empty(),
            "2 identical triples expected vs 2 found must NOT be reported as drift"
        );

        // And prove it's counting, not deduplicating: with one of the two
        // identical index rows gone, "2 expected, 1 found" IS drift.
        conn.execute(
            "DELETE FROM redactions WHERE id = (SELECT MIN(id) FROM redactions)",
            [],
        )
        .unwrap();
        let drift = check_redaction_consistency(&conn).unwrap();
        assert_eq!(drift.len(), 1);
        assert!(
            drift[0].detail.contains("missing from index"),
            "got: {}",
            drift[0].detail
        );

        cleanup(conn, &path);
    }

    /// `(id, hash, prev_hash)` for every row, for proving a repair left the
    /// chain byte-identical.
    fn all_hashes(conn: &Connection) -> Vec<(i64, String, Option<String>)> {
        let mut stmt = conn
            .prepare("SELECT id, hash, prev_hash FROM tool_calls ORDER BY id")
            .unwrap();
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap();
        rows.map(|r| r.unwrap()).collect()
    }

    #[test]
    fn repair_plan_is_a_dry_run_and_writes_nothing() {
        let path = temp_db_path("repair_dry");
        let mut conn = open_db(&path).unwrap();
        insert_row(&mut conn, &entry_with_flags(TEST_FLAGS)).unwrap();
        conn.execute("DELETE FROM redactions", []).unwrap();

        let plan = plan_redaction_repair(&conn).unwrap();
        assert_eq!(plan.actions.len(), 1);
        assert_eq!(plan.actions[0].add.len(), 1);
        assert!(plan.actions[0].remove.is_empty());

        // Planning must not have written anything: the drift is still there.
        assert_eq!(check_redaction_consistency(&conn).unwrap().len(), 1);
        cleanup(conn, &path);
    }

    #[test]
    fn repair_restores_consistency_and_leaves_hash_chain_untouched() {
        let path = temp_db_path("repair_apply");
        let mut conn = open_db(&path).unwrap();
        insert_row(&mut conn, &entry_with_flags(TEST_FLAGS)).unwrap();
        insert_row(&mut conn, &sample_entry()).unwrap();

        let hashes_before = all_hashes(&conn);

        // Corrupt the index in both directions: a legitimate row deleted,
        // and a bogus extra pointing at the redaction-free second call.
        conn.execute("DELETE FROM redactions", []).unwrap();
        conn.execute(
            "INSERT INTO redactions (tool_call_id, pattern, severity, secret_sha256) VALUES (2, 'bogus', 'low', 'ffff')",
            [],
        )
        .unwrap();
        assert_eq!(check_redaction_consistency(&conn).unwrap().len(), 2);

        let plan = apply_redaction_repair(&conn).unwrap();
        assert_eq!(plan.actions.len(), 2);
        assert!(plan.unrepairable.is_empty());

        // Consistency restored...
        assert!(check_redaction_consistency(&conn).unwrap().is_empty());
        // ...and the chain provably untouched: stored hashes byte-identical
        // AND full verification still passes.
        assert_eq!(all_hashes(&conn), hashes_before);
        assert_eq!(verify_chain(&conn).unwrap(), Ok(2));
        cleanup(conn, &path);
    }

    /// Regression test for the class of bug where detection fires (so
    /// `redaction_flags` records the hit and `query --verbose` reports it)
    /// but the redacted content never makes it into the persisted row --
    /// the stored JSON and the redaction metadata must never diverge.
    /// Runs the REAL response pipeline (`audit::build_entry`: detect →
    /// escalate → redact → render) on a parsed JSON-RPC response, inserts
    /// through the real write path, and then asserts on the raw string
    /// read back OUT of SQLite -- not on any in-memory value. The secret
    /// is embedded mid-sentence under a key literally named "text" (not a
    /// secret-shaped field name, not the whole field), so nothing about
    /// the shape hands detection the answer.
    #[test]
    fn secret_in_sentence_is_redacted_in_the_actual_stored_row() {
        let path = temp_db_path("stored_redaction");
        let mut conn = open_db(&path).unwrap();

        let secret = "sk-FAKE1234567890abcdefFAKEKEYFAKE00";
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":7,"result":{{"content":[{{"text":"here is a totally real config value: api_key={secret}","type":"text"}}],"isError":false}}}}"#
        );
        let msg: crate::jsonrpc::RpcMessage = serde_json::from_str(&line).unwrap();

        let call = crate::session::PendingCall {
            tool_name: "leak_secret".to_string(),
            args: None,
            bytes_in: 0,
            started: std::time::Instant::now(),
        };
        let patterns = crate::secrets::PatternSet::bundled().unwrap();
        let (entry, _dest) = crate::audit::build_entry(
            call,
            crate::audit::CallOutcome::from_rpc(&msg, line.len() as i64),
            "sess-test",
            "fake_server",
            crate::config::Tier::Standard,
            &patterns,
            &HashSet::new(),
        );
        insert_row(&mut conn, &entry).unwrap();

        let (stored_result, stored_flags): (String, String) = conn
            .query_row(
                "SELECT result_json, redaction_flags FROM tool_calls",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();

        // BOTH sides, from the same stored row: the metadata records the
        // hit AND the content actually reflects the redaction.
        assert!(
            stored_flags.contains("openai_api_key"),
            "flags must record the hit: {stored_flags}"
        );
        assert!(
            stored_result.contains("[REDACTED:openai_api_key]"),
            "stored result_json must contain the redaction marker: {stored_result}"
        );
        assert!(
            !stored_result.contains(secret),
            "plaintext secret must not appear anywhere in the stored row: {stored_result}"
        );
        assert!(
            !stored_result.contains("FAKEKEY"),
            "no fragment of the secret may survive in the stored row: {stored_result}"
        );

        cleanup(conn, &path);
    }

    #[test]
    fn repair_reports_unparseable_flags_as_unrepairable() {
        let path = temp_db_path("repair_unparseable");
        let mut conn = open_db(&path).unwrap();
        insert_row(&mut conn, &entry_with_flags("not valid json")).unwrap();

        let plan = apply_redaction_repair(&conn).unwrap();
        assert!(plan.actions.is_empty());
        assert_eq!(plan.unrepairable.len(), 1);

        // The drift stays visible afterwards rather than being silently
        // swallowed — there was no source of truth to rebuild from.
        assert_eq!(check_redaction_consistency(&conn).unwrap().len(), 1);
        cleanup(conn, &path);
    }

    /// Multiple concurrent writers against one shared DB file must produce
    /// ONE linear chain — never a fork (two rows claiming the same
    /// prev_hash).
    ///
    /// Fidelity of the simulation: each thread opens its OWN
    /// `rusqlite::Connection` to the same file. We don't use SQLite's
    /// shared-cache mode, so separate connections coordinate purely through
    /// file-level locking — the exact same mechanism two separate
    /// `auditmcp run` OS processes would use. Threads-with-own-connections
    /// therefore exercises the identical SQLite code path as real
    /// processes; the only thing it can't reproduce is a mid-write process
    /// kill, which is a durability question (WAL's job), not this race.
    ///
    /// The barrier releases all writers at once to maximize the window for
    /// the old read-modify-write race: under the pre-fix code (head read
    /// outside the write lock), this test reliably produced duplicate
    /// prev_hash values / LinkBroken. Under BEGIN IMMEDIATE with the head
    /// read inside the transaction, a fork is impossible by construction:
    /// only the write-lock holder can read the head, and it commits its
    /// new row before any other writer gets to read.
    #[test]
    fn concurrent_writers_produce_one_linear_chain_never_a_fork() {
        const WRITERS: usize = 4;
        const ROWS_PER_WRITER: usize = 25;

        let path = temp_db_path("concurrent");
        // Create the DB/schema up front so the threads race purely on the
        // insert path (schema creation is idempotent but racing it is not
        // what this test is about).
        let setup = open_db(&path).unwrap();
        drop(setup);

        let barrier = Arc::new(std::sync::Barrier::new(WRITERS));
        let mut handles = Vec::new();
        for w in 0..WRITERS {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                let mut conn = open_db(&path).unwrap();
                barrier.wait();
                for i in 0..ROWS_PER_WRITER {
                    let mut entry = sample_entry();
                    entry.server_name = Some(format!("server_{w}"));
                    entry.tool_name = format!("writer{w}_call{i}");
                    entry.session_id = format!("sess-{w}");
                    // unwrap on purpose: SQLITE_BUSY leaking through the
                    // busy_timeout would fail the test rather than silently
                    // shrinking the row count.
                    insert_row(&mut conn, &entry).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let conn = open_db(&path).unwrap();

        // Nothing dropped, and the full chain walk passes: every row's
        // prev_hash equals the actual hash of the row before it, so the
        // interleaved writers formed one straight line.
        assert_eq!(verify_chain(&conn).unwrap(), Ok(WRITERS * ROWS_PER_WRITER));

        // And the direct anti-fork assertion, independent of the walk: a
        // fork means two rows share a parent, i.e. a duplicate prev_hash.
        // With N rows there must be N distinct parents (genesis included).
        let distinct_parents: i64 = conn
            .query_row(
                "SELECT COUNT(DISTINCT COALESCE(prev_hash, 'GENESIS')) FROM tool_calls",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            distinct_parents as usize,
            WRITERS * ROWS_PER_WRITER,
            "duplicate prev_hash found: two rows claim the same parent — the chain forked"
        );

        cleanup(conn, &path);
    }

    /// Regression test for the cold-start race: several `auditmcp run`
    /// processes launching simultaneously against a shared db_path that
    /// does not exist yet. The first thing they contend on is `open_db`'s
    /// `PRAGMA journal_mode=WAL` (converting a fresh DB to WAL takes a
    /// brief exclusive lock, and SQLite acquires it WITHOUT consulting the
    /// busy handler — so busy_timeout alone doesn't cover it). Before
    /// open_db's manual retry loop, the losing process got an instant
    /// "database is locked", and fail-open then dropped its entire
    /// session's audit entries. Caught live in a two-process smoke test.
    #[test]
    fn concurrent_cold_start_open_all_succeed() {
        const OPENERS: usize = 4;
        let path = temp_db_path("cold_start");
        // No setup connection: the path must not exist yet — racing the
        // very first creation/WAL-conversion is the point.

        let barrier = Arc::new(std::sync::Barrier::new(OPENERS));
        let mut handles = Vec::new();
        for w in 0..OPENERS {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let mut conn = open_db(&path).expect("open_db must survive a cold-start race");
                let mut entry = sample_entry();
                entry.tool_name = format!("opener_{w}");
                insert_row(&mut conn, &entry).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let conn = open_db(&path).unwrap();
        assert_eq!(verify_chain(&conn).unwrap(), Ok(OPENERS));
        cleanup(conn, &path);
    }

    /// A shared DB holds rows from multiple logical servers interleaved by
    /// arrival order. `verify` must (a) pass on such a chain — the chain
    /// links row N to row N-1 by hash regardless of which server either
    /// row came from — and (b) still pinpoint tampering on it. Written by
    /// two separate connections alternating turns, mirroring how two
    /// proxies' rows actually land in a shared DB.
    #[test]
    fn verify_walks_interleaved_multi_server_chain() {
        let path = temp_db_path("interleaved");
        let mut conn_a = open_db(&path).unwrap();
        let mut conn_b = open_db(&path).unwrap();

        for i in 0..8 {
            let (conn, server, session) = if i % 2 == 0 {
                (&mut conn_a, "vault_reader", "sess-a")
            } else {
                (&mut conn_b, "web_fetcher", "sess-b")
            };
            let mut entry = sample_entry();
            entry.server_name = Some(server.to_string());
            entry.session_id = session.to_string();
            entry.tool_name = format!("tool_{i}");
            insert_row(conn, &entry).unwrap();
        }
        drop(conn_b);

        assert_eq!(verify_chain(&conn_a).unwrap(), Ok(8));

        // Cross-server linkage is real, not incidental: each row's
        // prev_hash is the hash of a row from the OTHER server.
        let cross_links: i64 = conn_a
            .query_row(
                "SELECT COUNT(*) FROM tool_calls c
                 JOIN tool_calls p ON c.prev_hash = p.hash
                 WHERE c.server_name != p.server_name",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            cross_links, 7,
            "every non-genesis row must chain to the other server's row"
        );

        // Tampering one server's row is still caught on the mixed chain.
        conn_a
            .execute("UPDATE tool_calls SET status = 'error' WHERE id = 4", [])
            .unwrap();
        match verify_chain(&conn_a).unwrap() {
            Err(ChainIssue::ContentTampered { id, .. }) => assert_eq!(id, 4),
            other => panic!("expected ContentTampered at id 4, got {other:?}"),
        }

        cleanup(conn_a, &path);
    }
}
