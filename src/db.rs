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

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::collections::{HashMap, HashSet};
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

    // Load-bearing for MULTI-PROCESS writers (several `auditmcp run`
    // instances sharing one db_path): without a busy timeout, a second
    // writer's `BEGIN IMMEDIATE` (see `insert_row`) fails instantly with
    // SQLITE_BUSY while another process holds the write lock — and since
    // logging is fail-open, that entry would be silently dropped rather
    // than briefly waiting its turn. 5s is far beyond any realistic single
    // insert (sub-millisecond), so hitting this timeout means something is
    // genuinely wedged, at which point failing open is the right call.
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

/// The `hash` of the most recently inserted row, or `GENESIS_PREV_HASH` if
/// the table is empty. This is the "input" form (see `compute_hash` doc),
/// not the raw nullable `prev_hash` column.
///
/// CONCURRENCY: for chaining a new row, this must only be called from
/// inside `insert_row`'s IMMEDIATE transaction. Read outside that
/// transaction, the value can be stale the instant it's returned — another
/// process sharing the db_path may commit a row right after — and chaining
/// against a stale head is exactly the read-modify-write race that forks
/// the chain.
fn last_hash(conn: &Connection) -> anyhow::Result<String> {
    let hash: Option<String> = conn
        .query_row(
            "SELECT hash FROM tool_calls ORDER BY id DESC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| anyhow::anyhow!("failed to read last hash: {e}"))?;

    Ok(hash.unwrap_or_else(|| GENESIS_PREV_HASH.to_string()))
}

/// Atomically reads the current chain head, computes the new row's hash,
/// and inserts it (plus its `redactions` index projection) in ONE exclusive
/// write transaction. Returns the new hash on success.
///
/// CONCURRENCY — this function is what makes a shared db_path across
/// multiple `auditmcp run` processes safe, via two properties that are
/// each necessary and only sufficient together:
///
///  1. `BEGIN IMMEDIATE` (`TransactionBehavior::Immediate`), not SQLite's
///     default deferred `BEGIN`. A deferred transaction takes no write
///     lock until its first write, so two processes could both read the
///     same head, both compute a hash chaining to it, and then serialize
///     only their INSERTs — committing two rows that each claim the same
///     prev_hash (a silent fork; WAL mode does nothing to prevent it).
///     IMMEDIATE acquires the write lock at BEGIN: a second writer blocks
///     at BEGIN (up to the busy_timeout set in `open_db`) until the first
///     COMMITs, and only then gets to read the head — by which point it
///     sees the first writer's row and chains after it.
///
///  2. The head is read HERE, inside the transaction — `last_hash` is not
///     a parameter. Locking alone can't fix a head value that was read
///     before the lock was taken; any caller-supplied prev_hash (like the
///     in-memory cache `writer_loop` used to keep) can be stale the moment
///     another process commits, and inserting with it forks the chain just
///     as surely as the deferred-BEGIN race.
pub(crate) fn insert_row(conn: &mut Connection, entry: &ToolCallEntry) -> anyhow::Result<String> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| anyhow::anyhow!("failed to begin insert transaction: {e}"))?;

    // Safe to read now and only now: the IMMEDIATE BEGIN above means we
    // hold the write lock, so no other process can move the head between
    // this read and our COMMIT.
    let prev_hash = last_hash(&tx)?;
    let hash = compute_hash(&prev_hash, entry)?;

    // GENESIS_PREV_HASH is a hash *input* sentinel only — the stored
    // prev_hash column stays NULL for the first row, matching the schema's
    // "prev_hash TEXT" (nullable) rather than persisting the sentinel text.
    let prev_hash_col: Option<&str> = if prev_hash == GENESIS_PREV_HASH {
        None
    } else {
        Some(prev_hash.as_str())
    };

    // One transaction for the tool_calls row AND its redactions-index
    // projection, so a crash/interruption between the two can never commit
    // one without the other (they used to be two separate autocommits).
    // Two distinct failure modes remain, deliberately:
    //  - transaction-level failure (the tool_calls INSERT errors, or COMMIT
    //    fails): everything rolls back, the caller (writer_loop) logs and
    //    drops the entry — the chain head isn't advanced, so the *next*
    //    entry still chains correctly;
    //  - logical failure inside insert_redaction_rows (unparseable
    //    redaction_flags JSON, or a single redaction INSERT erroring):
    //    fail-open — warn loudly and commit the primary row anyway, since
    //    the audit record must never be lost over a derived index. The
    //    resulting drift is detectable via `auditmcp verify`.
    tx.execute(
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

    if let Some(flags_json) = &entry.redaction_flags {
        // `Transaction` derefs to `Connection`, so these inserts join the
        // same transaction as the row above. Fail-open by design — see the
        // comment on the transaction and on `insert_redaction_rows` itself.
        insert_redaction_rows(&tx, flags_json);
    }

    tx.commit()
        .map_err(|e| anyhow::anyhow!("failed to commit insert transaction: {e}"))?;

    Ok(hash)
}

/// One entry of the `[{"pattern":..,"severity":..,"sha256":..}]` shape
/// `proxy.rs` writes into `redaction_flags` (see its `RedactionRecord`).
#[derive(serde::Deserialize)]
struct RedactionEntry {
    pattern: String,
    severity: String,
    sha256: String,
}

const INSERT_REDACTION_SQL: &str = r#"
INSERT INTO redactions (tool_call_id, pattern, severity, secret_sha256) VALUES (?1, ?2, ?3, ?4)
"#;

/// Fail-open projection into the `redactions` index: any failure here is
/// warned about loudly (stderr, like every other fail-open path) but never
/// propagated, so the primary `tool_calls` row still commits. The warning
/// names the consequence explicitly — index drift, i.e. `unmask` may not
/// resolve this row's hashes — and points at `verify`, which detects drift
/// after the fact (see `check_redaction_consistency`).
fn insert_redaction_rows(conn: &Connection, flags_json: &str) {
    let records: Vec<RedactionEntry> = match serde_json::from_str(flags_json) {
        Ok(records) => records,
        Err(e) => {
            tracing::warn!(
                "redactions index drift: failed to parse redaction_flags for the indexed projection \
                 (the audit row itself is committed and intact, but `unmask` will not resolve this row's \
                 secret hashes; run `auditmcp verify` to see all drifted rows): {e}"
            );
            return;
        }
    };

    let tool_call_id = conn.last_insert_rowid();
    for r in records {
        if let Err(e) = conn.execute(
            INSERT_REDACTION_SQL,
            params![tool_call_id, r.pattern, r.severity, r.sha256],
        ) {
            tracing::warn!(
                "redactions index drift: failed to insert index row for tool_call {tool_call_id} \
                 (the audit row itself is committed and intact, but `unmask` will not resolve this hash; \
                 run `auditmcp verify` to see all drifted rows): {e}"
            );
        }
    }
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

/// One detected mismatch between `tool_calls.redaction_flags` (the source
/// of truth) and the derived `redactions` index for a single tool call.
#[derive(Debug)]
pub struct RedactionDrift {
    pub tool_call_id: i64,
    pub detail: String,
}

/// Compares every row's `redaction_flags` JSON against what's actually in
/// the `redactions` index and reports each mismatch. The index is populated
/// fail-open (see `insert_redaction_rows`), so drift is possible by design
/// — a drifted row's audit record is intact, but `unmask` won't resolve its
/// hashes until the drift is addressed. Read-only; used by `verify`.
///
/// Cost profile matches `verify`'s existing full-table chain walk (this is
/// an offline integrity command, not hot-path code), unlike `unmask`'s
/// resolution, which stays on the indexed lookups above.
pub fn check_redaction_consistency(conn: &Connection) -> anyhow::Result<Vec<RedactionDrift>> {
    let mut state = load_redaction_state(conn)?;
    let mut drift = std::mem::take(&mut state.unparseable);

    for id in state.all_ids() {
        let exp = state
            .expected
            .get(&id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let act = state.actual.get(&id).map(Vec::as_slice).unwrap_or_default();
        let (missing, extra) = diff_triples(exp, act);

        if !missing.is_empty() || !extra.is_empty() {
            let mut parts = Vec::new();
            if !missing.is_empty() {
                parts.push(format!(
                    "missing from index: {}",
                    missing
                        .iter()
                        .map(short_triple)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if !extra.is_empty() {
                parts.push(format!(
                    "in index but not in redaction_flags: {}",
                    extra
                        .iter()
                        .map(short_triple)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            drift.push(RedactionDrift {
                tool_call_id: id,
                detail: parts.join("; "),
            });
        }
    }

    drift.sort_by_key(|d| d.tool_call_id);
    Ok(drift)
}

/// A (pattern, severity, sha256) triple — one redaction hit, as recorded in
/// both `redaction_flags` (the source of truth) and the `redactions` index.
pub type RedactionTriple = (String, String, String);

/// Both sides of the source-of-truth vs. index comparison, loaded once and
/// shared by `check_redaction_consistency` and the repair planner so they
/// can never disagree about what "consistent" means.
struct RedactionState {
    /// Triples each tool_call SHOULD have in the index, per its
    /// `redaction_flags` JSON.
    expected: HashMap<i64, Vec<RedactionTriple>>,
    /// Triples actually present in the `redactions` index.
    actual: HashMap<i64, Vec<RedactionTriple>>,
    /// Rows whose `redaction_flags` isn't parseable JSON: the index can't
    /// be verified against them, and `--repair-index` has no source of
    /// truth to rebuild them from.
    unparseable: Vec<RedactionDrift>,
}

impl RedactionState {
    /// Every tool_call id present on either side, sorted, deduplicated.
    fn all_ids(&self) -> Vec<i64> {
        let mut ids: Vec<i64> = self
            .expected
            .keys()
            .chain(self.actual.keys())
            .copied()
            .collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

fn load_redaction_state(conn: &Connection) -> anyhow::Result<RedactionState> {
    let mut expected: HashMap<i64, Vec<RedactionTriple>> = HashMap::new();
    let mut unparseable: Vec<RedactionDrift> = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT id, redaction_flags FROM tool_calls WHERE redaction_flags IS NOT NULL")
            .map_err(|e| anyhow::anyhow!("failed to prepare redaction_flags scan: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|e| anyhow::anyhow!("failed to scan redaction_flags: {e}"))?;
        for r in rows {
            let (id, raw) =
                r.map_err(|e| anyhow::anyhow!("failed to read redaction_flags row: {e}"))?;
            match serde_json::from_str::<Vec<RedactionEntry>>(&raw) {
                Ok(records) => {
                    expected.insert(
                        id,
                        records
                            .into_iter()
                            .map(|e| (e.pattern, e.severity, e.sha256))
                            .collect(),
                    );
                }
                // Unparseable source JSON is itself reportable drift: the
                // index can't be verified against it, and the write path
                // couldn't have projected it either.
                Err(e) => unparseable.push(RedactionDrift {
                    tool_call_id: id,
                    detail: format!(
                        "redaction_flags is not parseable JSON ({e}); index cannot be verified"
                    ),
                }),
            }
        }
    }

    let mut actual: HashMap<i64, Vec<RedactionTriple>> = HashMap::new();
    {
        let mut stmt = conn
            .prepare("SELECT tool_call_id, pattern, severity, secret_sha256 FROM redactions")
            .map_err(|e| anyhow::anyhow!("failed to prepare redactions scan: {e}"))?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    (
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ),
                ))
            })
            .map_err(|e| anyhow::anyhow!("failed to scan redactions: {e}"))?;
        for r in rows {
            let (id, triple) =
                r.map_err(|e| anyhow::anyhow!("failed to read redactions row: {e}"))?;
            actual.entry(id).or_default().push(triple);
        }
    }

    Ok(RedactionState {
        expected,
        actual,
        unparseable,
    })
}

/// Multiset difference for one tool call: `.0` is what's missing from the
/// index, `.1` what's extra in it. Multiset (not set) on purpose: the same
/// secret can legitimately produce two identical triples in one call —
/// duplicated within args, or appearing in both args and result — so
/// duplicates are counted, never deduplicated away (2 expected vs. 2 found
/// is consistent; 2 expected vs. 1 found is drift).
fn diff_triples(
    expected: &[RedactionTriple],
    actual: &[RedactionTriple],
) -> (Vec<RedactionTriple>, Vec<RedactionTriple>) {
    let mut remaining = actual.to_vec();
    let mut missing = Vec::new();
    for e in expected {
        if let Some(pos) = remaining.iter().position(|a| a == e) {
            remaining.remove(pos);
        } else {
            missing.push(e.clone());
        }
    }
    (missing, remaining)
}

fn short_triple(t: &RedactionTriple) -> String {
    format!("{}({}…)", t.0, &t.2[..t.2.len().min(12)])
}

/// What `verify --repair-index` would do (dry run) or did (apply) for one
/// drifted tool call: insert each `add` triple into the `redactions` index
/// and delete one index row per `remove` triple. Derived purely from
/// `redaction_flags`, so applying it makes the index match the source of
/// truth exactly; index rows that already agree are never touched.
pub struct RepairAction {
    pub tool_call_id: i64,
    pub add: Vec<RedactionTriple>,
    pub remove: Vec<RedactionTriple>,
}

pub struct RepairPlan {
    pub actions: Vec<RepairAction>,
    /// Drifted rows repair cannot fix: their `redaction_flags` doesn't
    /// parse, so there's nothing to rebuild the index from. Their existing
    /// index rows (if any) are left untouched rather than guessed at, and
    /// they remain visible as drift afterwards.
    pub unrepairable: Vec<RedactionDrift>,
}

/// Read-only: computes what `--repair-index` would change, without writing.
/// Shares `load_redaction_state`/`diff_triples` with
/// `check_redaction_consistency`, so a repair fixes exactly what the check
/// reports — nothing more.
pub fn plan_redaction_repair(conn: &Connection) -> anyhow::Result<RepairPlan> {
    let state = load_redaction_state(conn)?;
    let mut actions = Vec::new();

    for id in state.all_ids() {
        let exp = state
            .expected
            .get(&id)
            .map(Vec::as_slice)
            .unwrap_or_default();
        let act = state.actual.get(&id).map(Vec::as_slice).unwrap_or_default();
        let (missing, extra) = diff_triples(exp, act);
        if !missing.is_empty() || !extra.is_empty() {
            actions.push(RepairAction {
                tool_call_id: id,
                add: missing,
                remove: extra,
            });
        }
    }

    Ok(RepairPlan {
        actions,
        unrepairable: state.unparseable,
    })
}

/// Applies the repair plan in ONE transaction, touching ONLY the derived
/// `redactions` table — never `tool_calls`, and therefore never any
/// `hash`/`prev_hash`: the chain is structurally unaffected (and a test
/// proves the stored hashes are byte-identical across a repair). Unlike the
/// hot-path projection this is NOT fail-open: it's an explicit offline
/// command, so any failure rolls the whole repair back and surfaces to the
/// user instead of being warned past.
pub fn apply_redaction_repair(conn: &Connection) -> anyhow::Result<RepairPlan> {
    let plan = plan_redaction_repair(conn)?;
    if plan.actions.is_empty() {
        return Ok(plan);
    }

    let tx = conn
        .unchecked_transaction()
        .map_err(|e| anyhow::anyhow!("failed to begin repair transaction: {e}"))?;

    for action in &plan.actions {
        for t in &action.remove {
            // Deletes exactly ONE matching index row per extra triple: the
            // diff is a multiset, so two identical extras mean two deletes,
            // and a plain `DELETE .. WHERE tool_call_id/pattern/..` would
            // over-delete legitimate duplicates.
            tx.execute(
                "DELETE FROM redactions WHERE id = (
                   SELECT id FROM redactions
                   WHERE tool_call_id = ?1 AND pattern = ?2 AND severity = ?3 AND secret_sha256 = ?4
                   LIMIT 1)",
                params![action.tool_call_id, t.0, t.1, t.2],
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to delete stray index row for tool_call {}: {e}",
                    action.tool_call_id
                )
            })?;
        }
        for t in &action.add {
            tx.execute(
                INSERT_REDACTION_SQL,
                params![action.tool_call_id, t.0, t.1, t.2],
            )
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to insert index row for tool_call {}: {e}",
                    action.tool_call_id
                )
            })?;
        }
    }

    tx.commit()
        .map_err(|e| anyhow::anyhow!("failed to commit repair transaction: {e}"))?;

    Ok(plan)
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
    RowMissing {
        after_id: i64,
        expected_id: i64,
        found_id: i64,
    },
    /// A row's stored `prev_hash` doesn't equal the hash actually produced
    /// by the row immediately before it in the chain we've walked so far.
    /// Catches reordering and direct tampering with the `prev_hash`
    /// column itself.
    LinkBroken {
        id: i64,
        expected_prev_hash: String,
        stored_prev_hash: String,
    },
    /// A row's own hash doesn't match what its stored content (hashed
    /// against its own, valid, prev_hash) recomputes to — i.e. some other
    /// column was edited after the row was written.
    ContentTampered {
        id: i64,
        tool_name: String,
        expected_hash: String,
        stored_hash: String,
    },
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
                    tracing::warn!(
                        "audit log queue still full; {} entries dropped so far",
                        prev + 1
                    );
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
    #[allow(dead_code)]
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

    DbHandle {
        sender: tx,
        dropped: Arc::new(AtomicU64::new(0)),
    }
}

/// Runs on the dedicated writer thread. Every failure mode here is
/// logged-and-continued, never a panic: with `panic = "abort"` set in the
/// release profile, a panic on this thread would abort the *entire*
/// process, taking the proxied session down with it — exactly what
/// fail-open logging must not do.
fn writer_loop(path: &Path, rx: Receiver<ToolCallEntry>) {
    let mut conn = match open_db(path) {
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

    // Deliberately NO in-memory prev_hash cache here (there used to be
    // one). Other `auditmcp run` processes may share this db_path, so the
    // chain head can move between our inserts — the only head that's safe
    // to chain against is the one `insert_row` reads under its own write
    // lock. The cost is one indexed point query per insert, noise next to
    // the SHA-256 and the disk write.
    for entry in rx.iter() {
        let tool_name = entry.tool_name.clone();
        if let Err(e) = insert_row(&mut conn, &entry) {
            tracing::warn!("failed to write audit log entry for tool '{tool_name}': {e}");
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
    /// tell rows apart) and returns their ids in order.
    fn seed_chain(conn: &mut Connection, n: usize) -> Vec<i64> {
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
    /// Runs the REAL response pipeline (`proxy::build_entry`: detect →
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

        let call = crate::proxy::PendingCall {
            tool_name: "leak_secret".to_string(),
            args: None,
            bytes_in: 0,
            started: std::time::Instant::now(),
        };
        let patterns = crate::secrets::PatternSet::bundled().unwrap();
        let entry = crate::proxy::build_entry(
            call,
            &msg,
            line.len() as i64,
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
