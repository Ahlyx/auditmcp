//! The hash-chain itself: per-row hashing (legacy SHA-256 and Phase 3.5's
//! HMAC-SHA256), `chain_metadata` (including its own HMAC -- see
//! `verify_chain_metadata_hmac`), and the full-chain walk `verify` uses.
//!
//! Split out of `db.rs` because this is a distinct concern from schema/
//! connection management, the redaction-repair index, and the writer
//! thread -- each has its own file in this directory (see `db/mod.rs`).

use super::{read_all_rows, ToolCallEntry};
use crate::hex::hex_encode;
use hmac::{Hmac, Mac};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

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

/// `hash = HMAC-SHA256(chain_key, prev_hash || canonical_json(entry))`,
/// hex-encoded. Same canonicalization and prev_hash-input convention as
/// `compute_hash` (see its doc); the only difference is the keyed
/// primitive, which is what makes the chain unforgeable by someone who has
/// database write access but not the key file (Phase 3.5's whole point --
/// see `auditmcp-phase-3.5-chain-hardening.md` for the threat model this
/// defends against).
fn compute_hash_hmac(
    chain_key: &[u8; 32],
    prev_hash: &str,
    entry: &ToolCallEntry,
) -> anyhow::Result<String> {
    let canonical = serde_json::to_string(entry)
        .map_err(|e| anyhow::anyhow!("failed to canonicalize entry for hashing: {e}"))?;

    let mut mac = Hmac::<Sha256>::new_from_slice(chain_key)
        .map_err(|e| anyhow::anyhow!("failed to initialize HMAC: {e}"))?;
    mac.update(prev_hash.as_bytes());
    mac.update(canonical.as_bytes());
    let digest = mac.finalize().into_bytes();

    Ok(hex_encode(&digest))
}

/// Which hashing scheme a chain write or verification uses. `Legacy` is
/// the unkeyed Phase 1-3 SHA-256 chain (see `compute_hash`); `Hmac` is
/// Phase 3.5's keyed chain (see `compute_hash_hmac`). A single database's
/// chain is one or the other for its entire lifetime -- see
/// `chain::bootstrap` and the "No in-place upgrade" section of the Phase
/// 3.5 spec for why there is no in-between state.
#[derive(Clone, Copy)]
pub enum HashKey {
    Legacy,
    Hmac([u8; 32]),
}

impl HashKey {
    pub(crate) fn compute(&self, prev_hash: &str, entry: &ToolCallEntry) -> anyhow::Result<String> {
        match self {
            HashKey::Legacy => compute_hash(prev_hash, entry),
            HashKey::Hmac(key) => compute_hash_hmac(key, prev_hash, entry),
        }
    }
}

/// One `chain_metadata` row's worth of genesis configuration, read back.
/// `hmac_version` is `None` for a legacy (pre-Phase-3.5) chain -- its
/// absence, not a special value, is what marks legacy, matching how the
/// table is documented in `SCHEMA`.
#[derive(Debug, Clone)]
pub struct ChainMetadata {
    pub db_uuid: String,
    pub hmac_version: Option<String>,
    pub heartbeat_cadence_min_secs: Option<u64>,
    pub heartbeat_cadence_max_secs: Option<u64>,
    pub created_at: Option<String>,
}

fn chain_metadata_get(conn: &Connection, key: &str) -> anyhow::Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM chain_metadata WHERE key = ?1",
        params![key],
        |row| row.get(0),
    )
    .optional()
    .map_err(|e| anyhow::anyhow!("failed to read chain_metadata.{key}: {e}"))
}

/// Reads back the chain's genesis configuration, or `None` if this
/// database predates the `chain_metadata` table entirely (an empty, freshly
/// created table also reads back as `None` here via the `db_uuid` check --
/// a chain with no `db_uuid` row has no genesis configuration to speak of).
pub fn read_chain_metadata(conn: &Connection) -> anyhow::Result<Option<ChainMetadata>> {
    let Some(db_uuid) = chain_metadata_get(conn, "db_uuid")? else {
        return Ok(None);
    };
    let hmac_version = chain_metadata_get(conn, "hmac_version")?;
    let heartbeat_cadence_min_secs =
        chain_metadata_get(conn, "heartbeat_cadence_min_secs")?.and_then(|v| v.parse().ok());
    let heartbeat_cadence_max_secs =
        chain_metadata_get(conn, "heartbeat_cadence_max_secs")?.and_then(|v| v.parse().ok());
    let created_at = chain_metadata_get(conn, "created_at")?;

    Ok(Some(ChainMetadata {
        db_uuid,
        hmac_version,
        heartbeat_cadence_min_secs,
        heartbeat_cadence_max_secs,
        created_at,
    }))
}

/// `hmac_version` this build writes at genesis. Named so `write_chain_metadata_genesis`
/// and `compute_metadata_hmac` can't drift apart on the literal.
const CURRENT_HMAC_VERSION: &str = "1";

/// HMAC over the genesis `chain_metadata` fields that matter for chain
/// integrity: `db_uuid` (the HKDF salt), `hmac_version` (which hashing
/// scheme `verify` trusts), and the heartbeat cadence range (genesis-fixed
/// so it can't be widened retroactively to hide a truncation gap -- see
/// `write_chain_metadata_genesis`'s original doc). `chain_metadata` is a
/// plain SQLite table with no hash-chain linkage of its own, so without
/// this, an attacker with database write access could edit any of those
/// values directly -- e.g. flip `hmac_version` to make `run`/`verify` fall
/// back to the unkeyed legacy scheme, or widen `heartbeat_cadence_max_secs`
/// to suppress gap detection -- without touching a single hashed
/// `tool_calls` row, and `verify` would still report a clean chain. Fields
/// are `\0`-separated for the same reason `anchor.rs`'s `canonical_bytes`
/// is: these are scalar values, not a struct being canonically serialized,
/// so ambiguity has to be ruled out by hand.
fn compute_metadata_hmac(
    chain_key: &[u8; 32],
    db_uuid: &str,
    hmac_version: &str,
    heartbeat_cadence_min_secs: u64,
    heartbeat_cadence_max_secs: u64,
) -> anyhow::Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(chain_key)
        .map_err(|e| anyhow::anyhow!("failed to initialize metadata HMAC: {e}"))?;
    mac.update(db_uuid.as_bytes());
    mac.update(&[0]);
    mac.update(hmac_version.as_bytes());
    mac.update(&[0]);
    mac.update(heartbeat_cadence_min_secs.to_string().as_bytes());
    mac.update(&[0]);
    mac.update(heartbeat_cadence_max_secs.to_string().as_bytes());
    Ok(hex_encode(&mac.finalize().into_bytes()))
}

/// Recomputes `chain_metadata`'s own HMAC and compares it to what's stored,
/// so a `chain_metadata` row edited directly (bypassing the `tool_calls`
/// hash chain entirely -- see `compute_metadata_hmac`) is caught the same
/// way a tampered row is. `Ok(false)` both when no `metadata_hmac` was ever
/// written (a chain from before this check existed) and when one was
/// written but doesn't match -- both mean `chain_metadata` cannot be
/// trusted, and callers (`chain::bootstrap`, `verify::run`) treat either as
/// tamper.
pub fn verify_chain_metadata_hmac(
    conn: &Connection,
    chain_key: &[u8; 32],
    metadata: &ChainMetadata,
) -> anyhow::Result<bool> {
    let Some(stored) = chain_metadata_get(conn, "metadata_hmac")? else {
        return Ok(false);
    };
    let hmac_version = metadata.hmac_version.as_deref().unwrap_or_default();
    let expected = compute_metadata_hmac(
        chain_key,
        &metadata.db_uuid,
        hmac_version,
        metadata.heartbeat_cadence_min_secs.unwrap_or(30),
        metadata.heartbeat_cadence_max_secs.unwrap_or(90),
    )?;
    Ok(expected == stored)
}

/// Writes the genesis `chain_metadata` row set for a brand-new HMAC chain,
/// including its own `metadata_hmac` (see `compute_metadata_hmac`). Called
/// exactly once, at the moment a fresh database is initialized -- see
/// `chain::bootstrap`. Never called again afterward: these values are fixed
/// for the chain's lifetime (in particular, the heartbeat cadence range is
/// genesis-fixed specifically so an attacker with DB write access cannot
/// lower the expected cadence retroactively to hide a gap, since doing so
/// would break the HMAC of these very rows).
///
/// All rows commit in ONE transaction: written as separate autocommitted
/// INSERTs, a crash between them (e.g. after `db_uuid` commits but before
/// `hmac_version` does) would leave a database that a key file already
/// exists for but that `chain::bootstrap` reads back as legacy on the next
/// start -- silently downgrading a chain that was meant to be
/// HMAC-protected from row 1.
pub fn write_chain_metadata_genesis(
    conn: &mut Connection,
    chain_key: &[u8; 32],
    db_uuid: &str,
    heartbeat_cadence_min_secs: u64,
    heartbeat_cadence_max_secs: u64,
) -> anyhow::Result<()> {
    let created_at = chrono::Utc::now().to_rfc3339();
    let metadata_hmac = compute_metadata_hmac(
        chain_key,
        db_uuid,
        CURRENT_HMAC_VERSION,
        heartbeat_cadence_min_secs,
        heartbeat_cadence_max_secs,
    )?;
    let entries: [(&str, String); 6] = [
        ("db_uuid", db_uuid.to_string()),
        ("hmac_version", CURRENT_HMAC_VERSION.to_string()),
        (
            "heartbeat_cadence_min_secs",
            heartbeat_cadence_min_secs.to_string(),
        ),
        (
            "heartbeat_cadence_max_secs",
            heartbeat_cadence_max_secs.to_string(),
        ),
        ("created_at", created_at),
        ("metadata_hmac", metadata_hmac),
    ];
    let tx = conn
        .transaction()
        .map_err(|e| anyhow::anyhow!("failed to begin genesis metadata transaction: {e}"))?;
    for (key, value) in entries {
        tx.execute(
            "INSERT INTO chain_metadata (key, value) VALUES (?1, ?2)",
            params![key, value],
        )
        .map_err(|e| anyhow::anyhow!("failed to write chain_metadata.{key}: {e}"))?;
    }
    tx.commit()
        .map_err(|e| anyhow::anyhow!("failed to commit genesis metadata transaction: {e}"))?;
    Ok(())
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
pub(crate) fn last_hash(conn: &Connection) -> anyhow::Result<String> {
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
// See the `#[cfg(test)]` note on `insert_row` in `db/writer.rs` -- same
// reasoning.
#[cfg(test)]
pub fn verify_chain(conn: &Connection) -> anyhow::Result<Result<usize, ChainIssue>> {
    verify_chain_with_key(conn, &HashKey::Legacy)
}

/// Same as `verify_chain`, but recomputes each row's hash under the given
/// `HashKey`. See `insert_row_with_key` for why `verify_chain` stays a
/// thin `Legacy`-only wrapper rather than being replaced by this.
pub fn verify_chain_with_key(
    conn: &Connection,
    hash_key: &HashKey,
) -> anyhow::Result<Result<usize, ChainIssue>> {
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

        let recomputed = hash_key.compute(&stored_prev_hash, &row.entry)?;
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
