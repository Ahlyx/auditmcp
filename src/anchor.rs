//! Phase 3.5 external anchor: an append-only JSONL mini-log, itself an HMAC
//! chain, stored outside the audit database. Its job is to give `verify` a
//! second, independent witness of "the chain reached at least this row,
//! with at least this hash, as of this timestamp" -- one that lives in a
//! different file (and can be copied elsewhere) so a whole-database
//! truncate-and-replace attack has to also find and rewrite the anchor to
//! stay undetected.
//!
//! **Fail-open, deliberately weaker than the main chain.** An anchor write
//! failure (permission denied, disk full, a locked file) is warned about
//! and the proxy keeps running -- see the module-level fail-open contract
//! in the Phase 3.5 spec. This is audit hardening, not a gateway: nothing
//! here may ever block a `tools/call`.
//!
//! **Genesis sentinel.** The first anchor entry's `prev_anchor_hmac` is
//! 64 `'0'` characters -- an all-zero hex string the same length as every
//! other `anchor_hmac`, chosen (rather than an empty string or a named
//! marker) so every field in a genesis entry round-trips through the same
//! "64 lowercase hex chars" validation as every other entry; there is no
//! separate code path for "this is the first line."

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::Write;
use std::path::{Path, PathBuf};

fn genesis_prev_anchor_hmac() -> String {
    "0".repeat(64)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnchorEntry {
    pub timestamp: String,
    pub chain_last_id: i64,
    pub chain_last_hash: String,
    pub prev_anchor_hmac: String,
    pub anchor_hmac: String,
}

/// The exact byte sequence `anchor_hmac` is computed over: `timestamp ||
/// chain_last_id || chain_last_hash || prev_anchor_hmac`, each field
/// separated by `\0` so no ambiguity is possible between e.g. a
/// `chain_last_id` of `1` followed by hash `"23..."` and an id of `12`
/// followed by hash `"3..."` (JSON canonicalization doesn't apply here
/// since this isn't hashing a struct -- these are the four scalar values
/// named directly in the spec).
fn canonical_bytes(timestamp: &str, chain_last_id: i64, chain_last_hash: &str, prev_anchor_hmac: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(timestamp.as_bytes());
    buf.push(0);
    buf.extend_from_slice(chain_last_id.to_string().as_bytes());
    buf.push(0);
    buf.extend_from_slice(chain_last_hash.as_bytes());
    buf.push(0);
    buf.extend_from_slice(prev_anchor_hmac.as_bytes());
    buf
}

fn compute_anchor_hmac(
    anchor_key: &[u8; 32],
    timestamp: &str,
    chain_last_id: i64,
    chain_last_hash: &str,
    prev_anchor_hmac: &str,
) -> anyhow::Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(anchor_key)
        .map_err(|e| anyhow::anyhow!("failed to initialize anchor HMAC: {e}"))?;
    mac.update(&canonical_bytes(timestamp, chain_last_id, chain_last_hash, prev_anchor_hmac));
    let digest = mac.finalize().into_bytes();
    Ok(hex_encode(&digest))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// The per-platform default anchor path, used when `[anchor].path` is
/// empty in the config.
///
/// - Linux:   `${XDG_STATE_HOME:-$HOME/.local/state}/auditmcp/anchor.log`
/// - macOS:   `~/Library/Application Support/auditmcp/anchor.log`
/// - Windows: `%LOCALAPPDATA%\auditmcp\anchor.log`
pub fn default_anchor_path() -> anyhow::Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("LOCALAPPDATA")
            .ok_or_else(|| anyhow::anyhow!("%LOCALAPPDATA% is not set; cannot resolve the default anchor path"))?;
        Ok(PathBuf::from(base).join("auditmcp").join("anchor.log"))
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")
            .ok_or_else(|| anyhow::anyhow!("$HOME is not set; cannot resolve the default anchor path"))?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("auditmcp")
            .join("anchor.log"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = std::env::var_os("XDG_STATE_HOME") {
            return Ok(PathBuf::from(xdg).join("auditmcp").join("anchor.log"));
        }
        let home = std::env::var_os("HOME")
            .ok_or_else(|| anyhow::anyhow!("$HOME is not set; cannot resolve the default anchor path"))?;
        Ok(PathBuf::from(home)
            .join(".local")
            .join("state")
            .join("auditmcp")
            .join("anchor.log"))
    }
}

/// Resolves the configured anchor path, or the platform default if
/// `configured_path` is empty (the `[anchor].path = ""` convention).
pub fn resolve_anchor_path(configured_path: &str) -> anyhow::Result<PathBuf> {
    if configured_path.is_empty() {
        default_anchor_path()
    } else {
        crate::keys::expand_tilde(configured_path)
    }
}

/// Reads the last line of the anchor file (if any) to get the previous
/// entry's `anchor_hmac`, so the next entry can chain from it. `None` means
/// "no anchor file yet, or it's empty" -- the caller uses the genesis
/// sentinel in that case.
fn last_anchor_hmac(path: &Path) -> anyhow::Result<Option<String>> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(anyhow::anyhow!("failed to read anchor file {}: {e}", path.display())),
    };
    let last_line = content.lines().rev().find(|l| !l.trim().is_empty());
    match last_line {
        None => Ok(None),
        Some(line) => {
            let entry: AnchorEntry = serde_json::from_str(line)
                .map_err(|e| anyhow::anyhow!("last line of anchor file is not valid JSON: {e}"))?;
            Ok(Some(entry.anchor_hmac))
        }
    }
}

/// Appends one anchor entry, chaining from the file's last recorded
/// `anchor_hmac` (or the genesis sentinel if the file is new/empty).
///
/// Write-then-rename is deliberately NOT used here, unlike the
/// temp-file-then-rename pattern this codebase uses for atomic exports: an
/// anchor file is append-only and grows forever, so replacing the whole
/// file on every five-minute tick would mean re-writing an ever-larger
/// file each time. This opens with `O_APPEND` (`.append(true)`) instead,
/// which POSIX and Windows both guarantee is atomic for a single `write()`
/// of a size below the platform's atomic-write limit (comfortably true for
/// one JSON line), so two writers appending concurrently interleave whole
/// lines, never torn ones, without needing a rename step at all.
pub fn append_entry(
    path: &Path,
    anchor_key: &[u8; 32],
    chain_last_id: i64,
    chain_last_hash: &str,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| anyhow::anyhow!("failed to create anchor directory {}: {e}", parent.display()))?;
    }

    let prev_anchor_hmac = last_anchor_hmac(path)?.unwrap_or_else(genesis_prev_anchor_hmac);
    let timestamp = chrono::Utc::now().to_rfc3339();
    let anchor_hmac = compute_anchor_hmac(anchor_key, &timestamp, chain_last_id, chain_last_hash, &prev_anchor_hmac)?;

    let entry = AnchorEntry {
        timestamp,
        chain_last_id,
        chain_last_hash: chain_last_hash.to_string(),
        prev_anchor_hmac,
        anchor_hmac,
    };
    let line = serde_json::to_string(&entry)
        .map_err(|e| anyhow::anyhow!("failed to serialize anchor entry: {e}"))?;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| anyhow::anyhow!("failed to open anchor file {}: {e}", path.display()))?;
    writeln!(file, "{line}").map_err(|e| anyhow::anyhow!("failed to append to anchor file {}: {e}", path.display()))?;

    Ok(())
}

/// Reads every entry in the anchor file, in file order. `Ok(vec![])` if the
/// file doesn't exist -- an anchor that was never written is not itself an
/// error (see the fail-open contract: `verify` reports this, doesn't fail
/// on it).
pub fn read_entries(path: &Path) -> anyhow::Result<Vec<AnchorEntry>> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(anyhow::anyhow!("failed to read anchor file {}: {e}", path.display())),
    };
    let mut entries = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AnchorEntry = serde_json::from_str(line)
            .map_err(|e| anyhow::anyhow!("anchor file {} line {}: not valid JSON: {e}", path.display(), i + 1))?;
        entries.push(entry);
    }
    Ok(entries)
}

/// One broken link in the anchor's own internal HMAC chain.
#[derive(Debug, PartialEq)]
pub struct AnchorIssue {
    pub line: usize,
    pub detail: String,
}

impl std::fmt::Display for AnchorIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "anchor entry at line {}: {}", self.line, self.detail)
    }
}

/// Walks the anchor's internal HMAC chain and confirms every entry's
/// `anchor_hmac` recomputes correctly and chains from the entry before it.
/// Returns the first broken link found, matching `db::verify_chain`'s
/// "report the first issue" contract.
pub fn verify_anchor_chain(entries: &[AnchorEntry], anchor_key: &[u8; 32]) -> Option<AnchorIssue> {
    let mut expected_prev = genesis_prev_anchor_hmac();
    for (i, entry) in entries.iter().enumerate() {
        if entry.prev_anchor_hmac != expected_prev {
            return Some(AnchorIssue {
                line: i + 1,
                detail: format!(
                    "prev_anchor_hmac mismatch: expected {}, found {}",
                    expected_prev, entry.prev_anchor_hmac
                ),
            });
        }
        let recomputed = match compute_anchor_hmac(
            anchor_key,
            &entry.timestamp,
            entry.chain_last_id,
            &entry.chain_last_hash,
            &entry.prev_anchor_hmac,
        ) {
            Ok(h) => h,
            Err(e) => {
                return Some(AnchorIssue {
                    line: i + 1,
                    detail: format!("failed to recompute anchor_hmac: {e}"),
                })
            }
        };
        if recomputed != entry.anchor_hmac {
            return Some(AnchorIssue {
                line: i + 1,
                detail: format!(
                    "anchor_hmac mismatch: expected {recomputed}, stored {}",
                    entry.anchor_hmac
                ),
            });
        }
        expected_prev = entry.anchor_hmac.clone();
    }
    None
}

/// Cross-checks each anchor entry against the actual chain: the row it
/// names must exist and its stored `hash` must match `chain_last_hash`.
/// Returns every mismatch found (not just the first), since these are
/// independent claims about independent rows.
pub fn verify_anchor_against_chain(entries: &[AnchorEntry], chain_rows: &[crate::db::StoredRow]) -> Vec<String> {
    let mut issues = Vec::new();
    for entry in entries {
        match chain_rows.iter().find(|r| r.id == entry.chain_last_id) {
            None => issues.push(format!(
                "anchor entry at {} references chain row id {}, which no longer exists",
                entry.timestamp, entry.chain_last_id
            )),
            Some(row) if row.hash != entry.chain_last_hash => issues.push(format!(
                "anchor entry at {} references chain row id {} with hash {}, but the row's \
                 current hash is {}",
                entry.timestamp, entry.chain_last_id, entry.chain_last_hash, row.hash
            )),
            Some(_) => {}
        }
    }
    issues
}

/// Runs until aborted (the caller aborts this task at shutdown -- same
/// pattern as `heartbeat::run`). Each tick reads the current chain tail
/// from the database (a plain read-only open, not routed through the
/// writer thread) and appends one anchor entry. Fail-open per the module
/// doc: any failure here is a warning, never a panic or a way to stop the
/// proxy.
pub async fn run(db_path: PathBuf, anchor_path: PathBuf, anchor_key: [u8; 32], cadence_secs: u64) {
    let cadence = std::time::Duration::from_secs(cadence_secs.max(1));
    loop {
        tokio::time::sleep(cadence).await;

        let tail = match crate::db::open_readonly(&db_path).and_then(|conn| last_real_row(&conn)) {
            Ok(Some(t)) => t,
            Ok(None) => continue, // nothing logged yet; nothing to anchor
            Err(e) => {
                tracing::warn!("anchor: failed to read chain tail: {e}");
                continue;
            }
        };

        if let Err(e) = append_entry(&anchor_path, &anchor_key, tail.0, &tail.1) {
            tracing::warn!("anchor: failed to write anchor entry (continuing to proxy): {e}");
        }
    }
}

/// `(id, hash)` of the last row in `tool_calls`, or `None` if the table is
/// empty. Not filtered to non-synthetic rows -- the anchor's job is to
/// witness the chain's actual tail, whatever kind of row that is.
fn last_real_row(conn: &rusqlite::Connection) -> anyhow::Result<Option<(i64, String)>> {
    conn.query_row(
        "SELECT id, hash FROM tool_calls ORDER BY id DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(|e| anyhow::anyhow!("failed to read chain tail: {e}"))
}

use rusqlite::OptionalExtension;

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_anchor_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!("auditmcp_test_anchor_{label}_{}.log", uuid::Uuid::new_v4()))
    }

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn first_entry_chains_from_the_genesis_sentinel() {
        let path = temp_anchor_path("genesis");
        append_entry(&path, &key(1), 1, "hash1").unwrap();

        let entries = read_entries(&path).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].prev_anchor_hmac, genesis_prev_anchor_hmac());
        assert_eq!(entries[0].chain_last_id, 1);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn successive_entries_chain_from_the_previous_anchor_hmac() {
        let path = temp_anchor_path("chain");
        append_entry(&path, &key(1), 1, "hash1").unwrap();
        append_entry(&path, &key(1), 2, "hash2").unwrap();

        let entries = read_entries(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].prev_anchor_hmac, entries[0].anchor_hmac);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn intact_anchor_chain_verifies_clean() {
        let path = temp_anchor_path("verify_clean");
        append_entry(&path, &key(2), 1, "h1").unwrap();
        append_entry(&path, &key(2), 2, "h2").unwrap();
        append_entry(&path, &key(2), 3, "h3").unwrap();

        let entries = read_entries(&path).unwrap();
        assert!(verify_anchor_chain(&entries, &key(2)).is_none());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn rewritten_anchor_entry_is_detected() {
        let path = temp_anchor_path("tamper");
        append_entry(&path, &key(3), 1, "h1").unwrap();
        append_entry(&path, &key(3), 2, "h2").unwrap();

        let mut entries = read_entries(&path).unwrap();
        entries[0].chain_last_hash = "forged".to_string();

        let issue = verify_anchor_chain(&entries, &key(3));
        assert!(issue.is_some());
        assert_eq!(issue.unwrap().line, 1);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn wrong_anchor_key_fails_verification() {
        let path = temp_anchor_path("wrong_key");
        append_entry(&path, &key(4), 1, "h1").unwrap();
        let entries = read_entries(&path).unwrap();

        assert!(verify_anchor_chain(&entries, &key(9)).is_some());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_anchor_file_reads_as_empty_not_an_error() {
        let path = temp_anchor_path("missing");
        let entries = read_entries(&path).unwrap();
        assert!(entries.is_empty());
    }

    fn stored_row(id: i64, hash: &str) -> crate::db::StoredRow {
        crate::db::StoredRow {
            id,
            entry: crate::db::test_support::sample_entry(),
            hash: hash.to_string(),
            prev_hash: None,
        }
    }

    #[test]
    fn anchor_matching_the_chain_reports_no_issues() {
        let entries = vec![AnchorEntry {
            timestamp: "t".to_string(),
            chain_last_id: 5,
            chain_last_hash: "abc".to_string(),
            prev_anchor_hmac: genesis_prev_anchor_hmac(),
            anchor_hmac: "irrelevant".to_string(),
        }];
        let rows = vec![stored_row(5, "abc")];
        assert!(verify_anchor_against_chain(&entries, &rows).is_empty());
    }

    #[test]
    fn anchor_referencing_a_deleted_row_is_reported() {
        let entries = vec![AnchorEntry {
            timestamp: "t".to_string(),
            chain_last_id: 5,
            chain_last_hash: "abc".to_string(),
            prev_anchor_hmac: genesis_prev_anchor_hmac(),
            anchor_hmac: "irrelevant".to_string(),
        }];
        let issues = verify_anchor_against_chain(&entries, &[]);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("no longer exists"));
    }

    #[test]
    fn anchor_referencing_a_row_with_a_different_hash_is_reported() {
        let entries = vec![AnchorEntry {
            timestamp: "t".to_string(),
            chain_last_id: 5,
            chain_last_hash: "abc".to_string(),
            prev_anchor_hmac: genesis_prev_anchor_hmac(),
            anchor_hmac: "irrelevant".to_string(),
        }];
        let rows = vec![stored_row(5, "different")];
        let issues = verify_anchor_against_chain(&entries, &rows);
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("current hash is different"));
    }
}
