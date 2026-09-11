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

use crate::hex::hex_encode;
use hmac::{Hmac, Mac};
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::io::{Read, Seek, SeekFrom, Write};
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
fn canonical_bytes(
    timestamp: &str,
    chain_last_id: i64,
    chain_last_hash: &str,
    prev_anchor_hmac: &str,
) -> Vec<u8> {
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
    mac.update(&canonical_bytes(
        timestamp,
        chain_last_id,
        chain_last_hash,
        prev_anchor_hmac,
    ));
    let digest = mac.finalize().into_bytes();
    Ok(hex_encode(&digest))
}

/// Resolves the anchor path already finalized by `Config::load`.
pub fn resolve_anchor_path(configured_path: &str) -> anyhow::Result<PathBuf> {
    if configured_path.is_empty() {
        Err(anyhow::anyhow!(
            "anchor path was not resolved while loading configuration"
        ))
    } else {
        crate::keys::expand_tilde(configured_path)
    }
}

/// How far back from the end of the file `last_anchor_hmac` reads. The
/// anchor is read on every tick for the lifetime of a session; reading the
/// whole append-only file each time is O(file) forever, while the chaining
/// value only ever lives in the last line.
const TAIL_WINDOW_BYTES: u64 = 64 * 1024;

/// Reads the last COMPLETE line of the anchor file (if any) to get the
/// previous entry's `anchor_hmac`, so the next entry can chain from it.
/// `None` means "no anchor file yet, or it's empty" -- the caller uses the
/// genesis sentinel in that case.
///
/// A trailing PARTIAL line (a process killed or a disk-full error landing
/// mid-`writeln!`) is ignored rather than fatal: treating a torn write as
/// permanent corruption wedged every future anchor tick forever, silently
/// disabling the second witness while the proxy kept reporting healthy.
/// Only a complete-but-unparseable last line is an error -- that is
/// evidence of tampering, not of an interrupted write.
fn last_anchor_hmac(path: &Path) -> anyhow::Result<Option<String>> {
    let mut file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "failed to read anchor file {}: {e}",
                path.display()
            ))
        }
    };
    let len = file.metadata()?.len();
    let start = len.saturating_sub(TAIL_WINDOW_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let tail = read_tail_lossy(&mut file)
        .map_err(|e| anyhow::anyhow!("failed to read anchor file {}: {e}", path.display()))?;

    // Drop a trailing fragment that was never newline-terminated: it is by
    // definition an incomplete write. Then take the last non-empty line.
    let complete = match tail.rfind('\n') {
        Some(cut) => &tail[..cut],
        None => "",
    };
    let last_line = complete.lines().rev().find(|l| !l.trim().is_empty());
    match last_line {
        None => Ok(None),
        Some(line) => {
            let entry: AnchorEntry = serde_json::from_str(line)
                .map_err(|e| anyhow::anyhow!("last line of anchor file is not valid JSON: {e}"))?;
            Ok(Some(entry.anchor_hmac))
        }
    }
}

/// If the file's last byte is not `\n`, truncate the unterminated trailing
/// fragment away (back to the last complete line). A no-op on a clean,
/// empty, or not-yet-existing file. Only ever removes bytes after the final
/// newline, so no complete entry can be lost.
fn repair_torn_tail(path: &Path) -> anyhow::Result<()> {
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(f) => f,
        // Nothing to repair yet.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "failed to open anchor file {}: {e}",
                path.display()
            ))
        }
    };
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(());
    }
    file.seek(SeekFrom::Start(len - 1))?;
    let mut last = [0u8; 1];
    file.read_exact(&mut last)?;
    if last[0] == b'\n' {
        return Ok(());
    }

    // Find where the last complete line ends, within the tail window.
    let start = len.saturating_sub(TAIL_WINDOW_BYTES);
    file.seek(SeekFrom::Start(start))?;
    let tail = read_tail_lossy(&mut file)?;
    match tail.rfind('\n') {
        Some(pos) => {
            let keep = start + pos as u64 + 1;
            tracing::warn!(
                "anchor file {} ended in a partial line (interrupted write); \
                 truncating {} trailing byte(s) before appending",
                path.display(),
                len - keep
            );
            file.set_len(keep)?;
        }
        None => {
            tracing::warn!(
                "anchor file {} has no complete line in its tail window; \
                 leaving it untouched for `verify` to report",
                path.display()
            );
        }
    }
    Ok(())
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
///
/// **Chaining is serialized across processes with a lock file.** Atomic
/// appends prevent torn lines but not broken links: two sessions sharing a
/// `db_path` (the documented multi-server setup) would each read the same
/// tail, both chain from it, and produce two entries claiming the same
/// `prev_anchor_hmac` -- a permanent false-positive mismatch in `verify`.
///
/// The lock is held only around read-tail/compute/append. It is fail-open:
/// if it cannot be acquired within a few seconds -- a wedged live holder,
/// say -- this tick's append is SKIPPED with a warning and retried on the
/// next cadence tick, exactly like every other anchor write failure.
/// A crashed writer's stale lock file is force-broken after
/// `LOCK_STALE_AFTER`.
pub fn append_entry(
    path: &Path,
    anchor_key: &[u8; 32],
    chain_last_id: i64,
    chain_last_hash: &str,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            anyhow::anyhow!(
                "failed to create anchor directory {}: {e}",
                parent.display()
            )
        })?;
    }

    let _lock = AnchorLock::acquire(path)?;

    // Repair a torn tail left by a crash or disk-full landing mid-writeln!
    // BEFORE chaining: drop the unterminated trailing fragment so this
    // entry chains from the last COMPLETE entry and the file returns to
    // one-entry-per-line. Without this, the next tick would append after
    // the fragment -- turning it into permanent mid-file garbage that every
    // later read trips over.
    repair_torn_tail(path)?;
    let prev_anchor_hmac = last_anchor_hmac(path)?.unwrap_or_else(genesis_prev_anchor_hmac);
    let timestamp = chrono::Utc::now().to_rfc3339();
    let anchor_hmac = compute_anchor_hmac(
        anchor_key,
        &timestamp,
        chain_last_id,
        chain_last_hash,
        &prev_anchor_hmac,
    )?;

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
    writeln!(file, "{line}")
        .map_err(|e| anyhow::anyhow!("failed to append to anchor file {}: {e}", path.display()))?;

    Ok(())
}

/// Reads from the current position to EOF as text, replacing any invalid
/// UTF-8 rather than failing.
///
/// The two callers seek to `len - TAIL_WINDOW_BYTES`, an arbitrary byte
/// offset that can land in the middle of a multi-byte character -- or
/// inside garbage appended by a partially-successful tamper, or a
/// disk-corrupted region. `read_to_string` rejects that with `InvalidData`,
/// and in `repair_torn_tail` the error propagated unmapped, so every
/// subsequent anchor tick failed and the second witness went permanently
/// silent while the proxy still reported healthy. Byte positions are what
/// matter here -- the callers split on newlines and parse whole lines -- so
/// a replacement character in a window prefix is harmless: a mangled line
/// fails JSON parsing, which is reported, instead of disabling the anchor.
fn read_tail_lossy(file: &mut std::fs::File) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// How long `AnchorLock::acquire` waits for another process's live lock
/// before proceeding without it -- fail-open, per the module contract.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(5);
/// Age at which a lock file is presumed abandoned by a dead process and
/// force-removed rather than waited on.
const LOCK_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(10);

/// Advisory lock serializing the anchor's read-modify-append cycle across
/// processes. Held via RAII: dropping removes the file -- but only if the
/// file still carries THIS lock's token.
///
/// The token matters. Stale-lock takeover cannot be made a single atomic
/// step, so two processes can both decide a lock is stale; without an
/// owner check, the second one's `remove_file` deletes the lock the first
/// had just created, both then believe they hold it, and they append
/// entries chaining from the same `prev_anchor_hmac` -- a permanent
/// `AnchorChainBroken` that no later append can heal. The same applies on
/// the way out: a holder whose lock was force-broken would otherwise
/// delete its successor's lock when it drops.
struct AnchorLock {
    path: PathBuf,
    token: String,
}

impl AnchorLock {
    fn acquire(anchor_path: &Path) -> anyhow::Result<Self> {
        let lock_path = anchor_path.with_extension(
            anchor_path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!("{e}.lock"))
                .unwrap_or_else(|| "lock".to_string()),
        );
        let token = uuid::Uuid::new_v4().to_string();
        let deadline = std::time::Instant::now() + LOCK_WAIT;
        loop {
            match std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&lock_path)
            {
                Ok(mut f) => {
                    // Best-effort: a lock whose token cannot be written is
                    // still exclusive (create_new won it), it just cannot
                    // be proven ours later, so `drop` leaves it to go stale
                    // rather than risk deleting a successor's.
                    let _ = f.write_all(token.as_bytes());
                    return Ok(AnchorLock {
                        path: lock_path,
                        token,
                    });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => {
                    return Err(anyhow::anyhow!(
                        "failed to create anchor lock {}: {e}",
                        lock_path.display()
                    ))
                }
            }
            // Someone else holds it. Break a stale lock outright; otherwise
            // wait, then give up and proceed unlocked.
            let stale = std::fs::metadata(&lock_path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|modified| modified.elapsed().ok())
                .is_some_and(|age| age > LOCK_STALE_AFTER);
            if stale {
                // Take it over by RENAMING, not removing: rename is atomic
                // and names a specific file, so if two processes both see
                // the lock as stale exactly one rename succeeds and the
                // loser gets NotFound instead of silently deleting whatever
                // the winner has since created.
                let claimed = lock_path.with_extension(format!("stale-{token}"));
                if std::fs::rename(&lock_path, &claimed).is_ok() {
                    let _ = std::fs::remove_file(&claimed);
                }
                continue;
            }
            if std::time::Instant::now() >= deadline {
                tracing::warn!(
                    "anchor: could not acquire {} within {:?}; appending without \
                     the cross-process lock (verify may report a prev_anchor_hmac \
                     mismatch if another session appends concurrently)",
                    lock_path.display(),
                    LOCK_WAIT
                );
                return Err(anyhow::anyhow!("anchor lock busy"));
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

impl Drop for AnchorLock {
    fn drop(&mut self) {
        // Only remove a lock that is still ours. If our lock was declared
        // stale and taken over, the file now belongs to another process and
        // deleting it would hand a third process a lock the second still
        // thinks it holds.
        match std::fs::read_to_string(&self.path) {
            Ok(on_disk) if on_disk.trim() == self.token => {
                let _ = std::fs::remove_file(&self.path);
            }
            _ => {}
        }
    }
}

/// Reads every entry in the anchor file, in file order. `Ok(vec![])` if the
/// file doesn't exist -- an anchor that was never written is not itself an
/// error (see the fail-open contract: `verify` reports this, doesn't fail
/// on it).
///
/// A trailing PARTIAL line (no newline at EOF, not parseable) is a torn
/// write -- a crash or disk-full landing mid-`writeln!` -- and is skipped,
/// because hard-failing here conflated "crashed mid-write" with tampering
/// and made every subsequent `verify` report a healthy-but-anchored log as
/// broken forever. Any complete line failing to parse, or a torn-looking
/// line anywhere but the end of the file, is still an error: that is
/// evidence of editing, not of interruption.
pub fn read_entries(path: &Path) -> anyhow::Result<Vec<AnchorEntry>> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(anyhow::anyhow!(
                "failed to read anchor file {}: {e}",
                path.display()
            ))
        }
    };
    let ends_clean = content.ends_with('\n');
    let mut entries = Vec::new();
    for (i, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: AnchorEntry = match serde_json::from_str(line) {
            Ok(e) => e,
            // Only the final line can be a legitimate torn write (no
            // newline after it); anything else failing to parse is
            // mid-file damage and stays an error.
            Err(_) if i + 1 == content.lines().count() && !ends_clean => {
                tracing::warn!(
                    "anchor file {} ends in a partial line (interrupted write); \
                     it is skipped and chaining continues from the last complete entry",
                    path.display()
                );
                break;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "anchor file {} line {}: not valid JSON: {e}",
                    path.display(),
                    i + 1
                ))
            }
        };
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
pub fn verify_anchor_against_chain(
    entries: &[AnchorEntry],
    chain_rows: &[crate::db::StoredRow],
) -> Vec<String> {
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

        let tail = match crate::db::open_readonly(&db_path).and_then(|conn| last_chain_row(&conn)) {
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
fn last_chain_row(conn: &rusqlite::Connection) -> anyhow::Result<Option<(i64, String)>> {
    conn.query_row(
        "SELECT id, hash FROM tool_calls ORDER BY id DESC LIMIT 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )
    .optional()
    .map_err(|e| anyhow::anyhow!("failed to read chain tail: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_anchor_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "auditmcp_test_anchor_{label}_{}.log",
            uuid::Uuid::new_v4()
        ))
    }

    fn key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    /// A non-ASCII byte in the tail window used to make `read_to_string`
    /// fail with InvalidData, which `repair_torn_tail` propagated unmapped
    /// -- permanently disabling every later anchor tick while the proxy
    /// still looked healthy.
    #[test]
    fn a_non_utf8_byte_in_the_tail_does_not_disable_the_anchor() {
        let path = temp_anchor_path("bad_utf8");
        append_entry(&path, &key(1), 1, "hash1").unwrap();

        // Garbage appended after a complete line, as a partially-successful
        // tamper or a corrupted region would leave it.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            f.write_all(&[0xff, 0xfe, 0x80]).unwrap();
        }

        append_entry(&path, &key(1), 2, "hash2")
            .expect("a later tick must still succeed after invalid UTF-8 in the tail");

        let entries = read_entries(&path).unwrap();
        assert_eq!(entries.len(), 2, "both entries should be readable");
        assert_eq!(entries[1].chain_last_id, 2);

        let _ = std::fs::remove_file(&path);
    }

    /// A lock whose owner token does not match must not be removed on drop:
    /// deleting a successor's lock is what produces two writers chaining
    /// from the same `prev_anchor_hmac`.
    #[test]
    fn dropping_a_taken_over_lock_leaves_the_new_owners_lock_alone() {
        let path = temp_anchor_path("lock_owner");
        let lock = AnchorLock::acquire(&path).unwrap();
        let lock_path = lock.path.clone();

        // Simulate takeover: someone else replaced the file's contents.
        std::fs::write(&lock_path, "a-different-owner").unwrap();
        drop(lock);

        assert!(
            lock_path.exists(),
            "the new owner's lock must survive the old holder's drop"
        );
        assert_eq!(
            std::fs::read_to_string(&lock_path).unwrap(),
            "a-different-owner"
        );
        let _ = std::fs::remove_file(&lock_path);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn dropping_our_own_lock_removes_it() {
        let path = temp_anchor_path("lock_own");
        let lock = AnchorLock::acquire(&path).unwrap();
        let lock_path = lock.path.clone();
        assert!(lock_path.exists());
        drop(lock);
        assert!(!lock_path.exists());
        let _ = std::fs::remove_file(&path);
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

    /// A crash mid-`writeln!` leaves a trailing fragment with no newline.
    /// Chaining must continue from the last complete entry rather than
    /// wedging every future anchor tick, and `read_entries` must skip the
    /// fragment instead of reporting a healthy log as permanently broken.
    #[test]
    fn torn_trailing_line_is_tolerated_by_chaining_and_reading() {
        let path = temp_anchor_path("torn_tail");
        append_entry(&path, &key(5), 1, "h1").unwrap();
        append_entry(&path, &key(5), 2, "h2").unwrap();

        // Simulate the torn write: a partial line after the last newline.
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            std::io::Write::write_all(&mut f, b"{\"timestamp\":\"2026-").unwrap();
        }

        // The chaining read sees entry 2's hmac, not an error.
        let hmac = last_anchor_hmac(&path).unwrap().expect("entry 2 exists");
        assert_eq!(hmac, read_entries(&path).unwrap()[1].anchor_hmac);

        // And the reader tolerates it too: two complete entries survive.
        let entries = read_entries(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].chain_last_id, 2);

        // A subsequent append chains from the last complete entry and
        // verifies cleanly end to end.
        append_entry(&path, &key(5), 3, "h3").unwrap();
        let entries = read_entries(&path).unwrap();
        assert_eq!(entries.len(), 3);
        assert!(verify_anchor_chain(&entries, &key(5)).is_none());

        std::fs::remove_file(&path).ok();
    }

    /// A COMPLETE but unparseable last line is not a torn write -- that is
    /// tampering -- so both reads must still reject it.
    #[test]
    fn complete_but_corrupt_last_line_is_still_an_error() {
        let path = temp_anchor_path("corrupt_complete");
        append_entry(&path, &key(6), 1, "h1").unwrap();
        std::fs::write(&path, "not json at all\n").unwrap();

        assert!(last_anchor_hmac(&path).is_err());
        assert!(read_entries(&path).is_err());

        std::fs::remove_file(&path).ok();
    }

    /// The cross-process serialization actually works as a lock: while one
    /// holder is alive and fresh, acquisition waits; once released (drop),
    /// the next writer chains correctly from the appended state. The stale-
    /// takeover path is time-based and exercised only implicitly here --
    /// its failure mode is a skipped tick, which is fail-open by design.
    #[test]
    fn append_entry_cleans_up_its_lock_file_and_chains_across_uses() {
        let path = temp_anchor_path("lock");
        append_entry(&path, &key(7), 1, "h1").unwrap();
        append_entry(&path, &key(7), 2, "h2").unwrap();

        let lock_path = path.with_extension("log.lock");
        assert!(
            !lock_path.exists(),
            "the lock file must be removed when each append finishes"
        );

        let entries = read_entries(&path).unwrap();
        assert_eq!(entries[1].prev_anchor_hmac, entries[0].anchor_hmac);

        std::fs::remove_file(&path).ok();
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
