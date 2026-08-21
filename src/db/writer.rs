//! The async writer thread: the bounded channel a `DbHandle` submits
//! entries into, the dedicated OS thread that drains it into SQLite (one
//! `BEGIN IMMEDIATE` transaction per row -- see `insert_row_with_key`), and
//! the shutdown-time drain (`DbWriter::wait_for_drain`).
//!
//! Split out of `db.rs` because this is a distinct concern from schema/
//! connection management, the hash chain itself, and the redaction-repair
//! index -- each has its own file in this directory (see `db/mod.rs`).

use super::chain_hash::{last_hash, HashKey, GENESIS_PREV_HASH};
use super::redaction_repair::insert_redaction_rows;
use super::{open_db, ToolCallEntry};
use rusqlite::{params, Connection, TransactionBehavior};
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
// Every production write path now goes through `insert_row_with_key`
// (Phase 3.5), which needs a `HashKey` decided by `chain::bootstrap`. This
// plain-legacy wrapper has no production caller left -- it exists solely
// so the large pre-Phase-3.5 test suite, pinned to unkeyed SHA-256 golden
// hashes, needs no changes. `#[cfg(test)]` says that plainly instead of
// leaving it looking like unused production code.
#[cfg(test)]
pub(crate) fn insert_row(conn: &mut Connection, entry: &ToolCallEntry) -> anyhow::Result<String> {
    insert_row_with_key(conn, entry, &HashKey::Legacy)
}

/// Same as `insert_row`, but hashes under the given `HashKey` -- `Legacy`
/// for a pre-Phase-3.5 chain, `Hmac` for one bootstrapped under Phase 3.5.
/// `insert_row` is kept as a thin `Legacy`-only wrapper (rather than being
/// replaced by this everywhere) so the large existing Phase 1-3 test suite,
/// which is pinned to plain unkeyed SHA-256 golden hashes, needs no changes.
pub(crate) fn insert_row_with_key(
    conn: &mut Connection,
    entry: &ToolCallEntry,
    hash_key: &HashKey,
) -> anyhow::Result<String> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| anyhow::anyhow!("failed to begin insert transaction: {e}"))?;

    // Safe to read now and only now: the IMMEDIATE BEGIN above means we
    // hold the write lock, so no other process can move the head between
    // this read and our COMMIT.
    let prev_hash = last_hash(&tx)?;
    let hash = hash_key.compute(&prev_hash, entry)?;

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

/// Handle held by the proxy to submit entries for logging without ever
/// blocking on disk I/O. Cloneable and cheap — it's a bounded channel
/// sender plus a shared drop counter.
#[derive(Clone)]
pub struct DbHandle {
    sender: SyncSender<ToolCallEntry>,
    dropped: DropTally,
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
                let prev = self.dropped.record();
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
                self.dropped.record();
                tracing::warn!("audit log entry dropped, writer unavailable");
            }
        }
    }
}

/// Tally of entries that will never reach disk, shared by every path that
/// can lose one.
///
/// It exists as a single type precisely because it used to not be. Only the
/// queue-full path incremented a counter; a dead writer and a failed INSERT
/// warned and moved on, so the count read zero while rows went missing two
/// of the three ways they can. An alarm that covers some of the failures it
/// claims to cover is worse than no alarm, because it is trusted.
///
/// Cloned into both the submitting side (`DbHandle`) and the writer thread,
/// so there is one number and it means "entries this session did not
/// record".
#[derive(Clone, Default)]
pub struct DropTally(Arc<AtomicU64>);

impl DropTally {
    /// Records one lost entry, returning how many had already been lost
    /// before it. Callers use that to throttle their own warnings — a
    /// sustained backlog must not turn logging about dropped entries into
    /// its own performance problem.
    pub(crate) fn record(&self) -> u64 {
        self.0.fetch_add(1, Ordering::Relaxed)
    }

    pub fn count(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// How shutdown went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrainOutcome {
    /// The writer finished; `dropped` entries were lost during the session.
    Drained { dropped: u64 },
    /// The writer did not finish within the bound. Whatever was still
    /// queued is lost and is *not* included in `dropped`, because it was
    /// never handed to a path that could count it — the queue holds no
    /// accessible length. Reported as its own outcome rather than folded
    /// into the count, so it can't be mistaken for a clean drain.
    TimedOut { dropped: u64 },
}

/// Owns the writer thread so a caller can wait for the queue to be
/// written out before the process ends.
///
/// Without this the thread is detached, and a detached writer loses a race
/// it cannot win: the queue is drained on a background thread while the
/// process is tearing down, so whatever is still queued when the process
/// exits is silently gone. Measured on this codebase before the join
/// existed: of 500 tool calls logged in a burst, 412 rows reached disk and
/// 88 did not, with no error and no warning. Rows written near process
/// exit are the most exposed, which includes every `timeout` row, since
/// those are written after the target has already exited.
///
/// An audit log that quietly discards entries under load is a worse
/// failure than one that admits it, so this is deliberately a blocking
/// join rather than a best-effort sleep.
pub struct DbWriter {
    pub(crate) handle: std::thread::JoinHandle<()>,
    /// Signalled when the writer thread ends, by an explicit send and again
    /// by the sender dropping — so a panicking writer still reports
    /// finished rather than pinning shutdown until the timeout.
    pub(crate) done: Receiver<()>,
    pub(crate) tally: DropTally,
}

impl DbWriter {
    /// Waits, up to `timeout`, for every queued entry to be written.
    ///
    /// **All `DbHandle`s must be dropped first.** The writer loop ends when
    /// its channel closes, which happens only when the last sender goes
    /// away; waiting while one is still alive would burn the whole timeout
    /// and then report a spurious `TimedOut`. `proxy::run` drops its handle
    /// immediately before calling this, and the pump task's clone is
    /// already gone because that task has been awaited to completion.
    ///
    /// The bound matters at shutdown specifically: this runs while a
    /// service manager is counting down its own patience (systemd's
    /// `TimeoutStopSec`, the SCM's stop timeout), and a write wedged on a
    /// locked database must not turn a stop into a kill. Losing the tail of
    /// the queue and saying so beats hanging.
    pub fn wait_for_drain(self, timeout: std::time::Duration) -> DrainOutcome {
        let dropped = match self.done.recv_timeout(timeout) {
            // Explicit send, or the sender dropped with the thread: either
            // way the writer is finished and the queue is written out.
            Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                // Now safe: the thread is already ending, so this returns
                // promptly. A panicking writer logged and continued (see
                // `writer_loop`), so there is nothing further to report.
                let _ = self.handle.join();
                return DrainOutcome::Drained {
                    dropped: self.tally.count(),
                };
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => self.tally.count(),
        };
        // Deliberately not joined: the thread is still working and joining
        // would reintroduce the unbounded wait this method exists to avoid.
        // The process is ending anyway.
        DrainOutcome::TimedOut { dropped }
    }
}

/// Opens the audit database and spawns the dedicated writer thread,
/// returning a handle to submit entries plus the `DbWriter` used to wait
/// for it at shutdown. A plain OS thread (not a tokio task) because
/// rusqlite's `Connection` is synchronous; this keeps blocking disk I/O off
/// the tokio runtime entirely, which is what "async, buffered writes" means
/// in practice here — the proxy never awaits a DB call.
///
/// **The open happens here, on the calling thread, so that failing to open
/// the database is a startup error rather than a silent condition.** It
/// used to happen on the writer thread, which meant an unopenable database
/// produced a proxy that forwarded every tool call while recording nothing
/// — presenting as an audit tool and providing none of one. Fail-open
/// exists to keep the proxy from becoming a blocking dependency of work in
/// flight; at startup nothing is in flight, so there is nothing to protect
/// and the honest response is to refuse.
///
/// It is also the one degradation that cannot be recorded in-band: "I could
/// not record anything" is unwritable to the database that would not open,
/// so there is no way to tell the user later and the obligation moves to
/// telling them now.
///
/// Every production caller now goes through `spawn_writer_with_key` (Phase
/// 3.5, both `run` and `serve`), which needs a `HashKey` decided by
/// `chain::bootstrap`. This plain-legacy wrapper has no production caller
/// left -- it exists solely so tests that don't care about HMAC keying
/// (transport tests, mostly) don't each have to bootstrap one. `#[cfg(test)]`
/// says that plainly instead of leaving it looking like unused production
/// code.
#[cfg(test)]
pub(crate) fn spawn_writer(db_path: &Path) -> anyhow::Result<(DbHandle, DbWriter)> {
    spawn_writer_with_key(db_path, HashKey::Legacy)
}

/// Same as `spawn_writer`, but every row the writer thread inserts is
/// hashed under the given `HashKey` rather than always the legacy scheme.
/// This is what `chain::bootstrap`'s decision (fresh HMAC chain vs.
/// existing legacy chain) actually gets wired to at runtime.
pub fn spawn_writer_with_key(
    db_path: &Path,
    hash_key: HashKey,
) -> anyhow::Result<(DbHandle, DbWriter)> {
    let conn = open_db(db_path)?;
    let (tx, rx) = sync_channel::<ToolCallEntry>(CHANNEL_CAPACITY);
    let (done_tx, done_rx) = sync_channel::<()>(1);
    let tally = DropTally::default();

    let writer_tally = tally.clone();
    let handle = std::thread::spawn(move || {
        writer_loop(conn, rx, writer_tally, hash_key);
        let _ = done_tx.send(());
    });

    Ok((
        DbHandle {
            sender: tx,
            dropped: tally.clone(),
        },
        DbWriter {
            handle,
            done: done_rx,
            tally,
        },
    ))
}

/// Runs on the dedicated writer thread. Every failure mode here is
/// logged-and-continued, never a panic: with `panic = "abort"` set in the
/// release profile, a panic on this thread would abort the *entire*
/// process, taking the proxied session down with it — exactly what
/// fail-open logging must not do.
fn writer_loop(
    mut conn: Connection,
    rx: Receiver<ToolCallEntry>,
    dropped: DropTally,
    hash_key: HashKey,
) {
    // No "database unavailable" branch here any more: `spawn_writer` opens
    // the connection before this thread exists, so reaching this function
    // means the database is open. A proxy that runs while recording nothing
    // is refused at startup instead (see `spawn_writer`).

    // Deliberately NO in-memory prev_hash cache here (there used to be
    // one). Other `auditmcp run` processes may share this db_path, so the
    // chain head can move between our inserts — the only head that's safe
    // to chain against is the one `insert_row` reads under its own write
    // lock. The cost is one indexed point query per insert, noise next to
    // the SHA-256 and the disk write.
    for entry in rx.iter() {
        let tool_name = entry.tool_name.clone();
        if let Err(e) = insert_row_with_key(&mut conn, &entry, &hash_key) {
            // Counted, not just warned. This is a genuine loss -- the
            // transaction rolled back, so the chain is intact but shorter
            // than the calls that happened -- and it is the loss path most
            // likely under the deployment this project recommends, where
            // several processes share one database and contend for the
            // write lock.
            dropped.record();
            tracing::warn!("failed to write audit log entry for tool '{tool_name}': {e}");
        }
    }
}
