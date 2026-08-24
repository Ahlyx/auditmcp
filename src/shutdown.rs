//! Stop signals and the shutdown timings both transports share.
//!
//! Lives outside `proxy` and `http` because shutting down cleanly is a
//! property of the process, not of a transport: whichever one is running,
//! the audit queue has to reach disk before the process ends, and the wait
//! for it has to be bounded.
//!
//! # The Windows teardown race
//!
//! Tokio's console-control handlers (`ctrl_close`, `ctrl_shutdown`) return
//! immediately after waking their async future -- but for `CTRL_CLOSE`
//! and `CTRL_SHUTDOWN` events, Windows terminates the process once the
//! control handler returns or the ~5s teardown grace expires, whichever
//! comes first. The async path alone therefore races a near-immediate
//! kill, and even a full 10s `DRAIN_TIMEOUT` cannot fit inside the grace.
//! `install_blocking_close_handler` registers an ADDITIONAL handler that
//! blocks inside the grace window (up to [`HANDLER_GRACE`]) until the
//! async drain reports completion via `note_drain_complete`, buying the
//! queue real time to reach disk. Ctrl-C is unaffected either way: it is
//! a console-input event with no forced kill attached.

use std::sync::{Condvar, Mutex, OnceLock};
#[cfg(windows)]
use std::time::Duration;

/// How long the writer gets to finish its queue at shutdown. Generous
/// enough to write a full queue on a slow disk, and comfortably inside the
/// patience of the service managers that will be stopping this process
/// (systemd's `TimeoutStopSec` defaults to 90s; the Windows SCM's stop
/// timeout is on the same order). Being killed mid-drain would lose more
/// than giving up does.
pub(crate) const DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long the response pump gets to finish after the target has been
/// asked to stop. Only reached when a target ignores termination; anything
/// still in flight then is logged as a timeout, not lost.
pub(crate) const PUMP_SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// How long the blocking close/shutdown handler may hold the OS teardown
/// grace open. Windows grants roughly 5 seconds from delivering
/// `CTRL_CLOSE`/`CTRL_SHUTDOWN` to forcibly terminating the process;
/// staying under that bound means the drain gets nearly all of it instead
/// of racing a kill that arrives mid-write.
#[cfg(windows)]
pub(crate) const HANDLER_GRACE: Duration = Duration::from_secs(4);

/// Shared state between the async shutdown path (which knows when the
/// audit queue has reached disk) and the blocking console handler (which
/// must not outlive the OS's patience, but should outlive nothing else).
fn drain_gate() -> &'static (Mutex<bool>, Condvar) {
    static GATE: OnceLock<(Mutex<bool>, Condvar)> = OnceLock::new();
    GATE.get_or_init(|| (Mutex::new(false), Condvar::new()))
}

/// Called by the transport's shutdown path once every queued entry has
/// been written (`Drained`) or given up on (`TimedOut`). Either way there
/// is nothing more the blocking handler should wait for.
pub(crate) fn note_drain_complete() {
    let (lock, cvar) = drain_gate();
    let mut done = lock.lock().unwrap_or_else(|e| e.into_inner());
    *done = true;
    cvar.notify_all();
}

/// Registers the extra blocking console-control handler on Windows; a
/// no-op elsewhere, where POSIX signals carry no teardown deadline.
pub(crate) fn install_blocking_close_handler() {
    #[cfg(windows)]
    unsafe {
        // Best-effort: failure here only means close/shutdown fall back to
        // racing the grace period, exactly as before this existed.
        winapi::um::consoleapi::SetConsoleCtrlHandler(Some(blocking_close_handler), 1);
    }
}

#[cfg(windows)]
unsafe extern "system" fn blocking_close_handler(ctrl_type: u32) -> i32 {
    use winapi::um::wincon::{CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT};
    match ctrl_type {
        // These three come with a forced kill once handlers return (or the
        // grace lapses); holding the gate open is the whole point. Returning
        // nonzero marks them handled, which suppresses other handlers'
        // default-terminate behavior for close/shutdown while tokio's own
        // registration has already woken the async side.
        CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
            let (lock, cvar) = drain_gate();
            let guard = lock.lock().unwrap_or_else(|e| e.into_inner());
            let _ = cvar.wait_timeout_while(guard, HANDLER_GRACE, |done| !*done);
            1
        }
        // Everything else (including Ctrl-C) has no forced kill attached;
        // let it propagate untouched.
        _ => 0,
    }
}

/// Why the proxy is shutting down.
pub(crate) enum Stop {
    TargetExited(std::process::ExitStatus),
    Signal(&'static str),
}

/// Resolves when the process is asked to stop, naming the mechanism.
///
/// Covers the console/POSIX signals a supervisor or a terminal will send.
/// **Not covered: a true Windows Service stop.** The SCM delivers
/// `SERVICE_CONTROL_STOP` to a service control handler, which is not a
/// console control event and cannot be observed from here — wiring that up
/// needs a service dispatcher and belongs with the install/lifecycle work,
/// not here. A plain `net stop` on a service would bypass all of this.
///
/// For console close and system shutdown -- the two events Windows follows
/// with a forced kill -- the blocking handler installed by
/// `install_blocking_close_handler` holds the OS teardown grace open while
/// the drain runs; see the module doc.
///
/// If a handler can't be registered we log and never resolve, rather than
/// refusing to start: being unable to observe a signal is not a reason to
/// decline to audit anything.
pub(crate) async fn shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    "could not install SIGTERM handler ({e}); \
                                a terminated session may not flush its audit log"
                );
                std::future::pending::<()>().await;
                unreachable!()
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "SIGINT (Ctrl-C)",
            _ = term.recv() => "SIGTERM",
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows;
        // Each is a distinct console control event; a supervisor or
        // terminal may use any of them.
        let (mut brk, mut close, mut shutdown) = match (
            windows::ctrl_break(),
            windows::ctrl_close(),
            windows::ctrl_shutdown(),
        ) {
            (Ok(b), Ok(c), Ok(s)) => (b, c, s),
            _ => {
                tracing::warn!(
                    "could not install console control handlers; \
                                    a terminated session may not flush its audit log"
                );
                std::future::pending::<()>().await;
                unreachable!()
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "Ctrl-C",
            _ = brk.recv() => "Ctrl-Break",
            _ = close.recv() => "console close",
            _ = shutdown.recv() => "system shutdown",
        }
    }
}
