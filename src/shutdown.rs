//! Stop signals and the shutdown timings both transports share.
//!
//! Lives outside `proxy` and `http` because shutting down cleanly is a
//! property of the process, not of a transport: whichever one is running,
//! the audit queue has to reach disk before the process ends, and the wait
//! for it has to be bounded.

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
/// not here. `ctrl_shutdown` below catches system shutdown, which is the
/// adjacent case, but a plain `net stop` on a service would bypass all of
/// this.
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
