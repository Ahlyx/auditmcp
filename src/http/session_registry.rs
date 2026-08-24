//! Per-listener session bookkeeping: opening/closing a session per
//! connection, and the legacy HTTP+SSE endpoint-to-session binding.
//!
//! Split out of `http.rs` because this is a distinct concern from SSE wire
//! parsing (`sse`), the hyper body-streaming plumbing (`tee`), and the
//! top-level proxy orchestration (`server`) -- each has its own file in
//! this directory (see `http/mod.rs`).

use crate::session::{PendingCall, Session};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The sessions of ONE listener.
///
/// Deliberately not a process-wide map keyed by (listener, connection, id):
/// that is the composite key this design rejected, and a single mis-built
/// key there attributes one caller's response to another caller's request
/// in an audit log. Here a listener holds its own registry and hands each
/// connection its own `Session`, so the mistake has no way to be made.
///
/// The mutexes are `std` rather than tokio's on purpose: every critical
/// section below is one map statement with no `.await` inside, so blocking
/// is bounded to nanoseconds -- and keeping these calls synchronous lets
/// hyper body code (`tee.rs`'s `poll_frame`, which cannot await) bind,
/// look up, and release bindings inline instead of spawning tasks whose
/// scheduling order raced the very traffic they were correlating.
#[derive(Default)]
pub(crate) struct SessionRegistry {
    next_id: AtomicU64,
    open: Mutex<HashMap<u64, Arc<Session>>>,
    /// Legacy HTTP+SSE only: the POST endpoint a server advertised, mapped
    /// to the session of the SSE stream that advertised it.
    ///
    /// That transport splits one logical session across two connections --
    /// messages go out on a POST, answers come back on the GET stream --
    /// so correlation cannot be per connection there. Keyed by the
    /// endpoint's path and query, which is what the server chose to
    /// identify the session with and what the client sends back.
    endpoints: Mutex<HashMap<String, Arc<Session>>>,
}

impl SessionRegistry {
    /// Opens a session for one connection. `conn:` records how this
    /// session's identity was derived, because that differs per protocol
    /// generation and a `session_id` that silently means different things
    /// in different rows is worse than one that says which it is.
    pub(crate) fn open(&self) -> (u64, Arc<Session>) {
        let key = self.next_id.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(Session::new(format!("conn:{}", uuid::Uuid::new_v4())));
        Self::lock(&self.open).insert(key, Arc::clone(&session));
        (key, session)
    }

    /// Closes a session and returns any calls left unanswered on it, so the
    /// connection handler can log them rather than let them vanish.
    pub(crate) fn close(&self, key: u64) -> Vec<PendingCall> {
        match Self::lock(&self.open).remove(&key) {
            Some(s) => s.drain_abandoned(),
            None => Vec::new(),
        }
    }

    /// Every session still open, for the shutdown drain.
    pub(crate) fn take_all(&self) -> Vec<Arc<Session>> {
        let mut all: Vec<Arc<Session>> = Self::lock(&self.open).drain().map(|(_, s)| s).collect();
        all.extend(Self::lock(&self.endpoints).drain().map(|(_, s)| s));
        all
    }

    /// Binds a legacy POST endpoint to the session of the stream that
    /// advertised it.
    pub(crate) fn bind_endpoint(&self, key: String, session: Arc<Session>) {
        Self::lock(&self.endpoints).insert(key, session);
    }

    /// The session a legacy POST belongs to, if this path and query was
    /// advertised as an endpoint. Falls back to the connection's own
    /// session for every modern transport, where the two coincide.
    pub(crate) fn session_for_endpoint(&self, key: &str) -> Option<Arc<Session>> {
        Self::lock(&self.endpoints).get(key).cloned()
    }

    /// Releases an endpoint binding ONLY if it still names `expected`. A
    /// server that re-advertises the same endpoint key on a reconnect must
    /// not have its NEW binding deleted by the OLD stream's teardown --
    /// that unbound every subsequent POST from its real session and logged
    /// answered calls as timeouts.
    pub(crate) fn unbind_endpoint_if(&self, key: &str, expected: &Arc<Session>) -> bool {
        let mut endpoints = Self::lock(&self.endpoints);
        match endpoints.get(key) {
            Some(current) if Arc::ptr_eq(current, expected) => {
                endpoints.remove(key);
                true
            }
            _ => false,
        }
    }

    fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        // Recover from poisoning rather than propagating it: every critical
        // section here is a single map operation that cannot leave the map
        // inconsistent, and refusing to correlate calls because an
        // unrelated thread panicked would turn one failure into a silent
        // audit gap. Same policy as `session.rs`.
        mutex.lock().unwrap_or_else(|e| e.into_inner())
    }
}
