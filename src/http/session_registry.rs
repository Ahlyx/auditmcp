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
use std::sync::Arc;
use tokio::sync::Mutex;

/// The sessions of ONE listener.
///
/// Deliberately not a process-wide map keyed by (listener, connection, id):
/// that is the composite key this design rejected, and a single mis-built
/// key there attributes one caller's response to another caller's request
/// in an audit log. Here a listener holds its own registry and hands each
/// connection its own `Session`, so the mistake has no way to be made.
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
    pub(crate) async fn open(&self) -> (u64, Arc<Session>) {
        let key = self.next_id.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(Session::new(format!("conn:{}", uuid::Uuid::new_v4())));
        self.open.lock().await.insert(key, Arc::clone(&session));
        (key, session)
    }

    /// Closes a session and returns any calls left unanswered on it, so the
    /// connection handler can log them rather than let them vanish.
    pub(crate) async fn close(&self, key: u64) -> Vec<PendingCall> {
        let session = self.open.lock().await.remove(&key);
        match session {
            Some(s) => s.drain_abandoned(),
            None => Vec::new(),
        }
    }

    /// Every session still open, for the shutdown drain.
    pub(crate) async fn take_all(&self) -> Vec<Arc<Session>> {
        let mut all: Vec<Arc<Session>> = self.open.lock().await.drain().map(|(_, s)| s).collect();
        all.extend(self.endpoints.lock().await.drain().map(|(_, s)| s));
        all
    }

    /// Binds a legacy POST endpoint to the session of the stream that
    /// advertised it.
    pub(crate) async fn bind_endpoint(&self, key: String, session: Arc<Session>) {
        self.endpoints.lock().await.insert(key, session);
    }

    /// The session a legacy POST belongs to, if this path and query was
    /// advertised as an endpoint. Falls back to the connection's own
    /// session for every modern transport, where the two coincide.
    pub(crate) async fn session_for_endpoint(&self, key: &str) -> Option<Arc<Session>> {
        self.endpoints.lock().await.get(key).cloned()
    }

    pub(crate) async fn unbind_endpoint(&self, key: &str) -> Option<Arc<Session>> {
        self.endpoints.lock().await.remove(key)
    }
}
