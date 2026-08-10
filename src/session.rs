//! Correlation state: matching a JSON-RPC response back to the request
//! that produced it.
//!
//! **The scoping rule this module exists to enforce.** A `Session` owns its
//! pending-call map outright. Nothing hands that map to another session, and
//! no map anywhere holds two sessions' entries, so a response can only ever
//! resolve a call registered *in its own session*. That is an ownership
//! property, not a check someone has to remember to write — which matters
//! because the alternative is a single shared map keyed by a composite
//! `(session, id)` tuple, and there one mis-built key silently
//! cross-attributes one caller's response to another caller's request. The
//! audit log would look healthy and name the wrong tool.
//!
//! This is not hypothetical arithmetic about a future transport. JSON-RPC
//! ids are chosen by the client and are typically small integers restarting
//! at 1 per connection, so the moment more than one client is in flight,
//! id `1` is ambiguous unless something scopes it. Under stdio there is
//! exactly one client and therefore exactly one `Session`, which is why the
//! single map that predates this module was correct there — and why it
//! would stop being correct the instant a second client appeared.
//!
//! The same rule applies one level up, where it is also structural: a
//! listener owns its sessions, and nothing shares sessions between
//! listeners. If a process-wide view of in-flight calls ever seems
//! necessary (a metrics counter, a debug listing), it must not be built by
//! flattening these maps into one keyed by listener and session — that is
//! the composite key returning as infrastructure. Design it deliberately
//! instead.

use serde_json::Value;
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::Mutex;

/// A `tools/call` request seen on the wire, held until its response
/// arrives. Captured at request time and completed at response time,
/// because the effective logging tier depends on facts only the response
/// carries — see `audit::build_entry`.
pub(crate) struct PendingCall {
    pub(crate) tool_name: String,
    /// Full, untruncated parsed `arguments` value. Deliberately not
    /// truncated at capture time: a secret cut off by an early preview
    /// could not be detected afterwards, and detection is what decides how
    /// much truncation is allowed in the first place.
    pub(crate) args: Option<Value>,
    pub(crate) bytes_in: i64,
    pub(crate) started: Instant,
}

/// One correlation scope, and the audit `session_id` those rows carry.
///
/// The id is a plain UUID for stdio (one session per proxied process). The
/// HTTP transports prefix it with the signal the session was derived from
/// (`sse:`, `mcp:`, `conn:`), because those signals differ per protocol
/// revision and a session that silently means different things in
/// different rows is worse than one that says which it is.
pub(crate) struct Session {
    id: String,
    pending: Mutex<HashMap<String, PendingCall>>,
}

impl Session {
    pub(crate) fn new(id: String) -> Self {
        Session {
            id,
            pending: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Starts tracking a request. `id_key` comes from
    /// `RpcMessage::id_key`, which renders the id as canonical JSON so a
    /// numeric `1` and a string `"1"` — both legal, distinct JSON-RPC ids —
    /// never collide.
    pub(crate) async fn register(&self, id_key: String, call: PendingCall) {
        self.pending.lock().await.insert(id_key, call);
    }

    /// Takes the pending call for `id_key`, if this session has one.
    ///
    /// Removing on resolve is what makes correlation idempotent: a response
    /// delivered twice — which SSE stream replay could do on protocol
    /// revisions 2025-03-26 through 2025-11-25, where a reconnecting client
    /// replays from `Last-Event-ID` — finds nothing the second time and is
    /// ignored. Duplicate rows in a hash-chained audit log have no
    /// representation here rather than being deduplicated after the fact.
    pub(crate) async fn resolve(&self, id_key: &str) -> Option<PendingCall> {
        self.pending.lock().await.remove(id_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn call(tool: &str) -> PendingCall {
        PendingCall {
            tool_name: tool.to_string(),
            args: Some(json!({})),
            bytes_in: 10,
            started: Instant::now(),
        }
    }

    #[tokio::test]
    async fn resolve_returns_the_registered_call_once() {
        let s = Session::new("sess-1".to_string());
        s.register("1".to_string(), call("echo")).await;

        let first = s.resolve("1").await;
        assert_eq!(first.map(|c| c.tool_name), Some("echo".to_string()));

        assert!(
            s.resolve("1").await.is_none(),
            "a second resolve of the same id must find nothing — this is what \
             makes a replayed response produce no duplicate row"
        );
    }

    #[tokio::test]
    async fn unknown_id_resolves_to_none() {
        let s = Session::new("sess-1".to_string());
        assert!(s.resolve("999").await.is_none());
    }

    /// The property this module exists for: two sessions holding the same
    /// JSON-RPC id resolve to their own calls, never each other's.
    #[tokio::test]
    async fn sessions_with_colliding_ids_never_cross_attribute() {
        let a = Session::new("sess-a".to_string());
        let b = Session::new("sess-b".to_string());

        a.register("1".to_string(), call("delete_file")).await;
        b.register("1".to_string(), call("echo")).await;

        // Resolved in the opposite order to registration, so a shared map
        // would surface the mix-up rather than hide it behind ordering.
        assert_eq!(
            b.resolve("1").await.map(|c| c.tool_name),
            Some("echo".to_string())
        );
        assert_eq!(
            a.resolve("1").await.map(|c| c.tool_name),
            Some("delete_file".to_string())
        );
    }

    #[tokio::test]
    async fn resolving_in_one_session_leaves_the_other_untouched() {
        let a = Session::new("sess-a".to_string());
        let b = Session::new("sess-b".to_string());
        a.register("1".to_string(), call("a_tool")).await;
        b.register("1".to_string(), call("b_tool")).await;

        let _ = a.resolve("1").await;
        assert!(
            b.resolve("1").await.is_some(),
            "one session resolving an id must not consume another session's \
             entry for the same id"
        );
    }
}
