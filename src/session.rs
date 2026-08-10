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
use std::sync::Mutex;
use std::time::Instant;

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
    pub(crate) fn register(&self, id_key: String, call: PendingCall) {
        self.lock().insert(id_key, call);
    }

    /// Takes the pending call for `id_key`, if this session has one.
    ///
    /// Removing on resolve is what makes correlation idempotent: a response
    /// delivered twice — which SSE stream replay could do on protocol
    /// revisions 2025-03-26 through 2025-11-25, where a reconnecting client
    /// replays from `Last-Event-ID` — finds nothing the second time and is
    /// ignored. Duplicate rows in a hash-chained audit log have no
    /// representation here rather than being deduplicated after the fact.
    pub(crate) fn resolve(&self, id_key: &str) -> Option<PendingCall> {
        self.lock().remove(id_key)
    }

    /// Takes every call still awaiting a response, leaving the session
    /// empty. Called when no further response can arrive — for stdio, once
    /// the child has exited and both pumps have stopped.
    ///
    /// **A completed call can never appear here.** `resolve` removes on
    /// success, so a call that got its response is already out of the map
    /// by the time anything drains it; there is no flag to check and no
    /// window to get wrong. Whatever this returns is, by construction,
    /// exactly the set of calls that never completed.
    ///
    /// Ordering the drain after the readers have stopped is the caller's
    /// responsibility, and it is what rules out the converse race — a
    /// response arriving mid-drain and being logged twice, once by
    /// `resolve` and once here.
    pub(crate) fn drain_abandoned(&self) -> Vec<PendingCall> {
        self.lock().drain().map(|(_, c)| c).collect()
    }

    /// Recovers from a poisoned lock rather than propagating the panic.
    /// Every critical section here is a single map operation that cannot
    /// leave the map inconsistent, and refusing to correlate calls because
    /// an unrelated thread panicked would turn one failure into a silent
    /// audit gap.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, PendingCall>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
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

    #[test]
    fn resolve_returns_the_registered_call_once() {
        let s = Session::new("sess-1".to_string());
        s.register("1".to_string(), call("echo"));

        let first = s.resolve("1");
        assert_eq!(first.map(|c| c.tool_name), Some("echo".to_string()));

        assert!(
            s.resolve("1").is_none(),
            "a second resolve of the same id must find nothing — this is what \
             makes a replayed response produce no duplicate row"
        );
    }

    #[test]
    fn unknown_id_resolves_to_none() {
        let s = Session::new("sess-1".to_string());
        assert!(s.resolve("999").is_none());
    }

    /// The property this module exists for: two sessions holding the same
    /// JSON-RPC id resolve to their own calls, never each other's.
    #[test]
    fn sessions_with_colliding_ids_never_cross_attribute() {
        let a = Session::new("sess-a".to_string());
        let b = Session::new("sess-b".to_string());

        a.register("1".to_string(), call("delete_file"));
        b.register("1".to_string(), call("echo"));

        // Resolved in the opposite order to registration, so a shared map
        // would surface the mix-up rather than hide it behind ordering.
        assert_eq!(
            b.resolve("1").map(|c| c.tool_name),
            Some("echo".to_string())
        );
        assert_eq!(
            a.resolve("1").map(|c| c.tool_name),
            Some("delete_file".to_string())
        );
    }

    /// The invariant the drain depends on: a call that got its response is
    /// already gone from the map, so it cannot also be reported abandoned.
    #[test]
    fn drain_never_returns_a_call_that_was_resolved() {
        let s = Session::new("sess-1".to_string());
        s.register("1".to_string(), call("completed"));
        s.register("2".to_string(), call("abandoned"));

        let resolved = s.resolve("1");
        assert_eq!(resolved.map(|c| c.tool_name), Some("completed".to_string()));

        let drained: Vec<String> = s
            .drain_abandoned()
            .into_iter()
            .map(|c| c.tool_name)
            .collect();
        assert_eq!(
            drained,
            vec!["abandoned".to_string()],
            "a completed call must never be swept into a timeout row"
        );
    }

    #[test]
    fn drain_empties_the_session_so_it_cannot_double_report() {
        let s = Session::new("sess-1".to_string());
        s.register("1".to_string(), call("echo"));

        assert_eq!(s.drain_abandoned().len(), 1);
        assert!(
            s.drain_abandoned().is_empty(),
            "draining twice must not produce the same call twice"
        );
    }

    #[test]
    fn draining_with_nothing_in_flight_yields_nothing() {
        let s = Session::new("sess-1".to_string());
        s.register("1".to_string(), call("echo"));
        let _ = s.resolve("1");
        assert!(s.drain_abandoned().is_empty());
    }

    #[test]
    fn drain_is_scoped_to_its_own_session() {
        let a = Session::new("sess-a".to_string());
        let b = Session::new("sess-b".to_string());
        a.register("1".to_string(), call("a_tool"));
        b.register("1".to_string(), call("b_tool"));

        let drained: Vec<String> = a
            .drain_abandoned()
            .into_iter()
            .map(|c| c.tool_name)
            .collect();
        assert_eq!(drained, vec!["a_tool".to_string()]);
        assert!(
            b.resolve("1").is_some(),
            "draining one session must not touch another's in-flight calls"
        );
    }

    #[test]
    fn resolving_in_one_session_leaves_the_other_untouched() {
        let a = Session::new("sess-a".to_string());
        let b = Session::new("sess-b".to_string());
        a.register("1".to_string(), call("a_tool"));
        b.register("1".to_string(), call("b_tool"));

        let _ = a.resolve("1");
        assert!(
            b.resolve("1").is_some(),
            "one session resolving an id must not consume another session's \
             entry for the same id"
        );
    }
}
