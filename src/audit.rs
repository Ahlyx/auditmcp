//! The transport-neutral audit pipeline: turning one completed tool call
//! into one `ToolCallEntry`.
//!
//! Everything here is pure data transformation — no I/O, no awaits, no
//! knowledge of stdio, HTTP, or SSE. Transports capture a `PendingCall`,
//! build a `CallOutcome`, and hand both to `build_entry`; how the bytes got
//! there is not this module's concern.
//!
//! **There is exactly one `build_entry`, deliberately.** Two builders that
//! "stay in sync" would be the same defect this codebase has already seen
//! elsewhere: a rule updated in one place and not the other, invisible
//! until an audit came out wrong. The ordering constraints below are the
//! reason it matters that this is a single function rather than a
//! convention.
//!
//! The pipeline order is load-bearing and cannot be rearranged:
//!
//! 1. **Detect and redact first**, on the full untruncated values.
//!    Truncating first could slice a secret in half so no pattern matches
//!    it, and nothing can un-truncate a value afterwards to look again.
//! 2. **Then decide the tier**, because whether detection fired is an input
//!    to that decision.
//! 3. **Then render**, on the same bindings redaction already mutated — no
//!    copy of the pre-redaction values survives step 1, so what gets stored
//!    is provably the redacted form.

use crate::config::Tier;
use crate::db::ToolCallEntry;
use crate::jsonrpc::RpcMessage;
use crate::secrets::{self, Hit, PatternSet, Severity};
use crate::session::PendingCall;
use crate::truncate;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;

/// Byte cap applied when rendering a value under the `minimal` tier.
/// Unrelated to `standard` tier's semantic truncation (see `truncate.rs`)
/// — this is a blunt, cheap preview for the tier that wants the smallest
/// possible footprint, not a structure-preserving cap.
const PREVIEW_BYTES: usize = 200;

/// A captured payload, in the two shapes a transport can hand over.
///
/// `Json` is the ordinary case and the only one stdio can produce: stdio
/// MCP is JSON-RPC end to end, so every payload arrives already parsed.
/// `Raw` exists for HTTP, where a response body for a request we correlated
/// to a `tools/call` genuinely may not be JSON — a gateway's HTML 502, a
/// wrong `Content-Type`, a body truncated mid-flight. Those are transport
/// failures rather than tool results, and they are worth capturing: an
/// error page can echo back a request header carrying a bearer token.
pub(crate) enum Payload {
    Json(Value),
    // Not constructed outside tests until an HTTP transport lands. The
    // variant exists now so `build_entry` dispatches over both payload
    // shapes from the start — adding the second shape later would mean
    // reworking the pipeline's core with the transports already depending
    // on it. Its behavior is covered by this module's tests.
    #[allow(dead_code)]
    Raw(String),
}

impl Payload {
    /// Redacts in place, returning every hit found (including allowlisted
    /// ones, which are left unredacted but still reported so callers can
    /// tell "no secret here" from "a secret you already cleared").
    fn scan_and_redact(&mut self, patterns: &PatternSet, allowlist: &HashSet<String>) -> Vec<Hit> {
        match self {
            Payload::Json(v) => secrets::scan_and_redact_json(v, patterns, allowlist),
            Payload::Raw(s) => {
                let (redacted, hits) = secrets::scan_and_redact_text(s, patterns, allowlist);
                *s = redacted;
                hits
            }
        }
    }

    /// Renders to the string actually stored, under the given effective
    /// tier. Called only after `scan_and_redact`, so the value here is
    /// already redacted and truncation can neither bisect a secret nor cut
    /// around a redaction marker.
    fn render(&self, tier: Tier) -> String {
        match self {
            Payload::Json(v) => match tier {
                Tier::Minimal => truncate_preview(&v.to_string()),
                Tier::Standard => truncate::truncate_json_semantic(v).to_string(),
                Tier::Full => v.to_string(),
            },
            // No structure to preserve, so `standard` samples head, middle
            // and tail rather than keeping a head-only prefix: the tail of
            // a stack trace or a dumped body is usually where the
            // informative part is.
            Payload::Raw(s) => match tier {
                Tier::Minimal => truncate_preview(s),
                Tier::Standard => truncate::truncate_raw_sampled(s),
                Tier::Full => s.clone(),
            },
        }
    }
}

/// How a tool call ended. Stored verbatim in the `status` column, so these
/// four strings are a query contract (`query --status <value>`) and a
/// Phase 3 input, not an internal detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CallStatus {
    /// A JSON-RPC response carrying a final result.
    Success,
    /// Either a JSON-RPC-level error, or MCP's convention of reporting a
    /// tool's own failure inside an otherwise-successful response via
    /// `isError: true`. Both are tool-call failures for the audit log.
    Error,
    /// No complete response ever arrived and the call was abandoned — the
    /// server exited or the stream died while the call was in flight. See
    /// `CallOutcome::timed_out`.
    Timeout,
    /// The response was a durable handle rather than the tool's result: a
    /// `CreateTaskResult` from the `io.modelcontextprotocol/tasks`
    /// extension. The work continues server-side and the real result is
    /// retrieved later by `tasks/get`.
    ///
    /// **This does not mean the result was unobservable.** `tasks/get` and
    /// its response cross this proxy like any other traffic. We forward
    /// them and do not log them, because they are not `tools/call` messages
    /// and nothing correlates them back to this row. *Saw it and did not
    /// record it* is a weaker claim than *could not see it*, and for a log
    /// people are trusting to be complete, that difference is the entire
    /// reason this status exists rather than the row simply reading
    /// `success`.
    ///
    /// What the row does carry: `Deferred` escalates to the `full` tier, so
    /// `result_json` holds the whole handle including its `taskId`. Anyone
    /// reconstructing the outcome later — or building the correlation this
    /// version lacks — has the identifier to do it with.
    Deferred,
}

impl CallStatus {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            CallStatus::Success => "success",
            CallStatus::Error => "error",
            CallStatus::Timeout => "timeout",
            CallStatus::Deferred => "deferred",
        }
    }

    /// Whether this status forces the `full` tier regardless of
    /// configuration. Everything that is not a plain success is an
    /// incomplete or anomalous record, and truncating those would discard
    /// exactly the detail someone investigating needs. Extending the rule
    /// from `is_error` to "not success" keeps the two original statuses
    /// behaving identically to before.
    fn escalates(self) -> bool {
        !matches!(self, CallStatus::Success)
    }
}

/// The response half of a completed call, decided once so both transports
/// classify a call the same way.
pub(crate) struct CallOutcome {
    pub(crate) status: CallStatus,
    pub(crate) result: Option<Payload>,
    pub(crate) error: Option<Payload>,
    /// `None` when no response was received at all (a swept timeout), as
    /// distinct from a response that carried zero bytes.
    pub(crate) bytes_out: Option<i64>,
}

impl CallOutcome {
    /// Classifies a parsed JSON-RPC response. Checks both failure forms —
    /// a transport-level `error` and MCP's in-result `isError: true` —
    /// because a destructive tool call that ran and failed must never be
    /// under-logged by looking at only one of them.
    pub(crate) fn from_rpc(msg: &RpcMessage, bytes_out: i64) -> Self {
        // Errors first: a failure is a failure whatever shape the result
        // otherwise has.
        //
        // A task handle is deliberately NOT `Success`, while an MRTR
        // `input_required` interim result deliberately is. The difference
        // is whether the outcome ever reaches the log. An MRTR retry is a
        // new `tools/call`, so it produces its own row and the final result
        // is recorded there; nothing is lost, the story is just told across
        // two rows. A task's result arrives via `tasks/get`, which is not a
        // `tools/call` and is never logged — so without this status the row
        // would claim a plain success for a call whose outcome this log
        // does not contain.
        let status = if msg.is_error_response() || msg.is_mcp_tool_error() {
            CallStatus::Error
        } else if msg.is_task_handle() {
            CallStatus::Deferred
        } else {
            CallStatus::Success
        };
        CallOutcome {
            status,
            result: msg.result.clone().map(Payload::Json),
            error: msg.error.clone().map(Payload::Json),
            bytes_out: Some(bytes_out),
        }
    }

    /// A call that never completed. Every response-side field is `None`,
    /// including `bytes_out`: no response message closed this call, so
    /// there is no message whose size could be reported.
    ///
    /// That holds even when some bytes were forwarded. If a server dies
    /// mid-response, the partial bytes reach the client but never parse,
    /// which means we never read an `id` from them — so those bytes cannot
    /// be attributed to this call or any other. Recording them against a
    /// guess would be inventing evidence in an audit log.
    ///
    /// The request side is untouched: `args_json` and `bytes_in` were
    /// captured when the request went out and are still recorded, which is
    /// the point of writing this row at all. `Timeout` escalates to the
    /// `full` tier, so those args are stored untruncated.
    pub(crate) fn timed_out() -> Self {
        CallOutcome {
            status: CallStatus::Timeout,
            result: None,
            error: None,
            bytes_out: None,
        }
    }
}

/// One entry in the `redaction_flags` JSON array stored per row: which
/// pattern fired, at what severity, plus the sha256 of the plaintext secret
/// (never the plaintext itself) so the same secret can be correlated
/// across rows. No `allowlisted` field here -- this array is only ever
/// built from hits already filtered to non-allowlisted ones, so it would
/// always read `false` and add nothing.
#[derive(Serialize)]
struct RedactionRecord<'a> {
    pattern: &'a str,
    severity: Severity,
    sha256: &'a str,
}

/// Builds the `ToolCallEntry` for one completed tool call. See the module
/// doc comment for why the step order here cannot be rearranged.
pub(crate) fn build_entry(
    call: PendingCall,
    outcome: CallOutcome,
    session_id: &str,
    server_name: &str,
    configured_tier: Tier,
    patterns: &PatternSet,
    allowlist: &HashSet<String>,
) -> ToolCallEntry {
    let duration_ms = call.started.elapsed().as_millis() as i64;

    // Step 1: detect and redact, on the full untruncated values. Args are
    // always JSON — a request has to parse as JSON-RPC to be recognized as
    // a tools/call at all — so only the response side can be raw.
    let mut args = call.args.map(Payload::Json);
    let mut result = outcome.result;
    let mut error = outcome.error;

    let mut hits = Vec::new();
    for payload in [&mut args, &mut result, &mut error].into_iter().flatten() {
        hits.extend(payload.scan_and_redact(patterns, allowlist));
    }

    // Allowlisted hits are confirmed false positives, left unredacted by
    // the scan itself. They must not count toward escalation or the stored
    // redaction metadata -- only genuine, still-redacted hits do.
    let active_hit_count = hits.iter().filter(|h| !h.allowlisted).count();
    let secrets_fired = active_hit_count > 0;

    // Step 2: decide the tier, now that detection has run.
    let effective_tier = if secrets_fired || outcome.status.escalates() {
        Tier::Full
    } else {
        configured_tier
    };

    // Step 3: render the already-redacted values. These are the same
    // bindings mutated above; no pre-redaction copy survives.
    let args_json = args.map(|p| p.render(effective_tier));
    let result_json = result.map(|p| p.render(effective_tier));
    let error_message = error.map(|p| p.render(effective_tier));

    // Structured, not a flat array of pattern names: each entry pairs the
    // pattern (plus its severity) with the sha256 of the plaintext secret
    // it matched, so the same leaked value can be correlated across rows
    // without ever persisting the plaintext. `query`/`export` parse this as
    // `[{"pattern":..,"severity":..,"sha256":..}, ...]`.
    let redaction_flags = if secrets_fired {
        let records: Vec<RedactionRecord> = hits
            .iter()
            .filter(|h| !h.allowlisted)
            .map(|h| RedactionRecord {
                pattern: h.pattern_name.as_str(),
                severity: h.severity,
                sha256: h.secret_sha256.as_str(),
            })
            .collect();
        serde_json::to_string(&records).ok()
    } else {
        None
    };

    ToolCallEntry {
        timestamp: chrono::Utc::now().to_rfc3339(),
        session_id: session_id.to_string(),
        agent_id: None,
        tool_name: call.tool_name,
        server_name: Some(server_name.to_string()),
        args_json,
        result_json,
        status: outcome.status.as_str().to_string(),
        error_message,
        duration_ms: Some(duration_ms),
        bytes_in: Some(call.bytes_in),
        bytes_out: outcome.bytes_out,
        source: None,
        destination: None,
        redaction_flags,
        redaction_count: active_hit_count as i64,
        anomaly_score: None,
        anomaly_reasons: None,
    }
}

/// Truncates to at most `PREVIEW_BYTES` bytes, snapping back to the
/// nearest char boundary so this can never panic by slicing into the
/// middle of a multi-byte UTF-8 sequence.
fn truncate_preview(s: &str) -> String {
    if s.len() <= PREVIEW_BYTES {
        return s.to_string();
    }
    let end = truncate::snap_boundary(s, PREVIEW_BYTES);
    format!("{}... [truncated, {} bytes total]", &s[..end], s.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Instant;

    const FAKE_KEY: &str = "sk-FAKE1234567890abcdefFAKEKEYFAKE00";

    /// Long enough to be truncated at every tier boundary, so the tier that
    /// actually applied is visible in the stored string.
    fn long_args() -> Value {
        json!({ "text": "x".repeat(2000) })
    }

    fn pending(args: Value) -> PendingCall {
        PendingCall {
            tool_name: "echo".to_string(),
            args: Some(args),
            bytes_in: 42,
            started: Instant::now(),
        }
    }

    fn outcome(status: CallStatus, result: Value) -> CallOutcome {
        CallOutcome {
            status,
            result: Some(Payload::Json(result)),
            error: None,
            bytes_out: Some(99),
        }
    }

    fn entry_for(
        status: CallStatus,
        configured: Tier,
        args: Value,
        result: Value,
    ) -> ToolCallEntry {
        let patterns = PatternSet::bundled().unwrap();
        build_entry(
            pending(args),
            outcome(status, result),
            "sess-1",
            "srv",
            configured,
            &patterns,
            &HashSet::new(),
        )
    }

    #[test]
    fn status_strings_are_the_stored_contract() {
        assert_eq!(CallStatus::Success.as_str(), "success");
        assert_eq!(CallStatus::Error.as_str(), "error");
        assert_eq!(CallStatus::Timeout.as_str(), "timeout");
        assert_eq!(CallStatus::Deferred.as_str(), "deferred");
    }

    /// The escalation rule across its full input domain. `Timeout` and
    /// `Deferred` are not produced by any transport yet, so without this
    /// the rule would sit live but half-untested until the commits that
    /// write them.
    #[test]
    fn every_non_success_status_escalates_to_full() {
        assert!(!CallStatus::Success.escalates());
        assert!(CallStatus::Error.escalates());
        assert!(CallStatus::Timeout.escalates());
        assert!(CallStatus::Deferred.escalates());
    }

    /// Asserted through `build_entry` rather than on `escalates()` alone,
    /// so this covers the rule actually reaching the rendered output.
    #[test]
    fn escalation_is_visible_in_the_stored_row_for_all_four_statuses() {
        // Configured `minimal` would cap args at 200 bytes; anything that
        // escalates stores the full 2000-byte value instead.
        let success = entry_for(CallStatus::Success, Tier::Minimal, long_args(), json!({}));
        let args = success.args_json.unwrap();
        assert!(
            args.contains("[truncated"),
            "success must keep the configured minimal tier"
        );

        for status in [CallStatus::Error, CallStatus::Timeout, CallStatus::Deferred] {
            let e = entry_for(status, Tier::Minimal, long_args(), json!({}));
            let args = e.args_json.unwrap();
            assert!(
                !args.contains("[truncated"),
                "{} must escalate to full and store untruncated args",
                status.as_str()
            );
            assert_eq!(e.status, status.as_str());
        }
    }

    #[test]
    fn secrets_escalate_even_on_success() {
        let e = entry_for(
            CallStatus::Success,
            Tier::Minimal,
            long_args(),
            json!({ "api_key": FAKE_KEY }),
        );
        assert!(
            !e.args_json.unwrap().contains("[truncated"),
            "a secret anywhere in the call must force full capture"
        );
        assert_eq!(e.redaction_count, 1);
    }

    #[test]
    fn secret_is_redacted_in_the_rendered_result() {
        let e = entry_for(
            CallStatus::Success,
            Tier::Full,
            json!({}),
            json!({ "api_key": FAKE_KEY }),
        );
        let result = e.result_json.unwrap();
        assert!(
            !result.contains(FAKE_KEY),
            "plaintext secret must not be stored"
        );
        assert!(result.contains("[REDACTED:"));
        // The hash is stored for cross-row correlation, never the plaintext.
        let flags = e.redaction_flags.unwrap();
        assert!(flags.contains("openai_api_key"));
        assert!(!flags.contains(FAKE_KEY));
    }

    #[test]
    fn no_secrets_means_no_redaction_metadata() {
        let e = entry_for(
            CallStatus::Success,
            Tier::Full,
            json!({}),
            json!({"ok": true}),
        );
        assert_eq!(e.redaction_count, 0);
        assert!(e.redaction_flags.is_none());
    }

    /// Each tier renders differently, and `configured_tier` is what applies
    /// when nothing escalates.
    #[test]
    fn configured_tier_applies_when_nothing_escalates() {
        let minimal = entry_for(CallStatus::Success, Tier::Minimal, long_args(), json!({}))
            .args_json
            .unwrap();
        let standard = entry_for(CallStatus::Success, Tier::Standard, long_args(), json!({}))
            .args_json
            .unwrap();
        let full = entry_for(CallStatus::Success, Tier::Full, long_args(), json!({}))
            .args_json
            .unwrap();

        assert!(minimal.len() < standard.len());
        assert!(standard.len() < full.len());
        assert!(!full.contains("[truncated"));
    }

    /// The `Raw` arm, which no transport reaches yet: a non-JSON response
    /// body still gets scanned and rendered through the same pipeline, so
    /// the ordering guarantees hold for it too.
    #[test]
    fn raw_payload_is_scanned_and_sampled_not_head_truncated() {
        let patterns = PatternSet::bundled().unwrap();
        let body = format!(
            "<html><body>Gateway error. Upstream said: Authorization: Bearer {FAKE_KEY}\n{}\nTAIL_MARKER</body></html>",
            "filler ".repeat(500)
        );
        let mut payload = Payload::Raw(body);
        let hits = payload.scan_and_redact(&patterns, &HashSet::new());
        assert!(
            !hits.is_empty(),
            "a key in a raw body must still be detected"
        );

        let rendered = payload.render(Tier::Standard);
        assert!(!rendered.contains(FAKE_KEY));
        assert!(
            rendered.contains("TAIL_MARKER"),
            "standard-tier raw sampling must keep the tail, not just the head"
        );
    }

    #[test]
    fn raw_payload_at_full_tier_is_untouched_apart_from_redaction() {
        let patterns = PatternSet::bundled().unwrap();
        let mut payload = Payload::Raw("plain text, no secrets".to_string());
        assert!(payload
            .scan_and_redact(&patterns, &HashSet::new())
            .is_empty());
        assert_eq!(payload.render(Tier::Full), "plain text, no secrets");
    }

    #[test]
    fn from_rpc_classifies_both_failure_forms_as_error() {
        let jsonrpc_error: RpcMessage =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601}}"#).unwrap();
        assert_eq!(
            CallOutcome::from_rpc(&jsonrpc_error, 10).status,
            CallStatus::Error
        );

        let tool_error: RpcMessage =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"result":{"isError":true}}"#).unwrap();
        assert_eq!(
            CallOutcome::from_rpc(&tool_error, 10).status,
            CallStatus::Error
        );

        let ok: RpcMessage =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#).unwrap();
        assert_eq!(CallOutcome::from_rpc(&ok, 10).status, CallStatus::Success);
    }

    #[test]
    fn task_handle_response_is_classified_deferred() {
        let msg: RpcMessage = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"task","taskId":"t-42","status":"working"}}"#,
        )
        .unwrap();
        assert_eq!(CallOutcome::from_rpc(&msg, 10).status, CallStatus::Deferred);
    }

    /// An MRTR interim result is a plain success: the client retries as a
    /// new `tools/call`, which produces its own row carrying the final
    /// outcome. Nothing is missing from the log, so nothing needs flagging.
    #[test]
    fn mrtr_interim_result_is_not_deferred() {
        let msg: RpcMessage = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"input_required",
                 "inputRequests":{"k":{"method":"elicitation/create"}},"requestState":"blob"}}"#,
        )
        .unwrap();
        assert_eq!(CallOutcome::from_rpc(&msg, 10).status, CallStatus::Success);
    }

    /// A failing task-creating call is an error, not a deferral — there is
    /// no outcome still to come.
    #[test]
    fn an_error_wins_over_a_task_handle() {
        let msg: RpcMessage = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32603},"result":{"resultType":"task"}}"#,
        )
        .unwrap();
        assert_eq!(CallOutcome::from_rpc(&msg, 10).status, CallStatus::Error);
    }

    /// The taskId must survive into the stored row: it is the only thread
    /// back to an outcome this log does not otherwise contain. `Deferred`
    /// escalates to `full`, so the handle is stored whole even under a
    /// `minimal` configuration.
    #[test]
    fn deferred_row_retains_the_task_id_despite_a_minimal_tier() {
        let patterns = PatternSet::bundled().unwrap();
        let msg: RpcMessage = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"task","taskId":"t-abc-123",
                 "status":"working","ttlMs":600000,"pollIntervalMs":1000}}"#,
        )
        .unwrap();
        let e = build_entry(
            pending(long_args()),
            CallOutcome::from_rpc(&msg, 120),
            "sess-1",
            "srv",
            Tier::Minimal,
            &patterns,
            &HashSet::new(),
        );
        assert_eq!(e.status, "deferred");
        let result = e.result_json.unwrap();
        assert!(
            result.contains("t-abc-123"),
            "taskId must be stored: {result}"
        );
        assert!(!result.contains("[truncated"));
    }

    #[test]
    fn timeout_outcome_records_no_response_bytes() {
        let patterns = PatternSet::bundled().unwrap();
        let e = build_entry(
            pending(json!({"a": 1})),
            CallOutcome {
                status: CallStatus::Timeout,
                result: None,
                error: None,
                bytes_out: None,
            },
            "sess-1",
            "srv",
            Tier::Minimal,
            &patterns,
            &HashSet::new(),
        );
        assert_eq!(e.status, "timeout");
        assert_eq!(e.bytes_out, None);
        assert!(e.result_json.is_none());
        assert!(e.error_message.is_none());
        // Args were captured at request time and are still recorded.
        assert!(e.args_json.is_some());
        assert_eq!(e.bytes_in, Some(42));
    }

    #[test]
    fn truncate_preview_leaves_short_strings_untouched() {
        assert_eq!(truncate_preview("hello"), "hello");
    }

    #[test]
    fn truncate_preview_does_not_panic_on_multibyte_boundary() {
        // Each '✓' is 3 bytes in UTF-8; PREVIEW_BYTES (200) is not a
        // multiple of 3, so a naive byte-slice at exactly 200 would land
        // mid-character.
        let s: String = "✓".repeat(100);
        let preview = truncate_preview(&s);
        assert!(preview.starts_with('✓'));
        assert!(preview.contains("truncated"));
    }
}
