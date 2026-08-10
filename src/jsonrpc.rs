//! JSON-RPC 2.0 message shapes used to peek at MCP traffic without
//! altering it. Messages are re-serialized byte-for-byte to the peer;
//! these types are only used to extract logging metadata.

use serde::Deserialize;
use serde_json::Value;

/// Loosely-typed enough to parse a request, a response, or a notification
/// with one struct — we only care about pulling a handful of fields out
/// for logging, never round-tripping or re-serializing a full message.
/// Parsing this is purely a best-effort side channel: the raw bytes of
/// every message are forwarded to the peer regardless of whether parsing
/// here succeeds.
#[derive(Debug, Deserialize)]
pub struct RpcMessage {
    pub id: Option<Value>,
    pub method: Option<String>,
    pub params: Option<Value>,
    pub result: Option<Value>,
    pub error: Option<Value>,
}

impl RpcMessage {
    /// A `tools/call` request has both a `method` and an `id` (a
    /// notification, which expects no response, has no `id`).
    pub fn is_tool_call_request(&self) -> bool {
        self.id.is_some() && self.method.as_deref() == Some("tools/call")
    }

    pub fn tool_name(&self) -> Option<String> {
        self.params
            .as_ref()?
            .get("name")?
            .as_str()
            .map(|s| s.to_string())
    }

    pub fn arguments(&self) -> Option<&Value> {
        self.params.as_ref()?.get("arguments")
    }

    /// A stable string key for correlating a response back to the request
    /// that produced it. `Value`'s `Display` impl renders canonical JSON,
    /// so the same id value always produces the same key whether it came
    /// from the request or the matching response. `None` for messages with
    /// no id (notifications).
    pub fn id_key(&self) -> Option<String> {
        self.id.as_ref().map(|v| v.to_string())
    }

    pub fn is_error_response(&self) -> bool {
        self.error.is_some()
    }

    /// True for the MCP convention where a tool's own failure is reported
    /// as an ordinary JSON-RPC *success* response whose `result` carries
    /// `"isError": true` (e.g. "file not found" from a delete tool), as
    /// distinct from a JSON-RPC-level error (`is_error_response`, e.g.
    /// "method not found"). Both are tool-call failures from the audit
    /// log's point of view and must be treated the same way by callers.
    pub fn is_mcp_tool_error(&self) -> bool {
        self.result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }

    /// True when the response is a `CreateTaskResult` from the
    /// `io.modelcontextprotocol/tasks` extension — a durable handle
    /// (`taskId`, `status`, `ttlMs`, `pollIntervalMs`) returned in place of
    /// the result, for work the server expects to be long-running.
    ///
    /// MCP 2026-07-28 requires a `resultType` on every result, so this is a
    /// one-field check against a stable discriminator rather than a guess
    /// at the handle's shape. The core values are `"complete"` and
    /// `"input_required"`; the tasks extension adds `"task"`. Earlier
    /// protocol revisions omit the field entirely and are to be treated as
    /// complete, which falls out of comparing against `"task"`.
    pub fn is_task_handle(&self) -> bool {
        self.result
            .as_ref()
            .and_then(|r| r.get("resultType"))
            .and_then(|v| v.as_str())
            == Some("task")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> RpcMessage {
        serde_json::from_str(s).expect("should parse")
    }

    #[test]
    fn tool_call_request_is_recognized() {
        let msg = parse(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call",
                "params":{"name":"echo","arguments":{"msg":"hi"}}}"#,
        );
        assert!(msg.is_tool_call_request());
        assert_eq!(msg.tool_name().as_deref(), Some("echo"));
        assert_eq!(msg.arguments(), Some(&serde_json::json!({"msg":"hi"})));
    }

    /// A notification has no `id` and expects no response, so it can never
    /// be correlated to one — tracking it would leak a pending entry.
    #[test]
    fn tool_call_notification_without_id_is_not_a_request() {
        let msg = parse(r#"{"jsonrpc":"2.0","method":"tools/call","params":{"name":"echo"}}"#);
        assert!(!msg.is_tool_call_request());
        assert_eq!(msg.id_key(), None);
    }

    #[test]
    fn other_methods_are_not_tool_calls() {
        for method in [
            "tools/list",
            "initialize",
            "server/discover",
            "resources/read",
        ] {
            let raw = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}"}}"#);
            assert!(
                !parse(&raw).is_tool_call_request(),
                "{method} must not be treated as a tools/call"
            );
        }
    }

    #[test]
    fn responses_have_no_method_and_are_not_requests() {
        let msg = parse(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#);
        assert!(!msg.is_tool_call_request());
        assert_eq!(msg.method, None);
    }

    #[test]
    fn missing_or_malformed_params_yield_none_rather_than_panicking() {
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#).tool_name(),
            None
        );
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#).tool_name(),
            None
        );
        // `name` present but not a string.
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":42}}"#)
                .tool_name(),
            None
        );
        assert_eq!(
            parse(r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"e"}}"#)
                .arguments(),
            None
        );
    }

    /// The request and its response must produce the same correlation key,
    /// for every id type a client might use. This is what the pending-call
    /// map is keyed on.
    #[test]
    fn id_key_matches_between_request_and_response() {
        for (req, resp) in [
            (
                r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"e"}}"#,
                r#"{"jsonrpc":"2.0","id":7,"result":{}}"#,
            ),
            (
                r#"{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"e"}}"#,
                r#"{"jsonrpc":"2.0","id":"abc","result":{}}"#,
            ),
        ] {
            assert_eq!(parse(req).id_key(), parse(resp).id_key());
            assert!(parse(req).id_key().is_some());
        }
    }

    /// JSON-RPC permits both numeric and string ids, and `1` and `"1"` are
    /// distinct ids. Collapsing them would let one call's response resolve
    /// another call's pending entry.
    #[test]
    fn numeric_and_string_ids_are_distinct_keys() {
        let numeric = parse(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#).id_key();
        let string = parse(r#"{"jsonrpc":"2.0","id":"1","result":{}}"#).id_key();
        assert_ne!(numeric, string);
    }

    #[test]
    fn jsonrpc_level_error_is_an_error_response() {
        let msg = parse(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"nope"}}"#);
        assert!(msg.is_error_response());
        assert!(!msg.is_mcp_tool_error());
    }

    /// MCP reports a tool's own failure inside an otherwise-successful
    /// response via `isError: true`. Both forms are tool-call failures for
    /// the audit log, and checking only the transport-level `error` field
    /// would under-log a failed destructive call.
    #[test]
    fn mcp_tool_error_is_detected_inside_a_success_response() {
        let msg = parse(
            r#"{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"nope"}]}}"#,
        );
        assert!(!msg.is_error_response());
        assert!(msg.is_mcp_tool_error());
    }

    #[test]
    fn is_error_false_or_absent_or_non_bool_is_not_a_tool_error() {
        assert!(
            !parse(r#"{"jsonrpc":"2.0","id":1,"result":{"isError":false}}"#).is_mcp_tool_error()
        );
        assert!(!parse(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#).is_mcp_tool_error());
        assert!(
            !parse(r#"{"jsonrpc":"2.0","id":1,"result":{"isError":"true"}}"#).is_mcp_tool_error(),
            "a non-boolean isError must not be coerced to true"
        );
    }

    #[test]
    fn task_handle_is_detected_by_result_type() {
        let msg = parse(
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"task","taskId":"t-42",
                 "status":"working","ttlMs":600000,"pollIntervalMs":1000}}"#,
        );
        assert!(msg.is_task_handle());
        assert!(!msg.is_error_response());
        assert!(!msg.is_mcp_tool_error());
    }

    /// The other two `resultType` values are ordinary results as far as the
    /// audit log is concerned. `input_required` in particular must NOT read
    /// as a task handle: an MRTR retry is a new `tools/call` that gets its
    /// own row, so its outcome does reach the log.
    #[test]
    fn other_result_types_are_not_task_handles() {
        for rt in ["complete", "input_required"] {
            let raw = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"resultType":"{rt}"}}}}"#);
            assert!(
                !parse(&raw).is_task_handle(),
                "resultType {rt} must not be treated as a task handle"
            );
        }
    }

    /// Protocol revisions before 2026-07-28 have no `resultType` at all,
    /// and are to be treated as complete.
    #[test]
    fn absent_or_malformed_result_type_is_not_a_task_handle() {
        assert!(!parse(r#"{"jsonrpc":"2.0","id":1,"result":{"content":[]}}"#).is_task_handle());
        assert!(!parse(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#).is_task_handle());
        assert!(
            !parse(r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":7}}"#).is_task_handle(),
            "a non-string resultType must not be coerced"
        );
        assert!(!parse(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1}}"#).is_task_handle());
    }

    /// Unknown fields must be ignored, not rejected. The envelope is the
    /// only part of MCP that is stable across protocol revisions, and every
    /// revision hangs additional fields off it — 2026-07-28 carries
    /// per-request `_meta` (protocol version, client capabilities) and a
    /// required `resultType` on results. Parsing must survive fields this
    /// build has never heard of.
    #[test]
    fn unknown_envelope_fields_are_ignored() {
        let msg = parse(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
                 "name":"get_weather","arguments":{"location":"Seattle"},
                 "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28",
                          "io.modelcontextprotocol/clientCapabilities":{}}}}"#,
        );
        assert!(msg.is_tool_call_request());
        assert_eq!(msg.tool_name().as_deref(), Some("get_weather"));

        let resp = parse(
            r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","content":[],
                 "_meta":{"io.modelcontextprotocol/serverInfo":{"name":"x"}}}}"#,
        );
        assert!(!resp.is_error_response());
        assert!(!resp.is_mcp_tool_error());
    }
}
