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
        self.params.as_ref()?.get("name")?.as_str().map(|s| s.to_string())
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
}
