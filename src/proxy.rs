//! Core `run` command: spawns the target MCP server, pipes stdio
//! transparently, and intercepts JSON-RPC traffic for logging.
//!
//! Only `tools/call` request/response pairs are logged as `tool_calls`
//! rows — other JSON-RPC traffic (`initialize`, `tools/list`,
//! notifications, etc.) is proxied transparently but not logged, since the
//! schema's `tool_name TEXT NOT NULL` and this project's scope (auditing
//! *tool calls*, per its name and threat model) don't cover generic
//! protocol chatter.

use crate::config::Config;
use crate::db::{self, DbHandle, ToolCallEntry};
use crate::jsonrpc::RpcMessage;
use std::collections::HashMap;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

/// Phase 1 always truncates to a short preview regardless of configured
/// tier (see `Config::tier_for_tool`, called below) — semantic,
/// tier-aware truncation is Phase 2 work.
const PREVIEW_BYTES: usize = 200;

struct PendingCall {
    tool_name: String,
    args_preview: Option<String>,
    bytes_in: i64,
    started: Instant,
}

type PendingMap = Arc<Mutex<HashMap<String, PendingCall>>>;

pub async fn run(config_path: &Path, target: Vec<String>) -> anyhow::Result<()> {
    let config = Arc::new(Config::load(config_path)?);
    let (program, args) = target
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("no target command given after `--`"))?;

    let session_id = uuid::Uuid::new_v4().to_string();
    let server_name = program.clone();
    let db = db::spawn_writer(Path::new(&config.logging.db_path));

    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        // Inherited, not intercepted: child stderr (e.g. a Python
        // traceback) should reach the developer's terminal untouched, and
        // MCP framing never runs over stderr.
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn target command '{program}': {e}"))?;

    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow::anyhow!("child stdin was not piped"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("child stdout was not piped"))?;

    let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));

    let inbound = tokio::spawn(pump_client_to_child(child_stdin, Arc::clone(&pending)));

    let outbound = tokio::spawn(pump_child_to_client(
        child_stdout,
        Arc::clone(&pending),
        db,
        session_id,
        server_name,
        Arc::clone(&config),
    ));

    let status = child
        .wait()
        .await
        .map_err(|e| anyhow::anyhow!("failed waiting on child process: {e}"))?;

    // The inbound pump reads from *our* real stdin, which is driven by the
    // external client, not by the child — it has no natural reason to end
    // just because the child exited, and could otherwise block this
    // function (and the whole proxy process) from returning indefinitely
    // if the client keeps its stdin open without sending anything further.
    // The outbound pump, in contrast, is bounded by the child's stdout
    // closing, which just happened, so it's safe to await to completion.
    inbound.abort();
    let _ = outbound.await;

    if !status.success() {
        tracing::warn!("target command exited with status {status}");
    }

    Ok(())
}

/// Client stdin -> child stdin. Forwards every line byte-for-byte, and
/// best-effort parses `tools/call` requests to start tracking a pending
/// call. Parsing never gates forwarding: a malformed or non-UTF-8 line is
/// still passed through untouched, just not logged.
async fn pump_client_to_child(mut child_in: ChildStdin, pending: PendingMap) {
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut buf: Vec<u8> = Vec::new();

    loop {
        buf.clear();
        let n = match reader.read_until(b'\n', &mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("error reading from client stdin: {e}");
                break;
            }
        };
        if n == 0 {
            break; // EOF: client closed stdin.
        }

        if let Err(e) = child_in.write_all(&buf).await {
            tracing::warn!("error writing to child stdin: {e}");
            break;
        }
        if let Err(e) = child_in.flush().await {
            tracing::warn!("error flushing child stdin: {e}");
        }

        if let Some(msg) = parse_rpc_message(&buf) {
            if msg.is_tool_call_request() {
                if let (Some(id_key), Some(tool_name)) = (msg.id_key(), msg.tool_name()) {
                    let args_preview = msg.arguments().map(|v| truncate_preview(&v.to_string()));
                    let mut guard = pending.lock().await;
                    guard.insert(
                        id_key,
                        PendingCall {
                            tool_name,
                            args_preview,
                            bytes_in: buf.len() as i64,
                            started: Instant::now(),
                        },
                    );
                }
            }
        }
    }
}

/// Child stdout -> client stdout. Forwards every line byte-for-byte, and
/// best-effort parses responses to close out a pending call and submit a
/// `ToolCallEntry`. Same fail-open contract as `pump_client_to_child`.
async fn pump_child_to_client(
    child_out: ChildStdout,
    pending: PendingMap,
    db: DbHandle,
    session_id: String,
    server_name: String,
    config: Arc<Config>,
) {
    let mut reader = BufReader::new(child_out);
    let mut stdout = tokio::io::stdout();
    let mut buf: Vec<u8> = Vec::new();

    loop {
        buf.clear();
        let n = match reader.read_until(b'\n', &mut buf).await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("error reading from child stdout: {e}");
                break;
            }
        };
        if n == 0 {
            break; // EOF: child closed stdout (exited).
        }

        if let Err(e) = stdout.write_all(&buf).await {
            tracing::warn!("error writing to client stdout: {e}");
            break;
        }
        if let Err(e) = stdout.flush().await {
            tracing::warn!("error flushing client stdout: {e}");
        }

        let Some(msg) = parse_rpc_message(&buf) else {
            continue;
        };
        let Some(id_key) = msg.id_key() else {
            continue;
        };

        let pending_call = {
            let mut guard = pending.lock().await;
            guard.remove(&id_key)
        };
        let Some(call) = pending_call else {
            continue; // Response to something we didn't track (e.g. not a tools/call).
        };

        // Phase 2 will branch on tier here for standard/full truncation
        // strategy; Phase 1 always applies PREVIEW_BYTES regardless.
        let _tier = config.tier_for_tool(&call.tool_name);

        let duration_ms = call.started.elapsed().as_millis() as i64;
        let status = if msg.is_error_response() { "error" } else { "success" };
        let error_message = msg.error.as_ref().map(|e| truncate_preview(&e.to_string()));
        let result_preview = msg.result.as_ref().map(|v| truncate_preview(&v.to_string()));

        let entry = ToolCallEntry {
            timestamp: chrono::Utc::now().to_rfc3339(),
            session_id: session_id.clone(),
            agent_id: None,
            tool_name: call.tool_name,
            server_name: Some(server_name.clone()),
            args_json: call.args_preview,
            result_json: result_preview,
            status: status.to_string(),
            error_message,
            duration_ms: Some(duration_ms),
            bytes_in: Some(call.bytes_in),
            bytes_out: Some(buf.len() as i64),
            source: None,
            destination: None,
            redaction_flags: None,
            redaction_count: 0,
            anomaly_score: None,
            anomaly_reasons: None,
        };

        db.log(entry);
    }
}

/// Best-effort decode of a raw line for logging purposes only. Strips a
/// trailing `\n`/`\r\n` before parsing (the raw bytes forwarded to the peer
/// are never touched by this). Returns `None` — never panics — on
/// non-UTF-8 bytes or invalid/non-JSON-RPC-shaped content, which is
/// expected to happen sometimes (partial reads, non-MCP framing, etc.) and
/// must not be treated as fatal.
fn parse_rpc_message(buf: &[u8]) -> Option<RpcMessage> {
    let trimmed = strip_trailing_newline(buf);
    let text = std::str::from_utf8(trimmed).ok()?;
    serde_json::from_str::<RpcMessage>(text).ok()
}

fn strip_trailing_newline(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    if end > 0 && buf[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && buf[end - 1] == b'\r' {
        end -= 1;
    }
    &buf[..end]
}

/// Truncates to at most `PREVIEW_BYTES` bytes, snapping back to the
/// nearest char boundary so this can never panic by slicing into the
/// middle of a multi-byte UTF-8 sequence.
fn truncate_preview(s: &str) -> String {
    if s.len() <= PREVIEW_BYTES {
        return s.to_string();
    }
    let mut end = PREVIEW_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... [truncated, {} bytes total]", &s[..end], s.len())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn parse_rpc_message_returns_none_on_invalid_utf8() {
        let invalid_utf8 = vec![0xff, 0xfe, 0xfd, b'\n'];
        assert!(parse_rpc_message(&invalid_utf8).is_none());
    }

    #[test]
    fn parse_rpc_message_returns_none_on_malformed_json() {
        assert!(parse_rpc_message(b"not json at all\n").is_none());
    }

    #[test]
    fn parse_rpc_message_extracts_tool_call_request() {
        let line = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}
"#;
        let msg = parse_rpc_message(line).expect("should parse");
        assert!(msg.is_tool_call_request());
        assert_eq!(msg.tool_name().as_deref(), Some("echo"));
        assert_eq!(msg.id_key().as_deref(), Some("1"));
    }
}
