//! Core `run` command: spawns the target MCP server, pipes stdio
//! transparently, and intercepts JSON-RPC traffic for logging.
//!
//! Only `tools/call` request/response pairs are logged as `tool_calls`
//! rows — other JSON-RPC traffic (`initialize`, `tools/list`,
//! notifications, etc.) is proxied transparently but not logged, since the
//! schema's `tool_name TEXT NOT NULL` and this project's scope (auditing
//! *tool calls*, per its name and threat model) don't cover generic
//! protocol chatter.
//!
//! Args/result capture is deliberately two-phase: the request-side pump
//! stores the FULL, untruncated `arguments` value (see `PendingCall`) and
//! nothing more is decided until the matching response arrives. Only once
//! the response is in hand do we know both (a) whether the call errored
//! and (b) whether secrets detection fires on either side — and both of
//! those gate the effective logging tier (see `pump_child_to_client`).
//! Truncating at capture time, like Phase 1 did, would make that ordering
//! impossible: you can't retroactively un-truncate a value to redact a
//! secret that only got cut off by the earlier preview.

use crate::config::{Config, Tier};
use crate::db::{self, DbHandle, ToolCallEntry};
use crate::jsonrpc::RpcMessage;
use crate::secrets::{self, PatternSet, Severity};
use crate::truncate;
use serde::Serialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout, Command};
use tokio::sync::Mutex;

/// Byte cap applied when rendering a value under the `minimal` tier.
/// Unrelated to `standard` tier's semantic truncation (see `truncate.rs`)
/// — this is a blunt, cheap preview for the tier that wants the smallest
/// possible footprint, not a structure-preserving cap.
const PREVIEW_BYTES: usize = 200;

pub(crate) struct PendingCall {
    pub(crate) tool_name: String,
    /// Full, untruncated parsed `arguments` value — see the module-level
    /// doc comment for why this can't be truncated yet at capture time.
    pub(crate) args: Option<Value>,
    pub(crate) bytes_in: i64,
    pub(crate) started: Instant,
}

type PendingMap = Arc<Mutex<HashMap<String, PendingCall>>>;

/// One entry in the `redaction_flags` JSON array stored per row: which
/// pattern fired, at what severity, plus the sha256 of the plaintext secret
/// (never the plaintext itself) so the same secret can be correlated
/// across rows. No `allowlisted` field here -- this array is only ever
/// built from hits already filtered to non-allowlisted ones (see
/// `active_hit_count`/`redaction_flags` below), so it would always read
/// `false` and add nothing.
#[derive(Serialize)]
struct RedactionRecord<'a> {
    pattern: &'a str,
    severity: Severity,
    sha256: &'a str,
}

pub async fn run(config_path: &Path, target: Vec<String>) -> anyhow::Result<()> {
    let config = Arc::new(Config::load(config_path)?);
    let (program, args) = target
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("no target command given after `--`"))?;

    let session_id = uuid::Uuid::new_v4().to_string();
    let server_name = config.server_name_for(program);
    let db = db::spawn_writer(Path::new(&config.logging.db_path));

    // Fail-open: a corrupt/unparseable bundled patterns file must not take
    // the whole proxy down. Falling back to an empty pattern set (which
    // always parses) disables secrets *detection* for the session, not
    // logging itself — the fail-open contract is about the proxied session
    // never being blocked, not about detection always firing.
    let patterns = Arc::new(PatternSet::bundled().unwrap_or_else(|e| {
        tracing::error!(
            "failed to load bundled secrets patterns ({e}); secrets detection disabled for this session"
        );
        PatternSet::from_str("").expect("empty pattern set always parses")
    }));

    // Fail-open, same rationale as the patterns load above: on first run
    // the db file won't exist yet, and a read-only open failure here must
    // never block the proxied session. An empty set just means every
    // detected secret is redacted (the correct default) rather than
    // `unmask`'s allowlist entries silently never taking effect.
    let allowlist: Arc<HashSet<String>> = Arc::new(
        db::open_readonly(Path::new(&config.logging.db_path))
            .and_then(|conn| db::load_allowlist(&conn))
            .unwrap_or_else(|e| {
                tracing::warn!("failed to load secret allowlist ({e}); starting with an empty allowlist");
                HashSet::new()
            }),
    );

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
        patterns,
        allowlist,
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
                    let args = msg.arguments().cloned();
                    let mut guard = pending.lock().await;
                    guard.insert(
                        id_key,
                        PendingCall {
                            tool_name,
                            args,
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
    patterns: Arc<PatternSet>,
    allowlist: Arc<HashSet<String>>,
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

        let configured_tier = config.tier_for_tool(&call.tool_name);
        let entry = build_entry(
            call,
            &msg,
            buf.len() as i64,
            &session_id,
            &server_name,
            configured_tier,
            &patterns,
            &allowlist,
        );

        db.log(entry);
    }
}

/// Builds the `ToolCallEntry` for one completed tools/call from the parsed
/// response and its pending request state: detect secrets → decide status →
/// escalate tier → render the (already redacted) values → assemble the row.
/// Pure data transformation, no I/O and no awaits — extracted from
/// `pump_child_to_client` so this whole pipeline is regression-testable end
/// to end (see `db::tests::secret_in_sentence_is_redacted_in_the_actual_stored_row`):
/// a bug where the redacted value and the value actually persisted diverge
/// would be invisible to unit tests that only assert on
/// `scan_and_redact_json`'s in-memory output.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_entry(
    call: PendingCall,
    msg: &RpcMessage,
    bytes_out: i64,
    session_id: &str,
    server_name: &str,
    configured_tier: Tier,
    patterns: &PatternSet,
    allowlist: &HashSet<String>,
) -> ToolCallEntry {
    let duration_ms = call.started.elapsed().as_millis() as i64;
    // Covers both a JSON-RPC-level error (e.g. "method not found") and
    // the MCP convention of a tool's own failure reported inside an
    // otherwise-successful result via `isError: true` (e.g. a delete
    // tool that ran but couldn't find the file) -- per the threat
    // model, a failed destructive tool call must never be under-logged
    // by only checking the JSON-RPC transport-level error field.
    let is_error = msg.is_error_response() || msg.is_mcp_tool_error();
    let status = if is_error { "error" } else { "success" };

    // Secrets detection runs on the full, untruncated args/result/error
    // values before any tier-based truncation is even decided — the
    // decision of *how much* to truncate depends on whether detection
    // fired, so detection must go first.
    let mut args_value = call.args;
    let mut result_value = msg.result.clone();
    let mut error_value = msg.error.clone();

    let mut hits = Vec::new();
    if let Some(v) = args_value.as_mut() {
        hits.extend(secrets::scan_and_redact_json(v, patterns, allowlist));
    }
    if let Some(v) = result_value.as_mut() {
        hits.extend(secrets::scan_and_redact_json(v, patterns, allowlist));
    }
    if let Some(v) = error_value.as_mut() {
        hits.extend(secrets::scan_and_redact_json(v, patterns, allowlist));
    }

    // Allowlisted hits are confirmed false positives (left unredacted
    // by `scan_and_redact_json` itself) -- they must not count toward
    // escalation or the stored redaction metadata, only genuine,
    // still-redacted hits do.
    let active_hit_count = hits.iter().filter(|h| !h.allowlisted).count();
    let secrets_fired = active_hit_count > 0;

    // Tier escalation: configured tier, forced to `full` if secrets
    // fired anywhere in this call or the call errored. Anomalies (a
    // leaked secret, a failing tool call) must never be hidden by
    // truncation, regardless of what the user configured for this tool.
    let effective_tier = if secrets_fired || is_error { Tier::Full } else { configured_tier };

    // Truncation runs AFTER redaction, on the already-redacted values,
    // so it can never slice a secret in half before detection catches
    // it, and never re-exposes a redaction marker by cutting around it.
    // These are the SAME `*_value` bindings `scan_and_redact_json` mutated
    // above — no clone of the pre-redaction originals survives past this
    // point, so what gets rendered is provably the redacted tree.
    let args_json = args_value.map(|v| render_tier(&v, effective_tier));
    let result_json = result_value.map(|v| render_tier(&v, effective_tier));
    let error_message = error_value.map(|v| render_tier(&v, effective_tier));

    // Structured, not a flat array of pattern names: each entry pairs
    // the pattern (plus its severity) with the sha256 of the plaintext
    // secret it matched, so the same leaked value can be correlated
    // across separate tool calls/rows without ever persisting the
    // plaintext itself. This is a data-SHAPE change to `redaction_flags`
    // (still the same TEXT column, no migration) — `query`/`export`
    // must parse this as `[{"pattern":..,"severity":..,"sha256":..}, ...]`,
    // not `["pattern", ...]`.
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
        status: status.to_string(),
        error_message,
        duration_ms: Some(duration_ms),
        bytes_in: Some(call.bytes_in),
        bytes_out: Some(bytes_out),
        source: None,
        destination: None,
        redaction_flags,
        redaction_count: active_hit_count as i64,
        anomaly_score: None,
        anomaly_reasons: None,
    }
}

/// Renders a (already redacted) JSON value to its stored string form under
/// the given effective tier. `minimal` keeps Phase 1's blunt byte-preview
/// behavior; `standard` applies structure-preserving semantic truncation;
/// `full` stores the value as-is.
fn render_tier(value: &Value, tier: Tier) -> String {
    match tier {
        Tier::Minimal => truncate_preview(&value.to_string()),
        Tier::Standard => truncate::truncate_json_semantic(value).to_string(),
        Tier::Full => value.to_string(),
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
    let end = truncate::snap_boundary(s, PREVIEW_BYTES);
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
