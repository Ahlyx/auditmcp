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
//!
//! If the target server exits with calls still in flight, those calls are
//! logged as `timeout` rows rather than vanishing — a tool call that was
//! issued and never answered is exactly the kind of gap an audit log is
//! supposed to show. See the drain at the end of `run`.

use crate::audit::{self, CallOutcome};
use crate::config::Config;
use crate::db::{self, DbHandle};
use crate::jsonrpc::RpcMessage;
use crate::secrets::PatternSet;
use crate::session::{PendingCall, Session};
use crate::shutdown::{self, Stop, DRAIN_TIMEOUT, PUMP_SHUTDOWN_TIMEOUT};
use std::collections::HashSet;
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout, Command};

pub async fn run(config_path: &Path, target: Vec<String>) -> anyhow::Result<()> {
    let config = Arc::new(Config::load(config_path)?);
    let target = config.resolve_target(target)?;
    let (program, args) = target
        .split_first()
        .expect("resolve_target rejects an empty command");

    // Exactly one session: stdio proxies exactly one client, so all
    // JSON-RPC ids on this pipe come from that one caller and are
    // unambiguous. See `session.rs` for why the scope has to exist anyway.
    let session = Arc::new(Session::new(uuid::Uuid::new_v4().to_string()));
    let server_name = config.server_name_for(program);
    // Refuses to start if the database can't be opened -- see
    // `db::spawn_writer` for why that is not a fail-open case.
    let (db, writer) = db::spawn_writer(Path::new(&config.logging.db_path))?;

    // Also refuses to start, for a different reason: `patterns.toml` is
    // compiled into the binary with `include_str!`, so this parse is
    // deterministic and a test asserts it succeeds. Failing here means the
    // binary itself is broken, not that the environment is unusual. The
    // old behavior -- fall back to an empty pattern set and carry on --
    // meant a build defect turned into a session that stored every secret
    // it saw in the clear, while looking exactly like a healthy one.
    //
    // This stays correct only while the pattern set is compile-time. If a
    // user-supplied `patterns_path` is ever added (the spec's
    // "user-updatable" patterns file, deliberately not built -- see the
    // README), a malformed user file becomes an ordinary runtime failure
    // that fails toward under-redaction, and refusing to start would be
    // the wrong response to someone's typo. See `db::ToolCallEntry` for
    // what to do instead.
    let patterns = Arc::new(PatternSet::bundled().map_err(|e| {
        anyhow::anyhow!(
            "bundled secrets patterns failed to load: {e}. This is a defect in \
             this build of auditmcp, not a problem with your configuration -- \
             refusing to start rather than proxy with secrets detection disabled."
        )
    })?);

    // Fail-open, same rationale as the patterns load above: on first run
    // the db file won't exist yet, and a read-only open failure here must
    // never block the proxied session. An empty set just means every
    // detected secret is redacted (the correct default) rather than
    // `unmask`'s allowlist entries silently never taking effect.
    let allowlist: Arc<HashSet<String>> = Arc::new(
        db::open_readonly(Path::new(&config.logging.db_path))
            .and_then(|conn| db::load_allowlist(&conn))
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "failed to load secret allowlist ({e}); starting with an empty allowlist"
                );
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

    let inbound = tokio::spawn(pump_client_to_child(child_stdin, Arc::clone(&session)));

    let outbound = tokio::spawn(pump_child_to_client(
        child_stdout,
        Arc::clone(&session),
        db.clone(),
        server_name.clone(),
        Arc::clone(&config),
        Arc::clone(&patterns),
        Arc::clone(&allowlist),
    ));

    // Either the target exits on its own, or we're told to stop. A stop
    // signal must not skip the shutdown path below: everything queued for
    // the audit log would be discarded, which is the same silent gap the
    // writer join exists to prevent, just triggered by a service restart
    // instead of by process exit.
    let stop = tokio::select! {
        result = child.wait() => Stop::TargetExited(
            result.map_err(|e| anyhow::anyhow!("failed waiting on child process: {e}"))?,
        ),
        signal = shutdown::shutdown_signal() => Stop::Signal(signal),
    };

    if let Stop::Signal(name) = stop {
        tracing::warn!("received {name}; stopping the target and flushing the audit log");
        // Ends the target, which closes its stdout and lets the outbound
        // pump finish on its own rather than being cut off mid-message.
        let _ = child.start_kill();
    }

    // The inbound pump reads from *our* real stdin, which is driven by the
    // external client, not by the child — it has no natural reason to end
    // just because the child exited, and could otherwise block this
    // function (and the whole proxy process) from returning indefinitely
    // if the client keeps its stdin open without sending anything further.
    // The outbound pump, in contrast, is bounded by the child's stdout
    // closing, which just happened.
    inbound.abort();
    // Bounded even so: on the signal path the target was asked to die
    // rather than having exited, and a target that ignores the request
    // would otherwise hold shutdown open indefinitely. Anything still in
    // flight when this expires is drained as a timeout below.
    if tokio::time::timeout(PUMP_SHUTDOWN_TIMEOUT, outbound)
        .await
        .is_err()
    {
        tracing::warn!("target did not close its output within the shutdown window");
    }

    // Both pumps have now stopped, which is what makes this safe to do
    // here and nowhere else. Nothing can still be registering a call
    // (inbound is aborted) and nothing can still be resolving one
    // (outbound has run to completion, and it processes each message to
    // its `db.log` before reading the next). So the map holds exactly the
    // calls that never got a response, with no window in which a landing
    // response could be logged twice — once by `resolve` and again here.
    //
    // Draining inside the outbound pump at EOF would look more natural and
    // would be wrong: the inbound pump is still live at that moment and
    // could register a fresh call after the drain, which would then never
    // be recorded at all.
    let abandoned = session.drain_abandoned().await;
    if !abandoned.is_empty() {
        tracing::warn!(
            "shutting down with {} tool call(s) still in flight; \
             logging them as timeouts",
            abandoned.len()
        );
        for call in abandoned {
            let configured_tier = config.tier_for_tool(&call.tool_name);
            db.log(audit::build_entry(
                call,
                CallOutcome::timed_out(),
                session.id(),
                &server_name,
                configured_tier,
                &patterns,
                &allowlist,
            ));
        }
    }

    if let Stop::TargetExited(status) = stop {
        if !status.success() {
            tracing::warn!("target command exited with status {status}");
        }
    }

    // Drop the last sender so the writer's channel closes, then wait for it
    // to finish. Without this the queue is discarded when the process
    // exits — see `DbWriter`. The drop must come first: waiting with a live
    // sender would burn the whole timeout and report a spurious timeout.
    drop(db);
    match writer.wait_for_drain(DRAIN_TIMEOUT) {
        db::DrainOutcome::Drained { dropped: 0 } => {}
        db::DrainOutcome::Drained { dropped } => {
            return Err(anyhow::anyhow!(
                "audit log incomplete: {dropped} tool call(s) were not recorded \
                 this session (see the warnings above for why). The calls still \
                 happened -- the record of them did not."
            ));
        }
        db::DrainOutcome::TimedOut { dropped } => {
            return Err(anyhow::anyhow!(
                "audit log incomplete: the writer did not finish within {}s of \
                 shutdown, so an unknown number of queued tool calls were not \
                 written{}. Shutting down anyway rather than hanging.",
                DRAIN_TIMEOUT.as_secs(),
                if dropped > 0 {
                    format!(", on top of {dropped} already dropped")
                } else {
                    String::new()
                }
            ));
        }
    }

    Ok(())
}

/// Client stdin -> child stdin. Forwards every line byte-for-byte, and
/// best-effort parses `tools/call` requests to start tracking a pending
/// call. Parsing never gates forwarding: a malformed or non-UTF-8 line is
/// still passed through untouched, just not logged.
async fn pump_client_to_child(mut child_in: ChildStdin, session: Arc<Session>) {
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
                    session
                        .register(
                            id_key,
                            PendingCall {
                                tool_name,
                                args: msg.arguments().cloned(),
                                bytes_in: buf.len() as i64,
                                started: Instant::now(),
                            },
                        )
                        .await;
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
    session: Arc<Session>,
    db: DbHandle,
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

        // Response to something we didn't track (not a tools/call), or a
        // replay of one already resolved — either way there is nothing to
        // close out and nothing to log.
        let Some(call) = session.resolve(&id_key).await else {
            continue;
        };

        let configured_tier = config.tier_for_tool(&call.tool_name);
        let entry = audit::build_entry(
            call,
            CallOutcome::from_rpc(&msg, buf.len() as i64),
            session.id(),
            &server_name,
            configured_tier,
            &patterns,
            &allowlist,
        );

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

#[cfg(test)]
mod tests {
    use super::*;

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
