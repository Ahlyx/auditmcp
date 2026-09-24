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
use crate::shutdown::{self, InboundExit, Stop, DRAIN_TIMEOUT, PUMP_SHUTDOWN_TIMEOUT};
use std::collections::HashSet;
use std::io::{BufRead, Write};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, ChildStdout, Command};

/// Cap on a single buffered line. MCP framing is newline-delimited JSON-RPC,
/// so one line is one message; a peer that emits gigabytes without a newline
/// is not speaking MCP. Mirrors the HTTP transport's request cap in spirit
/// (`MAX_REQUEST_BYTES`): exceeding it is refused rather than truncated,
/// because forwarding half a message would corrupt the peer's view of the
/// protocol -- and buffering it whole would let a hostile or broken peer
/// exhaust memory through a proxy that promised fail-open.
const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;
type SharedDbHandle = Arc<std::sync::Mutex<Option<DbHandle>>>;

#[derive(Clone)]
struct PumpContext {
    session: Arc<Session>,
    db: SharedDbHandle,
    server_name: String,
    config: Arc<Config>,
    patterns: Arc<PatternSet>,
    allowlist: Arc<HashSet<String>>,
}

pub async fn run(config_path: &Path, target: Vec<String>) -> anyhow::Result<()> {
    // Windows: holds the console-close/shutdown teardown grace open while
    // the drain below runs, instead of racing a forced kill. No-op on Unix.
    shutdown::install_blocking_close_handler();

    let config = Arc::new(Config::load(config_path)?);
    let target = config.resolve_target(target)?;
    // Windows: the majority of real MCP servers launch through `.cmd`
    // shims (`npx`, `npm`, `uvx`), which `CreateProcess` will not resolve
    // or execute directly -- only `.exe` (or extensionless names that
    // resolve to one). Without this, `run -- npx -y some/server` fails
    // with "program not found" even though `npx` is on PATH.
    let target = maybe_wrap_windows_shim(target);
    let (program, args) = target
        .split_first()
        .expect("resolve_target rejects an empty command");

    // Exactly one session: stdio proxies exactly one client, so all
    // JSON-RPC ids on this pipe come from that one caller and are
    // unambiguous. See `session.rs` for why the scope has to exist anyway.
    let session = Arc::new(Session::new(uuid::Uuid::new_v4().to_string()));
    let server_name = config.server_name_for(program);

    let db_path = Path::new(&config.logging.db_path);
    // Phase 3.5: decides fresh-HMAC vs. existing-HMAC vs. legacy, and
    // refuses to start outright if this database is HMAC-protected but the
    // key can't be loaded or doesn't verify -- see `chain::bootstrap`.
    let key_path = config.chain.resolved_key_path()?;
    let chain_mode = crate::chain::bootstrap(
        db_path,
        &key_path,
        crate::chain::GenesisSettings {
            heartbeat_cadence_min_secs: config.heartbeat.cadence_min_secs,
            heartbeat_cadence_max_secs: config.heartbeat.cadence_max_secs,
            heartbeat_enabled: config.heartbeat.enabled,
            anchor_enabled: config.anchor.enabled,
        },
    )?;

    // Refuses to start if the database can't be opened -- see
    // `db::spawn_writer` for why that is not a fail-open case.
    let (db, writer) = db::spawn_writer_with_key(db_path, chain_mode.hash_key())?;
    let lease = crate::lease::SessionLease::create(db_path)?;
    match crate::recovery::recover_abandoned(db_path, &db) {
        Ok(count) if count > 0 => tracing::warn!(
            count,
            "appended session abandonment evidence for {count} previously terminated session(s)"
        ),
        Ok(_) => {}
        Err(error) => tracing::warn!(
            "could not scan for abandoned sessions; sessions without reliable evidence remain unknown: {error}"
        ),
    }

    let (heartbeat_min, heartbeat_max) = chain_mode.heartbeat_cadence();
    if config.heartbeat.enabled {
        db.log(crate::heartbeat::session_start_entry_with_lease(
            session.id(),
            &server_name,
            heartbeat_min,
            heartbeat_max,
            lease.id(),
        ));
    }
    let heartbeat_task = config.heartbeat.enabled.then(|| {
        tokio::spawn(crate::heartbeat::run(
            db.clone(),
            session.id().to_string(),
            server_name.clone(),
            heartbeat_min,
            heartbeat_max,
        ))
    });

    // Anchor needs a real key: a legacy (unkeyed) chain has nothing to
    // derive one from, so anchoring is silently unavailable there rather
    // than refusing to start -- see the fail-open contract.
    let anchor_task = match (config.anchor.enabled, chain_mode.anchor_key()) {
        (true, Some(anchor_key)) => {
            let anchor_path = crate::anchor::resolve_anchor_path(&config.anchor.path)?;
            Some(tokio::spawn(crate::anchor::run(
                db_path.to_path_buf(),
                anchor_path,
                anchor_key,
                config.anchor.cadence_secs,
            )))
        }
        (true, None) => {
            tracing::warn!(
                "[anchor] is enabled but this is a legacy (unkeyed) chain, which has no key \
                 to anchor with; anchoring is skipped for this session. Run `auditmcp reset \
                 --keep-old` to migrate to an HMAC-protected chain."
            );
            None
        }
        (false, _) => None,
    };

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
        .kill_on_drop(true)
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
    let client_lines = spawn_client_stdin_reader()?;
    let client_output = spawn_client_stdout_writer()?;
    let inbound_db: SharedDbHandle = Arc::new(std::sync::Mutex::new(Some(db.clone())));
    let outbound_db: SharedDbHandle = Arc::new(std::sync::Mutex::new(Some(db.clone())));
    let pump_context = PumpContext {
        session: Arc::clone(&session),
        db: Arc::clone(&inbound_db),
        server_name: server_name.clone(),
        config: Arc::clone(&config),
        patterns: Arc::clone(&patterns),
        allowlist: Arc::clone(&allowlist),
    };

    let (inbound_stop_tx, inbound_stop_rx) = tokio::sync::oneshot::channel();
    let mut inbound = tokio::spawn(pump_client_to_child(
        child_stdin,
        client_lines,
        inbound_stop_rx,
        pump_context.clone(),
    ));

    let mut outbound = tokio::spawn(pump_child_to_client(
        child_stdout,
        client_output,
        PumpContext {
            db: Arc::clone(&outbound_db),
            ..pump_context
        },
    ));

    // Either the target exits on its own, or we're told to stop. A stop
    // signal must not skip the shutdown path below: everything queued for
    // the audit log would be discarded, which is the same silent gap the
    // writer join exists to prevent, just triggered by a service restart
    // instead of by process exit.
    let (stop, inbound_completed) = tokio::select! {
        result = child.wait() => (
            match result {
                Ok(status) => Stop::TargetExited(status),
                Err(error) => Stop::TargetWaitFailure(error.to_string()),
            },
            false,
        ),
        result = &mut inbound => (
            Stop::InboundEnded(match result {
                Ok(exit) => exit,
                Err(error) => InboundExit::PumpTaskFailure(error.to_string()),
            }),
            true,
        ),
        signal = shutdown::shutdown_signal() => (Stop::Signal(signal), false),
    };

    session.stop_accepting();
    if !inbound_completed {
        // Close the registration gate before cancelling a possibly blocked
        // stdin read. `begin_input` shares this lock, so any line already
        // being registered/logged finishes its synchronous section first.
        if matches!(&stop, Stop::Signal(_) | Stop::TargetWaitFailure(_)) {
            let _ = child.start_kill();
        }
        let _ = inbound_stop_tx.send(());
        match tokio::time::timeout(PUMP_SHUTDOWN_TIMEOUT, &mut inbound).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::warn!("client input pump failed while stopping: {error}"),
            Err(_) => {
                tracing::warn!("client input pump did not stop within the shutdown window");
                // The closed registration gate still protects the drain if
                // a platform stdin read cannot be interrupted promptly.
                inbound.abort();
            }
        }
    }
    // The closed input gate prevents further registrations. Release the
    // pump's writer handle even if a platform input read returns late.
    inbound_db.lock().unwrap_or_else(|e| e.into_inner()).take();

    let (target_status, target_wait_error) = match &stop {
        Stop::TargetExited(status) => (Some(*status), None),
        Stop::InboundEnded(exit) => {
            match exit {
                InboundExit::ClientEof => {
                    tracing::info!("client closed stdin; stopping the target")
                }
                InboundExit::ClientReadFailure(error) => {
                    tracing::warn!("client stdin failed; stopping the target: {error}");
                }
                InboundExit::TargetWriteFailure(error) => {
                    tracing::warn!("target stdin failed; stopping the target: {error}");
                }
                InboundExit::TargetFlushFailure(error) => {
                    tracing::warn!("target stdin flush failed; stopping the target: {error}");
                }
                InboundExit::ProtocolSizeRefusal(bytes) => {
                    tracing::warn!(
                        "refusing oversized client message ({bytes} bytes); stopping the target"
                    );
                }
                InboundExit::PumpTaskFailure(error) => {
                    tracing::warn!("client input pump failed; stopping the target: {error}");
                }
                InboundExit::ShutdownRequested => {}
            }
            // Returning from the inbound pump closed ChildStdin. Give a
            // cooperative target time to observe EOF and exit cleanly.
            match tokio::time::timeout(shutdown::TARGET_EXIT_GRACE, child.wait()).await {
                Ok(Ok(status)) => (Some(status), None),
                Ok(Err(error)) => (None, Some(error.to_string())),
                Err(_) => {
                    tracing::warn!(
                        "target did not exit within {}s after client input closed; terminating it",
                        shutdown::TARGET_EXIT_GRACE.as_secs()
                    );
                    let _ = child.start_kill();
                    match tokio::time::timeout(PUMP_SHUTDOWN_TIMEOUT, child.wait()).await {
                        Ok(Ok(status)) => (Some(status), None),
                        Ok(Err(error)) => (None, Some(error.to_string())),
                        Err(_) => (
                            None,
                            Some("target did not exit after termination".to_string()),
                        ),
                    }
                }
            }
        }
        Stop::Signal(name) => {
            tracing::warn!("received {name}; stopping the target and flushing the audit log");
            let _ = child.start_kill();
            match tokio::time::timeout(PUMP_SHUTDOWN_TIMEOUT, child.wait()).await {
                Ok(Ok(status)) => (Some(status), None),
                Ok(Err(error)) => (None, Some(error.to_string())),
                Err(_) => (
                    None,
                    Some("target did not exit after termination".to_string()),
                ),
            }
        }
        Stop::TargetWaitFailure(error) => {
            tracing::warn!("failed waiting for target process: {error}; terminating it");
            let _ = child.start_kill();
            match tokio::time::timeout(PUMP_SHUTDOWN_TIMEOUT, child.wait()).await {
                Ok(Ok(status)) => (Some(status), None),
                Ok(Err(wait_error)) => (None, Some(wait_error.to_string())),
                Err(_) => (
                    None,
                    Some("target did not exit after termination".to_string()),
                ),
            }
        }
    };

    // Keep the existing bounded response window. Stdout writes can be
    // backed by non-cancellable OS writes, so on timeout fence resolution,
    // release its DB sender, and abort without awaiting that blocking write.
    let outbound_timed_out = match tokio::time::timeout(PUMP_SHUTDOWN_TIMEOUT, &mut outbound).await
    {
        Ok(Ok(())) => false,
        Ok(Err(error)) => {
            tracing::warn!("target response pump failed: {error}");
            false
        }
        Err(_) => {
            tracing::warn!("target response pump did not finish within the shutdown window");
            true
        }
    };
    session.stop_responses();
    outbound_db.lock().unwrap_or_else(|e| e.into_inner()).take();
    if outbound_timed_out {
        outbound.abort();
    }

    // The input gate and its lock ensure no registration can occur after
    // this point. The response gate similarly waits for any synchronous
    // resolve-and-log section already underway, then prevents later
    // responses from removing calls. Thus the map holds exactly the calls
    // with no logged response, even if a client stdout OS write is still
    // blocked after the bounded pump window.
    //
    // Draining inside the outbound pump at EOF would look more natural and
    // would be wrong: the inbound pump is still live at that moment and
    // could register a fresh call after the drain, which would then never
    // be recorded at all.
    let abandoned = session.drain_abandoned();
    if !abandoned.is_empty() {
        tracing::warn!(
            "shutting down with {} tool call(s) still in flight; \
             logging them as timeouts",
            abandoned.len()
        );
        for call in abandoned {
            log_completed(
                &session,
                call,
                CallOutcome::timed_out(),
                &server_name,
                &config,
                &patterns,
                &allowlist,
                &db,
            );
        }
    }

    if let Some(status) = target_status {
        if !status.success() {
            tracing::warn!("target command exited with status {status}");
        }
    }
    if let Some(error) = target_wait_error {
        tracing::warn!("could not confirm target process exit: {error}");
    }

    // Stop heartbeats before writing __session_end, so a heartbeat can
    // never land after the row that's supposed to close the session.
    if let Some(task) = heartbeat_task {
        task.abort();
        let _ = task.await;
    }
    if let Some(task) = anchor_task {
        task.abort();
        let _ = task.await;
    }
    if config.heartbeat.enabled {
        db.log(crate::heartbeat::session_end_entry(
            session.id(),
            &server_name,
        ));
    }

    // Drop the last sender so the writer's channel closes, then wait for it
    // to finish. Without this the queue is discarded when the process
    // exits — see `DbWriter`. The drop must come first: waiting with a live
    // sender would burn the whole timeout and report a spurious timeout.
    drop(db);
    let drain = writer.wait_for_drain(DRAIN_TIMEOUT);
    // Either way the queue has been written or given up on; the blocking
    // close/shutdown handler must stop holding the OS grace open.
    shutdown::note_drain_complete();
    match drain {
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

    // Keep the lease through the durable writer drain so a concurrent
    // recovery scan cannot mistake this session for a dead process.
    drop(lease);

    Ok(())
}

/// Client stdin -> child stdin. Forwards every line byte-for-byte, and
/// best-effort parses `tools/call` requests to start tracking a pending
/// call. Parsing never gates forwarding: a malformed or non-UTF-8 line is
/// still passed through untouched, just not logged.
async fn pump_client_to_child(
    mut child_in: ChildStdin,
    mut client_lines: tokio::sync::mpsc::Receiver<ClientInput>,
    mut stop_rx: tokio::sync::oneshot::Receiver<()>,
    context: PumpContext,
) -> InboundExit {
    loop {
        let buf = match tokio::select! {
            _ = &mut stop_rx => return InboundExit::ShutdownRequested,
            input = client_lines.recv() => input,
        } {
            Some(ClientInput::Line(line)) => line,
            Some(ClientInput::ReadFailure(error)) => {
                tracing::warn!("error reading from client stdin: {error}");
                return InboundExit::ClientReadFailure(error);
            }
            Some(ClientInput::Oversized(bytes)) => {
                return InboundExit::ProtocolSizeRefusal(bytes);
            }
            Some(ClientInput::Eof) | None => return InboundExit::ClientEof,
        };

        // Register BEFORE forwarding, mirroring the HTTP transport (where
        // `register_if_tool_call` precedes `client.request`). Both writes
        // below are await points on a multithreaded runtime, so a fast
        // target can answer a trivial tool call while this task is parked
        // inside them; registering first means that response always finds
        // its pending entry instead of vanishing ("nothing to close out")
        // and leaving an orphan to be mis-logged as a timeout at drain.
        {
            let Some(mut input_permit) = context.session.begin_input() else {
                return InboundExit::ShutdownRequested;
            };
            for msg in parse_rpc_messages(&buf) {
                if !msg.is_tool_call_request() {
                    continue;
                }
                if let (Some(id_key), Some(tool_name)) = (msg.id_key(), msg.tool_name()) {
                    let displaced = input_permit.register(
                        id_key,
                        PendingCall {
                            tool_name,
                            args: msg.arguments().cloned(),
                            bytes_in: buf.len() as i64,
                            started: Instant::now(),
                        },
                    );
                    if let Some(stale) = displaced {
                        tracing::warn!(
                            "JSON-RPC id reused for tool '{}' before its previous response \
                             arrived; logging the earlier call as a timeout rather than dropping it",
                            stale.tool_name
                        );
                        let db = context.db.lock().unwrap_or_else(|e| e.into_inner());
                        if let Some(db) = db.as_ref() {
                            log_completed(
                                &context.session,
                                stale,
                                CallOutcome::timed_out(),
                                &context.server_name,
                                &context.config,
                                &context.patterns,
                                &context.allowlist,
                                db,
                            );
                        }
                    }
                }
            }
        }

        if let Err(e) = child_in.write_all(&buf).await {
            tracing::warn!("error writing to child stdin: {e}");
            return InboundExit::TargetWriteFailure(e.to_string());
        }
        if let Err(e) = child_in.flush().await {
            tracing::warn!("error flushing child stdin: {e}");
            return InboundExit::TargetFlushFailure(e.to_string());
        }
    }
}

enum ClientInput {
    Line(Vec<u8>),
    Eof,
    ReadFailure(String),
    Oversized(usize),
}

struct OutputRequest {
    bytes: Vec<u8>,
    reply: tokio::sync::oneshot::Sender<Result<(), String>>,
}

/// Keeps potentially blocking writes to the client's stdout off the Tokio
/// runtime. The output thread holds no session or DB state, so the async
/// response pump can honor its shutdown bound even if the client stopped
/// reading.
fn spawn_client_stdout_writer() -> anyhow::Result<tokio::sync::mpsc::Sender<OutputRequest>> {
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<OutputRequest>(2);
    std::thread::Builder::new()
        .name("auditmcp-stdout-writer".to_string())
        .spawn(move || {
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            while let Some(request) = receiver.blocking_recv() {
                let result = stdout
                    .write_all(&request.bytes)
                    .and_then(|_| stdout.flush())
                    .map_err(|error| error.to_string());
                let failed = result.is_err();
                let _ = request.reply.send(result);
                if failed {
                    break;
                }
            }
        })
        .map_err(|e| anyhow::anyhow!("failed to start client stdout writer: {e}"))?;
    Ok(sender)
}

/// Reads stdin off the async runtime's worker threads. Tokio's stdin adapter
/// uses a blocking read that cannot be interrupted on Windows; a dedicated
/// reader thread sends bounded messages and owns no DB/session state, so a
/// target exit can stop the async pump without waiting for client EOF.
fn spawn_client_stdin_reader() -> anyhow::Result<tokio::sync::mpsc::Receiver<ClientInput>> {
    let (sender, receiver) = tokio::sync::mpsc::channel(2);
    std::thread::Builder::new()
        .name("auditmcp-stdin-reader".to_string())
        .spawn(move || {
            let stdin = std::io::stdin();
            let mut reader = stdin.lock();
            loop {
                let input = match read_client_line(&mut reader, MAX_LINE_BYTES) {
                    Ok(input) => input,
                    Err(error) => ClientInput::ReadFailure(error.to_string()),
                };
                let done = matches!(
                    &input,
                    ClientInput::Eof | ClientInput::ReadFailure(_) | ClientInput::Oversized(_)
                );
                if sender.blocking_send(input).is_err() || done {
                    break;
                }
            }
        })
        .map_err(|e| anyhow::anyhow!("failed to start client stdin reader: {e}"))?;
    Ok(receiver)
}

fn read_client_line(reader: &mut impl BufRead, max_bytes: usize) -> std::io::Result<ClientInput> {
    let mut line = Vec::new();
    loop {
        let available = reader.fill_buf()?;
        if available.is_empty() {
            return Ok(if line.is_empty() {
                ClientInput::Eof
            } else {
                ClientInput::Line(line)
            });
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let take = newline.map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > max_bytes {
            return Ok(ClientInput::Oversized(line.len().saturating_add(take)));
        }
        line.extend_from_slice(&available[..take]);
        reader.consume(take);
        if newline.is_some() {
            return Ok(ClientInput::Line(line));
        }
    }
}

/// The single place the stdio transport turns a completed or abandoned call
/// into a row, so the tier lookup, the pipeline inputs, and the anomaly
/// attachment cannot drift between the response path, the id-reuse path,
/// and the shutdown drain -- the same single-entry-point shape
/// `http::server::log_entry` provides for the HTTP transports.
#[allow(clippy::too_many_arguments)] // mirrors http's log_entry; bundling the pipeline inputs would obscure the uniformity it exists to enforce
fn log_completed(
    session: &Session,
    call: PendingCall,
    outcome: CallOutcome,
    server_name: &str,
    config: &Config,
    patterns: &PatternSet,
    allowlist: &HashSet<String>,
    db: &DbHandle,
) {
    let configured_tier = config.tier_for_tool(&call.tool_name);
    let (mut entry, dest) = audit::build_entry(
        call,
        outcome,
        session.id(),
        server_name,
        configured_tier,
        patterns,
        allowlist,
    );
    session.attach_anomaly(&mut entry, dest.as_ref(), Instant::now());
    db.log(entry);
}

/// Child stdout -> client stdout. Forwards every line byte-for-byte, and
/// best-effort parses responses to close out a pending call and submit a
/// `ToolCallEntry`. Same fail-open contract as `pump_client_to_child`.
async fn pump_child_to_client(
    child_out: ChildStdout,
    client_output: tokio::sync::mpsc::Sender<OutputRequest>,
    context: PumpContext,
) {
    let mut reader = BufReader::new(child_out);
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
        if buf.len() > MAX_LINE_BYTES && !buf.ends_with(b"\n") {
            tracing::warn!(
                "target sent {} bytes without a newline; refusing to buffer \
                 further -- closing the session rather than growing memory \
                 without bound",
                buf.len()
            );
            break;
        }

        let (reply, written) = tokio::sync::oneshot::channel();
        if client_output
            .send(OutputRequest {
                bytes: buf.clone(),
                reply,
            })
            .await
            .is_err()
        {
            tracing::warn!("client stdout writer is unavailable");
            break;
        }
        match written.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                tracing::warn!("error writing to client stdout: {error}");
                break;
            }
            Err(_) => {
                tracing::warn!("client stdout writer stopped before forwarding a line");
                break;
            }
        }

        let msgs = parse_rpc_messages(&buf);
        for msg in msgs {
            // Notifications and responses to untracked calls resolve
            // nothing; a replay of an already-resolved id finds nothing the
            // second time. Either way there is nothing to close out.
            let Some(id_key) = msg.id_key() else {
                continue;
            };
            let Some(mut response_permit) = context.session.begin_response() else {
                continue;
            };
            let Some(call) = response_permit.resolve(&id_key) else {
                continue;
            };

            let db = context.db.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(db) = db.as_ref() {
                log_completed(
                    &context.session,
                    call,
                    CallOutcome::from_rpc(&msg, buf.len() as i64),
                    &context.server_name,
                    &context.config,
                    &context.patterns,
                    &context.allowlist,
                    db,
                );
            }
        }
    }
}

/// Best-effort decode of a raw line for logging purposes only. Strips a
/// trailing `\n`/`\r\n` before parsing (the raw bytes forwarded to the peer
/// are never touched by this). Returns an empty vec — never panics — on
/// non-UTF-8 bytes or content with no parseable JSON-RPC envelope, which is
/// expected to happen sometimes (partial reads, non-MCP framing, batches of
/// malformed elements) and must not be treated as fatal.
fn parse_rpc_messages(buf: &[u8]) -> Vec<RpcMessage> {
    let trimmed = strip_trailing_newline(buf);
    match std::str::from_utf8(trimmed) {
        Ok(text) => RpcMessage::parse_batch(text.as_bytes()),
        Err(_) => Vec::new(),
    }
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

/// Windows: resolve `.cmd`/`.bat` shims so `run -- npx -y some/server`
/// works the way every MCP client's own launcher does. `CreateProcess`
/// searches PATH for `name` and `name.exe` but will neither find nor
/// execute `npx.cmd` -- and npm-style global installs ship exactly that
/// shim, making it the single most common MCP target command.
///
/// Returns a possibly-rewritten command vector. A shim is executed via
/// `cmd /c <full path>` because `.cmd`/`.bat` are batch scripts, not
/// executables; args pass through as ordinary quoted arguments, which is
/// correct for the package names and flags MCP launches use.
#[cfg(windows)]
fn maybe_wrap_windows_shim(target: Vec<String>) -> Vec<String> {
    let Some((program, rest)) = target.split_first() else {
        return target;
    };

    // Already a path, or an explicit .exe: CreateProcess handles both.
    let lower = program.to_lowercase();
    let has_path_sep = program.contains('\\') || program.contains('/');
    match () {
        _ if has_path_sep => return target,
        _ if lower.ends_with(".exe") => return target,
        _ if lower.ends_with(".cmd") || lower.ends_with(".bat") => {
            // Explicitly a batch file but not found by path search below
            // would fail anyway; route through cmd regardless of whether
            // PATH lookup locates it, since cmd resolves bare names too.
            let mut out = vec!["cmd".to_string(), "/c".to_string()];
            out.push(match find_on_path(program) {
                Some(full) => full,
                None => program.clone(),
            });
            out.extend(rest.iter().cloned());
            return out;
        }
        _ => {}
    }

    // Extensionless name: prefer what CreateProcess would do (.exe), and
    // only take over when the name resolves to a batch shim instead.
    match find_on_path(&format!("{program}.exe")) {
        Some(_) => target, // let CreateProcess do its normal thing
        None => match find_on_path(&format!("{program}.cmd"))
            .or_else(|| find_on_path(&format!("{program}.bat")))
        {
            Some(shim) => {
                tracing::warn!(
                    "target command '{program}' resolved to batch shim '{shim}'; \
                     launching via 'cmd /c' (Windows cannot execute .cmd shims directly)"
                );
                let mut out = vec!["cmd".to_string(), "/c".to_string(), shim];
                out.extend(rest.iter().cloned());
                out
            }
            // Nothing anywhere on PATH: leave untouched so the spawn fails
            // with the original, honest "program not found" error.
            None => target,
        },
    }
}

/// Searches PATH for an exact file name and returns its first absolute hit.
#[cfg(windows)]
fn find_on_path(file_name: &str) -> Option<String> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|dir| dir.join(file_name))
        .find(|candidate| candidate.is_file())
        .map(|found| found.to_string_lossy().into_owned())
}

#[cfg(not(windows))]
fn maybe_wrap_windows_shim(target: Vec<String>) -> Vec<String> {
    target
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rpc_messages_returns_empty_on_invalid_utf8() {
        let invalid_utf8 = vec![0xff, 0xfe, 0xfd, b'\n'];
        assert!(parse_rpc_messages(&invalid_utf8).is_empty());
    }

    #[test]
    fn parse_rpc_messages_returns_empty_on_malformed_json() {
        assert!(parse_rpc_messages(b"not json at all\n").is_empty());
    }

    /// A batch (top-level array) parses into one RpcMessage per element,
    /// so a batched tools/call is audited rather than silently forwarded
    /// with no trace. This is the stdio-side half of the contract the HTTP
    /// transport shares.
    #[test]
    fn parse_rpc_messages_handles_batches() {
        let line = br#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","arguments":{}}},
                      {"jsonrpc":"2.0","method":"notifications/initialized"}]
"#;
        let msgs = parse_rpc_messages(line);
        assert_eq!(msgs.len(), 2);
        assert_eq!(
            msgs.iter().filter(|m| m.is_tool_call_request()).count(),
            1,
            "exactly one element is a tools/call"
        );
        assert_eq!(msgs[0].tool_name().as_deref(), Some("a"));
    }
}
