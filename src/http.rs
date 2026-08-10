//! `auditmcp serve` — HTTP reverse proxy in front of one or more MCP
//! servers.
//!
//! Each `[[server]]` gets its own loopback port that mirrors exactly one
//! upstream at the origin level: every path and every method is forwarded
//! with only the scheme and authority swapped. Nothing is routed, nothing
//! is rewritten. That is what lets one implementation sit in front of all
//! three generations of MCP-over-HTTP in the field — legacy HTTP+SSE, the
//! session-based Streamable HTTP of 2025-03-26 through 2025-11-25, and the
//! stateless Streamable HTTP of 2026-07-28 — because the only thing this
//! module interprets is the JSON-RPC envelope, which is identical in all of
//! them. Transparency and interoperability are the same property here.
//!
//! Origin-level rather than path-prefixed for a concrete reason: OAuth
//! discovery derives `.well-known/oauth-protected-resource` from the URL
//! the client was given, so a proxy that only forwarded one path would
//! break authorization before it began.
//!
//! # Streaming
//!
//! Responses are forwarded frame by frame as the upstream produces them,
//! with a bounded copy taken alongside for the audit log (see [`TeeBody`]).
//! Nothing waits for a body to finish, so an event stream reaches the
//! client live and a `subscriptions/listen` stream that stays open for
//! hours costs constant memory. Auditing must never become a reason the
//! agent waits.
//!
//! # Correlation scope
//!
//! A listener owns its sessions and a session owns its pending calls; see
//! `session.rs`. Nothing is shared between listeners, so a JSON-RPC id can
//! only ever resolve a call registered on the same connection to the same
//! listener. That is ownership rather than a key that has to be built
//! correctly every time.

use crate::audit::{self, CallOutcome};
use crate::config::{Config, ServerConfig};
use crate::db::{self, DbHandle};
use crate::jsonrpc::RpcMessage;
use crate::secrets::PatternSet;
use crate::session::{PendingCall, Session};
use crate::shutdown::{self, DRAIN_TIMEOUT};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioIo;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::Mutex;

/// Cap on a request body, which must be buffered because it has to be
/// re-sent upstream. Generous for JSON-RPC, which is what MCP request
/// bodies are, and bounded so a hostile client cannot exhaust memory.
/// Exceeding it is refused rather than truncated: forwarding half a request
/// would corrupt the server's view of the protocol.
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

/// Cap on how much of a *response* is captured for the audit log.
///
/// Deliberately much smaller than the request cap, and deliberately not a
/// limit on what is forwarded. Responses stream through untouched however
/// large they are; this only bounds the copy kept for auditing, so a
/// gigabyte download or a long-lived event stream costs constant memory.
/// Going over it truncates the record and says so — it never delays or
/// truncates what the client receives.
const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

/// Cap on a single un-terminated SSE event while parsing. An event that
/// grows past this is abandoned and the parser resynchronises at the next
/// event boundary, so a stream that never emits one cannot grow the buffer
/// without bound.
const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

/// Incremental Server-Sent Events parser.
///
/// Hand-written rather than pulled from a crate because this stream is
/// forwarded as well as read: the bytes go to the client untouched and a
/// copy is parsed alongside, which a crate that consumes the stream would
/// fight. It only needs what MCP puts on the wire — `data:` payloads,
/// events terminated by a blank line — and must ignore the `:` keep-alive
/// comments servers send during quiet periods on a `subscriptions/listen`
/// stream.
#[derive(Default)]
struct SseParser {
    buf: Vec<u8>,
    /// Set when an event outgrew the cap: bytes are discarded until the
    /// next boundary rather than parsed as a corrupt fragment.
    resyncing: bool,
}

impl SseParser {
    /// Feeds one chunk and returns every `data` payload completed by it.
    fn feed(&mut self, chunk: &[u8]) -> Vec<String> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();

        while let Some(end) = find_event_end(&self.buf) {
            let event: Vec<u8> = self.buf.drain(..end.0).collect();
            self.buf.drain(..end.1);
            if self.resyncing {
                self.resyncing = false;
                continue;
            }
            if let Some(data) = data_payload(&event) {
                out.push(data);
            }
        }

        if self.buf.len() > MAX_SSE_EVENT_BYTES {
            self.buf.clear();
            self.resyncing = true;
        }
        out
    }
}

/// Offset of an event terminator and its length (`\n\n` or `\r\n\r\n`).
fn find_event_end(buf: &[u8]) -> Option<(usize, usize)> {
    let crlf = buf.windows(4).position(|w| w == b"\r\n\r\n");
    let lf = buf.windows(2).position(|w| w == b"\n\n");
    match (crlf, lf) {
        (Some(c), Some(l)) if c <= l => Some((c, 4)),
        (_, Some(l)) => Some((l, 2)),
        (Some(c), None) => Some((c, 4)),
        (None, None) => None,
    }
}

/// The concatenated `data:` lines of one event, or `None` for an event
/// that carries none (a comment-only keep-alive, or `event:`-only frames).
fn data_payload(event: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(event).ok()?;
    let mut data = String::new();
    for line in text.lines() {
        // Per the SSE spec a line starting with ':' is a comment. Servers
        // emit bare ':' lines as keep-alives on idle streams.
        if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
        }
    }
    (!data.is_empty()).then_some(data)
}

/// The body type returned to clients: either a streamed upstream response
/// or a small locally-generated error.
type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Everything a listener needs to serve and audit. Immutable after
/// construction apart from the session registry, which is per-listener.
struct Listener {
    server_name: String,
    upstream: http::Uri,
    allowed_origins: Vec<String>,
    config: Arc<Config>,
    db: DbHandle,
    patterns: Arc<PatternSet>,
    allowlist: Arc<HashSet<String>>,
    client: Client<HttpConnector, Full<Bytes>>,
    sessions: SessionRegistry,
}

/// The sessions of ONE listener.
///
/// Deliberately not a process-wide map keyed by (listener, connection, id):
/// that is the composite key this design rejected, and a single mis-built
/// key there attributes one caller's response to another caller's request
/// in an audit log. Here a listener holds its own registry and hands each
/// connection its own `Session`, so the mistake has no way to be made.
#[derive(Default)]
struct SessionRegistry {
    next_id: AtomicU64,
    open: Mutex<HashMap<u64, Arc<Session>>>,
}

impl SessionRegistry {
    /// Opens a session for one connection. `conn:` records how this
    /// session's identity was derived, because that differs per protocol
    /// generation and a `session_id` that silently means different things
    /// in different rows is worse than one that says which it is.
    async fn open(&self) -> (u64, Arc<Session>) {
        let key = self.next_id.fetch_add(1, Ordering::Relaxed);
        let session = Arc::new(Session::new(format!("conn:{}", uuid::Uuid::new_v4())));
        self.open.lock().await.insert(key, Arc::clone(&session));
        (key, session)
    }

    /// Closes a session and returns any calls left unanswered on it, so the
    /// connection handler can log them rather than let them vanish.
    async fn close(&self, key: u64) -> Vec<PendingCall> {
        let session = self.open.lock().await.remove(&key);
        match session {
            Some(s) => s.drain_abandoned(),
            None => Vec::new(),
        }
    }

    /// Every session still open, for the shutdown drain.
    async fn take_all(&self) -> Vec<Arc<Session>> {
        self.open.lock().await.drain().map(|(_, s)| s).collect()
    }
}

/// The response body handed back to the client: the upstream's own body,
/// forwarded frame by frame, with a bounded copy taken on the way past.
///
/// **Forwarding never waits for auditing.** Each frame is passed on in the
/// same poll that captures it, and capture is a bounded copy, so the client
/// sees bytes at exactly the rate the upstream produces them. Reading the
/// body to completion before returning it — which is what this replaces —
/// would have made a slow upstream into a slow proxy and an event stream
/// into a hang, i.e. would have made the audit tool a blocking dependency
/// of the agent it audits. That is the one thing the design says it must
/// never be.
struct TeeBody {
    inner: Incoming,
    /// Taken when the stream ends, so the final audit runs exactly once.
    tee: Option<Tee>,
}

struct Tee {
    listener: Arc<Listener>,
    session: Arc<Session>,
    /// Correlation key from the request, used when the response body is
    /// not parseable JSON-RPC and therefore carries no id of its own.
    pending_key: Option<String>,
    succeeded: bool,
    bytes_out: i64,
    mode: TeeMode,
}

enum TeeMode {
    /// A single JSON body: accumulate up to the cap, audit when it ends.
    Whole { captured: Vec<u8>, truncated: bool },
    /// An event stream: audit each complete message as it goes by, and
    /// never accumulate, so a stream that stays open for hours costs
    /// nothing.
    Events(SseParser),
}

impl TeeBody {
    fn new(
        inner: Incoming,
        listener: Arc<Listener>,
        session: Arc<Session>,
        pending_key: Option<String>,
        succeeded: bool,
        is_event_stream: bool,
    ) -> Self {
        TeeBody {
            inner,
            tee: Some(Tee {
                listener,
                session,
                pending_key,
                succeeded,
                bytes_out: 0,
                mode: if is_event_stream {
                    TeeMode::Events(SseParser::default())
                } else {
                    TeeMode::Whole {
                        captured: Vec::new(),
                        truncated: false,
                    }
                },
            }),
        }
    }
}

impl hyper::body::Body for TeeBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        let polled = std::pin::Pin::new(&mut this.inner).poll_frame(cx);

        match &polled {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(chunk) = frame.data_ref() {
                    if let Some(tee) = this.tee.as_mut() {
                        tee.observe(chunk);
                    }
                }
            }
            // End of stream, cleanly or otherwise: a body that failed
            // partway is still evidence of a call that happened.
            std::task::Poll::Ready(None) | std::task::Poll::Ready(Some(Err(_))) => {
                if let Some(tee) = this.tee.take() {
                    tee.finish();
                }
            }
            std::task::Poll::Pending => {}
        }
        polled
    }
}

/// Anything left unfinished when the client disconnects mid-response still
/// gets recorded, rather than the call disappearing because nobody polled
/// the body to its end.
impl Drop for TeeBody {
    fn drop(&mut self) {
        if let Some(tee) = self.tee.take() {
            tee.finish();
        }
    }
}

impl Tee {
    /// Called with each frame *after* it has been handed onward. Bounded
    /// work only: a copy for the whole-body case, an incremental parse for
    /// the event-stream case.
    fn observe(&mut self, chunk: &Bytes) {
        self.bytes_out += chunk.len() as i64;
        match &mut self.mode {
            TeeMode::Whole {
                captured,
                truncated,
            } => {
                let room = MAX_CAPTURE_BYTES.saturating_sub(captured.len());
                if room == 0 {
                    *truncated = true;
                } else if chunk.len() > room {
                    captured.extend_from_slice(&chunk[..room]);
                    *truncated = true;
                } else {
                    captured.extend_from_slice(chunk);
                }
            }
            TeeMode::Events(parser) => {
                for payload in parser.feed(chunk) {
                    // Each event carries its own JSON-RPC message, so
                    // correlation is per message rather than per stream --
                    // which is what makes one response stream able to close
                    // one call while notifications flow past unlogged.
                    let Ok(msg) = serde_json::from_str::<RpcMessage>(&payload) else {
                        continue;
                    };
                    let Some(id_key) = msg.id_key() else { continue };
                    let Some(call) = self.session.resolve(&id_key) else {
                        continue;
                    };
                    let outcome = CallOutcome::from_rpc(&msg, payload.len() as i64);
                    log_entry(&self.listener, self.session.id(), call, outcome);
                }
            }
        }
    }

    fn finish(self) {
        let TeeMode::Whole {
            captured,
            truncated,
        } = self.mode
        else {
            // Event streams audited as they went; anything still pending
            // belongs to the connection, and is drained when it closes.
            return;
        };

        let parsed = serde_json::from_slice::<RpcMessage>(&captured).ok();
        let id_key = parsed
            .as_ref()
            .and_then(|m| m.id_key())
            .or(self.pending_key);
        let Some(call) = id_key.and_then(|k| self.session.resolve(&k)) else {
            return;
        };

        let outcome = match (parsed, truncated) {
            (Some(msg), false) => CallOutcome::from_rpc(&msg, self.bytes_out),
            // Over the cap: the client got everything, our copy did not.
            (_, true) => CallOutcome::capture_truncated(self.succeeded, self.bytes_out),
            // Complete, and not JSON-RPC at all: a gateway error page or a
            // wrong Content-Type. Kept as evidence and scanned like any
            // other payload, because such pages echo request headers.
            (None, false) => CallOutcome::non_json(
                String::from_utf8_lossy(&captured).into_owned(),
                self.bytes_out,
            ),
        };
        log_entry(&self.listener, self.session.id(), call, outcome);
    }
}

pub async fn serve(config_path: &Path) -> anyhow::Result<()> {
    let config = Arc::new(Config::load(config_path)?);
    let servers = config.http_servers()?;

    // Same refuse-to-start conditions as `run`: an audit tool that cannot
    // record, or that would store secrets in the clear, must not proxy.
    let (db, writer) = db::spawn_writer(Path::new(&config.logging.db_path))?;
    let patterns = Arc::new(PatternSet::bundled().map_err(|e| {
        anyhow::anyhow!(
            "bundled secrets patterns failed to load: {e}. This is a defect in \
             this build of auditmcp, not a problem with your configuration -- \
             refusing to start rather than proxy with secrets detection disabled."
        )
    })?);
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

    // Bind every listener before serving any of them, so a port conflict
    // fails startup instead of leaving some servers proxying and others
    // silently absent.
    let mut bound = Vec::new();
    for s in servers {
        let addr = s.socket_addr().map_err(|e| anyhow::anyhow!("{e}"))?;
        let tcp = TcpListener::bind(addr)
            .await
            .map_err(|e| anyhow::anyhow!("[[server]] '{}' could not bind {addr}: {e}", s.name))?;
        bound.push((tcp, addr, s));
    }

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    let mut listeners = Vec::new();
    let mut tasks = Vec::new();
    for (tcp, addr, s) in bound {
        let listener = Arc::new(build_listener(s, &config, &db, &patterns, &allowlist)?);
        tracing::warn!(
            "auditmcp listening on http://{addr} -> {} (server '{}')",
            listener.upstream,
            listener.server_name
        );
        listeners.push(Arc::clone(&listener));
        tasks.push(tokio::spawn(accept_loop(tcp, listener, stop_rx.clone())));
    }
    drop(stop_rx);

    let signal = shutdown::shutdown_signal().await;
    tracing::warn!("received {signal}; stopping listeners and flushing the audit log");
    let _ = stop_tx.send(true);
    // Awaited, not aborted: each accept loop shuts its own connections down
    // and only then returns, which is what guarantees no `DbHandle` clone
    // survives into the drain below.
    for t in tasks {
        let _ = t.await;
    }

    // Every producer has stopped, so no new session can open and none can
    // still be resolving. Calls left open on connections that were cut off
    // are recorded here rather than vanishing.
    for listener in &listeners {
        for session in listener.sessions.take_all().await {
            for call in session.drain_abandoned() {
                log_timeout(listener, session.id(), call);
            }
        }
    }

    // The listeners hold the last `DbHandle` clones; both must go before
    // the writer's channel can close.
    drop(listeners);
    drop(db);
    match writer.wait_for_drain(DRAIN_TIMEOUT) {
        db::DrainOutcome::Drained { dropped: 0 } => Ok(()),
        db::DrainOutcome::Drained { dropped } => Err(anyhow::anyhow!(
            "audit log incomplete: {dropped} tool call(s) were not recorded this \
             session (see the warnings above for why). The calls still happened -- \
             the record of them did not."
        )),
        db::DrainOutcome::TimedOut { dropped } => Err(anyhow::anyhow!(
            "audit log incomplete: the writer did not finish within {}s of shutdown, \
             so an unknown number of queued tool calls were not written{}. Shutting \
             down anyway rather than hanging.",
            DRAIN_TIMEOUT.as_secs(),
            if dropped > 0 {
                format!(", on top of {dropped} already dropped")
            } else {
                String::new()
            }
        )),
    }
}

fn build_listener(
    s: &ServerConfig,
    config: &Arc<Config>,
    db: &DbHandle,
    patterns: &Arc<PatternSet>,
    allowlist: &Arc<HashSet<String>>,
) -> anyhow::Result<Listener> {
    let upstream = s.upstream_uri().map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut connector = HttpConnector::new();
    // A proxy must not silently rewrite what it forwards; leaving hyper's
    // defaults alone here keeps the connection behaviour boring on purpose.
    connector.enforce_http(true);
    Ok(Listener {
        server_name: s.name.clone(),
        upstream,
        allowed_origins: s
            .allowed_origins
            .clone()
            .unwrap_or_else(default_allowed_origins),
        config: Arc::clone(config),
        db: db.clone(),
        patterns: Arc::clone(patterns),
        allowlist: Arc::clone(allowlist),
        client: Client::builder(hyper_util::rt::TokioExecutor::new()).build(connector),
        sessions: SessionRegistry::default(),
    })
}

/// Loopback origins only, unless the config says otherwise. MCP requires
/// servers to validate `Origin` against DNS rebinding, and a loopback
/// listener is exactly the target that attack aims at: a page in the user's
/// browser can otherwise drive their MCP servers through us.
fn default_allowed_origins() -> Vec<String> {
    vec![
        "http://localhost".to_string(),
        "http://127.0.0.1".to_string(),
        "http://[::1]".to_string(),
    ]
}

/// Serves one listener until asked to stop.
///
/// Stops by request rather than by being aborted, and that distinction is
/// load-bearing. Aborting this task would leave the connection tasks it
/// spawned running, and each of those holds a `DbHandle` clone — the
/// writer's queue only closes when the last handle drops, so the shutdown
/// drain would wait out its entire timeout and then report an incomplete
/// audit log that was merely still held open. Draining correctly requires
/// knowing every producer has finished, which means owning them:
/// `JoinSet::shutdown` aborts the connections and waits for them, so by the
/// time this returns nothing is left holding a handle.
async fn accept_loop(
    tcp: TcpListener,
    listener: Arc<Listener>,
    mut stop: tokio::sync::watch::Receiver<bool>,
) {
    let mut connections = tokio::task::JoinSet::new();

    loop {
        let accepted = tokio::select! {
            _ = stop.changed() => break,
            accepted = tcp.accept() => accepted,
        };

        let (stream, _peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!("server '{}': accept failed: {e}", listener.server_name);
                continue;
            }
        };

        let listener = Arc::clone(&listener);
        connections.spawn(async move {
            let (key, session) = listener.sessions.open().await;
            let io = TokioIo::new(stream);

            let svc = {
                let listener = Arc::clone(&listener);
                let session = Arc::clone(&session);
                service_fn(move |req| handle(req, Arc::clone(&listener), Arc::clone(&session)))
            };

            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                tracing::debug!("server '{}': connection ended: {e}", listener.server_name);
            }

            // A connection that ends with calls still open means the client
            // went away mid-request. Those calls happened and were never
            // answered, which is exactly what `timeout` records.
            for call in listener.sessions.close(key).await {
                log_timeout(&listener, session.id(), call);
            }
        });
    }

    // Aborts every in-flight connection and waits for them to unwind, so no
    // `DbHandle` clone outlives this function. Calls those connections had
    // open stay in the session registry and are drained by `serve`.
    connections.shutdown().await;
}

async fn handle(
    req: Request<Incoming>,
    listener: Arc<Listener>,
    session: Arc<Session>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    match proxy_once(req, &listener, &session).await {
        Ok(resp) => Ok(resp),
        // Fail-closed only at the transport edge: if the upstream cannot be
        // reached there is no response to forward, so the client is told
        // plainly rather than left hanging. The call is still logged.
        Err(e) => {
            tracing::warn!(
                "server '{}': upstream request failed: {e}",
                listener.server_name
            );
            Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("auditmcp: upstream request failed: {e}"),
            ))
        }
    }
}

async fn proxy_once(
    req: Request<Incoming>,
    listener_arc: &Arc<Listener>,
    session_arc: &Arc<Session>,
) -> anyhow::Result<Response<ProxyBody>> {
    let listener: &Listener = listener_arc;
    let session: &Session = session_arc;
    if let Some(origin) = req.headers().get(hyper::header::ORIGIN) {
        let origin = origin.to_str().unwrap_or("");
        if !origin_allowed(origin, &listener.allowed_origins) {
            tracing::warn!(
                "server '{}': rejected request with Origin '{origin}'",
                listener.server_name
            );
            return Ok(error_response(
                StatusCode::FORBIDDEN,
                "auditmcp: Origin not allowed",
            ));
        }
    }

    let (parts, body) = req.into_parts();
    let body = match Limited::new(body, MAX_REQUEST_BYTES).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => {
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "auditmcp: request body exceeds the proxy's size limit",
            ))
        }
    };

    // Register before forwarding, so a call is tracked even if the upstream
    // never answers.
    let pending_key = register_if_tool_call(session, &parts, &body).await;

    // Origin-level mirror: only scheme and authority change. Headers pass
    // through untouched -- Authorization, MCP-Protocol-Version, Mcp-Method,
    // Mcp-Name and any Mcp-Param-* included, the last of which MCP requires
    // intermediaries to forward and which servers reject requests over if
    // they disagree with the body.
    let mut upstream_req = Request::builder()
        .method(parts.method.clone())
        .uri(rewrite_uri(&listener.upstream, &parts.uri))
        .body(Full::new(body.clone()))?;
    *upstream_req.headers_mut() = parts.headers.clone();

    let upstream_resp = listener.client.request(upstream_req).await?;
    let (resp_parts, resp_body) = upstream_resp.into_parts();

    // Headers are returned to the client now, before a single body byte has
    // been read. An event stream's first event therefore reaches the client
    // when the upstream emits it, not when the stream ends.
    let is_event_stream = resp_parts
        .headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim_start().starts_with("text/event-stream"))
        .unwrap_or(false);

    let tee = TeeBody::new(
        resp_body,
        Arc::clone(listener_arc),
        Arc::clone(session_arc),
        pending_key,
        resp_parts.status.is_success(),
        is_event_stream,
    );

    let mut out = Response::builder()
        .status(resp_parts.status)
        .body(BoxBody::new(tee))?;
    *out.headers_mut() = resp_parts.headers;
    Ok(out)
}

/// Records a `tools/call` request so its response can be matched to it.
/// Returns the correlation key, or `None` for anything that is not a tool
/// call — those are forwarded and not logged, exactly as on stdio.
async fn register_if_tool_call(
    session: &Session,
    parts: &http::request::Parts,
    body: &Bytes,
) -> Option<String> {
    if parts.method != hyper::Method::POST {
        return None;
    }
    let msg: RpcMessage = serde_json::from_slice(body).ok()?;
    if !msg.is_tool_call_request() {
        return None;
    }
    let (id_key, tool_name) = (msg.id_key()?, msg.tool_name()?);
    session.register(
        id_key.clone(),
        PendingCall {
            tool_name,
            args: msg.arguments().cloned(),
            bytes_in: body.len() as i64,
            started: Instant::now(),
        },
    );
    Some(id_key)
}

fn log_timeout(listener: &Listener, session_id: &str, call: PendingCall) {
    log_entry(listener, session_id, call, CallOutcome::timed_out());
}

/// The single place this transport turns a completed call into a row, so
/// the tier lookup and the pipeline inputs cannot drift between the
/// streaming path, the event path and the shutdown drain.
fn log_entry(listener: &Listener, session_id: &str, call: PendingCall, outcome: CallOutcome) {
    let tier = listener.config.tier_for_tool(&call.tool_name);
    listener.db.log(audit::build_entry(
        call,
        outcome,
        session_id,
        &listener.server_name,
        tier,
        &listener.patterns,
        &listener.allowlist,
    ));
}

/// Swaps scheme and authority for the upstream's, keeping path and query
/// exactly as the client sent them.
fn rewrite_uri(upstream: &http::Uri, original: &http::Uri) -> http::Uri {
    let mut parts = upstream.clone().into_parts();
    parts.path_and_query = original
        .path_and_query()
        .cloned()
        .or_else(|| Some(http::uri::PathAndQuery::from_static("/")));
    http::Uri::from_parts(parts).unwrap_or_else(|_| upstream.clone())
}

/// An origin matches if it equals an allowed entry or is that entry with a
/// port. Comparing on the scheme+host prefix keeps `http://localhost:5173`
/// working without listing every dev port.
fn origin_allowed(origin: &str, allowed: &[String]) -> bool {
    allowed.iter().any(|a| {
        origin == a
            || (origin.starts_with(a.as_str())
                && origin[a.len()..].starts_with(':')
                && origin[a.len() + 1..].chars().all(|c| c.is_ascii_digit()))
    })
}

fn error_response(status: StatusCode, message: &str) -> Response<ProxyBody> {
    // A JSON-RPC error with no id: the shape MCP specifies for a transport
    // level rejection, and one a client can parse rather than guess at.
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "error": { "code": -32000, "message": message }
    })
    .to_string();
    Response::builder()
        .status(status)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(BoxBody::new(
            Full::new(Bytes::from(body)).map_err(|never| match never {}),
        ))
        .expect("static response is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::test_support::{remove_db_files, temp_db_path};

    /// A fake upstream MCP server. Echoes the tool name back inside a
    /// JSON-RPC result, so a row can be traced to the request that produced
    /// it — which is the whole point of the cross-attribution test.
    async fn spawn_fake_upstream() -> String {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = tcp.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let svc = service_fn(|req: Request<Incoming>| async move {
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let msg: serde_json::Value =
                            serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                        let id = msg.get("id").cloned().unwrap_or(serde_json::Value::Null);
                        let tool = msg
                            .pointer("/params/name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("?")
                            .to_string();
                        let out = serde_json::json!({
                            "jsonrpc": "2.0", "id": id,
                            "result": {"content": [{"type": "text", "text": tool}], "isError": false}
                        })
                        .to_string();
                        Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(out))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        format!("http://{addr}")
    }

    fn test_config(db_path: &std::path::Path) -> Arc<Config> {
        Arc::new(
            toml::from_str(&format!(
                "[logging]\ndb_path = '{}'\ndefault_tier = 'full'\n",
                db_path.to_string_lossy()
            ))
            .unwrap(),
        )
    }

    async fn post_tool_call(
        client: &Client<HttpConnector, Full<Bytes>>,
        base: &str,
        id: i64,
        tool: &str,
    ) {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": {"name": tool, "arguments": {}}
        })
        .to_string();
        let req = Request::builder()
            .method(hyper::Method::POST)
            .uri(format!("{base}/mcp"))
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)))
            .unwrap();
        let resp = client.request(req).await.unwrap();
        let _ = resp.into_body().collect().await.unwrap();
    }

    /// The property the whole ownership model exists for, at the layer
    /// above `session.rs`: two listeners, the same JSON-RPC id on both, and
    /// neither one's response may resolve the other's call. A process-wide
    /// map keyed by (listener, connection, id) would pass or fail here on
    /// whether one key was built correctly; separate registries make the
    /// mistake unrepresentable.
    #[tokio::test]
    async fn two_listeners_with_colliding_ids_never_cross_attribute() {
        let upstream = spawn_fake_upstream().await;
        let db_path = temp_db_path("http_two_listeners");
        let config = test_config(&db_path);
        let (db, writer) = db::spawn_writer(&db_path).unwrap();
        let patterns = Arc::new(PatternSet::bundled().unwrap());
        let allowlist = Arc::new(HashSet::new());

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let mut bases = Vec::new();
        let mut tasks = Vec::new();
        let mut listeners = Vec::new();
        for name in ["alpha", "beta"] {
            let sc: ServerConfig = toml::from_str(&format!(
                "name = '{name}'\nupstream = '{upstream}'\nlisten = '127.0.0.1:0'\n"
            ))
            .unwrap();
            let listener =
                Arc::new(build_listener(&sc, &config, &db, &patterns, &allowlist).unwrap());
            listeners.push(Arc::clone(&listener));
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            bases.push(format!("http://{}", tcp.local_addr().unwrap()));
            tasks.push(tokio::spawn(accept_loop(tcp, listener, stop_rx.clone())));
        }
        drop(stop_rx);

        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());

        // Same id on both listeners, different tools. Answered in the
        // opposite order to issue, so a shared map would surface the mix-up
        // rather than hide it behind ordering.
        post_tool_call(&client, &bases[1], 1, "beta_tool").await;
        post_tool_call(&client, &bases[0], 1, "alpha_tool").await;

        // The real shutdown sequence: ask the loops to stop, await them (so
        // their connection tasks are gone), then release the handles.
        let _ = stop_tx.send(true);
        for t in tasks {
            let _ = t.await;
        }
        drop(listeners);
        drop(db);
        assert!(matches!(
            writer.wait_for_drain(std::time::Duration::from_secs(30)),
            db::DrainOutcome::Drained { dropped: 0 }
        ));

        let conn = db::open_readonly(&db_path).unwrap();
        let mut pairs: Vec<(String, String)> = db::read_all_rows(&conn)
            .unwrap()
            .into_iter()
            .map(|r| (r.entry.server_name.unwrap_or_default(), r.entry.tool_name))
            .collect();
        pairs.sort();
        drop(conn);
        remove_db_files(&db_path);

        assert_eq!(
            pairs,
            vec![
                ("alpha".to_string(), "alpha_tool".to_string()),
                ("beta".to_string(), "beta_tool".to_string()),
            ],
            "each listener's row must carry its own server_name and tool_name"
        );
    }

    /// A non-JSON response body is the `Payload::Raw` path: it is a
    /// transport failure rather than a tool result, it still belongs in the
    /// log, and it is still scanned for credentials because error pages
    /// echo request headers.
    #[tokio::test]
    async fn non_json_upstream_response_is_logged_as_an_error_with_its_body() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}", tcp.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((stream, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    let svc = service_fn(|_req: Request<Incoming>| async move {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(Full::new(Bytes::from(
                                    "<html><body>502 Bad Gateway. token=sk-FAKE1234567890abcdefFAKEKEYFAKE00</body></html>",
                                )))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let db_path = temp_db_path("http_raw_body");
        let config = test_config(&db_path);
        let (db, writer) = db::spawn_writer(&db_path).unwrap();
        let patterns = Arc::new(PatternSet::bundled().unwrap());
        let allowlist = Arc::new(HashSet::new());
        let sc: ServerConfig = toml::from_str(&format!(
            "name = 'gw'\nupstream = '{upstream}'\nlisten = '127.0.0.1:0'\n"
        ))
        .unwrap();
        let listener = Arc::new(build_listener(&sc, &config, &db, &patterns, &allowlist).unwrap());
        let listeners = vec![Arc::clone(&listener)];
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", tcp.local_addr().unwrap());
        let task = tokio::spawn(accept_loop(tcp, listener, stop_rx));

        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());
        post_tool_call(&client, &base, 1, "fetch_thing").await;

        let _ = stop_tx.send(true);
        let _ = task.await;
        drop(listeners);
        drop(db);
        assert!(matches!(
            writer.wait_for_drain(std::time::Duration::from_secs(30)),
            db::DrainOutcome::Drained { dropped: 0 }
        ));

        let conn = db::open_readonly(&db_path).unwrap();
        let rows = db::read_all_rows(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0].entry;
        assert_eq!(
            row.status, "error",
            "an unparseable response is not a success"
        );
        let err = row.error_message.clone().unwrap_or_default();
        assert!(
            err.contains("502 Bad Gateway"),
            "the body is evidence: {err}"
        );
        assert!(
            !err.contains("sk-FAKE1234567890abcdefFAKEKEYFAKE00"),
            "a credential echoed in an error page must still be redacted: {err}"
        );
        assert_eq!(row.redaction_count, 1);
        drop(conn);
        remove_db_files(&db_path);
    }

    #[test]
    fn sse_parser_splits_events_on_either_line_ending() {
        let mut p = SseParser::default();
        assert_eq!(p.feed(b"data: one\n\ndata: two\n\n"), vec!["one", "two"]);
        let mut p = SseParser::default();
        assert_eq!(
            p.feed(b"data: one\r\n\r\ndata: two\r\n\r\n"),
            vec!["one", "two"]
        );
    }

    /// Frames arrive split wherever TCP happens to break them, so an event
    /// must survive being delivered a byte at a time.
    #[test]
    fn sse_parser_reassembles_events_across_chunk_boundaries() {
        let mut p = SseParser::default();
        let mut got = Vec::new();
        for byte in b"data: {\"id\":1}\n\n" {
            got.extend(p.feed(&[*byte]));
        }
        assert_eq!(got, vec!["{\"id\":1}"]);
    }

    /// Servers emit bare `:` comments as keep-alives on idle streams; they
    /// carry no data and must not be mistaken for messages.
    #[test]
    fn sse_parser_ignores_comments_and_non_data_fields() {
        let mut p = SseParser::default();
        assert!(p.feed(b":\n\n").is_empty());
        assert!(p.feed(b": keep-alive\n\n").is_empty());
        assert!(p.feed(b"event: ping\nid: 7\n\n").is_empty());
        assert_eq!(p.feed(b"event: message\ndata: hi\n\n"), vec!["hi"]);
    }

    #[test]
    fn sse_parser_joins_multiline_data_fields() {
        let mut p = SseParser::default();
        assert_eq!(p.feed(b"data: a\ndata: b\n\n"), vec!["a\nb"]);
    }

    /// An event that never terminates must not grow the buffer without
    /// bound; the parser drops it and picks up at the next boundary.
    #[test]
    fn sse_parser_resyncs_after_an_oversized_event() {
        let mut p = SseParser::default();
        let huge = vec![b'x'; MAX_SSE_EVENT_BYTES + 1024];
        assert!(p.feed(&huge).is_empty());
        assert!(
            p.buf.len() <= MAX_SSE_EVENT_BYTES,
            "buffer must stay bounded"
        );
        // The remainder of the oversized event is discarded...
        assert!(p.feed(b"trailing junk\n\n").is_empty());
        // ...and the next event parses normally.
        assert_eq!(p.feed(b"data: recovered\n\n"), vec!["recovered"]);
    }

    /// One SSE response stream carrying a progress notification and then
    /// the final response: only the response closes the call, and it
    /// produces exactly one row.
    #[tokio::test]
    async fn sse_response_stream_produces_one_row_for_the_final_response() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}", tcp.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((stream, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    let svc = service_fn(|_req: Request<Incoming>| async move {
                        let events = concat!(
                            "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{}}\n\n",
                            ": keep-alive\n\n",
                            "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"resultType\":\"complete\",\"content\":[]}}\n\n",
                        );
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .header(hyper::header::CONTENT_TYPE, "text/event-stream")
                                .body(Full::new(Bytes::from(events)))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let db_path = temp_db_path("http_sse");
        let config = test_config(&db_path);
        let (db, writer) = db::spawn_writer(&db_path).unwrap();
        let patterns = Arc::new(PatternSet::bundled().unwrap());
        let allowlist = Arc::new(HashSet::new());
        let sc: ServerConfig = toml::from_str(&format!(
            "name = 'sse'\nupstream = '{upstream}'\nlisten = '127.0.0.1:0'\n"
        ))
        .unwrap();
        let listener = Arc::new(build_listener(&sc, &config, &db, &patterns, &allowlist).unwrap());
        let listeners = vec![Arc::clone(&listener)];
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", tcp.local_addr().unwrap());
        let task = tokio::spawn(accept_loop(tcp, listener, stop_rx));

        let client: Client<HttpConnector, Full<Bytes>> =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());
        post_tool_call(&client, &base, 1, "streamer").await;

        let _ = stop_tx.send(true);
        let _ = task.await;
        drop(listeners);
        drop(db);
        assert!(matches!(
            writer.wait_for_drain(std::time::Duration::from_secs(30)),
            db::DrainOutcome::Drained { dropped: 0 }
        ));

        let conn = db::open_readonly(&db_path).unwrap();
        let rows = db::read_all_rows(&conn).unwrap();
        assert_eq!(rows.len(), 1, "the notification must not produce a row");
        assert_eq!(rows[0].entry.tool_name, "streamer");
        assert_eq!(rows[0].entry.status, "success");
        drop(conn);
        remove_db_files(&db_path);
    }

    #[test]
    fn uri_rewrite_keeps_path_and_query_and_swaps_authority() {
        let upstream: http::Uri = "http://example.com:9000/base".parse().unwrap();
        let original: http::Uri = "/mcp?x=1".parse().unwrap();
        assert_eq!(
            rewrite_uri(&upstream, &original).to_string(),
            "http://example.com:9000/mcp?x=1"
        );
    }

    /// OAuth discovery asks for a well-known path off the origin the client
    /// was pointed at. Forwarding it unchanged is what keeps authorization
    /// working through the proxy.
    #[test]
    fn well_known_paths_are_forwarded_unchanged() {
        let upstream: http::Uri = "http://example.com/mcp".parse().unwrap();
        let original: http::Uri = "/.well-known/oauth-protected-resource".parse().unwrap();
        assert_eq!(
            rewrite_uri(&upstream, &original).to_string(),
            "http://example.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn loopback_origins_are_allowed_with_or_without_a_port() {
        let allowed = default_allowed_origins();
        for ok in [
            "http://localhost",
            "http://localhost:5173",
            "http://127.0.0.1:8787",
            "http://[::1]:3000",
        ] {
            assert!(origin_allowed(ok, &allowed), "{ok} should be allowed");
        }
    }

    /// The DNS-rebinding case: a page on a remote origin must not be able
    /// to drive local MCP servers through this proxy.
    #[test]
    fn remote_and_lookalike_origins_are_rejected() {
        let allowed = default_allowed_origins();
        for bad in [
            "http://evil.example",
            "https://localhost",
            "http://localhost.evil.example",
            "http://127.0.0.1.evil.example",
            "http://localhostx",
        ] {
            assert!(!origin_allowed(bad, &allowed), "{bad} should be rejected");
        }
    }
}
