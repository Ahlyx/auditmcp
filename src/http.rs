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

/// One complete SSE event: the exact bytes it occupied on the wire,
/// terminator included, alongside what they mean.
///
/// `raw` exists so the stream can be re-emitted byte for byte. Everything
/// except the legacy `endpoint` event is forwarded exactly as received, and
/// keeping the original bytes rather than re-serialising from the parsed
/// fields is what makes that guarantee hold for framing this parser does
/// not model — unknown fields, spacing, line-ending style.
struct SseEvent {
    raw: Vec<u8>,
    name: Option<String>,
    data: Option<String>,
}

impl SseParser {
    /// Feeds one chunk and returns every event completed by it.
    fn feed(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();

        while let Some((body_len, term_len)) = find_event_end(&self.buf) {
            let raw: Vec<u8> = self.buf.drain(..body_len + term_len).collect();
            if self.resyncing {
                self.resyncing = false;
                continue;
            }
            let body = &raw[..body_len];
            out.push(SseEvent {
                name: field(body, "event:"),
                data: data_payload(body),
                raw,
            });
        }

        if self.buf.len() > MAX_SSE_EVENT_BYTES {
            self.buf.clear();
            self.resyncing = true;
        }
        out
    }

    /// Bytes received that have not yet formed a complete event, taken so
    /// they can be flushed when the stream ends. A server that closes
    /// without a final terminator still gets its last bytes forwarded.
    fn take_remainder(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}

/// The value of the first line with the given field prefix.
fn field(event: &[u8], prefix: &str) -> Option<String> {
    let text = std::str::from_utf8(event).ok()?;
    text.lines().find_map(|line| {
        line.strip_prefix(prefix)
            .map(|rest| rest.strip_prefix(' ').unwrap_or(rest).to_string())
    })
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

/// Rewrites the URI carried by a legacy `endpoint` event so it points at
/// this proxy instead of the upstream.
///
/// **This is the only place auditmcp deliberately alters a byte it
/// forwards, and it is not optional.** In the HTTP+SSE transport of
/// protocol version 2024-11-05 the server's first event hands the client
/// the URI to POST every subsequent message to. Relayed untouched, that
/// URI names the upstream, so the client would POST directly to it — past
/// the proxy — and the audit log would contain the opening connection and
/// nothing else. A proxy that looks healthy and records nothing is the
/// worst failure this tool has, so the rewrite ships with legacy support
/// rather than after it.
///
/// A relative URI already resolves against whoever served the stream,
/// which is this proxy, so it is returned unchanged; only an absolute one
/// needs its scheme and authority replaced. Anything that does not parse
/// is left alone — corrupting an event we do not understand would be worse
/// than failing to redirect it, and the failure is visible (the client
/// bypasses us) rather than silent traffic damage.
fn rewrite_endpoint_uri(raw: &str, local_addr: &std::net::SocketAddr) -> Option<String> {
    let uri: http::Uri = raw.trim().parse().ok()?;
    uri.authority()?; // relative: already points at us
    let mut parts = uri.into_parts();
    parts.scheme = Some(http::uri::Scheme::HTTP);
    parts.authority = Some(local_addr.to_string().parse().ok()?);
    if parts.path_and_query.is_none() {
        parts.path_and_query = Some(http::uri::PathAndQuery::from_static("/"));
    }
    Some(http::Uri::from_parts(parts).ok()?.to_string())
}

/// The path-and-query a legacy POST will carry, which is what identifies
/// the session on the way back. Everything before it is our own authority
/// after the rewrite, and a client that resolved a relative URI sends only
/// this part anyway — so it is the one stable key both sides agree on.
fn endpoint_key(uri: &str) -> Option<String> {
    let parsed: http::Uri = uri.trim().parse().ok()?;
    Some(parsed.path_and_query()?.to_string())
}

/// Replaces the `data:` payload of one event, preserving its other lines
/// and its terminator so nothing else about the frame changes.
fn replace_event_data(raw: &[u8], new_data: &str) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(raw) else {
        return raw.to_vec();
    };
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = String::with_capacity(text.len() + new_data.len());
    let mut replaced = false;
    for line in text.split(newline) {
        if line.starts_with("data:") {
            // Multi-line data collapses to one line; the payload is a URI,
            // which cannot legally span lines.
            if !replaced {
                out.push_str("data: ");
                out.push_str(new_data);
                out.push_str(newline);
                replaced = true;
            }
        } else {
            out.push_str(line);
            out.push_str(newline);
        }
    }
    // `split` yields a trailing empty piece for the terminator, which the
    // loop already re-added; drop the extra newline it introduces.
    out.truncate(out.len() - newline.len());
    out.into_bytes()
}

/// The body type returned to clients: either a streamed upstream response
/// or a small locally-generated error.
type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// The outbound client: HTTP or HTTPS, chosen per upstream URL.
type UpstreamClient = Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    Full<Bytes>,
>;

/// Everything a listener needs to serve and audit. Immutable after
/// construction apart from the session registry, which is per-listener.
struct Listener {
    server_name: String,
    upstream: http::Uri,
    /// This listener's own address, needed to point a rewritten legacy
    /// `endpoint` event back at ourselves.
    local_addr: std::net::SocketAddr,
    allowed_origins: Vec<String>,
    config: Arc<Config>,
    db: DbHandle,
    patterns: Arc<PatternSet>,
    allowlist: Arc<HashSet<String>>,
    client: UpstreamClient,
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
    /// Legacy HTTP+SSE only: the POST endpoint a server advertised, mapped
    /// to the session of the SSE stream that advertised it.
    ///
    /// That transport splits one logical session across two connections --
    /// messages go out on a POST, answers come back on the GET stream --
    /// so correlation cannot be per connection there. Keyed by the
    /// endpoint's path and query, which is what the server chose to
    /// identify the session with and what the client sends back.
    endpoints: Mutex<HashMap<String, Arc<Session>>>,
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
        let mut all: Vec<Arc<Session>> = self.open.lock().await.drain().map(|(_, s)| s).collect();
        all.extend(self.endpoints.lock().await.drain().map(|(_, s)| s));
        all
    }

    /// Binds a legacy POST endpoint to the session of the stream that
    /// advertised it.
    async fn bind_endpoint(&self, key: String, session: Arc<Session>) {
        self.endpoints.lock().await.insert(key, session);
    }

    /// The session a legacy POST belongs to, if this path and query was
    /// advertised as an endpoint. Falls back to the connection's own
    /// session for every modern transport, where the two coincide.
    async fn session_for_endpoint(&self, key: &str) -> Option<Arc<Session>> {
        self.endpoints.lock().await.get(key).cloned()
    }

    async fn unbind_endpoint(&self, key: &str) -> Option<Arc<Session>> {
        self.endpoints.lock().await.remove(key)
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
    /// Event-stream mode only: complete events waiting to go out. Empty
    /// for whole-body responses, which forward their frames directly.
    pending_out: std::collections::VecDeque<Bytes>,
}

struct Tee {
    listener: Arc<Listener>,
    session: Arc<Session>,
    /// Set once a legacy `endpoint` event has been seen, so the binding
    /// is released when the stream ends.
    endpoint_key: Option<String>,
    /// Correlation key from the request, used when the response body is
    /// not parseable JSON-RPC and therefore carries no id of its own.
    pending_key: Option<String>,
    succeeded: bool,
    bytes_out: i64,
    mode: TeeMode,
}

enum TeeMode {
    /// A single JSON body: accumulate up to the cap, audit when it ends.
    /// Frames pass straight through; nothing here is ever rewritten.
    Whole { captured: Vec<u8>, truncated: bool },
    /// An event stream: audit each complete message as it goes by, and
    /// never accumulate, so a stream that stays open for hours costs
    /// nothing.
    ///
    /// Unlike `Whole`, this re-emits at event granularity rather than
    /// passing frames through as they arrive, because the legacy
    /// `endpoint` event has to be rewritten before the client sees it and
    /// a frame already forwarded cannot be taken back. The delay is until
    /// the event's terminator, which the server sends with it — an event
    /// is still delivered the moment it is complete, which is the unit SSE
    /// is defined in. Every event except `endpoint` is re-emitted from its
    /// original bytes, so the stream stays byte-identical.
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
            pending_out: std::collections::VecDeque::new(),
            tee: Some(Tee {
                listener,
                session,
                endpoint_key: None,
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
        use std::task::Poll;
        let this = self.get_mut();

        loop {
            // Event-stream mode may hold bytes ready from a previous poll:
            // one upstream frame can complete several events.
            if let Some(ready) = this.pending_out.pop_front() {
                return Poll::Ready(Some(Ok(hyper::body::Frame::data(ready))));
            }

            let polled = std::pin::Pin::new(&mut this.inner).poll_frame(cx);
            match polled {
                Poll::Ready(Some(Ok(frame))) => {
                    let Some(chunk) = frame.data_ref() else {
                        // Trailers and other non-data frames pass through.
                        return Poll::Ready(Some(Ok(frame)));
                    };
                    match this.tee.as_mut() {
                        Some(tee) => {
                            let out = tee.observe(chunk);
                            match out {
                                // `Whole` mode: forward the original frame
                                // untouched, exactly as before.
                                None => return Poll::Ready(Some(Ok(frame))),
                                // `Events` mode: forward whatever complete
                                // events this chunk produced, if any. If it
                                // produced none, loop and read more rather
                                // than emitting an empty frame.
                                Some(events) => this.pending_out.extend(events),
                            }
                        }
                        None => return Poll::Ready(Some(Ok(frame))),
                    }
                }
                // End of stream, cleanly or otherwise: a body that failed
                // partway is still evidence of a call that happened.
                Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                    if let Some(mut tee) = this.tee.take() {
                        // Any trailing bytes that never formed an event are
                        // still the server's, and are forwarded as-is.
                        let remainder = tee.take_remainder();
                        tee.finish();
                        if !remainder.is_empty() {
                            this.pending_out.push_back(Bytes::from(remainder));
                            continue;
                        }
                    }
                    return polled;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
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
    /// Returns `None` for whole-body responses, whose frames the caller
    /// forwards untouched, and `Some(events)` for event streams, where the
    /// caller forwards exactly what comes back here.
    fn observe(&mut self, chunk: &Bytes) -> Option<Vec<Bytes>> {
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
                None
            }
            TeeMode::Events(parser) => {
                let events = parser.feed(chunk);
                let mut out = Vec::with_capacity(events.len());
                for event in events {
                    out.push(self.handle_event(event));
                }
                Some(out)
            }
        }
    }

    /// Audits one event and returns the bytes to forward for it --
    /// unchanged except for a legacy `endpoint`, which is rewritten to
    /// point at this proxy.
    fn handle_event(&mut self, event: SseEvent) -> Bytes {
        if event.name.as_deref() == Some("endpoint") {
            if let Some(advertised) = event.data.as_deref() {
                return self.rewrite_endpoint(&event.raw, advertised);
            }
        }

        if let Some(payload) = event.data.as_deref() {
            // Each event carries its own JSON-RPC message, so correlation
            // is per message rather than per stream -- which is what lets
            // one response close one call while notifications flow past
            // unlogged.
            if let Ok(msg) = serde_json::from_str::<RpcMessage>(payload) {
                if let Some(call) = msg.id_key().and_then(|k| self.session.resolve(&k)) {
                    let outcome = CallOutcome::from_rpc(&msg, payload.len() as i64);
                    log_entry(&self.listener, &self.session, call, outcome);
                }
            }
        }
        Bytes::from(event.raw)
    }

    /// Points the advertised POST endpoint at this proxy and binds a
    /// session to it.
    ///
    /// The session is created here rather than reused from the connection
    /// because legacy HTTP+SSE splits one logical session across two
    /// connections: messages go out on a POST, answers come back on this
    /// stream. Correlation therefore belongs to the endpoint, not to
    /// either connection. `sse:` records that derivation, the way `conn:`
    /// records it for the modern transports.
    fn rewrite_endpoint(&mut self, raw_event: &[u8], advertised: &str) -> Bytes {
        let session = Arc::new(Session::new(format!("sse:{}", uuid::Uuid::new_v4())));
        self.session = Arc::clone(&session);

        let rewritten = rewrite_endpoint_uri(advertised, &self.listener.local_addr);
        let effective = rewritten.as_deref().unwrap_or(advertised);

        // Bound by the path and query the client will send back, which is
        // all that survives its own resolution of a relative URI.
        match endpoint_key(effective) {
            Some(key) => {
                let listener = Arc::clone(&self.listener);
                self.endpoint_key = Some(key.clone());
                tokio::spawn(async move {
                    listener.sessions.bind_endpoint(key, session).await;
                });
            }
            None => tracing::warn!(
                "server {}: could not derive an endpoint key from {advertised}; \
                 legacy POSTs on this stream will not be correlated",
                self.listener.server_name
            ),
        }

        match rewritten {
            Some(uri) => Bytes::from(replace_event_data(raw_event, &uri)),
            // Relative already resolves against us, so nothing to change.
            None => Bytes::from(raw_event.to_vec()),
        }
    }

    fn take_remainder(&mut self) -> Vec<u8> {
        match &mut self.mode {
            TeeMode::Events(parser) => parser.take_remainder(),
            TeeMode::Whole { .. } => Vec::new(),
        }
    }

    fn finish(self) {
        // A legacy stream ending takes its endpoint with it: the client
        // must reconnect to get a new one, and leaving the binding would
        // let a later POST resolve against a dead session.
        if let Some(key) = self.endpoint_key.clone() {
            let listener = Arc::clone(&self.listener);
            let session = Arc::clone(&self.session);
            tokio::spawn(async move {
                if listener.sessions.unbind_endpoint(&key).await.is_some() {
                    for call in session.drain_abandoned() {
                        log_timeout(&listener, &session, call);
                    }
                }
            });
        }

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
        log_entry(&self.listener, &self.session, call, outcome);
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
        let listener = Arc::new(build_listener(
            s, addr, &config, &db, &patterns, &allowlist,
        )?);
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
                log_timeout(listener, &session, call);
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
    local_addr: std::net::SocketAddr,
    config: &Arc<Config>,
    db: &DbHandle,
    patterns: &Arc<PatternSet>,
    allowlist: &Arc<HashSet<String>>,
) -> anyhow::Result<Listener> {
    let upstream = s.upstream_uri().map_err(|e| anyhow::anyhow!("{e}"))?;
    // `https_or_http`, not `https_only`: an upstream on loopback in
    // cleartext is a normal local setup, and refusing it would make TLS
    // support a downgrade for everyone already using one.
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Ok(Listener {
        server_name: s.name.clone(),
        upstream,
        local_addr,
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
                log_timeout(&listener, &session, call);
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

    // Legacy HTTP+SSE posts to an endpoint the server advertised on a
    // different connection, and its answer comes back on that connection.
    // So correlation follows the endpoint when this path was advertised as
    // one, and the connection otherwise -- which is every modern transport,
    // where request and response share a connection anyway.
    let mut via_legacy_endpoint = false;
    let session_arc: Arc<Session> = match parts.uri.path_and_query().map(|pq| pq.to_string()) {
        Some(key) => match listener.sessions.session_for_endpoint(&key).await {
            Some(bound) => {
                via_legacy_endpoint = true;
                bound
            }
            None => Arc::clone(session_arc),
        },
        None => Arc::clone(session_arc),
    };
    let session: &Session = &session_arc;

    // Register before forwarding, so a call is tracked even if the upstream
    // never answers.
    let pending_key = register_if_tool_call(session, &parts, &body);

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

    // `Host` is addressing, not content: it names where the request is
    // going, and the client's copy names this proxy. Forwarded as-is it
    // sends the upstream a request addressed to somebody else -- against a
    // real remote server that means being routed to a default virtual host
    // instead of the MCP endpoint, which is invisible on a loopback
    // upstream where both authorities happen to look alike. Removing it
    // lets hyper regenerate it from the rewritten URI, which is the
    // upstream's own authority and what a server validating `Host` against
    // DNS rebinding expects to see.
    upstream_req.headers_mut().remove(hyper::header::HOST);

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

    // Whether this response is where the call's answer is expected.
    //
    // On legacy HTTP+SSE it never is: a message POST is acknowledged with
    // `202 Accepted` and a body of no consequence, while the real answer
    // arrives later on the open event stream. Treating the acknowledgement
    // as the answer closed every legacy call as a failure -- the body is
    // not JSON-RPC, so it fell to the raw path and logged `error` for calls
    // that had in fact succeeded. `202` is excluded for the same reason on
    // any transport: the modern spec uses it to accept a notification, and
    // a notification is not an answer to anything.
    let answer_expected_here = !via_legacy_endpoint && resp_parts.status != StatusCode::ACCEPTED;

    let tee = TeeBody::new(
        resp_body,
        Arc::clone(listener_arc),
        session_arc,
        pending_key.filter(|_| answer_expected_here),
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
fn register_if_tool_call(
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

fn log_timeout(listener: &Listener, session: &Session, call: PendingCall) {
    log_entry(listener, session, call, CallOutcome::timed_out());
}

/// The single place this transport turns a completed call into a row, so
/// the tier lookup, the pipeline inputs, and the anomaly attachment
/// cannot drift between the streaming path, the event path and the
/// shutdown drain.
fn log_entry(listener: &Listener, session: &Session, call: PendingCall, outcome: CallOutcome) {
    let tier = listener.config.tier_for_tool(&call.tool_name);
    let mut entry = audit::build_entry(
        call,
        outcome,
        session.id(),
        &listener.server_name,
        tier,
        &listener.patterns,
        &listener.allowlist,
    );
    session.attach_anomaly(&mut entry, Instant::now());
    listener.db.log(entry);
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

    /// Tests all talk to loopback fixtures over cleartext; the same
    /// connector the proxy uses handles both schemes.
    fn test_connector(
    ) -> hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector> {
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_http1()
            .build()
    }

    /// The `data` payloads of every event a chunk completed, which is what
    /// the parser tests care about.
    fn datas(events: Vec<SseEvent>) -> Vec<String> {
        events.into_iter().filter_map(|e| e.data).collect()
    }

    /// The session drain `serve` performs at shutdown. Tests need it
    /// because HTTP keeps connections alive: a connection that never closes
    /// never runs its own cleanup, so calls still open at shutdown are
    /// recorded here or not at all.
    async fn drain_sessions(listeners: &[Arc<Listener>]) {
        for listener in listeners {
            for session in listener.sessions.take_all().await {
                for call in session.drain_abandoned() {
                    log_timeout(listener, &session, call);
                }
            }
        }
    }

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

    async fn post_tool_call(client: &UpstreamClient, base: &str, id: i64, tool: &str) {
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
            let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = tcp.local_addr().unwrap();
            let listener =
                Arc::new(build_listener(&sc, addr, &config, &db, &patterns, &allowlist).unwrap());
            listeners.push(Arc::clone(&listener));
            bases.push(format!("http://{addr}"));
            tasks.push(tokio::spawn(accept_loop(tcp, listener, stop_rx.clone())));
        }
        drop(stop_rx);

        let client: UpstreamClient =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build(test_connector());

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
        let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy_tcp.local_addr().unwrap();
        let listener =
            Arc::new(build_listener(&sc, addr, &config, &db, &patterns, &allowlist).unwrap());
        let listeners = vec![Arc::clone(&listener)];
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let base = format!("http://{addr}");
        let task = tokio::spawn(accept_loop(proxy_tcp, listener, stop_rx));

        let client: UpstreamClient =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build(test_connector());
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
        assert_eq!(datas(p.feed(b"data: one\n\ndata: two\n\n")), ["one", "two"]);
        let mut p = SseParser::default();
        assert_eq!(
            datas(p.feed(b"data: one\r\n\r\ndata: two\r\n\r\n")),
            ["one", "two"]
        );
    }

    /// Frames arrive split wherever TCP happens to break them, so an event
    /// must survive being delivered a byte at a time.
    #[test]
    fn sse_parser_reassembles_events_across_chunk_boundaries() {
        let mut p = SseParser::default();
        let mut got = Vec::new();
        for byte in b"data: {\"id\":1}\n\n" {
            got.extend(datas(p.feed(&[*byte])));
        }
        assert_eq!(got, ["{\"id\":1}"]);
    }

    /// Servers emit bare `:` comments as keep-alives on idle streams; they
    /// carry no data and must not be mistaken for messages.
    #[test]
    fn sse_parser_ignores_comments_and_non_data_fields() {
        let mut p = SseParser::default();
        assert!(datas(p.feed(b":\n\n")).is_empty());
        assert!(datas(p.feed(b": keep-alive\n\n")).is_empty());
        assert!(datas(p.feed(b"event: ping\nid: 7\n\n")).is_empty());
        assert_eq!(datas(p.feed(b"event: message\ndata: hi\n\n")), ["hi"]);
    }

    #[test]
    fn sse_parser_joins_multiline_data_fields() {
        let mut p = SseParser::default();
        assert_eq!(datas(p.feed(b"data: a\ndata: b\n\n")), ["a\nb"]);
    }

    /// An event that never terminates must not grow the buffer without
    /// bound; the parser drops it and picks up at the next boundary.
    #[test]
    fn sse_parser_resyncs_after_an_oversized_event() {
        let mut p = SseParser::default();
        let huge = vec![b'x'; MAX_SSE_EVENT_BYTES + 1024];
        assert!(datas(p.feed(&huge)).is_empty());
        assert!(
            p.buf.len() <= MAX_SSE_EVENT_BYTES,
            "buffer must stay bounded"
        );
        // The remainder of the oversized event is discarded...
        assert!(datas(p.feed(b"trailing junk\n\n")).is_empty());
        // ...and the next event parses normally.
        assert_eq!(datas(p.feed(b"data: recovered\n\n")), ["recovered"]);
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
        let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy_tcp.local_addr().unwrap();
        let listener =
            Arc::new(build_listener(&sc, addr, &config, &db, &patterns, &allowlist).unwrap());
        let listeners = vec![Arc::clone(&listener)];
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let base = format!("http://{addr}");
        let task = tokio::spawn(accept_loop(proxy_tcp, listener, stop_rx));

        let client: UpstreamClient =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build(test_connector());
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

    fn addr() -> std::net::SocketAddr {
        "127.0.0.1:8787".parse().unwrap()
    }

    /// An absolute endpoint URI names the upstream. Left alone, the client
    /// would POST straight to it and never touch the proxy again — the
    /// audit log would hold the opening connection and nothing else.
    #[test]
    fn absolute_endpoint_uri_is_repointed_at_the_proxy() {
        assert_eq!(
            rewrite_endpoint_uri("http://upstream.test:3000/messages?sessionId=abc", &addr()),
            Some("http://127.0.0.1:8787/messages?sessionId=abc".to_string())
        );
    }

    /// A relative URI already resolves against whoever served the stream,
    /// which is the proxy, so rewriting it would be a change for its own
    /// sake.
    #[test]
    fn relative_endpoint_uri_is_left_alone() {
        assert_eq!(
            rewrite_endpoint_uri("/messages?sessionId=abc", &addr()),
            None
        );
        assert_eq!(rewrite_endpoint_uri("not a uri at all", &addr()), None);
    }

    /// Both forms have to produce the same correlation key, because the
    /// client sends only the path and query back either way.
    #[test]
    fn endpoint_key_is_the_path_and_query_for_either_form() {
        assert_eq!(
            endpoint_key("http://127.0.0.1:8787/messages?sessionId=abc"),
            Some("/messages?sessionId=abc".to_string())
        );
        assert_eq!(
            endpoint_key("/messages?sessionId=abc"),
            Some("/messages?sessionId=abc".to_string())
        );
    }

    /// The rewrite replaces the payload and nothing else: other fields,
    /// ordering and the line-ending style all survive.
    #[test]
    fn replacing_event_data_preserves_the_rest_of_the_frame() {
        assert_eq!(
            replace_event_data(b"event: endpoint\ndata: OLD\n\n", "NEW"),
            b"event: endpoint\ndata: NEW\n\n".to_vec()
        );
        assert_eq!(
            replace_event_data(b"event: endpoint\r\ndata: OLD\r\n\r\n", "NEW"),
            b"event: endpoint\r\ndata: NEW\r\n\r\n".to_vec()
        );
        assert_eq!(
            replace_event_data(b"id: 9\nevent: endpoint\ndata: OLD\nretry: 50\n\n", "NEW"),
            b"id: 9\nevent: endpoint\ndata: NEW\nretry: 50\n\n".to_vec()
        );
    }

    /// The inverse of the rewrite, at the unit level: an event that is not
    /// an `endpoint` must come back out as the exact bytes that went in.
    /// A rewrite firing on the wrong frame corrupts traffic rather than
    /// merely mis-logging it, so this is the more important direction.
    #[test]
    fn non_endpoint_events_round_trip_byte_for_byte() {
        let inputs: Vec<&[u8]> = vec![
            b"data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n",
            b"event: message\ndata: {\"a\":1}\n\n",
            b": keep-alive\n\n",
            b"event: ping\nid: 3\nretry: 1000\n\n",
            b"data: line one\ndata: line two\n\n",
            b"event: endpointish\ndata: http://upstream.test/x\n\n",
            b"event: message\r\nid: 4\r\ndata: {\"b\":2}\r\n\r\n",
        ];
        for raw in inputs {
            let mut p = SseParser::default();
            let events = p.feed(raw);
            assert_eq!(events.len(), 1, "expected one event from {raw:?}");
            assert_eq!(
                events[0].raw, raw,
                "a non-endpoint event must be forwarded unchanged"
            );
        }
    }

    /// A `202 Accepted` acknowledgement is not an answer. Legacy HTTP+SSE
    /// answers every message POST that way and delivers the real result on
    /// the event stream, and the modern spec uses 202 for notifications.
    /// Treating the acknowledgement's body as the response logged every
    /// such call as an `error` — the body is not JSON-RPC, so it fell to
    /// the raw path — for calls that had actually succeeded.
    #[tokio::test]
    async fn an_accepted_acknowledgement_does_not_close_a_call_as_failed() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = format!("http://{}", tcp.local_addr().unwrap());
        tokio::spawn(async move {
            while let Ok((stream, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    let svc = service_fn(|_req: Request<Incoming>| async move {
                        Ok::<_, hyper::Error>(
                            Response::builder()
                                .status(StatusCode::ACCEPTED)
                                .header(hyper::header::CONTENT_TYPE, "text/plain")
                                .body(Full::new(Bytes::from("accepted")))
                                .unwrap(),
                        )
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let db_path = temp_db_path("http_accepted");
        let config = test_config(&db_path);
        let (db, writer) = db::spawn_writer(&db_path).unwrap();
        let patterns = Arc::new(PatternSet::bundled().unwrap());
        let allowlist = Arc::new(HashSet::new());
        let sc: ServerConfig = toml::from_str(&format!(
            "name = 'ack'\nupstream = '{upstream}'\nlisten = '127.0.0.1:0'\n"
        ))
        .unwrap();
        let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = proxy_tcp.local_addr().unwrap();
        let listener =
            Arc::new(build_listener(&sc, addr, &config, &db, &patterns, &allowlist).unwrap());
        let listeners = vec![Arc::clone(&listener)];
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let base = format!("http://{addr}");
        let task = tokio::spawn(accept_loop(proxy_tcp, listener, stop_rx));

        let client: UpstreamClient =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build(test_connector());
        post_tool_call(&client, &base, 1, "acked").await;

        let _ = stop_tx.send(true);
        let _ = task.await;
        drain_sessions(&listeners).await;
        drop(listeners);
        drop(db);
        assert!(matches!(
            writer.wait_for_drain(std::time::Duration::from_secs(30)),
            db::DrainOutcome::Drained { dropped: 0 }
        ));

        let conn = db::open_readonly(&db_path).unwrap();
        let rows = db::read_all_rows(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].entry.status, "timeout",
            "an unanswered call is a timeout, not a failure invented from an ack body"
        );
        drop(conn);
        remove_db_files(&db_path);
    }

    /// The upstream must be addressed by its own authority, not by the
    /// proxy's. Forwarding the client's `Host` untouched sends a request
    /// addressed to somebody else: against a real remote server that lands
    /// on a default virtual host rather than the MCP endpoint. Two loopback
    /// fixtures cannot show this — their authorities look alike — so the
    /// upstream here reports back which `Host` it was given.
    #[tokio::test]
    async fn upstream_is_addressed_by_its_own_host_not_the_proxys() {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = tcp.local_addr().unwrap();
        let upstream = format!("http://{upstream_addr}");
        tokio::spawn(async move {
            while let Ok((stream, _)) = tcp.accept().await {
                tokio::spawn(async move {
                    let svc = service_fn(|req: Request<Incoming>| async move {
                        let host = req
                            .headers()
                            .get(hyper::header::HOST)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("<none>")
                            .to_string();
                        let body = serde_json::json!({
                            "jsonrpc": "2.0", "id": 1,
                            "result": {"resultType": "complete",
                                       "content": [{"type": "text", "text": host}],
                                       "isError": false}
                        })
                        .to_string();
                        Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from(body))))
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });

        let db_path = temp_db_path("http_host_header");
        let config = test_config(&db_path);
        let (db, writer) = db::spawn_writer(&db_path).unwrap();
        let patterns = Arc::new(PatternSet::bundled().unwrap());
        let allowlist = Arc::new(HashSet::new());
        let sc: ServerConfig = toml::from_str(&format!(
            "name = 'h'\nupstream = '{upstream}'\nlisten = '127.0.0.1:0'\n"
        ))
        .unwrap();
        let proxy_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_tcp.local_addr().unwrap();
        let listener =
            Arc::new(build_listener(&sc, proxy_addr, &config, &db, &patterns, &allowlist).unwrap());
        let listeners = vec![Arc::clone(&listener)];
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let base = format!("http://{proxy_addr}");
        let task = tokio::spawn(accept_loop(proxy_tcp, listener, stop_rx));

        let client: UpstreamClient =
            Client::builder(hyper_util::rt::TokioExecutor::new()).build(test_connector());
        post_tool_call(&client, &base, 1, "whoami").await;

        let _ = stop_tx.send(true);
        let _ = task.await;
        drain_sessions(&listeners).await;
        drop(listeners);
        drop(db);
        let _ = writer.wait_for_drain(std::time::Duration::from_secs(30));

        let conn = db::open_readonly(&db_path).unwrap();
        let rows = db::read_all_rows(&conn).unwrap();
        assert_eq!(rows.len(), 1);
        let seen = rows[0].entry.result_json.clone().unwrap_or_default();
        drop(conn);
        remove_db_files(&db_path);

        assert!(
            seen.contains(&upstream_addr.to_string()),
            "upstream should have been addressed as {upstream_addr}, saw: {seen}"
        );
        assert!(
            !seen.contains(&proxy_addr.to_string()),
            "the proxy's own authority must not be forwarded as Host: {seen}"
        );
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
