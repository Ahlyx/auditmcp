//! Top-level proxy orchestration: `serve`, binding listeners, the
//! accept/connection loop, and the one place a completed call becomes an
//! audit row (`log_entry`).
//!
//! Split out of `http.rs` because this is a distinct concern from SSE
//! wire-protocol parsing (`sse`), the hyper body-streaming plumbing
//! (`tee`), and per-listener session bookkeeping (`session_registry`) --
//! each has its own file in this directory (see `http/mod.rs`).

use super::tee::TeeBody;
use super::Listener;
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
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;

use super::ProxyBody;

/// Cap on a request body, which must be buffered because it has to be
/// re-sent upstream. Generous for JSON-RPC, which is what MCP request
/// bodies are, and bounded so a hostile client cannot exhaust memory.
/// Exceeding it is refused rather than truncated: forwarding half a request
/// would corrupt the server's view of the protocol.
const MAX_REQUEST_BYTES: usize = 16 * 1024 * 1024;

pub async fn serve(config_path: &Path) -> anyhow::Result<()> {
    let config = Arc::new(Config::load(config_path)?);
    let servers = config.http_servers()?;

    let db_path = Path::new(&config.logging.db_path);
    // Same Phase 3.5 bootstrap `run` uses (see `proxy::run`): decides
    // fresh-HMAC vs. existing-HMAC vs. legacy for this db_path, and refuses
    // to start if it's HMAC-protected but the key can't be loaded or
    // doesn't verify. `serve` used to hardcode `HashKey::Legacy` here,
    // which silently ignored `[chain]`/`[heartbeat]`/`[anchor]` config and
    // -- worse -- made `verify` report every `serve`-written row as
    // tampered whenever the same db_path had already been bootstrapped
    // into HMAC mode by `run`.
    let key_path = config.chain.resolved_key_path()?;
    let chain_mode = crate::chain::bootstrap(
        db_path,
        &key_path,
        config.heartbeat.cadence_min_secs,
        config.heartbeat.cadence_max_secs,
    )?;

    // Same refuse-to-start conditions as `run`: an audit tool that cannot
    // record, or that would store secrets in the clear, must not proxy.
    let (db, writer) = db::spawn_writer_with_key(db_path, chain_mode.hash_key())?;

    // `serve` has no single stdio-style session -- sessions are created
    // per HTTP connection, dynamically, by each listener. Heartbeats need
    // *some* session_id to attach to, so this process gets one synthetic
    // "serve is alive" session, analogous to `run`'s one stdio session; it
    // is independent of the per-connection sessions the listeners manage.
    let serve_session_id = format!("serve:{}", uuid::Uuid::new_v4());
    const SERVE_HEARTBEAT_SERVER_NAME: &str = "auditmcp-serve";

    let (heartbeat_min, heartbeat_max) = chain_mode.heartbeat_cadence(
        config.heartbeat.cadence_min_secs,
        config.heartbeat.cadence_max_secs,
    );
    if config.heartbeat.enabled {
        db.log(crate::heartbeat::session_start_entry(
            &serve_session_id,
            SERVE_HEARTBEAT_SERVER_NAME,
            heartbeat_min,
            heartbeat_max,
        ));
    }
    let heartbeat_task = config.heartbeat.enabled.then(|| {
        tokio::spawn(crate::heartbeat::run(
            db.clone(),
            serve_session_id.clone(),
            SERVE_HEARTBEAT_SERVER_NAME.to_string(),
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

    let patterns = Arc::new(PatternSet::bundled().map_err(|e| {
        anyhow::anyhow!(
            "bundled secrets patterns failed to load: {e}. This is a defect in \
             this build of auditmcp, not a problem with your configuration -- \
             refusing to start rather than proxy with secrets detection disabled."
        )
    })?);
    let allowlist: Arc<HashSet<String>> = Arc::new(
        db::open_readonly(db_path)
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

    // Stop heartbeats before writing __session_end, so a heartbeat can
    // never land after the row that's supposed to close the session --
    // same ordering `run` uses.
    if let Some(task) = heartbeat_task {
        task.abort();
    }
    if let Some(task) = anchor_task {
        task.abort();
    }
    if config.heartbeat.enabled {
        db.log(crate::heartbeat::session_end_entry(
            &serve_session_id,
            SERVE_HEARTBEAT_SERVER_NAME,
        ));
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

pub(crate) fn build_listener(
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
        sessions: super::session_registry::SessionRegistry::default(),
    })
}

/// Loopback origins only, unless the config says otherwise. MCP requires
/// servers to validate `Origin` against DNS rebinding, and a loopback
/// listener is exactly the target that attack aims at: a page in the user's
/// browser can otherwise drive their MCP servers through us.
pub(crate) fn default_allowed_origins() -> Vec<String> {
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
pub(crate) async fn accept_loop(
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
    let pending_key = register_if_tool_call(listener, session, &parts, &body);

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
///
/// If a call is already pending under this same id (the client reused a
/// JSON-RPC id before the earlier call's response arrived), that earlier
/// `PendingCall` is displaced -- see `Session::register`. Rather than let
/// its eventual response find nothing to resolve and vanish from the log,
/// it is logged here as a timeout, same as any other call this proxy never
/// saw an answer for.
fn register_if_tool_call(
    listener: &Listener,
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
    if let Some(stale) = session.register(
        id_key.clone(),
        PendingCall {
            tool_name,
            args: msg.arguments().cloned(),
            bytes_in: body.len() as i64,
            started: Instant::now(),
        },
    ) {
        tracing::warn!(
            "server '{}': JSON-RPC id reused for tool '{}' before its previous response \
             arrived; logging the earlier call as a timeout rather than dropping it",
            listener.server_name,
            stale.tool_name
        );
        log_timeout(listener, session, stale);
    }
    Some(id_key)
}

pub(crate) fn log_timeout(listener: &Listener, session: &Session, call: PendingCall) {
    log_entry(listener, session, call, CallOutcome::timed_out());
}

/// The single place this transport turns a completed call into a row, so
/// the tier lookup, the pipeline inputs, and the anomaly attachment
/// cannot drift between the streaming path, the event path and the
/// shutdown drain.
pub(crate) fn log_entry(
    listener: &Listener,
    session: &Session,
    call: PendingCall,
    outcome: CallOutcome,
) {
    let tier = listener.config.tier_for_tool(&call.tool_name);
    let (mut entry, dest) = audit::build_entry(
        call,
        outcome,
        session.id(),
        &listener.server_name,
        tier,
        &listener.patterns,
        &listener.allowlist,
    );
    session.attach_anomaly(&mut entry, dest.as_ref(), Instant::now());
    listener.db.log(entry);
}

/// Swaps scheme and authority for the upstream's, keeping path and query
/// exactly as the client sent them.
pub(crate) fn rewrite_uri(upstream: &http::Uri, original: &http::Uri) -> http::Uri {
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
pub(crate) fn origin_allowed(origin: &str, allowed: &[String]) -> bool {
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
