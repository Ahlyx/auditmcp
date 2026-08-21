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
//! with a bounded copy taken alongside for the audit log (see [`tee::TeeBody`]).
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
//!
//! # Module layout
//!
//! Split into four files by concern: `sse` (wire-protocol parsing), `tee`
//! (hyper body-streaming plumbing), `session_registry` (per-listener
//! session bookkeeping), and `server` (top-level orchestration -- `serve`,
//! the accept loop, `proxy_once`). This file keeps only what all four
//! share: the `Listener` struct and the two body/client type aliases.

mod server;
mod session_registry;
mod sse;
mod tee;

pub use server::serve;
// Re-exported at crate-visibility rather than left as plain `mod`-private
// so this file's own `#[cfg(test)]` test module (below) -- which spans all
// four submodules' concerns and predates the split -- can keep resolving
// every name it uses via a single `use super::*`, unchanged.
#[allow(unused_imports)]
pub(crate) use server::{
    accept_loop, build_listener, default_allowed_origins, log_entry, log_timeout, origin_allowed,
    rewrite_uri,
};
#[allow(unused_imports)]
pub(crate) use sse::{
    endpoint_key, replace_event_data, rewrite_endpoint_uri, SseEvent, SseParser,
    MAX_SSE_EVENT_BYTES,
};
#[allow(unused_imports)]
pub(crate) use tee::{Tee, TeeBody, TeeMode, MAX_CAPTURE_BYTES};

use crate::config::Config;
use crate::db::DbHandle;
use crate::secrets::PatternSet;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use std::collections::HashSet;
use std::sync::Arc;

// The rest of these aren't used directly in this file -- they're here so
// this file's own `#[cfg(test)]` test module (below), which exercises the
// full stack (spawning fake upstream servers, building raw requests), can
// resolve them via `use super::*` exactly as it could when all of this was
// one flat file.
#[cfg(test)]
#[allow(unused_imports)]
use {
    crate::audit::{self, CallOutcome},
    crate::config::ServerConfig,
    crate::db::{self},
    crate::jsonrpc::RpcMessage,
    crate::session::{PendingCall, Session},
    crate::shutdown::{self, DRAIN_TIMEOUT},
    http_body_util::{BodyExt, Full, Limited},
    hyper::body::Incoming,
    hyper::service::service_fn,
    hyper::{Request, Response, StatusCode},
    hyper_util::client::legacy::Client,
    hyper_util::rt::TokioIo,
    std::path::Path,
    std::time::Instant,
    tokio::net::TcpListener,
};

/// The body type returned to clients: either a streamed upstream response
/// or a small locally-generated error.
pub(crate) type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// The outbound client: HTTP or HTTPS, chosen per upstream URL.
pub(crate) type UpstreamClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    http_body_util::Full<Bytes>,
>;

/// Everything a listener needs to serve and audit. Immutable after
/// construction apart from the session registry, which is per-listener.
pub(crate) struct Listener {
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
    sessions: session_registry::SessionRegistry,
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
