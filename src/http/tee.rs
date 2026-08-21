//! The response body wrapper that forwards frames to the client and audits
//! a bounded copy alongside, without ever waiting for the body to finish --
//! see the module doc on `TeeBody`.
//!
//! Split out of `http.rs` because this is hyper body-streaming plumbing, a
//! distinct concern from SSE wire-protocol parsing (`sse`), per-listener
//! session bookkeeping (`session_registry`), and the top-level proxy
//! orchestration (`server`) -- each has its own file in this directory
//! (see `http/mod.rs`).

use super::server::{log_entry, log_timeout};
use super::sse::{endpoint_key, replace_event_data, rewrite_endpoint_uri, SseEvent, SseParser};
use super::Listener;
use crate::audit::CallOutcome;
use crate::jsonrpc::RpcMessage;
use crate::session::Session;
use bytes::Bytes;
use hyper::body::Incoming;
use std::sync::Arc;

/// Cap on how much of a *response* is captured for the audit log.
///
/// Deliberately much smaller than the request cap, and deliberately not a
/// limit on what is forwarded. Responses stream through untouched however
/// large they are; this only bounds the copy kept for auditing, so a
/// gigabyte download or a long-lived event stream costs constant memory.
/// Going over it truncates the record and says so — it never delays or
/// truncates what the client receives.
pub(crate) const MAX_CAPTURE_BYTES: usize = 1024 * 1024;

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
pub(crate) struct TeeBody {
    inner: Incoming,
    /// Taken when the stream ends, so the final audit runs exactly once.
    tee: Option<Tee>,
    /// Event-stream mode only: complete events waiting to go out. Empty
    /// for whole-body responses, which forward their frames directly.
    pending_out: std::collections::VecDeque<Bytes>,
}

pub(crate) struct Tee {
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

pub(crate) enum TeeMode {
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
    pub(crate) fn new(
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
