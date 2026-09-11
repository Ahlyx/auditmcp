//! Server-Sent Events wire-protocol parsing, plus the legacy `endpoint`
//! event rewrite that keeps HTTP+SSE (protocol 2024-11-05) sessions
//! correlated through this proxy -- see the module doc on `rewrite_endpoint_uri`.
//!
//! Split out of `http.rs` because this is byte-level wire-protocol parsing,
//! a distinct concern from the hyper body-streaming plumbing (`tee`), the
//! per-listener session bookkeeping (`session_registry`), and the top-level
//! proxy orchestration (`server`) -- each has its own file in this
//! directory (see `http/mod.rs`).

/// Cap on a single un-terminated SSE event while PARSING. An event that
/// grows past this stops being parsed -- the parser hands its bytes back
/// for forwarding unexamined and resynchronises at the next event boundary
/// -- so a stream that never emits one cannot grow the buffer without
/// bound.
///
/// This is a limit on what is audited, never on what is forwarded (see the
/// invariant in `tee.rs`). It previously did both: the buffer was cleared
/// and the next completed event skipped, so a >1 MiB event was deleted
/// from the stream the client receives. In Events mode the client sees
/// only what this parser returns, so a large tool result -- a file read, a
/// base64 screenshot -- simply vanished and the caller waited forever for
/// a response the upstream had already sent.
pub(crate) const MAX_SSE_EVENT_BYTES: usize = 1024 * 1024;

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
pub(crate) struct SseParser {
    pub(crate) buf: Vec<u8>,
    /// Set when an event outgrew the cap: bytes are forwarded but not
    /// parsed until the next boundary, rather than parsed as a corrupt
    /// fragment.
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
pub(crate) struct SseEvent {
    pub(crate) raw: Vec<u8>,
    pub(crate) name: Option<String>,
    pub(crate) data: Option<String>,
}

impl SseEvent {
    /// Bytes to forward verbatim with no audit interpretation: the parser
    /// gave up on them (they outgrew `MAX_SSE_EVENT_BYTES`), but the
    /// stream still owes them to the client. With `name` and `data` both
    /// `None`, `Tee::handle_event` falls straight through to forwarding
    /// `raw`, which is exactly the intent.
    fn passthrough(raw: Vec<u8>) -> Self {
        SseEvent {
            raw,
            name: None,
            data: None,
        }
    }
}

impl SseParser {
    /// Feeds one chunk and returns every event completed by it, plus any
    /// unparsed bytes that must still be forwarded (see
    /// `SseEvent::passthrough`).
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();

        while let Some((body_len, term_len)) = find_event_end(&self.buf) {
            let raw: Vec<u8> = self.buf.drain(..body_len + term_len).collect();
            if self.resyncing {
                // The tail of an event that outgrew the cap. Its prefix has
                // already gone out verbatim; this completes it, so it is
                // forwarded too and parsing resumes at the next boundary.
                self.resyncing = false;
                out.push(SseEvent::passthrough(raw));
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
            // Hand the buffered prefix back for forwarding instead of
            // dropping it, and stop parsing this event. The client still
            // receives every byte in order; only the audit record is lost,
            // which is the trade this cap is allowed to make.
            let raw = std::mem::take(&mut self.buf);
            tracing::warn!(
                bytes = raw.len(),
                "SSE event exceeded the {MAX_SSE_EVENT_BYTES}-byte parse cap; forwarding it                  to the client unexamined and skipping its audit record"
            );
            out.push(SseEvent::passthrough(raw));
            self.resyncing = true;
        }
        out
    }

    /// Bytes received that have not yet formed a complete event, taken so
    /// they can be flushed when the stream ends. A server that closes
    /// without a final terminator still gets its last bytes forwarded.
    pub(crate) fn take_remainder(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }
}

/// The value of the given field. When a field appears more than once in an
/// event, the SPEC says the last occurrence wins (SSE §"field definitions"
/// applies each line in order, overwriting), so an
/// `event: message\nevent: endpoint` frame must be treated as an endpoint
/// frame -- taking the first would forward it unrewritten and let the
/// client bypass the proxy.
fn field(event: &[u8], prefix: &str) -> Option<String> {
    let text = std::str::from_utf8(event).ok()?;
    let mut found = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(prefix) {
            found = Some(rest.strip_prefix(' ').unwrap_or(rest).to_string());
        }
    }
    found
}

/// Offset of an event terminator and its length. The SSE grammar allows
/// either LF or CRLF line endings independently per line, so besides the
/// two uniform terminators (`\n\n`, `\r\n\r\n`) a mixed-style blank line
/// (`"\n\r\n"` -- LF-terminated data line followed by CRLF terminator)
/// is also spec-legal and must end the event rather than stall the parser
/// until it merges with the next one's bytes.
fn find_event_end(buf: &[u8]) -> Option<(usize, usize)> {
    // Candidates as (offset, terminator length); earliest offset wins,
    // longest terminator breaks ties so `\r\n\r\n` is consumed whole rather
    // than leaving a stray `\n` to start the next event.
    let mut candidates: Vec<(usize, usize)> = Vec::with_capacity(3);
    if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        candidates.push((i, 4));
    }
    if let Some(i) = buf.windows(3).position(|w| w == b"\n\r\n") {
        candidates.push((i, 3));
    }
    if let Some(i) = buf.windows(2).position(|w| w == b"\n\n") {
        candidates.push((i, 2));
    }
    candidates
        .into_iter()
        .min_by_key(|&(pos, len)| (pos, std::cmp::Reverse(len)))
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
pub(crate) fn rewrite_endpoint_uri(raw: &str, local_addr: &std::net::SocketAddr) -> Option<String> {
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
pub(crate) fn endpoint_key(uri: &str) -> Option<String> {
    let parsed: http::Uri = uri.trim().parse().ok()?;
    Some(parsed.path_and_query()?.to_string())
}

/// Replaces the `data:` payload of one event, preserving everything else
/// about the frame byte-for-byte -- other fields, their order, and each
/// line's OWN line-ending style. Splitting the whole frame on a single
/// detected newline style would silently rewrite the endings of lines that
/// used the other style (a mixed-style frame is spec-legal), which is
/// exactly the kind of byte the forwarding guarantee says never changes.
pub(crate) fn replace_event_data(raw: &[u8], new_data: &str) -> Vec<u8> {
    let Ok(text) = std::str::from_utf8(raw) else {
        return raw.to_vec();
    };
    let mut out = String::with_capacity(text.len() + new_data.len() + 2);
    let mut replaced = false;
    // split_inclusive keeps each line's terminator attached, so it is
    // re-emitted verbatim for untouched lines and reattached to the one
    // line whose payload changes.
    for line in text.split_inclusive('\n') {
        let (content, terminator) = match line.strip_suffix("\r\n") {
            Some(content) => (content, "\r\n"),
            None => match line.strip_suffix('\n') {
                Some(content) => (content, "\n"),
                None => (line, ""), // final line without a terminator
            },
        };
        if content.starts_with("data:") {
            // Multi-line data collapses to one line; the payload is a URI,
            // which cannot legally span lines.
            if !replaced {
                out.push_str("data: ");
                out.push_str(new_data);
                out.push_str(terminator);
                replaced = true;
            }
            // Subsequent data lines are dropped along with their terminators.
        } else {
            out.push_str(content);
            out.push_str(terminator);
        }
    }
    out.into_bytes()
}
