//! Server-Sent Events wire-protocol parsing, plus the legacy `endpoint`
//! event rewrite that keeps HTTP+SSE (protocol 2024-11-05) sessions
//! correlated through this proxy -- see the module doc on `rewrite_endpoint_uri`.
//!
//! Split out of `http.rs` because this is byte-level wire-protocol parsing,
//! a distinct concern from the hyper body-streaming plumbing (`tee`), the
//! per-listener session bookkeeping (`session_registry`), and the top-level
//! proxy orchestration (`server`) -- each has its own file in this
//! directory (see `http/mod.rs`).

/// Cap on a single un-terminated SSE event while parsing. An event that
/// grows past this is abandoned and the parser resynchronises at the next
/// event boundary, so a stream that never emits one cannot grow the buffer
/// without bound.
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
pub(crate) struct SseEvent {
    pub(crate) raw: Vec<u8>,
    pub(crate) name: Option<String>,
    pub(crate) data: Option<String>,
}

impl SseParser {
    /// Feeds one chunk and returns every event completed by it.
    pub(crate) fn feed(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
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
    pub(crate) fn take_remainder(&mut self) -> Vec<u8> {
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

/// Replaces the `data:` payload of one event, preserving its other lines
/// and its terminator so nothing else about the frame changes.
pub(crate) fn replace_event_data(raw: &[u8], new_data: &str) -> Vec<u8> {
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
