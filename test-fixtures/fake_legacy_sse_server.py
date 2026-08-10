#!/usr/bin/env python3
"""Minimal fake MCP server on the legacy HTTP+SSE transport (2024-11-05).

Two endpoints, per that revision:
  GET  /sse       opens the event stream and immediately sends an `endpoint`
                  event naming the URI to POST messages to
  POST <endpoint> accepts a JSON-RPC message, answers 202, and delivers the
                  actual response as a `message` event on the open stream

Deliberately emits a mix of frame shapes -- comments, `event:`-only frames,
multi-line data, an id/retry field, CRLF endings -- so a proxy can be diffed
byte for byte against talking to this server directly.

Usage: python fake_legacy_sse_server.py <port> [--absolute-endpoint]
"""
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, __file__.rsplit("/", 1)[0].rsplit("\\", 1)[0])
from fake_server import handle_tool_call  # noqa: E402

PORT = int(sys.argv[1])
ABSOLUTE = "--absolute-endpoint" in sys.argv
SESSION = "sess-legacy-001"

# The single open SSE stream, and a queue of frames to push down it.
_streams = []
_lock = threading.Lock()


def push(frame: bytes):
    with _lock:
        for wfile in list(_streams):
            try:
                wfile.write(frame)
                wfile.flush()
            except Exception:
                pass


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        if not self.path.startswith("/sse"):
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        with _lock:
            _streams.append(ChunkedWriter(self.wfile))
        w = _streams[-1]

        endpoint = (
            f"http://127.0.0.1:{PORT}/messages?sessionId={SESSION}"
            if ABSOLUTE
            else f"/messages?sessionId={SESSION}"
        )
        # The event whose URI decides whether the client ever talks to the
        # proxy again.
        w.write(f"event: endpoint\ndata: {endpoint}\n\n".encode())
        # A deliberate spread of other frame shapes, none of which may be
        # altered in transit.
        w.write(b": stream open\n\n")
        w.write(b"event: ping\nid: 1\nretry: 2000\n\n")
        w.write(b"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n")
        w.write(b"event: message\r\nid: 2\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\r\n\r\n")
        w.write(b"data: first line\ndata: second line\n\n")
        w.flush()

        # Hold the stream open long enough for a POST to be answered on it.
        deadline = time.time() + 6
        while time.time() < deadline:
            time.sleep(0.05)
        w.close()
        with _lock:
            if w in _streams:
                _streams.remove(w)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n)
        body = b"accepted"
        self.send_response(202)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

        try:
            msg = json.loads(raw)
        except Exception:
            return
        if msg.get("method") != "tools/call":
            return
        result = handle_tool_call(msg.get("params") or {})
        result.setdefault("resultType", "complete")
        response = json.dumps({"jsonrpc": "2.0", "id": msg.get("id"), "result": result})
        # The answer arrives on the SSE stream, not on this POST -- which is
        # what makes correlation span two connections on this transport.
        push_frame = f"event: message\ndata: {response}\n\n".encode()
        threading.Timer(0.05, push, args=(push_frame,)).start()


class ChunkedWriter:
    """Writes HTTP/1.1 chunked frames, so events leave immediately."""

    def __init__(self, wfile):
        self.wfile = wfile

    def write(self, payload: bytes):
        self.wfile.write(b"%x\r\n" % len(payload) + payload + b"\r\n")
        self.wfile.flush()

    def flush(self):
        self.wfile.flush()

    def close(self):
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except Exception:
            pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
