#!/usr/bin/env python3
"""Minimal fake MCP server over Streamable HTTP, for exercising `auditmcp serve`.

A companion to fake_server.py (stdio): same tools, same responses, POSTed to
a single MCP endpoint instead of piped over stdin/stdout. Not a spec-complete
MCP server; it exists purely as a test fixture.

Usage: python fake_http_server.py <port>
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, __file__.rsplit("/", 1)[0].rsplit("\\", 1)[0])
from fake_server import TOOLS, handle_tool_call  # noqa: E402


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep the test output readable

    def _send(self, status, payload, content_type="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        # 2026-07-28 removed the GET stream endpoint; a modern-only server
        # answers 405 here, which is also part of how clients detect era.
        self._send(405, {"jsonrpc": "2.0", "error": {"code": -32601, "message": "GET not supported"}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length)
        try:
            msg = json.loads(raw)
        except Exception:
            self._send(400, {"jsonrpc": "2.0", "error": {"code": -32700, "message": "parse error"}})
            return

        method, msg_id = msg.get("method"), msg.get("id")
        if method == "tools/list":
            self._send(200, {"jsonrpc": "2.0", "id": msg_id,
                             "result": {"resultType": "complete", "tools": TOOLS}})
        elif method == "tools/call":
            result = handle_tool_call(msg.get("params") or {})
            result.setdefault("resultType", "complete")
            self._send(200, {"jsonrpc": "2.0", "id": msg_id, "result": result})
        elif method == "break_the_response":
            # Not JSON at all -- exercises the raw-payload path.
            self._send(502, b"<html><body>502 Bad Gateway</body></html>", "text/html")
        else:
            self._send(404, {"jsonrpc": "2.0", "id": msg_id,
                             "error": {"code": -32601, "message": "Method not found"}})


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
