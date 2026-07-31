#!/usr/bin/env python3
"""Minimal fake MCP stdio server for exercising auditmcp's proxy.

Speaks newline-delimited JSON-RPC 2.0 on stdin/stdout -- just enough of the
MCP shape (initialize, tools/list, tools/call) to be a useful proxy target.
Not a spec-complete MCP server; it exists purely as a test fixture.

Exposes 3 tools:
  - echo(text): returns text unchanged
  - delete_file(path): simulates a destructive action, never touches disk
  - leak_secret(): returns a string containing a fake API key, for
    exercising secrets-detection later (Phase 2)
"""
import json
import sys

TOOLS = [
    {
        "name": "echo",
        "description": "Echoes the given text back.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
        },
    },
    {
        "name": "delete_file",
        "description": "Simulates deleting a file. Does not touch the real filesystem.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "leak_secret",
        "description": "Returns a string containing a fake API key (for secrets-detection testing).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "simulate_tool_failure",
        "description": (
            "Deliberately returns a normal, successful JSON-RPC response "
            "whose result carries \"isError\": true -- the MCP convention "
            "for a tool's own failure, as opposed to a JSON-RPC-level "
            "error (for exercising that escalation path specifically)."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]

FAKE_API_KEY = "sk-FAKE1234567890abcdefFAKEKEYFAKE00"


def text_result(text, is_error=False):
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def handle_tool_call(params):
    name = params.get("name")
    args = params.get("arguments") or {}

    if name == "echo":
        return text_result(str(args.get("text", "")))
    if name == "delete_file":
        path = args.get("path", "<unspecified>")
        return text_result(f"[simulated] deleted {path}")
    if name == "leak_secret":
        # The fake key sits under a field literally named "api_key" (not
        # buried in an unlabeled sentence) so a live run exercises BOTH the
        # specific `openai_api_key` pattern (regex match on the "sk-..."
        # value) AND the generic heuristic pattern (fires because the key
        # name "api_key" satisfies its hints and the value clears the
        # entropy bar) on the exact same span -- the overlap-merge case.
        result = text_result("Retrieved credentials for the widget service.")
        result["api_key"] = FAKE_API_KEY
        return result
    if name == "simulate_tool_failure":
        return text_result("simulated failure: target resource not found", is_error=True)

    return text_result(f"unknown tool: {name}", is_error=True)


def send(msg):
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main():
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method")
        msg_id = msg.get("id")

        # Notifications (no id) get no response.
        if msg_id is None:
            continue

        if method == "initialize":
            send({
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "auditmcp-fake-server", "version": "0.1.0"},
                },
            })
        elif method == "tools/list":
            send({"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}})
        elif method == "tools/call":
            try:
                result = handle_tool_call(msg.get("params") or {})
                send({"jsonrpc": "2.0", "id": msg_id, "result": result})
            except Exception as e:
                send({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32000, "message": str(e)},
                })
        else:
            send({
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            })


if __name__ == "__main__":
    main()
