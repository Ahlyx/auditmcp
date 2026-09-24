#!/usr/bin/env python3
"""Small stdio MCP target for release status-path CLI integration tests."""

import json
import sys

FAKE_API_KEY = "sk-FAKE1234567890abcdefFAKEKEYFAKE00"


def response(msg):
    if msg.get("method") != "tools/call":
        return {"jsonrpc": "2.0", "id": msg.get("id"), "result": {}}

    params = msg.get("params") or {}
    name = params.get("name")
    args = params.get("arguments") or {}
    msg_id = msg.get("id")

    if name == "no_response":
        return None
    if name == "jsonrpc_error":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32001, "message": "fixture error"},
        }

    if name == "simulate_tool_failure":
        result = {"content": [{"type": "text", "text": "fixture failure"}], "isError": True}
    elif name == "deferred":
        result = {
            "resultType": "task",
            "taskId": "fixture-task-1",
            "status": "working",
            "ttlMs": 60000,
            "pollIntervalMs": 1000,
        }
    elif name == "secret":
        result = {"api_key": FAKE_API_KEY, "content": []}
    elif name == "echo":
        result = {"content": [{"type": "text", "text": str(args.get("text", ""))}], "isError": False}
    else:
        result = {"content": [{"type": "text", "text": "unknown tool"}], "isError": True}

    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


for raw in sys.stdin:
    try:
        message = json.loads(raw)
    except json.JSONDecodeError:
        continue
    if isinstance(message, list):
        replies = [reply for item in message if (reply := response(item)) is not None]
        if replies:
            sys.stdout.write(json.dumps(replies) + "\n")
            sys.stdout.flush()
        continue
    reply = response(message)
    if reply is not None:
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()
