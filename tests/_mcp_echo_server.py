"""A minimal stdio MCP server for the coriqo-mcp tests and benchmark.

Raw JSON-RPC, one message per line, no SDK: it answers ``initialize``,
``tools/list`` (three tools) and ``tools/call`` (echoes the tool name and
arguments back), and writes the name of every tool it actually ran to the file
named by ``ECHO_SERVER_LOG``, so a test can prove a refused call never arrived.
"""

from __future__ import annotations

import json
import os
import sys

TOOLS = [
    {"name": name, "description": f"{name} tool", "inputSchema": {"type": "object"}}
    for name in ("search", "transfer_funds", "delete_account")
]


def answer(msg: dict) -> dict | None:
    method = msg.get("method")
    if "id" not in msg:
        return None
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "echo", "version": "0"},
        }
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        params = msg.get("params") or {}
        log = os.environ.get("ECHO_SERVER_LOG")
        if log:
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(str(params.get("name")) + "\n")
        result = {
            "content": [{"type": "text", "text": json.dumps(params, sort_keys=True)}],
            "isError": False,
        }
    elif method == "ping":
        result = {}
    else:
        return {"jsonrpc": "2.0", "id": msg["id"],
                "error": {"code": -32601, "message": "Method not found"}}
    return {"jsonrpc": "2.0", "id": msg["id"], "result": result}


def main() -> None:
    if os.environ.get("ECHO_SERVER_PID"):
        with open(os.environ["ECHO_SERVER_PID"], "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        parsed = json.loads(line)
        if isinstance(parsed, list):
            out = [r for r in (answer(m) for m in parsed) if r is not None]
            reply = out or None
        else:
            reply = answer(parsed)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
