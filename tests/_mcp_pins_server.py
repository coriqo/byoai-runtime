"""A stdio MCP server whose tool list a test can change while it runs.

Raw JSON-RPC, one message per line. Environment:

``PINS_TOOLS_FILE``  JSON list of tool objects, read again on every ``tools/list``
``PINS_HOST_TOOLS_FILE``  when set, a ``tools/list`` whose id does not start with
                     ``byoai-pin-`` (the host's) is answered from this file instead
``PINS_PAGE``        page size for ``tools/list`` (default: everything in one page)
``PINS_DELAY``       seconds to wait before answering ``tools/list``
``PINS_LOG``         every message received is appended here, one JSON line each
``ECHO_SERVER_LOG``  the name of every tool actually run is appended here

``x/emit_list_changed`` (a request) makes the server send
``notifications/tools/list_changed`` and then answer.
"""

from __future__ import annotations

import json
import os
import sys
import time


def tools(msg_id: object = None) -> list[dict]:
    path = os.environ["PINS_TOOLS_FILE"]
    own = isinstance(msg_id, str) and msg_id.startswith("byoai-pin-")
    if os.environ.get("PINS_HOST_TOOLS_FILE") and not own:
        path = os.environ["PINS_HOST_TOOLS_FILE"]
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def send(obj: object) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def answer(msg: dict) -> None:
    if isinstance(msg, list):
        for item in msg:
            answer(item)
        return
    method = msg.get("method")
    if "id" not in msg:
        return
    if method == "initialize":
        result: dict = {"protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {"listChanged": True}},
                        "serverInfo": {"name": "pins", "version": "0"}}
    elif method == "tools/list":
        delay = float(os.environ.get("PINS_DELAY", "0"))
        if delay:
            time.sleep(delay)
        everything = tools(msg.get("id"))
        page = int(os.environ.get("PINS_PAGE", "0")) or len(everything) or 1
        start = int((msg.get("params") or {}).get("cursor") or 0)
        chunk = everything[start:start + page]
        result = {"tools": chunk}
        if start + page < len(everything):
            result["nextCursor"] = str(start + page)
    elif method == "tools/call":
        params = msg.get("params") or {}
        log = os.environ.get("ECHO_SERVER_LOG")
        if log:
            with open(log, "a", encoding="utf-8") as fh:
                fh.write(str(params.get("name")) + "\n")
        result = {"content": [{"type": "text", "text": "ran " + str(params.get("name"))}],
                  "isError": False}
    elif method == "ping":
        result = {}
    elif method == "x/emit_list_changed":
        send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        result = {}
    else:
        send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "no"}})
        return
    send({"jsonrpc": "2.0", "id": msg["id"], "result": result})


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        msg = json.loads(line)
        with open(os.environ["PINS_LOG"], "a", encoding="utf-8") as fh:
            for item in msg if isinstance(msg, list) else [msg]:
                fh.write(json.dumps({"t": time.time(), "msg": item}) + "\n")
        answer(msg)


if __name__ == "__main__":
    main()
