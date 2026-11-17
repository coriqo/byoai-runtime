"""Drive the capture server over a real MCP session and show what lands.

    python examples/mcp_capture/client.py

Spawns server.py over stdio, does a real initialize handshake (as Claude
Desktop would, with client info), lists tools, then exercises:

    1. execute              — one-shot call (has cache-hit second round)
    2. execute again        — same input, proves cache.hit capture
    3. execute_stream       — streamed tool call (progress deltas)
    4. execute with a failing payload — error capture path

The server echoes every captured record to stderr; the final section prints
captures.jsonl grouped by kind, i.e. THE THING WE WOULD SHOW IN THE CORIQO UI.
"""

from __future__ import annotations

import asyncio
import json
import sys
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).parent
CAPTURES = HERE / "captures.jsonl"


async def main() -> None:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=[str(HERE / "server.py")],
        env={},  # inherit
    )
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write,
                                 client_info=__import__("mcp.types", fromlist=["Implementation"]).Implementation(
                                     name="claude-demo-client", version="0.1")) as session:
            await session.initialize()
            print("── initialized real MCP session (client_info sent) ──")

            tools = await session.list_tools()
            print("── tools/list →",
                  [t.name for t in tools.tools])

            r1 = await session.call_tool("execute", {"input": "refund my order #8841", "user_id": "u_ev"})
            assert not r1.is_error, r1
            print("── call execute (1st) → ok ──")

            r2 = await session.call_tool("execute", {"input": "refund my order #8841", "user_id": "u_ev"})
            assert not r2.is_error, r2
            print("── call execute (same input, cache expected) ──")

            r3 = await session.call_tool("execute_stream", {"input": "hello there"})
            assert not r3.is_error, r3
            print("── call execute_stream ──")

            bad = await session.call_tool("execute", {"input": 42})
            print(f"── call execute (bad payload) → isError={bad.is_error} ──")


def show_ledger() -> None:
    if not CAPTURES.exists():
        print("no captures.jsonl — nothing captured")
        return
    rows = [json.loads(x) for x in CAPTURES.read_text().splitlines() if x.strip()]
    print()
    print("============ WHAT THE MCP SURFACE CAPTURED ============")
    by_kind: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        by_kind[r["kind"]].append(r)
    print(f"records: {len(rows)}  kinds: {len(by_kind)}")
    for kind, recs in sorted(by_kind.items()):
        print(f"\n· {kind} ×{len(recs)}")
        for r in recs[-2:]:
            print("   " + json.dumps(
                {k: r[k] for k in sorted(r) if k != "wall_clock"},
                sort_keys=True, default=str))


if __name__ == "__main__":
    asyncio.run(main())
    show_ledger()
