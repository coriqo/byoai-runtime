"""A real MCP SDK server with three tools, for the coriqo-mcp end-to-end
tests against the SDK's own client. stdio by default; ``--http PORT`` serves
streamable HTTP at ``/mcp`` on 127.0.0.1 instead."""

from __future__ import annotations

import asyncio
import sys

try:
    from mcp.server import MCPServer as _Server
except ImportError:  # SDK < 2.0
    from mcp.server.fastmcp import FastMCP as _Server  # pyright: ignore[reportMissingImports]

server = _Server("tools-under-test")


@server.tool(name="search", description="Search")
def search(query: str) -> str:
    return f"results for {query}"


@server.tool(name="transfer_funds", description="Move money")
def transfer_funds(amount: int) -> str:
    return f"moved {amount}"


@server.tool(name="delete_account", description="Delete an account")
def delete_account(account: str) -> str:
    return f"deleted {account}"


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--http":
        import uvicorn

        uvicorn.run(server.streamable_http_app(), host="127.0.0.1", port=int(sys.argv[2]),
                    log_level="warning")
    else:
        asyncio.run(server.run_stdio_async())
