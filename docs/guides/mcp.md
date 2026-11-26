# MCP (Model Context Protocol)

Requires the `mcp` extra: `pip install "byoai-runtime[mcp]"`.

`byoai.integrations.mcp` exposes a `Runtime` as an MCP tool server, so any MCP client (Claude
Desktop, another agent, your own orchestrator) can call it exactly like it calls any other tool —
same payload dialect as every other transport.

It works against MCP SDK versions on both sides of the `FastMCP` → `MCPServer` rename (SDK
`>=2.0` vs `<2.0`), resolving whichever is installed automatically.

## Standalone server (stdio)

The classic MCP integration — a subprocess a client launches and talks to over stdin/stdout:

```python
from byoai import Runtime
from byoai.integrations.mcp import create_server

runtime = Runtime(llm={"provider": "openai", "model": "gpt-4o"})
server = create_server(runtime, name="my-app")

import asyncio
asyncio.run(server.run_stdio_async())
```

`create_server()` returns the underlying MCP SDK server object, so every native method is
available too — `run_streamable_http_async(port=...)` for a standalone HTTP server, for example.
See [`examples/mcp_server/main.py`](https://github.com/coriqo/byoai-runtime/blob/main/examples/mcp_server/main.py)
for a runnable script that supports both `--http` and stdio from one entry point.

## Mounting into an existing app

```python
from fastapi import FastAPI
from byoai import Runtime
from byoai.integrations.mcp import attach

app = FastAPI()
attach(app, Runtime(llm={"provider": "openai", "model": "gpt-4o"}), path="/mcp")
```

Exposes streamable-HTTP MCP at `POST`/`GET /mcp`. This does more than a plain `app.mount()`:
it manually enters/exits the MCP sub-app's own ASGI lifespan via the host app's startup/shutdown
handlers (Starlette doesn't cascade a parent lifespan into a mounted sub-app, so without this the
streamable-HTTP session manager never starts and requests fail). It also closes the runtime on
shutdown, same as the FastAPI and Robyn integrations.

`attach()` requires the host app (or its `.router`) to support `add_event_handler` — it raises
`ConfigurationError` immediately if not, with a message pointing at the manual lifespan-context
alternative for apps that only use `lifespan=`.

## Tools exposed

- **`execute`** — one request, one response; same shape as `POST /execute` on the other
  transports. A `ByoAIError` is returned as `{"error": ..., "error_type": ...}` rather than
  crashing the tool call.
- **`execute_stream`** — streams token deltas back as MCP progress notifications while
  accumulating the full text, then returns the same result shape as `execute`. Disable it by
  passing `stream_tool_name=None` to `create_server()`/`attach()`.

Both tools accept `input`, and the same optional `pipeline`, `session_id`, `user_id`, `model`,
`filters` as `runtime.execute()`.

## Exact parameters

For the full `create_server()`/`attach()`/`create_app()` signatures, see
[CONFIGURATION.md](https://github.com/coriqo/byoai-runtime/blob/main/CONFIGURATION.md) —
that file is kept as the authoritative, exact parameter reference across every component; this
guide covers the narrative "how it fits together."
