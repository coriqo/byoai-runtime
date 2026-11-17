# FastAPI integration

Requires the `fastapi` extra: `pip install "byoai-runtime[fastapi]"`.

`byoai.integrations.fastapi` wires a `Runtime` into an existing FastAPI app with three pieces:

- [`attach(app, runtime)`][byoai.integrations.fastapi.attach] — stores the runtime on
  `app.state.byoai` and registers a shutdown hook that closes provider/cache/vector-store
  connections. It composes with an app's existing lifespan/startup handlers rather than
  replacing them.
- [`get_runtime`][byoai.integrations.fastapi.get_runtime] — a `Depends`-compatible accessor for
  route handlers.
- [`stream_response`][byoai.integrations.fastapi.stream_response] — wraps `runtime.stream()` in
  a Server-Sent-Events `StreamingResponse`.

```python
from fastapi import Depends, FastAPI
from byoai import Runtime
from byoai.integrations.fastapi import attach, get_runtime, stream_response

app = FastAPI()  # your existing app
attach(app, Runtime(llm={"provider": "openai", "model": "gpt-4o"}))

@app.post("/ask")
async def ask(body: dict, runtime: Runtime = Depends(get_runtime)):
    result = await runtime.execute(body["query"], user_id=body.get("user_id"))
    return {"content": result.content, "cached": result.cached, "usage": result.usage.__dict__}

@app.post("/ask/stream")
async def ask_stream(body: dict, runtime: Runtime = Depends(get_runtime)):
    return stream_response(runtime, body["query"], user_id=body.get("user_id"))
```

The SSE stream emits `data: {"delta": "..."}` events per token batch, then a final
`data: {"done": true, "usage": {...}}` event. `stream_response()` also accepts `headers=` to
override or drop the default buffering-safe response headers (`Cache-Control`,
`X-Accel-Buffering`) — pass `{}` to omit them entirely.

## Exposing the runtime over MCP alongside FastAPI

`byoai.integrations.mcp.attach()` mounts an MCP tool server into the same FastAPI app — see the
[MCP guide](mcp.md).

## WebSocket

`serve_websocket(runtime, websocket)` serves the same transport dialect as HTTP/SSE over an
already-accepted (or fresh) WebSocket connection — one JSON payload per client message, a stream
of JSON frames back:

```python
from fastapi import WebSocket
from byoai.integrations.fastapi import serve_websocket

@app.websocket("/ws")
async def ws(websocket: WebSocket, runtime: Runtime = Depends(get_runtime)):
    await serve_websocket(runtime, websocket)
```

See [`examples/fastapi_app/main.py`](https://github.com/coriqo/byoai-runtime/blob/main/examples/fastapi_app/main.py)
for a runnable app with events, caching, and provider fallback.
