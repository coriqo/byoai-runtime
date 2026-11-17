# Flask integration

Requires the `flask` extra: `pip install "byoai-runtime[flask]"`.

Flask is WSGI/sync; `Runtime` (and its httpx-based providers) is asyncio-native.
`byoai.integrations.flask` bridges the two internally using a persistent background
event-loop thread owned by the attached app, so route handlers stay plain `def`. No
`flask[async]`/asgiref, no `async def` views.

- [`attach(app, runtime)`][byoai.integrations.flask.attach] — stores the runtime (and its
  bridge thread) on `app.extensions["byoai"]`. Idempotent: calling it again on an
  already-attached app returns the existing runtime instead of starting a second thread.
- [`get_runtime`][byoai.integrations.flask.get_runtime] — the attached `Runtime`, resolved
  from `flask.current_app` by default (pass `app=` to call outside a request/app context).
- [`execute`][byoai.integrations.flask.execute] — sync wrapper for `runtime.execute()`.
- [`stream_response`][byoai.integrations.flask.stream_response] — sync wrapper returning a
  Server-Sent-Events `Response`.

```python
from flask import Flask, request, jsonify
from byoai import Runtime
from byoai.integrations.flask import attach, execute, stream_response

def create_app():
    app = Flask(__name__)
    attach(app, Runtime(llm={"provider": "anthropic", "model": "claude-sonnet-5"}))

    @app.post("/ask")
    def ask():
        result = execute(request.get_json()["query"], user_id=request.get_json().get("user_id"))
        return jsonify({"content": result.content, "cached": result.cached})

    @app.post("/ask/stream")
    def ask_stream():
        return stream_response(request.get_json()["query"])

    return app
```

The SSE stream emits `data: {"delta": "..."}` events per token batch, then a final
`data: {"done": true, "usage": {...}}` event — same frame shape as the FastAPI/Robyn
integrations. A tool-use turn emits `data: {"delta": "", "tool_call": {"index": 0, ...}}`
events instead (see `docs/guides/providers.md`'s "Streaming a tool call" section for the
full `tool_call` shape). `stream_response()` also accepts `headers=` to override or drop
the default buffering-safe response headers (`Cache-Control`, `X-Accel-Buffering`) — pass
`{}` to omit them entirely.

## Why an application factory

Build the `Runtime` and call `attach()` **inside** `create_app()`, never at module import
time. This isn't just a Flask style preference: it's load-bearing. `attach()` starts a
background thread running its own asyncio event loop, and that thread must exist *after*
your process model has finished forking, not before.

## Deploying with gunicorn

- **Never use `gunicorn --preload`.** Preload imports the app (and, if `attach()` runs at
  import time, starts the bridge thread) in the master process *before* forking workers.
  `fork()` doesn't carry other threads into the child, so the bridge thread simply won't
  exist post-fork; any lock it held at fork time can deadlock the child. Building the runtime
  inside `create_app()` and calling that factory once per worker process avoids this
  entirely.
- **Use `gthread` workers.** Each worker process gets its own bridge thread and event loop;
  Flask's request-thread pool dispatches onto that one loop, which is what the bridge is
  built for.
- **`gevent`/`eventlet` workers are untested here.** Their monkey-patching of
  `threading`/sockets against a real OS thread running its own asyncio loop hasn't been
  checked — don't assume it works without verifying it yourself.

## A missing API key shouldn't crash the whole app at boot

`AnthropicProvider` (and the other adapters) raise `ConfigurationError` eagerly at
construction if no API key is configured — fail-fast, not a lazy per-request check. In an app
factory, catch it and decide what "misconfigured" should mean for your app (e.g. a 503 stub
instead of refusing to boot):

```python
from byoai.errors import ConfigurationError

def create_app():
    app = Flask(__name__)
    try:
        runtime = Runtime(llm={"provider": "anthropic", "model": "claude-sonnet-5"})
    except ConfigurationError as exc:
        app.logger.error("ByoAI runtime misconfigured: %s", exc)
        runtime = None

    if runtime is not None:
        attach(app, runtime)
    else:
        @app.post("/ask")
        def ask_unavailable():
            return {"error": "AI features unavailable"}, 503

    return app
```

See [`examples/flask_app/main.py`](https://github.com/coriqo/byoai-runtime/blob/main/examples/flask_app/main.py)
for a runnable app with this pattern, `provider_metadata=`, and `cache_system=`.
