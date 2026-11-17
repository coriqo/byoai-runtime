"""MCP (Model Context Protocol) transport — expose a ByoAI runtime as an MCP
tool server, so any MCP client (Claude Desktop, another agent, your own
orchestrator) can call it exactly like it calls any other tool.

Same payload dialect as every other transport (see ``byoai.transport``):

    from byoai import Runtime
    from byoai.integrations.mcp import create_server

    runtime = Runtime(llm={"provider": "openai", "model": "gpt-4o"})
    server = create_server(runtime, name="my-app")
    server.run_stdio_async()          # classic MCP stdio server, or:

Mount into an existing ASGI app (FastAPI/Starlette) instead of running
standalone::

    from byoai.integrations.mcp import attach
    attach(app, runtime, path="/mcp")   # exposes POST/GET /mcp (streamable HTTP)

Requires the ``mcp`` extra: ``pip install byoai-runtime[mcp]``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

try:
    # MCP SDK >=2.0 renamed FastMCP -> MCPServer; both expose the same
    # .tool()/.streamable_http_app()/.run_stdio_async() surface.
    from mcp.server import MCPServer as _MCPServerCls
except ImportError:
    try:
        # SDK <2.0; not present in the >=2.0 layout pyright resolves against
        # in this environment, so this fallback path can't be statically
        # verified — that's expected, it's only ever reached on an old SDK.
        from mcp.server.fastmcp import (  # pyright: ignore[reportMissingImports]
            FastMCP as _MCPServerCls,  # pyright: ignore[reportAttributeAccessIssue]
        )
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "byoai.integrations.mcp requires the mcp package: "
            "pip install 'byoai-runtime[mcp]'"
        ) from exc

# Context's location isn't strictly tied to which of the above resolved —
# try both independently so a mismatch between the two doesn't produce the
# misleading "package missing" error when only Context moved.
try:
    from mcp.server.mcpserver import Context as _ContextCls  # SDK >=2.0
except ImportError:
    try:
        # SDK <2.0; see the matching comment on the FastMCP fallback above.
        from mcp.server.fastmcp import (  # pyright: ignore[reportMissingImports]
            Context as _ContextCls,  # pyright: ignore[reportAttributeAccessIssue]
        )
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "byoai.integrations.mcp requires the mcp package: "
            "pip install 'byoai-runtime[mcp]'"
        ) from exc

from ..errors import ByoAIError
from ..runtime import Runtime
from ..transport import execute_payload, stream_frames

if TYPE_CHECKING:  # pragma: no cover
    from starlette.applications import Starlette

MCPServer = _MCPServerCls  # re-exported for type hints / advanced customization
Context = _ContextCls


def _payload_from_args(
    input: str,
    pipeline: str | None,
    session_id: str | None,
    user_id: str | None,
    model: str | None,
    filters: dict[str, Any] | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {"input": input}
    for key, value in (
        ("pipeline", pipeline),
        ("session_id", session_id),
        ("user_id", user_id),
        ("model", model),
        ("filters", filters),
    ):
        if value is not None:
            payload[key] = value
    return payload


def create_server(
    runtime: Runtime,
    *,
    name: str = "byoai-runtime",
    tool_name: str = "execute",
    description: str | None = None,
    stream_tool_name: str | None = "execute_stream",
    stream_description: str | None = None,
    **server_kwargs: Any,
) -> Any:
    """Build an MCP server exposing ``runtime`` as one or two tools.

    Both tools accept the same payload shape as every other transport
    (``input``, optional ``pipeline``, ``session_id``, ``user_id``, ``model``,
    ``filters``) and return the same result dict as ``POST /execute`` elsewhere.

    * ``tool_name`` (default ``"execute"``) — one request, one response.
    * ``stream_tool_name`` (default ``"execute_stream"``; pass ``None`` to
      disable) — streams token deltas as MCP progress notifications (visible
      to clients that render them live) while still returning the same full
      result dict at the end, so non-streaming-aware clients work unchanged.
      Progress notifications require a live client session; if the tool is
      invoked without one (e.g. a local `call_tool()` in a test), reporting
      is skipped and the full result is still returned correctly.

    ``**server_kwargs`` are forwarded to the underlying MCP server
    constructor (``instructions``, ``version``, ``debug``, ``auth``, ...) for
    anything this wrapper doesn't already surface.
    """
    server = _MCPServerCls(name, **server_kwargs)

    @server.tool(
        name=tool_name,
        description=description
        or "Execute a request through the ByoAI runtime (routing, caching, "
        "retries, cost tracking) and return the response.",
    )
    async def execute(
        input: str,
        pipeline: str | None = None,
        session_id: str | None = None,
        user_id: str | None = None,
        model: str | None = None,
        filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload = _payload_from_args(input, pipeline, session_id, user_id, model, filters)
        try:
            return await execute_payload(runtime, payload)
        except ByoAIError as exc:
            # Surfaced to the MCP client as a tool error, not a transport crash.
            return {"error": str(exc), "error_type": type(exc).__name__}

    if stream_tool_name is not None:

        @server.tool(
            name=stream_tool_name,
            description=stream_description
            or "Like the execute tool, but streams token deltas as progress "
            "notifications while still returning the full response at the end.",
        )
        async def execute_stream(
            input: str,
            ctx: Context,
            pipeline: str | None = None,
            session_id: str | None = None,
            user_id: str | None = None,
            model: str | None = None,
            filters: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            payload = _payload_from_args(input, pipeline, session_id, user_id, model, filters)
            parts: list[str] = []
            chars_sent = 0
            final: dict[str, Any] = {}
            try:
                async for frame in stream_frames(runtime, payload):
                    if frame.get("done"):
                        final = frame
                        continue
                    delta = frame.get("delta", "")
                    if not delta:
                        continue
                    parts.append(delta)
                    chars_sent += len(delta)
                    try:
                        await ctx.report_progress(chars_sent, message=delta)
                    except ValueError:
                        pass  # no live client session (e.g. local call_tool()) — non-fatal
            except ByoAIError as exc:
                return {"error": str(exc), "error_type": type(exc).__name__}
            # Same key set as the non-streaming `execute` tool / POST /execute,
            # so a caller reading e.g. result["provider"] doesn't need to
            # special-case the streaming tool.
            return {
                "content": "".join(parts),
                "cached": final.get("cached", False),
                "model": final.get("model"),
                "provider": final.get("provider"),
                "usage": final.get(
                    "usage", {"input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0}
                ),
                "request_id": final.get("request_id"),
            }

    return server


def attach(
    app: Starlette,
    runtime: Runtime,
    *,
    path: str = "/mcp",
    name: str = "byoai-runtime",
    **create_kwargs: Any,
) -> Any:
    """Mount an MCP server into an existing Starlette/FastAPI app at ``path``
    (streamable HTTP transport).

    Two things ``app.mount()`` alone doesn't give you, both handled here:

    * The MCP sub-app has its own ASGI lifespan (it starts the streamable-HTTP
      session manager's task group); Starlette never cascades a parent app's
      lifespan into a mounted sub-app, so without this the session manager
      never starts and every request 500s. We enter/exit that lifespan
      manually via the host app's startup/shutdown hooks.
    * ``server.streamable_http_app()`` registers its own internal route at
      ``streamable_http_path`` — mounting *that* app again at ``path`` would
      double the prefix (``path`` + ``path``). We register the sub-app's
      internal route at ``"/"`` so ``path`` is applied exactly once, by
      ``app.mount()``.

    Requires the host app to support ``add_event_handler`` (FastAPI's
    router, or Starlette apps not yet on the lifespan-only contract) so we
    have somewhere to hook the sub-app's startup/shutdown — raises
    :class:`ConfigurationError` immediately if it doesn't, rather than
    mounting an endpoint that would 500 on every request. Plain modern
    Starlette apps (``lifespan=`` only) aren't supported by this helper;
    wire the MCP server's lifespan into your own instead.
    """
    from ..errors import ConfigurationError

    server = create_server(runtime, name=name, **create_kwargs)
    mcp_app = server.streamable_http_app(streamable_http_path="/")
    app.mount(path, mcp_app)

    # add_event_handler is gone from the Starlette/FastAPI app class itself in
    # current versions but survives (deprecated) on FastAPI's own APIRouter —
    # hasattr-based duck typing across that version split, so `target` can't
    # be given a real static type here.
    target: Any = next(
        (t for t in (app, getattr(app, "router", None)) if hasattr(t, "add_event_handler")),
        None,
    )
    if target is None:
        raise ConfigurationError(
            "byoai.integrations.mcp.attach() requires an app with "
            "add_event_handler (FastAPI, or Starlette with the on_event-style "
            "lifecycle) to start the MCP session manager's lifespan — plain "
            "modern Starlette apps using lifespan= only aren't supported here. "
            "Enter mcp_app.router.lifespan_context(mcp_app) in your own "
            "lifespan instead, where mcp_app = server.streamable_http_app()."
        )

    lifespan_cm = mcp_app.router.lifespan_context(mcp_app)

    async def _start_mcp() -> None:
        await lifespan_cm.__aenter__()

    async def _stop_mcp() -> None:
        await lifespan_cm.__aexit__(None, None, None)
        await runtime.close()

    target.add_event_handler("startup", _start_mcp)
    target.add_event_handler("shutdown", _stop_mcp)
    return server


def create_app(runtime: Runtime, *, name: str = "byoai-runtime", **create_kwargs: Any):
    """A standalone ASGI app serving the MCP tool over streamable HTTP."""
    server = create_server(runtime, name=name, **create_kwargs)
    return server.streamable_http_app()
