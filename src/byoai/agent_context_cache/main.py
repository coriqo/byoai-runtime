import asyncio
import copy
import hashlib
import hmac
import json
import os
import random
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
import redis.asyncio as redis
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, RedirectResponse, Response, StreamingResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from ..recorder.integration import get_recorder
from ..recorder.ledger import LedgerWriteError
from ..recorder.proxy_gate import (
    SseEnforcer,
    enforce_response_body,
    proxy_enforcement_enabled,
    resolve_enforcer,
    start_proxy_enforcement,
    stop_proxy_enforcement,
)
from ..recorder.schema import new_span_id, new_trace_id
from ..session_hash import RedisHashStore
from ..shield_guard import gateway as shield_gw
from ..stages import PromptCacheInjection, SessionDedup
from ..stages import _count_cache_control_markers as _stage_count_cache_control_markers
from . import console as console_assets
from . import db, openai_compat

# Configuration
ANTHROPIC_UPSTREAM = "https://api.anthropic.com"
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# Route specific model names/prefixes to an OpenAI-spec-compatible backend
# (self-hosted vLLM/Ollama, Groq, OpenRouter, Together, etc.) instead of
# Anthropic. Client keeps sending Anthropic-shaped requests either way;
# openai_compat.py handles translating both directions. Configure via env
# so this doesn't require a code change per deployment:
#   BYOAI_OPENAI_COMPAT_MODELS="local-llama-3,my-vllm-model"
#   BYOAI_OPENAI_COMPAT_BASE_URL="http://localhost:8000/v1"
#   BYOAI_OPENAI_COMPAT_API_KEY="..."
OPENAI_COMPAT_MODELS = {
    m.strip() for m in os.getenv("BYOAI_OPENAI_COMPAT_MODELS", "").split(",") if m.strip()
}
OPENAI_COMPAT_BASE_URL = os.getenv("BYOAI_OPENAI_COMPAT_BASE_URL", "")
OPENAI_COMPAT_API_KEY = os.getenv("BYOAI_OPENAI_COMPAT_API_KEY", "")

# How long a conversation's dedup hash set survives with no new requests.
# There is no explicit "session end" signal in the Anthropic Messages API
# (it's a stateless HTTP endpoint), so we approximate "discard when the
# session ends" with an idle TTL: every time the session is touched, the
# TTL is refreshed; if nobody calls in with that session for this long,
# Redis reaps the key on its own.
SESSION_TTL_SECONDS = int(os.getenv("BYOAI_SESSION_TTL_SECONDS", str(8 * 60 * 60)))  # 8h default

# Optional shared-secret gate. When set, every request must present the token —
# so the proxy can be exposed through a public tunnel (ngrok/Cloudflare) for a
# remote client (Claude web/mobile, a phone) without becoming an open relay to
# Anthropic (or, if OpenAI-compat is configured, leaking that server-side key).
# Empty (the default) = no gate, suitable for a localhost-only deployment.
#
# The token is accepted two ways so it works even with clients that only let you
# set the base URL and not custom headers (e.g. Claude's web/mobile apps):
#   * header  `x-byoai-proxy-token: <token>`
#   * URL path prefix — set ANTHROPIC_BASE_URL to https://<host>/<token>, and the
#     leading /<token> segment is stripped before routing.
PROXY_TOKEN = os.getenv("BYOAI_PROXY_TOKEN", "")

# httpx defaults to a 5-SECOND total timeout when none is set. That's fine
# for a typical REST call but far too aggressive for LLM streaming
# responses, where gaps between SSE chunks (thinking time, tool execution,
# slow generation) routinely exceed 5s. Without an explicit override here,
# any such gap raises httpx.ReadTimeout mid-stream, and since nothing
# catches it, it crashes the whole ASGI response instead of failing
# gracefully. Read timeout is intentionally generous; connect/write stay
# tight since those really should be fast.
REQUEST_READ_TIMEOUT_SECONDS = float(os.getenv("BYOAI_READ_TIMEOUT_SECONDS", "600"))
HTTP_TIMEOUT = httpx.Timeout(
    connect=10.0, write=300.0, pool=10.0, read=REQUEST_READ_TIMEOUT_SECONDS
)

# Real-tokenizer benchmarking. estimate_tokens() (len(json)//4) is a rough
# heuristic — fine for a live console readout, not defensible as a public
# claim of "X% saved". Anthropic's own /v1/messages/count_tokens endpoint
# returns an authoritative token count from their real tokenizer, and does
# NOT generate a completion, so it isn't billed like a normal request.
# Calling it on the pre- and post-optimization payload for a sampled
# fraction of real traffic gives a number backed by Anthropic's own count,
# not our guess — that's the number worth publishing, not the estimate.
# Off by default: this adds two extra round trips per sampled request, so
# it must be deliberately enabled and rate-limited via sampling.
BENCHMARK_SAMPLE_RATE = float(os.getenv("BYOAI_BENCHMARK_SAMPLE_RATE", "0.1"))

# Only genuinely-retired model IDs should be remapped, and only onto
# models that are currently active. Do not remap models that already work.
MODEL_MAP = {
    "claude-3-5-haiku-20241022": "claude-haiku-4-5-20251001",
}

# Unsafe response headers that cause Starlette/client decoding errors
UNSAFE_RESPONSE_HEADERS = {
    "content-encoding",
    "content-length",
    "transfer-encoding",
    "connection",
    "server",
    "keep-alive",
}

# Redis keys, centralized so the same string literal isn't repeated at
# every call site.
REDIS_KEY_ENABLED = "byoai:config:enabled"
REDIS_KEY_TOKENS_SAVED = "byoai:stats:tokens_saved"

JSON_MEDIA_TYPE = "application/json"

# Redis Connection Pool & in-memory backup (used only if Redis is unreachable)
r = redis.from_url(REDIS_URL, decode_responses=True)


# Runtime primitives (byoai.stages) are the single source of truth for
# request-side optimization on the live /v1/messages path. The legacy inline
# implementations (ensure_cache_control / optimize_payload / is_duplicate_hash
# / add_hash) have been deleted; PromptCacheInjection and SessionDedup now own
# this logic. One module-level store + dedup stage so per-session dedup state
# persists across requests. The store resolves the module-level `r` lazily
# (via _LazyRedisClient) rather than capturing it at import time, so a test
# that monkeypatches `acc_main.r` — or a runtime redis reconnect — is honored
# on the live path.
class _LazyRedisClient:
    def __getattr__(self, name):
        return getattr(r, name)


_session_hash_store = RedisHashStore(_LazyRedisClient(), ttl_seconds=SESSION_TTL_SECONDS)
_session_dedup_stage = SessionDedup(_session_hash_store)

# Shared, connection-pooled HTTP client reused across every request to
# Anthropic. Creating a fresh httpx.AsyncClient() per request (the prior
# behavior) meant a new TCP+TLS handshake to api.anthropic.com on every
# single call — tens of milliseconds of pure connection setup, wasted, on
# every request. One long-lived client with keep-alive avoids that: this
# is the single biggest real latency win available here (see note in
# conversation — everything else is dwarfed by network + model generation
# time regardless of language).
http_client: httpx.AsyncClient | None = None

# Fire-and-forget durable-record writes (db.record_usage_event,
# db.record_benchmark_sample) hold no other reference once scheduled, so
# asyncio would be free to garbage-collect them mid-write. Keeping them in
# this set until they finish prevents that.
_background_tasks: set[asyncio.Task] = set()


def _fire_and_forget(coro):
    task = asyncio.create_task(coro)
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)
    return task


def get_http_client() -> httpx.AsyncClient:
    """Return the shared client, set up by `lifespan` before any request is served."""
    assert http_client is not None, "http_client used before FastAPI lifespan startup ran"
    return http_client


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global http_client
    http_client = httpx.AsyncClient(
        limits=httpx.Limits(max_keepalive_connections=50, max_connections=200),
        timeout=HTTP_TIMEOUT,
    )
    try:
        if not await r.exists(REDIS_KEY_ENABLED):
            await r.set(REDIS_KEY_ENABLED, "1")
    except Exception as e:
        print(f"[byoai-runtime Warning] Redis offline on startup ({e}). Operating in memory mode.")
    await db.init_db()
    print(f">>> byoai-runtime control plane initialized. Durable record: {db.DB_PATH}")
    # Apply the retention window once per start. Startup (rather than a
    # periodic timer) is enough: the log grows slowly, and a proxy left running
    # for months is exactly the case where an idle background task would be
    # holding the event loop for no benefit. `byoai-cache prune` covers the
    # long-uptime case on demand.
    #
    # vacuum=False here: this runs before `yield`, so nothing is served until
    # it returns, and VACUUM rewrites the whole file under an exclusive lock —
    # on a large DB that turns a restart into a visible outage. The DELETE
    # alone is fast and bounded. Space is reclaimed by explicit
    # `byoai-cache prune`, where the caller chose to pay the cost.
    pruned = await db.prune(vacuum=False)
    if pruned.get("deleted_rows"):
        print(
            f">>> byoai-runtime retention: removed {pruned['deleted_rows']} rows older than "
            f"{pruned['retention_days']}d"
            + (" (vacuumed)" if pruned.get("vacuumed") else "")
        )
    enforcement_gates = await start_proxy_enforcement()
    yield
    await stop_proxy_enforcement(enforcement_gates)
    await http_client.aclose()
    await r.close()


app = FastAPI(title="byoai-runtime Context Optimizer", lifespan=lifespan)


# Root and health are intentionally ungated so a tunnel/monitor/browser can
# probe liveness without the secret.
_AUTH_EXEMPT_PATHS = frozenset({"/", "/health"})


@app.middleware("http")
async def _proxy_auth_gate(request: Request, call_next):
    """Enforce the optional BYOAI_PROXY_TOKEN shared secret when configured.

    Accepts the token via the ``x-byoai-proxy-token`` header or a leading URL
    path segment (``/<token>/v1/messages``), stripping that segment so the
    normal routes still match. No-op when the token is empty.
    """
    # Read the module global (not a captured copy) so tests and runtime env
    # both take effect.
    token = PROXY_TOKEN
    if token and request.url.path not in _AUTH_EXEMPT_PATHS:
        authed = False
        header_tok = request.headers.get("x-byoai-proxy-token", "")
        if header_tok and hmac.compare_digest(header_tok, token):
            authed = True
        else:
            # Path-prefix form: /<token>/<rest>. Constant-time compare the first
            # segment; on match, rewrite the path so downstream routing is
            # unchanged.
            stripped = request.url.path.lstrip("/")
            first, _, rest = stripped.partition("/")
            if hmac.compare_digest(first, token):
                new_path = "/" + rest
                request.scope["path"] = new_path
                request.scope["raw_path"] = new_path.encode()
                authed = True
        if not authed:
            return Response(
                content=json.dumps(
                    {
                        "error": {
                            "type": "authentication_error",
                            "message": "byoai-runtime: missing or invalid proxy token",
                        }
                    }
                ),
                status_code=401,
                media_type=JSON_MEDIA_TYPE,
            )
    return await call_next(request)


def estimate_tokens(data: dict) -> int:
    """Quick Token Estimator (~4 chars per token average)."""
    return len(json.dumps(data)) // 4


def _recorder_write_failed_response(exc: LedgerWriteError) -> Response:
    return Response(
        content=json.dumps({"error": {"type": "api_error", "message": f"byoai-runtime: {exc}"}}),
        status_code=503,
        media_type=JSON_MEDIA_TYPE,
    )


def clean_response_headers(headers: dict) -> dict:
    """Strips transfer/encoding headers so FastAPI/Starlette doesn't corrupt streams."""
    return {k: v for k, v in headers.items() if k.lower() not in UNSAFE_RESPONSE_HEADERS}


def log_usage(session_id: str, usage: dict | None):
    """
    Prints Anthropic's *actual* billed token accounting for a response,
    including prompt-cache hits/writes — this is the real cost signal,
    separate from the rough estimate_tokens() heuristic used elsewhere.
    """
    if not usage:
        return
    input_tok = usage.get("input_tokens", 0)
    output_tok = usage.get("output_tokens", 0)
    cache_read = usage.get("cache_read_input_tokens", 0)
    cache_write = usage.get("cache_creation_input_tokens", 0)

    total_context = input_tok + cache_read + cache_write
    cache_hit_pct = (cache_read / total_context * 100) if total_context > 0 else 0.0

    print(f"[byoai-runtime 💰 USAGE] session={session_id}")
    print(f" ├─ input={input_tok:,} output={output_tok:,}")
    print(f" ├─ cache_read={cache_read:,}  cache_write={cache_write:,}")
    if cache_read == 0 and cache_write == 0:
        print(
            " └─ No prompt caching detected on this call "
            "(no cache_control hit or the request doesn't use it)."
        )
    else:
        print(
            f" └─ Cache hit rate: {cache_hit_pct:.1f}% of context served "
            "from cache (cheap) vs fresh (full price)."
        )


def derive_session_id(request: Request, body: dict) -> str:
    """
    Scope dedup state to a single conversation.

    Preferred: an explicit client-supplied session/conversation id header,
    if the caller sends one (e.g. Claude Code or another agent harness that
    tracks its own conversation ids). Falls back to a stable hash of the
    caller's API key plus the first message in the array plus the system
    prompt — in practice, agentic frameworks append to conversation history
    turn over turn but don't rewrite the opening message, so this stays
    constant for the life of one conversation and changes for a new one.

    The API key is included deliberately: without it, the fallback hash is a
    pure function of request *content*, with no notion of which caller sent
    it. Two unrelated, concurrent conversations under different accounts that
    happen to start with a byte-identical system prompt and first message
    (common for subagent/Task-tool calls, which reuse a fixed boilerplate
    opening message) would otherwise collide onto the same session id — and
    since dedup state controls whether SessionDedup deletes content as
    "already seen", a collision means one conversation's genuinely-first-seen
    file content gets silently replaced with a stale-duplicate placeholder.
    Scoping by API key makes that cross-account collision impossible. The one
    remaining case — two terminals under the *same* key opening with
    byte-identical content within the same SESSION_TTL_SECONDS window — is a
    narrower, honest residual risk; callers who need a hard guarantee should
    send X-BYOAI-Session-Id explicitly.
    """
    explicit = request.headers.get("x-byoai-session-id") or request.headers.get("x-session-id")
    if explicit:
        return f"hdr:{explicit}"

    api_key = request.headers.get("x-api-key", "")
    messages = body.get("messages", [])
    system = body.get("system", "")
    seed = json.dumps(
        {"key": api_key, "system": system, "first": messages[0] if messages else None},
        sort_keys=True,
    )
    return "auto:" + hashlib.sha256(seed.encode()).hexdigest()


def derive_trace_context(request: Request) -> tuple[str, str, str | None, str | None]:
    """Recorder trace attribution for one request.

    ``trace_id``: the caller's ``X-BYOAI-Trace-Id`` header if sent (a
    sub-agent or a harness that already tracks its own run id), otherwise a
    fresh one — this request is then the root of a new logical run.

    ``span_id``: always freshly generated per request; this call is one agent
    invocation regardless of whether it's a root or sub-agent.

    ``parent_span_id``: from ``X-BYOAI-Parent-Span-Id`` if sent, else ``None``
    (top-level agent, no parent).

    ``continues_from``: from ``X-BYOAI-Continues-From`` if sent, else
    ``None``. Plumbing only — this recorder does not attempt to auto-detect
    that a request continues a prior (now-restarted) session; a caller that
    wants that link recorded must send the header itself.
    """
    trace_id = request.headers.get("x-byoai-trace-id") or new_trace_id()
    span_id = new_span_id()
    parent_span_id = request.headers.get("x-byoai-parent-span-id") or None
    continues_from = request.headers.get("x-byoai-continues-from") or None
    return trace_id, span_id, parent_span_id, continues_from


async def safe_redis_get(key: str, default: str = "0") -> str:
    try:
        val = await r.get(key)
        # decode_responses=True on the client makes this always str at
        # runtime; redis-py's stubs still type it as bytes | str | None.
        return str(val) if val is not None else default
    except Exception:
        return default


async def safe_redis_incrby(key: str, val: int):
    try:
        await r.incrby(key, val)
    except Exception:
        pass


async def real_token_count(count_token_headers: dict, body: dict | None) -> int | None:
    """
    Ask Anthropic's actual tokenizer for the real input token count of a
    request body, via /v1/messages/count_tokens. This does not generate a
    completion and is not billed as one — it exists specifically for this
    kind of pre-flight measurement. Returns None on any failure so a
    benchmarking call can never break or delay the real request it rides
    alongside; callers must treat None as "sample discarded", not zero.
    """
    if body is None:
        return None
    try:
        # /v1/messages/count_tokens has a STRICTER schema than /v1/messages —
        # it rejects unknown fields outright (confirmed via a real 400:
        # "metadata: Extra inputs are not permitted") rather than ignoring
        # them. Anthropic's docs confirm only these fields are accepted;
        # generation/sampling params (max_tokens, temperature, top_p, top_k)
        # and metadata/stream are NOT, so allow-list rather than exclude a
        # few — an exclude-list breaks again the next time the client sends
        # some other field this endpoint doesn't recognize.
        COUNT_TOKENS_ALLOWED_FIELDS = {
            "model",
            "messages",
            "system",
            "tools",
            "tool_choice",
            "thinking",
        }
        count_body = {k: v for k, v in body.items() if k in COUNT_TOKENS_ALLOWED_FIELDS}
        res = await get_http_client().post(
            f"{ANTHROPIC_UPSTREAM}/v1/messages/count_tokens",
            json=count_body,
            headers=count_token_headers,
            timeout=30.0,
        )
        if res.status_code != 200:
            print(
                f"[byoai-runtime 🔬 BENCHMARK ERROR] count_tokens returned "
                f"{res.status_code}: {res.content[:500]!r}"
            )
            return None
        return json.loads(res.content).get("input_tokens")
    except Exception as e:
        print(
            f"[byoai-runtime 🔬 BENCHMARK ERROR] count_tokens call raised {type(e).__name__}: {e}"
        )
        return None


@app.api_route("/", methods=["GET", "HEAD"])
async def root():
    """A small landing/liveness response so a bare probe of ``/`` (browsers,
    tunnel health checks, uptime monitors) gets a friendly 200 instead of a
    confusing 404. HEAD is included because many probes use it."""
    return {
        "service": "byoai-agent-context-cache",
        "status": "ok",
        "docs": "https://github.com/coriqo/byoai-runtime#-agent-context-cache",
        "endpoints": {
            "messages": "/v1/messages",
            "count_tokens": "/v1/messages/count_tokens",
            "health": "/health",
            "stats": "/v1/stats",
        },
    }


@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "byoai-runtime is operational."}


@dataclass
class _Gate:
    parse: bytes                       # readable body, for routes that read it themselves
    forward: bytes                     # what a passthrough sends
    drop_encoding: bool = False        # True only when ``forward`` is not the original body
    active: bool = False               # the guard looked at this request
    response: Response | None = None   # set when the request must stop here


async def _shield_gate(request: Request, body_bytes: bytes, shape: str, provider: str) -> _Gate:
    """Shield guard for one body-carrying request. With the guard off, or no
    body, nothing changes. ``observe`` records and forwards the original bytes;
    only ``enforce`` blocks or rewrites."""
    if shield_gw.mode() == "off" or not body_bytes:
        return _Gate(body_bytes, body_bytes)
    outcome = await run_in_threadpool(
        shield_gw.guard_raw, body_bytes, request.headers.get("content-encoding"), shape)
    try:
        shield_gw.record_evidence(
            get_recorder(), outcome, provider=provider, path=request.url.path,
            session_id=request.headers.get("x-byoai-session-id") or "shield-guard",
            trace_id=new_trace_id(), span_id=new_span_id())
    except LedgerWriteError as e:
        return _Gate(b"", b"", response=_recorder_write_failed_response(e))
    if outcome.blocked is not None:
        return _Gate(b"", b"", response=Response(
            content=shield_gw.error_bytes(outcome.blocked), status_code=403,
            media_type=JSON_MEDIA_TYPE))
    return _Gate(outcome.parse, outcome.forward, outcome.drop_encoding, active=True)


_BASE_DROP = ("host", "content-length", "accept-encoding", "connection")


def _fwd_headers(request: Request, drop_encoding: bool = False) -> dict:
    drop = _BASE_DROP + (("content-encoding",) if drop_encoding else ())
    return {k: v for k, v in request.headers.items() if k.lower() not in drop}


@app.api_route("/v1/messages/count_tokens", methods=["GET", "POST"])
async def proxy_count_tokens(request: Request):
    """
    Plain pass-through for Anthropic's token-counting endpoint. This has
    no optimizer/dedup logic — it's a lightweight pre-flight call clients
    make to estimate tokens before sending the real request, and if it
    404s, the client can end up retrying aggressively. Just relay it.

    Models routed to an OpenAI-compat backend (Ollama, vLLM, etc.) have no
    Anthropic tokenizer to call and may have no real Anthropic API key
    configured at all — passing through unconditionally would always
    401/404 for those. Answer with our own estimate_tokens() heuristic
    instead; it's the same estimate already used for the /v1/stats
    savings numbers, so it's consistent even if not tokenizer-exact.
    """
    gate = await _shield_gate(request, await request.body(), "anthropic", "anthropic")
    if gate.response is not None:
        return gate.response
    body_bytes = gate.forward

    if gate.parse:
        try:
            raw_body = json.loads(gate.parse)
        except (ValueError, RecursionError):
            raw_body = None
        if isinstance(raw_body, dict) and raw_body.get("model") in OPENAI_COMPAT_MODELS:
            return Response(
                content=json.dumps({"input_tokens": estimate_tokens(raw_body)}),
                status_code=200,
                media_type=JSON_MEDIA_TYPE,
            )

    headers = _fwd_headers(request, gate.drop_encoding)
    upstream_url = f"{ANTHROPIC_UPSTREAM}/v1/messages/count_tokens"
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    res = await get_http_client().request(
        request.method,
        upstream_url,
        content=body_bytes if body_bytes else None,
        headers=headers,
        timeout=30.0,
    )
    if res.status_code >= 400:
        print(f"[byoai-runtime ❌ UPSTREAM {res.status_code}] count_tokens")
        print(f" └─ body: {res.content[:500]!r}")
    return Response(
        content=res.content,
        status_code=res.status_code,
        headers=clean_response_headers(dict(res.headers)),
    )


async def proxy_openai_compat_request(
    request: Request, raw_body: dict
) -> Response | StreamingResponse:
    """
    Handle a request whose model is configured to route to an OpenAI-spec
    backend instead of Anthropic. Client still sent (and expects back) the
    Anthropic Messages shape; openai_compat.py does the translation both
    ways. Anthropic-only concerns (MODEL_MAP retirement remap, cache_control
    injection) don't apply here — Anthropic's cache_control has no meaning
    once translated to an OpenAI request, and OpenAI-compatible backends
    have their own model catalog, not Anthropic's.
    """
    requested_model = raw_body.get("model", "")
    is_stream = raw_body.get("stream", False)
    session_id = derive_session_id(request, raw_body)

    # Seam B applies here too. This branch returns long before the Anthropic
    # path's enforcement point, so without this a tenant that routes a model
    # through the OpenAI-compat bridge gets no enforcement at all — silently,
    # while the console says the agent is enforced. The bridge translates the
    # upstream response INTO Anthropic shape either way, so the same enforcer
    # works unchanged on both branches below.
    enforcer = (
        resolve_enforcer(request.headers, run_id=session_id)
        if proxy_enforcement_enabled()
        else None
    )

    if not OPENAI_COMPAT_BASE_URL:
        return Response(
            content=json.dumps(
                {
                    "error": {
                        "type": "invalid_request_error",
                        "message": f"Model '{requested_model}' is configured for OpenAI-compat "
                        f"routing but BYOAI_OPENAI_COMPAT_BASE_URL is not set.",
                    }
                }
            ),
            status_code=500,
            media_type=JSON_MEDIA_TYPE,
        )

    print(
        f"[byoai-runtime 🌉 OPENAI-COMPAT] session={session_id} "
        f"model={requested_model} -> {OPENAI_COMPAT_BASE_URL}"
    )

    try:
        res = await openai_compat.forward_to_openai_compatible(
            http_client, OPENAI_COMPAT_BASE_URL, OPENAI_COMPAT_API_KEY, raw_body
        )
    except httpx.HTTPError as e:
        print(f"[byoai-runtime ❌ OPENAI-COMPAT ERROR] session={session_id}: {e}")
        return Response(
            content=json.dumps(
                {
                    "error": {
                        "type": "api_error",
                        "message": f"Upstream OpenAI-compat backend unreachable: {e}",
                    }
                }
            ),
            status_code=502,
            media_type=JSON_MEDIA_TYPE,
        )

    if res.status_code >= 400:
        body_preview = res.content if not is_stream else b"<streamed>"
        print(f"[byoai-runtime ❌ UPSTREAM {res.status_code}] openai-compat session={session_id}")
        print(f" └─ body: {body_preview[:1000]!r}")
        return Response(
            content=res.content if not is_stream else b"",
            status_code=res.status_code,
            media_type=JSON_MEDIA_TYPE,
        )

    if is_stream:

        async def openai_line_iter():
            buffer = ""
            async for chunk in res.aiter_bytes():
                buffer += chunk.decode("utf-8", errors="ignore")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if line:
                        yield line

        async def stream_translated():
            sse_enforcer = SseEnforcer(enforcer) if enforcer is not None else None
            try:
                async for anthropic_chunk in openai_compat.translate_openai_stream_to_anthropic_sse(
                    openai_line_iter(), requested_model, raw_body.get("stop_sequences")
                ):
                    if sse_enforcer is None:
                        yield anthropic_chunk
                    else:
                        gated = sse_enforcer.feed(anthropic_chunk)
                        if gated:
                            yield gated
                if sse_enforcer is not None:
                    tail = sse_enforcer.close()
                    if tail:
                        yield tail
            finally:
                await res.aclose()

        return StreamingResponse(
            stream_translated(), status_code=200, media_type="text/event-stream"
        )
    else:
        try:
            openai_resp = json.loads(res.content)
        except json.JSONDecodeError:
            return Response(content=res.content, status_code=502, media_type=JSON_MEDIA_TYPE)
        anthropic_resp = openai_compat.openai_to_anthropic_response(
            openai_resp, requested_model, raw_body.get("stop_sequences")
        )
        if enforcer is not None:
            anthropic_resp, _changed = enforce_response_body(anthropic_resp, enforcer)
        log_usage(session_id, anthropic_resp.get("usage"))
        _fire_and_forget(
            db.record_usage_event(
                session_id, "openai_compat", requested_model, anthropic_resp.get("usage")
            )
        )
        return Response(
            content=json.dumps(anthropic_resp), status_code=200, media_type=JSON_MEDIA_TYPE
        )


async def _apply_optimizer(
    raw_body: dict, session_id: str, is_enabled: bool
) -> tuple[dict, bool, dict | None]:
    """
    Run (or skip) the context optimizer for one request, and decide whether
    it's sampled for tokenizer-verified benchmarking.

    Returns (body, is_benchmark_sample, pre_optimize_snapshot). `body` is
    `raw_body` unchanged when the optimizer is off, or the SessionDedup stage's
    mutated-in-place result when it's on.
    """
    # Snapshot BEFORE the dedup stage runs — it mutates the body's nested
    # blocks in place, so by the time it returns, the "original" is already
    # gone. Only pay the deepcopy cost when this request is actually
    # sampled for benchmarking.
    # random() picks whether this request gets sampled for benchmarking —
    # not security-sensitive, so the default PRNG is fine here.
    is_benchmark_sample = (
        is_enabled and BENCHMARK_SAMPLE_RATE > 0 and random.random() < BENCHMARK_SAMPLE_RATE
    )  # noqa: S311
    pre_optimize_snapshot = copy.deepcopy(raw_body) if is_benchmark_sample else None

    if not is_enabled:
        print("\n[byoai-runtime 🔴 OPTIMIZER OFF - Direct Pass-Through]\n")
        return raw_body, is_benchmark_sample, pre_optimize_snapshot

    body, orig_tok, opt_tok = await _session_dedup_stage.optimize(raw_body, session_id)
    saved_tok = max(0, orig_tok - opt_tok)

    await safe_redis_incrby("byoai:stats:tokens_original", orig_tok)
    await safe_redis_incrby("byoai:stats:tokens_sent", opt_tok)
    await safe_redis_incrby(REDIS_KEY_TOKENS_SAVED, saved_tok)

    cum_saved = await safe_redis_get(REDIS_KEY_TOKENS_SAVED, default="0")
    pct_saved = (saved_tok / orig_tok * 100) if orig_tok > 0 else 0

    print(f"\n[byoai-runtime ⚡ OPTIMIZER ON] session={session_id}")
    print(f" ├─ Payload: {orig_tok:,} tok  ➔  {opt_tok:,} tok (estimate)")
    print(
        f" ├─ Turn Savings: {saved_tok:,} tok ({pct_saved:.1f}%) "
        "(estimate — see /v1/stats/benchmark for tokenizer-verified numbers)"
    )
    print(f" └─ Lifetime Saved: {int(cum_saved):,} tokens (estimate)\n")

    return body, is_benchmark_sample, pre_optimize_snapshot


async def _maybe_run_benchmark_sample(
    is_benchmark_sample: bool,
    pre_optimize_snapshot: dict | None,
    body: dict,
    headers: dict,
    session_id: str,
    requested_model: str,
) -> None:
    """
    For a request sampled for benchmarking, ask Anthropic's real tokenizer
    (via /v1/messages/count_tokens) for the pre- and post-optimization token
    counts, update the running stats, and persist a durable sample row.
    """
    if not is_benchmark_sample:
        return

    count_token_headers = {
        k: v
        for k, v in headers.items()
        if k.lower()
        in ("x-api-key", "authorization", "anthropic-version", "anthropic-beta", "content-type")
    }
    count_token_headers.setdefault("content-type", JSON_MEDIA_TYPE)
    real_orig, real_opt = await asyncio.gather(
        real_token_count(count_token_headers, pre_optimize_snapshot),
        real_token_count(count_token_headers, body),
    )
    if real_orig is None or real_opt is None:
        print(
            "[byoai-runtime 🔬 BENCHMARK] sample discarded — count_tokens "
            "call failed, not counted toward stats\n"
        )
        return

    real_saved = max(0, real_orig - real_opt)
    real_pct = (real_saved / real_orig * 100) if real_orig > 0 else 0.0
    await safe_redis_incrby("byoai:stats:real_tokens_original", real_orig)
    await safe_redis_incrby("byoai:stats:real_tokens_sent", real_opt)
    await safe_redis_incrby("byoai:stats:real_tokens_saved", real_saved)
    await safe_redis_incrby("byoai:stats:real_sample_count", 1)
    # Fire-and-forget: the durable SQLite row is the permanent record; don't
    # make the live response wait on a disk write.
    _fire_and_forget(
        db.record_benchmark_sample(
            session_id, body.get("model", requested_model), real_orig, real_opt, real_saved
        )
    )
    print("[byoai-runtime 🔬 REAL BENCHMARK — Anthropic tokenizer, not an estimate]")
    print(
        f" ├─ real_orig={real_orig:,}  real_opt={real_opt:,}  "
        f"real_saved={real_saved:,} ({real_pct:.1f}%)"
    )
    print(
        f" └─ via /v1/messages/count_tokens (not billed as a completion) "
        f"— persisted to {db.DB_PATH}\n"
    )


@app.api_route("/v1/messages", methods=["GET", "POST"])
async def proxy_claude_messages(request: Request):
    gate = await _shield_gate(request, await request.body(), "anthropic", "anthropic")
    if gate.response is not None:
        return gate.response
    body_bytes = gate.parse

    if not body_bytes or request.method == "GET":
        return Response(
            content=json.dumps({"status": "ok", "message": "byoai-runtime proxy active"}),
            status_code=200,
            media_type=JSON_MEDIA_TYPE,
        )

    try:
        raw_body = json.loads(body_bytes)
        if not isinstance(raw_body, dict):
            raise ValueError
    except (ValueError, RecursionError):
        return Response(
            content=json.dumps(
                {"error": {"type": "invalid_request_error", "message": "Invalid JSON payload"}}
            ),
            status_code=400,
            media_type=JSON_MEDIA_TYPE,
        )

    requested_model = raw_body.get("model", "")

    if requested_model in OPENAI_COMPAT_MODELS:
        return await proxy_openai_compat_request(request, raw_body)

    if requested_model in MODEL_MAP:
        remapped = MODEL_MAP[requested_model]
        raw_body["model"] = remapped
        print(f"[byoai-runtime 🔄 REMAP] '{requested_model}' ➔ '{remapped}'")

    had_cache_control_already = _stage_count_cache_control_markers(raw_body) > 0
    raw_body = PromptCacheInjection.inject(raw_body)
    if not had_cache_control_already and _stage_count_cache_control_markers(raw_body) > 0:
        print("[byoai-runtime 📌 CACHE] Injected cache_control breakpoint(s) — client sent none.")

    # NOTE: if this upstream traffic uses prompt caching (cache_control
    # breakpoints — including the ones we may have just injected above),
    # mutating cached blocks below busts the cache for everything after
    # that point in the prompt on every call. The SessionDedup stage only
    # touches tool_result/text blocks inside individual user messages, not
    # the system/tools blocks we cache here, so the two don't conflict —
    # but keep that boundary in mind if SessionDedup is ever extended.
    is_enabled = (await safe_redis_get(REDIS_KEY_ENABLED, default="1")) != "0"
    session_id = derive_session_id(request, raw_body)
    body, is_benchmark_sample, pre_optimize_snapshot = await _apply_optimizer(
        raw_body, session_id, is_enabled
    )

    # This route sends its own re-serialised JSON, so a request the guard read
    # (and possibly decoded) must not keep the client's Content-Encoding.
    headers = _fwd_headers(request, gate.active)

    await _maybe_run_benchmark_sample(
        is_benchmark_sample, pre_optimize_snapshot, body, headers, session_id, requested_model
    )

    upstream_url = f"{ANTHROPIC_UPSTREAM}/v1/messages"
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    is_stream = body.get("stream", False)
    log_session_id = derive_session_id(request, body)
    trace_id, span_id, parent_span_id, continues_from = derive_trace_context(request)

    # Seam B. The latch bucket is the session, not the request: a model that
    # is refused a tool and asks again next turn arrives as a fresh HTTP call,
    # and a per-request bucket would make every repeat look like a first try.
    enforcer = (
        resolve_enforcer(request.headers, run_id=log_session_id)
        if proxy_enforcement_enabled()
        else None
    )

    recorder = get_recorder()
    if recorder is not None:
        try:
            recorder.record_request_body(
                body,
                session_id=log_session_id,
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_span_id,
                continues_from=continues_from,
            )
        except LedgerWriteError as e:
            return _recorder_write_failed_response(e)

    if is_stream:
        req = get_http_client().build_request("POST", upstream_url, json=body, headers=headers)
        try:
            res = await get_http_client().send(req, stream=True)
        except httpx.HTTPError as e:
            print(f"[byoai-runtime ❌ CONNECT {type(e).__name__}] session={log_session_id}: {e}")
            return Response(
                content=json.dumps(
                    {
                        "error": {
                            "type": "api_error",
                            "message": f"byoai-runtime: could not reach upstream: {e}",
                        }
                    }
                ),
                status_code=502,
                media_type=JSON_MEDIA_TYPE,
            )

        async def stream_and_close():
            # SSE events are separated by a blank line ("\n\n"). Anthropic
            # sends usage (incl. cache_read/cache_creation) split across
            # message_start (initial usage) and message_delta (final
            # output_tokens) events, so we buffer decoded text across
            # chunks and parse complete events without altering the bytes
            # we forward downstream.
            buffer = ""
            usage_seen = {}
            stream_error = None
            stream_extractor = (
                recorder.new_stream_extractor(
                    session_id=log_session_id,
                    model=body.get("model"),
                    trace_id=trace_id,
                    span_id=span_id,
                    parent_span_id=parent_span_id,
                    continues_from=continues_from,
                )
                if recorder is not None
                else None
            )
            sse_enforcer = SseEnforcer(enforcer) if enforcer is not None else None
            try:
                async for chunk in res.aiter_bytes():
                    if sse_enforcer is None:
                        yield chunk
                    else:
                        # Only the frames of an in-flight tool_use block (and
                        # at most one partial frame) are held back; text
                        # frames go out in the same pass they arrived.
                        gated = sse_enforcer.feed(chunk)
                        if gated:
                            yield gated
                    if stream_extractor is not None and recorder is not None:
                        try:
                            recorder.feed_stream_chunk(stream_extractor, chunk)
                        except LedgerWriteError as ledger_exc:
                            # Bytes are already on the wire — there's no 503
                            # to give mid-stream, so strict_mode's failure
                            # posture degrades to log-and-continue here
                            # instead of crashing the response.
                            print(
                                f"[byoai-runtime ❌ RECORDER {type(ledger_exc).__name__}] "
                                f"ledger write failed mid-stream: {ledger_exc}"
                            )
                    try:
                        buffer += chunk.decode("utf-8", errors="ignore")
                    except Exception:
                        continue
                    while "\n\n" in buffer:
                        event, buffer = buffer.split("\n\n", 1)
                        for line in event.split("\n"):
                            if not line.startswith("data:"):
                                continue
                            try:
                                payload = json.loads(line[len("data:") :].strip())
                            except json.JSONDecodeError:
                                continue
                            msg_usage = payload.get("message", {}).get("usage") or payload.get(
                                "usage"
                            )
                            if msg_usage:
                                usage_seen.update(
                                    {k: v for k, v in msg_usage.items() if v is not None}
                                )
                if sse_enforcer is not None:
                    tail = sse_enforcer.close()
                    if tail:
                        yield tail
            except (
                httpx.ReadTimeout,
                httpx.ConnectTimeout,
                httpx.RemoteProtocolError,
                httpx.ConnectError,
            ) as e:
                # Upstream connection dropped/stalled mid-stream. Don't let
                # this crash the ASGI response (that's what was happening
                # before — an unhandled httpx.ReadTimeout propagating up
                # through StreamingResponse). Emit a well-formed SSE error
                # event so the client sees a clean failure instead of a
                # truncated stream with no explanation, then stop iterating.
                stream_error = e
                print(f"[byoai-runtime ❌ STREAM {type(e).__name__}] session={log_session_id}: {e}")
                error_event = {
                    "type": "error",
                    "error": {
                        "type": "api_error",
                        "message": (
                            f"byoai-runtime: upstream connection "
                            f"{type(e).__name__} mid-stream: {e}"
                        ),
                    },
                }
                yield f"event: error\ndata: {json.dumps(error_event)}\n\n".encode()
            finally:
                await res.aclose()
                if recorder is not None and stream_extractor is not None:
                    try:
                        recorder.close_stream_extractor(stream_extractor)
                    except LedgerWriteError as ledger_exc:
                        print(
                            f"[byoai-runtime ❌ RECORDER {type(ledger_exc).__name__}] "
                            f"ledger write failed closing stream extractor: {ledger_exc}"
                        )
                # NOTE: do not close http_client here — it's the shared,
                # long-lived pooled client reused across every request.
                if usage_seen:
                    log_usage(log_session_id, usage_seen)
                    _fire_and_forget(
                        db.record_usage_event(
                            log_session_id, "anthropic", body.get("model"), usage_seen
                        )
                    )
                if not stream_error and res.status_code >= 400:
                    print(f"[byoai-runtime ❌ UPSTREAM {res.status_code}] session={log_session_id}")
                    print(
                        f" └─ retry-after={dict(res.headers).get('retry-after', 'n/a')}  "
                        "(see client for error body; streamed responses aren't buffered here)"
                    )

        return StreamingResponse(
            stream_and_close(),
            status_code=res.status_code,
            headers=clean_response_headers(dict(res.headers)),
        )
    else:
        try:
            res = await get_http_client().post(
                upstream_url,
                json=body,
                headers=headers,
            )
        except httpx.HTTPError as e:
            print(f"[byoai-runtime ❌ CONNECT {type(e).__name__}] session={log_session_id}: {e}")
            return Response(
                content=json.dumps(
                    {
                        "error": {
                            "type": "api_error",
                            "message": f"byoai-runtime: could not reach upstream: {e}",
                        }
                    }
                ),
                status_code=502,
                media_type=JSON_MEDIA_TYPE,
            )
        if res.status_code >= 400:
            print(f"[byoai-runtime ❌ UPSTREAM {res.status_code}] session={log_session_id}")
            print(f" ├─ retry-after={res.headers.get('retry-after', 'n/a')}")
            print(f" └─ body: {res.content[:1000]!r}")
        else:
            try:
                resp_json = json.loads(res.content)
                log_usage(log_session_id, resp_json.get("usage"))
                _fire_and_forget(
                    db.record_usage_event(
                        log_session_id, "anthropic", body.get("model"), resp_json.get("usage")
                    )
                )
                if recorder is not None:
                    # Recorded before enforcement, and from the upstream body:
                    # the record is what the model actually asked for, denied
                    # blocks included. The verdict alongside it says what the
                    # agent was allowed to see.
                    recorder.record_response_body(
                        resp_json,
                        session_id=log_session_id,
                        trace_id=trace_id,
                        span_id=span_id,
                        parent_span_id=parent_span_id,
                        continues_from=continues_from,
                    )
                if enforcer is not None:
                    gated, changed = enforce_response_body(resp_json, enforcer)
                    if changed:
                        return Response(
                            content=json.dumps(gated),
                            status_code=res.status_code,
                            headers=clean_response_headers(dict(res.headers)),
                            media_type=JSON_MEDIA_TYPE,
                        )
            except (json.JSONDecodeError, AttributeError):
                pass
            except LedgerWriteError as e:
                return _recorder_write_failed_response(e)
        return Response(
            content=res.content,
            status_code=res.status_code,
            headers=clean_response_headers(dict(res.headers)),
        )


class ConfigRequest(BaseModel):
    enabled: bool


@app.get("/v1/stats")
async def get_stats():
    enabled_val = await safe_redis_get(REDIS_KEY_ENABLED, default="1")
    tokens_saved = int(await safe_redis_get(REDIS_KEY_TOKENS_SAVED, default="0"))
    tokens_orig = int(await safe_redis_get("byoai:stats:tokens_original", default="0"))
    tokens_sent = int(await safe_redis_get("byoai:stats:tokens_sent", default="0"))

    pct_saved = (tokens_saved / tokens_orig * 100) if tokens_orig > 0 else 0.0

    return {
        "optimizer_enabled": enabled_val != "0",
        "tokens_saved": tokens_saved,
        "tokens_original": tokens_orig,
        "tokens_sent": tokens_sent,
        "savings_percentage": f"{pct_saved:.2f}%",
        "methodology": "ESTIMATE ONLY — len(json.dumps(body)) // 4, "
        "a rough character-count heuristic. "
        "Not Anthropic's real tokenizer. Do not use this endpoint's numbers in external/marketing "
        "claims — use /v1/stats/benchmark instead, which is tokenizer-verified.",
    }


@app.get("/v1/stats/benchmark")
async def get_benchmark_stats():
    """
    Tokenizer-verified savings, safe to cite externally. Every number here
    comes from Anthropic's own /v1/messages/count_tokens endpoint called on
    both the pre- and post-optimization payload for a randomly sampled
    subset of real production requests — never from our own estimate.
    Empty/zero until BYOAI_BENCHMARK_SAMPLE_RATE is set above 0 and some
    sampled traffic has flowed through.
    """
    sample_count = int(await safe_redis_get("byoai:stats:real_sample_count", default="0"))
    real_orig = int(await safe_redis_get("byoai:stats:real_tokens_original", default="0"))
    real_sent = int(await safe_redis_get("byoai:stats:real_tokens_sent", default="0"))
    real_saved = int(await safe_redis_get("byoai:stats:real_tokens_saved", default="0"))
    pct = (real_saved / real_orig * 100) if real_orig > 0 else 0.0

    return {
        "sample_count": sample_count,
        "sample_rate_configured": BENCHMARK_SAMPLE_RATE,
        "real_tokens_original": real_orig,
        "real_tokens_sent": real_sent,
        "real_tokens_saved": real_saved,
        "real_savings_percentage": f"{pct:.2f}%",
        "methodology": "Each sampled request's raw and optimized payload "
        "were independently submitted to "
        "Anthropic's own /v1/messages/count_tokens endpoint (a real tokenizer call, not billed "
        "as a completion) and compared. This measures payload-size reduction only.",
        "scope_note": "This does NOT include prompt-cache savings, which are "
        "typically the larger cost lever "
        "and are tracked separately per-request in the console log (cache_read/cache_write), not "
        "aggregated here yet.",
        "sample_size_caveat": "Treat this as directional until sample_count "
        "is reasonably large (dozens+ of "
        "sampled requests spanning varied payload sizes) before citing externally.",
    }


@app.get("/v1/stats/permanent")
async def get_permanent_stats():
    """
    Same measurement as /v1/stats/benchmark, but read directly from the
    durable SQLite log instead of Redis counters. This is the number to
    trust if Redis has ever been restarted or flushed since you started
    sampling — Redis counters reset to zero silently on that; this table
    doesn't. Use this as the source of truth; /v1/stats/benchmark is a
    faster read of (hopefully) the same numbers.

    Bounded, not unlimited: rows older than BYOAI_RETENTION_DAYS (default 90)
    are pruned on each proxy start, so these totals cover the retention window
    rather than all time. The response reports the window the last prune
    actually enforced in `retention_days` (null if none has run, meaning the
    totals are all-time) — set BYOAI_RETENTION_DAYS to 0 to keep everything.
    """
    bench = await db.benchmark_summary()
    usage = await db.usage_summary()
    real_orig = bench["real_tokens_original"]
    real_saved = bench["real_tokens_saved"]
    pct = (real_saved / real_orig * 100) if real_orig > 0 else 0.0

    return {
        "storage": db.DB_PATH,
        "benchmark": {
            "sample_count": bench["sample_count"],
            "real_tokens_original": real_orig,
            "real_tokens_sent": bench["real_tokens_sent"],
            "real_tokens_saved": real_saved,
            "real_savings_percentage": f"{pct:.2f}%",
        },
        "usage_totals": usage,
        # Surfaced in the response so a caller reading these totals can see the
        # window they cover, instead of assuming they are all-time. This is the
        # window the last prune actually enforced, not the current env var —
        # editing BYOAI_RETENTION_DAYS without a restart changes what the *next*
        # prune will do, not what this table already contains. null means no
        # prune has run in this process, so the totals are all-time.
        "retention_days": db.enforced_retention_days(),
        "methodology": "Identical measurement methodology to "
        "/v1/stats/benchmark (Anthropic's real tokenizer via "
        "count_tokens), but persisted to disk on every sample rather than kept only in Redis — "
        "survives restarts, Redis flushes, and infrastructure changes. Covers the last "
        "retention_days days (0 = all time); older rows are pruned on proxy start.",
    }


@app.get("/v1/stats/history")
async def get_benchmark_history(limit: int = 50):
    """Individual benchmark data points, most recent first — useful for
    eyeballing variance across samples before trusting an aggregate
    percentage (a single unusually large or small payload can skew an
    average built from only a handful of samples)."""
    samples = await db.recent_benchmark_samples(limit=min(limit, 500))
    return {"count": len(samples), "samples": samples}


@app.post("/v1/config")
async def set_config(config: ConfigRequest):
    val = "1" if config.enabled else "0"
    try:
        await r.set(REDIS_KEY_ENABLED, val)
    except Exception:
        pass
    return {
        "status": "success",
        "optimizer_enabled": config.enabled,
        "message": f"Optimizer is now {'ON' if config.enabled else 'OFF'}",
    }


@app.post("/v1/toggle")
async def toggle_config():
    current = await safe_redis_get(REDIS_KEY_ENABLED, default="1")
    new_val = "0" if current != "0" else "1"
    try:
        await r.set(REDIS_KEY_ENABLED, new_val)
    except Exception:
        pass
    is_on = new_val == "1"
    return {
        "status": "success",
        "optimizer_enabled": is_on,
        "message": f"Optimizer toggled {'ON' if is_on else 'OFF'}",
    }


# --------------------------------------------------------------------------
# Console SPA
# --------------------------------------------------------------------------
# Registered before the /v1 catch-all purely for readability — /console/* and
# /v1/* can't collide — but it does have to sit after "/" so the root JSON
# landing response is untouched. The console is deliberately NOT in
# _AUTH_EXEMPT_PATHS: when BYOAI_PROXY_TOKEN is set, the UI is unreachable for
# exactly the same requests the API is unreachable for.


# The data the console reads. Mounted here rather than in its own service so
# one `pip install` and one port serve both the API and the UI over it.
#
# The store is opened lazily and read-only: a deployment with no ingest
# database yet gets an empty fleet, which is the truthful answer, rather than
# a failure to start.
_INGEST_DB = os.environ.get(
    "BYOAI_INGEST_DB", os.path.join(os.path.expanduser("~"), ".byoai", "ingest.db")
)
# The one org the console serves; set below once the ingest store opens.
_console_org = os.environ.get("BYOAI_CONSOLE_ORG", "").strip() or "default"

try:
    from byoai.console import build_console_router
    from byoai.ingest import IngestStore

    _ingest_store = IngestStore(_INGEST_DB)
    # Single-org: the public
    # console serves exactly one org, matching the free Shield server — a
    # many-org view is Coriqo's paid MSP console. `BYOAI_CONSOLE_ORG` picks
    # it explicitly; otherwise default to whichever tenant is already in this
    # store (an existing single-org install upgrades with no config change),
    # falling back to "default" — the same default `byoai-shield-server`
    # uses — for a store that has no tenant yet.
    _console_org = (
        os.environ.get("BYOAI_CONSOLE_ORG", "").strip()
        or _ingest_store.default_tenant_slug()
        or "default"
    )
    app.include_router(build_console_router(_ingest_store, org=_console_org))
except Exception as exc:  # pragma: no cover - defensive
    # The proxy's own job does not depend on the console API, so a failure to
    # open the ingest store must not stop token caching from serving. Say so
    # loudly rather than leaving a silently absent route — an earlier version
    # printed to a `sys` that is not imported at module scope, which turned a
    # diagnostic into a second, quieter failure.
    import sys as _sys
    import traceback as _tb

    print(f"[byoai] console API unavailable ({_INGEST_DB}): {exc!r}", file=_sys.stderr)
    _tb.print_exc(file=_sys.stderr)


@app.api_route("/console", methods=["GET", "HEAD"])
async def console_root_redirect():
    # The built assets use base "/console/", so relative URLs only resolve from
    # the trailing-slash form. Redirect rather than serve index.html here.
    return RedirectResponse(url="/console/", status_code=307)


@app.api_route("/console/{path:path}", methods=["GET", "HEAD"])
async def console_spa(path: str):
    """Serve the built console, falling back to index.html for client routes.

    Anything that isn't a real file is answered with index.html so a hard
    refresh on a deep route like /console/acme/fleet/coverage still boots the
    SPA, which then resolves the route itself.
    """
    if path == "":
        # Single-org: land on the org this proxy serves, not the build-time
        # default baked into the SPA.
        return RedirectResponse(url=f"/console/{_console_org}/fleet", status_code=307)
    if console_assets.env_flag_disabled():
        return Response(
            content="The ByoAI console is disabled (BYOAI_CONSOLE=0).\n",
            status_code=404,
            media_type="text/plain; charset=utf-8",
        )
    if not console_assets.assets_available():
        # 503, not 404: the route exists and the deployment is simply missing a
        # build step. Say which command produces it instead of implying the URL
        # is wrong.
        return Response(
            content=console_assets.MISSING_BUILD_MESSAGE,
            status_code=503,
            media_type="text/plain; charset=utf-8",
        )
    asset = console_assets.resolve_asset(path)
    if asset is not None:
        return FileResponse(asset, headers=console_assets.cache_headers(path))
    return FileResponse(
        console_assets.INDEX_FILE,
        headers=console_assets.cache_headers("index.html"),
    )


@app.post("/v1/chat/completions")
@app.post("/v1/responses")
async def proxy_openai_guarded(request: Request):
    """OpenAI-shaped chat requests, checked by Shield's rules before they go on.

    With BYOAI_SHIELD_GUARD off (the default) this is the old behaviour: the
    generic passthrough below. Otherwise the request is checked, then sent to
    BYOAI_SHIELD_OPENAI_UPSTREAM (default https://api.openai.com) and the reply
    is streamed back as it arrives."""
    path = request.url.path.strip("/").lower()[len("v1/"):]
    if shield_gw.mode() == "off":
        return await proxy_catch_all(request, path)
    gate = await _shield_gate(request, await request.body(), "openai", "openai")
    if gate.response is not None:
        return gate.response
    body_bytes = gate.forward
    headers = _fwd_headers(request, gate.drop_encoding)
    if gate.drop_encoding:
        headers["content-type"] = "application/json"
    url = f"{shield_gw.openai_upstream()}/v1/{path}"
    if request.url.query:
        url = f"{url}?{request.url.query}"
    client = get_http_client()
    req = client.build_request("POST", url, content=body_bytes, headers=headers)
    try:
        res = await client.send(req, stream=True)
    except httpx.HTTPError as e:
        return Response(
            content=json.dumps({"error": {
                "message": f"byoai-runtime: could not reach upstream: {e}",
                "type": "api_error", "code": "upstream_unreachable"}}),
            status_code=502, media_type=JSON_MEDIA_TYPE)

    async def relay():
        try:
            async for chunk in res.aiter_bytes():
                yield chunk
        finally:
            await res.aclose()

    return StreamingResponse(relay(), status_code=res.status_code,
                             headers=clean_response_headers(dict(res.headers)))


@app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy_catch_all(request: Request, path: str):
    """
    Generic fallback for any other Anthropic /v1/* endpoint (models list,
    batches, files, etc.) that this proxy doesn't have bespoke logic for.
    Without this, any endpoint the client calls that we haven't explicitly
    wired up 404s locally instead of reaching Anthropic at all — which is
    exactly what happened with count_tokens before it got its own route.

    MUST stay the last route defined in this file: FastAPI/Starlette
    matches routes in registration order, and this path pattern (/v1/*)
    would otherwise shadow every specific route above it (/v1/messages,
    /v1/messages/count_tokens, /v1/stats, /v1/config, /v1/toggle).
    """
    norm = path.strip("/").lower()
    if shield_gw.mode() != "off" and request.method == "POST":
        # Trailing-slash and case variants of the guarded routes take the same road.
        if norm in shield_gw.OPENAI_PATHS:
            return await proxy_openai_guarded(request)
        if norm == "messages":
            return await proxy_claude_messages(request)
        if norm == "messages/count_tokens":
            return await proxy_count_tokens(request)
    gate = await _shield_gate(request, await request.body(), "anthropic", "anthropic")
    if gate.response is not None:
        return gate.response
    body_bytes = gate.forward
    headers = _fwd_headers(request, gate.drop_encoding)
    upstream_url = f"{ANTHROPIC_UPSTREAM}/v1/{path}"
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    res = await get_http_client().request(
        request.method,
        upstream_url,
        content=body_bytes if body_bytes else None,
        headers=headers,
        timeout=60.0,
    )
    if res.status_code >= 400:
        print(f"[byoai-runtime ❌ UPSTREAM {res.status_code}] passthrough /v1/{path}")
        print(f" └─ body: {res.content[:500]!r}")
    return Response(
        content=res.content,
        status_code=res.status_code,
        headers=clean_response_headers(dict(res.headers)),
    )


# --------------------------------------------------------------------------
# CLI: foreground server + background start/stop/status
# --------------------------------------------------------------------------

# Runtime files live alongside the durable SQLite log under ~/.byoai/ so a
# developer has one predictable place for the proxy's state, pid, and logs.
_BYOAI_HOME = os.path.join(os.path.expanduser("~"), ".byoai")
_PID_FILE = os.path.join(_BYOAI_HOME, "proxy.pid")
# The bind the running proxy actually used. Without this, `status` and
# `console` printed a URL derived from the CURRENT invocation's flags — so
# `byoai-cache start --port 9000` followed by a bare `byoai-cache console`
# handed you http://localhost:8787/console/, which is nothing. The command
# whose whole job is giving you the URL must read where the proxy is, not
# where this invocation would have put one.
_BIND_FILE = os.path.join(_BYOAI_HOME, "proxy.bind")
_LOG_FILE = os.path.join(_BYOAI_HOME, "proxy.log")


def _resolve_host_port(args) -> tuple[str, int]:
    # getattr: the bare `byoai-cache` (no subcommand) namespace has no host/port
    # attributes since those flags live on the subparsers.
    host = getattr(args, "host", None) or os.getenv("BYOAI_HOST", "0.0.0.0")
    arg_port = getattr(args, "port", None)
    port = arg_port if arg_port is not None else int(os.getenv("BYOAI_PORT", "8787"))
    return host, port


def _display_url(host: str, port: int) -> str:
    # 0.0.0.0 / :: mean "all interfaces" — not a usable address to click, so
    # show localhost, which is where a developer actually reaches it.
    shown = "localhost" if host in ("0.0.0.0", "::", "") else host
    return f"http://{shown}:{port}"


def run(host: str = "0.0.0.0", port: int = 8787) -> None:
    """Run the proxy in the foreground (blocks). Shared by the default command
    and the detached child spawned by ``start``."""
    import uvicorn

    uvicorn.run(app, host=host, port=port)


def _read_pid() -> int | None:
    try:
        with open(_PID_FILE) as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # signal 0 only checks existence/permission, doesn't kill
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists but owned by another user
    return True


def _running_pid() -> int | None:
    """The pid of a live proxy per the pidfile, cleaning up a stale file."""
    pid = _read_pid()
    if pid is None:
        return None
    if _pid_alive(pid):
        return pid
    # Stale pidfile from a crash/kill -9 — remove it so `start` can proceed.
    try:
        os.remove(_PID_FILE)
    except FileNotFoundError:
        pass
    # Outside the try: sharing one block meant an already-missing pidfile
    # jumped past this and left proxy.bind on disk, so a later status read a
    # bind for an address nothing was listening on — the exact staleness this
    # call exists to prevent. _forget_bind swallows its own OSError.
    _forget_bind()
    return None


def _forget_bind() -> None:
    """Drop the recorded bind. A stopped proxy must not leave a file behind
    asserting an address nothing is listening on."""
    try:
        os.remove(_BIND_FILE)
    except OSError:
        pass


def _running_bind(args) -> tuple[str, int]:
    """Where the running proxy is, falling back to what this invocation implies.

    The fallback matters when the bind file is missing — an older background
    proxy started before this file existed, or one started by hand. Reporting
    the flag-derived guess is still better than reporting nothing, but the
    recorded value wins whenever it exists.
    """
    try:
        with open(_BIND_FILE) as f:
            host, _, port = f.read().strip().rpartition(":")
        if host and port:
            return host, int(port)
    except (OSError, ValueError):
        pass
    return _resolve_host_port(args)


def _cmd_start(args) -> int:
    import subprocess
    import sys

    existing = _running_pid()
    if existing is not None:
        host, port = _running_bind(args)
        print(f"already running (pid {existing}) → {_display_url(host, port)}")
        return 0

    os.makedirs(_BYOAI_HOME, exist_ok=True)
    host, port = _resolve_host_port(args)
    logf = open(_LOG_FILE, "a")
    # Re-invoke ourselves in the foreground as a detached session leader:
    # start_new_session=True gives the child its own session with no
    # controlling terminal, so it survives the parent shell closing. stdin is
    # detached; stdout/stderr stream to the log file.
    proc = subprocess.Popen(
        [sys.executable, "-m", "byoai.agent_context_cache.main",
         "serve", "--host", host, "--port", str(port)],
        stdin=subprocess.DEVNULL,
        stdout=logf,
        stderr=logf,
        start_new_session=True,
    )
    # Bind first, pid second. The pid file is what every other command tests
    # for liveness, so writing it last makes "a pid exists" imply "a bind
    # exists". The other order left a window where a concurrent status saw a
    # live pid, found no bind, and fell back to its own flags — printing the
    # wrong URL, which is the bug this file records the bind to prevent.
    with open(_BIND_FILE, "w") as f:
        f.write(f"{host}:{port}")
    with open(_PID_FILE, "w") as f:
        f.write(str(proc.pid))
    print(f"proxy running (pid {proc.pid}) → {_display_url(host, port)}")
    print(f"logs: {_LOG_FILE}")
    print("stop with: byoai-cache stop")
    return 0


def _cmd_console(args) -> int:
    """Thin wrapper over ``start``: same background proxy, plus the console URL.

    The console is served by the proxy itself, so there is no second process to
    manage — ``byoai-cache stop`` stops this too."""
    rc = _cmd_start(args)
    if rc != 0:
        return rc
    host, port = _running_bind(args)
    print(f"console: {console_assets.console_url(_display_url(host, port))}")
    if not console_assets.assets_available():
        # Say it here rather than letting the user discover a 503 in the
        # browser — this is the command whose entire job is the console.
        print("warning: the console has not been built; /console/ will explain how.")
        print(f"  build it with: {console_assets.BUILD_COMMAND}")
    return rc


def _cmd_stop(args) -> int:
    import signal
    import time

    pid = _running_pid()
    if pid is None:
        # Nothing to signal, but a bind file may still be sitting here from a
        # proxy that died without cleaning up. Clearing it is the point of
        # this branch: leaving it lets a later `status` resolve an address
        # nothing is listening on, moments after this command said "not
        # running".
        _forget_bind()
        print("not running")
        return 0
    os.kill(pid, signal.SIGTERM)
    # Give uvicorn a moment to shut down gracefully, then escalate.
    for _ in range(50):  # up to ~5s
        if not _pid_alive(pid):
            break
        time.sleep(0.1)
    else:
        os.kill(pid, signal.SIGKILL)
    try:
        os.remove(_PID_FILE)
    except FileNotFoundError:
        pass
    # Outside the try: sharing one block meant an already-missing pidfile
    # jumped past this and left proxy.bind on disk, so a later status read a
    # bind for an address nothing was listening on — the exact staleness this
    # call exists to prevent. _forget_bind swallows its own OSError.
    _forget_bind()
    print("stopped")
    return 0


def _cmd_status(args) -> int:
    pid = _running_pid()
    if pid is None:
        print("stopped")
        return 1
    host, port = _running_bind(args)
    print(f"running (pid {pid}) → {_display_url(host, port)}")
    return 0


def _cmd_prune(args) -> int:
    async def _run():
        await db.init_db()  # a prune before the proxy's first run shouldn't error
        return await db.prune(args.days, vacuum=not args.no_vacuum)

    result = asyncio.run(_run())
    if result.get("error"):
        print(f"prune failed: {result['error']}")
        return 1
    if result.get("skipped"):
        print("retention disabled (BYOAI_RETENTION_DAYS=0) — nothing pruned")
        return 0
    size_mb = result.get("size_bytes", 0) / (1024 * 1024)
    print(
        f"pruned {result['deleted_rows']} rows older than {result['retention_days']}d"
        + (" (vacuumed)" if result.get("vacuumed") else "")
        + f" → {db.DB_PATH} is now {size_mb:.1f} MB"
    )
    if result.get("vacuum_skipped"):
        # The caller asked for a reclaim and isn't getting one. Say why, rather
        # than printing output identical to a successful vacuum.
        print(
            f"note: skipped reclaiming space — only {result['deleted_rows']} rows were "
            f"deleted (under the {db.VACUUM_MIN_DELETED_ROWS}-row threshold), and rewriting "
            f"the whole file costs more than the space it would return."
        )
    if result.get("vacuum_error"):
        # The rows are gone; only the space reclaim failed. Say so explicitly
        # so this doesn't read as "the prune didn't happen".
        print(
            f"note: rows were deleted, but reclaiming space failed "
            f"({result['vacuum_error']}). This usually means the proxy is "
            f"running — stop it and re-run, or ignore it and let future rows "
            f"reuse the freed pages."
        )
    return 0


def cli(argv: list[str] | None = None) -> int:
    """Console-script entry point.

    Default (no subcommand) runs the proxy in the foreground, matching the
    historical behavior. ``start``/``stop``/``status`` manage a detached
    background instance whose pid and logs live under ``~/.byoai/``.
    """
    import argparse

    parser = argparse.ArgumentParser(
        prog="byoai-cache",
        description="ByoAI agent context-cache proxy (Anthropic-compatible).",
    )
    # Shared --host/--port live on the subparsers only (not the top level) so a
    # value given before a subcommand can't be clobbered by the subparser's
    # default. Bare `byoai-cache` reads host/port from the environment.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--host", help="bind address (env BYOAI_HOST, default 0.0.0.0)")
    common.add_argument("--port", type=int, help="port (env BYOAI_PORT, default 8787)")

    sub = parser.add_subparsers(dest="command")
    for name, help_text in (
        ("serve", "run in the foreground (default)"),
        ("start", "start in the background (detached; survives closing the terminal)"),
        ("stop", "stop the background proxy"),
        ("status", "show whether the background proxy is running"),
        ("console", "start in the background and print the console URL"),
    ):
        sub.add_parser(name, parents=[common], help=help_text)

    # No --host/--port: prune operates on the SQLite file directly and needs no
    # running proxy. Safe to run against a live instance — WAL mode means the
    # delete doesn't block in-flight readers.
    prune_p = sub.add_parser(
        "prune",
        help="delete durable-record rows older than the retention window",
    )
    prune_p.add_argument(
        "--days",
        type=int,
        help=f"retention window (env BYOAI_RETENTION_DAYS, default {db.DEFAULT_RETENTION_DAYS})",
    )
    prune_p.add_argument(
        "--no-vacuum",
        action="store_true",
        help="skip reclaiming file space (VACUUM rewrites the whole DB)",
    )

    args = parser.parse_args(argv)

    if args.command in (None, "serve"):
        host, port = _resolve_host_port(args)
        run(host, port)
        return 0
    if args.command == "start":
        return _cmd_start(args)
    if args.command == "console":
        return _cmd_console(args)
    if args.command == "stop":
        return _cmd_stop(args)
    if args.command == "status":
        return _cmd_status(args)
    if args.command == "prune":
        return _cmd_prune(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(cli())
