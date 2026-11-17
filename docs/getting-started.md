# Getting Started

## Installation

```bash
pip install byoai-runtime
```

`byoai-runtime` is a beta (`0.1.x`). The parts that are a stable contract, and the
parts that may still change, are listed in the [README](https://github.com/coriqo/byoai-runtime#what-is-stable).

Optional integrations are extras — install only what you need:

```bash
pip install "byoai-runtime[fastapi]"   # FastAPI integration
pip install "byoai-runtime[robyn]"     # Robyn integration
pip install "byoai-runtime[flask]"     # Flask (WSGI) integration
pip install "byoai-runtime[mcp]"       # MCP tool-server integration
pip install "byoai-runtime[redis]"     # Redis cache / queue / shared semantic cache
pip install "byoai-runtime[pgvector]"  # pgvector vector store
pip install "byoai-runtime[semantic]"  # in-process semantic (intent) cache
pip install "byoai-runtime[perf]"      # orjson hot-path JSON codec
pip install "byoai-runtime[otel]"      # OpenTelemetry export
pip install "byoai-runtime[bedrock]"   # Anthropic on AWS Bedrock
pip install "byoai-runtime[vertex]"    # Anthropic on Google Vertex AI
pip install "byoai-runtime[agent-context-cache]"  # the byoai-cache proxy
pip install "byoai-runtime[all]"       # everything above
```

The Qdrant and Pinecone vector stores and the Gemini provider need no extra — they're built on
the core `httpx` dependency, same as the OpenAI-compatible and Anthropic providers.

## Configuration & environment variables

Nothing is required — every setting can be passed explicitly in a config dict — but each
built-in LLM provider falls back to a conventional environment variable for its API key when you
don't pass `api_key` yourself:

| Env var | Used by |
| --- | --- |
| `OPENAI_API_KEY` | `provider: "openai"` (and any OpenAI-compatible provider/embedder that doesn't override `api_key`) |
| `ANTHROPIC_API_KEY` | `provider: "anthropic"` |
| `GEMINI_API_KEY` (or `GOOGLE_API_KEY`) | `provider: "gemini"` |
| `AZURE_OPENAI_ENDPOINT` | `provider: "azure_openai"` — fallback for `endpoint` |
| `AZURE_OPENAI_API_KEY` | `provider: "azure_openai"` — fallback for `api_key` |
| `OPENROUTER_API_KEY` | `provider: "openrouter"` |

```bash
export OPENAI_API_KEY=sk-...
```

```python
# api_key omitted — falls back to $OPENAI_API_KEY
runtime = Runtime(llm={"provider": "openai", "model": "gpt-4o"})
```

`provider: "bedrock"` and `provider: "vertex"` are the exception to "API key" above — they take
no API key at all (AWS/GCP credentials come from the standard chain / Application Default
Credentials), but their required *deployment location* also falls back to env vars:
`aws_region` from `AWS_REGION`/`AWS_DEFAULT_REGION`; `project_id`/`region` from
`ANTHROPIC_VERTEX_PROJECT_ID`/`GOOGLE_CLOUD_PROJECT` and
`ANTHROPIC_VERTEX_REGION`/`CLOUD_ML_REGION`. See [Providers: Anthropic on AWS Bedrock and Google
Vertex](guides/providers.md#anthropic-on-aws-bedrock-and-google-vertex).

Beyond these, the runtime reads no other environment variables automatically. Redis `url`,
pgvector `dsn`, Qdrant/Pinecone `url`/`host`, the OTel collector `endpoint` — all have no env-var
fallback and must be passed explicitly in the config dict. If you want those sourced from the
environment too, read them yourself (`os.environ["REDIS_URL"]`, or a `.env` file loaded with
something like [`python-dotenv`](https://pypi.org/project/python-dotenv/) — the runtime doesn't
load `.env` files on its own) and pass the values in.

## Minimal example

```python
import asyncio
from byoai import Runtime

async def main():
    runtime = Runtime(llm={"provider": "openai", "model": "gpt-4o"})
    result = await runtime.execute("What are our enterprise SLA terms?")
    print(result.content, result.usage.total_tokens, result.cached)
    await runtime.close()

asyncio.run(main())
```

`Runtime` also supports `async with` — it closes provider/cache/vector-store/embedder
connections and shuts down any tracer provider it created automatically:

```python
async with Runtime(llm={"provider": "openai", "model": "gpt-4o"}) as runtime:
    result = await runtime.execute("...")
```

## System prompts

The simplest option: pass `system_prompt=` once, at construction. `ContextResolver` prepends it
to every request that pipeline runs:

```python
runtime = Runtime(
    llm={"provider": "openai", "model": "gpt-4o"},
    system_prompt="You are a support assistant for Acme Corp. Be concise and cite sources.",
)
```

If your app already builds its own system prompt per request — a per-user persona, per-tenant
instructions, whatever you're already doing — skip `system_prompt=` at construction and pass
your message as part of `input=` instead. `execute()`/`stream()` accept a list of messages, not
just a bare string:

```python
result = await runtime.execute(
    input=[
        {"role": "system", "content": build_system_prompt(user)},  # your existing logic
        {"role": "user", "content": user_query},
    ],
)
```

Don't combine both on the same runtime: if `system_prompt=` is set at construction *and* your
`input=` also includes a `role: "system"` message, the model sees two system messages back to
back. Pick one — fixed at construction, or per-request via `input=`.

## Connecting to existing infrastructure

Every adapter is configured with a plain dict (or you can construct adapter objects yourself for
full control — see each guide). Nothing here requires a schema migration or vector re-index — a
full worked example wiring Redis, pgvector, and an OpenAI → Azure OpenAI fallback together is in
the [project README](https://github.com/coriqo/byoai-runtime#-quickstart).

For each adapter's individual configuration surface, see
[Caching](guides/caching.md), [Vector stores](guides/vector-stores.md), and
[Provider routing](guides/providers.md); the [API reference](reference/api.md) auto-generates
signatures from docstrings, and
[CONFIGURATION.md](https://github.com/coriqo/byoai-runtime/blob/main/CONFIGURATION.md) in the
repository is the authoritative parameter-by-parameter reference across every component.

## Next steps

- Drop the runtime into an existing app: [FastAPI guide](guides/fastapi.md),
  [Robyn guide](guides/robyn.md), or expose it as a tool over [MCP](guides/mcp.md).
- Run executions off the request path: [Background workers](guides/workers.md).
- Serve similar (not just identical) queries from cache: [Semantic caching](guides/semantic-cache.md).
- Add retrieval-augmented generation: [Vector stores — RAG retrieval in the
  pipeline](guides/vector-stores.md#rag-retrieval-in-the-pipeline).
- Trace executions to your existing observability stack: [Telemetry](guides/telemetry.md).
- Runnable example apps live in [`examples/`](https://github.com/coriqo/byoai-runtime/tree/main/examples)
  in the repository.
