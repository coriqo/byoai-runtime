# ByoAI Runtime

> **Bring Your Own Infrastructure (BYOI). ByoAI Brings the Runtime.**

ByoAI Runtime is an infrastructure-agnostic AI agent engine and workflow execution layer for
Python. It connects directly to your existing Redis clusters, vector databases (pgvector,
Qdrant, Pinecone), LLMs (OpenAI-compatible, Anthropic, Gemini), and telemetry pipelines
**without requiring data migrations, vector re-indexing, database schema alterations, or vendor
lock-in.**

## Why ByoAI Runtime?

Most AI frameworks force engineering teams to adapt their database schemas, re-embed millions of
vectors, and rewrite state management logic. **ByoAI Runtime adapts to your existing stack
instead.**

- **Zero-migration schema mapping.** A declarative `schema_map` points ByoAI at your existing
  vector tables/collections/indexes — no re-indexing, no data duplication.
- **Cross-provider AST filter parser.** Write one Mongo-style filter dialect and ByoAI compiles it
  to each backend's native form: pgvector JSONB, Qdrant filters, Pinecone metadata filters.
- **Non-invasive cache isolation.** Runtime writes stay under an isolated `byoai:` namespace; a
  read-only `session_reader` pattern ingests chat history your app already stores.
- **Semantic (intent) caching** serves similar, not just identical, queries from cache via
  embedding similarity — in-process, or shared across workers on Redis.
- **Resilient provider routing** retries with backoff and jitter, then falls back across an
  ordered provider chain (OpenAI → Azure OpenAI → Ollama, for example).
- **Zero-SaaS OpenTelemetry tracing.** One span per execution, a child span per pipeline stage,
  OTLP export straight to a collector you already run.
- **Framework-agnostic transports.** FastAPI, Robyn, MCP, WebSocket, and background queue workers
  all speak the same execution dialect.
- **A plugin system** resolves unrecognized `provider` values for `llm=`, `cache=`, `vector_store=`,
  `embedder=`, and `semantic_cache=` through Python entry points, so a `pip install` adds a new
  adapter without touching ByoAI's code.

## Architecture

```
                          ┌──────────────────────────┐
                          │   runtime.execute()       │
                          └─────────────┬─────────────┘
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
┌──────────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│  Cache / session      │    │  Vector store +      │    │  Provider router     │
│  (Redis / in-memory)  │    │  AST filter parser    │    │  (retry / fallback)  │
└──────────┬───────────┘    └───────────┬──────────┘    └───────────┬──────────┘
           │                            │                            │
           ▼                            ▼                            ▼
   Existing Redis DB            Existing Vector DB           LLM APIs / Inference
 (no keys overwritten)       (no vector re-indexing)       (existing API keys)
```

Start with [Getting Started](getting-started.md), or jump straight to a guide:
[FastAPI](guides/fastapi.md), [Robyn](guides/robyn.md), [MCP](guides/mcp.md),
[Caching](guides/caching.md), [Semantic caching](guides/semantic-cache.md),
[Vector stores](guides/vector-stores.md), [Provider routing](guides/providers.md),
[Background workers](guides/workers.md), [Telemetry](guides/telemetry.md).

These guides cover how the pieces fit together and why. For the exact parameter reference of
every component — every constructor argument and its default — see
[CONFIGURATION.md](https://github.com/coriqo/byoai-runtime/blob/main/CONFIGURATION.md) in the
repository; it's kept as the single source of truth for exact signatures, cross-linked from the
guides rather than duplicated in them.
