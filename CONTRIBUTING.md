# Contributing to byoai-runtime

Thanks for your interest in contributing! This document covers how to get a dev environment
running, the checks your change needs to pass, and how PRs get reviewed and released.

## Development setup

```bash
git clone https://github.com/coriqo/byoai-runtime.git
cd byoai-runtime
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[all,dev]"
```

`all` pulls in every optional integration (FastAPI, Robyn, Redis, pgvector, OTel) so the full
test suite can run; `dev` adds pytest, ruff, pyright, and packaging tools.

## Design principle: bring your own function

Every extension point whose protocol has **one natural operation** must accept a bare async
function, not just a class — no boilerplate `name`/`model` attributes, no `close()` method to
stub out, nothing to subclass. A user with an existing async callable (a wrapped SDK client, an
internal gateway, a test double) should be able to hand it straight to `Runtime` and have it work.

This is already the case for:

- **Pipeline stages** — `Pipeline.add(fn)` auto-wraps a bare `async def fn(ctx)` in
  `FunctionStage`.
- **`embedder=`** — accepts any `async (str) -> list[float]` callable directly.
- **`providers=`** — accepts any `async (messages, **options) -> str | ProviderResponse`
  callable directly (auto-wrapped in `FunctionProvider`).
- **`vector_store=`** — accepts any `async (embedding, *, top_k, filters) -> list[Document]`
  callable directly (auto-wrapped in `FunctionVectorStore`).
- **Middleware** — `runtime.use(fn)` accepts a bare `async def fn(ctx, call_next)` already, since
  `MiddlewareChain` just calls whatever it's given.

If you add a new extension point with a one-operation protocol, follow the same pattern: accept
the callable directly, and auto-wrap it (`obj if hasattr(obj, "<method>") else
FunctionSomething(obj)`) at the point of construction, matching `Pipeline.add()` and
`ProviderRouter.__init__()`.

**When *not* to force this**: a protocol with several genuinely distinct operations —
`CacheStore` (`get`/`set`/`delete`/`read_session`/`close`) and `SemanticCacheStore`
(`find`/`add`/`close`) — doesn't reduce cleanly to one function, since a cache is inherently
read *and* write, not one call. Don't contort those into a single-callable shape just for
consistency; a class (or a small tuple/namespace of callables, if that ever comes up) is the
honest fit there.

## Branching

Do all work on a feature branch off `main` — never commit directly to `main`:

```bash
git checkout main && git pull
git checkout -b feat/<short-description>   # or fix/<short-description>
```

## Checks

Run these before opening a PR — CI runs the same checks on every push and PR:

```bash
ruff check .        # lint
pyright             # type check
python -m pytest    # tests (use `python -m pytest`, not bare `pytest` —
                     # the test modules import `tests.conftest`, which needs
                     # the repo root on sys.path)
```

Tests live under `tests/`, mirroring the module they cover (e.g. `src/byoai/cache/redis.py` →
`tests/test_cache_memory.py` / integration tests). New runtime behavior needs test coverage;
bug fixes should include a regression test.

## Commit messages and PRs

- Keep commits focused — one logical change per commit.
- Write commit messages that explain *why*, not just *what*.
- Update `CHANGELOG.md` under `[Unreleased]` for any user-facing change (new feature, behavior
  change, bug fix, deprecation).
- Open a PR against `main`. Fill in the PR template — link any related issue, and describe how
  you tested the change.

## AI-assisted development

This project welcomes AI-assisted contributions (code, tests, docs, debugging). Regardless of
how a change was produced:

- All contributions are reviewed by maintainers before merge.
- All code must meet the project's quality bar (lint, types, tests).
- Runtime changes require tests.
- Security-sensitive changes require human review — see [SECURITY.md](SECURITY.md).
- You remain responsible for code you submit, however it was produced.

## Code of Conduct

Participation in this project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Release process

Maintainers bump `version` in `pyproject.toml`, tag `vX.Y.Z` (matching that version exactly),
and publish a GitHub Release; the [`publish.yml`](.github/workflows/publish.yml) workflow
verifies the tag matches `pyproject.toml`, then builds and publishes to PyPI automatically.
Contributors don't need to do anything release-related beyond keeping `CHANGELOG.md` up to date.
