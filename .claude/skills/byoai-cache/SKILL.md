---
name: byoai-cache
description: Start, stop, or check the local BYOAI caching proxy that sits in front of api.anthropic.com and injects prompt-cache breakpoints to cut token spend. Use when the user wants to enable/disable prompt caching for the current session, asks about token/cost savings, or mentions "byoai-cache" / "caching proxy".
---

# byoai-cache

`byoai-cache` is a local FastAPI proxy (installed as a console script by this repo's `pyproject.toml`) that sits between a client like Claude Code and `api.anthropic.com`. It injects Anthropic prompt-cache breakpoints, truncates oversized tool output, and collapses repeated large tool results within a request to reduce token spend. It never rewrites user instructions, and keeps no state between requests. Full reference: `CONFIGURATION.md` (search "byoai-cache" / "BYOAI_PROXY").

## Prerequisite

The CLI must be installed (it ships with this package):

```bash
pip install -e ".[agent-context-cache]"          # inside this repo, or
pip install "byoai-runtime[agent-context-cache]"  # from PyPI
```

Verify it's on PATH: `command -v byoai-cache`. If missing, install first — don't try to invoke `python -m ...` as a substitute; use the console script.

## Enable caching for this session

1. Check if it's already running:
   ```bash
   byoai-cache status
   ```
2. If not running, start it in the background (it detaches, writes pid to `~/.byoai/proxy.pid`, logs to `~/.byoai/proxy.log`):
   ```bash
   byoai-cache start
   ```
   If `start` fails with "address already in use", something else already owns port 8787 — usually a proxy from another session/terminal that this CLI invocation's pidfile doesn't know about. Run `curl -s http://localhost:8787/health` to confirm it's a live byoai-cache instance before reusing it; don't kill an unrecognized process on that port without checking with the user first.
3. Point the client at the proxy for the current shell/session:
   ```bash
   export ANTHROPIC_BASE_URL=http://localhost:8787
   ```
   If `BYOAI_PROXY_TOKEN` was set when the proxy was started, also export it and pass it as the `x-byoai-proxy-token` header (or leading URL path segment) — see `CONFIGURATION.md` for the exact gate behavior.

Only export `ANTHROPIC_BASE_URL` in the current shell/session — don't write it into global shell rc files or commit it, since it repoints all Anthropic traffic through the local proxy.

## Check savings / health

```bash
curl -s http://localhost:8787/v1/stats | jq       # session dedup/cache stats
curl -s http://localhost:8787/health               # liveness
```

## Stop it

```bash
byoai-cache stop
```
This sends SIGTERM, escalates to SIGKILL after ~5s if needed, and removes the pidfile. Also unset `ANTHROPIC_BASE_URL` in the current shell if you exported it, so traffic goes back to the real API.

## Config knobs (env vars, set before `byoai-cache start`)

| Var | Default | Purpose |
|---|---|---|
| `BYOAI_HOST` | `0.0.0.0` | bind host |
| `BYOAI_PORT` | `8787` | bind port |
| `BYOAI_PROXY_TOKEN` | unset | optional shared-secret gate for remote exposure |
| `REDIS_URL` | unset | session/dedup state store (falls back to in-process) |
| `BYOAI_SQLITE_PATH` | unset | durable request log |

Don't guess at other vars — the full table is in `CONFIGURATION.md`; read it before changing anything not listed here.

## Adding this skill to another project

This skill only depends on the `byoai-cache` console script being installed — it has no repo-specific logic. To reuse it elsewhere:

```bash
cp -r .claude/skills/byoai-cache /path/to/other-repo/.claude/skills/
```

Then `pip install "byoai-runtime[agent-context-cache]"` in that project's environment so the
`byoai-cache` command resolves. The bare package does not pull in FastAPI/uvicorn/redis, so
without the extra the command exists but fails to import.
