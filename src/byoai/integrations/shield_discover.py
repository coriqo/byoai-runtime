"""`byoai-shield discover`: list AI tooling configured on this computer.

Read-only and offline. It finds three things and nothing else:

* MCP servers configured in the config files of known clients (Claude Desktop,
  Cursor, VS Code, Claude Code, Windsurf);
* known AI desktop apps that are installed;
* local model runtimes (Ollama, LM Studio, ...): whether something listens on
  the runtime's default loopback port, and the names of installed models.

What it records is **that something is configured, not what it holds**. For an
MCP server: its name, how it connects (stdio or http), the program's file name
(no arguments), the host of a URL (no path, query or user info), and the
*names* of the environment variables and headers it passes (never a value).
File contents, arguments, tokens and the user name are never read into the
output, and home-directory paths are written as ``~/...``.

The output is a JSON document marked ``unattested``. It is a claim made by an
unauthenticated scan, not evidence: it is written to stdout or ``--out`` and
never to Shield's signed ledger, and this command makes no network call (the
runtime check connects to 127.0.0.1 only; ``--no-probe`` turns it off).

Nothing leaves the computer unless the person or their admin's tool moves the
file.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import sys
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SCHEMA = "byoai.shield.discovery/1"
SIGNATURES_PATH = Path(__file__).with_name("shield_discovery_signatures.json")
MAX_CONFIG_BYTES = 1_048_576   # a config larger than this is skipped, not parsed
MAX_SERVERS_PER_FILE = 200
MAX_MODELS = 50
PROBE_TIMEOUT_S = 0.25


def load_signatures(path: Path = SIGNATURES_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


# ---- path handling -------------------------------------------------------

def _expand(raw: str, home: Path, env: Mapping[str, str]) -> Path | None:
    """``~`` and ``%VAR%`` expanded against the given home and env; None if a variable is unset."""
    out = raw
    if out.startswith("~"):
        out = str(home) + out[1:]
    while "%" in out:
        start = out.find("%")
        end = out.find("%", start + 1)
        if end < 0:
            return None
        name = out[start + 1:end]
        val = env.get(name)
        if not val:
            return None
        out = out[:start] + val + out[end + 1:]
    return Path(out)


def _display(path: Path, home: Path) -> str:
    for base in (home, home.resolve()):
        try:
            return "~/" + path.relative_to(base).as_posix()
        except ValueError:
            continue
    return path.name


def _read_json(path: Path, home: Path) -> tuple[Any | None, str | None]:
    """Parse a user config. Returns (data, reason it was skipped). A symlink is followed only when it
    stays inside the home directory, so a planted link cannot make us read another account's file."""
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        return None, None  # absent: not an error, not worth a line
    try:
        resolved.relative_to(home.resolve())
    except ValueError:
        return None, "outside the home directory"
    try:
        if not resolved.is_file():
            return None, "not a regular file"
        if resolved.stat().st_size > MAX_CONFIG_BYTES:
            return None, "larger than 1 MiB"
        return json.loads(resolved.read_text(encoding="utf-8")), None
    except (OSError, UnicodeDecodeError):
        return None, "unreadable"
    except (ValueError, RecursionError):  # JSONDecodeError is a ValueError; deep nesting recurses
        return None, "not valid JSON"


# ---- MCP -----------------------------------------------------------------

def _program_name(command: object) -> str | None:
    """File name only. Arguments are never recorded: they can carry tokens."""
    if not isinstance(command, str) or not command.strip():
        return None
    # First word only, then its file name: an argument may contain "/" and a secret.
    word = command.strip().split()[0].strip("\"'").replace("\\", "/")
    return word.split("/")[-1][:80] or None


def _url_host(url: object) -> str | None:
    if not isinstance(url, str):
        return None
    try:
        return (urlsplit(url).hostname or None)
    except ValueError:
        return None


def _names(value: object) -> list[str]:
    if not isinstance(value, dict):
        return []
    return sorted({str(k)[:80] for k in value})[:50]


def describe_server(name: str, spec: object) -> dict[str, Any] | None:
    if not isinstance(spec, dict):
        return None
    host = _url_host(spec.get("url") or spec.get("serverUrl"))
    program = _program_name(spec.get("command"))
    transport = "stdio" if program else ("sse" if str(spec.get("type", "")).lower() == "sse" else "http") if host else "unknown"
    return {
        "server": str(name)[:120],
        "transport": transport,
        "program": program,
        "host": host,
        "env_names": _names(spec.get("env")),
        "header_names": _names(spec.get("headers")),
    }


def _servers_in(data: object) -> list[tuple[str, object]]:
    """``mcpServers`` or VS Code's ``servers``, at the top level and (Claude Code) per project."""
    found: list[tuple[str, object]] = []
    if not isinstance(data, dict):
        return found
    for key in ("mcpServers", "servers"):
        block = data.get(key)
        if isinstance(block, dict):
            found.extend(block.items())
    projects = data.get("projects")
    if isinstance(projects, dict):
        for proj in projects.values():
            if isinstance(proj, dict) and isinstance(proj.get("mcpServers"), dict):
                found.extend(proj["mcpServers"].items())
    return found


def _record_hash(record: Mapping[str, Any]) -> str:
    """Hash of the redacted record, so a change shows up but no secret is ever hashed."""
    return hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]


def scan_mcp(sigs: dict, platform: str, home: Path, env: Mapping[str, str]
             ) -> tuple[list[dict], list[dict]]:
    items: list[dict] = []
    skipped: list[dict] = []
    for client in sigs.get("mcp_clients", []):
        for raw in client.get("paths", {}).get(platform, []):
            path = _expand(raw, home, env)
            if path is None:
                continue
            data, reason = _read_json(path, home)
            if reason:
                skipped.append({"client": client["client"], "path": _display(path, home), "reason": reason})
                continue
            if data is None:
                continue
            seen: set[str] = set()
            for name, spec in _servers_in(data)[:MAX_SERVERS_PER_FILE]:
                rec = describe_server(name, spec)
                if rec is None:
                    continue
                rec = {"kind": "mcp_server", "client": client["client"],
                       "config": _display(path, home), **rec}
                rec["config_hash"] = _record_hash(rec)
                if rec["config_hash"] in seen:
                    continue
                seen.add(rec["config_hash"])
                items.append(rec)
    return items, skipped


# ---- apps and runtimes ---------------------------------------------------

def _app_candidates(entry: Mapping[str, Any], platform: str, home: Path, env: Mapping[str, str],
                    path_dirs: list[Path]) -> list[Path]:
    out: list[Path] = []
    for raw in entry.get(platform, []):
        if platform == "darwin":
            out += [Path("/Applications") / raw, home / "Applications" / raw]
        elif platform == "linux":
            out += [d / raw for d in path_dirs]
        else:
            p = _expand(raw, home, env)
            if p is not None:
                out.append(p)
    return out


def scan_apps(sigs: dict, platform: str, home: Path, env: Mapping[str, str],
              exists: Callable[[Path], bool] = Path.exists) -> list[dict]:
    path_dirs = [Path(p) for p in env.get("PATH", "").split(os.pathsep) if p]
    items = []
    for entry in sigs.get("apps", []):
        for cand in _app_candidates(entry, platform, home, env, path_dirs):
            if exists(cand):
                items.append({"kind": "app", "app": entry["app"], "location": _display(cand, home)})
                break
    return items


def _loopback_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=PROBE_TIMEOUT_S):
            return True
    except OSError:
        return False


def _model_names(dirs: list[Path]) -> list[str]:
    names: set[str] = set()
    for d in dirs:
        try:
            if not d.is_dir() or d.is_symlink():
                continue
            for pub in sorted(d.iterdir())[:200]:
                if pub.is_symlink() or not pub.is_dir():
                    continue
                children = [c for c in sorted(pub.iterdir())[:200] if c.is_dir() and not c.is_symlink()]
                names.update(f"{pub.name}/{c.name}"[:120] for c in children)
                if len(names) >= MAX_MODELS:
                    break
        except OSError:
            continue
    return sorted(names)[:MAX_MODELS]


def scan_runtimes(sigs: dict, home: Path, env: Mapping[str, str], *, probe: bool = True,
                  port_open: Callable[[int], bool] = _loopback_open) -> list[dict]:
    items = []
    for entry in sigs.get("runtimes", []):
        dirs = [p for p in (_expand(r, home, env) for r in entry.get("model_dirs", [])) if p]
        models = _model_names(dirs)
        listening = port_open(entry["port"]) if probe else None
        if listening or models:
            items.append({"kind": "runtime", "runtime": entry["runtime"], "port": entry["port"],
                          "listening": listening, "models": models})
    return items


# ---- run -----------------------------------------------------------------

def discover(*, platform: str | None = None, home: Path | None = None, env: Mapping[str, str] | None = None,
             probe: bool = True, signatures: dict | None = None,
             port_open: Callable[[int], bool] = _loopback_open,
             exists: Callable[[Path], bool] = Path.exists,
             now: Callable[[], float] = time.time) -> dict[str, Any]:
    platform = platform or sys.platform
    if platform.startswith("linux"):
        platform = "linux"
    home = home or Path.home()
    env = os.environ if env is None else env
    sigs = signatures if signatures is not None else load_signatures()
    mcp, skipped = scan_mcp(sigs, platform, home, env)
    return {
        "schema": SCHEMA,
        "attestation": "unattested",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now())),
        "platform": platform,
        "signatures_version": sigs.get("version"),
        "items": mcp + scan_apps(sigs, platform, home, env, exists) + scan_runtimes(
            sigs, home, env, probe=probe, port_open=port_open),
        "skipped": skipped,
    }


def planned_paths(sigs: dict, platform: str, home: Path, env: Mapping[str, str]) -> list[str]:
    out = []
    for client in sigs.get("mcp_clients", []):
        for raw in client.get("paths", {}).get(platform, []):
            p = _expand(raw, home, env)
            if p is not None:
                out.append(_display(p, home))
    return out


def run_discover(argv: list[str], *, out=None, err=None, **kw) -> int:
    out = out or sys.stdout
    err = err or sys.stderr
    ap = argparse.ArgumentParser(
        prog="byoai-shield discover",
        description="List MCP servers, AI apps and local model runtimes on this computer. "
                    "Read-only, offline, never touches Shield's ledger.")
    ap.add_argument("--out", type=Path, help="write the JSON here (mode 0600) instead of stdout")
    ap.add_argument("--no-probe", action="store_true", help="do not connect to default runtime ports on 127.0.0.1")
    ap.add_argument("--dry-run", action="store_true", help="print the config files it would read, then stop")
    args = ap.parse_args(argv)

    if args.dry_run:
        platform = kw.get("platform") or ("linux" if sys.platform.startswith("linux") else sys.platform)
        env = kw.get("env")
        env = os.environ if env is None else env
        for p in planned_paths(load_signatures(), platform, kw.get("home") or Path.home(), env):
            print(p, file=out)
        return 0

    print("Reading the config files of known AI tools; contents, arguments and secrets are not recorded.",
          file=err)
    report = discover(probe=not args.no_probe, **kw)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        try:
            fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                os.fchmod(fd, 0o600) if hasattr(os, "fchmod") else None  # an existing file keeps its old mode otherwise
                fh.write(text)
        except OSError as exc:
            print(f"Cannot write {args.out}: {exc.strerror}", file=err)
            return 1
        print(f"Wrote {len(report['items'])} item(s) to {args.out}.", file=err)
    else:
        out.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(run_discover(sys.argv[1:]))
