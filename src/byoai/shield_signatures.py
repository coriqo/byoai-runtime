"""Shield signature loader and model-endpoint matcher (U1.3).

Reads a base signature file (``docs/shield-signatures.md``) and matches a request's
host and path against its ``model_endpoint`` entries. The model name is read only
from a JSON payload field that is present; it is never guessed, never taken from
the URL, and anything malformed yields ``unknown``. Nothing here raises on bad input.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

UNKNOWN = "unknown"
DEFAULT_CATALOG = Path(__file__).with_name("shield_catalog_models.json")
SCHEMA_PATH = Path(__file__).with_name("shield_signatures.schema.json")

_MAX_FILE_BYTES = 1_000_000
_MAX_PATH = 2048
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}")
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z", re.ASCII)
_HOST_RE = re.compile(r"(\*\.)?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+")
_PATH_RE = re.compile(r"/[A-Za-z0-9/_.:*{}-]{0,120}")

#: Payload fields a model name may be read from, by vendor. Request side first.
_MODEL_FIELDS: dict[str, tuple[tuple[str, str], ...]] = {
    "openai": (("model", "request_field"),),
    "anthropic": (("model", "request_field"),),
    "google": (("modelVersion", "response_field"), ("model", "request_field")),
}
_PROVIDERS = {"openai": "openai", "anthropic": "anthropic", "google": "google"}


@dataclass(frozen=True)
class ModelMatch:
    """Result of a match. Row fields only: no payload text."""

    provider: str = UNKNOWN
    deployment: str = UNKNOWN
    model: str | None = None
    model_source: str | None = None
    rule_id: str | None = None
    rule_version: int | None = None
    confidence: str | None = None


NO_MATCH = ModelMatch()


@dataclass(frozen=True)
class _Entry:
    id: str
    version: int
    provider: str
    confidence: str
    hosts: tuple[str, ...]
    paths: tuple[str, ...]
    expires_at: str


@dataclass(frozen=True)
class Catalog:
    entries: tuple[_Entry, ...] = ()
    error: str | None = None
    expired_ids: tuple[str, ...] = field(default=())

    def match(self, host: Any, path: Any, body: Any = None, *, now: str | None = None) -> ModelMatch:
        """Provider (and model if the payload carries one). Never raises.

        An entry whose ``expires_at`` has passed no longer matches, even if it was
        valid when the catalog was loaded. ``now`` (UTC, ``YYYY-MM-DDTHH:MM:SSZ``) is for tests.
        """
        try:
            return self._match(host, path, body, now)
        except Exception:  # noqa: BLE001 - fail closed on anything unexpected
            return NO_MATCH

    def _match(self, host: Any, path: Any, body: Any, now: str | None) -> ModelMatch:
        h = _norm_host(host)
        p = _norm_path(path)
        if h is None or p is None:
            return NO_MATCH
        now_s = _now(now)
        for e in self.entries:
            if e.expires_at <= now_s:
                continue
            if any(_host_ok(pat, h) for pat in e.hosts) and any(_path_ok(pat, p) for pat in e.paths):
                model, src = _read_model(e.provider, body)
                return ModelMatch(
                    provider=e.provider,
                    deployment="vendor_api",
                    model=model,
                    model_source=src,
                    rule_id=e.id,
                    rule_version=e.version,
                    confidence=e.confidence if e.confidence != "confirmed" else "probable",
                )
        return NO_MATCH


def _now(override: Any = None) -> str:
    """Current UTC time, or ``override`` if it is a valid timestamp (normalised to seconds).

    Anything that is not a valid timestamp (wrong type, junk) is ignored and the
    real clock is used, so a bad override can never make an entry look unexpired
    by string order.
    """
    if isinstance(override, str) and _TS_RE.fullmatch(override):
        try:
            return _norm_ts(override)
        except ValueError:
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _norm_ts(ts: str) -> str:
    """Validate a timestamp and normalise it to ``YYYY-MM-DDTHH:MM:SSZ`` (fraction dropped).

    Parsed with ``strptime`` (not ``fromisoformat``, whose accepted forms differ
    between Python 3.10 and 3.11+). Raises ValueError for month 13, hour 25, ...
    """
    sec = ts[17:19] if len(ts) > 17 and ts[16] == ":" else "00"
    datetime.strptime(ts[:16] + ":" + sec, "%Y-%m-%dT%H:%M:%S")
    return ts[:16] + ":" + sec + "Z"


def _norm_host(host: Any) -> str | None:
    if not isinstance(host, str) or not host or len(host) > 260:
        return None
    h = host.strip().lower().rstrip(".")
    if h.startswith("[") or h.count(":") > 1:
        return None
    h = h.split(":", 1)[0]
    return h if _HOST_RE.fullmatch(h) and not h.startswith("*") else None


def _norm_path(path: Any) -> str | None:
    if not isinstance(path, str) or not path.startswith("/") or len(path) > _MAX_PATH:
        return None
    p = re.split(r"[?#]", path, maxsplit=1)[0]
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in p) or "//" in p:
        return None
    if any(seg in ("..", ".") for seg in p.split("/")):
        return None
    return p


def _host_ok(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        head, _, rest = host.partition(".")
        return bool(head) and rest == pattern[2:]
    return pattern == host


def _path_ok(pattern: str, path: str) -> bool:
    """``*`` matches one or more characters within a single segment, never across ``/``.

    Segment by segment with a greedy literal search: no regex, so a pattern full
    of ``*`` cannot cause backtracking blow-up.
    """
    pats, segs = pattern.split("/"), path.split("/")
    return len(pats) == len(segs) and all(_seg_ok(a, b) for a, b in zip(pats, segs))


def _seg_ok(pat: str, seg: str) -> bool:
    parts = pat.split("*")
    if len(parts) == 1:
        return pat == seg
    first, last = parts[0], parts[-1]
    end = len(seg) - len(last)
    if not seg.startswith(first) or not seg.endswith(last) or end < len(first):
        return False
    pos = len(first)
    for mid in parts[1:-1]:
        pos += 1  # the star before ``mid`` takes at least one character
        idx = seg.find(mid, pos)
        if idx < 0 or idx + len(mid) > end:
            return False
        pos = idx + len(mid)
    return pos + 1 <= end  # the last star takes at least one character


def _read_model(provider: str, body: Any) -> tuple[str | None, str | None]:
    if not isinstance(body, Mapping):
        return None, None
    for key, source in _MODEL_FIELDS.get(provider, ()):
        v = body.get(key)
        if isinstance(v, str) and _MODEL_RE.fullmatch(v):
            return v, source
    return None, None


# --- loader ---------------------------------------------------------------------------

_FILE_KEYS = {
    "schema_version", "format", "kind", "file_version", "generated_at", "expires_at",
    "publisher", "signatures", "signature",
}  # fmt: skip


def _schema_keys() -> tuple[set[str], set[str], set[str]]:
    """Closed key sets (entry, match, source) read from the shipped schema."""
    s = json.loads(SCHEMA_PATH.read_text())
    item = s["properties"]["signatures"]["items"]["properties"]
    return set(item), set(item["match"]["properties"]), set(item["source"]["properties"])


def _fail(msg: str) -> Catalog:
    return Catalog(error=msg)


def load_catalog(path: str | Path | None = None, *, now: str | None = None) -> Catalog:
    """Load a base signature file; default is the shipped model catalog. Never raises."""
    try:
        p = Path(path) if path is not None else DEFAULT_CATALOG
        if p.stat().st_size > _MAX_FILE_BYTES:
            return _fail("file too large")
        return load_catalog_text(p.read_text(encoding="utf-8"), now=now)
    except Exception as exc:  # noqa: BLE001
        return _fail(f"unreadable: {type(exc).__name__}")


def _reject_const(_: str) -> Any:
    raise ValueError("non-finite number")


def load_catalog_text(text: str, *, now: str | None = None) -> Catalog:
    """Validate and load. Any structural problem rejects the whole file (fail closed)."""
    try:
        return _load(text, now)
    except Exception as exc:  # noqa: BLE001
        return _fail(f"invalid: {type(exc).__name__}")


def _load(text: str, now: str | None) -> Catalog:
    if not isinstance(text, str) or len(text) > _MAX_FILE_BYTES:
        return _fail("bad input")
    try:
        doc = json.loads(text, parse_constant=_reject_const)
    except (ValueError, RecursionError):
        return _fail("not json")
    if not isinstance(doc, dict) or set(doc) - _FILE_KEYS:
        return _fail("unknown or missing file fields")
    if doc.get("schema_version") != 1 or isinstance(doc.get("schema_version"), bool):
        return _fail("unsupported schema_version")
    if doc.get("format") != "coriqo.shield.signatures":
        return _fail("wrong format")
    if doc.get("kind") != "base" or "signature" in doc:
        return _fail("only a base list is loaded here")
    sigs = doc.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        return _fail("no signatures")
    now_s = _now(now)
    entry_keys, match_keys, source_keys = _schema_keys()
    seen: set[str] = set()
    entries: list[_Entry] = []
    expired: list[str] = []
    for s in sigs:
        if not isinstance(s, dict) or set(s) - entry_keys:
            return _fail("bad entry")
        sid, m, src = s.get("id"), s.get("match"), s.get("source")
        if not isinstance(sid, str) or sid in seen or not isinstance(m, dict) or not isinstance(src, dict):
            return _fail("bad entry")
        seen.add(sid)
        if set(m) - match_keys or set(src) - source_keys:
            return _fail("unknown match or source field")
        exp, ver, conf = s.get("expires_at"), s.get("version"), s.get("confidence")
        if not isinstance(exp, str) or not _TS_RE.fullmatch(exp):
            return _fail("bad expires_at")
        try:
            exp = _norm_ts(exp)
        except ValueError:
            return _fail("bad expires_at")
        if not isinstance(ver, int) or isinstance(ver, bool) or ver < 1:
            return _fail("bad version")
        if conf not in ("confirmed", "probable", "possible"):
            return _fail("bad confidence")
        if s.get("type") != "model_endpoint":
            continue
        hosts, paths = m.get("hosts"), m.get("paths")
        if not isinstance(hosts, list) or not isinstance(paths, list):
            return _fail("bad hosts or paths")
        if not _strs(hosts, _HOST_RE) or not _strs(paths, _PATH_RE):
            return _fail("bad hosts or paths")
        if exp <= now_s:
            expired.append(sid)
            continue
        provider = _PROVIDERS.get(str(s.get("vendor", "")).lower())
        if provider is None:
            return _fail("unsupported vendor")
        entries.append(_Entry(sid, ver, provider, conf, tuple(hosts), tuple(paths), exp))
    return Catalog(entries=tuple(entries), expired_ids=tuple(expired))


def _strs(v: Any, rx: re.Pattern[str]) -> bool:
    return (
        isinstance(v, list)
        and bool(v)
        and all(isinstance(x, str) and rx.fullmatch(x) is not None for x in v)
    )
