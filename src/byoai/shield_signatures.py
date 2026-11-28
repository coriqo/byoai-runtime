"""Shield signature loader and model-endpoint matcher (U1.3).

Reads a base signature file (``docs/shield-signatures.md``) and matches a request's
host and path against its ``model_endpoint`` entries. The model name is read only
from a JSON payload field that is present; it is never guessed, never taken from
the URL, and anything malformed yields ``unknown``. Nothing here raises on bad input.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

UNKNOWN = "unknown"
DEFAULT_CATALOG = Path(__file__).with_name("shield_catalog_models.json")
SCHEMA_PATH = Path(__file__).with_name("shield_signatures.schema.json")

_MAX_FILE_BYTES = 1_000_000
_MAX_PATH = 2048
_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}")
_TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?Z", re.ASCII)
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
_TYPES = ("app_domain", "model_endpoint", "agent_protocol", "mcp_config_path", "local_runtime", "local_app")
_MAX_STARS = 4  # `*` per path pattern; keeps matching cheap and the pattern readable
_MAX_LIFETIME = timedelta(days=400)  # expires_at - last_verified, per docs/shield-signatures.md
_PORT_RE = re.compile(r"[0-9]{1,5}")
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
    expires_at: datetime


@dataclass(frozen=True)
class Catalog:
    entries: tuple[_Entry, ...] = ()
    error: str | None = None
    expired_ids: tuple[str, ...] = field(default=())

    def match(self, host: Any, path: Any, body: Any = None, *, now: str | None = None) -> ModelMatch:
        """Provider (and model if the payload carries one). Never raises.

        An entry past its ``expires_at`` never matches, however long the process has run.
        ``now`` (a UTC timestamp string) is for tests.
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
        clock = _clock(now)
        for e in self.entries:
            if e.expires_at <= clock:
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


def _norm_host(host: Any) -> str | None:
    if not isinstance(host, str) or not host or len(host) > 260:
        return None
    h = host.strip().lower().rstrip(".")
    if h.startswith("[") or h.count(":") > 1:
        return None
    h, sep, port = h.partition(":")
    if sep and not (_PORT_RE.fullmatch(port) and 1 <= int(port) <= 65535):
        return None
    return h if _HOST_RE.fullmatch(h) and not h.startswith("*") else None


def _norm_path(path: Any) -> str | None:
    if not isinstance(path, str) or not path.startswith("/") or len(path) > _MAX_PATH:
        return None
    p = re.split(r"[?#]", path, maxsplit=1)[0]
    if any(ord(c) < 0x21 or ord(c) == 0x7F for c in p) or "//" in p:
        return None
    if ".." in p or any(seg == "." for seg in p.split("/")):
        return None
    return p


def _host_ok(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        head, _, rest = host.partition(".")
        return bool(head) and rest == pattern[2:]
    return pattern == host


@lru_cache(maxsize=512)
def _tokens(pattern: str) -> tuple[str, ...]:
    """Per pattern segment, the glob token string (computed once, then cached)."""
    return tuple("".join("?*" if c == "*" else c for c in seg) for seg in pattern.split("/"))


def _path_ok(pattern: str, path: str) -> bool:
    """``*`` is one or more characters within a segment (never across ``/``).

    Segment by segment with an iterative glob (single backtrack point), so the cost is
    at most pattern length times segment length however many stars there are.
    """
    pats, segs = _tokens(pattern), path.split("/")
    return len(pats) == len(segs) and all(_glob(a, b) for a, b in zip(pats, segs, strict=True))


def _glob(toks: str, text: str) -> bool:
    # ``toks`` comes from _tokens: "?" (never in a pattern; the schema forbids it) means any
    # one character and a `*` became "?*" (one or more); then the usual single-backtrack glob.
    i = j = mark = 0
    star = -1
    while j < len(text):
        if i < len(toks) and toks[i] == "*":
            star, mark = i, j
            i += 1
        elif i < len(toks) and toks[i] in ("?", text[j]):
            i += 1
            j += 1
        elif star >= 0:
            i, mark = star + 1, mark + 1
            j = mark
        else:
            return False
    while i < len(toks) and toks[i] == "*":
        i += 1
    return i == len(toks)


def _read_model(provider: str, body: Any) -> tuple[str | None, str | None]:
    if not isinstance(body, Mapping):
        return None, None
    for key, source in _MODEL_FIELDS.get(provider, ()):
        v = body.get(key)
        if isinstance(v, str) and _MODEL_RE.fullmatch(v) and ".." not in v and "//" not in v:
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


def _parse_ts(value: Any) -> datetime | None:
    """Strict UTC timestamp (seconds optional, fraction dropped); anything else is None.

    Parsed with ``strptime`` (``fromisoformat`` differs between Python 3.10 and 3.11+), so
    month 13, hour 25 and non-ASCII digits are rejected.
    """
    if not isinstance(value, str) or not _TS_RE.fullmatch(value):
        return None
    sec = value[17:19] if len(value) > 17 and value[16] == ":" else "00"
    try:
        return datetime.strptime(value[:16] + ":" + sec, "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        return None


def _clock(now: Any) -> datetime:
    """``now`` if it is a valid timestamp, else the real clock. A bad override can never make
    an entry look unexpired: it falls back to real time, not to "the past"."""
    return _parse_ts(now) or datetime.now(timezone.utc)


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


def _validated(
    text: str, now: str | None
) -> tuple[list[tuple[dict[str, Any], datetime]], datetime, str | None]:
    """Parse and validate a base file. Returns (entries with parsed expiry, error)."""
    if not isinstance(text, str) or len(text) > _MAX_FILE_BYTES:
        return [], _EPOCH, "bad input"
    try:
        doc = json.loads(text, parse_constant=_reject_const)
    except (ValueError, RecursionError):
        return [], _EPOCH, "not json"
    if not isinstance(doc, dict) or set(doc) - _FILE_KEYS:
        return [], _EPOCH, "unknown or missing file fields"
    if doc.get("schema_version") != 1 or isinstance(doc.get("schema_version"), bool):
        return [], _EPOCH, "unsupported schema_version"
    if doc.get("format") != "coriqo.shield.signatures":
        return [], _EPOCH, "wrong format"
    if doc.get("kind") != "base" or "signature" in doc:
        return [], _EPOCH, "only a base list is loaded here"
    sigs = doc.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        return [], _EPOCH, "no signatures"
    clock = _clock(now)
    entry_keys, match_keys, source_keys = _schema_keys()
    seen: set[str] = set()
    out: list[tuple[dict[str, Any], datetime]] = []
    for s in sigs:
        if not isinstance(s, dict) or set(s) - entry_keys:
            return [], _EPOCH, "bad entry"
        sid, m, src = s.get("id"), s.get("match"), s.get("source")
        if not isinstance(sid, str) or sid in seen or not isinstance(m, dict) or not isinstance(src, dict):
            return [], _EPOCH, "bad entry"
        seen.add(sid)
        if set(m) - match_keys or set(src) - source_keys:
            return [], _EPOCH, "unknown match or source field"
        first, last, exp = (_parse_ts(s.get(k)) for k in ("first_seen", "last_verified", "expires_at"))
        if first is None or last is None or exp is None:
            return [], _EPOCH, "bad timestamp"
        if not first <= last <= exp or exp - last > _MAX_LIFETIME:
            return [], _EPOCH, "bad entry dates"
        ver, conf = s.get("version"), s.get("confidence")
        if not isinstance(ver, int) or isinstance(ver, bool) or ver < 1:
            return [], _EPOCH, "bad version"
        if conf not in ("confirmed", "probable", "possible"):
            return [], _EPOCH, "bad confidence"
        if s.get("type") not in _TYPES:
            return [], _EPOCH, "unknown entry type"
        out.append((s, exp))
    return out, clock, None


def _load(text: str, now: str | None) -> Catalog:
    sigs, clock, err = _validated(text, now)
    if err:
        return _fail(err)
    entries: list[_Entry] = []
    expired: list[str] = []
    for s, exp in sigs:
        if s.get("type") != "model_endpoint":
            continue
        m = s["match"]
        hosts, paths = m.get("hosts"), m.get("paths")
        if not _strs(hosts, _HOST_RE) or not _strs(paths, _PATH_RE):
            return _fail("bad hosts or paths")
        if any(p.count("*") > _MAX_STARS for p in paths):
            return _fail("too many wildcards in a path")
        if exp <= clock:
            expired.append(s["id"])
            continue
        provider = _PROVIDERS.get(str(s.get("vendor", "")).lower())
        if provider is None:
            return _fail("unsupported vendor")
        entries.append(_Entry(s["id"], s["version"], provider, s["confidence"],
                              tuple(hosts), tuple(paths), exp))
    return Catalog(entries=tuple(entries), expired_ids=tuple(expired))


# --- app catalog (base list plus its bound sidecar) ---------------------------------------

DEFAULT_APPS = Path(__file__).with_name("shield_catalog_apps.json")
DEFAULT_APPS_META = Path(__file__).with_name("shield_catalog_apps_meta.json")
_TIERS = ("listed", "candidate")
_NATURES = ("ai-native", "ai-enabled")
_ORIGINS = ("seed", "shadow-ai", "tio", "autotune")
_CATEGORIES = frozenset(
    "chatbot meeting_transcription image_video writing coding sales_marketing data_analytics "
    "model_hub hr_recruiting productivity_agents design search".split()
)


@dataclass(frozen=True)
class AppEntry:
    """One ``app_domain`` entry joined to its sidecar record. ``verified`` is False for every
    entry whose facts came from a third-party list rather than a Coriqo review."""

    id: str
    hosts: tuple[str, ...]
    vendor: str
    confidence: str
    tier: str
    nature: str
    category: str
    origin: str
    verified: bool


@dataclass(frozen=True)
class AppCatalog:
    entries: tuple[AppEntry, ...] = ()
    error: str | None = None


def load_app_catalog(
    path: str | Path | None = None,
    meta_path: str | Path | None = None,
    *,
    now: str | None = None,
) -> AppCatalog:
    """Load the app catalog and validate its sidecar against it. Never raises.

    The sidecar records the sha256 of the catalog file it was built for, must hold exactly
    one record per ``app_domain`` or model entry id, and every tier, nature, category and
    origin must be a known value that agrees with the entry (a candidate or ``ai-enabled``
    entry may not report above ``possible``). Any mismatch rejects the whole catalog.
    """
    try:
        p = Path(path) if path is not None else DEFAULT_APPS
        mp = Path(meta_path) if meta_path is not None else DEFAULT_APPS_META
        if p.stat().st_size > _MAX_FILE_BYTES or mp.stat().st_size > _MAX_FILE_BYTES * 2:
            return AppCatalog(error="file too large")
        raw = p.read_bytes()
        meta = json.loads(mp.read_text(encoding="utf-8"), parse_constant=_reject_const)
        sigs, clock, err = _validated(raw.decode("utf-8"), now)
        if err:
            return AppCatalog(error=err)
        if (not isinstance(meta, dict) or meta.get("format") != "coriqo.shield.catalog-meta"
                or meta.get("catalog_sha256") != hashlib.sha256(raw).hexdigest()
                or not isinstance(meta.get("entries"), dict)):
            return AppCatalog(error="sidecar does not match catalog")
        records = meta["entries"]
        if set(records) != {s["id"] for s, _ in sigs}:
            return AppCatalog(error="sidecar ids differ from catalog")
        out: list[AppEntry] = []
        for s, exp in sigs:
            r = records[s["id"]]
            if not isinstance(r, dict) or set(r) != {"category", "nature", "tier", "origin"}:
                return AppCatalog(error="bad sidecar record")
            tier, nature, origin = r["tier"], r["nature"], r["origin"]
            if (tier not in _TIERS or nature not in _NATURES or origin not in _ORIGINS
                    or r["category"] not in _CATEGORIES):
                return AppCatalog(error="bad sidecar value")
            listed_origin = origin in ("seed", "shadow-ai")
            if (tier == "listed") != listed_origin:
                return AppCatalog(error="tier disagrees with origin")
            if (tier == "candidate" or nature == "ai-enabled") and s["confidence"] != "possible":
                return AppCatalog(error="confidence above what tier and nature allow")
            if s["type"] != "app_domain":
                continue
            hosts = s["match"].get("hosts")
            if not _strs(hosts, _HOST_RE) or any(h.startswith("*") for h in hosts):
                return AppCatalog(error="bad app hosts")
            if exp <= clock:
                continue
            out.append(AppEntry(s["id"], tuple(hosts), s["vendor"],
                                s["confidence"], tier, nature, r["category"], origin,
                                verified=origin == "seed"))
        return AppCatalog(entries=tuple(out))
    except Exception as exc:  # noqa: BLE001
        return AppCatalog(error=f"unreadable: {type(exc).__name__}")


def _strs(v: Any, rx: re.Pattern[str]) -> bool:
    return (
        isinstance(v, list)
        and bool(v)
        and all(isinstance(x, str) and rx.fullmatch(x) is not None for x in v)
    )
