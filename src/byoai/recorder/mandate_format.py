"""Reference reader for the Coriqo mandate file, `coriqo.mandate.yaml` v1 (revision 1.3).

MANDATE_SPEC.md is the format. This module is its reference implementation:
what a document must look like, the defaults a reader applies, and the
document hash. Standard library only; YAML needs PyYAML (JSON, which is
also valid YAML, needs nothing).

    python mandate_format.py coriqo.mandate.yaml          # check it
    python mandate_format.py coriqo.mandate.yaml --hash   # check it, print the hash

Exit 0 the file is a valid v1 mandate, 1 it is not (each problem is printed
with its field), 2 the file could not be read.

Copied verbatim into coriqo-agents (coriqo_agents/mandate_format.py) and
Coriqo's API (api/domains/mandate/mandate_format.py). Change it here and
re-copy; a test in each place fails when a copy drifts.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from decimal import Decimal, InvalidOperation
from typing import Any

SPEC_NAME = "coriqo.mandate"
SPEC_MAJOR = 1
SPEC_MINOR = 4  # the newest v1 revision this reader knows
SPEC_ID = f"{SPEC_NAME}/v{SPEC_MAJOR}"
MAX_FILE_BYTES = 256 * 1024

MODES = ("shadow", "enforce")
STALE_POLICIES = ("fail_open", "fail_closed")
DELEGATION_POLICIES = ("none", "attenuated")
VIOLATION_ACTIONS = ("deny", "deny_and_halt_run", "alert_only")
INSPECTION_SWITCHES = {
    "instruction_like": ("off", "flag"),
    "secrets": ("off", "flag", "redact"),
    "pii": ("off", "flag", "redact"),
}

MIN_STALENESS_S, MAX_STALENESS_S = 30, 86400
MAX_DELEGATION_DEPTH = 20
MAX_STEPS = 1_000_000
MAX_COST_USD = Decimal("999999.999999")
MAX_TOOLS = 500
MAX_MANDATE_CHARS = 20000
MIN_STOP_GRACE_S, MAX_STOP_GRACE_S = 1, 600  # v1.1
# v1.2: money an agent may move, in US dollars, to the cent.
MAX_TRANSACTION_USD = Decimal("999999999999.99")
TRANSACTION_LIMIT_KEYS = ("max_transaction_usd_per_day", "max_transaction_usd")
# v1.3: the asset classes and venues an agent may act on. Venues are tenant-defined ids.
ASSET_CLASSES = ("crypto_asset", "stablecoin", "tokenized_security", "tokenized_fund", "fiat")
ASSET_SCOPE_KEYS = ("asset_classes", "venues")
MAX_VENUES, MAX_VENUE_CHARS = 50, 64
# v1.4: tool pins. A hash of each approved MCP tool's definition, so a change after approval is seen.
MAX_PIN_SERVERS = 50
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_PIN_TOOL_KEYS = ("definition_sha256", "annotations_sha256")

# What a reader that enforces from the file alone applies to a field the file
# leaves out. A field missing here (environment, mandate, tools.allowed, the
# two budgets, stop_grace_s, the two transaction limits, asset_scope) has no default: absent means "not set" (no
# allow-list, no limit, the runtime's own grace period).
DEFAULTS: dict[str, Any] = {
    "mode": "shadow",
    "on_stale_snapshot": "fail_open",
    "max_staleness_s": 300,
    "on_violation": "deny",
    "delegation": {"policy": "none", "max_depth": 3},
    "output_inspection": {"instruction_like": "off", "secrets": "off", "pii": "off"},
}

_SPEC_RE = re.compile(r"^coriqo\.mandate/v(\d+)(?:\.(\d+))?$")
_ENV_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_TOP_KEYS = (
    "spec", "agent", "environment", "mandate", "mode", "on_stale_snapshot",
    "max_staleness_s", "tools", "max_steps_per_run", "max_cost_usd",
    "delegation", "output_inspection", "on_violation",
    "stop_grace_s",  # v1.1
    "max_transaction_usd_per_day", "max_transaction_usd",  # v1.2
    "asset_scope",  # v1.3
    "tool_pins",  # v1.4
)
_AGENT_KEYS = ("name", "id", "external_id")


class MandateFileError(ValueError):
    """The text could not be read as a document at all (not JSON, not YAML,
    or not a mapping). A readable document with bad fields is not an error
    here: check() lists those."""


def parse_text(text: str) -> Any:
    """JSON first (no dependency), then YAML through PyYAML's safe loader."""
    if len(text.encode("utf-8")) > MAX_FILE_BYTES:
        raise MandateFileError(f"the file is larger than {MAX_FILE_BYTES // 1024} KB")
    stripped = text.strip()
    if not stripped:
        raise MandateFileError("the file is empty")
    if stripped[0] in "{[":
        try:
            return json.loads(stripped)
        except RecursionError as exc:
            raise MandateFileError("the file is nested too deeply") from exc
        except ValueError:
            pass  # YAML flow style also starts with "{"; let YAML try
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError as exc:
        raise MandateFileError(
            "this file is YAML; install PyYAML (pip install pyyaml) or save it as JSON"
        ) from exc
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise MandateFileError(f"not valid YAML: {exc}") from exc
    except RecursionError as exc:
        raise MandateFileError("the file is nested too deeply") from exc


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _str(v: Any, path: str, errors: list[str], *, max_len: int = 256) -> None:
    if not isinstance(v, str) or not v.strip():
        errors.append(f"{path}: must be a non-empty string")
    elif len(v) > max_len:
        errors.append(f"{path}: must be at most {max_len} characters")


def _enum(v: Any, path: str, allowed: tuple[str, ...], errors: list[str]) -> None:
    if isinstance(v, bool) or v not in allowed:
        # A YAML 1.1 loader reads a bare off/on/yes/no as a boolean.
        hint = ' (write "off" in quotes)' if isinstance(v, bool) and "off" in allowed else ""
        errors.append(f"{path}: must be one of {', '.join(allowed)}{hint}")


def _int_range(v: Any, path: str, lo: int, hi: int, errors: list[str]) -> None:
    if not _is_int(v) or not lo <= v <= hi:
        errors.append(f"{path}: must be a whole number from {lo} to {hi}")


def _unknown(obj: dict, known: tuple[str, ...], path: str, newer: bool,
             errors: list[str], warnings: list[str], *, allow_ext: bool = False) -> None:
    for key in obj:
        if key in known or (allow_ext and isinstance(key, str) and key.startswith("x-")):
            continue
        where = f"{path}.{key}" if path else str(key)
        if newer:
            warnings.append(f"{where}: not part of v1.{SPEC_MINOR}; ignored")
        else:
            errors.append(f"{where}: unknown field (extension fields start with x-)")


def _check_tool_pins(pins: Any, allowed: Any, newer: bool,
                     errors: list[str], warnings: list[str]) -> None:
    """v1.4 tool_pins: servers -> tools -> hashes. Every pinned tool must be in
    tools.allowed, and a tool name may be pinned under one server only (the
    allow-list is a flat list of names, so two servers cannot be told apart)."""
    if not isinstance(pins, dict):
        errors.append("tool_pins: must be a mapping with servers")
        return
    _unknown(pins, ("servers",), "tool_pins", newer, errors, warnings)
    servers = pins.get("servers")
    if servers is None:
        return
    if not isinstance(servers, dict):
        errors.append("tool_pins.servers: must be a mapping of server name to its tools")
        return
    if len(servers) > MAX_PIN_SERVERS:
        errors.append(f"tool_pins.servers: at most {MAX_PIN_SERVERS} servers")
    owner: dict[str, str] = {}
    pinned = 0
    for sname, sv in servers.items():
        where = f"tool_pins.servers.{sname}"
        if not isinstance(sname, str) or not _ENV_RE.match(sname):
            errors.append("tool_pins.servers: a server name is letters, digits, dot, dash or underscore, "
                          "up to 64 characters")
            continue
        if not isinstance(sv, dict):
            errors.append(f"{where}: must be a mapping with tools")
            continue
        _unknown(sv, ("tools",), where, newer, errors, warnings)
        tools = sv.get("tools")
        if tools is None:
            continue
        if not isinstance(tools, dict):
            errors.append(f"{where}.tools: must be a mapping of tool name to its hashes")
            continue
        for tname, entry in tools.items():
            tw = f"{where}.tools.{tname}"
            if not isinstance(tname, str) or not tname.strip() or len(tname) > 256:
                errors.append(f"{where}.tools: a tool name must be a non-empty string of at most 256 characters")
                continue
            pinned += 1
            if not isinstance(entry, dict):
                errors.append(f"{tw}: must be a mapping with definition_sha256")
                continue
            _unknown(entry, _PIN_TOOL_KEYS, tw, newer, errors, warnings)
            d = entry.get("definition_sha256")
            if not isinstance(d, str) or not _HASH_RE.match(d):
                errors.append(f"{tw}.definition_sha256: required, 64 lowercase hex characters")
            a = entry.get("annotations_sha256")
            if a is not None and (not isinstance(a, str) or not _HASH_RE.match(a)):
                errors.append(f"{tw}.annotations_sha256: 64 lowercase hex characters, or leave it out")
            if tname in owner and owner[tname] != sname:
                errors.append(f"{tw}: this tool is also pinned under {owner[tname]}; "
                              "a tool name can be pinned under one server only")
            owner.setdefault(tname, sname)
            if isinstance(allowed, list) and tname not in allowed:
                errors.append(f"{tw}: not in tools.allowed")
    if pinned > MAX_TOOLS:
        errors.append(f"tool_pins: at most {MAX_TOOLS} pinned tools")
    if pinned and not isinstance(allowed, list):
        errors.append("tool_pins: pins need tools.allowed, because every pinned tool must be allowed")


def _tool_list(v: Any, path: str, errors: list[str]) -> None:
    if not isinstance(v, list):
        errors.append(f"{path}: must be a list of tool names")
        return
    if len(v) > MAX_TOOLS:
        errors.append(f"{path}: at most {MAX_TOOLS} tools")
    for i, t in enumerate(v):
        _str(t, f"{path}[{i}]", errors)


def _cost(v: Any) -> Decimal | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    try:
        d = Decimal(str(v))
    except InvalidOperation:
        return None
    return d if d.is_finite() else None


def _check_asset_scope(scope: Any, newer: bool, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(scope, dict):
        errors.append("asset_scope: must be a mapping with asset_classes and/or venues")
        return
    classes, venues = scope.get("asset_classes"), scope.get("venues")
    if classes is not None:
        if not isinstance(classes, list):
            errors.append("asset_scope.asset_classes: must be a list of asset classes")
        else:
            for i, c in enumerate(classes):
                if isinstance(c, bool) or c not in ASSET_CLASSES:
                    errors.append(f"asset_scope.asset_classes[{i}]: must be one of {', '.join(ASSET_CLASSES)}")
            if len(set(c for c in classes if isinstance(c, str))) != len([c for c in classes if isinstance(c, str)]):
                errors.append("asset_scope.asset_classes: must not repeat an asset class")
    if venues is not None:
        if not isinstance(venues, list):
            errors.append("asset_scope.venues: must be a list of venue ids")
        else:
            if len(venues) > MAX_VENUES:
                errors.append(f"asset_scope.venues: at most {MAX_VENUES} venues")
            seen: set[str] = set()
            for i, v in enumerate(venues):
                if not isinstance(v, str) or not v.strip() or len(v.strip()) > MAX_VENUE_CHARS:
                    errors.append(f"asset_scope.venues[{i}]: must be a venue id of 1 to {MAX_VENUE_CHARS} characters")
                elif v.strip() in seen:
                    errors.append(f"asset_scope.venues[{i}]: repeats the venue {v.strip()}")
                else:
                    seen.add(v.strip())
    _unknown(scope, ASSET_SCOPE_KEYS, "asset_scope", newer, errors, warnings)


def check(doc: Any) -> tuple[list[str], list[str]]:
    """(errors, warnings). No errors means a valid v1 document."""
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(doc, dict):
        return ["the document must be a mapping of fields"], warnings

    spec = doc.get("spec")
    m = _SPEC_RE.match(spec) if isinstance(spec, str) else None
    if m is None:
        errors.append(f"spec: required; write spec: {SPEC_ID}")
        return errors, warnings
    major, minor = int(m.group(1)), int(m.group(2) or 0)
    if major != SPEC_MAJOR:
        errors.append(f"spec: this reader understands v{SPEC_MAJOR}; the file is v{major}")
        return errors, warnings
    newer = minor > SPEC_MINOR
    _unknown(doc, _TOP_KEYS, "", newer, errors, warnings, allow_ext=True)

    agent = doc.get("agent")
    if not isinstance(agent, dict):
        errors.append("agent: required, with at least a name")
    else:
        _str(agent.get("name"), "agent.name", errors)
        if "id" in agent:
            _str(agent["id"], "agent.id", errors, max_len=64)
        if "external_id" in agent:
            _str(agent["external_id"], "agent.external_id", errors)
        _unknown(agent, _AGENT_KEYS, "agent", newer, errors, warnings)

    # null is allowed where a field has no default: it says "not set" out loud,
    # which is how an export states that an agent has no budget or allow-list.
    if doc.get("environment") is not None and not (
        isinstance(doc["environment"], str) and _ENV_RE.match(doc["environment"])
    ):
        errors.append("environment: letters, digits, dot, dash or underscore, up to 64 characters")
    if doc.get("mandate") is not None:
        _str(doc["mandate"], "mandate", errors, max_len=MAX_MANDATE_CHARS)
    if "mode" in doc:
        _enum(doc["mode"], "mode", MODES, errors)
    if "on_stale_snapshot" in doc:
        _enum(doc["on_stale_snapshot"], "on_stale_snapshot", STALE_POLICIES, errors)
    if "max_staleness_s" in doc:
        _int_range(doc["max_staleness_s"], "max_staleness_s", MIN_STALENESS_S, MAX_STALENESS_S, errors)
    if "on_violation" in doc:
        _enum(doc["on_violation"], "on_violation", VIOLATION_ACTIONS, errors)
    if doc.get("max_steps_per_run") is not None:
        _int_range(doc["max_steps_per_run"], "max_steps_per_run", 1, MAX_STEPS, errors)
    if doc.get("max_cost_usd") is not None:
        d = _cost(doc["max_cost_usd"])
        if d is None or d <= 0 or d > MAX_COST_USD or d.as_tuple().exponent < -6:
            errors.append("max_cost_usd: must be a number above 0 and at most 999999.999999, "
                          "with no more than 6 decimal places")
    for key in TRANSACTION_LIMIT_KEYS:
        if doc.get(key) is not None:
            d = _cost(doc[key])
            if d is None or d <= 0 or d > MAX_TRANSACTION_USD or d.as_tuple().exponent < -2:
                errors.append(f"{key}: must be a number above 0 and at most 999999999999.99, "
                              "with no more than 2 decimal places")
    per_day, per_call = _cost(doc.get("max_transaction_usd_per_day")), _cost(doc.get("max_transaction_usd"))
    if per_day is not None and per_call is not None and per_call > per_day > 0:
        errors.append("max_transaction_usd: must not be more than max_transaction_usd_per_day")

    if doc.get("asset_scope") is not None:
        _check_asset_scope(doc["asset_scope"], newer, errors, warnings)

    tools = doc.get("tools")
    if "tools" in doc:
        if not isinstance(tools, dict):
            errors.append("tools: must be a mapping with allowed and/or prohibited")
        else:
            if tools.get("allowed") is not None:
                _tool_list(tools["allowed"], "tools.allowed", errors)
            if "prohibited" in tools:
                _tool_list(tools["prohibited"], "tools.prohibited", errors)
            _unknown(tools, ("allowed", "prohibited"), "tools", newer, errors, warnings)
            allowed, prohibited = tools.get("allowed"), tools.get("prohibited")
            if isinstance(allowed, list) and isinstance(prohibited, list):
                both = sorted({t for t in allowed if isinstance(t, str)}
                              & {t for t in prohibited if isinstance(t, str)})
                if both:
                    errors.append(f"tools: listed as both allowed and prohibited: {', '.join(both)}")

    if doc.get("tool_pins") is not None:
        allowed_for_pins = tools.get("allowed") if isinstance(tools, dict) else None
        _check_tool_pins(doc["tool_pins"], allowed_for_pins, newer, errors, warnings)

    if "delegation" in doc:
        dele = doc["delegation"]
        if not isinstance(dele, dict):
            errors.append("delegation: must be a mapping with policy and/or max_depth")
        else:
            if "policy" in dele:
                _enum(dele["policy"], "delegation.policy", DELEGATION_POLICIES, errors)
            if "max_depth" in dele:
                _int_range(dele["max_depth"], "delegation.max_depth", 0, MAX_DELEGATION_DEPTH, errors)
            _unknown(dele, ("policy", "max_depth"), "delegation", newer, errors, warnings)

    if "output_inspection" in doc:
        oi = doc["output_inspection"]
        if not isinstance(oi, dict):
            errors.append("output_inspection: must be a mapping of switches")
        else:
            for key, allowed_values in INSPECTION_SWITCHES.items():
                if key in oi:
                    _enum(oi[key], f"output_inspection.{key}", allowed_values, errors)
            _unknown(oi, tuple(INSPECTION_SWITCHES), "output_inspection", newer, errors, warnings)

    if doc.get("stop_grace_s") is not None:
        _int_range(doc["stop_grace_s"], "stop_grace_s", MIN_STOP_GRACE_S, MAX_STOP_GRACE_S, errors)
    return errors, warnings


def _normalise_text(text: Any) -> str | None:
    if not isinstance(text, str):
        return None
    out = text.replace("\r\n", "\n").replace("\r", "\n").rstrip()
    return out or None


def _cost_string(v: Any) -> str | None:
    d = _cost(v)
    if d is None:
        return None
    return format(d.normalize(), "f")


def _tools(v: Any) -> list[str] | None:
    if not isinstance(v, list):
        return None
    return sorted({t for t in v if isinstance(t, str)})


def _asset_scope(v: Any) -> dict | None:
    """The v1.3 block in its hashed form: sorted lists, an empty or absent
    list (or an empty block) left out, None when nothing is restricted."""
    if not isinstance(v, dict):
        return None
    out: dict = {}
    classes = sorted({c for c in v.get("asset_classes") or [] if isinstance(c, str)})
    venues = sorted({x.strip() for x in v.get("venues") or [] if isinstance(x, str) and x.strip()})
    if classes:
        out["asset_classes"] = classes
    if venues:
        out["venues"] = venues
    return out or None


def _tool_pins(v: Any) -> dict | None:
    """The v1.4 block in its hashed form: servers and tools sorted, a server
    with no tools left out, an absent annotations_sha256 left out, None when
    nothing is pinned."""
    if not isinstance(v, dict) or not isinstance(v.get("servers"), dict):
        return None
    servers: dict = {}
    for sname in sorted(k for k in v["servers"] if isinstance(k, str)):
        sv = v["servers"][sname]
        tools_in = sv.get("tools") if isinstance(sv, dict) else None
        if not isinstance(tools_in, dict):
            continue
        tools_out: dict = {}
        for tname in sorted(k for k in tools_in if isinstance(k, str)):
            entry = tools_in[tname]
            if not isinstance(entry, dict) or not entry.get("definition_sha256"):
                continue
            item = {"definition_sha256": entry["definition_sha256"]}
            if entry.get("annotations_sha256"):
                item["annotations_sha256"] = entry["annotations_sha256"]
            tools_out[tname] = item
        if tools_out:
            servers[sname] = {"tools": tools_out}
    return {"servers": servers} if servers else None


def normalise(doc: dict) -> dict:
    """The document with every default applied, in the one form that hashes.

    Call on a document check() accepted. Tool lists are sorted with
    duplicates removed, mandate text has its line endings turned into \\n and
    trailing whitespace removed, max_cost_usd becomes a decimal string, and
    x- extension fields and fields from a newer revision are dropped.

    A field added after v1.0 (stop_grace_s, the two transaction limits, whose
    amounts become decimal strings, and asset_scope, whose lists are sorted) is in the result only when the
    document sets it, so a document that leaves it out hashes exactly as it
    did under v1.0."""
    agent = doc.get("agent") or {}
    tools = doc.get("tools") or {}
    dele = {**DEFAULTS["delegation"], **(doc.get("delegation") or {})}
    oi = {**DEFAULTS["output_inspection"], **{
        k: v for k, v in (doc.get("output_inspection") or {}).items() if k in INSPECTION_SWITCHES
    }}
    out = {
        "spec": SPEC_ID,
        "agent": {
            "name": agent.get("name"),
            "id": agent.get("id"),
            "external_id": agent.get("external_id"),
        },
        "environment": doc.get("environment"),
        "mandate": _normalise_text(doc.get("mandate")),
        "mode": doc.get("mode", DEFAULTS["mode"]),
        "on_stale_snapshot": doc.get("on_stale_snapshot", DEFAULTS["on_stale_snapshot"]),
        "max_staleness_s": doc.get("max_staleness_s", DEFAULTS["max_staleness_s"]),
        "tools": {
            "allowed": _tools(tools.get("allowed")),
            "prohibited": _tools(tools.get("prohibited")) or [],
        },
        "max_steps_per_run": doc.get("max_steps_per_run"),
        "max_cost_usd": _cost_string(doc.get("max_cost_usd")),
        "delegation": {"policy": dele["policy"], "max_depth": dele["max_depth"]},
        "output_inspection": oi,
        "on_violation": doc.get("on_violation", DEFAULTS["on_violation"]),
    }
    if doc.get("stop_grace_s") is not None:
        out["stop_grace_s"] = doc["stop_grace_s"]
    for key in TRANSACTION_LIMIT_KEYS:
        if doc.get(key) is not None:
            out[key] = _cost_string(doc[key])
    scope = _asset_scope(doc.get("asset_scope"))
    if scope is not None:
        out["asset_scope"] = scope
    pins = _tool_pins(doc.get("tool_pins"))
    if pins is not None:
        out["tool_pins"] = pins
    return out


def merge(current: dict, incoming: dict) -> dict:
    """MANDATE_SPEC.md §5: `incoming`'s stated fields over a mandate a system
    already holds. Fields `incoming` leaves out keep `current`'s value; the
    nested blocks (tools, delegation, output_inspection) merge per key.
    `spec`, `agent` and x- fields of `incoming` are not mandate content and
    are not merged."""
    out = {k: (dict(v) if isinstance(v, dict) else v) for k, v in current.items()}
    for key, value in incoming.items():
        if key in ("spec", "agent") or key not in _TOP_KEYS:
            continue
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key].update(value)
        else:
            out[key] = value
    return out


def changes(before: dict, after: dict) -> list[dict]:
    """The mandate fields that differ between two valid documents, compared in
    normalised form, as [{"field": "tools.prohibited", "old": ..., "new": ...}]
    in the order of section 6.1. Identity (spec, agent) is not compared. A
    field only one side has (one added after v1.0, set on that side alone)
    is compared too, with None for the side that leaves it out."""
    def flat(doc: dict) -> dict:
        out: dict = {}
        for key, value in normalise(doc).items():
            if key in ("spec", "agent", "tool_pins"):
                continue
            if isinstance(value, dict) and key != "asset_scope":
                out.update({f"{key}.{sub}": v for sub, v in value.items()})
            else:
                out[key] = value
        return out
    a, b = flat(before), flat(after)
    keys = list(a) + [k for k in b if k not in a]
    out = [{"field": k, "old": a.get(k), "new": b.get(k)} for k in keys if a.get(k) != b.get(k)]
    pa, pb = _pin_map(before), _pin_map(after)
    for server, tool in sorted(set(pa) | set(pb)):
        ta, tb = pa.get((server, tool)), pb.get((server, tool))
        # A server name cannot contain "/" but a tool name can contain anything,
        # so "server/tool" is unambiguous where "server.tool" is not. The
        # structured server, tool and part keys are the authority; field is
        # for display.
        field = f"tool_pins.{server}/{tool}"
        if ta is None or tb is None:
            out.append({"field": field, "old": ta, "new": tb, "server": server, "tool": tool, "part": None})
            continue
        for part in ("definition", "annotations"):
            old, new = ta.get(f"{part}_sha256"), tb.get(f"{part}_sha256")
            if old != new:
                out.append({"field": f"{field}.{part}", "old": old, "new": new,
                            "server": server, "tool": tool, "part": part})
    return out


def _pin_map(doc: dict) -> dict:
    """{(server, tool): {"definition_sha256": ..., "annotations_sha256": ...}} in normalised form."""
    out: dict = {}
    for server, sv in ((normalise(doc).get("tool_pins") or {}).get("servers") or {}).items():
        for tool, entry in sv["tools"].items():
            out[(server, tool)] = entry
    return out


def _es6_number(v: float) -> str:
    """A number the way RFC 8785 writes it (the ECMAScript number-to-string rules)."""
    if v != v or v in (float("inf"), float("-inf")):
        raise ValueError("JSON cannot hold NaN or infinity")
    if v == 0:
        return "0"
    sign = "-" if v < 0 else ""
    t = Decimal(repr(abs(v))).as_tuple()
    all_digits = "".join(str(d) for d in t.digits)
    n = len(all_digits) + t.exponent  # the value is 0.<digits> x 10**n
    digits = all_digits.rstrip("0") or "0"
    k = len(digits)
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        mant = digits if k == 1 else digits[0] + "." + digits[1:]
        body = f"{mant}e{'+' if e >= 0 else '-'}{abs(e)}"
    return sign + body


def _jcs_string(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("a string with an unpaired surrogate is not valid Unicode and cannot be hashed") from None
    return json.dumps(s, ensure_ascii=False)


def jcs(obj: Any) -> str:
    """RFC 8785 JSON Canonicalization Scheme, for the tool hashes. It differs
    from canonical_bytes() (which hashes the mandate document and is not
    changed) on number formatting and on key order for characters outside the
    Basic Multilingual Plane, and JSON Schema carries numbers."""
    if obj is None:
        return "null"
    if obj is True:
        return "true"
    if obj is False:
        return "false"
    if isinstance(obj, int):
        if abs(obj) > 2 ** 53:
            raise ValueError("an integer beyond 2**53 is not exactly representable in JSON")
        return str(obj)
    if isinstance(obj, float):
        return _es6_number(obj)
    if isinstance(obj, str):
        return _jcs_string(obj)
    if isinstance(obj, (list, tuple)):
        return "[" + ",".join(jcs(x) for x in obj) + "]"
    if isinstance(obj, dict):
        for k in obj:
            if not isinstance(k, str):
                raise ValueError("a JSON object key must be a string")
        items = sorted(obj.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(v) for k, v in items) + "}"
    raise ValueError(f"cannot canonicalise a {type(obj).__name__}")


_TOOL_DEFINITION_FIELDS = ("name", "description", "inputSchema", "outputSchema")


def tool_definition_form(tool: dict) -> dict:
    """What definition_sha256 covers: name, description, inputSchema and
    outputSchema when present. A field the protocol version does not have is
    left out, never written as null."""
    if not isinstance(tool, dict) or not isinstance(tool.get("name"), str) or not tool["name"]:
        raise ValueError("a tool needs a name")
    return {k: tool[k] for k in _TOOL_DEFINITION_FIELDS if tool.get(k) is not None}


def tool_annotations_form(tool: dict) -> dict:
    """What annotations_sha256 covers: the title and the annotation hints. The
    title is read from the top-level title, else from annotations.title (the
    2024-11-05 protocol kept it there), and is always written top-level."""
    ann = tool.get("annotations")
    ann = ann if isinstance(ann, dict) else {}
    title = tool.get("title")
    if title is None:
        title = ann.get("title")
    out = {k: v for k, v in ann.items() if k != "title" and v is not None}
    if title is not None:
        out["title"] = title
    return out


def tool_definition_sha256(tool: dict) -> str:
    """Lowercase hex SHA-256 of the RFC 8785 form of tool_definition_form(tool)."""
    return hashlib.sha256(jcs(tool_definition_form(tool)).encode("utf-8")).hexdigest()


def tool_annotations_sha256(tool: dict) -> str | None:
    """The same for tool_annotations_form(tool); None when the tool has neither
    a title nor annotations, so no hash is pinned for it. _meta and icons are
    not covered by either hash."""
    form = tool_annotations_form(tool)
    return hashlib.sha256(jcs(form).encode("utf-8")).hexdigest() if form else None


def canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def document_sha256(doc: dict) -> str:
    """Lowercase hex SHA-256 of the canonical JSON of normalise(doc)."""
    return hashlib.sha256(canonical_bytes(normalise(doc))).hexdigest()


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    want_hash = "--hash" in args
    paths = [a for a in args if a != "--hash"]
    if len(paths) != 1:
        print("usage: mandate_format.py FILE [--hash]", file=sys.stderr)
        return 2
    try:
        with open(paths[0], encoding="utf-8") as fh:
            doc = parse_text(fh.read())
    except (OSError, UnicodeDecodeError, MandateFileError) as exc:
        print(f"cannot read {paths[0]}: {exc}", file=sys.stderr)
        return 2
    errors, warnings = check(doc)
    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")
    if errors:
        print(f"INVALID: {len(errors)} problem(s) in {paths[0]}")
        return 1
    print(f"VALID: {paths[0]} is a {SPEC_ID} mandate")
    if want_hash:
        print(f"sha256 {document_sha256(doc)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
