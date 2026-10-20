"""Reference reader for the Coriqo mandate file, `coriqo.mandate.yaml` v1 (revision 1.1).

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
SPEC_MINOR = 1  # the newest v1 revision this reader knows
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

# What a reader that enforces from the file alone applies to a field the file
# leaves out. A field missing here (environment, mandate, tools.allowed, the
# two budgets, stop_grace_s) has no default: absent means "not set" (no
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


def normalise(doc: dict) -> dict:
    """The document with every default applied, in the one form that hashes.

    Call on a document check() accepted. Tool lists are sorted with
    duplicates removed, mandate text has its line endings turned into \\n and
    trailing whitespace removed, max_cost_usd becomes a decimal string, and
    x- extension fields and fields from a newer revision are dropped.

    A field added after v1.0 (stop_grace_s) is in the result only when the
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
            if key in ("spec", "agent"):
                continue
            if isinstance(value, dict):
                out.update({f"{key}.{sub}": v for sub, v in value.items()})
            else:
                out[key] = value
        return out
    a, b = flat(before), flat(after)
    keys = list(a) + [k for k in b if k not in a]
    return [{"field": k, "old": a.get(k), "new": b.get(k)} for k in keys if a.get(k) != b.get(k)]


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
