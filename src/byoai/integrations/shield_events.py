"""Map existing Shield rows to Shield event envelope v1 (docs/shield-event-envelope.md).

Pure functions: no network, no ledger writes, no input mutation. Fields not on
the allowlist are dropped (message text included). A model name is only used
when the row itself carries one; execution is never inferred.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, MutableSet
from typing import Any

# Existing row fields an envelope row may keep. Everything else is dropped,
# including `preview` (message-derived) and a raw file `name`.
_KEEP = (
    "wall_clock", "chars", "wire", "sent_at", "row_id", "send_id", "stage",
    "gate_id", "flags", "redactions", "verdict", "tools", "sources", "mime",
    "bytes", "sha256", "name_hash", "scanned", "rules_version", "ok", "status",
    "action", "text_hmac", "not_covered", "call_id", "payload_hash",
    "mandate_verdict", "error_type",
)
_APP = re.compile(r"^[a-z0-9_]{1,40}$")
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,127}$")
_TOOL = re.compile(r"^[A-Za-z0-9_.:-]{1,48}$")
_CALL = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_HOST = re.compile(r"^[a-z0-9._:-]{1,253}$")
_REASON = re.compile(r"^[a-z_]{1,40}$")
_PROVIDER = re.compile(r"^[a-z0-9_]{1,40}$")

_MANDATE = {"allowed": ("allow", "allowed"), "flagged": ("flag", "allowed"),
            "blocked": ("block", "denied"), "pending_approval": ("pending_approval", "unknown")}
_BROWSER_VERDICT = {"blocked": ("block", "blocked"), "observe": ("observe", "sent"),
                    "warned->sent": ("warn", "sent"), "warned->cancelled": ("warn", "cancelled")}

_FIXED = {  # kind -> (ai_event_type, collector)
    "browser.chat.request": ("ai.model.requested", "browser_extension"),
    "browser.chat.reply": ("ai.model.response", "browser_extension"),
    "browser.chat.status": ("ai.model.response", "browser_extension"),
    "browser.chat.attachment": ("ai.data.attachment", "browser_extension"),
    "browser.health.unmatched": ("ai.collector.health", "browser_extension"),
    "browser.health.core_missing": ("ai.collector.health", "browser_extension"),
    "desktop.chat.request": ("ai.model.requested", "desktop_proxy"),
    "desktop.chat.response": ("ai.model.response", "desktop_proxy"),
    "desktop.chat.attachment": ("ai.data.attachment", "desktop_proxy"),
    "desktop.verdict.denied": ("ai.policy.enforced", "desktop_proxy"),
    "desktop.meta": ("ai.app.visited", "desktop_proxy"),
    "desktop.health.unmatched": ("ai.collector.health", "desktop_proxy"),
    "tool.call": ("ai.tool_call.requested", "mcp_interposer"),
    "tool.result": ("ai.tool.result", "mcp_interposer"),
    "tool.error": ("ai.tool.result", "mcp_interposer"),
}


def _model(row: Mapping[str, Any], source: str) -> dict[str, str]:
    name = row.get("model")
    if isinstance(name, str) and _MODEL.fullmatch(name):
        return {"identification": "observed", "name": name, "source": source}
    return {"identification": "unknown"}


def _decision(kind: str, row: Mapping[str, Any]) -> tuple[str, str]:
    """(policy_action, outcome) for one existing row."""
    verdict = row.get("verdict")
    if kind == "browser.chat.request":
        if isinstance(verdict, str) and verdict.startswith("redacted("):
            return "redact", "sent_redacted"
        return _BROWSER_VERDICT.get(verdict, ("none", "unknown")) if isinstance(verdict, str) \
            else ("none", "unknown")
    if kind == "desktop.chat.request":
        if row.get("action") == "warn":
            return "warn", "sent_redacted" if row.get("redactions") else "sent"
        if isinstance(verdict, str) and verdict.startswith("redacted("):
            return "redact", "sent_redacted"
        if verdict == "observe":
            return "observe", "sent"
        return "none", "sent"
    if kind in ("browser.chat.attachment", "desktop.chat.attachment"):
        return {"allowed": ("allow", "uploaded"), "blocked": ("block", "blocked")}.get(
            verdict if isinstance(verdict, str) else "", ("none", "unknown"))
    if kind == "desktop.verdict.denied":
        return "block", "blocked"
    if kind in ("browser.chat.reply", "desktop.chat.response"):
        return "none", "answered"
    if kind == "browser.chat.status":
        return "none", "failed" if row.get("ok") is False else "answered"
    if kind == "tool.call":
        word = row.get("mandate_verdict")
        return _MANDATE.get(word, ("none", "unknown")) if isinstance(word, str) \
            else ("none", "unknown")
    if kind == "tool.result":
        return "allow", "allowed"
    if kind == "tool.error":
        err = row.get("error_type")
        word = err[len("mandate_"):] if isinstance(err, str) and err.startswith("mandate_") else ""
        if word == "pending_approval":
            return "pending_approval", "unknown"
        if word in ("blocked", "flagged"):
            return "block", "denied"
        return "none", "failed"  # a runtime failure, not a policy denial
    return "none", "not_applicable"


def _tool(name: Any, status: str, call_id: Any = None) -> dict[str, str]:
    out: dict[str, str] = {"status": status}
    if isinstance(name, str) and _TOOL.fullmatch(name):
        out["name"] = name
    if isinstance(call_id, str) and _CALL.fullmatch(call_id):
        out["call_id"] = call_id
    return out


def adapt_row(row: Mapping[str, Any],
              seen_visits: MutableSet[tuple[str, str]] | None = None) -> list[dict[str, Any]]:
    """Envelope rows for one ledger row (browser.*, desktop.*, tool.*).

    Returns ``[]`` for a kind it does not know. A reply row with ``tools[]``
    yields its response envelope plus one ``ai.tool_call.requested`` per tool.
    When ``seen_visits`` is given, a request row also yields one
    ``ai.app.visited`` envelope per (app, day), recorded in that set.
    """
    if not isinstance(row, Mapping):
        return []
    kind = row.get("kind")
    if not isinstance(kind, str) or kind not in _FIXED:
        return []
    event_type, collector = _FIXED[kind]
    evidence = "observed"
    if kind == "tool.call":
        evidence = "observed_requested"
    if kind == "desktop.meta" and row.get("not_covered"):
        event_type, evidence = "ai.app.discovered", "unobservable_payload"

    base: dict[str, Any] = {k: row[k] for k in _KEEP if k in row}
    app_raw = row.get("app")
    if isinstance(app_raw, str):
        # Schema tags are [a-z0-9_]; fold other spellings (extra-site names,
        # hosts) onto that rather than losing the app.
        tag = re.sub(r"[^a-z0-9_]", "_", app_raw.lower())[:40]
        if _APP.fullmatch(tag):
            base["app"] = tag
    # path/target/reason are free text in the source rows; keep only safe shapes.
    path = row.get("path")
    if isinstance(path, str):
        base["path"] = re.sub(r"[^A-Za-z0-9/_.:-]", "?", re.split(r"[?#]", path, maxsplit=1)[0])[:60]
    target = row.get("target")
    if isinstance(target, str) and _HOST.fullmatch(target.lower()):
        base["target"] = target.lower()
    reason = row.get("reason")
    if isinstance(reason, str) and _REASON.fullmatch(reason):
        base["reason"] = reason
    ident = row.get("identity")
    client = ident.get("client_name") if isinstance(ident, Mapping) else None
    if isinstance(client, str) and _CALL.fullmatch(client):
        base["identity"] = {"client_name": client}  # nested object: keep only this key
    policy, outcome = _decision(kind, row)
    env: dict[str, Any] = {**base, "kind": kind, "envelope_version": 1,
                           "ai_event_type": event_type, "evidence_level": evidence,
                           "collector": collector, "policy_action": policy, "outcome": outcome}
    if kind in ("browser.chat.request", "desktop.chat.request"):
        env["model"] = _model(row, "request_field")
    elif kind in ("browser.chat.reply", "desktop.chat.response"):
        env["model"] = _model(row, "response_field")
    elif kind.startswith("tool."):
        env["tool"] = _tool(row.get("tool"), "requested" if kind == "tool.call" else "result",
                            row.get("call_id"))
    out = [env]

    if kind in ("browser.chat.reply", "desktop.chat.response"):
        # Schema: any row with a non-empty tools[] is a tool_call.requested row,
        # so the response envelope drops the list and the derived rows carry it.
        tools = row.get("tools")
        env.pop("tools", None)
        for name in (tools if isinstance(tools, list) else []):
            if isinstance(name, str) and _TOOL.fullmatch(name):
                out.append({**{k: v for k, v in env.items() if k not in ("model", "tool")},
                            "ai_event_type": "ai.tool_call.requested",
                            "evidence_level": "observed_requested",
                            "policy_action": "none", "outcome": "not_applicable",
                            "tool": _tool(name, "requested")})

    app, clock = env.get("app"), row.get("wall_clock")
    if (seen_visits is not None and kind in ("browser.chat.request", "desktop.chat.request")
            and isinstance(app, str) and isinstance(clock, str)):
        key = (app, clock[:10])
        if key not in seen_visits:
            seen_visits.add(key)
            out.append({"kind": kind, "app": app, "envelope_version": 1,
                        "ai_event_type": "ai.app.visited", "evidence_level": "observed",
                        "collector": collector, "policy_action": "none",
                        "outcome": "not_applicable",
                        "wall_clock": clock})
    return out


def _get(event: Any, name: str) -> Any:
    return event.get(name) if isinstance(event, Mapping) else getattr(event, name, None)


def adapt_agent_event(event: Any, governed: bool = False) -> dict[str, Any] | None:
    """Derived envelope for a recorder ``AgentEvent`` (or a dict of its fields).

    Never written back into the event payload. ``governed`` marks a
    ``tool_result`` that came from ``@governed_tool``; only then is
    ``ai.tool.executed`` used. Other event kinds return ``None``.
    """
    kind = _get(event, "kind")
    if kind not in ("tool_use", "tool_result", "mandate_verdict"):
        return None
    env: dict[str, Any] = {"kind": kind, "envelope_version": 1, "collector": "recorder",
                           "evidence_level": "observed", "policy_action": "none",
                           "outcome": "not_applicable"}
    name = _get(event, "tool_name")
    if kind == "tool_use":
        env |= {"ai_event_type": "ai.tool_call.requested", "evidence_level": "observed_requested",
                "tool": _tool(name, "requested", _get(event, "tool_use_id"))}
        model = _get(event, "model")
        if isinstance(model, str) and _MODEL.fullmatch(model):
            m = {"identification": "observed", "name": model, "source": "event_field"}
            provider = _get(event, "provider")
            if isinstance(provider, str) and _PROVIDER.fullmatch(provider):
                m["provider"] = provider
            env["model"] = m
        else:
            env["model"] = {"identification": "unknown"}
    elif kind == "tool_result":
        call_id = _get(event, "tool_use_id")
        if governed:
            env |= {"ai_event_type": "ai.tool.executed", "collector": "governed_tool",
                    "evidence_level": "verified",
                    "tool": {**_tool(name, "executed", call_id),
                             "execution_source": "governed_tool"}}
        else:
            env |= {"ai_event_type": "ai.tool.result", "tool": _tool(name, "result", call_id)}
    else:
        payload = _get(event, "payload")
        word = payload.get("verdict") if isinstance(payload, Mapping) else None
        policy, outcome = _MANDATE.get(word, ("none", "unknown")) if isinstance(word, str) \
            else ("none", "unknown")
        env |= {"ai_event_type": "ai.policy.evaluated", "policy_action": policy,
                "outcome": outcome}  # no tool: status=requested would force observed_requested
    return env
