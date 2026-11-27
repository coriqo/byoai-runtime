"""U1.1: the Shield row -> envelope adapter, checked against the v1 schema."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

jsonschema = pytest.importorskip("jsonschema")

from byoai.integrations.shield_events import adapt_agent_event, adapt_row  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((ROOT / "src" / "byoai" / "shield_envelope.schema.json").read_text())
FIXTURES = ROOT / "tests" / "fixtures" / "shield_envelope" / "valid"
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)

LEDGER_KINDS = [
    "browser.chat.request", "browser.chat.reply", "browser.chat.status",
    "browser.chat.attachment", "browser.health.unmatched", "browser.health.core_missing",
    "desktop.chat.request", "desktop.chat.response", "desktop.chat.attachment",
    "desktop.verdict.denied", "desktop.meta", "desktop.health.unmatched",
    "tool.call", "tool.result", "tool.error",
]
ENVELOPE_KEYS = {"envelope_version", "ai_event_type", "evidence_level", "collector",
                 "policy_action", "outcome", "model", "tool"}
CORE = ("ai_event_type", "evidence_level", "collector", "policy_action", "outcome")


def _source(kind: str) -> dict:
    """The row as the collector wrote it: the fixture minus envelope fields."""
    row = json.loads((FIXTURES / f"{kind}.json").read_text())
    return {k: v for k, v in row.items() if k not in ENVELOPE_KEYS}


def _tool_name(kind: str, src: dict) -> dict:
    # Real tool.* rows carry the tool name as a bare string.
    if kind.startswith("tool."):
        fx = json.loads((FIXTURES / f"{kind}.json").read_text())
        return {**src, "tool": fx["tool"]["name"]}
    return src


def _check(envs: list[dict]) -> None:
    assert envs
    for e in envs:
        VALIDATOR.validate(e)


@pytest.mark.parametrize("kind", LEDGER_KINDS)
def test_fixture_rows_adapt_to_valid_envelopes(kind):
    envs = adapt_row(_tool_name(kind, _source(kind)))
    _check(envs)
    fx = json.loads((FIXTURES / f"{kind}.json").read_text())
    first = envs[0]
    if kind == "browser.chat.reply":
        assert first["ai_event_type"] == "ai.model.response"
        first = envs[1]
    for key in CORE:
        assert first[key] == fx[key], (kind, key)


def test_unknown_fields_and_text_are_dropped():
    envs = adapt_row({"kind": "browser.chat.request", "app": "claude", "chars": 3,
                      "verdict": "observe", "prompt": "secret", "text": "x",
                      "preview": "hi", "name": "report.pdf", "weird": 1})
    _check(envs)
    assert set(envs[0]) <= {"kind", "app", "chars", "verdict", "envelope_version",
                            *CORE, "model"}


def test_unknown_kind_gives_nothing():
    assert adapt_row({"kind": "scanner.x"}) == []
    assert adapt_row({"kind": "desktop.chat.zzz"}) == []
    assert adapt_row("nope") == []  # type: ignore[arg-type]


def test_model_never_invented():
    for kind in ("browser.chat.request", "desktop.chat.request", "desktop.chat.response",
                 "browser.chat.reply"):
        for e in adapt_row({"kind": kind, "app": "deepseek", "target": "api.deepseek.com"}):
            if "model" in e:
                assert e["model"] == {"identification": "unknown"}


def test_model_taken_only_when_row_carries_it():
    req = adapt_row({"kind": "desktop.chat.request", "app": "mistral",
                     "model": "mistral-large-latest"})[0]
    assert req["model"] == {"identification": "observed", "name": "mistral-large-latest",
                            "source": "request_field"}
    resp = adapt_row({"kind": "desktop.chat.response", "model": "gpt-x"})[0]
    assert resp["model"]["source"] == "response_field"
    bad = adapt_row({"kind": "desktop.chat.request", "model": "not a model!!"})[0]
    assert bad["model"] == {"identification": "unknown"}
    _check([req, resp, bad])


def test_reply_tools_are_requested_not_executed():
    envs = adapt_row({"kind": "browser.chat.reply", "app": "chatgpt",
                      "tools": ["web_search", "code"]})
    _check(envs)
    assert [e["ai_event_type"] for e in envs] == [
        "ai.model.response", "ai.tool_call.requested", "ai.tool_call.requested"]
    for e in envs[1:]:
        assert e["evidence_level"] == "observed_requested"
        assert e["tool"]["status"] == "requested"
    assert [e["tool"]["name"] for e in envs[1:]] == ["web_search", "code"]


@pytest.mark.parametrize(("verdict", "action", "outcome"), [
    ("redacted(2)", "redact", "sent_redacted"), ("blocked", "block", "blocked"),
    ("observe", "observe", "sent"), ("warned->sent", "warn", "sent"),
    ("warned->cancelled", "warn", "cancelled")])
def test_browser_request_verdicts(verdict, action, outcome):
    e = adapt_row({"kind": "browser.chat.request", "verdict": verdict})[0]
    assert (e["policy_action"], e["outcome"]) == (action, outcome)
    _check([e])


def test_desktop_warn_outcome_depends_on_redactions():
    warn = {"kind": "desktop.chat.request", "action": "warn", "verdict": "observe"}
    a = adapt_row({**warn, "redactions": ["email"], "verdict": "redacted(1)"})[0]
    b = adapt_row({**warn, "redactions": []})[0]
    assert (a["policy_action"], a["outcome"]) == ("warn", "sent_redacted")
    assert (b["policy_action"], b["outcome"]) == ("warn", "sent")


def test_status_row_outcome():
    assert adapt_row({"kind": "browser.chat.status", "ok": True})[0]["outcome"] == "answered"
    assert adapt_row({"kind": "browser.chat.status", "ok": False})[0]["outcome"] == "failed"


def test_attachment_verdicts():
    ok = adapt_row({"kind": "desktop.chat.attachment", "verdict": "allowed"})[0]
    no = adapt_row({"kind": "browser.chat.attachment", "verdict": "blocked"})[0]
    assert (ok["policy_action"], ok["outcome"]) == ("allow", "uploaded")
    assert (no["policy_action"], no["outcome"]) == ("block", "blocked")


def test_meta_not_covered_is_unobservable_and_null_app_is_omitted():
    e = adapt_row({"kind": "desktop.meta", "app": None, "target": "x.ai",
                   "not_covered": "certificate pinned"})[0]
    assert e["ai_event_type"] == "ai.app.discovered"
    assert e["evidence_level"] == "unobservable_payload"
    assert "app" not in e
    v = adapt_row({"kind": "desktop.meta", "app": "claude", "path": "/api/x"})[0]
    assert (v["ai_event_type"], v["evidence_level"]) == ("ai.app.visited", "observed")
    _check([e, v])


def test_tool_rows_are_a_gate_decision_not_execution():
    call = adapt_row({"kind": "tool.call", "tool": "read_file", "call_id": "abc123",
                      "mandate_verdict": "flagged", "payload_hash": "sha256:" + "e" * 64})[0]
    res = adapt_row({"kind": "tool.result", "tool": "read_file", "call_id": "abc123"})[0]
    err = adapt_row({"kind": "tool.error", "tool": "rm", "call_id": "abc124",
                     "error_type": "mandate_blocked"})[0]
    assert (call["policy_action"], call["outcome"]) == ("flag", "allowed")
    assert res["ai_event_type"] == "ai.tool.result" and res["tool"]["status"] == "result"
    assert (err["policy_action"], err["outcome"]) == ("block", "denied")
    for e in (call, res, err):
        assert e["tool"]["status"] != "executed"
        assert "execution_source" not in e["tool"]
    _check([call, res, err])


def test_visit_derived_once_per_app_per_day():
    seen: set = set()
    row = {"kind": "browser.chat.request", "app": "claude",
           "wall_clock": "2026-11-27 10:00:00"}
    first = adapt_row(row, seen_visits=seen)
    again = adapt_row(row, seen_visits=seen)
    nextday = adapt_row({**row, "wall_clock": "2026-11-28 09:00:00"}, seen_visits=seen)
    assert [e["ai_event_type"] for e in first] == ["ai.model.requested", "ai.app.visited"]
    assert len(again) == 1 and len(nextday) == 2
    _check(first + nextday)
    assert len(adapt_row(row)) == 1  # no state, no visit row


def _event(kind, **kw):
    base = dict(kind=kind, tool_name=None, tool_use_id=None, model=None,
                provider="anthropic", payload={})
    return SimpleNamespace(**{**base, **kw})


def test_recorder_events():
    use = adapt_agent_event(_event("tool_use", tool_name="search", tool_use_id="toolu_01",
                                   model="claude-sonnet-5-5"))
    use2 = adapt_agent_event(_event("tool_use", tool_name="search"))
    res = adapt_agent_event(_event("tool_result", tool_name="search"))
    exe = adapt_agent_event(_event("tool_result", tool_name="refund"), governed=True)
    ver = adapt_agent_event(_event("mandate_verdict", tool_name="rm",
                                   provider="coriqo-mandate", payload={"verdict": "blocked"}))
    assert use and use2 and res and exe and ver
    _check([use, use2, res, exe, ver])
    assert use["model"] == {"identification": "observed", "name": "claude-sonnet-5-5",
                            "provider": "anthropic", "source": "event_field"}
    assert use["tool"]["call_id"] == "toolu_01"
    assert use2["model"] == {"identification": "unknown"}
    assert res["tool"]["status"] == "result"
    assert exe["ai_event_type"] == "ai.tool.executed" and exe["collector"] == "governed_tool"
    assert (ver["policy_action"], ver["outcome"]) == ("block", "denied")


def test_recorder_other_kinds_ignored_and_dict_events_ok():
    assert adapt_agent_event(_event("message")) is None
    d = adapt_agent_event({"kind": "tool_use", "tool_name": "t", "model": None})
    assert d and d["kind"] == "tool_use"
    _check([d])


def test_inputs_not_mutated():
    row = {"kind": "browser.chat.reply", "tools": ["a"], "prompt": "p"}
    snap = json.loads(json.dumps(row))
    adapt_row(row)
    assert row == snap


def test_app_is_normalised_not_dropped():
    e = adapt_row({"kind": "browser.chat.request", "app": "Claude-Desktop"},
                  seen_visits=set())
    _check(e)
    assert all(v["app"] == "claude_desktop" for v in e) and len(e) == 1 or len(e) == 2


def test_free_text_fields_are_sanitised():
    e = adapt_row({"kind": "desktop.health.unmatched", "app": "claude",
                   "path": "/search?q=my secret prompt", "target": "https://x/?t=1",
                   "reason": "the user typed a password"})[0]
    assert e["path"] == "/search" and "target" not in e and "reason" not in e
    ok = adapt_row({"kind": "desktop.health.unmatched", "target": "Claude.ai"})[0]
    assert ok["target"] == "claude.ai"
    _check([e, ok])


def test_tool_error_that_is_not_a_denial_is_a_failure():
    e = adapt_row({"kind": "tool.error", "tool": "t", "error_type": "timeout"})[0]
    assert (e["policy_action"], e["outcome"]) == ("none", "failed")
    _check([e])
