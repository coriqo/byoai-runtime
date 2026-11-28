"""Shield Wave 0/1 review finding 7 (adapter): one test per defect."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

jsonschema = pytest.importorskip("jsonschema")

from byoai.integrations.shield_events import adapt_agent_event, adapt_row  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = jsonschema.Draft202012Validator(
    json.loads((ROOT / "src" / "byoai" / "shield_envelope.schema.json").read_text())
)


@pytest.mark.parametrize(
    "extra",
    [
        {"flags": ["free text"]},
        {"flags": ["secret:API-Key"]},
        {"verdict": {"x": "secret text"}},
        {"chars": "lots"},
        {"chars": True},
        {"wall_clock": "2026-01-01T00:00:00"},
        {"wall_clock": "yesterday"},
        {"not_covered": 7},
        {"redactions": ["a"] * 61},
        {"sha256": "nothex"},
    ],
)
def test_malformed_field_is_stripped_but_the_event_survives(extra):
    row = {"kind": "desktop.chat.request", "app": "claude", "action": "warn", **extra}
    envs = adapt_row(row)
    assert envs and envs[0]["ai_event_type"] == "ai.model.requested"
    for k in extra:
        assert k not in envs[0]
    VALIDATOR.validate(envs[0])


@pytest.mark.parametrize(
    "bad",
    [{"flags": ["secret:API-Key"]}, {"wall_clock": "2026-01-01T00:00:00"},
     {"redactions": ["a"] * 61}],
)
def test_block_verdict_survives_a_malformed_optional_field(bad):
    env = adapt_row({"kind": "desktop.chat.request", "verdict": "blocked", **bad})[0]
    assert (env["policy_action"], env["outcome"]) == ("block", "blocked")
    assert env["verdict"] == "blocked"
    red = adapt_row({"kind": "browser.chat.request", "verdict": "redacted(2)", **bad})[0]
    assert (red["policy_action"], red["outcome"]) == ("redact", "sent_redacted")


def test_fields_foreign_to_the_kind_are_not_copied():
    envs = adapt_row({"kind": "browser.chat.request", "tools": ["a"], "not_covered": "x",
                      "app": "chatgpt"})
    assert envs and all("tools" not in e and "not_covered" not in e for e in envs)
    for e in envs:
        VALIDATOR.validate(e)


def test_not_covered_false_is_not_a_discovery_and_truthy_junk_is_dropped():
    covered = adapt_row({"kind": "desktop.meta", "not_covered": False})
    assert covered[0]["ai_event_type"] == "ai.app.visited"
    assert adapt_row({"kind": "desktop.meta", "not_covered": "no way truly: ok"})[0][
        "ai_event_type"] == "ai.app.discovered"
    junk = adapt_row({"kind": "desktop.meta", "not_covered": ["x"]})[0]
    assert junk["ai_event_type"] == "ai.app.visited" and "not_covered" not in junk


def test_blocked_request_is_not_reported_as_sent():
    env = adapt_row({"kind": "desktop.chat.request", "verdict": "blocked"})[0]
    assert (env["policy_action"], env["outcome"]) == ("block", "blocked")


def test_tool_result_honours_mandate_verdict():
    env = adapt_row({"kind": "tool.result", "mandate_verdict": "blocked"})[0]
    assert (env["policy_action"], env["outcome"]) == ("block", "denied")
    env = adapt_row({"kind": "tool.result", "mandate_verdict": "pending_approval"})[0]
    assert env["policy_action"] == "pending_approval"


def _ev(**kw):
    base = dict(kind="tool_result", tool_name="refund", tool_use_id="toolu_01", model=None,
                provider="x", payload={})
    return SimpleNamespace(**{**base, **kw})


def test_governed_flag_alone_is_not_verified_execution():
    ok = adapt_agent_event(_ev(), governed=True)
    assert ok and ok["ai_event_type"] == "ai.tool.executed" and ok["evidence_level"] == "verified"
    err = adapt_agent_event(_ev(payload={"is_error": True}), governed=True)
    assert err and err["ai_event_type"] == "ai.tool.result" and err["evidence_level"] == "observed"
    assert err["outcome"] == "failed"
    nameless = adapt_agent_event(_ev(tool_name=None), governed=True)
    assert nameless and nameless["ai_event_type"] == "ai.tool.result"
    VALIDATOR.validate(err)
    VALIDATOR.validate(nameless)


def test_adapt_agent_event_never_raises():
    class Hostile:
        def __getattr__(self, name):
            raise RuntimeError(name)

    assert adapt_agent_event(Hostile()) is None
    assert adapt_agent_event(SimpleNamespace(kind="tool_use", tool_name=object())) is not None
    assert adapt_agent_event(None) is None


@pytest.mark.parametrize("verdict", ["redacted(120)", "Redacted(2) extra", "redact-all"])
def test_off_list_redact_verdict_still_reports_redact(verdict):
    d = adapt_row({"kind": "desktop.chat.request", "verdict": verdict})[0]
    b = adapt_row({"kind": "browser.chat.request", "verdict": verdict})[0]
    assert (d["policy_action"], d["outcome"]) == ("redact", "sent_redacted")
    assert (b["policy_action"], b["outcome"]) == ("redact", "sent_redacted")
    assert "verdict" not in d and "verdict" not in b
    VALIDATOR.validate(d)
    VALIDATOR.validate(b)


def test_off_list_block_verdict_still_blocks():
    for kind in ("desktop.chat.request", "browser.chat.request"):
        env = adapt_row({"kind": kind, "verdict": "BLOCKED by rule"})[0]
        assert (env["policy_action"], env["outcome"]) == ("block", "blocked")
        VALIDATOR.validate(env)


@pytest.mark.parametrize("redactions", [["a"] * 61, ["Api_Key"], "api_key"])
def test_warn_with_malformed_redactions_is_still_sent_redacted(redactions):
    env = adapt_row({"kind": "desktop.chat.request", "action": "warn",
                     "redactions": redactions})[0]
    assert (env["policy_action"], env["outcome"]) == ("warn", "sent_redacted")
    assert "redactions" not in env
    VALIDATOR.validate(env)


def test_real_proxy_not_covered_reason_with_comma_is_still_a_discovery():
    env = adapt_row({"kind": "desktop.meta", "app": "perplexity",
                     "not_covered": "proprietary format, not captured"})[0]
    assert env["ai_event_type"] == "ai.app.discovered"
    assert env["evidence_level"] == "unobservable_payload"
    VALIDATOR.validate(env)
