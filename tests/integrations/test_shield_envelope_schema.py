"""U0.1: the Shield event envelope schema against fixtures and real row shapes."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "src" / "byoai" / "shield_envelope.schema.json"
FIXTURES = ROOT / "tests" / "fixtures" / "shield_envelope"

#: Every existing row kind in the spec's section 3.1 mapping.
EXISTING_KINDS = [
    "browser.chat.request", "browser.chat.reply", "browser.chat.status",
    "browser.chat.attachment", "browser.health.unmatched", "browser.health.core_missing",
    "desktop.chat.request", "desktop.chat.response", "desktop.chat.attachment",
    "desktop.verdict.denied", "desktop.meta", "desktop.health.unmatched",
    "tool.call", "tool.result", "tool.error",
    "tool_use", "tool_result", "mandate_verdict",
]


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def test_schema_is_2020_12():
    assert json.loads(SCHEMA_PATH.read_text())["$schema"].endswith("2020-12/schema")


@pytest.mark.parametrize("kind", EXISTING_KINDS)
def test_every_existing_kind_has_a_valid_fixture(validator, kind):
    row = _load(FIXTURES / "valid" / f"{kind}.json")
    assert row["kind"] == kind
    validator.validate(row)


@pytest.mark.parametrize("path", sorted((FIXTURES / "valid").glob("*.json")), ids=lambda p: p.stem)
def test_valid_fixtures_validate(validator, path):
    validator.validate(_load(path))


@pytest.mark.parametrize("path", sorted((FIXTURES / "invalid").glob("*.json")), ids=lambda p: p.stem)
def test_invalid_fixtures_are_rejected(validator, path):
    assert list(validator.iter_errors(_load(path))), f"{path.name} should not validate"


def test_no_ai_value_enters_recorder_event_kind():
    from byoai.recorder.schema import EventKind

    assert not [k.value for k in EventKind if k.value.startswith("ai.")]
    schema = json.loads(SCHEMA_PATH.read_text())
    assert not [v for v in schema["properties"]["ai_event_type"]["enum"]
                if v in {k.value for k in EventKind}]


def test_real_cleaned_browser_row_accepts_the_envelope(validator):
    """Allowlisted fields clean_browser_row really emits must not clash with the schema."""
    from byoai.integrations.shield import clean_browser_row

    cleaned = clean_browser_row({
        "kind": "browser.chat.request", "app": "claude.ai", "chars": 12,
        "stage": "input", "verdict": "redacted(1)", "flags": ["secret:aws_key"],
        "row_id": "abcd1234efgh", "send_id": "send-1234abcd",
        "text": "must be dropped by the allowlist",
    })
    assert cleaned is not None and "text" not in cleaned
    row = {**cleaned, "envelope_version": 1, "ai_event_type": "ai.model.requested",
           "evidence_level": "observed", "collector": "browser_extension",
           "policy_action": "redact", "outcome": "sent_redacted",
           "model": {"identification": "unknown"}}
    validator.validate(row)


def test_real_tool_receipt_rows_accept_the_envelope(validator, tmp_path):
    """Rows ReceiptSink writes to the ledger keep validating once stamped."""
    pytest.importorskip("cryptography")
    from types import SimpleNamespace

    from byoai.integrations.coriqo_mcp_receipts import ReceiptSink

    class _Verdicts:
        def record_tool_use(self, *a, **k):
            return None

    sink = ReceiptSink(_Verdicts(), shield_dir=tmp_path / "s", key_dir=tmp_path / "k")
    sink.note("sess", "read_file", "f" * 64, SimpleNamespace(verdict="allowed", allowed=True))
    sink.note("sess", "delete_file", "f" * 64, SimpleNamespace(verdict="blocked", allowed=False))
    rows = [json.loads(line) for line in (tmp_path / "s" / "ledger.jsonl").read_text().splitlines()]
    kinds = [r["kind"] for r in rows]
    assert kinds == ["tool.call", "tool.result", "tool.call", "tool.error"]
    stamp = {
        "tool.call": ("ai.tool_call.requested", "observed_requested", "requested"),
        "tool.result": ("ai.tool.result", "observed", "result"),
        "tool.error": ("ai.tool.result", "observed", "result"),
    }
    for r in rows:
        t, ev, st = stamp[r["kind"]]
        validator.validate({**r, "envelope_version": 1, "ai_event_type": t,
                            "evidence_level": ev, "collector": "mcp_interposer",
                            "policy_action": "block" if r.get("mandate_verdict") == "blocked" else "allow",
                            "outcome": "denied" if r["kind"] == "tool.error" else "allowed",
                            "tool": {"name": r["tool"], "status": st, "call_id": r["call_id"]}})


def test_frozen_interface_snapshot():
    """A silent edit to a frozen value fails here; changing one is a version bump."""
    s = json.loads(SCHEMA_PATH.read_text())
    assert s["$id"] == "https://coriqo.com/schemas/shield-event-envelope-v1.json"
    assert s["properties"]["envelope_version"] == {"const": 1}
    enums = {k: s["properties"][k]["enum"] for k in
             ("ai_event_type", "evidence_level", "collector", "outcome", "policy_action")}
    assert enums == {
        "ai_event_type": ["ai.model.requested", "ai.model.response", "ai.tool_call.requested",
                          "ai.tool.result", "ai.tool.executed", "ai.data.attachment",
                          "ai.policy.enforced", "ai.policy.evaluated", "ai.app.discovered",
                          "ai.app.visited", "ai.collector.health", "ai.mcp.configured",
                          "ai.runtime.detected"],
        "evidence_level": ["observed", "observed_requested", "inferred", "verified",
                           "unobservable_payload", "unattested"],
        "collector": ["browser_extension", "desktop_proxy", "mcp_interposer", "recorder",
                      "governed_tool", "scanner"],
        "outcome": ["not_applicable", "unknown", "sent", "sent_redacted", "blocked", "cancelled",
                    "answered", "failed", "uploaded", "removed", "allowed", "denied"],
        "policy_action": ["none", "observe", "allow", "flag", "warn", "redact", "block",
                          "pending_approval"],
    }


def test_row_field_set_is_closed(validator):
    s = json.loads(SCHEMA_PATH.read_text())
    assert s["unevaluatedProperties"] is False
    row = _load(FIXTURES / "valid" / "browser.chat.request.json")
    for name in ("file_name", "prompt_text", "Text", "name"):
        assert list(validator.iter_errors({**row, name: "x"})), name
    # a desktop-only field is not allowed on a browser row
    assert list(validator.iter_errors({**row, "target": "claude.ai"}))
    # every string is bounded
    assert list(validator.iter_errors({**row, "wire": "x" * 61}))
    assert list(validator.iter_errors({**row, "flags": ["secret:" + "a" * 100]}))
