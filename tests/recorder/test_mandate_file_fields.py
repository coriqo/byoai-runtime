"""Every field the vendored reader accepts reaches the snapshot the gate enforces."""

from __future__ import annotations

import json
from pathlib import Path

from byoai.recorder import mandate_format
from byoai.recorder.mandate import (
    Allow,
    Deny,
    Flag,
    MandateGate,
    MandateSnapshot,
    Posture,
    ProposedAction,
    Reason,
)
from byoai.recorder.mandate_file import load_mandate_text, snapshot_payload

from .test_mandate import FakeClock

PINS = json.loads(json.dumps(
    mandate_format.parse_text(
        (Path(__file__).resolve().parent.parent / "fixtures" / "mandate" / "tool_pins_set.yaml")
        .read_text(encoding="utf-8")
    )["tool_pins"]
))

#: Reader keys that are identity, format or the mandate's prose, or that
#: reach the snapshot under another name, with where they land.
NOT_MAPPED_BY_NAME = {
    "spec": "format",
    "agent": "identity (agent_id comes from agent.id or agent.name)",
    "mandate": "prose",
    "mode": "mandate_enforcement",
    "on_stale_snapshot": "enforcement_posture",
    "tools": "allowed_tools / prohibited_tools",
    "max_steps_per_run": "max_run_steps",
    "max_cost_usd": "max_run_cost_usd",
    "delegation": "delegation_policy / max_delegation_depth",
}

FULL = {
    "spec": "coriqo.mandate/v1.4",
    "agent": {"name": "payer"},
    "environment": "production",
    "mandate": "Pays invoices.",
    "mode": "enforce",
    "on_stale_snapshot": "fail_closed",
    "max_staleness_s": 600,
    "tools": {"allowed": ["search", "fetch_doc", "stripe.refund", "search_orders"], "prohibited": ["wipe"]},
    "max_steps_per_run": 25,
    "max_cost_usd": 1.5,
    "delegation": {"policy": "attenuated", "max_depth": 1},
    "output_inspection": {"instruction_like": "flag", "secrets": "redact", "pii": "flag"},
    "on_violation": "deny_and_halt_run",
    "stop_grace_s": 30,
    "max_transaction_usd_per_day": 250000,
    "max_transaction_usd": 100.5,
    "asset_scope": {"asset_classes": ["fiat"], "venues": ["bank-wire"]},
    "tool_pins": PINS,
}


def _loaded(doc=None):
    return load_mandate_text(json.dumps(doc or FULL))


def _gate(payload, **kw) -> MandateGate:
    async def never(_etag):  # pragma: no cover
        raise AssertionError

    g = MandateGate(never, agent_id="payer", clock=FakeClock(), **kw)
    g.apply_snapshot(payload)
    return g


def test_every_reader_key_is_mapped_or_explained():
    payload = snapshot_payload(_loaded().normalised, sha256="0" * 64)
    for key in mandate_format._TOP_KEYS:
        assert key in payload or key in NOT_MAPPED_BY_NAME or key in {"agent"}, (
            f"mandate_format accepts {key!r} but snapshot_payload drops it; map it "
            "or list it in NOT_MAPPED_BY_NAME with where it goes"
        )


def test_the_test_document_sets_every_reader_key():
    assert set(FULL) >= set(mandate_format._TOP_KEYS)


def test_every_field_reaches_the_snapshot():
    loaded = _loaded()
    snap = MandateSnapshot.from_payload(loaded.payload(), received_at=0.0)
    assert snap.allowed_tools == ("fetch_doc", "search", "search_orders", "stripe.refund")
    assert snap.prohibited_tools == ("wipe",)
    assert (snap.max_run_steps, snap.max_run_cost_usd) == (25, 1.5)
    assert (snap.delegation_policy, snap.max_delegation_depth) == ("attenuated", 1)
    assert snap.environment == "production" and snap.stop_grace_s == 30
    assert snap.on_violation == "deny_and_halt_run"
    assert snap.max_transaction_usd == 100.5
    assert snap.max_transaction_usd_per_day == 250000.0
    assert snap.asset_classes == ("fiat",) and snap.venues == ("bank-wire",)
    assert snap.unreadable_keys == ("tool_pins",)


def test_a_file_without_the_newer_fields_yields_none_of_their_keys():
    doc = {k: v for k, v in FULL.items() if k not in (
        "stop_grace_s", "max_transaction_usd_per_day", "max_transaction_usd",
        "asset_scope", "tool_pins")}
    payload = _loaded(doc).payload()
    for key in ("max_transaction_usd_per_day", "max_transaction_usd", "asset_scope",
                "tool_pins", "required_fields", "stop_grace_s"):
        assert key not in payload


def _no_pins_payload():
    return _loaded({k: v for k, v in FULL.items() if k != "tool_pins"}).payload()


def test_the_gate_enforces_payment_limits_and_asset_scope_from_a_file():
    g = _gate(_no_pins_payload())
    ok = {"asset_class": "fiat", "venue": "bank-wire", "amount_usd": 100}
    assert isinstance(g.decide(ProposedAction(tool="search", asset=ok)), Allow)
    over = g.decide(ProposedAction(tool="search", asset={**ok, "amount_usd": 100.6}))
    assert isinstance(over, Deny) and over.reason == Reason.TRANSACTION_LIMIT_EXCEEDED
    wrong = g.decide(ProposedAction(tool="search", asset={**ok, "venue": "dex"}))
    assert isinstance(wrong, Deny) and wrong.reason == Reason.VENUE_NOT_ALLOWED


def test_the_daily_limit_comes_from_the_file():
    doc = {k: v for k, v in FULL.items() if k not in ("tool_pins", "max_transaction_usd")}
    g = _gate(_loaded(doc).payload())
    a = {"asset_class": "fiat", "venue": "bank-wire", "amount_usd": 200000}
    assert isinstance(g.decide(ProposedAction(tool="search", asset=a)), Allow)
    d = g.decide(ProposedAction(tool="search", asset={**a, "amount_usd": 60000}))
    assert isinstance(d, Deny) and d.reason == Reason.DAILY_TRANSACTION_LIMIT_EXCEEDED


def test_tool_pins_make_the_gate_report_unreadable_keys_under_the_posture():
    closed = _gate(_loaded().payload())
    assert closed.unreadable_keys == ("tool_pins",)
    verdict = closed.decide("search")
    assert isinstance(verdict, Deny) and verdict.reason == Reason.SNAPSHOT_UNREADABLE
    opened = _gate(_loaded({**FULL, "on_stale_snapshot": "fail_open"}).payload())
    verdict = opened.decide("search")
    assert isinstance(verdict, Flag) and verdict.reason == Reason.SNAPSHOT_UNREADABLE
    assert closed.posture == Posture.FAIL_CLOSED
