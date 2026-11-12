"""RP-6: a held call's arguments go to Coriqo with its approval request, and
the approved action's ledger entry carries approval_id and amount_usd, never
the raw args (that ledger is append-only and cannot be redacted)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging

import pytest

from byoai.recorder.mandate import (
    Allow,
    ProposedAction,
    Reason,
    RequireApproval,
    approval_amount_usd,
    approval_args,
    approval_request_id,
    mandate_gate,
)
from byoai.recorder.verdicts import ledger_payload

from .test_mandate import FakeClock, snapshot_payload

# Computed once with Coriqo's own api.utils.canonical_hash._canonical_hash
# (the function approval_terms() and the sign-off check both use) over the
# args below as they arrive at the server. Frozen: if this changes, the
# runtime and Coriqo no longer agree on what an approval covers.
ARGS = {
    "to": "acct-42", "amount_usd": 1250.0, "memo": "Zürich invoice", "asset": {"symbol": "USDC"},
}
ARGS_SHA256 = "d4ec4762ef121c26ae842d21add4d5f8f7abde94a08eb318d488892f66eb2d72"
ASSET_ARGS = {"to": "acct-7", "asset": {"symbol": "USDC", "amount_usd": 99.5}}
ASSET_ARGS_SHA256 = "4bf38602d035a2917ac97b414916c24b57d6222ffe29de75abe11e052b5abb66"


def coriqo_hash(obj) -> str:
    """Coriqo's _canonical_hash, restated: sha256 over Python json.dumps."""
    return hashlib.sha256(
        json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str,
        ).encode()
    ).hexdigest()


def over_the_wire(obj):
    return json.loads(json.dumps(obj))


@pytest.fixture(autouse=True)
def _default_flag(monkeypatch):
    monkeypatch.delenv("BYOAI_APPROVAL_SEND_ARGS", raising=False)


@pytest.mark.parametrize("args, expected", [(ARGS, ARGS_SHA256), (ASSET_ARGS, ASSET_ARGS_SHA256)])
def test_fingerprint_matches_coriqo_vector(args, expected):
    sent = approval_args(args)
    assert coriqo_hash(over_the_wire(sent)) == expected
    # 1250.0 and 1250 are one JSON number after canonicalisation.
    assert approval_args({**args}) == approval_args(over_the_wire(approval_args(args)))


class FakeClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def request_tool_approval(self, agent_id, **kw):
        self.calls.append(kw)
        return {}


def _held_report(monkeypatch, flag: str | None) -> dict:
    if flag is not None:
        monkeypatch.setenv("BYOAI_APPROVAL_SEND_ARGS", flag)
    client = FakeClient()

    async def run() -> None:
        gate = mandate_gate("agent-rp6", client=client, clock=FakeClock())
        gate.apply_snapshot(snapshot_payload(approval_required_tools=["wire"]))
        action = ProposedAction(tool="wire", trajectory_id="t1", step_index=3, arguments=ARGS)
        verdict = gate.decide(action)
        assert isinstance(verdict, RequireApproval)
        gate.report_approval_request(verdict)
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    asyncio.run(run())
    assert len(client.calls) == 1
    return client.calls[0]


def test_approval_request_sends_args_by_default(monkeypatch):
    call = _held_report(monkeypatch, None)
    assert coriqo_hash(over_the_wire(call["args"])) == ARGS_SHA256


def test_flag_off_sends_no_args(monkeypatch):
    call = _held_report(monkeypatch, "0")
    assert call["args"] is None


def _approved_payload(arguments):
    verdict = Allow(reason=Reason.APPROVAL_GRANTED, tool="wire", trajectory_id="t1", step_index=3)
    return ledger_payload(verdict, agent_id="agent-rp6", arguments=arguments)


def test_approved_entry_carries_terms_but_no_raw_args():
    payload = _approved_payload(ARGS)
    assert payload["approval_id"] == approval_request_id("wire", "t1", 3, ARGS)
    assert payload["amount_usd"] == 1250
    assert "args" not in payload
    blob = json.dumps(payload, ensure_ascii=False)
    assert "acct-42" not in blob and "Zürich" not in blob


def test_approved_entry_reads_asset_amount():
    payload = _approved_payload(ASSET_ARGS)
    assert payload["amount_usd"] == 99.5
    assert "args" not in payload and "acct-7" not in json.dumps(payload)


def test_flag_off_records_no_amount(monkeypatch):
    monkeypatch.setenv("BYOAI_APPROVAL_SEND_ARGS", "false")
    payload = _approved_payload(ARGS)
    assert "amount_usd" not in payload and "args" not in payload
    assert payload["approval_id"]


@pytest.mark.parametrize("bad", ["1250", True, False, None, [1], {"v": 1}])
def test_non_numeric_amount_is_none(bad, caplog):
    with caplog.at_level(logging.WARNING):
        assert approval_amount_usd({"amount_usd": bad}) is None
        assert approval_amount_usd({"asset": {"amount_usd": bad}}) is None
    assert repr(bad) not in caplog.text or bad is None


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_amount_is_none(bad, caplog):
    with caplog.at_level(logging.WARNING):
        assert approval_amount_usd({"amount_usd": bad}) is None
    assert "amount_usd" in caplog.text and "inf" not in caplog.text.replace("info", "")


def test_unreadable_amount_warns_once(caplog):
    with caplog.at_level(logging.WARNING):
        payload = _approved_payload({"amount_usd": "lots", "to": "x"})
    assert "amount_usd" not in payload
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1
    assert "lots" not in caplog.text


def test_other_verdicts_unchanged():
    verdict = Allow(reason=Reason.IN_SCOPE, tool="search")
    payload = ledger_payload(verdict, agent_id="a", arguments=ARGS)
    assert not {"approval_id", "amount_usd", "args"} & payload.keys()
