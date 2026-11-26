"""coriqo-mcp --shield-dir: sealed tool rows that match the ledger's steps."""

from __future__ import annotations

import argparse

import pytest

from byoai.integrations.coriqo_mcp import Interposer, _build_recorder, _parser
from byoai.integrations.coriqo_mcp_receipts import ReceiptSink
from byoai.recorder.coriqo_agents import read_tool_steps
from byoai.recorder.keys import load_or_create_device_key
from byoai.recorder.ledger import Ledger
from byoai.recorder.verdicts import VerdictRecorder, use_verdict_recorder

from .test_coriqo_mcp import ENFORCE, arguments_sha256, call, file_gate


def _run(tmp_path, *, shield: bool):
    key_dir = tmp_path / "rec"
    load_or_create_device_key(key_dir)
    ledger = Ledger(key_dir / "ledger.db", "device-test")
    verdicts = VerdictRecorder(ledger=ledger, session_id="coriqo-mcp")
    interposer = Interposer(file_gate(ENFORCE), run_id="mcp-run-1")
    sink = None
    if shield:
        sink = ReceiptSink(verdicts, shield_dir=tmp_path / "shield", key_dir=key_dir)
        interposer.receipts = sink
    with use_verdict_recorder(verdicts):
        interposer.gate_request(call("search", q="SECRET-VALUE-123"))
        interposer.gate_request(call("delete_account", account="A-1"))
    return ledger, sink


def test_off_is_unchanged(tmp_path):
    ledger, sink = _run(tmp_path, shield=False)
    kinds = [e.event.kind for e in ledger.iter_entries()]
    ledger.close()
    assert sink is None
    assert kinds == ["mandate_verdict", "mandate_verdict"]
    assert not (tmp_path / "shield").exists()


def test_flag_defaults_to_off_and_build_recorder_makes_no_sink(tmp_path):
    assert _parser().parse_args(["--mandate", "m", "--", "x"]).shield_dir is None
    args = argparse.Namespace(no_record=False, recorder_dir=str(tmp_path / "r"))
    record = _build_recorder(args, None)
    try:
        assert record is not None and record.receipts is None
    finally:
        record.recorder.close()
    assert not (tmp_path / "shield").exists()


def test_on_seals_rows_whose_hash_matches_the_step_and_never_holds_args(tmp_path):
    ledger, sink = _run(tmp_path, shield=True)
    steps = read_tool_steps(ledger, "mcp-run-1")
    entries = list(ledger.iter_entries())
    ledger.close()
    # One tool_use, for the allowed call only; denied calls have no step.
    assert [s.tool_name for s in steps] == ["search"]
    uses = [e.event for e in entries if e.event.kind == "tool_use"]
    assert uses[0].payload == {
        "tool": "search", "arguments_sha256": arguments_sha256({"q": "SECRET-VALUE-123"}),
    }
    assert "SECRET-VALUE-123" not in repr([e.event.payload for e in entries])

    found = sink.feed.seals.receipts_for_payload_hashes({steps[0].args_hash})
    assert steps[0].args_hash in found
    rows = [e["payload"] for e, _ in sink.feed.seals._scan_log()]
    assert sorted(r["mandate_verdict"] for r in rows) == ["allowed", "blocked"]
    assert {r["payload_hash"] for r in rows if r["mandate_verdict"] == "allowed"} == {
        steps[0].args_hash}
    assert "SECRET-VALUE-123" not in sink.feed.cfg.ledger.read_text()
    assert list(sink.sessions) == ["mcp-run-1"]


@pytest.mark.asyncio
async def test_close_publishes_once_with_the_seal_chain_only_when_shipping(tmp_path, monkeypatch):
    from byoai.integrations import coriqo_mcp
    from byoai.recorder import coriqo_agents

    seen = []
    monkeypatch.setattr(coriqo_agents, "publish_session",
                        lambda client, **kw: seen.append(kw))
    creds = coriqo_agents.CoriqoCredentials("http://x", "k", "t")
    monkeypatch.setattr(coriqo_agents.CoriqoCredentials, "from_env", classmethod(lambda cls: creds))

    class Rec:
        payload_mode = "redacted"
        key = None
        ledger = object()

        def close(self, **_kw):
            pass

    class Shipper:
        async def ship_once(self):
            return None

    feed = type("F", (), {"seals": "CHAIN"})()
    sink = type("S", (), {"sessions": {"s1": None, "s2": None}, "feed": feed})()
    rec = coriqo_mcp._Record(Rec(), None, Shipper())
    rec.receipts, rec.agent_id = sink, "agt_1"
    await rec.close()
    assert [k["session_id"] for k in seen] == ["s1", "s2"]
    assert all(k["seal_chain"] == "CHAIN" and k["coriqo_agent_id"] == "agt_1" for k in seen)

    seen.clear()
    rec = coriqo_mcp._Record(Rec(), None, None)  # not shipping
    rec.receipts, rec.agent_id = sink, "agt_1"
    await rec.close()
    assert seen == []
