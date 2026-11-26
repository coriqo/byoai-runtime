"""M2: all 8 agents complete end-to-end; B2/B4/H1 show a correctly-attributed
sub-agent span. No network access — every run exercises the fallback path.
"""

from __future__ import annotations

import pytest
from examples.agent_showcase.agents.registry import list_agents
from examples.agent_showcase.app import app
from fastapi.testclient import TestClient

from byoai.recorder import integration as recorder_integration
from byoai.recorder.verify import verify_ledger

ALL_AGENT_IDS = [a.id for a in list_agents()]
SUB_AGENT_PARENTS = {
    "b2-kyc-onboarding": "b2-sub-sanctions-screener",
    "b4-loan-prequalification": "b4-sub-document-extractor",
    "h1-prior-authorization": "h1-sub-criteria-matcher",
}


@pytest.fixture
def demo_client(tmp_path, monkeypatch):
    monkeypatch.setenv("BYOAI_RECORDER_ENABLED", "1")
    monkeypatch.setenv("BYOAI_RECORDER_DIR", str(tmp_path / "ledger"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    recorder_integration.reset_recorder_for_tests()
    with TestClient(app) as client:
        yield client, tmp_path / "ledger"
    recorder_integration.reset_recorder_for_tests()


def _run_to_completion(client, agent_id):
    started = client.post(f"/api/agents/{agent_id}/run").json()
    run_id = started["run_id"]
    summary = None
    for _ in range(200):
        summary = client.get(f"/api/runs/{run_id}").json()
        if summary["done"]:
            break
    assert summary is not None and summary["done"], f"{agent_id} did not complete"
    return summary


@pytest.mark.parametrize("agent_id", ALL_AGENT_IDS)
def test_agent_completes_end_to_end(demo_client, agent_id):
    client, _ = demo_client
    summary = _run_to_completion(client, agent_id)
    assert summary["event_count"] > 0
    kinds = {e["kind"] for e in summary["events"]}
    assert "tool_use" in kinds
    assert "tool_result" in kinds


@pytest.mark.parametrize("agent_id", SUB_AGENT_PARENTS.keys())
def test_sub_agent_span_has_correct_parent(demo_client, agent_id):
    client, _ = demo_client
    summary = _run_to_completion(client, agent_id)

    root_spans = {e["span_id"] for e in summary["events"] if e["parent_span_id"] is None}
    assert len(root_spans) == 1
    (root_span,) = root_spans

    sub_events = [e for e in summary["events"] if e["parent_span_id"] == root_span]
    assert sub_events, f"expected at least one sub-agent event parented to {root_span}"
    sub_spans = {e["span_id"] for e in sub_events}
    assert len(sub_spans) == 1, "sub-agent events should share one span_id"
    assert next(iter(sub_spans)) != root_span


def test_misfire_agent_is_flagged_but_still_sealed(demo_client):
    client, ledger_dir = demo_client
    summary = _run_to_completion(client, "b5-misfire-demo")

    assert summary["flagged"] is True
    assert len(summary["policy_violations"]) == 1
    violation = summary["policy_violations"][0]
    assert violation["tool_name"] == "initiate_wire_transfer"
    assert "not in b5-misfire-demo's declared tool schema" in violation["reason"]

    # The off-scope call is still fully captured and chain-verified — being
    # out of scope doesn't mean the recorder missed it or broke the ledger.
    tool_use_events = [e for e in summary["events"] if e["kind"] == "tool_use"]
    tool_names = [e["tool_name"] for e in tool_use_events]
    assert "initiate_wire_transfer" in tool_names
    result_events = [
        e for e in summary["events"]
        if e["kind"] == "tool_result" and e["tool_name"] == "initiate_wire_transfer"
    ]
    assert result_events and result_events[0]["data"]["result"]["status"] == "initiated"

    report = verify_ledger(ledger_dir / "ledger.db")
    assert report.ok
    assert report.broken_links == []


def test_normal_agents_are_never_flagged(demo_client):
    client, _ = demo_client
    for agent_id in ("b1-fraud-triage", "b2-kyc-onboarding", "h1-prior-authorization"):
        summary = _run_to_completion(client, agent_id)
        assert summary["flagged"] is False
        assert summary["policy_violations"] == []


def test_replay_reconstructs_run_from_ledger_alone(demo_client):
    client, _ = demo_client
    summary = _run_to_completion(client, "b1-fraud-triage")

    replay = client.get(f"/api/runs/{summary['run_id']}/replay").json()
    assert replay["source"] == "ledger (not in-memory state)"
    replay_kinds = [e["kind"] for e in replay["events"]]
    # session_start/api_error are sealed directly (recorder.record) rather
    # than surfaced as RunEvents, so they appear in the ledger but not in the
    # in-memory summary — replay (ledger-only) sees strictly more than that.
    assert "session_start" in replay_kinds
    assert "api_error" in replay_kinds
    for kind in ("message", "tool_use", "tool_result"):
        assert replay_kinds.count(kind) == sum(1 for e in summary["events"] if e["kind"] == kind)
    kinds = {e["kind"] for e in replay["events"]}
    assert "tool_use" in kinds
    assert "tool_result" in kinds


def test_replay_survives_in_memory_state_being_wiped(demo_client):
    """Acceptance criterion: kill the in-memory run state and
    replay still works, because it reads exclusively from the ledger."""
    client, _ = demo_client
    summary = _run_to_completion(client, "b1-fraud-triage")

    from examples.agent_showcase import app as app_module

    app_module._RUNS.clear()

    replay = client.get(f"/api/runs/{summary['run_id']}/replay").json()
    assert replay["source"] == "ledger (not in-memory state)"
    assert replay["event_count"] > 0


def test_replay_unknown_run_returns_404(demo_client):
    client, _ = demo_client
    resp = client.get("/api/runs/run_does_not_exist/replay")
    assert resp.status_code == 404


def test_tamper_demo_disabled_by_default(demo_client):
    client, _ = demo_client
    summary = _run_to_completion(client, "b1-fraud-triage")
    resp = client.post(f"/api/demo/tamper/{summary['run_id']}")
    assert resp.status_code == 403


def test_tamper_demo_breaks_verify_when_enabled(demo_client, monkeypatch):
    monkeypatch.setenv("DEMO_TAMPER", "1")
    client, _ = demo_client
    summary = _run_to_completion(client, "b1-fraud-triage")

    verify_before = client.get(f"/api/runs/{summary['run_id']}/verify").json()
    assert verify_before["chain_ok"] is True
    assert verify_before["digests_ok"] is True

    tamper = client.post(f"/api/demo/tamper/{summary['run_id']}")
    assert tamper.status_code == 200

    verify_after = client.get(f"/api/runs/{summary['run_id']}/verify").json()
    assert verify_after["digests_ok"] is False
    assert verify_after["tampered_events"], "expected the tampered seq to show up as a broken link"


def test_every_agent_seals_cleanly_into_one_ledger(demo_client):
    client, ledger_dir = demo_client
    for agent_id in ALL_AGENT_IDS:
        _run_to_completion(client, agent_id)

    report = verify_ledger(ledger_dir / "ledger.db")
    assert report.ok
    assert report.broken_links == []
    assert report.orphan_tool_results == []

    # B6's Bedrock trace ends with a returnControl call: the agent asked the
    # caller to run initiate_wire_transfer and the demo never did, so that
    # tool_use has no result and verify names it. That is the true state of
    # the run, not a defect in capture — an unpaired call is a finding the
    # examiner is supposed to see, so it is asserted rather than excused.
    assert report.unpaired_tool_uses == ["bda_returnControl:demo-return-control-01"]
