"""Covers the demo's live-call TTL throttle and the misfire failure injection.

No network access — ANTHROPIC_API_KEY is intentionally left unset/invalid, so
every run already exercises the fallback-transcript path; these tests only
check which *mode* that fallback got reached through.
"""

from __future__ import annotations

import pytest
from examples.agent_showcase import runner as runner_module
from examples.agent_showcase.app import app
from fastapi.testclient import TestClient

from byoai.recorder import integration as recorder_integration


@pytest.fixture
def demo_client(tmp_path, monkeypatch):
    monkeypatch.setenv("BYOAI_RECORDER_ENABLED", "1")
    monkeypatch.setenv("BYOAI_RECORDER_DIR", str(tmp_path / "ledger"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(runner_module, "LIVE_CALL_STATE_PATH", tmp_path / "live_calls.json")
    monkeypatch.setattr(runner_module, "_live_call_state_loaded", False)
    recorder_integration.reset_recorder_for_tests()
    runner_module._LAST_LIVE_CALL.clear()
    with TestClient(app) as client:
        yield client
    runner_module._LAST_LIVE_CALL.clear()
    recorder_integration.reset_recorder_for_tests()


def _run_to_completion(client, run_id):
    for _ in range(100):
        summary = client.get(f"/api/runs/{run_id}").json()
        if summary["done"]:
            return summary
    raise AssertionError("run did not complete")


def _run_complete_data(summary):
    event = next(e for e in summary["events"] if e["kind"] == "run_complete")
    return event["data"]


def test_no_api_key_replays_with_replay_mode(demo_client):
    started = demo_client.post("/api/agents/b1-fraud-triage/run").json()
    summary = _run_to_completion(demo_client, started["run_id"])
    assert _run_complete_data(summary)["mode"] == "replay"


def test_second_run_within_ttl_uses_cached_mode(demo_client, monkeypatch):
    # Simulate a prior live call for this agent inside the TTL window.
    monkeypatch.setitem(runner_module._LAST_LIVE_CALL, "b1-fraud-triage", runner_module.time.time())

    started = demo_client.post("/api/agents/b1-fraud-triage/run").json()
    summary = _run_to_completion(demo_client, started["run_id"])
    data = _run_complete_data(summary)
    assert data["mode"] == "cached"
    assert data["used_fallback"] is True


def test_force_live_bypasses_ttl_cooldown(demo_client, monkeypatch):
    monkeypatch.setitem(runner_module._LAST_LIVE_CALL, "b1-fraud-triage", runner_module.time.time())

    started = demo_client.post("/api/agents/b1-fraud-triage/run?force_live=true").json()
    summary = _run_to_completion(demo_client, started["run_id"])
    # No API key is set, so the bypassed live attempt still fails over — but
    # via the error path (replay), not the TTL short-circuit (cached).
    assert _run_complete_data(summary)["mode"] == "replay"


def test_inject_misfire_forces_fallback_without_attempting_live_call(demo_client):
    started = demo_client.post("/api/agents/b1-fraud-triage/run?inject_misfire=true").json()
    summary = _run_to_completion(demo_client, started["run_id"])
    kinds = {e["kind"] for e in summary["events"]}
    assert "misfire" in kinds
    assert _run_complete_data(summary)["mode"] == "misfire"


def test_live_call_ttl_cooldown_helper():
    agent_runner = runner_module.AgentRunner.__new__(runner_module.AgentRunner)
    agent_runner.agent = type("A", (), {"id": "some-agent"})()  # pyright: ignore[reportAttributeAccessIssue]  # stand-in agent: only .id is read

    assert agent_runner._live_call_on_cooldown() is False

    runner_module._LAST_LIVE_CALL["some-agent"] = runner_module.time.time()
    assert agent_runner._live_call_on_cooldown() is True

    runner_module._LAST_LIVE_CALL["some-agent"] -= runner_module.LIVE_CALL_TTL_SECONDS + 1
    assert agent_runner._live_call_on_cooldown() is False
