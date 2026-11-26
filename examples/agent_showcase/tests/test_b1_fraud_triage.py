"""End-to-end smoke test for M1: one agent, real recorder, real verify.

No network access — ANTHROPIC_API_KEY is intentionally left unset/invalid so
every run exercises the fallback-transcript path, which still seals real
events through the recorder.
"""

from __future__ import annotations

import pytest
from examples.agent_showcase.app import app
from fastapi.testclient import TestClient

from byoai.recorder import integration as recorder_integration


@pytest.fixture
def demo_client(tmp_path, monkeypatch):
    monkeypatch.setenv("BYOAI_RECORDER_ENABLED", "1")
    monkeypatch.setenv("BYOAI_RECORDER_DIR", str(tmp_path / "ledger"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    recorder_integration.reset_recorder_for_tests()
    with TestClient(app) as client:
        yield client
    recorder_integration.reset_recorder_for_tests()


def test_agent_catalog_lists_b1(demo_client):
    agents = demo_client.get("/api/agents").json()
    ids = [a["id"] for a in agents]
    assert "b1-fraud-triage" in ids


def test_b1_runs_end_to_end_and_seals_events(demo_client):
    started = demo_client.post("/api/agents/b1-fraud-triage/run").json()
    run_id = started["run_id"]

    summary: dict = {}
    for _ in range(100):
        summary = demo_client.get(f"/api/runs/{run_id}").json()
        if summary["done"]:
            break
    assert summary["done"], "run did not complete"
    assert summary["event_count"] > 0
    kinds = {e["kind"] for e in summary["events"]}
    assert "tool_use" in kinds
    assert "tool_result" in kinds
    assert "run_complete" in kinds


def test_verify_is_green_on_untampered_run(demo_client):
    started = demo_client.post("/api/agents/b1-fraud-triage/run").json()
    run_id = started["run_id"]
    for _ in range(100):
        summary = demo_client.get(f"/api/runs/{run_id}").json()
        if summary["done"]:
            break

    verify = demo_client.get(f"/api/runs/{run_id}/verify").json()
    assert verify["chain_ok"] is True
    assert verify["digests_ok"] is True
    assert verify["tampered_events"] == []


def test_unknown_agent_returns_404(demo_client):
    resp = demo_client.post("/api/agents/does-not-exist/run")
    assert resp.status_code == 404
