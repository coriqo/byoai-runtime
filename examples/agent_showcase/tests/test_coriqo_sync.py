"""The showcase's Coriqo wiring.

The publishing machinery itself is core and tested in
tests/recorder/test_coriqo_agents.py. What's left to cover here is only what
this app adds: mapping an ``AgentDef`` onto a Coriqo registration, publishing on
run completion, and the deliberate choice to log-and-continue rather than let a
Coriqo failure surface as a broken run.

Also distinct from test_coriqo_shipping.py, which covers the recorder's device
ledger sync (``/v1/ingest/batch``) — a different integration entirely.
"""

from __future__ import annotations

import json

import httpx
import pytest
from examples.agent_showcase import coriqo_sync
from examples.agent_showcase.agents.registry import get_agent, list_agents
from examples.agent_showcase.app import app
from fastapi.testclient import TestClient

from byoai.recorder import integration as recorder_integration

_AGENT_ID = "b1-fraud-triage"
_CORIQO_AGENT_ID = "coriqo-agent-1"


@pytest.fixture
def sync_env(tmp_path, monkeypatch):
    """Recorder on (so runs actually seal), Coriqo configured, agent map at a
    throwaway path so a developer's real ~/.byoai/coriqo_agents.json is never
    touched by a test run."""
    monkeypatch.setenv("BYOAI_RECORDER_ENABLED", "1")
    monkeypatch.setenv("BYOAI_RECORDER_DIR", str(tmp_path / "ledger"))
    monkeypatch.setenv("BYOAI_CORIQO_URL", "https://coriqo.example.com")
    monkeypatch.setenv("BYOAI_CORIQO_API_KEY", "cq_sa_testkey")
    monkeypatch.setenv("BYOAI_CORIQO_TENANT_SLUG", "acme_bank")
    monkeypatch.delenv("BYOAI_CORIQO_AUTO_REGISTER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    recorder_integration.reset_recorder_for_tests()
    # publish_run caches one client for the process, so it has to be dropped
    # around every test or the first test's fake transport would still be
    # answering requests in the next one.
    coriqo_sync.close()
    yield tmp_path
    coriqo_sync.close()
    recorder_integration.reset_recorder_for_tests()


def _install_fake_coriqo(monkeypatch, handler):
    """Routes the core client's httpx.Client at a MockTransport.

    Patched at the module the client is built in, rather than threaded through
    the app's own functions, so production signatures stay free of test-only
    plumbing.
    """
    from byoai.recorder import coriqo_agents

    real_client = httpx.Client

    def factory(**kwargs):
        kwargs.pop("transport", None)
        return real_client(**kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(coriqo_agents.httpx, "Client", factory)


def _run_to_completion(client, agent_id=_AGENT_ID):
    run_id = client.post(f"/api/agents/{agent_id}/run").json()["run_id"]
    for _ in range(400):
        if client.get(f"/api/runs/{run_id}").json()["done"]:
            return run_id
    raise AssertionError(f"{agent_id} did not complete")


def test_every_agent_registers_with_its_real_declared_tools(sync_env, monkeypatch):
    """Coriqo enforces allowed_tools on every trace and opens a mandate Finding
    for anything outside it, so a padded or trimmed list here would flag every
    ordinary run as out-of-mandate."""
    registered = []

    def handler(request: httpx.Request) -> httpx.Response:
        registered.append(json.loads(request.content))
        return httpx.Response(201, json={"agent_id": f"coriqo-{len(registered)}"})

    _install_fake_coriqo(monkeypatch, handler)
    mapping = coriqo_sync.ensure_agents_registered()

    assert len(mapping) == len(list_agents())
    by_name = {body["name"]: body for body in registered}
    for showcase_id in mapping:
        agent = get_agent(showcase_id)
        assert agent is not None
        body = by_name[agent.name]
        assert body["allowed_tools"] == sorted(agent.declared_tool_names)
        assert body["mandate"] == agent.description
        assert body["system"] == (agent.system or f"byoai-agent-showcase/{agent.domain}")
        assert body.get("use_case") == agent.use_case
        # The external_id is namespaced so this demo's generic keys can't
        # collide with another publisher's in a shared tenant.
        assert body["external_id"] == f"byoai-agent-showcase:{showcase_id}"

    # Banking and healthcare agents both act on regulated decisions; neither
    # domain should register as low-risk.
    assert {body["risk_tier"] for body in registered} == {"high"}


def test_a_run_publishes_its_sealed_steps(sync_env, monkeypatch):
    traces = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/trajectories"):
            return httpx.Response(201, json={"trajectory_id": "traj-1"})
        if path.endswith("/complete"):
            return httpx.Response(200, json={})
        traces.extend(json.loads(request.content)["traces"])
        return httpx.Response(
            201, json={"recorded": len(traces), "flagged": 0, "traces": []}
        )

    with TestClient(app) as client:
        run_id = _run_to_completion(client)

    _install_fake_coriqo(monkeypatch, handler)
    coriqo_sync.publish_run(
        run_id, _AGENT_ID, agent_map={_AGENT_ID: _CORIQO_AGENT_ID}, final_text="cleared"
    )

    assert traces, "no steps were published"
    agent = get_agent(_AGENT_ID)
    assert agent is not None
    # The app's goal comes from the agent's own scenario, and it tags each
    # trace with the showcase agent id so a Coriqo trace can be traced back to
    # which demo agent produced it.
    for trace in traces:
        assert trace["inputs"]["showcase_agent"] == _AGENT_ID
    assert traces[-1]["output"] == "cleared"


def test_a_coriqo_failure_never_breaks_a_run(sync_env, monkeypatch):
    """The ledger is the authoritative record: a Coriqo outage costs
    visibility, not evidence, and must not raise into the app."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    with TestClient(app) as client:
        run_id = _run_to_completion(client)

    _install_fake_coriqo(monkeypatch, handler)
    coriqo_sync.publish_run(run_id, _AGENT_ID, agent_map={_AGENT_ID: _CORIQO_AGENT_ID})


def test_an_unreachable_coriqo_leaves_registration_empty(sync_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    _install_fake_coriqo(monkeypatch, handler)
    assert coriqo_sync.ensure_agents_registered() == {}


def test_publish_skips_an_unmapped_agent(sync_env, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should not have called Coriqo")

    _install_fake_coriqo(monkeypatch, handler)
    coriqo_sync.publish_run("run_missing", _AGENT_ID, agent_map={})


def test_sync_is_off_without_a_url(sync_env, monkeypatch):
    monkeypatch.delenv("BYOAI_CORIQO_URL")
    assert coriqo_sync.enabled() is False
    assert coriqo_sync.ensure_agents_registered() == {}


def test_a_key_that_cannot_register_resolves_already_registered_agents(sync_env, monkeypatch):
    banking = [a for a in list_agents() if a.domain == "banking"]
    registered_first = banking[:2]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            return httpx.Response(403, json={"detail": "Role 'governance:approve' required"})
        items = [
            {"agent_id": f"coriqo-{a.id}", "external_id": f"byoai-agent-showcase:{a.id}"}
            for a in registered_first
        ]
        return httpx.Response(200, json={"items": items, "total": len(items)})

    _install_fake_coriqo(monkeypatch, handler)
    mapping = coriqo_sync.ensure_agents_registered(banking)

    assert mapping == {a.id: f"coriqo-{a.id}" for a in registered_first}


def test_auto_register_off_registers_nothing(sync_env, monkeypatch):
    monkeypatch.setenv("BYOAI_CORIQO_AUTO_REGISTER", "0")

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should not have touched Coriqo")

    _install_fake_coriqo(monkeypatch, handler)
    assert coriqo_sync.ensure_agents_registered() == {}


def test_status_endpoint_reports_sync_off_by_default(monkeypatch):
    monkeypatch.delenv("BYOAI_CORIQO_URL", raising=False)
    monkeypatch.setenv("BYOAI_RECORDER_ENABLED", "0")
    recorder_integration.reset_recorder_for_tests()
    with TestClient(app) as client:
        status = client.get("/api/coriqo/status").json()
    recorder_integration.reset_recorder_for_tests()
    assert status["enabled"] is False
    assert status["mapped_agents"] == {}
