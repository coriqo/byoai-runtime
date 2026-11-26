"""publish_session with the device's own signature, no service-account API key.

Coriqo side: its device-signed publish routes under
``/api/v1/agent-runtime/agents/{agent}/runs/{run}`` (see Coriqo's
``device_signed_publish_spec``). The fake server here checks what Coriqo checks:
there is no ``X-API-Key``, and the signature verifies over method, path, the
SHA-256 of the exact body bytes, key and timestamp.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Iterator

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from byoai.recorder import coriqo_agents
from byoai.recorder.coriqo_agents import (
    AgentSuspendedError,
    CoriqoAgentsClient,
    CoriqoAgentsError,
    CoriqoCredentials,
    make_publish_client,
    publish_session,
)
from byoai.recorder.coriqo_async import request_path, signing_payload
from byoai.recorder.identity import CoriqoIdentity
from byoai.recorder.keys import load_or_create_device_key
from byoai.recorder.ledger import Ledger

from .test_coriqo_agents import _seal_run

AGENT = "agent-1"
BASE = f"/api/v1/agent-runtime/agents/{AGENT}"


@pytest.fixture
def key(tmp_path):
    return load_or_create_device_key(tmp_path)


@pytest.fixture
def ledger(tmp_path, key) -> Iterator[Ledger]:
    led = Ledger(tmp_path / "ledger.db", device_id=key.device_id)
    yield led
    led.close()


@pytest.fixture(autouse=True)
def _reset_refusal_notice():
    coriqo_agents._reset_publish_refusal_notice_for_tests()


def _verify(request: httpx.Request, pub_hex: str) -> None:
    assert "x-api-key" not in request.headers, "a device publish never carries the API key"
    assert request.headers["X-Coriqo-Public-Key"] == pub_hex
    payload = signing_payload(
        method=request.method, path=request_path(request.url), body=request.content,
        timestamp=request.headers["X-Coriqo-Timestamp"], public_key_hex=pub_hex)
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
        bytes.fromhex(request.headers["X-Coriqo-Signature"]), payload)


def _client(key, handler) -> CoriqoAgentsClient:
    identity = CoriqoIdentity.from_device(
        base_url="https://coriqo.test", device_id=key.device_id, signer=key, tenant_slug="acme_bank")
    return CoriqoAgentsClient.for_device(
        identity, http_client=httpx.Client(base_url="https://coriqo.test",
                                           transport=httpx.MockTransport(handler)))


def _pub_hex(key) -> str:
    import base64
    return base64.b64decode(key.public_key_b64).hex()


def _server(key, seen: list):
    runs: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        _verify(request, _pub_hex(key))
        assert request.headers["X-Tenant-Slug"] == "acme_bank"
        path = request.url.path
        seen.append((request.method, path))
        assert path.startswith(BASE + "/runs/"), path
        tail = path[len(BASE + "/runs/"):].split("/", 1)
        run_id = tail[0]
        uuid.UUID(run_id)
        if request.method == "PUT":
            first = run_id not in runs
            runs[run_id] = json.loads(request.content)
            return httpx.Response(201 if first else 200, json={"trajectory_id": run_id})
        action = tail[1]
        body = json.loads(request.content)
        if action == "traces/batch":
            assert request.headers["X-Coriqo-Payload-Mode"] == "redacted", "the declared mode travels with the batch"
            assert all(t["trajectory_id"] == run_id for t in body["traces"])
            return httpx.Response(201, json={"recorded": len(body["traces"]), "flagged": 0, "traces": [
                {"step_index": t["step_index"], "status": "within", "event_hash": "e" * 64}
                for t in body["traces"]]})
        if action == "complete":
            return httpx.Response(200, json={})
        if action == "device-receipts":
            return httpx.Response(200, json={"stored": len(body["receipts"]), "duplicates": 0})
        if action == "external-controls":
            assert body["trajectory_id"] == run_id
            return httpx.Response(201, json={"recorded": len(body["controls"]), "skipped": 0})
        raise AssertionError(path)
    return handler


def test_publish_session_runs_on_the_device_routes_with_no_api_key(ledger, key):
    _seal_run(ledger, "s1", ["search", "summarize"])
    seen: list = []
    client = _client(key, _server(key, seen))
    result = publish_session(client, coriqo_agent_id=AGENT, ledger=ledger, session_id="s1",
                             goal="answer a question")
    assert result is not None and result.recorded == 2 and result.status == "completed"
    uuid.UUID(result.trajectory_id)
    assert [m for m, _ in seen] == ["PUT", "POST", "POST"]
    assert seen[1][1].endswith("/traces/batch") and seen[2][1].endswith("/complete")
    assert all(f"/runs/{result.trajectory_id}" in p for _, p in seen)


def test_device_receipts_and_external_controls_use_the_run_routes(key):
    seen: list = []
    client = _client(key, _server(key, seen))
    run = client.open_trajectory(AGENT, goal="g")["trajectory_id"]
    assert client.record_device_receipts(AGENT, run, [{"receipt": {}, "step_index": 0}])["stored"] == 1
    ctl = {"control_system": "aws.bedrock.guardrail", "action": "blocked", "evidence_ref": "r1"}
    assert client.record_external_controls(AGENT, run, [ctl])["recorded"] == 1
    assert seen[-2][1].endswith("/device-receipts") and seen[-1][1].endswith("/external-controls")


def test_a_retried_open_names_the_same_run_and_a_repeated_close_is_done(key):
    calls: list = []
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.method == "PUT":
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise httpx.ConnectError("reset", request=request)
            return httpx.Response(200, json={"trajectory_id": request.url.path.rsplit("/", 1)[1]})
        return httpx.Response(409, json={"detail": "This trajectory is already completed."})

    client = _client(key, handler)
    run = client.open_trajectory(AGENT, goal="g")["trajectory_id"]
    assert calls[0] == calls[1] and calls[0].endswith(run), "the retry reuses the run id"
    client.complete_trajectory(AGENT, run)  # 409 "already completed" means a retry of a close that worked

    def open_subruns(_request):
        return httpx.Response(409, json={"detail": "This run still has open sub-runs. Complete them first."})
    with pytest.raises(CoriqoAgentsError):
        _client(key, open_subruns).complete_trajectory(AGENT, run)


def test_a_refusal_because_publishing_is_off_is_logged_once_with_where_to_fix(ledger, key, caplog):
    _seal_run(ledger, "s1", ["search"])
    detail = ("Device publishing is off for this workspace. An administrator turns it on in "
              "Settings > Agent evaluations > Record completeness.")
    client = _client(key, lambda r: httpx.Response(403, json={"detail": detail}))
    with caplog.at_level(logging.WARNING, logger="byoai.recorder.coriqo_agents"):
        for _ in range(2):
            with pytest.raises(CoriqoAgentsError) as err:
                publish_session(client, coriqo_agent_id=AGENT, ledger=ledger, session_id="s1")
            assert err.value.status_code == 403 and "Device publishing is off" in err.value.detail
    notes = [r for r in caplog.records if "Device publishing is off" in r.getMessage()]
    assert len(notes) == 1, "said once per process, not once per run"
    assert "Settings > Agent evaluations > Record completeness" in notes[0].getMessage()


def test_a_suspended_agent_still_raises_agent_suspended(ledger, key):
    _seal_run(ledger, "s1", ["search"])
    client = _client(key, lambda r: httpx.Response(423, json={"detail": "suspended"}))
    with pytest.raises(AgentSuspendedError):
        publish_session(client, coriqo_agent_id=AGENT, ledger=ledger, session_id="s1")


def test_a_device_client_refuses_calls_it_has_no_route_for(key):
    client = _client(key, lambda r: httpx.Response(200, json={}))
    with pytest.raises(CoriqoAgentsError, match="service-account"):
        client.list_agents()


def test_the_api_key_path_is_unchanged(ledger, key):
    _seal_run(ledger, "s1", ["search"])
    paths: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        assert request.headers["X-API-Key"] == "cq_sa_test"
        if request.url.path.endswith("/trajectories"):
            return httpx.Response(201, json={"trajectory_id": "traj-1"})
        if request.url.path.endswith("/traces/batch"):
            return httpx.Response(201, json={"recorded": 1, "flagged": 0, "traces": []})
        return httpx.Response(200, json={})
    client = CoriqoAgentsClient(
        CoriqoCredentials("https://coriqo.test", "cq_sa_test", "acme_bank"),
        http_client=httpx.Client(base_url="https://coriqo.test", headers={"X-API-Key": "cq_sa_test"},
                                 transport=httpx.MockTransport(handler)))
    publish_session(client, coriqo_agent_id=AGENT, ledger=ledger, session_id="s1")
    assert paths[0] == f"/api/v1/agents/{AGENT}/trajectories"
    assert not any("agent-runtime" in p for p in paths)


def test_make_publish_client_prefers_the_api_key_then_the_enrolled_device(tmp_path, key, monkeypatch):
    creds = CoriqoCredentials("https://c.test", "k", "t")
    monkeypatch.setattr(CoriqoCredentials, "from_env", classmethod(lambda cls: creds))
    assert make_publish_client(key, key_dir=tmp_path).device_publish is False

    monkeypatch.setattr(CoriqoCredentials, "from_env", classmethod(lambda cls: None))
    ident = CoriqoIdentity.from_device(base_url="https://c.test", device_id=key.device_id,
                                       signer=key, tenant_slug="t")
    monkeypatch.setattr("byoai.recorder.identity.resolve_identity", lambda key_dir=None: ident)
    assert make_publish_client(key, key_dir=tmp_path).device_publish is True

    monkeypatch.setattr("byoai.recorder.identity.resolve_identity", lambda key_dir=None: None)
    assert make_publish_client(key, key_dir=tmp_path) is None
    tenantless = CoriqoIdentity.from_device(base_url="https://c.test", device_id=key.device_id, signer=key)
    monkeypatch.setattr("byoai.recorder.identity.resolve_identity", lambda key_dir=None: tenantless)
    assert make_publish_client(key, key_dir=tmp_path) is None, "no tenant, nothing to sign for"
