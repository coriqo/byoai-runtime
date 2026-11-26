"""M5: Coriqo shipping smoke test.

Runs a real demo agent through the FastAPI app (sealing real events into the
real local ledger, exactly like the other tests), then hands that same
ledger + device key to byoai-runtime's public Shipper against a local double
standing in for Coriqo's /v1/ingest/batch — no live Coriqo credentials or
network access required. Proves the demo's sealed events are shippable
as-is: signed, gzip-encoded, batched, and watermark-advanced by the real
Shipper class, not a hand-rolled stand-in.
"""

from __future__ import annotations

import gzip
import json

import httpx
import pytest
from examples.agent_showcase.app import app
from fastapi.testclient import TestClient

from byoai.recorder import integration as recorder_integration
from byoai.recorder.integration import get_recorder
from byoai.recorder.shipper import Shipper, ShipResult


@pytest.fixture
def demo_client(tmp_path, monkeypatch):
    monkeypatch.setenv("BYOAI_RECORDER_ENABLED", "1")
    monkeypatch.setenv("BYOAI_RECORDER_DIR", str(tmp_path / "ledger"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    recorder_integration.reset_recorder_for_tests()
    with TestClient(app) as client:
        yield client
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


def _decode_body(request: httpx.Request) -> dict:
    return json.loads(gzip.decompress(request.content))


def test_sealed_events_ship_to_a_local_coriqo_double(demo_client):
    _run_to_completion(demo_client, "b1-fraud-triage")

    recorder = get_recorder()
    assert recorder is not None

    requests_seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(request)
        body = _decode_body(request)
        assert body["device_id"] == recorder.key.device_id
        assert request.headers["x-coriqo-device"] == recorder.key.device_id
        # Signature proves these events came from this device's key, not
        # just "some JSON that showed up" — the whole point of shipping a
        # signed batch instead of a raw dump.
        assert request.headers["x-coriqo-signature"].startswith("ed25519:")
        assert request.headers["content-encoding"] == "gzip"
        for entry in body["entries"]:
            assert set(entry.keys()) == {"seq", "entry_hash", "event"}
        return httpx.Response(
            202, json={"accepted": len(body["entries"]), "duplicates": 0, "gaps": []}
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    shipper = Shipper(
        recorder.ledger,
        recorder.key,
        coriqo_base_url="https://coriqo.example.com",
        http_client=client,
    )
    try:
        result = shipper.ship_once()
    finally:
        shipper.close()

    assert isinstance(result, ShipResult)
    assert len(requests_seen) == 1
    assert result.duplicates == 0
    assert result.gaps == []
    assert result.accepted > 0
    assert result.synced_up_to == result.accepted
    assert recorder.ledger.get_synced_up_to() == result.synced_up_to


def test_second_ship_attempt_has_nothing_new(demo_client):
    _run_to_completion(demo_client, "b1-fraud-triage")
    recorder = get_recorder()
    assert recorder is not None

    def accept_all(request: httpx.Request) -> httpx.Response:
        body = _decode_body(request)
        return httpx.Response(202, json={"accepted": len(body["entries"]), "duplicates": 0, "gaps": []})

    client = httpx.Client(transport=httpx.MockTransport(accept_all))
    shipper = Shipper(recorder.ledger, recorder.key, coriqo_base_url="https://coriqo.example.com", http_client=client)
    try:
        first = shipper.ship_once()
        assert first is not None and first.accepted > 0

        second = shipper.ship_once()
        assert second is None, "nothing unsynced remains after the first successful ship"
    finally:
        shipper.close()
