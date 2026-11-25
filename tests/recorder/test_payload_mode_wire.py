"""The payload mode a host records under travels to Coriqo outside every digest (W8).

The ledger stores the mode each entry was written in; the shipper sends it beside the event
(never inside it) and names its configured mode in the signed ``runtime`` block; a 409
``payload_mode_refused`` is read back as a refusal; decision traces carry the mode in the
``X-Coriqo-Payload-Mode`` header.
"""

from __future__ import annotations

import gzip
import json
import logging
import sqlite3
import threading

import httpx
import pytest

from byoai.recorder.coriqo_agents import CoriqoAgentsClient, CoriqoCredentials
from byoai.recorder.keys import DeviceKey, load_or_create_device_key
from byoai.recorder.ledger import Ledger
from byoai.recorder.redact import PAYLOAD_MODE_HEADER, PayloadMode, payload_mode_headers
from byoai.recorder.shipper import ShipError, Shipper
from byoai.recorder.verify import verify_ledger

from .test_shipper import DEVICE, _append_checkpoints
from .test_shipper import make_event as _event

AGENT_ID = "agt_1"
REFUSAL = {
    "detail": {
        "code": "payload_mode_refused",
        "modes": ["full"],
        "payload_mode": "redacted",
        "message": "Coriqo refused this batch.",
    }
}


@pytest.fixture
def ledger(tmp_path):
    led = Ledger(tmp_path / "ledger.sqlite3", DEVICE)
    yield led
    led.close()


@pytest.fixture
def key(tmp_path) -> DeviceKey:
    return load_or_create_device_key(tmp_path / "keydir")


def _shipper(ledger: Ledger, key: DeviceKey, handler, **kwargs) -> Shipper:
    return Shipper(
        ledger,
        key,
        coriqo_base_url="https://coriqo.example.com",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        **kwargs,
    )


def _client(handler) -> CoriqoAgentsClient:
    return CoriqoAgentsClient(
        CoriqoCredentials(
            base_url="https://coriqo.test", api_key="cq_sa_test", tenant_slug="acme_bank"
        ),
        http_client=httpx.Client(
            base_url="https://coriqo.test", transport=httpx.MockTransport(handler)
        ),
    )


# ---- ledger -------------------------------------------------------------------


def test_the_ledger_keeps_the_mode_each_entry_was_written_in(ledger):
    ledger.append(_event(), payload_mode="redacted")
    ledger.append(_event())

    entries = ledger.read_unsynced()

    assert [entry.payload_mode for entry in entries] == ["redacted", None]


def test_a_ledger_with_modes_stored_still_verifies(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    led = Ledger(path, DEVICE)
    led.append(_event(), payload_mode="hash-only")
    led.append(_event(), payload_mode="full")
    led.close()

    assert verify_ledger(path).ok


def test_the_mode_is_stored_outside_the_event_table(tmp_path):
    """A verifier released before W8 rebuilds each event from every agent_events column but
    the chain ones, so a mode stored there would read as a changed event on every row."""
    path = tmp_path / "ledger.sqlite3"
    led = Ledger(path, DEVICE)
    led.append(_event(), payload_mode="redacted")
    led.close()

    conn = sqlite3.connect(path)
    try:
        event_columns = {row[1] for row in conn.execute("PRAGMA table_info(agent_events)")}
        stored_modes = conn.execute("SELECT seq, payload_mode FROM agent_event_payload_modes").fetchall()
    finally:
        conn.close()

    assert "payload_mode" not in event_columns
    assert stored_modes == [(1, "redacted")]


def test_a_ledger_from_the_first_w8_build_moves_its_modes_out_on_open(tmp_path):
    """The first W8 build kept the mode in an agent_events column; reopening such a file moves
    the modes to their own table, so they still read back and the file verifies."""
    path = tmp_path / "ledger.sqlite3"
    led = Ledger(path, DEVICE)
    led.append(_event(), payload_mode="hash-only")
    led.append(_event())
    led.close()
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("ALTER TABLE agent_events ADD COLUMN payload_mode TEXT")
    conn.execute("UPDATE agent_events SET payload_mode = 'hash-only' WHERE seq = 1")
    conn.execute("DELETE FROM agent_event_payload_modes")
    conn.close()

    led = Ledger(path, DEVICE)
    led.append(_event(), payload_mode="full")
    modes = [entry.payload_mode for entry in led.read_unsynced()]
    led.close()

    assert modes == ["hash-only", None, "full"]
    assert verify_ledger(path).ok


def test_a_ledger_with_the_mode_column_still_verifies_before_it_is_reopened(tmp_path):
    path = tmp_path / "ledger.sqlite3"
    led = Ledger(path, DEVICE)
    led.append(_event())
    led.close()
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("ALTER TABLE agent_events ADD COLUMN payload_mode TEXT")
    conn.execute("UPDATE agent_events SET payload_mode = 'redacted'")
    conn.close()

    assert verify_ledger(path).ok


# ---- shipper ------------------------------------------------------------------


def test_the_mode_ships_beside_the_event_and_only_when_it_was_recorded(ledger, key):
    ledger.append(_event(), payload_mode="redacted")
    ledger.append(_event())
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(gzip.decompress(request.content)))
        return httpx.Response(202, json={"accepted": 2, "duplicates": 0, "gaps": []})

    _shipper(ledger, key, handler).ship_once()

    first, second = bodies[0]["entries"]
    assert first["payload_mode"] == "redacted" and "payload_mode" not in first["event"]
    assert "payload_mode" not in second


def test_the_runtime_block_names_the_configured_mode(ledger, key):
    ledger.append(_event(), payload_mode="redacted")
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(gzip.decompress(request.content)))
        return httpx.Response(202, json={"accepted": 1, "duplicates": 0, "gaps": []})

    _shipper(ledger, key, handler, payload_mode="redacted").ship_once()

    assert bodies[0]["runtime"]["name"] == "byoai-runtime"
    assert bodies[0]["runtime"]["payload_mode"] == "redacted"


def test_the_mode_and_the_heartbeat_capability_share_one_runtime_block(ledger, key):
    ledger.append(_event(), payload_mode="redacted")
    bodies = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(gzip.decompress(request.content)))
        return httpx.Response(202, json={"accepted": 1, "duplicates": 0, "gaps": []})

    capability = {"version": "x", "capabilities": ["heartbeat_chain_v1"], "heartbeat_interval_s": 900}
    _shipper(ledger, key, handler, payload_mode="redacted", runtime_info=lambda: capability).ship_once()

    runtime = bodies[0]["runtime"]
    assert runtime["capabilities"] == ["heartbeat_chain_v1"]
    assert runtime["payload_mode"] == "redacted" and runtime["name"] == "byoai-runtime"


def test_a_heartbeat_is_recorded_as_runtime_authored(ledger):
    from byoai.recorder.heartbeat import HeartbeatEmitter

    HeartbeatEmitter(ledger, DEVICE, interval_s=900).tick()

    assert [entry.payload_mode for entry in ledger.read_unsynced()] == ["runtime"]


def test_a_refused_batch_raises_with_the_reason_and_stays_unsynced(ledger, key):
    ledger.append(_event(), payload_mode="full")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json=REFUSAL, headers={"Retry-After": "900"})

    with pytest.raises(ShipError) as refused:
        _shipper(ledger, key, handler).ship_once()

    assert refused.value.refusal()["modes"] == ["full"]
    assert refused.value.retry_after == 900
    assert ledger.get_synced_up_to() == 0


def test_any_other_rejection_is_not_read_as_a_refusal():
    conflict = json.dumps({"detail": "conflict"})
    assert ShipError("x", status_code=409, body=conflict).refusal() is None
    assert ShipError("x", status_code=500, body=json.dumps(REFUSAL)).refusal() is None
    assert ShipError("x", status_code=409, body="not json").refusal() is None
    assert ShipError("x").refusal() is None


def test_a_repeated_refusal_is_logged_once(ledger, key, caplog):
    shipper = _shipper(ledger, key, lambda request: httpx.Response(202))
    refusal = ShipError("x", status_code=409, body=json.dumps(REFUSAL))

    with caplog.at_level(logging.WARNING, logger="byoai.recorder.shipper"):
        shipper._log_failure(refusal)
        shipper._log_failure(refusal)

    refused = [r for r in caplog.records if "refused this host's ledger batch" in r.getMessage()]
    assert len(refused) == 1


def _stop_after(stop: threading.Event, rounds: int):
    """A wait function that ends run_forever after ``rounds`` waits, without sleeping."""
    waits: list[float] = []

    def wait(seconds: float) -> bool:
        waits.append(seconds)
        if len(waits) >= rounds:
            stop.set()
        return stop.is_set()

    return wait


def test_a_refused_entry_batch_does_not_stop_checkpoints_from_shipping(ledger, key):
    _append_checkpoints(ledger, key, 2)
    paths = []

    def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path.endswith("/checkpoints/batch"):
            return httpx.Response(202, json={"accepted": 2, "duplicates": 0, "rejected": []})
        return httpx.Response(409, json=REFUSAL, headers={"Retry-After": "900"})

    stop = threading.Event()
    _shipper(ledger, key, handler, wait=_stop_after(stop, 1)).run_forever(stop=stop)

    assert any(path.endswith("/checkpoints/batch") for path in paths)
    assert ledger.get_synced_checkpoint_up_to() > 0


def test_a_refusal_after_a_successful_batch_is_logged_again(ledger, key, caplog):
    responses = iter([
        httpx.Response(409, json=REFUSAL),
        httpx.Response(202, json={"accepted": 1, "duplicates": 0, "gaps": []}),
        httpx.Response(409, json=REFUSAL),
    ])

    def handler(request: httpx.Request) -> httpx.Response:
        ledger.append(_event(), payload_mode="full")  # always something left to ship
        return next(responses)

    ledger.append(_event(), payload_mode="full")
    stop = threading.Event()
    shipper = _shipper(ledger, key, handler, wait=_stop_after(stop, 3))

    with caplog.at_level(logging.WARNING, logger="byoai.recorder.shipper"):
        shipper.run_forever(stop=stop)

    refused = [r for r in caplog.records if "refused this host's ledger batch" in r.getMessage()]
    assert len(refused) == 2


# ---- decision traces ----------------------------------------------------------


def test_payload_mode_headers():
    assert payload_mode_headers(None) == {}
    assert payload_mode_headers(PayloadMode.HASH_ONLY) == {PAYLOAD_MODE_HEADER: "hash-only"}
    assert payload_mode_headers("redacted") == {PAYLOAD_MODE_HEADER: "redacted"}
    with pytest.raises(ValueError):
        payload_mode_headers("everything")


@pytest.mark.parametrize("batch", [False, True])
def test_a_trace_says_its_payload_mode_in_a_header(batch):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"recorded": 1, "traces": []})

    client = _client(handler)
    if batch:
        traces = [{"inputs": {}, "output": "ok"}]
        client.record_traces(AGENT_ID, traces, payload_mode=PayloadMode.REDACTED)
    else:
        client.record_trace(AGENT_ID, inputs={}, output="ok", payload_mode="redacted")

    assert seen[0].headers[PAYLOAD_MODE_HEADER] == "redacted"


def test_a_trace_without_a_mode_sends_no_header():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"event_hash": "sha256:" + "0" * 64})

    _client(handler).record_trace(AGENT_ID, inputs={}, output="ok")

    assert PAYLOAD_MODE_HEADER not in seen[0].headers
