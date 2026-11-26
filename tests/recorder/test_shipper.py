"""Batching shipper tests — workstream G."""

from __future__ import annotations

import gzip
import json
import threading
import time
import uuid

import httpx
import pytest

from byoai.recorder.canonical import canonicalize, sha256_hex
from byoai.recorder.checkpoint import Checkpointer
from byoai.recorder.coriqo_async import AsyncCoriqoAgentsClient
from byoai.recorder.identity import CoriqoIdentity
from byoai.recorder.keys import DeviceKey, load_or_create_device_key
from byoai.recorder.ledger import Ledger
from byoai.recorder.schema import (
    EVENT_SCHEMA_VERSION,
    AgentEvent,
    EventKind,
    new_span_id,
    new_trace_id,
)
from byoai.recorder.shipper import (
    AttestationShipResult,
    CheckpointShipResult,
    ShipError,
    Shipper,
    ShipResult,
)

DEVICE = "dev_test"


def make_event(session_id: str = "sess_1", *, payload: dict | None = None) -> AgentEvent:
    payload = {"command": "ls -la"} if payload is None else payload
    return AgentEvent(
        schema_version=EVENT_SCHEMA_VERSION,
        event_id="evt_" + uuid.uuid4().hex,
        device_id=DEVICE,
        session_id=session_id,
        seq=0,  # placeholder; the ledger assigns the real seq
        kind=EventKind.TOOL_USE.value,
        ts_device="2026-08-10T12:00:00.000000Z",
        ts_monotonic_ns=time.monotonic_ns(),
        tool_use_id="toolu_" + uuid.uuid4().hex[:8],
        tool_name="Bash",
        payload=payload,
        payload_hash=sha256_hex(canonicalize(payload)),
        model="claude-opus-4-20250514",
        provider="anthropic",
        trace_id=new_trace_id(),
        span_id=new_span_id(),
        parent_span_id=None,
        continues_from=None,
    )


@pytest.fixture
def ledger(tmp_path):
    led = Ledger(tmp_path / "ledger.sqlite3", DEVICE)
    yield led
    led.close()


@pytest.fixture
def key(tmp_path) -> DeviceKey:
    return load_or_create_device_key(tmp_path / "keydir")


def _decode_body(request: httpx.Request) -> dict:
    return json.loads(gzip.decompress(request.content))


def make_shipper(ledger: Ledger, key: DeviceKey, handler, **kwargs) -> Shipper:
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return Shipper(
        ledger,
        key,
        coriqo_base_url="https://coriqo.example.com",
        http_client=client,
        **kwargs,
    )


def test_ship_once_returns_none_when_nothing_unsynced(ledger, key):
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called when nothing is unsynced")

    shipper = make_shipper(ledger, key, handler)
    assert shipper.ship_once() is None


def test_ship_once_clean_accept_advances_watermark(ledger, key):
    for i in range(3):
        ledger.append(make_event(payload={"i": i}))

    requests_seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests_seen.append(request)
        body = _decode_body(request)
        # W8: the batch also says who is shipping; a shipper built with no payload mode sends none.
        assert set(body.keys()) == {"device_id", "entries"}
        assert body["device_id"] == key.device_id
        assert len(body["entries"]) == 3
        for entry in body["entries"]:
            assert set(entry.keys()) == {"seq", "entry_hash", "event"}
        assert request.headers["x-coriqo-device"] == key.device_id
        assert request.headers["x-coriqo-signature"].startswith("ed25519:")
        assert request.headers["content-encoding"] == "gzip"
        return httpx.Response(202, json={"accepted": 3, "duplicates": 0, "gaps": []})

    shipper = make_shipper(ledger, key, handler)
    result = shipper.ship_once()

    assert len(requests_seen) == 1
    assert isinstance(result, ShipResult)
    assert result.accepted == 3
    assert result.duplicates == 0
    assert result.gaps == []
    assert result.synced_up_to == 3
    assert ledger.get_synced_up_to() == 3


def test_ship_once_partial_dedup(ledger, key):
    for i in range(4):
        ledger.append(make_event(payload={"i": i}))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"accepted": 2, "duplicates": 2, "gaps": []})

    shipper = make_shipper(ledger, key, handler)
    result = shipper.ship_once()

    assert result.accepted == 2
    assert result.duplicates == 2
    # Even though only 2 were newly accepted, all 4 shipped seqs are
    # confirmed by the server (accepted + duplicates), so the watermark
    # advances past all of them.
    assert result.synced_up_to == 4
    assert ledger.get_synced_up_to() == 4


def test_ship_once_signature_is_over_canonicalized_body(ledger, key):
    ledger.append(make_event())
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = _decode_body(request)
        captured["signature"] = request.headers["x-coriqo-signature"]
        return httpx.Response(202, json={"accepted": 1, "duplicates": 0, "gaps": []})

    shipper = make_shipper(ledger, key, handler)
    shipper.ship_once()

    expected_sig = key.sign(canonicalize(captured["body"]))
    assert captured["signature"] == expected_sig


def test_ship_once_gap_in_middle_does_not_advance_past_gap(ledger, key):
    """Critical correctness case: a gap reported mid-batch must stop the
    watermark before the gap, even though later seqs in the same batch were
    reported accepted by the server."""
    for i in range(5):
        ledger.append(make_event(payload={"i": i}))

    # Server accepts seq 1,2 and 4,5 but reports seq 3 as a gap (e.g. a
    # different device's concurrent write raced it, or local drop). Even
    # though seq 4 and 5 are "accepted" per the count, the watermark may not
    # skip over the gap at seq 3.
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            202, json={"accepted": 4, "duplicates": 0, "gaps": [[3, 3]]}
        )

    shipper = make_shipper(ledger, key, handler)
    result = shipper.ship_once()

    assert result.gaps == [[3, 3]]
    # Watermark stops at seq 2 (the highest seq strictly before the gap),
    # never advancing to 4 or 5 despite them being in the "accepted" count.
    assert result.synced_up_to == 2
    assert ledger.get_synced_up_to() == 2

    # The next read_unsynced() call still includes seq 3 onward, so a
    # subsequent ship attempt will retry them.
    unsynced_seqs = [e.seq for e in ledger.read_unsynced()]
    assert unsynced_seqs == [3, 4, 5]


def test_ship_once_stale_gap_below_watermark_does_not_stall_sync(ledger, key):
    # A gap the server reports at a seq already behind the local watermark
    # (an old, unrelated, or permanently-lost gap from before this batch)
    # must never block this batch — or every batch after it — from syncing.
    for _ in range(3):
        ledger.append(make_event())
    ledger.set_synced_up_to(2)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"accepted": 1, "duplicates": 0, "gaps": [[1, 1]]})

    shipper = make_shipper(ledger, key, handler)
    result = shipper.ship_once()

    assert result.synced_up_to == 3
    assert ledger.get_synced_up_to() == 3


def test_ship_once_no_confirmation_leaves_watermark_unchanged(ledger, key):
    ledger.append(make_event())

    def handler(request: httpx.Request) -> httpx.Response:
        # Entire batch is one big gap: nothing safe to mark synced.
        return httpx.Response(202, json={"accepted": 0, "duplicates": 0, "gaps": [[1, 1]]})

    shipper = make_shipper(ledger, key, handler)
    result = shipper.ship_once()

    assert result.synced_up_to == 0
    assert ledger.get_synced_up_to() == 0


def test_ship_once_raises_ship_error_on_non_2xx(ledger, key):
    ledger.append(make_event())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    shipper = make_shipper(ledger, key, handler)
    with pytest.raises(ShipError):
        shipper.ship_once()

    # Nothing was confirmed; watermark untouched.
    assert ledger.get_synced_up_to() == 0


def test_ship_once_raises_ship_error_on_network_failure(ledger, key):
    ledger.append(make_event())

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    shipper = make_shipper(ledger, key, handler)
    with pytest.raises(ShipError):
        shipper.ship_once()


def test_ship_once_respects_max_batch_events(ledger, key):
    for i in range(10):
        ledger.append(make_event(payload={"i": i}))

    def handler(request: httpx.Request) -> httpx.Response:
        body = _decode_body(request)
        assert len(body["entries"]) == 3
        return httpx.Response(202, json={"accepted": 3, "duplicates": 0, "gaps": []})

    shipper = make_shipper(ledger, key, handler, max_batch_events=3)
    result = shipper.ship_once()
    assert result.synced_up_to == 3
    assert len(ledger.read_unsynced()) == 7


def test_ship_once_respects_max_batch_bytes(ledger, key):
    # Each entry's canonical JSON is a few hundred bytes; force a tiny byte
    # cap so only the first entry fits.
    for i in range(5):
        ledger.append(make_event(payload={"i": i, "padding": "x" * 50}))

    def handler(request: httpx.Request) -> httpx.Response:
        body = _decode_body(request)
        assert len(body["entries"]) == 1
        return httpx.Response(202, json={"accepted": 1, "duplicates": 0, "gaps": []})

    shipper = make_shipper(ledger, key, handler, max_batch_bytes=200)
    shipper.ship_once()


def test_retry_after_overrides_backoff_and_run_forever_waits_at_least_that_long(ledger, key):
    ledger.append(make_event())
    call_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return httpx.Response(429, json={"error": "slow down"}, headers={"Retry-After": "7"})
        return httpx.Response(202, json={"accepted": 1, "duplicates": 0, "gaps": []})

    waits: list[float] = []
    stop = threading.Event()

    def fake_wait(seconds: float) -> bool:
        waits.append(seconds)
        # Stop after we've observed the backoff wait following the failure.
        if len(waits) >= 2:
            stop.set()
        return stop.is_set()

    shipper = make_shipper(ledger, key, handler, wait=fake_wait)
    start = time.monotonic()
    shipper.run_forever(stop=stop)
    elapsed = time.monotonic() - start

    # Fast: the injected wait function never actually sleeps for 7 seconds.
    assert elapsed < 0.5
    assert call_count >= 1
    # The wait triggered by the 429/Retry-After must be exactly 7 (not the
    # computed exponential-backoff-with-jitter value).
    assert 7 in waits


def test_run_forever_exits_promptly_when_stop_is_set_mid_backoff(ledger, key):
    ledger.append(make_event())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "unavailable"})

    stop = threading.Event()
    call_count = 0

    def fake_wait(seconds: float) -> bool:
        nonlocal call_count
        call_count += 1
        # Simulate stop firing while we're "asleep" mid-backoff.
        stop.set()
        return True

    shipper = make_shipper(ledger, key, handler, wait=fake_wait)

    thread = threading.Thread(target=shipper.run_forever, kwargs={"stop": stop})
    start = time.monotonic()
    thread.start()
    thread.join(timeout=2.0)
    elapsed = time.monotonic() - start

    assert not thread.is_alive()
    assert elapsed < 2.0
    assert call_count >= 1


def test_run_forever_never_raises_on_repeated_failures(ledger, key):
    ledger.append(make_event())

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    stop = threading.Event()
    attempts = 0

    def fake_wait(seconds: float) -> bool:
        nonlocal attempts
        attempts += 1
        if attempts >= 3:
            stop.set()
        return stop.is_set()

    shipper = make_shipper(ledger, key, handler, wait=fake_wait)
    # Must not raise despite every attempt failing.
    shipper.run_forever(stop=stop)
    assert attempts >= 3


def _append_checkpoints(ledger: Ledger, key: DeviceKey, count: int) -> list[int]:
    """Append ``count`` events, one checkpoint per event, and return the
    checkpoints' seq_ends in order."""
    cpr = Checkpointer(ledger, key, every_events=1)
    seq_ends = []
    for i in range(count):
        entry = ledger.append(make_event(payload={"i": i}))
        cp = cpr.note(entry.seq)
        assert cp is not None
        seq_ends.append(cp["seq_end"])
    return seq_ends


def test_ship_checkpoints_once_clean_accept_advances_watermark(ledger, key):
    seq_ends = _append_checkpoints(ledger, key, 3)

    def handler(request: httpx.Request) -> httpx.Response:
        body = _decode_body(request)
        assert set(body.keys()) == {"device_id", "checkpoints"}
        assert len(body["checkpoints"]) == 3
        return httpx.Response(202, json={"accepted": 3, "duplicates": 0, "rejected": []})

    shipper = make_shipper(ledger, key, handler)
    result = shipper.ship_checkpoints_once()

    assert isinstance(result, CheckpointShipResult)
    assert result.accepted == 3
    assert result.synced_checkpoint_up_to == seq_ends[-1]
    assert ledger.get_synced_checkpoint_up_to() == seq_ends[-1]


def test_ship_checkpoints_once_rejected_checkpoint_does_not_advance_past_it(ledger, key):
    # Server accepts fewer checkpoints than were sent (e.g. one was
    # malformed/failed its own signature check) — the watermark must stop
    # strictly before the rejected checkpoint, never past it, even though
    # later checkpoints in the same batch were reported as accepted.
    seq_ends = _append_checkpoints(ledger, key, 5)
    rejected_seq_end = seq_ends[2]

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            202,
            json={
                "accepted": 4,
                "duplicates": 0,
                "rejected": [{"seq_end": rejected_seq_end, "reason": "bad signature"}],
            },
        )

    shipper = make_shipper(ledger, key, handler)
    result = shipper.ship_checkpoints_once()

    # Watermark stops at the checkpoint strictly before the rejected one.
    assert result.synced_checkpoint_up_to == seq_ends[1]
    assert ledger.get_synced_checkpoint_up_to() == seq_ends[1]

    # The rejected checkpoint (and everything after it) is retried on the
    # next attempt.
    unsynced = [cp["seq_end"] for cp in ledger.read_unsynced_checkpoints()]
    assert unsynced == seq_ends[2:]


def test_ship_checkpoints_once_rejected_checkpoint_retried_next_call(ledger, key):
    seq_ends = _append_checkpoints(ledger, key, 2)
    rejected_seq_end = seq_ends[0]

    calls = []

    def failing_then_accepting(request: httpx.Request) -> httpx.Response:
        body = _decode_body(request)
        calls.append(body)
        if len(calls) == 1:
            return httpx.Response(
                202,
                json={
                    "accepted": 1,
                    "duplicates": 0,
                    "rejected": [{"seq_end": rejected_seq_end, "reason": "bad signature"}],
                },
            )
        return httpx.Response(202, json={"accepted": 1, "duplicates": 1, "rejected": []})

    shipper = make_shipper(ledger, key, failing_then_accepting)

    first = shipper.ship_checkpoints_once()
    assert first.synced_checkpoint_up_to == 0
    assert ledger.get_synced_checkpoint_up_to() == 0
    assert [cp["seq_end"] for cp in calls[0]["checkpoints"]] == seq_ends

    second = shipper.ship_checkpoints_once()
    assert second.synced_checkpoint_up_to == seq_ends[-1]
    assert ledger.get_synced_checkpoint_up_to() == seq_ends[-1]
    # The retry batch still includes the previously-rejected checkpoint.
    assert [cp["seq_end"] for cp in calls[1]["checkpoints"]] == seq_ends


def test_ship_checkpoints_once_no_confirmation_leaves_watermark_unchanged(ledger, key):
    seq_ends = _append_checkpoints(ledger, key, 1)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            202,
            json={
                "accepted": 0,
                "duplicates": 0,
                "rejected": [{"seq_end": seq_ends[0], "reason": "bad signature"}],
            },
        )

    shipper = make_shipper(ledger, key, handler)
    result = shipper.ship_checkpoints_once()

    assert result.synced_checkpoint_up_to == 0
    assert ledger.get_synced_checkpoint_up_to() == 0


# -- ship_attestations_once (AIR-7d) -----------------------------------------

_ATTESTATION_BASE_URL = "https://coriqo.example.com"


def _verdict_event(
    agent_id: str, *, resource: str | None = "tool:payments.refund", on_behalf_of=None
) -> AgentEvent:
    payload: dict = {"verdict": "allowed", "reason": "in_scope", "agent_id": agent_id}
    if resource is not None:
        payload["resource"] = resource
    if on_behalf_of is not None:
        payload["on_behalf_of"] = on_behalf_of
    return AgentEvent(
        schema_version=EVENT_SCHEMA_VERSION,
        event_id="evt_" + uuid.uuid4().hex,
        device_id=DEVICE,
        session_id="sess_1",
        seq=0,
        kind=EventKind.MANDATE_VERDICT.value,
        ts_device="2026-08-10T12:00:00.000000Z",
        ts_monotonic_ns=time.monotonic_ns(),
        tool_use_id=None,
        tool_name=None,
        payload=payload,
        payload_hash=sha256_hex(canonicalize(payload)),
        model=None,
        provider="anthropic",
        trace_id=new_trace_id(),
        span_id=new_span_id(),
        parent_span_id=None,
        continues_from=None,
    )


def _attestation_client(key: DeviceKey, handler) -> AsyncCoriqoAgentsClient:
    identity = CoriqoIdentity.from_device(
        base_url=_ATTESTATION_BASE_URL, device_id=key.device_id, signer=key,
        tenant_slug="acme_bank",
    )
    return AsyncCoriqoAgentsClient(
        identity,
        http_client=httpx.AsyncClient(
            base_url=_ATTESTATION_BASE_URL, transport=httpx.MockTransport(handler)
        ),
    )


def make_shipper_with_attestation(
    ledger: Ledger, key: DeviceKey, attestation_handler, **kwargs
) -> Shipper:
    return Shipper(
        ledger,
        key,
        coriqo_base_url=_ATTESTATION_BASE_URL,
        http_client=httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(202))),
        attestation_client=_attestation_client(key, attestation_handler),
        **kwargs,
    )


def _append_checkpoint_over(ledger: Ledger, key: DeviceKey, events: list[AgentEvent]) -> dict:
    cpr = Checkpointer(ledger, key, every_events=len(events))
    checkpoint = None
    for event in events:
        entry = ledger.append(event)
        checkpoint = cpr.note(entry.seq)
    assert checkpoint is not None
    return checkpoint


def test_ship_attestations_once_returns_none_when_nothing_pending(ledger, key):
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should not be called when nothing is pending")

    shipper = make_shipper_with_attestation(ledger, key, handler)
    assert shipper.ship_attestations_once() is None


def test_ship_attestations_once_ships_envelope_and_advances_watermark(ledger, key):
    checkpoint = _append_checkpoint_over(ledger, key, [_verdict_event("agent_1")])

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"status": "accepted"})

    shipper = make_shipper_with_attestation(ledger, key, handler)
    result = shipper.ship_attestations_once()

    assert isinstance(result, AttestationShipResult)
    assert result.envelopes_shipped == 1
    assert result.duplicates == 0
    assert result.synced_attestation_up_to == checkpoint["seq_end"]
    assert ledger.get_synced_attestation_up_to() == checkpoint["seq_end"]

    request = seen[0]
    assert request.url.path == "/api/v1/agent-runtime/attestations"
    # Body is gzipped, same as every other ledger-shipper request (checkpoints,
    # ingest batches) — attest_execution() uses the real Coriqo signing scheme,
    # not a bespoke one, so its body is compressed the same way.
    body = json.loads(gzip.decompress(request.content))
    assert body["subject"]["agent_id"] == "agent_1"
    assert body["events"][0]["resource"] == "tool:payments.refund"
    # The request itself is device-signed — the HTTP signature layer, kept
    # distinct from the envelope's own chain_head already inside `body`.
    # Asserting both here is what keeps this test from
    # conflating the two.
    assert "X-Coriqo-Signature" in request.headers
    assert "chain_head" in body


def test_ship_attestations_once_duplicate_advances_watermark_like_success(ledger, key):
    checkpoint = _append_checkpoint_over(ledger, key, [_verdict_event("agent_1")])

    def handler(request: httpx.Request) -> httpx.Response:
        # Coriqo's real AttestationIngestOut shape (runtime_router.py) — no
        # top-level "duplicate" boolean, only "status": "sealed" | "duplicate".
        return httpx.Response(200, json={"status": "duplicate", "record_id": "rec_1"})

    shipper = make_shipper_with_attestation(ledger, key, handler)
    result = shipper.ship_attestations_once()

    assert result.envelopes_shipped == 0
    assert result.duplicates == 1
    assert result.synced_attestation_up_to == checkpoint["seq_end"]
    assert ledger.get_synced_attestation_up_to() == checkpoint["seq_end"]


def test_ship_attestations_once_4xx_does_not_retry_or_advance_watermark(ledger, key):
    checkpoint = _append_checkpoint_over(ledger, key, [_verdict_event("agent_1")])

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(400, json={"detail": "broken internal event chain"})

    shipper = make_shipper_with_attestation(ledger, key, handler)

    with pytest.raises(ShipError):
        shipper.ship_attestations_once()

    assert len(seen) == 1, "a refused envelope must not be retried"
    assert ledger.get_synced_attestation_up_to() == 0
    assert checkpoint["seq_end"] > 0


def test_ship_attestations_once_no_attestable_events_still_advances_watermark(ledger, key):
    """A checkpoint window with only non-attestable events (e.g. TOOL_USE) has
    nothing to attest, so it is not an error to be retried forever — the
    watermark moves past it with no envelope sent."""
    checkpoint = _append_checkpoint_over(ledger, key, [make_event(payload={"i": 0})])

    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("nothing attestable, no request should be sent")

    shipper = make_shipper_with_attestation(ledger, key, handler)
    result = shipper.ship_attestations_once()

    assert result.envelopes_shipped == 0
    assert result.duplicates == 0
    assert result.synced_attestation_up_to == checkpoint["seq_end"]
    assert ledger.get_synced_attestation_up_to() == checkpoint["seq_end"]


def test_ship_attestations_once_groups_by_agent_into_separate_envelopes(ledger, key):
    checkpoint = _append_checkpoint_over(
        ledger, key, [_verdict_event("agent_1"), _verdict_event("agent_2")]
    )

    seen_agent_ids: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(gzip.decompress(request.content))
        seen_agent_ids.append(body["subject"]["agent_id"])
        return httpx.Response(200, json={"status": "accepted"})

    shipper = make_shipper_with_attestation(ledger, key, handler)
    result = shipper.ship_attestations_once()

    assert result.envelopes_shipped == 2
    assert sorted(seen_agent_ids) == ["agent_1", "agent_2"]
    assert ledger.get_synced_attestation_up_to() == checkpoint["seq_end"]
