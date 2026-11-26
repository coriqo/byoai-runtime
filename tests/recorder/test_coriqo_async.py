"""The async, retrying Coriqo client.

Companion to test_coriqo_agents.py, which covers the synchronous publisher.
The fakes here use ``httpx.MockTransport`` the same way, so nothing touches a
network, and the signature assertions re-derive the signed bytes from the
recorded request rather than from the client's own helper where it matters —
a test that asks the client what it signed would pass on any format at all.

The canonical tuple checked here is Coriqo's: canonical JSON over ``body_sha256``,
``method``, ``path`` (query string included), ``public_key`` (the signer's own,
lowercase hex) and ``timestamp``, with a 120s past / 30s future window.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json

import httpx
import pytest

from byoai.errors import ByoAIError, EnforcementIdentityUnavailableError, RateLimitError
from byoai.recorder import coriqo_async
from byoai.recorder.coriqo_agents import (
    AgentRegistration,
    AgentSuspendedError,
    CoriqoAgentsError,
    CoriqoCredentials,
)
from byoai.recorder.coriqo_async import (
    ENFORCEMENT_PREFIX,
    AsyncCoriqoAgentsClient,
    RetryPolicy,
    device_headers,
    signing_payload,
)
from byoai.recorder.identity import CoriqoIdentity
from byoai.recorder.keys import load_or_create_device_key
from byoai.recorder.redact import PAYLOAD_MODE_HEADER, PayloadMode, payload_mode_headers

_AGENT = "coriqo-agent-1"
_BASE = "https://coriqo.test"


class RecordingSleep:
    """Stands in for ``asyncio.sleep`` so backoff is observable, not spent."""

    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def _credentials() -> CoriqoCredentials:
    return CoriqoCredentials(
        base_url=_BASE, api_key="cq_sa_test", tenant_slug="acme_bank"
    )


def _client(handler, **kwargs) -> AsyncCoriqoAgentsClient:
    identity = kwargs.pop("identity", None) or CoriqoIdentity.from_credentials(
        _credentials()
    )
    return AsyncCoriqoAgentsClient(
        identity,
        tenant_slug=kwargs.pop("tenant_slug", "acme_bank"),
        http_client=httpx.AsyncClient(
            base_url=_BASE, transport=httpx.MockTransport(handler)
        ),
        **kwargs,
    )


def _device_client(handler, tmp_path, **kwargs) -> AsyncCoriqoAgentsClient:
    key = load_or_create_device_key(tmp_path)
    identity = CoriqoIdentity.from_device(
        base_url=_BASE,
        device_id=key.device_id,
        signer=key,
        tenant_slug=kwargs.pop("enrolled_tenant", None),
    )
    return _client(handler, identity=identity, **kwargs)


def _json(payload: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(status, json=payload)


# -- the happy path --------------------------------------------------------


async def test_successful_request_returns_parsed_body():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"id": _AGENT, "status": "in_review"})

    client = _client(handler)
    try:
        agent = await client.get_agent(_AGENT)
    finally:
        await client.close()

    assert agent == {"id": _AGENT, "status": "in_review"}
    assert seen[0].headers["X-API-Key"] == "cq_sa_test"
    assert seen[0].headers["X-Tenant-Slug"] == "acme_bank"


async def test_caller_supplied_client_is_not_closed():
    http_client = httpx.AsyncClient(
        base_url=_BASE, transport=httpx.MockTransport(lambda r: _json({}))
    )
    client = AsyncCoriqoAgentsClient(
        _credentials(), http_client=http_client, tenant_slug="acme_bank"
    )
    await client.close()
    assert not http_client.is_closed
    await http_client.aclose()


async def test_list_agents_pages_until_total_is_reached():
    def handler(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params["offset"])
        items = [{"id": f"a{offset}"}] if offset < 2 else []
        return _json({"items": items, "total": 2})

    client = _client(handler)
    try:
        assert [a["id"] for a in await client.list_agents()] == ["a0", "a1"]
    finally:
        await client.close()


# -- retry -----------------------------------------------------------------


async def test_retries_retryable_status_then_succeeds():
    statuses = [503, 502, 200]

    def handler(request: httpx.Request) -> httpx.Response:
        status = statuses.pop(0)
        if status == 200:
            return _json({"id": _AGENT})
        return httpx.Response(status, text="upstream is unwell")

    sleep = RecordingSleep()
    client = _client(handler, sleep=sleep, retry=RetryPolicy(attempts=3))
    try:
        assert await client.get_agent(_AGENT) == {"id": _AGENT}
    finally:
        await client.close()

    assert statuses == []
    assert len(sleep.delays) == 2


async def test_retry_budget_exhausted_raises_the_last_error():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, json={"detail": "still unwell"})

    sleep = RecordingSleep()
    client = _client(handler, sleep=sleep, retry=RetryPolicy(attempts=3))
    try:
        with pytest.raises(CoriqoAgentsError) as excinfo:
            await client.get_agent(_AGENT)
    finally:
        await client.close()

    assert calls == 3
    assert len(sleep.delays) == 2  # slept between attempts, not after the last
    assert excinfo.value.status_code == 503
    assert excinfo.value.detail == "still unwell"


async def test_transport_failure_is_retried_then_surfaces_as_coriqo_error():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("no route to host")

    client = _client(handler, sleep=RecordingSleep(), retry=RetryPolicy(attempts=2))
    try:
        with pytest.raises(CoriqoAgentsError) as excinfo:
            await client.get_agent(_AGENT)
    finally:
        await client.close()

    assert calls == 2
    assert excinfo.value.status_code is None


async def test_retry_after_header_is_honored_verbatim():
    statuses = [429, 200]

    def handler(request: httpx.Request) -> httpx.Response:
        if statuses.pop(0) == 429:
            return httpx.Response(429, headers={"retry-after": "7"}, text="slow down")
        return _json({"id": _AGENT})

    sleep = RecordingSleep()
    client = _client(handler, sleep=sleep, retry=RetryPolicy(attempts=2))
    try:
        await client.get_agent(_AGENT)
    finally:
        await client.close()

    # Not jittered: the server named a time, and the computed backoff for the
    # first attempt would be well under a second.
    assert sleep.delays == [7.0]


async def test_retry_after_is_capped_so_a_bad_header_cannot_park_a_refresh_loop():
    policy = RetryPolicy(max_retry_after=30.0)
    assert policy.delay_for(0, retry_after=3600.0) == 30.0


async def test_rate_limit_error_from_a_hook_carries_its_own_retry_after():
    """A transport already speaking the runtime's error vocabulary is trusted:
    `retryable` decides, `retry_after` sets the wait."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RateLimitError("throttled", provider="coriqo", retry_after=2.5)
        return _json({"id": _AGENT})

    sleep = RecordingSleep()
    client = _client(handler, sleep=sleep, retry=RetryPolicy(attempts=2))
    try:
        assert await client.get_agent(_AGENT) == {"id": _AGENT}
    finally:
        await client.close()

    assert sleep.delays == [2.5]


async def test_non_idempotent_write_is_not_retried():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503, text="gateway")

    sleep = RecordingSleep()
    client = _client(handler, sleep=sleep, retry=RetryPolicy(attempts=5))
    try:
        with pytest.raises(CoriqoAgentsError):
            await client.record_trace(_AGENT, output="done")
    finally:
        await client.close()

    assert calls == 1, "a retried trace would record the same decision twice"
    assert sleep.delays == []


async def test_registration_is_retried_only_with_an_external_id_and_opt_in():
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(1)
        return httpx.Response(503, text="gateway")

    policy = RetryPolicy(attempts=3, retry_writes=True)

    client = _client(handler, sleep=RecordingSleep(), retry=policy)
    try:
        with pytest.raises(CoriqoAgentsError):
            await client.register_agent(AgentRegistration(name="a"))
        assert len(seen) == 1, "no external_id means a retry creates a duplicate agent"

        seen.clear()
        with pytest.raises(CoriqoAgentsError):
            await client.register_agent(
                AgentRegistration(name="a", external_id="my-app:a")
            )
        assert len(seen) == 3
    finally:
        await client.close()


async def test_registration_is_not_retried_by_default():
    seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(1)
        return httpx.Response(503, text="gateway")

    client = _client(handler, sleep=RecordingSleep(), retry=RetryPolicy(attempts=3))
    try:
        with pytest.raises(CoriqoAgentsError):
            await client.register_agent(
                AgentRegistration(name="a", external_id="my-app:a")
            )
    finally:
        await client.close()
    assert len(seen) == 1


# -- jitter ----------------------------------------------------------------


def test_backoff_grows_and_stays_inside_its_jitter_band():
    policy = RetryPolicy(base_delay=0.2, max_delay=5.0, jitter=0.5)
    for attempt in range(4):
        capped = min(0.2 * (2**attempt), 5.0)
        for _ in range(50):
            delay = policy.delay_for(attempt)
            assert capped * 0.5 <= delay < capped


def test_jitter_actually_varies():
    policy = RetryPolicy(base_delay=1.0, jitter=0.5)
    seen = {policy.delay_for(2) for _ in range(50)}
    assert len(seen) > 1, "backoff without jitter puts a whole fleet back in lockstep"


def test_zero_jitter_is_deterministic():
    policy = RetryPolicy(base_delay=0.25, jitter=0.0)
    assert policy.delay_for(1) == 0.5


def test_backoff_is_capped_at_max_delay():
    policy = RetryPolicy(base_delay=1.0, max_delay=2.0, jitter=0.0)
    assert policy.delay_for(10) == 2.0


def test_a_policy_that_cannot_retry_is_rejected_at_construction():
    with pytest.raises(ValueError):
        RetryPolicy(attempts=0)
    with pytest.raises(ValueError):
        RetryPolicy(jitter=1.5)


# -- error contract --------------------------------------------------------


async def test_423_raises_agent_suspended():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(423, json={"detail": "agent is suspended"})

    client = _client(handler)
    try:
        with pytest.raises(AgentSuspendedError) as excinfo:
            await client.record_trace(_AGENT, output="done")
    finally:
        await client.close()

    assert excinfo.value.status_code == 423
    assert excinfo.value.detail == "agent is suspended"


@pytest.mark.parametrize("status", [403, 409, 422])
async def test_status_codes_are_preserved_for_branching(status: int):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"detail": f"nope {status}"})

    client = _client(handler)
    try:
        with pytest.raises(CoriqoAgentsError) as excinfo:
            await client.get_agent(_AGENT)
    finally:
        await client.close()

    assert excinfo.value.status_code == status
    assert not isinstance(excinfo.value, AgentSuspendedError)


async def test_every_error_is_a_byoai_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    client = _client(handler)
    try:
        with pytest.raises(ByoAIError):
            await client.get_agent(_AGENT)
    finally:
        await client.close()


async def test_two_xx_with_a_non_json_body_is_a_coriqo_error():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>maintenance</html>")

    client = _client(handler)
    try:
        with pytest.raises(CoriqoAgentsError, match="non-JSON"):
            await client.get_agent(_AGENT)
    finally:
        await client.close()


# -- signing ---------------------------------------------------------------


async def test_signed_request_matches_coriqos_canonical_tuple(tmp_path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"allowed_tools": ["search"], "mandate_version": 3})

    key = load_or_create_device_key(tmp_path)
    client = _device_client(handler, tmp_path)
    try:
        snapshot = await client.fetch_mandate(_AGENT)
    finally:
        await client.close()

    assert snapshot["allowed_tools"] == ["search"]
    request = seen[0]

    public_key_hex = base64.b64decode(key.public_key_b64).hex()
    assert request.headers["X-Coriqo-Public-Key"] == public_key_hex
    assert request.headers["X-Tenant-Slug"] == "acme_bank"
    # The enforcement path refuses a service-account key outright, so sending
    # one alongside a signature would turn a valid request into a 403.
    assert "X-API-Key" not in request.headers

    expected = json.dumps(
        {
            "body_sha256": hashlib.sha256(request.content).hexdigest(),
            "method": "GET",
            "path": f"{ENFORCEMENT_PREFIX}/agents/{_AGENT}/mandate",
            "public_key": public_key_hex,
            "timestamp": request.headers["X-Coriqo-Timestamp"],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    signature = "ed25519:" + base64.b64encode(
        bytes.fromhex(request.headers["X-Coriqo-Signature"])
    ).decode("ascii")
    assert key.verify(key.public_key_b64, expected, signature)


async def test_signed_post_covers_the_exact_body_bytes(tmp_path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"id": "verdict-1"}, status=201)

    key = load_or_create_device_key(tmp_path)
    client = _device_client(handler, tmp_path)
    try:
        await client.record_verdict(_AGENT, tool="rm", verdict="blocked")
    finally:
        await client.close()

    request = seen[0]
    assert json.loads(request.content)["verdict"] == "blocked"
    payload = signing_payload(
        method="POST",
        path=f"{ENFORCEMENT_PREFIX}/agents/{_AGENT}/verdicts",
        body=request.content,
        timestamp=request.headers["X-Coriqo-Timestamp"],
        public_key_hex=base64.b64decode(key.public_key_b64).hex(),
    )
    signature = "ed25519:" + base64.b64encode(
        bytes.fromhex(request.headers["X-Coriqo-Signature"])
    ).decode("ascii")
    assert key.verify(key.public_key_b64, payload, signature)


async def test_attest_capability_snapshot_sends_the_wire_contract(tmp_path):
    """W-7: the request shape Coriqo's wire contract names, plus the
    default (never send raw prompt text unless opted in)."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"status": "accepted"})

    client = _device_client(handler, tmp_path)
    tools = [{"name": "search", "description": "d", "input_schema": {"type": "object"}}]
    try:
        await client.attest_capability_snapshot(
            _AGENT,
            tools=tools,
            system_prompt="you are a helpful assistant",
            model_id="claude-x",
            runtime_version="1.2.3",
        )
    finally:
        await client.close()

    request = seen[0]
    assert request.url.path == f"{ENFORCEMENT_PREFIX}/agents/{_AGENT}/capability-snapshot"
    body = json.loads(request.content)
    assert body["tools"] == tools
    # store_system_prompt defaults to False: the raw text never rides along.
    assert body["system_prompt"] is None
    assert body["system_prompt_sha256"] == hashlib.sha256(
        b"you are a helpful assistant"
    ).hexdigest()
    assert body["model_id"] == "claude-x"
    assert body["runtime_version"] == "1.2.3"
    assert body["digest_spec"] == "cap-digest-v1"
    assert len(body["digest"]) == 64
    assert "X-Coriqo-Signature" in request.headers


async def test_attest_capability_snapshot_sends_raw_prompt_only_when_opted_in(tmp_path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"status": "accepted"})

    client = _device_client(handler, tmp_path)
    try:
        await client.attest_capability_snapshot(
            _AGENT,
            tools=[],
            system_prompt="secret instructions",
            store_system_prompt=True,
        )
    finally:
        await client.close()

    body = json.loads(seen[0].content)
    assert body["system_prompt"] == "secret instructions"


async def test_attest_capability_snapshot_digest_matches_local_port(tmp_path):
    """The digest on the wire is exactly what the local cap-digest-v1 port
    computes for the same inputs — the 422-avoidance property this endpoint
    depends on."""
    from byoai.recorder.capability_digest import compute_capability_digest

    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"status": "accepted"})

    tools = [{"name": "b"}, {"name": "a", "description": "d"}]
    client = _device_client(handler, tmp_path)
    try:
        await client.attest_capability_snapshot(
            _AGENT, tools=tools, system_prompt=None, model_id="m1",
        )
    finally:
        await client.close()

    expected_digest, expected_prompt_hash = compute_capability_digest(
        tools=tools, system_prompt=None, model_id="m1",
    )
    body = json.loads(seen[0].content)
    assert body["digest"] == expected_digest
    assert body["system_prompt_sha256"] == expected_prompt_hash


# -- attest_execution (AIR-7d) ----------------------------------------------


def _envelope(agent_id: str = _AGENT) -> dict:
    return {
        "emitter": {"kind": "proxy", "vendor": "byoai-runtime", "software_version": "0.1.0"},
        "subject": {"agent_id": agent_id, "agent_version": "1.0.0"},
        "window": {"started_at": "2026-09-22T10:00:00Z", "ended_at": "2026-09-22T10:00:05Z"},
        "events": [
            {
                "seq": 1,
                "event_type": "MANDATE_VERDICT",
                "ts": "2026-09-22T10:00:01Z",
                "payload_hash": "abc123",
                "resource": "tool:payments.refund",
                "on_behalf_of": [],
            }
        ],
        "chain_head": "deadbeef",
    }


async def test_attest_execution_sends_envelope_device_signed(tmp_path):
    """Request lands on the bare (no `/agents/{id}/`) attestations path,
    carries the envelope verbatim (gzipped, canonical), and is signed with
    the SECOND, raw ledger-shipper scheme — not the tuple-based
    `device_headers()` enforcement scheme every other signed call in this
    client uses.

    AIR-7e (a real round trip against a live Coriqo instance) found that
    `/attestations` uses Coriqo's ledger-device check, the same no-timestamp
    `Ed25519(canonicalize(body))` scheme `Shipper._post_signed_batch`
    already speaks for `/ingest/batch`/`/checkpoints/batch` — not
    `device_headers()`, which this method was first written to use
    but which Coriqo's actual live route 401s on ("Device signature did not
    verify"). See `attest_execution`'s docstring for the full account; this
    test pins the corrected contract."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"status": "accepted"})

    key = load_or_create_device_key(tmp_path)
    client = _device_client(handler, tmp_path)
    envelope = _envelope()
    try:
        result = await client.attest_execution(_AGENT, envelope)
    finally:
        await client.close()

    assert result == {"status": "accepted"}
    request = seen[0]
    assert request.url.path == f"{ENFORCEMENT_PREFIX}/attestations"
    assert request.headers["Content-Encoding"] == "gzip"
    canonical_body = gzip.decompress(request.content)
    assert json.loads(canonical_body) == envelope

    # Re-derive the signature independently of the client's own helper, same
    # discipline the module docstring calls for: a test that only asks the
    # client what it signed would pass for any signing scheme at all.
    expected_signature = key.sign(canonical_body)
    assert request.headers["X-Coriqo-Signature"] == expected_signature
    assert request.headers["X-Coriqo-Device"] == key.device_id
    # The tuple-scheme-only headers must be ABSENT — their presence would
    # mean this is still signing the wrong way, just with extra headers
    # current_ledger_device happens to ignore.
    assert "X-Coriqo-Public-Key" not in request.headers
    assert "X-Coriqo-Timestamp" not in request.headers


async def test_attest_execution_rejects_mismatched_subject(tmp_path):
    """Guards the caller against shipping an envelope for a different agent
    than the one it claims to be attesting — a local bug, not something
    Coriqo should have to catch for us."""
    client = _device_client(lambda r: _json({}), tmp_path)
    try:
        with pytest.raises(ValueError, match="does not match"):
            await client.attest_execution("some-other-agent", _envelope(_AGENT))
    finally:
        await client.close()


async def test_attest_execution_duplicate_response_is_returned_not_raised(tmp_path):
    """A `duplicate` response is Coriqo's idempotency signal, not
    an error — the client hands it back to the caller (shipper.py) to act
    on, same as it would a fresh accept."""
    client = _device_client(
        lambda r: _json({"status": "duplicate", "duplicate": True}), tmp_path
    )
    try:
        result = await client.attest_execution(_AGENT, _envelope())
    finally:
        await client.close()

    assert result["duplicate"] is True


async def test_attest_execution_4xx_is_not_retried(tmp_path):
    """A refused envelope (bad chain, unbound agent, ...) raises immediately
    and is never resent — a retry after silently reshaping the batch would
    be a second, divergent attestation, not a retry of the first."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"detail": "broken internal event chain"}, status=400)

    client = _device_client(handler, tmp_path)
    try:
        with pytest.raises(CoriqoAgentsError):
            await client.attest_execution(_AGENT, _envelope())
    finally:
        await client.close()

    assert len(seen) == 1, "a refused attestation must not be retried"


async def test_a_default_api_key_header_is_stripped_from_a_signed_request(tmp_path):
    """Coriqo 403s any enforcement request presenting a service-account key, so
    one sitting in a caller-supplied client's default headers must not ride
    along on an otherwise valid signature."""
    seen: list[httpx.Request] = []
    key = load_or_create_device_key(tmp_path)
    identity = CoriqoIdentity.from_device(
        base_url=_BASE, device_id=key.device_id, signer=key
    )

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"allowed_tools": []})

    client = AsyncCoriqoAgentsClient(
        identity,
        tenant_slug="acme_bank",
        http_client=httpx.AsyncClient(
            base_url=_BASE,
            headers={"X-API-Key": "cq_sa_test"},
            transport=httpx.MockTransport(handler),
        ),
    )
    try:
        await client.fetch_mandate(_AGENT)
    finally:
        await client.close()

    assert "X-API-Key" not in seen[0].headers


def test_the_signed_path_includes_the_query_string(tmp_path):
    key = load_or_create_device_key(tmp_path)
    plain = device_headers(key, method="GET", path="/x/agents", body=b"")
    with_query = device_headers(key, method="GET", path="/x/agents?limit=1", body=b"")
    assert plain["X-Coriqo-Signature"] != with_query["X-Coriqo-Signature"]


def test_the_signers_own_key_is_inside_the_signed_bytes(tmp_path):
    """So a captured signature cannot be replayed under a different identity."""
    key = load_or_create_device_key(tmp_path)
    mine = signing_payload(
        method="GET",
        path="/x",
        body=b"",
        timestamp="2026-08-25T10:00:00Z",
        public_key_hex=base64.b64decode(key.public_key_b64).hex(),
    )
    theirs = signing_payload(
        method="GET",
        path="/x",
        body=b"",
        timestamp="2026-08-25T10:00:00Z",
        public_key_hex="ab" * 32,
    )
    assert mine != theirs


def test_signing_timestamp_is_rfc3339_utc_to_the_second():
    from byoai.recorder.coriqo_async import signing_timestamp

    stamp = signing_timestamp()
    assert stamp.endswith("Z") and "." not in stamp
    assert len(stamp) == len("2026-08-25T10:00:00Z")


async def test_each_retry_is_signed_afresh(tmp_path, monkeypatch):
    """Coriqo refuses a signature more than 120s old, so a retried attempt has
    to be re-signed at the moment it is sent. Reusing the first attempt's
    headers would work in a unit test and fail against a slow real outage."""
    seen: list[httpx.Request] = []
    statuses = [503, 200]
    stamps = iter(["2026-08-25T10:00:00Z", "2026-08-25T10:00:30Z"])
    monkeypatch.setattr(coriqo_async, "signing_timestamp", lambda *a, **k: next(stamps))

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if statuses.pop(0) == 503:
            return httpx.Response(503, text="gateway")
        return _json({"allowed_tools": []})

    client = _device_client(
        handler, tmp_path, sleep=RecordingSleep(), retry=RetryPolicy(attempts=2)
    )
    try:
        await client.fetch_mandate(_AGENT)
    finally:
        await client.close()

    assert len(seen) == 2
    assert [r.headers["X-Coriqo-Timestamp"] for r in seen] == [
        "2026-08-25T10:00:00Z",
        "2026-08-25T10:00:30Z",
    ]
    assert seen[0].headers["X-Coriqo-Signature"] != seen[1].headers["X-Coriqo-Signature"]


async def test_a_static_key_identity_cannot_make_an_enforcement_call():
    client = _client(lambda r: _json({}))
    try:
        with pytest.raises(EnforcementIdentityUnavailableError):
            await client.fetch_mandate(_AGENT)
    finally:
        await client.close()


async def test_a_signed_request_without_a_tenant_is_refused_before_it_is_sent(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("BYOAI_CORIQO_TENANT_SLUG", raising=False)
    client = _device_client(lambda r: _json({}), tmp_path, tenant_slug=None)
    try:
        with pytest.raises(CoriqoAgentsError, match="tenant"):
            await client.fetch_mandate(_AGENT)
    finally:
        await client.close()


async def test_an_enrolled_device_supplies_its_own_tenant(tmp_path, monkeypatch):
    """The point of persisting the tenant: a fully enrolled device enforces
    without a stray legacy env var left in its environment."""
    monkeypatch.delenv("BYOAI_CORIQO_TENANT_SLUG", raising=False)
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"agent_id": _AGENT})

    client = _device_client(
        handler, tmp_path, tenant_slug=None, enrolled_tenant="enrolled_bank"
    )
    try:
        await client.fetch_mandate(_AGENT)
    finally:
        await client.close()

    assert seen[0].headers["X-Tenant-Slug"] == "enrolled_bank"
    assert "X-API-Key" not in seen[0].headers


async def test_an_explicit_tenant_argument_beats_the_enrolled_one(tmp_path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"agent_id": _AGENT})

    client = _device_client(
        handler, tmp_path, tenant_slug="explicit_bank", enrolled_tenant="enrolled_bank"
    )
    try:
        await client.fetch_mandate(_AGENT)
    finally:
        await client.close()

    assert seen[0].headers["X-Tenant-Slug"] == "explicit_bank"


async def test_a_tenantless_enrollment_still_falls_back_to_the_env_var(
    tmp_path, monkeypatch
):
    """Devices enrolled before the tenant was persisted are the normal case,
    not an edge case: they keep enforcing on the legacy env var."""
    monkeypatch.setenv("BYOAI_CORIQO_TENANT_SLUG", "legacy_bank")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"agent_id": _AGENT})

    client = _device_client(handler, tmp_path, tenant_slug=None, enrolled_tenant=None)
    try:
        await client.fetch_mandate(_AGENT)
    finally:
        await client.close()

    assert seen[0].headers["X-Tenant-Slug"] == "legacy_bank"


# -- file-mandate ids on the suspend-ack and approval routes ----------------

_FILE_MANDATE_ID = "sha256:" + "ab" * 32
_CORIQO_VERSION = "0b9c7c5e-4f3a-4a7e-9d2c-1f6a8e3b2d10"  # 36 characters


async def _sent_bodies(call, tmp_path):
    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return _json({"ok": True}, 201)

    client = _device_client(handler, tmp_path)
    try:
        await call(client)
    finally:
        await client.close()
    return sent


async def _ack(client, version):
    await client.ack_suspend(_AGENT, mandate_version_id=version)


async def _approve(client, version):
    await client.request_tool_approval(
        _AGENT, request_id="req-1", tool="pay", trajectory_id="t", step_index=1,
        mandate_version_id=version,
    )


@pytest.mark.parametrize("send", [_ack, _approve])
async def test_file_mandate_id_goes_out_as_null(send, tmp_path):
    sent = await _sent_bodies(lambda c: send(c, _FILE_MANDATE_ID), tmp_path)
    assert sent[0]["mandate_version_id"] is None


@pytest.mark.parametrize("send", [_ack, _approve])
async def test_overlong_id_goes_out_as_null(send, tmp_path):
    sent = await _sent_bodies(lambda c: send(c, "x" * 37), tmp_path)
    assert sent[0]["mandate_version_id"] is None


@pytest.mark.parametrize("send", [_ack, _approve])
async def test_coriqo_version_id_is_unchanged(send, tmp_path):
    assert len(_CORIQO_VERSION) == 36
    sent = await _sent_bodies(lambda c: send(c, _CORIQO_VERSION), tmp_path)
    assert sent[0]["mandate_version_id"] == _CORIQO_VERSION


@pytest.mark.parametrize("send", [_ack, _approve])
async def test_no_version_stays_null(send, tmp_path):
    sent = await _sent_bodies(lambda c: send(c, None), tmp_path)
    assert sent[0]["mandate_version_id"] is None


def test_wire_helper_does_not_touch_the_local_value():
    from byoai.recorder.coriqo_agents import wire_mandate_version_id

    version = _FILE_MANDATE_ID
    assert wire_mandate_version_id(version) is None
    assert version == "sha256:" + "ab" * 32  # the caller's (ledger's) copy is unchanged


# -- device-signed single trace declares its payload mode -------------------


@pytest.mark.parametrize("mode", [PayloadMode.REDACTED, PayloadMode.HASH_ONLY, "full"])
async def test_signed_trace_declares_the_payload_mode(tmp_path, mode):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"trace_id": "t1"})

    client = _device_client(handler, tmp_path, enrolled_tenant="acme_bank")
    await client.record_signed_trace(_AGENT, output=None, payload_mode=mode)
    headers = seen[0].headers
    assert dict(payload_mode_headers(mode)) == {
        PAYLOAD_MODE_HEADER: headers[PAYLOAD_MODE_HEADER]
    }
    assert headers[PAYLOAD_MODE_HEADER] == PayloadMode(mode).value
    # The method ships the caller's body as given; shaping is the caller's job.
    assert json.loads(seen[0].content)["output"] is None


async def test_signed_trace_without_a_mode_sends_no_header(tmp_path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return _json({"trace_id": "t1"})

    client = _device_client(handler, tmp_path, enrolled_tenant="acme_bank")
    await client.record_signed_trace(_AGENT, output="x")
    assert PAYLOAD_MODE_HEADER not in seen[0].headers
