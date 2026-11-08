"""``AsyncCoriqoAgentsClient.request_token_action``: an agent's token action,
device-signed, posted to Coriqo's ``POST /api/v1/token-ops/actions/agent-signed``.

The fixture below mirrors Coriqo's ``ActionIn`` (``api/domains/token_ops/
router_actions.py``, ``extra="forbid"``): any key outside it is a 422 there,
so the test fails if the client grows one. The signature is re-derived from
the recorded request with Coriqo's own canonicalization (sorted keys, compact
separators), not with the client's helper.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re

import httpx
import pytest

from byoai.recorder.coriqo_agents import CoriqoAgentsError
from byoai.recorder.coriqo_async import (
    TOKEN_OPS_AGENT_SIGNED_PATH,
    AsyncCoriqoAgentsClient,
    RetryPolicy,
)
from byoai.recorder.identity import CoriqoIdentity
from byoai.recorder.keys import load_or_create_device_key

_BASE = "https://coriqo.test"
_AGENT = "8d0c2f7e-1111-4222-8333-944455556666"

#: Coriqo's ActionIn: field -> (required, check).
_ACTION_IN = {
    "program_id": (True, lambda v: isinstance(v, str) and 1 <= len(v) <= 36),
    "kind": (True, lambda v: isinstance(v, str) and len(v) <= 32),
    "chain_id": (True, lambda v: isinstance(v, int) and v >= 1),
    "function_selector": (True, lambda v: bool(re.fullmatch(r"0x[0-9a-fA-F]{8}", v))),
    "arguments": (False, lambda v: isinstance(v, dict)),
    "value": (False, lambda v: isinstance(v, int) and v >= 0),
    "nonce": (False, lambda v: isinstance(v, int) and v >= 0),
    "basis_ref": (False, lambda v: v is None or len(v) <= 256),
    "authorization_id": (False, lambda v: v is None),  # refused (403) on this route
    "request_id": (False, lambda v: isinstance(v, str) and 1 <= len(v) <= 64),
}


def _assert_matches_action_in(body: dict) -> None:
    assert set(body) <= set(_ACTION_IN), set(body) - set(_ACTION_IN)
    for name, (required, check) in _ACTION_IN.items():
        if required:
            assert name in body, name
        if name in body:
            assert check(body[name]), (name, body[name])
    # Coriqo derives the agent from the device binding; request_id is required.
    assert "agent_id" not in body
    assert body["request_id"]


class RecordingSleep:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


def _client(handler, tmp_path, **kwargs) -> tuple[AsyncCoriqoAgentsClient, object]:
    key = load_or_create_device_key(tmp_path)
    identity = CoriqoIdentity.from_device(
        base_url=_BASE, device_id=key.device_id, signer=key, tenant_slug="acme_bank"
    )
    client = AsyncCoriqoAgentsClient(
        identity,
        http_client=httpx.AsyncClient(base_url=_BASE, transport=httpx.MockTransport(handler)),
        **kwargs,
    )
    return client, key


async def _mint(client: AsyncCoriqoAgentsClient, **overrides):
    params = dict(
        program_id="prog-1",
        kind="mint",
        chain_id=11155111,
        function_selector="0x40c10f19",
        request_id="apr_123",
        arguments={"to": "0xabc", "amount": "1000"},
        basis_ref="ticket-42",
    )
    params.update(overrides)
    return await client.request_token_action(**params)


async def test_request_shape_and_signature_match_coriqo(tmp_path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"id": "act-1", "state": "requested"})

    client, key = _client(handler, tmp_path)
    try:
        result = await _mint(client)
    finally:
        await client.close()

    assert result["id"] == "act-1"
    request = seen[0]
    assert request.method == "POST"
    assert request.url.path == TOKEN_OPS_AGENT_SIGNED_PATH
    assert TOKEN_OPS_AGENT_SIGNED_PATH == "/api/v1/token-ops/actions/agent-signed"
    assert request.headers["X-Tenant-Slug"] == "acme_bank"
    assert "X-API-Key" not in request.headers

    body = json.loads(request.content)
    _assert_matches_action_in(body)
    assert "authorization_id" not in body

    public_key_hex = base64.b64decode(key.public_key_b64).hex()
    assert request.headers["X-Coriqo-Public-Key"] == public_key_hex
    signed = json.dumps(
        {
            "body_sha256": hashlib.sha256(request.content).hexdigest(),
            "method": "POST",
            "path": TOKEN_OPS_AGENT_SIGNED_PATH,
            "public_key": public_key_hex,
            "timestamp": request.headers["X-Coriqo-Timestamp"],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    sig = request.headers["X-Coriqo-Signature"]
    assert len(bytes.fromhex(sig)) == 64
    as_b64 = "ed25519:" + base64.b64encode(bytes.fromhex(sig)).decode()
    assert key.verify(key.public_key_b64, signed, as_b64)


@pytest.mark.parametrize(
    ("status", "detail"),
    [
        (401, "Device signature did not verify."),
        (403, "This host holds no binding for that agent."),
        (409, "That approval request was already used by an earlier action."),
        (422, "The approval request is for a different tool."),
    ],
)
async def test_refusals_raise_with_status_and_are_not_retried(tmp_path, status, detail):
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(status, json={"detail": detail})

    sleep = RecordingSleep()
    client, _ = _client(handler, tmp_path, sleep=sleep)
    try:
        with pytest.raises(CoriqoAgentsError) as info:
            await _mint(client)
    finally:
        await client.close()
    assert info.value.status_code == status
    assert detail in str(info.value.detail)
    assert calls == 1 and sleep.delays == []


async def test_rate_limit_is_retried_bounded_honouring_retry_after_and_resigned(tmp_path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(429, headers={"Retry-After": "2"}, json={"detail": "slow down"})

    sleep = RecordingSleep()
    client, _ = _client(handler, tmp_path, sleep=sleep, retry=RetryPolicy(attempts=3))
    try:
        with pytest.raises(CoriqoAgentsError) as info:
            await _mint(client)
    finally:
        await client.close()
    assert info.value.status_code == 429
    assert len(seen) == 3
    assert sleep.delays == [2.0, 2.0]
    assert all("X-Coriqo-Signature" in r.headers for r in seen)


async def test_503_then_success(tmp_path):
    answers = iter(
        [httpx.Response(503, json={"detail": "busy"}), httpx.Response(201, json={"id": "act-2"})]
    )
    sleep = RecordingSleep()
    client, _ = _client(lambda r: next(answers), tmp_path, sleep=sleep)
    try:
        assert (await _mint(client))["id"] == "act-2"
    finally:
        await client.close()
    assert len(sleep.delays) == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"request_id": ""},
        {"function_selector": "0x1234"},
        {"chain_id": 0},
        {"value": -1},
    ],
)
async def test_invalid_input_is_refused_before_sending(tmp_path, overrides):
    def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("must not send")

    client, _ = _client(handler, tmp_path)
    try:
        with pytest.raises(ValueError):
            await _mint(client, **overrides)
    finally:
        await client.close()


async def test_replayed_receipt_is_success_and_returned(tmp_path):
    receipt = {
        "action_id": "act-1",
        "state": "requested",
        "event_hash": "ab" * 32,
        "request_id": "apr_123",
        "replayed": True,
    }
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=receipt)

    client, _ = _client(handler, tmp_path)
    try:
        result = await _mint(client)
    finally:
        await client.close()
    assert result == receipt
    assert len(seen) == 1
    assert "agent_id" not in json.loads(seen[0].content)


@pytest.mark.parametrize(
    "detail",
    [
        "This signature was already used.",
        "A different action body was already sent for this approval request.",
    ],
)
async def test_409_is_never_retried_even_with_attempts_left(tmp_path, detail):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(409, json={"detail": detail})

    sleep = RecordingSleep()
    client, _ = _client(handler, tmp_path, sleep=sleep, retry=RetryPolicy(attempts=5))
    try:
        with pytest.raises(CoriqoAgentsError) as info:
            await _mint(client)
    finally:
        await client.close()
    assert info.value.status_code == 409
    assert detail in str(info.value.detail)
    assert len(seen) == 1 and sleep.delays == []
    assert "agent_id" not in json.loads(seen[0].content)


async def test_agent_id_argument_is_deprecated_and_not_sent(tmp_path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(201, json={"id": "act-3"})

    client, _ = _client(handler, tmp_path)
    try:
        with pytest.warns(DeprecationWarning):
            await client.request_token_action(
                _AGENT,
                program_id="prog-1",
                kind="mint",
                chain_id=1,
                function_selector="0x40c10f19",
                request_id="apr_9",
            )
    finally:
        await client.close()
    assert "agent_id" not in json.loads(seen[0].content)
