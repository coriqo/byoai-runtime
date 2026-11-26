"""Device auth on the checkpoint/policy routes: bad signature, unknown
device, revoked device, stale ``sent_at``."""

from __future__ import annotations

import time

import httpx
import pytest
from tests.shield_server.conftest import make_device_key, now_iso, signed_headers


@pytest.fixture
async def async_client(app):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def _enrol(client: httpx.AsyncClient, store, pub_b64: str) -> str:
    token = store.mint_token()
    r = await client.post("/v1/enroll", json={"public_key": pub_b64, "token": token})
    assert r.status_code == 201
    return r.json()["device_id"]


async def test_bad_signature_is_refused(async_client, store):
    priv, pub_b64 = make_device_key()
    device_id = await _enrol(async_client, store, pub_b64)
    other_priv, _ = make_device_key()
    body = {"sent_at": now_iso(), "have_version": None}
    payload, headers = signed_headers(other_priv, device_id, body)  # signed with the WRONG key
    r = await async_client.post("/v1/shield/policy", content=payload, headers=headers)
    assert r.status_code == 401
    assert "did not verify" in r.json()["detail"]


async def test_unknown_device_is_refused(async_client):
    priv, _ = make_device_key()
    body = {"sent_at": now_iso(), "have_version": None}
    payload, headers = signed_headers(priv, "dev_doesnotexist", body)
    r = await async_client.post("/v1/shield/policy", content=payload, headers=headers)
    assert r.status_code == 401


async def test_revoked_device_is_refused(async_client, store, ingest):
    priv, pub_b64 = make_device_key()
    device_id = await _enrol(async_client, store, pub_b64)
    assert ingest.revoke_device(device_id)
    body = {"sent_at": now_iso(), "have_version": None}
    payload, headers = signed_headers(priv, device_id, body)
    r = await async_client.post("/v1/shield/policy", content=payload, headers=headers)
    assert r.status_code == 401
    assert "revoked" in r.json()["detail"]


async def test_unknown_and_revoked_devices_are_indistinguishable_under_a_bad_signature(
    async_client, store, ingest,
):
    """A caller with a bad signature must not learn whether the device_id it
    guessed belongs to a real (if revoked) device or none at all — that
    would let a probe with garbage signatures enumerate real device ids."""
    priv, pub_b64 = make_device_key()
    device_id = await _enrol(async_client, store, pub_b64)
    assert ingest.revoke_device(device_id)

    unknown_priv, _ = make_device_key()
    bad_body = {"sent_at": now_iso(), "have_version": None}

    payload_unknown, headers_unknown = signed_headers(unknown_priv, "dev_totally_unknown", bad_body)
    r_unknown = await async_client.post(
        "/v1/shield/policy", content=payload_unknown, headers=headers_unknown)

    other_priv, _ = make_device_key()  # wrong key, signing as the REVOKED device's id
    payload_revoked, headers_revoked = signed_headers(other_priv, device_id, bad_body)
    r_revoked_bad_sig = await async_client.post(
        "/v1/shield/policy", content=payload_revoked, headers=headers_revoked)

    assert r_unknown.status_code == r_revoked_bad_sig.status_code == 401
    assert r_unknown.json() == r_revoked_bad_sig.json()

    # But the SAME revoked device, signing with its OWN real key, still gets
    # the distinct, client-recognised "revoked" refusal — the signature
    # genuinely proved who it is, so the server can safely say so.
    payload_valid, headers_valid = signed_headers(priv, device_id, bad_body)
    r_revoked_valid_sig = await async_client.post(
        "/v1/shield/policy", content=payload_valid, headers=headers_valid)
    assert r_revoked_valid_sig.status_code == 401
    assert "revoked" in r_revoked_valid_sig.json()["detail"]
    assert r_revoked_valid_sig.json() != r_unknown.json()


async def test_stale_sent_at_is_refused(async_client, store):
    priv, pub_b64 = make_device_key()
    device_id = await _enrol(async_client, store, pub_b64)
    stale = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600))
    body = {"sent_at": stale, "have_version": None}
    payload, headers = signed_headers(priv, device_id, body)
    r = await async_client.post("/v1/shield/policy", content=payload, headers=headers)
    assert r.status_code == 401
    assert "clock" in r.json()["detail"].lower()


async def test_future_sent_at_is_refused(async_client, store):
    priv, pub_b64 = make_device_key()
    device_id = await _enrol(async_client, store, pub_b64)
    future = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 3600))
    body = {"sent_at": future, "have_version": None}
    payload, headers = signed_headers(priv, device_id, body)
    r = await async_client.post("/v1/shield/policy", content=payload, headers=headers)
    assert r.status_code == 401


async def test_missing_headers_are_refused(async_client):
    r = await async_client.post("/v1/shield/policy", content=b"{}")
    assert r.status_code == 401


async def test_absent_sent_at_is_accepted(async_client, store):
    """Older clients send no sent_at at all; that must still work."""
    priv, pub_b64 = make_device_key()
    device_id = await _enrol(async_client, store, pub_b64)
    body = {"have_version": None}
    payload, headers = signed_headers(priv, device_id, body)
    r = await async_client.post("/v1/shield/policy", content=payload, headers=headers)
    assert r.status_code == 200
    assert r.json() == {"changed": False, "version": None}


async def test_reenrol_same_key_is_idempotent(async_client, store):
    priv, pub_b64 = make_device_key()
    token1 = store.mint_token()
    r1 = await async_client.post("/v1/enroll", json={"public_key": pub_b64, "token": token1})
    assert r1.status_code == 201
    token2 = store.mint_token()
    r2 = await async_client.post("/v1/enroll", json={"public_key": pub_b64, "token": token2})
    assert r2.status_code == 201
    assert r2.json()["device_id"] == r1.json()["device_id"]


async def test_reenrol_with_a_new_label_updates_the_device_label(async_client, store, ingest):
    """Enrol, revoke, re-enrol with a fresh token carrying a different label
    — the device's shield-state row already exists from the first enrol, so
    this exercises the ON CONFLICT path of ``record_shield_state``, which
    used to only ever touch ``last_seen_at`` and silently keep the old
    label forever."""
    priv, pub_b64 = make_device_key()
    token1 = store.mint_token(label="Old Label")
    r1 = await async_client.post("/v1/enroll", json={"public_key": pub_b64, "token": token1})
    assert r1.status_code == 201
    device_id = r1.json()["device_id"]
    assert store.device_shield_state(device_id).label == "Old Label"

    assert ingest.revoke_device(device_id)

    token2 = store.mint_token(label="New Label")
    r2 = await async_client.post("/v1/enroll", json={"public_key": pub_b64, "token": token2})
    assert r2.status_code == 201
    assert r2.json()["device_id"] == device_id
    assert r2.json()["label"] == "New Label"
    assert store.device_shield_state(device_id).label == "New Label"


async def test_enrol_with_bad_token_is_401(async_client):
    _priv, pub_b64 = make_device_key()
    r = await async_client.post("/v1/enroll", json={"public_key": pub_b64, "token": "shieldtok_bogus"})
    assert r.status_code == 401


async def test_enrol_with_used_token_is_401(async_client, store):
    _priv, pub_b64 = make_device_key()
    token = store.mint_token()
    r1 = await async_client.post("/v1/enroll", json={"public_key": pub_b64, "token": token})
    assert r1.status_code == 201
    _priv2, pub2 = make_device_key()
    r2 = await async_client.post("/v1/enroll", json={"public_key": pub2, "token": token})
    assert r2.status_code == 401
