"""Correctness tests for the mock Coriqo test double itself (workstream H).

These exercise `MockCoriqo` directly over a real ASGI transport (no real
socket), independent of the end-to-end shipper/enroll flow covered in
`test_end_to_end_sync.py`.
"""

from __future__ import annotations

import gzip
from collections.abc import Iterator

import httpx
import pytest

from byoai.recorder.canonical import canonicalize
from byoai.recorder.keys import DeviceKey, derive_device_id, load_or_create_device_key

from .conftest import asgi_client
from .mock_coriqo import MockCoriqo


@pytest.fixture
def mock() -> MockCoriqo:
    return MockCoriqo()


@pytest.fixture
def client(mock: MockCoriqo) -> Iterator[httpx.Client]:
    with asgi_client(mock) as c:
        yield c


def _device_key(tmp_path) -> DeviceKey:
    return load_or_create_device_key(tmp_path / "device")


def _enroll(client: httpx.Client, key: DeviceKey, token: str = "cik_live_test") -> httpx.Response:
    return client.post(
        "/v1/enroll", json={"public_key": key.public_key_b64, "token": token}
    )


def _signed_ingest(
    client: httpx.Client,
    key: DeviceKey,
    entries: list[dict],
    *,
    device_id: str | None = None,
    corrupt: bool = False,
) -> httpx.Response:
    body = {"device_id": device_id or key.device_id, "entries": entries}
    canonical_body = canonicalize(body)
    signature = key.sign(canonical_body)
    payload = gzip.compress(canonical_body)
    if corrupt:
        payload = gzip.compress(canonical_body + b" ")
    return client.post(
        "/v1/ingest/batch",
        content=payload,
        headers={
            "content-type": "application/json",
            "content-encoding": "gzip",
            "x-coriqo-device": device_id or key.device_id,
            "x-coriqo-signature": signature,
        },
    )


# -- enroll -------------------------------------------------------------


def test_enroll_success(client, mock, tmp_path):
    key = _device_key(tmp_path)
    response = _enroll(client, key)

    assert response.status_code == 201
    body = response.json()
    assert body["device_id"] == derive_device_id(key.public_key_b64)
    assert "coriqo_base_url" in body

    devices = mock.devices()
    assert body["device_id"] in devices
    assert devices[body["device_id"]].public_key_b64 == key.public_key_b64


def test_enroll_unknown_token_rejected(client, tmp_path):
    key = _device_key(tmp_path)
    response = _enroll(client, key, token="cik_live_never_issued")

    assert response.status_code == 401
    assert "error" in response.json()


def test_enroll_replay_with_consumed_token_is_conflict(client, tmp_path):
    key1 = _device_key(tmp_path / "d1")
    key2 = _device_key(tmp_path / "d2")

    first = _enroll(client, key1)
    assert first.status_code == 201

    replay = _enroll(client, key2)
    assert replay.status_code == 409


# -- ingest ---------------------------------------------------------------


def _enrolled_key(client: httpx.Client, tmp_path) -> DeviceKey:
    key = _device_key(tmp_path)
    resp = _enroll(client, key)
    assert resp.status_code == 201
    return key


def test_ingest_accept(client, mock, tmp_path):
    key = _enrolled_key(client, tmp_path)
    entries = [
        {"seq": 1, "entry_hash": "sha256:aaa", "event": {"kind": "test", "n": 1}},
        {"seq": 2, "entry_hash": "sha256:bbb", "event": {"kind": "test", "n": 2}},
    ]

    response = _signed_ingest(client, key, entries)

    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] == 2
    assert body["duplicates"] == 0
    assert body["gaps"] == []

    stored = mock.entries_for(key.device_id)
    assert [e.seq for e in stored] == [1, 2]


def test_ingest_dedup_by_entry_hash(client, mock, tmp_path):
    key = _enrolled_key(client, tmp_path)
    entries = [{"seq": 1, "entry_hash": "sha256:aaa", "event": {"kind": "test"}}]

    first = _signed_ingest(client, key, entries)
    assert first.status_code == 202
    assert first.json()["accepted"] == 1
    assert first.json()["duplicates"] == 0

    second = _signed_ingest(client, key, entries)
    assert second.status_code == 202
    assert second.json()["accepted"] == 0
    assert second.json()["duplicates"] == 1

    assert len(mock.entries_for(key.device_id)) == 1


def test_ingest_gap_reporting_via_inject_gap(client, mock, tmp_path):
    key = _enrolled_key(client, tmp_path)
    entries = [
        {"seq": 1, "entry_hash": "sha256:aaa", "event": {"kind": "test"}},
        {"seq": 2, "entry_hash": "sha256:bbb", "event": {"kind": "test"}},
        {"seq": 3, "entry_hash": "sha256:ccc", "event": {"kind": "test"}},
    ]
    first = _signed_ingest(client, key, entries)
    assert first.status_code == 202
    assert first.json()["gaps"] == []

    mock.inject_gap(key.device_id, 2)

    more_entries = [{"seq": 4, "entry_hash": "sha256:ddd", "event": {"kind": "test"}}]
    second = _signed_ingest(client, key, more_entries)
    assert second.status_code == 202
    assert second.json()["gaps"] == [[2, 2]]


def test_ingest_bad_signature_rejected(client, tmp_path):
    key = _enrolled_key(client, tmp_path)
    entries = [{"seq": 1, "entry_hash": "sha256:aaa", "event": {"kind": "test"}}]

    response = _signed_ingest(client, key, entries, corrupt=True)

    assert response.status_code == 401


def test_ingest_unknown_device_id_rejected(client, tmp_path):
    key = _device_key(tmp_path)  # never enrolled
    entries = [{"seq": 1, "entry_hash": "sha256:aaa", "event": {"kind": "test"}}]

    response = _signed_ingest(client, key, entries)

    assert response.status_code == 401
