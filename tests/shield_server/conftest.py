from __future__ import annotations

import asyncio
import base64
import gzip
import time
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from byoai.recorder.canonical import canonicalize
from byoai.shield_server.app import create_app
from byoai.shield_server.config import ShieldServerConfig


@pytest.fixture
def cfg(tmp_path: Path) -> ShieldServerConfig:
    return ShieldServerConfig(
        data_dir=tmp_path / "data", host="127.0.0.1", port=17840,
        public_url="http://127.0.0.1:17840", org="default", admin_token="test-admin-token",
    )


@pytest.fixture
def app(cfg):
    return create_app(cfg)


@pytest.fixture
def store(app):
    return app.state.server_store


@pytest.fixture
def ingest(app):
    return app.state.ingest_store


@pytest.fixture
def signer(app):
    return app.state.signer


class SyncASGIClient:
    """A synchronous httpx-Client-shaped wrapper around an ASGI app, so the
    real (synchronous) ``shield_publish.Publisher`` can run against
    ``create_app()`` in-process with no real network — the integration test
    the plan asks for. httpx's ``ASGITransport`` only implements the async
    protocol, so each call drives one short-lived event loop.
    """

    def __init__(self, app) -> None:
        self._app = app

    def __enter__(self) -> SyncASGIClient:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def close(self) -> None:
        pass

    def post(self, url: str, **kwargs) -> httpx.Response:
        return asyncio.run(self._arequest("POST", url, **kwargs))

    def get(self, url: str, **kwargs) -> httpx.Response:
        return asyncio.run(self._arequest("GET", url, **kwargs))

    async def _arequest(self, method: str, url: str, **kwargs) -> httpx.Response:
        transport = httpx.ASGITransport(app=self._app)
        async with httpx.AsyncClient(transport=transport, timeout=30) as client:
            return await client.request(method, url, **kwargs)


@pytest.fixture
def client_factory(app):
    return lambda: SyncASGIClient(app)


def sign_body(priv: Ed25519PrivateKey, body: dict) -> bytes:
    return priv.sign(canonicalize(body))


def make_device_key() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    return priv, pub_b64


def signed_headers(priv: Ed25519PrivateKey, device_id: str, body: dict) -> tuple[bytes, dict]:
    canon = canonicalize(body)
    sig = "ed25519:" + base64.b64encode(priv.sign(canon)).decode()
    payload = gzip.compress(canon)
    headers = {
        "content-type": "application/json", "content-encoding": "gzip",
        "x-coriqo-device": device_id, "x-coriqo-signature": sig,
    }
    return payload, headers


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def admin_call(app, method: str, path: str, headers: dict, **kwargs):
    """One admin HTTP call against ``app`` over an httpx ASGI transport,
    raising on a non-2xx and returning the parsed JSON body otherwise. Shared
    by every test that drives the admin API directly (rather than through
    the ``Publisher``), so each doesn't grow its own ad hoc async transport
    wiring."""

    async def go():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            r = await client.request(method, path, headers=headers, **kwargs)
            r.raise_for_status()
            return r.json()

    return asyncio.run(go())
