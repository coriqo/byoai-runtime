"""POST /api/coriqo/proof: the Shield signs Coriqo's nonce with its device key, and only that."""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.request

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from tests.integrations.test_shield import _serve, make_cfg

from byoai.integrations.shield import (
    IDENTITY_PREFIX,
    LINK_PROOF_PREFIX,
    link_proof_message,
    request_problem,
)

JSON = {"Content-Type": "application/json"}
EXT = "chrome-extension://jbbongpiablbbmfflcaafjbeejeododc"


def _post(base, payload, origin=EXT, raw=None):
    if isinstance(payload, dict):
        payload = {"base_url": "https://coriqo.test", **payload}
    headers = {**JSON, **({"Origin": origin} if origin else {})}
    req = urllib.request.Request(base + "/api/coriqo/proof", method="POST",
                                 data=raw if raw is not None else json.dumps(payload).encode(), headers=headers)
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


@pytest.fixture(autouse=True)
def _trusted_host(monkeypatch):
    monkeypatch.setenv("BYOAI_CORIQO_LINK_HOSTS", "coriqo.test")


def test_proof_is_an_extension_only_route():
    h = {**JSON, "Host": "127.0.0.1:17831"}
    assert request_problem("POST", "/api/coriqo/proof", {**h, "Origin": EXT}) is None
    for origin in ("", "https://evil.test", "http://127.0.0.1:17831"):
        assert request_problem("POST", "/api/coriqo/proof", {**h, "Origin": origin}) is not None
    assert request_problem("POST", "/api/coriqo/proof", {**h, "Origin": EXT, "Host": "evil.test"}) is not None


def test_the_signature_verifies_over_exactly_the_agreed_bytes(tmp_path):
    base = _serve(make_cfg(tmp_path))
    code, body = _post(base, {"nonce": "abc123XYZ-_.~", "tenant_slug": "coriqo_msp_usa"})
    assert code == 200
    pub = bytes.fromhex(body["public_key_hex"])
    assert len(pub) == 32 and body["public_key_hex"] == body["public_key_hex"].lower()
    msg = link_proof_message("abc123XYZ-_.~", "coriqo_msp_usa", body["public_key_hex"])
    assert msg == b"coriqo-shield-link-v1\nabc123XYZ-_.~\ncoriqo_msp_usa\n" + body["public_key_hex"].encode()
    Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(body["signature"]), msg)
    # not valid for another workspace or nonce
    for other in (link_proof_message("abc123XYZ-_.~", "other", body["public_key_hex"]),
                  link_proof_message("different12", "coriqo_msp_usa", body["public_key_hex"])):
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(base64.b64decode(body["signature"]), other)
        except Exception:
            continue
        raise AssertionError("signature verified for different bytes")


def test_the_prefix_is_not_one_that_identity_or_anything_else_signs():
    assert not LINK_PROOF_PREFIX.startswith(IDENTITY_PREFIX) and not IDENTITY_PREFIX.startswith(LINK_PROOF_PREFIX)
    # /api/identity only signs IDENTITY_PREFIX + hex, so it can never produce LINK_PROOF_PREFIX bytes


def test_bad_input_is_refused_and_nothing_is_signed(tmp_path):
    base = _serve(make_cfg(tmp_path))
    for payload in ({"nonce": "short", "tenant_slug": "x"},
                    {"nonce": "okokokokok\nextra", "tenant_slug": "x"},
                    {"nonce": "okokokokok", "tenant_slug": "a\nb"},
                    {"nonce": "okokokokok", "tenant_slug": ""},
                    {"nonce": "o" * 300, "tenant_slug": "x"},
                    {"nonce": 5, "tenant_slug": "x"}):
        code, body = _post(base, payload)
        assert code == 400 and "signature" not in body, payload
    assert _post(base, None, raw=b"[1]")[0] == 400
    assert _post(base, None, raw=b"not json")[0] == 400


def test_no_proof_once_enrolled_or_for_an_unpinned_workspace(tmp_path, monkeypatch):
    base = _serve(make_cfg(tmp_path))
    monkeypatch.setenv("BYOAI_CORIQO_LINK_WORKSPACES", "acme")
    assert _post(base, {"nonce": "okokokokok", "tenant_slug": "other"})[0] == 403
    assert _post(base, {"nonce": "okokokokok", "tenant_slug": "ACME"})[0] == 200
    from byoai.recorder.enroll import ENROLLMENT_FILENAME
    (tmp_path / "keys").mkdir(exist_ok=True)
    (tmp_path / "keys" / ENROLLMENT_FILENAME).write_text("{ not readable")
    assert _post(base, {"nonce": "okokokokok", "tenant_slug": "acme"})[0] == 409


def test_a_bad_content_length_is_a_clean_400(tmp_path):
    import socket
    from urllib.parse import urlsplit
    base = _serve(make_cfg(tmp_path))
    host, port = urlsplit(base).hostname, urlsplit(base).port
    for value in ("-1", "abc", "99999"):
        with socket.create_connection((host, port), timeout=5) as c:
            c.sendall((f"POST /api/coriqo/proof HTTP/1.1\r\nHost: {host}:{port}\r\nOrigin: {EXT}\r\n"
                       f"Content-Type: application/json\r\nContent-Length: {value}\r\n\r\n").encode())
            first = c.recv(200).split(b"\r\n", 1)[0]
        assert b" 400 " in first, (value, first)
        # the server stays up and still answers
        assert _post(base, {"nonce": "okokokokok", "tenant_slug": "x"})[0] == 200


def test_no_proof_for_a_server_this_mac_was_not_told_to_trust(tmp_path, monkeypatch):
    base = _serve(make_cfg(tmp_path))
    for server in ("https://evil.test", "", "http://coriqo.test"):
        code, body = _post(base, {"base_url": server, "nonce": "okokokokok", "tenant_slug": "x"})
        assert code == 403 and "signature" not in body, server
    monkeypatch.delenv("BYOAI_CORIQO_LINK_HOSTS")
    assert _post(base, {"nonce": "okokokokok", "tenant_slug": "x"})[0] == 403  # no list: nothing is trusted
