"""Extension sign-in + link: the public half, run against a stub of Coriqo's private API.

The stub answers the three things Coriqo's side must provide (OAuth token, a per-device
enrolment grant that counts devices, and the existing /v1/enroll). Nothing here is Coriqo's
real server; the shapes it checks are the ones CONFIGURATION.md documents."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from byoai.integrations.shield import link_host_problem, request_problem
from byoai.recorder.enroll import load_enrollment_state
from tests.integrations.test_shield import _serve, make_cfg

SCRIPT = Path(__file__).parent / "link_flow.mjs"


class StubCoriqo:
    """OAuth token + self-enrol (device limit counted by public key) + /v1/enroll."""

    def __init__(self, limit=1):
        self.limit, self.keys, self.minted, self.calls = limit, [], {}, []
        stub = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, body):
                data = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                stub.calls.append(self.path)
                if self.path == "/oauth/token":
                    f = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                    ok = (f.get("grant_type") == "authorization_code" and f.get("code") == "goodcode"
                          and len(f.get("code_verifier", "")) >= 43 and f.get("client_id"))
                    return self._json(200, {"access_token": "at_1", "email": "a@b.test",
                                            "tenants": ["coriqo_msp_usa", "coriqo_msp_uk"]}) if ok \
                        else self._json(400, {"error": "invalid_grant"})
                if self.path == "/v1/enroll/self":
                    if self.headers.get("Authorization") != "Bearer at_1":
                        return self._json(401, {})
                    if self.headers.get("X-Tenant-Slug") not in ("coriqo_msp_usa", "coriqo_msp_uk"):
                        return self._json(403, {})
                    body = json.loads(raw)
                    if body["device_public_key"] not in stub.keys:
                        if len(stub.keys) >= stub.limit:
                            return self._json(402, {"detail": {"error": "device_limit_reached", "limit": stub.limit,
                                                               "count": len(stub.keys), "upgrade_url": "https://billing.test/add"}})
                        stub.keys.append(body["device_public_key"])
                    tok = f"cik_live_coriqo_msp_usa.{len(stub.minted)}"
                    stub.minted[tok] = body["device_public_key"]
                    return self._json(200, {"token": tok, "device_index": stub.keys.index(body["device_public_key"]) + 1,
                                            "device_limit": stub.limit, "billing_state": "included"})
                if self.path == "/v1/enroll":
                    body = json.loads(raw)
                    if stub.minted.pop(body["token"], None) != body["public_key"]:
                        return self._json(404, {"detail": "invalid"})
                    return self._json(200, {"device_id": "dev_" + body["public_key"][:6], "tenant_slug": "coriqo_msp_usa"})
                self._json(404, {})

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()


@pytest.fixture
def coriqo():
    s = StubCoriqo(limit=1)
    yield s
    s.close()


def _run(base, shield, origin=None):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    args = [node, str(SCRIPT), base, shield] + ([origin] if origin else [])
    done = subprocess.run(args, capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_sign_in_links_the_first_computer_and_refuses_the_second(tmp_path, coriqo, monkeypatch):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    monkeypatch.setenv("BYOAI_CORIQO_LINK_HOSTS", coriqo.base.removeprefix("http://"))
    one = _serve(make_cfg(tmp_path / "a"))
    two = _serve(make_cfg(tmp_path / "b"))
    first = _run(coriqo.base, one)
    assert first["linked"] is True and first["grant"]["deviceIndex"] == 1 and first["grant"]["deviceLimit"] == 1
    state = load_enrollment_state(tmp_path / "a" / "keys")
    assert state is not None and state.tenant_slug == "coriqo_msp_usa"

    second = _run(coriqo.base, two)           # a different device: over the limit
    assert second["grant"] == {"ok": False, "reason": "device_limit_reached", "limit": 1, "count": 1,
                               "upgradeUrl": "https://billing.test/add"}
    assert "linked" not in second
    assert load_enrollment_state(tmp_path / "b" / "keys") is None

    again = _run(coriqo.base, one)             # the same device again is not a new device
    assert again["linked"] is True and len(coriqo.keys) == 1


def test_the_hand_off_refuses_a_page_and_an_unlisted_server(tmp_path, coriqo, monkeypatch):
    base = _serve(make_cfg(tmp_path))
    import urllib.error
    import urllib.request

    def post(origin, url):
        req = urllib.request.Request(base + "/api/coriqo/link", method="POST",
                                     data=json.dumps({"base_url": url, "token": "t"}).encode(),
                                     headers={"Content-Type": "application/json", **({"Origin": origin} if origin else {})})
        try:
            return urllib.request.urlopen(req, timeout=3).status
        except urllib.error.HTTPError as e:
            return e.code
    assert post("https://evil.test", coriqo.base) == 403      # a web page
    assert post(None, coriqo.base) == 403                     # no origin at all
    assert post("chrome-extension://x", "https://attacker.test") == 403   # not on the Mac's list
    assert post("chrome-extension://x", "http://attacker.test") == 403
    assert coriqo.calls == []                                 # nothing reached any server
    for body in (b"[]", b'"x"', b"7", b"null"):               # a body that is not an object: a clean 400
        req = urllib.request.Request(base + "/api/coriqo/link", method="POST", data=body,
                                     headers={"Content-Type": "application/json", "Origin": "chrome-extension://x"})
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(req, timeout=3)
        assert e.value.code == 400


def test_link_host_problem_is_fail_closed():
    assert link_host_problem("http://127.0.0.1:9", {}) is not None                  # localhost must be listed too
    assert link_host_problem("http://127.0.0.1:9", {"BYOAI_CORIQO_LINK_HOSTS": "127.0.0.1:9"}) is None
    assert link_host_problem("http://127.0.0.1:10", {"BYOAI_CORIQO_LINK_HOSTS": "127.0.0.1:9"}) is not None
    assert link_host_problem("http://127.0.0.1:9", {"BYOAI_CORIQO_LINK_HOSTS": "127.0.0.1"}) is not None   # bare host: default port only
    assert link_host_problem("https://a.test:8443", {"BYOAI_CORIQO_LINK_HOSTS": "a.test"}) is not None
    assert link_host_problem("https://a.test:8443", {"BYOAI_CORIQO_LINK_HOSTS": "a.test:8443"}) is None
    assert link_host_problem("https://a.test:99999", {"BYOAI_CORIQO_LINK_HOSTS": "a.test"}) is not None
    assert link_host_problem("https://a.test", {}) is not None                       # empty list refuses
    assert link_host_problem("https://a.test", {"BYOAI_CORIQO_LINK_HOSTS": "a.test"}) is None
    assert link_host_problem("http://a.test", {"BYOAI_CORIQO_LINK_HOSTS": "a.test"}) is not None   # never plain http
    assert link_host_problem("https://a.test.evil.test", {"BYOAI_CORIQO_LINK_HOSTS": "a.test"}) is not None
    assert link_host_problem("https://evil.test@a.test/", {"BYOAI_CORIQO_LINK_HOSTS": "a.test"}) is None  # host is a.test
    assert link_host_problem("", {"BYOAI_CORIQO_LINK_HOSTS": "a.test"}) is not None


def test_extension_ids_pin_applies_to_the_link_route(monkeypatch):
    monkeypatch.setenv("BYOAI_SHIELD_EXTENSION_IDS", "good")
    h = {"Host": "127.0.0.1:1", "Content-Type": "application/json"}
    assert request_problem("POST", "/api/coriqo/link", {**h, "Origin": "chrome-extension://good"}) is None
    assert request_problem("POST", "/api/coriqo/link", {**h, "Origin": "chrome-extension://other"}) is not None
    assert request_problem("POST", "/api/coriqo/link", {**h, "Origin": "http://127.0.0.1:1"}) is not None


def test_pkce_challenge_matches_the_verifier_and_rejects_forged_redirects():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    code = r"""
const {webcrypto}=require('node:crypto');const L=require(process.argv[1]);
(async()=>{const p=await L.makePkce(webcrypto);
const want=require('node:crypto').createHash('sha256').update(p.verifier).digest('base64url');
const r='https://x.chromiumapp.org/cb';const bad=[];
const t=(u)=>{try{L.parseRedirect(u,{redirectUri:r,state:p.state});return 'accepted'}catch(e){return e.message}};
console.log(JSON.stringify({same:want===p.challenge,len:p.verifier.length,
 ok:t(r+'?code=c&state='+p.state),wrongState:t(r+'?code=c&state=zz'),noState:t(r+'?code=c'),
 otherHost:t('https://evil.test/cb?code=c&state='+p.state),otherPath:t('https://x.chromiumapp.org/other?code=c&state='+p.state),
 denied:t(r+'?error=access_denied&state='+p.state),noCode:t(r+'?state='+p.state),junk:t('nope'),
 plain:(()=>{try{L.checkBase('http://coriqo.example');return 'accepted'}catch(e){return e.message}})()}))})()
"""
    done = subprocess.run([node, "-e", code, str(Path(__file__).parents[2] / "src/byoai/browser_extension/coriqo-link.js")],
                          capture_output=True, text=True, timeout=20)
    got = json.loads(done.stdout)
    assert got["same"] and got["len"] >= 43
    assert got["ok"] == "accepted" and got["wrongState"] == "bad_state" and got["noState"] == "bad_state"
    assert got["otherHost"] == got["otherPath"] == got["junk"] == got["noCode"] == "bad_redirect"
    assert got["denied"] == "denied" and got["plain"] == "bad_base"
