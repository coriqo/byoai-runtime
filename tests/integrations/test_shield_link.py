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
import time as _time
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

            def do_GET(self):
                stub.calls.append(self.path)
                if self.path == "/oauth/userinfo" and self.headers.get("Authorization") == "Bearer at_1":
                    return self._json(200, {"sub": "u1", "email": "a@b.test",
                                            "tenants": ["coriqo_msp_usa", "coriqo_msp_uk"]})
                self._json(401 if self.path == "/oauth/userinfo" else 404, {})

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                stub.calls.append(self.path)
                if self.path == "/oauth/token":
                    f = {k: v[0] for k, v in parse_qs(raw.decode()).items()}
                    ok = (f.get("grant_type") == "authorization_code" and f.get("code") == "goodcode"
                          and len(f.get("code_verifier", "")) >= 43 and f.get("client_id"))
                    return self._json(200, {"access_token": "at_1", "token_type": "Bearer", "expires_in": 600}) if ok \
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
                    owner = stub.minted.pop(body["token"], "missing")
                    if owner == "missing" or (owner != body["public_key"] and not getattr(stub, "accept_any", False)):
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

    again = _run(coriqo.base, one)             # already linked: the extension cannot replace the identity
    assert again["linked"] is False and "already connected" in again["linkError"]
    assert len(coriqo.keys) == 1 and state == load_enrollment_state(tmp_path / "a" / "keys")


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


def test_link_refuses_when_the_enrolment_file_exists_but_cannot_be_read(tmp_path, coriqo, monkeypatch):
    monkeypatch.setenv("BYOAI_CORIQO_LINK_HOSTS", coriqo.base.removeprefix("http://"))
    base = _serve(make_cfg(tmp_path))
    keys = tmp_path / "keys"
    keys.mkdir(exist_ok=True)
    (keys / "enrollment.json").write_text("{not json")
    first = _run(coriqo.base, base)
    assert first["linked"] is False and "already connected" in first["linkError"]
    assert (keys / "enrollment.json").read_text() == "{not json"   # untouched


def test_two_simultaneous_links_enrol_once(tmp_path, coriqo, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    monkeypatch.setenv("BYOAI_CORIQO_LINK_HOSTS", coriqo.base.removeprefix("http://"))
    cfg = make_cfg(tmp_path)
    base = _serve(cfg)
    import urllib.error
    import urllib.request

    def link(i):
        coriqo.minted[f"cik_live_x.{i}"] = None  # tokens the stub will accept for any key
        req = urllib.request.Request(base + "/api/coriqo/link", method="POST",
                                     data=json.dumps({"base_url": coriqo.base, "token": f"cik_live_x.{i}"}).encode(),
                                     headers={"Content-Type": "application/json", "Origin": "chrome-extension://x"})
        for _ in range(5):                       # a refused or reset connect is the test client's, not the route's
            try:
                return urllib.request.urlopen(req, timeout=10).status
            except urllib.error.HTTPError as e:
                return e.code
            except OSError:
                _time.sleep(0.1)
        raise AssertionError("could not reach Shield")
    # the stub only redeems a token minted for the caller's key; make it accept any
    coriqo.accept_any = True
    with ThreadPoolExecutor(8) as ex:
        codes = sorted(ex.map(link, range(8)))
    assert codes.count(200) == 1 and codes.count(409) == 7


def test_the_enrol_route_follows_the_list_only_when_one_is_set(tmp_path, coriqo, monkeypatch):
    import urllib.error
    import urllib.request
    base = _serve(make_cfg(tmp_path))

    def enrol(url):
        req = urllib.request.Request(base + "/api/coriqo/enrol", method="POST",
                                     data=json.dumps({"base_url": url, "token": "t"}).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            return urllib.request.urlopen(req, timeout=5).status
        except urllib.error.HTTPError as e:
            return e.code
    # no list: unchanged (the stub refuses the token, which is a 400 from Coriqo, not a 403 from the list)
    assert enrol(coriqo.base) == 400
    monkeypatch.setenv("BYOAI_CORIQO_LINK_HOSTS", "good.example")
    assert enrol(coriqo.base) == 403
    assert coriqo.calls == ["/v1/enroll"]          # only the first call reached any server


def test_workspace_names_and_region_suggestion():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    code = r"""
const L=require(process.argv[1]);
const d=(language,timeZone)=>L.detectRegion({language,timeZone});
console.log(JSON.stringify({
 label:L.tenantLabel('coriqo_msp_usa'), uk:L.tenantLabel('coriqo_msp_uk'), plain:L.tenantLabel('acme-bank'), odd:L.tenantLabel('x'),
 us:d('en-US','America/New_York'), gb:d('en-GB',''), de:d('de-DE',''), fr:d('fr',  'Europe/Paris'), tzLondon:d('en','Europe/London'),
 tzUS:d('en','America/Chicago'), brazil:d('pt-BR','America/Sao_Paulo'), none:d('',''),
 berlinEnUS:d('en-US','Europe/Berlin'), toronto:d('en','America/Toronto'), torontoEnUS:d('en-US','America/Toronto'), zurich:d('en','Europe/Zurich'),
 pickRegion:L.pickTenant(['coriqo_msp_usa','coriqo_msp_uk'],'uk','coriqo_msp_usa'), pickNoneNamed:L.pickTenant(['coriqo_msp_usa','coriqo_msp_uk'],'uk',null),
 pickNoMatch:L.pickTenant(['coriqo_msp_usa','coriqo_msp_uk'],'eu','coriqo_msp_uk'),
 pickPreferred:L.pickTenant(['a','b'],null,'b'), pickFirst:L.pickTenant(['a','b'],null,'zzz'), pickEmpty:L.pickTenant([],'usa','x')}))
"""
    done = subprocess.run([node, "-e", code, str(Path(__file__).parents[2] / "src/byoai/browser_extension/coriqo-link.js")],
                          capture_output=True, text=True, timeout=20)
    g = json.loads(done.stdout)
    assert g["label"] == {"name": "Coriqo MSP", "region": "United States", "regionKey": "usa"}
    assert g["uk"]["region"] == "United Kingdom" and g["plain"] == {"name": "Acme Bank", "region": None, "regionKey": None}
    assert g["odd"]["name"] == "X"
    assert (g["us"], g["gb"], g["de"], g["fr"], g["tzLondon"], g["tzUS"]) == ("usa", "uk", "eu", "eu", "uk", "usa")
    assert g["brazil"] is None and g["none"] is None
    # time zone beats the browser's default language; Canada is not the US; non-EU Europe is no guess
    assert (g["berlinEnUS"], g["toronto"], g["torontoEnUS"], g["zurich"]) == ("eu", "ca", "ca", None)
    # Coriqo's own workspace always wins over the region guess; the guess only fills a gap
    assert (g["pickRegion"], g["pickNoneNamed"], g["pickNoMatch"], g["pickPreferred"], g["pickFirst"], g["pickEmpty"]) == (
        "coriqo_msp_usa", "coriqo_msp_uk", "coriqo_msp_uk", "b", "a", None)


def test_the_oauth_client_id_is_configurable_and_validated():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    code = r"""
const L=require(process.argv[1]);
const ok=(v)=>{try{return L.checkClientId(v)}catch(e){return e.message}};
const q=(id)=>new URL(L.buildAuthorizeUrl({base:'https://c.test',clientId:id,redirectUri:'https://x.chromiumapp.org/',challenge:'c',state:'s'})).searchParams.get('client_id');
console.log(JSON.stringify({
 name:ok('my-client'), meta:ok('https://c.test/.well-known/shield-client.json'),
 http:ok('http://c.test/m.json'), space:ok('a b'), js:ok('javascript:alert(1)'), empty:ok(''), long:ok('a'.repeat(200)),
 userinfo:ok('https://u:p@c.test/m'), dflt:q(undefined), custom:q('https://c.test/m.json'),
 builderBad:(()=>{try{q('a b');return 'accepted'}catch(e){return e.message}})()}))
"""
    done = subprocess.run([node, "-e", code, str(Path(__file__).parents[2] / "src/byoai/browser_extension/coriqo-link.js")],
                          capture_output=True, text=True, timeout=20)
    g = json.loads(done.stdout)
    assert g["name"] == "my-client" and g["meta"] == "https://c.test/.well-known/shield-client.json"
    assert {g[k] for k in ("http", "space", "js", "empty", "long", "userinfo")} == {"bad_client_id"}
    assert g["dflt"] == "coriqo-shield-extension" and g["custom"] == "https://c.test/m.json"
    assert g["builderBad"] == "bad_client_id"      # the builders check it themselves, not only the caller


def test_sign_in_asks_for_only_the_device_link_scope():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    code = r"""
const L=require(process.argv[1]);
const u=new URL(L.buildAuthorizeUrl({base:'https://c.test',redirectUri:'https://x.chromiumapp.org/',challenge:'c',state:'s'}));
console.log(u.searchParams.get('scope'))
"""
    done = subprocess.run([node, "-e", code, str(Path(__file__).parents[2] / "src/byoai/browser_extension/coriqo-link.js")],
                          capture_output=True, text=True, timeout=20)
    assert done.stdout.strip() == "devices:link", done.stderr


def test_identity_comes_from_userinfo_with_a_whole_token_reply_fallback_and_real_errors():
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    code = r"""
const L=require(process.argv[1]);
const run=async(tok,ui)=>{try{return await L.exchangeCode({base:'https://c.test',redirectUri:'https://x.chromiumapp.org/',code:'c',verifier:'v',
 fetchImpl:async(u)=>u.endsWith('/oauth/token')?{ok:true,json:async()=>tok}:ui}) }catch(e){return e.message}};
(async()=>{console.log(JSON.stringify({
 ui:await run({access_token:'t'},{ok:true,json:async()=>({email:'a@b',tenants:['x','y']})}),
 fallback:await run({access_token:'t',tenant_slug:'old',tenants:['old']},{ok:true,json:async()=>({email:'a@b'})}),
 mixed:await run({access_token:'t',tenants:['old']},{ok:true,json:async()=>({tenant_slug:'new'})}),
 e401:await run({access_token:'t'},{ok:false,status:401}),
 badjson:await run({access_token:'t'},{ok:true,json:async()=>{throw new Error('x')}})}))})()
"""
    done = subprocess.run([node, "-e", code, str(Path(__file__).parents[2] / "src/byoai/browser_extension/coriqo-link.js")],
                          capture_output=True, text=True, timeout=20)
    g = json.loads(done.stdout)
    assert g["ui"]["tenants"] == ["x", "y"] and g["ui"]["email"] == "a@b"
    assert g["fallback"]["tenant_slug"] == "old" and g["fallback"]["email"] == "a@b"
    assert g["mixed"]["tenant_slug"] == "new" and g["mixed"]["tenants"] == []
    assert (g["e401"], g["badjson"]) == ("http:401", "bad_userinfo")
