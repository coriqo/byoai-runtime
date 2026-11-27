"""Fail-closed guards on Shield's Coriqo enrol/link routes and the workspace pin."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from tests.integrations.test_shield import _serve, make_cfg
from tests.integrations.test_shield_link import (
    coriqo,  # noqa: F401  # pyright: ignore[reportUnusedImport]
)

from byoai.integrations.shield import request_problem
from byoai.recorder.enroll import load_enrollment_state

JSON = {"Content-Type": "application/json"}


def test_enrol_without_an_origin_is_refused():
    h = {**JSON, "Host": "127.0.0.1:17831"}
    assert request_problem("POST", "/api/coriqo/enrol", h) is not None
    assert request_problem("POST", "/api/coriqo/enrol", {**h, "Origin": "http://127.0.0.1:17831"}) is None


def test_enrol_refuses_a_foreign_host_or_a_foreign_origin():
    own = {**JSON, "Origin": "http://127.0.0.1:17831"}
    assert request_problem("POST", "/api/coriqo/enrol", {**own, "Host": "attacker.test:17831"}) is not None
    assert request_problem("POST", "/api/coriqo/link", {**JSON, "Host": "evil.test",
                                                        "Origin": "chrome-extension://x"}) is not None
    for origin in ("https://evil.test", "http://localhost:5555", "chrome-extension://x"):
        assert request_problem("POST", "/api/coriqo/enrol",
                               {**JSON, "Host": "127.0.0.1:17831", "Origin": origin}) is not None


def _post(base, path, payload, origin):
    req = urllib.request.Request(base + path, method="POST", data=json.dumps(payload).encode(),
                                 headers={**JSON, "Origin": origin})
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_no_origin_enrol_never_reaches_a_server(tmp_path, coriqo):  # noqa: F811
    base = _serve(make_cfg(tmp_path))
    req = urllib.request.Request(base + "/api/coriqo/enrol", method="POST", headers=JSON,
                                 data=json.dumps({"base_url": coriqo.base, "token": "t"}).encode())
    try:
        code = urllib.request.urlopen(req, timeout=5).status
    except urllib.error.HTTPError as e:
        code = e.code
    assert code == 403 and coriqo.calls == []


def _pinned(tmp_path, coriqo, monkeypatch, pin):  # noqa: F811
    monkeypatch.setenv("BYOAI_CORIQO_LINK_HOSTS", coriqo.base.removeprefix("http://"))
    monkeypatch.setenv("BYOAI_CORIQO_LINK_WORKSPACES", pin)
    coriqo.accept_any = True
    return _serve(make_cfg(tmp_path))


def test_workspace_pin_refuses_before_anything_is_sent(tmp_path, coriqo, monkeypatch):  # noqa: F811
    base = _pinned(tmp_path, coriqo, monkeypatch, "acme, coriqo_msp_usa")
    for tok in ("cik_live_other.1", "tok1", "cik_live_.1", "", "cik_live_acmeX.1"):
        coriqo.minted[tok] = "x"
        for path, origin in (("/api/coriqo/link", "chrome-extension://x"),
                             ("/api/coriqo/enrol", base)):
            code, body = _post(base, path, {"base_url": coriqo.base, "token": tok or "t"}, origin)
            assert code in (400, 403), (tok, path, code)
    assert "/v1/enroll" not in coriqo.calls and load_enrollment_state(tmp_path / "keys") is None


def test_workspace_pin_binds_the_enrol_route_and_never_replaces(tmp_path, coriqo, monkeypatch):  # noqa: F811
    base = _pinned(tmp_path, coriqo, monkeypatch, "coriqo_msp_usa")
    coriqo.minted["cik_live_coriqo_msp_usa.1"] = "x"
    code, _ = _post(base, "/api/coriqo/enrol", {"base_url": coriqo.base, "token": "cik_live_coriqo_msp_usa.1"}, base)
    assert code == 200
    before = load_enrollment_state(tmp_path / "keys")
    coriqo.minted["cik_live_other.2"] = "x"
    code, body = _post(base, "/api/coriqo/enrol", {"base_url": coriqo.base, "token": "cik_live_other.2"}, base)
    assert code == 403 and "BYOAI_CORIQO_LINK_WORKSPACES" in body["error"]
    assert load_enrollment_state(tmp_path / "keys").device_id == before.device_id


def test_workspace_pin_undoes_a_link_when_the_server_names_another_workspace(tmp_path, coriqo, monkeypatch):  # noqa: F811
    base = _pinned(tmp_path, coriqo, monkeypatch, "acme")
    coriqo.minted["cik_live_acme.1"] = "x"  # the stub answers with workspace coriqo_msp_usa
    code, body = _post(base, "/api/coriqo/link", {"base_url": coriqo.base, "token": "cik_live_acme.1"},
                       "chrome-extension://x")
    assert code == 403 and "BYOAI_CORIQO_LINK_WORKSPACES" in body["error"]
    assert load_enrollment_state(tmp_path / "keys") is None


def test_unset_pin_does_not_restrict(tmp_path, coriqo, monkeypatch):  # noqa: F811
    monkeypatch.setenv("BYOAI_CORIQO_LINK_HOSTS", coriqo.base.removeprefix("http://"))
    monkeypatch.delenv("BYOAI_CORIQO_LINK_WORKSPACES", raising=False)
    coriqo.accept_any = True
    coriqo.minted["tok"] = "x"
    base = _serve(make_cfg(tmp_path))
    code, _ = _post(base, "/api/coriqo/link", {"base_url": coriqo.base, "token": "tok"}, "chrome-extension://x")
    assert code == 200


def test_a_refused_replace_restores_the_previous_enrolment(tmp_path, coriqo, monkeypatch):  # noqa: F811
    base = _pinned(tmp_path, coriqo, monkeypatch, "acme, coriqo_msp_usa")
    coriqo.minted["cik_live_coriqo_msp_usa.1"] = "x"
    assert _post(base, "/api/coriqo/enrol", {"base_url": coriqo.base, "token": "cik_live_coriqo_msp_usa.1"}, base)[0] == 200
    path = tmp_path / "keys" / "enrollment.json"
    before = path.read_bytes()
    # token says acme (pinned) but the stub answers coriqo_msp_usa; make the pin exclude that answer
    monkeypatch.setenv("BYOAI_CORIQO_LINK_WORKSPACES", "acme")
    coriqo.minted["cik_live_acme.2"] = "x"
    code, _ = _post(base, "/api/coriqo/enrol", {"base_url": coriqo.base, "token": "cik_live_acme.2"}, base)
    assert code == 403 and path.read_bytes() == before


def test_an_unwritable_key_dir_is_not_reported_as_a_pin_refusal():
    from byoai.integrations.shield_publish import WorkspacePinError
    assert issubclass(WorkspacePinError, PermissionError)
    src = (__import__("pathlib").Path(__file__).parents[2] / "src/byoai/integrations/shield.py").read_text()
    assert "except WorkspacePinError" in src and "except PermissionError as exc:\n                self._send(403" not in src


def test_login_page_explains_a_refused_saved_address():
    src = (__import__("pathlib").Path(__file__).parents[2] / "src/byoai/browser_extension/login.js").read_text()
    assert src.count("bad_base' ? BAD_BASE_TEXT") + src.count("=== 'bad_base' ? BAD_BASE_TEXT") >= 4


def test_workspace_pin_ignores_case(tmp_path, coriqo, monkeypatch):  # noqa: F811
    base = _pinned(tmp_path, coriqo, monkeypatch, "Coriqo_MSP_USA")
    coriqo.minted["cik_live_coriqo_msp_usa.1"] = "x"
    code, _ = _post(base, "/api/coriqo/link", {"base_url": coriqo.base, "token": "cik_live_coriqo_msp_usa.1"},
                    "chrome-extension://x")
    assert code == 200
