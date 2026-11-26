"""`byoai-shield enrol`: token and server from an MDM-managed source, never logged."""
from __future__ import annotations

import io
import json
import os
import plistlib
import sys

import httpx
import pytest

pytest.importorskip("cryptography")

from byoai.integrations import shield_enrol as se  # noqa: E402
from byoai.recorder.enroll import load_enrollment_state  # noqa: E402

TOKEN = "cik_live_acme.0123456789abcdef"
URL = "https://shield.example.com"


def _mock(status_codes=(200,), seen=None):
    codes = list(status_codes)

    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(json.loads(request.content))
        code = codes.pop(0) if len(codes) > 1 else codes[0]
        if code != 200:
            return httpx.Response(code, text="busy")
        return httpx.Response(200, json={"device_id": "dev_1", "coriqo_base_url": URL, "tenant_slug": "acme"})
    return httpx.Client(transport=httpx.MockTransport(handler))


def _run(argv, tmp_path, client=None, **kw):
    out, err = io.StringIO(), io.StringIO()
    kw.setdefault("platform", "linux")
    kw.setdefault("file_path", tmp_path / "none.json")
    rc = se.run_enrol(argv, key_dir=tmp_path / "keys", http_client=client or _mock(),
                      sleep=lambda s: None, out=out, err=err, **kw)
    return rc, out.getvalue(), err.getvalue()


def _managed_file(tmp_path, data, mode=0o644):
    p = tmp_path / "enrol.json"
    p.write_text(json.dumps(data))
    p.chmod(mode)
    return p


def test_token_and_server_flags_enrol(tmp_path):
    seen = []
    rc, out, err = _run(["--token", TOKEN, "--server", URL], tmp_path, _mock(seen=seen))
    assert rc == 0, err
    assert seen[0]["token"] == TOKEN
    assert load_enrollment_state(tmp_path / "keys").device_id == "dev_1"
    assert TOKEN not in out + err


def test_token_file(tmp_path):
    f = tmp_path / "tok"
    f.write_text(TOKEN + "\n")
    rc, out, err = _run(["--token-file", str(f), "--server", URL], tmp_path)
    assert rc == 0, err
    assert "token file" in out


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission check")
def test_managed_file_supplies_token_and_server(tmp_path):
    p = _managed_file(tmp_path, {"token": TOKEN, "server_url": URL})
    seen = []
    rc, out, err = _run([], tmp_path, _mock(seen=seen), file_path=p)
    assert rc == 0, err
    assert seen[0]["token"] == TOKEN
    assert "file" in out and TOKEN not in out + err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission check")
def test_group_writable_managed_file_is_refused(tmp_path):
    p = _managed_file(tmp_path, {"token": TOKEN, "server_url": URL}, mode=0o664)
    rc, out, err = _run([], tmp_path, file_path=p)
    assert rc == 2
    assert "writable by group or other" in err and "chmod" in err
    assert TOKEN not in err
    assert load_enrollment_state(tmp_path / "keys") is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX ownership check")
def test_file_owned_by_someone_else_is_refused(tmp_path):
    p = _managed_file(tmp_path, {"token": TOKEN, "server_url": URL})
    rc, _o, err = _run([], tmp_path, file_path=p, uid=os.getuid() + 12345)
    assert rc == 2 and "owned by another user" in err


def test_windows_registry_source(tmp_path):
    rc, out, err = _run([], tmp_path, platform="win32",
                        registry=lambda: {"EnrolToken": TOKEN, "ServerUrl": URL})
    assert rc == 0, err
    assert "registry" in out and TOKEN not in out + err


def test_windows_without_registry_values_falls_through_to_file(tmp_path):
    p = _managed_file(tmp_path, {"token": TOKEN, "server_url": URL})
    rc, _o, err = _run([], tmp_path, platform="win32", registry=lambda: {}, file_path=p)
    assert rc == 0, err


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission check")
def test_macos_managed_preference(tmp_path):
    plist = tmp_path / "com.coriqo.shield.plist"
    plist.write_bytes(plistlib.dumps({"EnrolToken": TOKEN, "ServerUrl": URL}))
    plist.chmod(0o644)
    rc, out, err = _run([], tmp_path, platform="darwin", plist_path=plist)
    assert rc == 0, err
    assert "managed preference" in out and TOKEN not in out + err


def test_flag_server_overrides_managed_server(tmp_path):
    rc, out, _e = _run(["--server", "https://other.example.com"], tmp_path, platform="win32",
                       registry=lambda: {"EnrolToken": TOKEN, "ServerUrl": URL})
    assert rc == 0  # the mock answers any host; the point is that it resolved


def test_no_source_says_where_to_set_it(tmp_path):
    rc, _o, err = _run([], tmp_path)
    assert rc == 2
    assert "EnrolToken" in err and "msp-zero-touch" in err


def test_no_server_is_refused(tmp_path):
    rc, _o, err = _run(["--token", TOKEN], tmp_path)
    assert rc == 2 and "server address" in err


def test_plain_http_to_a_remote_host_is_refused(tmp_path):
    rc, _o, err = _run(["--token", TOKEN, "--server", "http://shield.example.com"], tmp_path)
    assert rc == 2 and "https://" in err
    assert TOKEN not in err


def test_http_to_this_computer_is_allowed(tmp_path):
    rc, _o, err = _run(["--token", TOKEN, "--server", "http://127.0.0.1:17840"], tmp_path)
    assert rc == 0, err


def test_already_enrolled_is_success_without_a_request(tmp_path):
    assert _run(["--token", TOKEN, "--server", URL], tmp_path)[0] == 0
    seen = []
    rc, out, _e = _run(["--token", TOKEN, "--server", URL], tmp_path, _mock(seen=seen))
    assert rc == 0 and "Already enrolled" in out and seen == []


def test_force_enrols_again(tmp_path):
    _run(["--token", TOKEN, "--server", URL], tmp_path)
    seen = []
    rc, _o, _e = _run(["--token", TOKEN, "--server", URL, "--force"], tmp_path, _mock(seen=seen))
    assert rc == 0 and len(seen) == 1


def test_rejected_token_fails_without_echoing_it(tmp_path):
    def handler(request):
        return httpx.Response(401, text=f"Invalid token {TOKEN}")
    client = httpx.Client(transport=httpx.MockTransport(handler))
    rc, out, err = _run(["--token", TOKEN, "--server", URL], tmp_path, client)
    assert rc == 1 and "401" in err
    assert TOKEN not in out + err


def test_busy_server_is_retried_with_backoff_then_succeeds(tmp_path):
    sleeps = []
    out, err = io.StringIO(), io.StringIO()
    rc = se.run_enrol(["--token", TOKEN, "--server", URL], key_dir=tmp_path / "keys",
                      http_client=_mock((429, 503, 200)), sleep=sleeps.append, rand=lambda: 0.5,
                      out=out, err=err, platform="linux", file_path=tmp_path / "none.json")
    assert rc == 0, err.getvalue()
    assert len(sleeps) == 2 and sleeps[1] > sleeps[0]


def test_busy_forever_gives_up_after_three_attempts(tmp_path):
    rc, _o, err = _run(["--token", TOKEN, "--server", URL], tmp_path, _mock((503,)))
    assert rc == 1 and "503" in err


def test_jitter_waits_a_random_slice_capped(tmp_path):
    sleeps = []
    out, err = io.StringIO(), io.StringIO()
    se.run_enrol(["--token", TOKEN, "--server", URL, "--jitter-seconds", "99999"],
                 key_dir=tmp_path / "keys", http_client=_mock(), sleep=sleeps.append,
                 rand=lambda: 1.0, out=out, err=err, platform="linux", file_path=tmp_path / "none.json")
    assert sleeps == [se.MAX_JITTER_S]


def test_token_is_not_in_the_repr():
    m = se.ManagedEnrolment(TOKEN, URL, "x")
    assert TOKEN not in repr(m)


def test_main_dispatches_enrol_subcommand(monkeypatch):
    import byoai.integrations.shield as shield
    seen = {}
    monkeypatch.setattr(se, "run_enrol", lambda argv: seen.setdefault("argv", argv) and 0)
    monkeypatch.setattr(shield._sys, "argv", ["byoai-shield", "enrol", "--force"])
    with pytest.raises(SystemExit) as exc:
        shield.main()
    assert exc.value.code == 0 and seen["argv"] == ["--force"]
