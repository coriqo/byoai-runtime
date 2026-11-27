import io
import json
import os

import httpx
import pytest

from byoai.integrations import shield_discover as sd
from byoai.integrations import shield_discover_send as ss

KEY = "cik_disc_acme.SECRETSECRETSECRET"
SERVER = "https://coriqo.example.com"


def _run(argv, handler=None, *, tmp_path, managed_file=None, **extra):
    out, err = io.StringIO(), io.StringIO()
    calls: list[httpx.Request] = []

    def wrapped(req):
        calls.append(req)
        return handler(req) if handler else httpx.Response(201, json={"status": "stored"})

    client = httpx.Client(transport=httpx.MockTransport(wrapped))
    sleeps: list[float] = []
    code = sd.run_discover(
        argv, out=out, err=err, platform="linux", home=tmp_path, env={"PATH": ""},
        send_kw=dict(http_client=client, sleep=sleeps.append, rand=lambda: 0.0,
                     platform="linux", file_path=managed_file or tmp_path / "none.json", **extra))
    return code, out.getvalue(), err.getvalue(), calls, sleeps


def _keyfile(tmp_path, text=KEY):
    p = tmp_path / "k"
    p.write_text(text + "\n")
    return p


def _argv(tmp_path, *more):
    return ["--send", "--no-probe", "--key-file", str(_keyfile(tmp_path)), "--server", SERVER, *more]


def test_success_sends_only_the_report(tmp_path):
    code, out, err, calls, _ = _run(_argv(tmp_path), tmp_path=tmp_path)
    assert code == 0 and len(calls) == 1
    req = calls[0]
    assert str(req.url) == SERVER + "/api/v1/discovery/endpoint-reports"
    assert req.headers["authorization"] == f"Bearer {KEY}"
    body = json.loads(req.content)
    assert body["schema"] == "byoai.shield.discovery/1" and body["attestation"] == "unattested"
    assert set(body) <= {"schema", "attestation", "generated_at", "platform", "signatures_version", "items", "skipped"}
    assert str(tmp_path) not in req.content.decode()
    assert KEY not in out + err and "SECRETSECRET" not in out + err
    assert '"items"' not in out  # report is not dumped to stdout with --send


@pytest.mark.parametrize("status,code", [(401, 11), (403, 10), (413, 13), (422, 14), (400, 14), (415, 14), (423, 15)])
def test_refusals_have_distinct_codes_and_never_echo_server_text(tmp_path, status, code):
    h = lambda r: httpx.Response(status, json={"detail": f"ZZMARK {KEY}"})  # noqa: E731
    got, out, err, calls, _ = _run(_argv(tmp_path), h, tmp_path=tmp_path)
    assert got == code and len(calls) == 1
    assert KEY not in out + err and "ZZMARK" not in err and "Send failed:" in err


def test_rate_limit_short_retry_after_retries_then_ok(tmp_path):
    seq = iter([httpx.Response(429, headers={"Retry-After": "5"}), httpx.Response(201, json={})])
    code, _, _, calls, sleeps = _run(_argv(tmp_path), lambda r: next(seq), tmp_path=tmp_path)
    assert code == 0 and len(calls) == 2 and sleeps == [5.0]


def test_rate_limit_long_retry_after_gives_up(tmp_path):
    h = lambda r: httpx.Response(429, headers={"Retry-After": "900"})  # noqa: E731
    code, _, _, calls, _ = _run(_argv(tmp_path), h, tmp_path=tmp_path)
    assert code == 12 and len(calls) == 1


def test_transient_retries_then_succeeds_and_caps(tmp_path):
    seq = iter([httpx.Response(503), httpx.Response(409), httpx.Response(201, json={})])
    code, _, _, calls, sleeps = _run(_argv(tmp_path), lambda r: next(seq), tmp_path=tmp_path)
    assert code == 0 and len(calls) == 3 and len(sleeps) == 2
    code, _, err, calls, _ = _run(_argv(tmp_path), lambda r: httpx.Response(503), tmp_path=tmp_path)
    assert code == 1 and len(calls) == ss.MAX_ATTEMPTS and "503" in err


def test_network_error_shows_class_only(tmp_path):
    def boom(req):
        raise httpx.ConnectError(f"failed {KEY} {req.url}")
    code, out, err, calls, _ = _run(_argv(tmp_path), boom, tmp_path=tmp_path)
    assert code == 1 and len(calls) == ss.MAX_ATTEMPTS
    assert KEY not in out + err and "ConnectError" in err and "coriqo.example.com" not in err


def test_duplicate_200_is_success(tmp_path):
    code, *_ = _run(_argv(tmp_path), lambda r: httpx.Response(200, json={"status": "duplicate"}), tmp_path=tmp_path)
    assert code == 0


def test_over_limit_is_not_sent(tmp_path, monkeypatch):
    monkeypatch.setattr(ss, "MAX_BODY_BYTES", 10)
    code, _, _, calls, _ = _run(_argv(tmp_path), tmp_path=tmp_path)
    assert code == 13 and calls == []


def test_non_https_refused_without_network(tmp_path):
    argv = ["--send", "--no-probe", "--key-file", str(_keyfile(tmp_path)), "--server", "http://coriqo.example.com"]
    code, out, err, calls, _ = _run(argv, tmp_path=tmp_path)
    assert code == 2 and calls == [] and "https://" in err and KEY not in out + err


def test_wrong_kind_of_key_refused(tmp_path):
    argv = ["--send", "--no-probe", "--key-file", str(_keyfile(tmp_path, "enrol-token-123")), "--server", SERVER]
    code, out, err, calls, _ = _run(argv, tmp_path=tmp_path)
    assert code == 2 and calls == [] and "enrol-token-123" not in out + err


def test_no_send_makes_no_network_call(tmp_path):
    out, err = io.StringIO(), io.StringIO()

    def forbidden(req):
        raise AssertionError("network call without --send")
    client = httpx.Client(transport=httpx.MockTransport(forbidden))
    code = sd.run_discover(["--no-probe", "--key-file", str(_keyfile(tmp_path)), "--server", SERVER], out=out, err=err,
                           platform="linux", home=tmp_path, env={"PATH": ""},
                           send_kw=dict(http_client=client))
    assert code == 0 and '"items"' in out.getvalue()


def test_managed_file_used_and_untrusted_refused(tmp_path):
    f = tmp_path / "discover.json"
    f.write_text(json.dumps({"key": KEY, "server_url": SERVER}))
    os.chmod(f, 0o644)
    code, _, _, calls, _ = _run(["--send", "--no-probe"], tmp_path=tmp_path, managed_file=f)
    assert code == 0 and calls[0].headers["authorization"] == f"Bearer {KEY}"
    os.chmod(f, 0o666)
    code, out, err, calls, _ = _run(["--send", "--no-probe"], tmp_path=tmp_path, managed_file=f)
    assert code == 2 and calls == [] and "writable by group or other" in err and KEY not in out + err


def test_malformed_managed_file_does_not_quote_content(tmp_path):
    f = tmp_path / "discover.json"
    f.write_text(f'{{"key": "{KEY}" oops')
    code, out, err, calls, _ = _run(["--send", "--no-probe"], tmp_path=tmp_path, managed_file=f)
    assert code == 2 and calls == [] and KEY not in out + err


def test_registry_and_plist_sources(tmp_path):
    reg = ss.read_managed(platform="win32", registry=lambda: {"DiscoveryKey": KEY, "ServerUrl": SERVER}, file_path=tmp_path / "x")
    assert reg and reg.key == KEY and "registry" in reg.source and KEY not in repr(reg)
    import plistlib
    p = tmp_path / "m.plist"
    p.write_bytes(plistlib.dumps({"DiscoveryKey": KEY, "ServerUrl": SERVER}))
    os.chmod(p, 0o644)
    m = ss.read_managed(platform="darwin", plist_path=p, file_path=tmp_path / "x")
    assert m and m.server_url == SERVER


def test_no_key_anywhere(tmp_path):
    code, _, err, calls, _ = _run(["--send", "--no-probe"], tmp_path=tmp_path)
    assert code == 2 and calls == [] and "No discovery key" in err


def test_jitter_is_capped(tmp_path):
    _, _, _, _, sleeps = _run(_argv(tmp_path, "--jitter-seconds", "99999"), tmp_path=tmp_path)
    assert sleeps == [0.0]
