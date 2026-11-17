"""Proxy host table, per-app fixtures, warn/block actions, canary, uploads."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("mitmproxy")

from byoai.integrations.shield import COVERED_APPS, default_policy  # noqa: E402
from byoai.integrations.shield_proxy import (  # noqa: E402
    HOSTS,
    ShieldProxy,
    app_for_host,
)

from .test_shield_proxy import _Flow, _rows  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "proxy"
NEW_APPS = ["github_copilot", "mistral", "deepseek", "groq", "openrouter",
            "together", "gemini_api"]


@pytest.fixture
def proxy(tmp_path, monkeypatch):
    import byoai.integrations.shield as sh
    real = sh._fingerprint_key
    monkeypatch.setattr(sh, "_fingerprint_key", lambda p=None: real(tmp_path / "fp.key"))
    return ShieldProxy(ledger=tmp_path / "captures.jsonl", policy_path=tmp_path / "policy.json")


def _enable(proxy, **extra):
    proxy.policy_path.write_text(json.dumps({"policy_version": 2, **extra}))
    proxy._policy = None  # skip the two-second policy cache


@pytest.mark.parametrize("host,app", [
    ("api.openai.com", "chatgpt"), ("chatgpt.com", "chatgpt"), ("claude.ai", "claude"),
    ("api.anthropic.com", "claude"), ("API.Anthropic.com.", "claude"),
    ("api.githubcopilot.com", "github_copilot"), ("x.y.githubcopilot.com", "github_copilot"),
    ("api.mistral.ai", "mistral"), ("generativelanguage.googleapis.com", "gemini_api"),
])
def test_hosts_match_exactly_or_on_a_dot_boundary(host, app):
    assert app_for_host(host) == app


@pytest.mark.parametrize("host", [
    "evil-openai.com.attacker", "openai.com.attacker.io", "notopenai.com",
    "evilanthropic.com", "claude.ai.evil.example", "fakechatgpt.com",
    "githubcopilot.com.evil.io", "xgithubcopilot.com", "api.mistral.ai.evil.io", "", None,
])
def test_lookalike_hosts_are_not_governed(host):
    assert app_for_host(host) is None


def test_lookalike_host_is_never_inspected_even_when_the_app_is_on(proxy):
    _enable(proxy, apps={"chatgpt": True})
    flow = _Flow("evil-openai.com.attacker", "/v1/chat/completions",
                 json.dumps({"messages": [{"role": "user", "content": "a@x.co"}]}))
    proxy.request(flow)
    assert "a@x.co" in flow.request.get_text() and not proxy.ledger.exists()


def test_every_covered_app_has_a_host_entry_and_new_ones_are_off_by_default():
    assert {e["app"] for e in HOSTS if e["app"] in COVERED_APPS} == set(COVERED_APPS)
    assert all(not default_policy()["apps"][a] for a in NEW_APPS)
    assert all(e["verified"] is False for e in HOSTS if e["app"] in NEW_APPS)


@pytest.mark.parametrize("app", NEW_APPS)
def test_fixture_is_redacted_for_each_new_app(proxy, app):
    fx = json.loads((FIXTURES / f"{app}.json").read_text())
    assert app_for_host(fx["host"]) == app
    body = json.dumps(fx["body"])
    off = _Flow(fx["host"], fx["path"], body)
    proxy.request(off)                       # default policy: app is off
    assert off.request.get_text() == body and not proxy.ledger.exists()
    _enable(proxy, apps={app: True})
    flow = _Flow(fx["host"], fx["path"], body)
    proxy.request(flow)
    sent = flow.request.get_text()
    assert "jane.doe@example.com" not in sent and "[EMAIL_1]" in sent
    (row,) = _rows(proxy)
    assert row["app"] == app and row["redactions"] == ["emails"]
    assert "jane.doe" not in json.dumps(row)


def test_secret_is_stopped_by_default_in_a_history_turn_too(proxy):
    body = {"messages": [{"role": "user", "content": "key AKIAIOSFODNN7EXAMPLE"},
                         {"role": "assistant", "content": "ok"},
                         {"role": "user", "content": "thanks"}]}
    flow = _Flow("api.openai.com", "/v1/chat/completions", json.dumps(body))
    _enable(proxy, apps={"chatgpt": True})
    proxy.request(flow)
    assert flow.response is not None and flow.response.status_code == 403
    assert b"AWS access key" in flow.response.content
    (row,) = _rows(proxy)
    assert row["kind"] == "desktop.verdict.denied" and "AKIA" not in json.dumps(row)


def test_warn_is_redact_in_the_proxy_and_the_row_says_so(proxy):
    flow = _Flow("claude.ai", "/api/organizations/o1/chat_conversations/c1/completion",
                 json.dumps({"prompt": "the db password: hunter42x"}))
    proxy.request(flow)
    assert json.loads(flow.request.get_text())["prompt"] == "the db [SECRET_1]"
    (row,) = _rows(proxy)
    assert row["action"] == "warn" and row["redactions"] == ["credential_assign"]
    assert "hunter42x" not in json.dumps(row)


def test_deploy_sh_is_only_a_signal(proxy):
    _enable(proxy, mode="block")
    flow = _Flow("claude.ai", "/api/organizations/o1/chat_conversations/c1/completion",
                 json.dumps({"prompt": "why does deploy.sh fail?"}))
    proxy.request(flow)
    assert flow.response is None
    (row,) = _rows(proxy)
    assert "flag:executable_masquerade" in row["flags"]


def test_canary_fires_after_three_unrecognised_sends_and_not_when_inspected(proxy):
    def send(path):
        proxy.request(_Flow("claude.ai", path, "{}"))
    for _ in range(2):
        send("/api/new/chat_thing/start")
    assert not proxy.ledger.exists()
    send("/api/new/chat_thing/start")
    (row,) = _rows(proxy)
    assert row["kind"] == "desktop.health.unmatched" and row["app"] == "claude"
    assert "body" not in row and len(row["path"]) <= 60
    # an inspected send in the window suppresses it
    proxy.request(_Flow("claude.ai", "/api/organizations/o1/chat_conversations/c1/completion",
                        json.dumps({"prompt": "hi"})))
    n = len(_rows(proxy))
    for _ in range(3):
        send("/api/new/chat_thing/start")
    assert [r["kind"] for r in _rows(proxy)[n:]] == []


def test_attachment_records_type_and_size_not_content(proxy):
    part = (b'--b\r\nContent-Disposition: form-data; name="file"; filename="q.pdf"\r\n'
            b"Content-Type: application/pdf\r\n\r\nTOPSECRETBYTES\r\n--b--\r\n")
    flow = _Flow("chatgpt.com", "/backend-api/files", "")
    _enable(proxy, apps={"chatgpt": True})
    flow.request.headers = {"content-type": "multipart/form-data; boundary=b"}
    flow.request.get_content = lambda strict=False: part
    proxy.request(flow)
    (row,) = _rows(proxy)
    assert row["kind"] == "desktop.chat.attachment"
    assert row["mime"] == "application/pdf" and row["bytes"] == len(b"TOPSECRETBYTES")
    assert row["scanned"] is False and row["verdict"] == "allowed"
    assert "TOPSECRET" not in json.dumps(row)


def test_uncovered_hosts_get_one_meta_row(proxy):
    for _ in range(2):
        proxy.request(_Flow("api2.cursor.sh", "/aiserver.v1.Chat/Stream", "\x00"))
    (row,) = _rows(proxy)
    assert row["kind"] == "desktop.meta" and row["target"] == "api2.cursor.sh"
    assert row["not_covered"]


def _upload_fixture(name):
    return json.loads((Path(__file__).resolve().parents[1] / "fixtures" / "uploads" / name).read_text())


def test_chatgpt_presigned_put_is_an_upload(proxy):
    step = _upload_fixture("chatgpt.json")["steps"][1]
    assert step["method"] == "PUT"
    _enable(proxy, apps={"chatgpt": True})
    flow = _Flow("files.oaiusercontent.com", "/files/abc123/raw", "")
    flow.request.method = "PUT"
    flow.request.headers = {"content-type": "text/plain"}
    flow.request.get_content = lambda strict=False: b"hello\n"
    proxy.request(flow)
    (row,) = _rows(proxy)
    assert row["kind"] == "desktop.chat.attachment" and row["app"] == "chatgpt"
    assert row["sha256"] == "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
    assert row["bytes"] == 6 and row["verdict"] == "allowed"


def test_chatgpt_presigned_put_can_be_blocked(proxy):
    _enable(proxy, apps={"chatgpt": True}, files={"chatgpt": "block"})
    flow = _Flow("files.oaiusercontent.com", "/files/abc123/raw", "")
    flow.request.method = "PUT"
    flow.request.headers = {"content-type": "text/plain"}
    flow.request.get_content = lambda strict=False: b"hello\n"
    proxy.request(flow)
    assert _rows(proxy)[0]["verdict"] == "blocked"
    assert flow.response is not None


@pytest.mark.parametrize("host,path", [
    ("evil-oaiusercontent.com", "/files/abc/raw"),   # not on a dot boundary
])
def test_only_the_storage_host_counts(proxy, host, path):
    _enable(proxy, apps={"chatgpt": True})
    flow = _Flow(host, path, "")
    flow.request.method = "PUT"
    flow.request.headers = {"content-type": "text/plain"}
    flow.request.get_content = lambda strict=False: b"hello\n"
    proxy.request(flow)
    assert not proxy.ledger.exists() or [r for r in _rows(proxy) if r["kind"].endswith("attachment")] == []


def test_chatgpt_metadata_post_is_not_an_attachment(proxy):
    _enable(proxy, apps={"chatgpt": True})
    flow = _Flow("chatgpt.com", "/backend-api/files", "{}")
    flow.request.headers = {"content-type": "application/json"}
    proxy.request(flow)
    assert not proxy.ledger.exists() or [r for r in _rows(proxy) if r["kind"].endswith("attachment")] == []


def test_claude_wiggle_upload_multipart(proxy):
    path = _upload_fixture("claude_ai.json")["upload"]["url"].split("claude.ai", 1)[1]
    path = path.replace("<org-uuid>", "o1").replace("<conversation-uuid>", "c1")
    part = (b'--b\r\nContent-Disposition: form-data; name="file"; filename="hello.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\nhello\n\r\n--b--\r\n")
    _enable(proxy, apps={"claude": True})
    flow = _Flow("claude.ai", path, "")
    flow.request.headers = {"content-type": "multipart/form-data; boundary=b"}
    flow.request.get_content = lambda strict=False: part
    proxy.request(flow)
    (row,) = _rows(proxy)
    assert row["kind"] == "desktop.chat.attachment" and row["scanned"] is True
    assert row["sha256"] == "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
    assert "hello.txt" not in json.dumps(row)
