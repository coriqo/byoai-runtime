from __future__ import annotations

import gzip
import json

import httpx
import pytest
from starlette.testclient import TestClient

from byoai.agent_context_cache import main as acc_main


class FakeRedis:
    def __init__(self):
        self.kv = {}

    async def exists(self, key):
        return key in self.kv

    async def set(self, key, value):
        self.kv[key] = str(value)

    async def get(self, key):
        return self.kv.get(key)

    async def incrby(self, key, amount):
        self.kv[key] = str(int(self.kv.get(key, "0")) + amount)

    async def sismember(self, key, value):
        return False

    async def sadd(self, key, value):
        pass

    async def expire(self, key, seconds):
        pass

    async def close(self):
        pass

KEY = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0k1L2"


@pytest.fixture
def client(monkeypatch, tmp_path):
    saved = acc_main.r
    monkeypatch.setattr(acc_main, "r", FakeRedis())
    monkeypatch.setattr(acc_main.db, "DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setenv("BYOAI_SHIELD_KEY_PATH", str(tmp_path / "fp.key"))
    monkeypatch.setenv("BYOAI_SHIELD_GUARD", "enforce")
    acc_main._session_hash_store.fallback._sessions.clear()
    with TestClient(acc_main.app) as c:
        yield c
    acc_main.r = saved


def upstream(seen, *, sse=False):
    def handler(req: httpx.Request):
        seen.append((str(req.url), json.loads(req.content)))
        if sse:
            return httpx.Response(200, headers={"content-type": "text/event-stream"},
                                  content=b"data: one\n\ndata: two\n\ndata: [DONE]\n\n")
        return httpx.Response(200, json={"ok": True})
    acc_main.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))


def anth(client, text, **kw):
    return client.post("/v1/messages", headers={"x-api-key": "k"}, json={
        "model": "claude-x", "max_tokens": 5,
        "messages": [{"role": "user", "content": text}], **kw})


def oai(client, text, path="/v1/chat/completions", **kw):
    return client.post(path, headers={"authorization": "Bearer k"}, json={
        "model": "gpt-x", "messages": [{"role": "user", "content": text}], **kw})


def test_anthropic_block_shape_and_nothing_forwarded(client):
    seen = []
    upstream(seen)
    r = anth(client, f"key {KEY}")
    assert r.status_code == 403
    j = r.json()
    assert j["type"] == "error" and j["error"]["type"] == "coriqo_shield_blocked"
    assert "Anthropic API key" in j["error"]["labels"] and KEY not in r.text
    assert seen == []


def test_openai_block_shape(client):
    seen = []
    upstream(seen)
    for path in ("/v1/chat/completions", "/v1/responses"):
        r = oai(client, f"key {KEY}", path)
        assert r.status_code == 403
        e = r.json()["error"]
        assert e["type"] == "coriqo_shield_blocked" and e["code"] == "shield_blocked"
        assert KEY not in r.text
    assert seen == []


def test_redact_forwards_redacted_body(client):
    seen = []
    upstream(seen)
    assert anth(client, "mail a@b.co").status_code == 200
    assert seen[-1][1]["messages"][0]["content"] == "mail [EMAIL_1]"
    assert oai(client, "mail a@b.co").status_code == 200
    url, sent = seen[-1]
    assert url == "https://api.openai.com/v1/chat/completions"
    assert sent["messages"][0]["content"] == "mail [EMAIL_1]"


def test_observe_forwards_as_sent(client, monkeypatch):
    monkeypatch.setenv("BYOAI_SHIELD_GUARD", "observe")
    seen = []
    upstream(seen)
    assert anth(client, f"key {KEY}").status_code == 200
    assert KEY in json.dumps(seen[-1][1])
    assert oai(client, f"key {KEY}").status_code == 200


def test_openai_stream_passthrough(client):
    seen = []
    upstream(seen, sse=True)
    r = oai(client, "hello", stream=True)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    assert r.text == "data: one\n\ndata: two\n\ndata: [DONE]\n\n"


def test_anthropic_stream_still_streams(client):
    seen = []
    upstream(seen, sse=True)
    r = anth(client, "hello", stream=True)
    assert r.status_code == 200 and "data: two" in r.text


def test_off_leaves_openai_path_on_old_route(client, monkeypatch):
    monkeypatch.delenv("BYOAI_SHIELD_GUARD")
    seen = []
    upstream(seen)
    assert oai(client, f"key {KEY}").status_code == 200
    assert seen[-1][0].startswith("https://api.anthropic.com/v1/chat/completions")


def test_policy_file_and_evidence_row(client, monkeypatch, tmp_path):
    pol = tmp_path / "policy.json"
    from byoai.integrations import shield
    p = shield.default_policy()
    p["actions"] = dict(p["actions"], pii="block")
    p["acknowledge"] = "less_private"
    pol.write_text(json.dumps(p))
    monkeypatch.setenv("BYOAI_SHIELD_POLICY", str(pol))
    seen = []
    upstream(seen)
    assert anth(client, "mail a@b.co").status_code == 403

    rows = []

    class Rec:
        def record(self, ev):
            rows.append(ev)
    monkeypatch.setattr(acc_main, "get_recorder", lambda: Rec())
    anth(client, f"key {KEY}")
    ev = rows[-1]
    assert ev.kind == "shield_guard"
    assert ev.payload["action"] == "block" and ev.payload["forwarded"] is False
    assert "anthropic_key" in ev.payload["rules"] and ev.payload["text_hmac"]
    assert KEY not in json.dumps(ev.payload)


def raw(client, method, path, content, headers=None):
    h = {"x-api-key": "k", "content-type": "application/json", **(headers or {})}
    return client.request(method, path, content=content, headers=h, follow_redirects=False)


AWS = "AKIA" + "Q3ZT7XWPL2MN4RJK"


def test_every_body_path_is_guarded(client):
    seen = []
    upstream(seen)
    msgs = json.dumps({"model": "claude-x", "max_tokens": 5,
                       "messages": [{"role": "user", "content": AWS}]}).encode()
    oai_body = json.dumps({"model": "g", "messages": [{"role": "user", "content": AWS}]}).encode()
    cases = [
        ("POST", "/v1/messages/", msgs, None),
        ("POST", "/v1/messages/count_tokens", msgs, None),
        ("POST", "/v1/complete", json.dumps({"prompt": AWS}).encode(), None),
        ("POST", "/v1/messages/batches",
         json.dumps({"requests": [{"custom_id": "a", "params": json.loads(msgs)}]}).encode(), None),
        ("PUT", "/v1/messages", msgs, None),
        ("PUT", "/v1/anything", msgs, None),
        ("POST", "/v1/chat/completions/", oai_body, None),
        ("POST", "/v1/responses/", json.dumps({"instructions": AWS}).encode(), None),
        ("POST", "/v1/messages", gzip.compress(msgs), {"content-encoding": "gzip"}),
        ("POST", "/v1/messages", msgs, {"content-encoding": "br"}),
        ("POST", "/v1/messages", b"not json " + AWS.encode(), None),
    ]
    for meth, path, body, hdr in cases:
        r = raw(client, meth, path, body, hdr)
        assert r.status_code in (403, 307, 308, 404, 405), (meth, path, r.status_code, r.text[:100])
    assert not any(AWS.encode() in c for _, c in [(0, json.dumps(b).encode()) for _, b in seen])
    assert seen == []


def test_off_does_not_touch_bodies(client, monkeypatch):
    monkeypatch.delenv("BYOAI_SHIELD_GUARD")
    seen = []
    upstream(seen)
    assert raw(client, "PUT", "/v1/anything", json.dumps({"k": AWS}).encode()).status_code == 200


def spy(seen):
    def handler(req: httpx.Request):
        seen.append((str(req.url), dict(req.headers), req.content))
        return httpx.Response(200, json={"ok": True})
    acc_main.http_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_guard_off_gzip_passthrough_is_byte_identical(client, monkeypatch):
    monkeypatch.delenv("BYOAI_SHIELD_GUARD")
    seen = []
    spy(seen)
    body = gzip.compress(json.dumps({"k": "a@b.co"}).encode())
    r = raw(client, "POST", "/v1/anything", body, {"content-encoding": "gzip"})
    assert r.status_code == 200
    assert seen[-1][2] == body and seen[-1][1]["content-encoding"] == "gzip"


def test_observe_forwards_original_bytes_and_headers(client, monkeypatch):
    monkeypatch.setenv("BYOAI_SHIELD_GUARD", "observe")
    seen = []
    spy(seen)
    body = gzip.compress(json.dumps({"messages": [{"role": "user", "content": "a@b.co"}]}).encode())
    for path in ("/v1/anything", "/v1/chat/completions"):
        assert raw(client, "POST", path, body, {"content-encoding": "gzip"}).status_code == 200
        assert seen[-1][2] == body and seen[-1][1]["content-encoding"] == "gzip"
    r = raw(client, "POST", "/v1/anything", json.dumps({"k": KEY}).encode())
    assert r.status_code == 200 and KEY.encode() in seen[-1][2]


def test_enforce_clean_gzip_stays_gzip_and_redacted_is_plain(client):
    seen = []
    spy(seen)
    clean = gzip.compress(json.dumps({"k": "hi"}).encode())
    raw(client, "POST", "/v1/anything", clean, {"content-encoding": "gzip"})
    assert seen[-1][2] == clean and seen[-1][1]["content-encoding"] == "gzip"
    dirty = gzip.compress(json.dumps({"k": "a@b.co"}).encode())
    raw(client, "POST", "/v1/anything", dirty, {"content-encoding": "gzip"})
    assert json.loads(seen[-1][2]) == {"k": "[EMAIL_1]"} and "content-encoding" not in seen[-1][1]


def test_enforce_multipart_only_secrets_block_and_body_untouched(client):
    seen = []
    spy(seen)
    part = b"--b\r\nContent-Disposition: form-data; name=f; filename=a.txt\r\n\r\nmail jane@example.org\r\n--b--"
    h = {"content-type": "multipart/form-data; boundary=b"}
    assert raw(client, "POST", "/v1/files", part, h).status_code == 200
    assert seen[-1][2] == part
    assert raw(client, "POST", "/v1/files", part.replace(b"jane@example.org", AWS.encode()),
               h).status_code == 403


def test_policy_is_cached_by_mtime(monkeypatch, tmp_path):
    from byoai.shield_guard import gateway
    pol = tmp_path / "p.json"
    pol.write_text("{}")
    monkeypatch.setenv("BYOAI_SHIELD_POLICY", str(pol))
    a = gateway._policy()
    assert gateway._policy() is a
    import os
    pol.write_text('{"mode": "observe"}')
    os.utime(pol, ns=(1, 1))
    assert gateway._policy() is not a
