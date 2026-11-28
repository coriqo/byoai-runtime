"""U2.1: provider, model and tool requests on desktop proxy rows.

Fixtures in tests/fixtures/proxy/sig_*.json are real request/response shapes from the
public API docs (no live captures, no keys). Rows carry facts only: no body text.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("mitmproxy")

from byoai.integrations.shield import COVERED_APPS  # noqa: E402
from byoai.integrations.shield_events import adapt_row  # noqa: E402
from byoai.integrations.shield_proxy import (  # noqa: E402
    ShieldProxy,
    observe_reply,
    signature_fields,
)

from .test_shield_proxy import _Flow, _Resp, _rows  # noqa: E402
from .test_shield_proxy_hosts import _enable  # noqa: E402


@pytest.fixture
def proxy(tmp_path, monkeypatch):
    import byoai.integrations.shield as sh
    real = sh._fingerprint_key
    monkeypatch.setattr(sh, "_fingerprint_key", lambda p=None: real(tmp_path / "fp.key"))
    px = ShieldProxy(ledger=tmp_path / "captures.jsonl", policy_path=tmp_path / "policy.json")
    _enable(px, apps={a: True for a in COVERED_APPS})
    return px


FIXTURES = sorted((Path(__file__).resolve().parents[1] / "fixtures" / "proxy").glob("sig_*.json"))
IDS = [p.stem for p in FIXTURES]
# Hosts the proxy governs: the others only go through the pure helpers.
GOVERNED = {"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com"}

REQ_KEYS = {"kind", "wall_clock", "target", "app", "verdict", "redactions", "flags", "chars",
            "text_hmac", "action", "provider", "deployment", "model"}
RESP_KEYS = {"kind", "wall_clock", "target", "app", "status", "flags", "chars", "text_hmac",
             "provider", "deployment", "model", "tools"}
BODY_WORDS = ("Paris", "Weather", "weather in", "Let me check", "city", "hi")


def _fx(path: Path) -> dict:
    return json.loads(path.read_text())


def _raw(fx: dict) -> str:
    return fx["response_sse"] if "response_sse" in fx else json.dumps(fx["response_json"])


@pytest.mark.parametrize("path", FIXTURES, ids=IDS)
def test_helpers_read_provider_model_and_tools(path):
    fx = _fx(path)
    exp = fx["expect"]
    req = signature_fields(fx["host"], fx["path"], fx["request"])
    assert req["provider"] == exp["provider"] and req["deployment"] == exp["deployment"]
    assert req.get("model") == exp["model"]
    rep = observe_reply(fx["host"], fx["path"], _raw(fx))
    assert rep.get("tools", []) == exp["tools"]
    assert rep.get("model") == exp["response_model"]


@pytest.mark.parametrize("path", [p for p in FIXTURES if _fx(p)["host"] in GOVERNED], ids=lambda p: p.stem)
def test_rows_carry_facts_and_no_body_text(proxy, path):
    fx = _fx(path)
    exp = fx["expect"]
    flow = _Flow(fx["host"], fx["path"], json.dumps(fx["request"]))
    proxy.request(flow)
    flow.response = _Resp(_raw(fx))
    proxy.response(flow)
    req, resp = _rows(proxy)
    assert req["kind"] == "desktop.chat.request" and resp["kind"] == "desktop.chat.response"
    assert req["provider"] == exp["provider"] == resp["provider"]
    assert req["deployment"] == exp["deployment"]
    assert req.get("model") == exp["model"]
    assert resp.get("model") == exp["response_model"]
    assert resp.get("tools", []) == exp["tools"]
    assert set(req) <= REQ_KEYS and set(resp) <= RESP_KEYS
    for row in (req, resp):
        dump = json.dumps(row)
        assert not any(w in dump for w in BODY_WORDS), dump
        assert "toolu_" not in dump and "call_1" not in dump  # ids and arguments are not stored


@pytest.mark.parametrize("path", [p for p in FIXTURES if _fx(p)["host"] in GOVERNED], ids=lambda p: p.stem)
def test_adapter_still_accepts_the_rows(proxy, path):
    fx = _fx(path)
    flow = _Flow(fx["host"], fx["path"], json.dumps(fx["request"]))
    proxy.request(flow)
    flow.response = _Resp(_raw(fx))
    proxy.response(flow)
    req, resp = _rows(proxy)
    (req_env,) = adapt_row(req)
    assert req_env["model"].get("name") == fx["expect"]["model"] if fx["expect"]["model"] else \
        req_env["model"] == {"identification": "unknown"}
    envs = adapt_row(resp)
    tools = [e["tool"]["name"] for e in envs if e["ai_event_type"] == "ai.tool_call.requested"]
    assert tools == fx["expect"]["tools"]
    assert all(e["evidence_level"] == "observed_requested" for e in envs[1:])
    assert not any(e["tool"]["status"] == "executed" for e in envs if "tool" in e)


@pytest.mark.parametrize("path", [p for p in FIXTURES if _fx(p)["host"] not in GOVERNED], ids=lambda p: p.stem)
def test_private_azure_and_gateways_report_unknown(path):
    fx = _fx(path)
    req = signature_fields(fx["host"], fx["path"], fx["request"])
    assert req == {"provider": "unknown", "deployment": "unknown"}  # the body's model is not trusted here


def test_openai_compatible_host_is_unknown_provider_but_tools_still_seen(proxy):
    body = {"model": "mistral-large-latest", "messages": [{"role": "user", "content": "hi"}]}
    flow = _Flow("api.mistral.ai", "/v1/chat/completions", json.dumps(body))
    proxy.request(flow)
    flow.response = _Resp(json.dumps({"choices": [{"message": {"tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": "lookup", "arguments": "{}"}}]}}]}))
    proxy.response(flow)
    req, resp = _rows(proxy)
    assert req["provider"] == "unknown" and "model" not in req
    assert resp["tools"] == ["lookup"]


@pytest.mark.parametrize("raw", [
    "", "data: {not json\n\n", "event: ping\n\n", "\x00\xff", "[1,2", "data: [DONE]\n\n",
])
def test_unparseable_reply_is_empty_not_guessed(proxy, raw):
    flow = _Flow("api.anthropic.com", "/v1/messages", json.dumps({"model": "claude-sonnet-4-5"}))
    proxy.request(flow)
    flow.response = _Resp(raw)
    proxy.response(flow)
    resp = _rows(proxy)[1]
    assert "tools" not in resp and "model" not in resp


def test_streaming_response_without_content_is_empty(proxy):
    class _Streamed(_Resp):
        def get_text(self, strict=False):
            raise ValueError("streamed")

    flow = _Flow("api.openai.com", "/v1/chat/completions", json.dumps({"model": "gpt-4o"}))
    proxy.request(flow)
    flow.response = _Streamed("")
    proxy.response(flow)
    resp = _rows(proxy)[1]
    assert "tools" not in resp and "model" not in resp


def test_plain_text_reply_has_no_tools(proxy):
    fx = _fx(next(p for p in FIXTURES if p.stem == "sig_gateway"))
    raw = _raw(fx)
    assert observe_reply(fx["host"], fx["path"], raw) == {}


def test_error_envelope_is_empty_with_nothing_to_record():
    raw = json.dumps({"error": {"type": "rate_limit_error", "message": "slow down"}})
    assert observe_reply("api.anthropic.com", "/v1/messages", raw) == {}


def test_json_array_reply_is_observed_per_element_and_bounded():
    chunk = {"candidates": [{"content": {"parts": [{"functionCall": {"name": "late"}}]}}]}
    raw = json.dumps([{"candidates": []}] * 500 + [chunk])
    out = observe_reply("generativelanguage.googleapis.com",
                        "/v1beta/models/gemini-2.0-flash:streamGenerateContent", raw)
    assert "tools" not in out  # elements past the bound are not read
    assert observe_reply("h", "/p", json.dumps([1, "x"])) == {}


def test_long_sse_without_model_stops_catalog_matching(monkeypatch):
    import byoai.integrations.shield_proxy as sp

    calls = []
    real = sp._catalog()

    class _Spy:
        def match(self, *a):
            calls.append(1)
            return real.match(*a)

    monkeypatch.setattr(sp, "_catalog", lambda: _Spy())
    raw = "".join('data: {"type": "ping"}\n\n' for _ in range(200))
    sp.observe_reply("api.anthropic.com", "/v1/messages", raw)
    assert len(calls) <= 3 * sp.MODEL_SCAN_EVENTS


def test_hostile_names_and_shapes_never_raise_or_leak():
    body = json.dumps({"content": [
        {"type": "tool_use", "name": "x" * 200}, {"type": "tool_use", "name": "bad name!"},
        {"type": "tool_use", "name": 7}, "junk", None,
        *({"type": "tool_use", "name": f"t{i}"} for i in range(40)),
    ]})
    out = observe_reply("api.anthropic.com", "/v1/messages", body)
    assert out["tools"] == ["unnamed_tool", *(f"t{i}" for i in range(30)), "tools_truncated"][:32]
    for junk in (None, 5, [], {}, "x"):
        assert signature_fields(None, None, junk) == {"provider": "unknown", "deployment": "unknown"}
        assert observe_reply("h", "/p", junk) == {}  # type: ignore[arg-type]


def test_a_denied_request_row_keeps_provider_but_no_model_leak(proxy):
    body = {"model": "gpt-4o", "messages": [{"role": "user", "content": "use AKIAIOSFODNN7EXAMPLE now"}]}
    flow = _Flow("api.openai.com", "/v1/chat/completions", json.dumps(body))
    _enable(proxy, mode="block", apps={a: True for a in COVERED_APPS})
    proxy.request(flow)
    (row,) = _rows(proxy)
    assert row["kind"] == "desktop.verdict.denied"
    assert row["provider"] == "openai" and row["model"] == "gpt-4o"
    assert "AKIA" not in json.dumps(row)


def test_signature_paths_are_a_subset_of_interesting():
    from byoai.integrations.shield_proxy import INTERESTING, SIGNATURE_PATHS

    assert all(p in INTERESTING for p in SIGNATURE_PATHS)
    assert INTERESTING[-len(SIGNATURE_PATHS):] == SIGNATURE_PATHS


def test_known_host_reply_without_model_records_no_model():
    raw = json.dumps({"content": [{"type": "text", "text": "hi"}]})
    assert "model" not in observe_reply("api.anthropic.com", "/v1/messages", raw)


def test_a_hostile_event_keeps_tools_already_collected(monkeypatch):
    import byoai.integrations.shield_proxy as sp

    real = sp._catalog()

    class _Boom:
        def __init__(self):
            self.n = 0

        def match(self, *a):
            self.n += 1
            if self.n > 1:
                raise RuntimeError("hostile")
            return real.match(*a)

    monkeypatch.setattr(sp, "_catalog", lambda: _Boom())
    first = {"content": [{"type": "tool_use", "name": "keep_me"}]}
    raw = "".join(f"data: {json.dumps(e)}\n\n" for e in (first, {"type": "ping"}))
    assert sp.observe_reply("api.anthropic.com", "/v1/messages", raw)["tools"] == ["keep_me"]


def _tools(*blocks, host="api.anthropic.com", path="/v1/messages"):
    return observe_reply(host, path, json.dumps({"content": list(blocks)})).get("tools")


def _use(name):
    return {"type": "tool_use", "name": name}


@pytest.mark.parametrize("name", [
    "Ba sh", "Bash\u200bx", "a" * 48 + "b", " " * 512 + "shell_exec", "x" * 300, "",
])
def test_a_name_is_verbatim_or_the_placeholder_never_rewritten(name):
    assert _tools(_use(name)) == ["unnamed_tool"]


def test_a_name_at_the_limit_is_kept_verbatim():
    assert _tools(_use("a" * 48)) == ["a" * 48]


def test_empty_name_gemini_function_call_is_unnamed():
    body = json.dumps({"candidates": [{"content": {"parts": [{"functionCall": {"name": ""}}]}}]})
    assert observe_reply("generativelanguage.googleapis.com", "/v1beta/models/g:generateContent",
                         body)["tools"] == ["unnamed_tool"]


def test_complete_tool_use_without_name_key_is_unnamed():
    assert _tools({"type": "tool_use"}) == ["unnamed_tool"]


def test_stream_delta_without_a_name_is_skipped():
    delta = {"choices": [{"delta": {"tool_calls": [{"function": {"arguments": "{}"}}]}}]}
    assert observe_reply("api.openai.com", "/v1/chat/completions",
                         "data: " + json.dumps(delta) + "\n\n") == {}


def test_tool_flood_is_marked_truncated():
    tools = _tools(*(_use(f"t{i}") for i in range(40)))
    assert len(tools) == 32 and tools[:31] == [f"t{i}" for i in range(31)]
    assert tools[-1] == "tools_truncated"
