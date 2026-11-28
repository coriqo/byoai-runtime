"""U2.2: MCP JSON-RPC detection in captured HTTP bodies."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from byoai.integrations.shield_mcp_detect import MAX_BODY_BYTES, detect_mcp

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests" / "fixtures" / "mcp_detect"
SCHEMA = ROOT / "src" / "byoai" / "shield_envelope.schema.json"


def _fx(name: str) -> bytes:
    return (FIX / name).read_bytes()


@pytest.fixture(scope="module")
def validator():
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text()))


def _calls(rows):
    return [r for r in rows if r["ai_event_type"] == "ai.tool_call.requested"]


def test_tools_call_request_is_requested_never_executed(validator):
    d = detect_mcp(_fx("call_request.json"), "request", "application/json", host="Mcp.Example.com")
    [row] = d.rows
    validator.validate(row)
    assert row["evidence_level"] == "observed_requested"
    assert row["tool"] == {"status": "requested", "name": "read_file", "call_id": "7",
                           "destination": "mcp.example.com"}
    assert row["collector"] == "desktop_proxy"
    assert "executed" not in json.dumps(row)
    assert "passwords" not in json.dumps(row)  # arguments never copied


def test_tools_list_request_and_result(validator):
    pending: dict = {}
    d = detect_mcp(_fx("list_request.json"), "request", "application/json", pending=pending)
    assert d.methods == ["tools/list"]
    for r in d.rows:
        validator.validate(r)
        assert r["ai_event_type"] == "ai.app.visited"
    d2 = detect_mcp(_fx("list_result.json"), "response", "application/json", pending=pending)
    assert d2.methods == ["tools/list"]
    assert d2.tool_names == ["read_file", "write_file"]
    assert pending == {}
    assert not _calls(d2.rows)


def test_batch_request(validator):
    d = detect_mcp(_fx("batch_request.json"), "request", "application/json")
    names = [r["tool"]["name"] for r in _calls(d.rows)]
    assert names == ["search", "fetch_url"]
    for r in d.rows:
        validator.validate(r)


def test_sse_result_correlates_by_id():
    pending: dict = {}
    detect_mcp(_fx("call_request.json"), "request", "application/json", pending=pending)
    assert len(pending) == 1
    d = detect_mcp(_fx("call_result.sse"), "response", "text/event-stream", pending=pending)
    assert d.correlated == [{"call_id": "7", "method": "tools/call", "tool": "read_file",
                             "is_error": False}]
    assert pending == {}
    assert not d.rows  # a result is not a new request, and the schema has no proxy result row


def test_sse_crlf_framing():
    sse = (b'event: message\r\ndata: {"jsonrpc":"2.0","id":3,\r\n'
           b'data: "method":"tools/call","params":{"name":"x"}}\r\n\r\n')
    d = detect_mcp(sse, "request", "text/event-stream")
    assert [r["tool"]["name"] for r in d.rows] == ["x"]


def test_error_result_is_flagged():
    pending: dict = {}
    detect_mcp(b'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"x"}}',
               "request", None, pending=pending)
    err = b'{"jsonrpc":"2.0","id":3,"error":{"code":-1,"message":"boom"}}'
    d = detect_mcp(err, "response", "application/json", pending=pending)
    assert d.correlated[0]["is_error"] is True


def test_string_and_int_ids_do_not_collide():
    pending: dict = {}
    detect_mcp(b'{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"a"}}',
               "request", None, pending=pending)
    d = detect_mcp(b'{"jsonrpc":"2.0","id":1,"result":{}}', "response", None, pending=pending)
    assert d.correlated == [] and len(pending) == 1


@pytest.mark.parametrize("body", [b"", b"null", b"[]", b'"x"',
                                  b'{"jsonrpc":"1.0","method":"tools/call"}',
                                  b'{"jsonrpc":"2.0","method":"tools/call","params":[]}',
                                  12345, None])
def test_malformed_never_raises_and_yields_nothing(body):
    assert detect_mcp(body, "request", "application/json").rows == []


def test_bad_tool_name_and_id_are_omitted(validator):
    body = b'{"jsonrpc":"2.0","id":"a b","method":"tools/call","params":{"name":"has space"}}'
    [row] = detect_mcp(body, "request", None).rows
    validator.validate(row)
    assert row["tool"] == {"status": "requested"}


def test_oversized_is_unobservable(validator):
    big = (b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"a","x":"'
           + b"a" * MAX_BODY_BYTES + b'"}}')
    d = detect_mcp(big, "request", "application/json", host="mcp.example.com")
    [row] = d.rows
    validator.validate(row)
    assert row["evidence_level"] == "unobservable_payload"
    assert row["ai_event_type"] == "ai.app.discovered"
    assert row["target"] == "mcp.example.com"


@pytest.mark.parametrize("kw", [{"encrypted": True}, {"content_type": "application/octet-stream"},
                                {"content_encoding": "br"}])
def test_encrypted_and_unsupported_streams_are_unobservable(validator, kw):
    kw = {"content_type": "application/json", **kw}
    d = detect_mcp(_fx("call_request.json"), "request", host="h.example", **kw)
    [row] = d.rows
    validator.validate(row)
    assert row["evidence_level"] == "unobservable_payload"
    assert "tool" not in row


def test_pending_is_bounded():
    pending: dict = {}
    for i in range(2000):
        body = json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                           "params": {"name": "t"}}).encode()
        detect_mcp(body, "request", None, pending=pending)
    assert len(pending) <= 1024


def test_batch_is_capped():
    msg = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "t"}}
    d = detect_mcp(json.dumps([dict(msg, id=i) for i in range(500)]).encode(), "request", None)
    assert len(d.rows) <= 100


@pytest.mark.parametrize("body", [b"{", b"[1,2", b"\xff\xfe", b"data: {oops\n\n"])
def test_malformed_or_non_utf8_is_unobservable(validator, body):
    [row] = detect_mcp(body, "request", None, host="h.example").rows
    validator.validate(row)
    assert row["evidence_level"] == "unobservable_payload"
    assert "tool" not in row


@pytest.mark.parametrize("method", ["tools/call", "tools/list"])
def test_server_to_client_method_is_not_a_client_request(method):
    pending: dict = {}
    body = json.dumps({"jsonrpc": "2.0", "id": 5, "method": method,
                       "params": {"name": "x"}}).encode()
    d = detect_mcp(body, "response", "application/json", pending=pending)
    assert d.rows == [] and d.methods == [] and pending == {}


def test_reinserted_pending_key_moves_to_end():
    pending: dict = {}

    def call(i):
        detect_mcp(json.dumps({"jsonrpc": "2.0", "id": i, "method": "tools/call",
                               "params": {"name": "t"}}).encode(), "request", None,
                   pending=pending)
    for i in range(1024):
        call(i)
    call(0)  # re-issued: now newest
    call(5000)  # evicts the oldest, which must be id 1, not the fresh id 0
    assert ("int", "0") in pending and ("int", "1") not in pending


def test_result_in_request_direction_never_touches_pending():
    pending: dict = {}
    call = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}'
    detect_mcp(call, "request", None, pending=pending)
    # client answers a server-initiated request that reuses id 1
    reply = b'{"jsonrpc":"2.0","id":1,"result":{"isError":true}}'
    d = detect_mcp(reply, "request", None, pending=pending)
    assert d.correlated == [] and list(pending) == [("int", "1")]
    real = b'{"jsonrpc":"2.0","id":1,"result":{}}'
    d2 = detect_mcp(real, "response", None, pending=pending)
    assert d2.correlated == [
        {"call_id": "1", "method": "tools/call", "tool": "x", "is_error": False}
    ]
    assert pending == {}
