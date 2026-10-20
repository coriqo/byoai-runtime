"""coriqo-mcp: the interposer between an MCP host and an MCP server."""

from __future__ import annotations

import asyncio
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, cast

import httpx
import pytest

from byoai.integrations.coriqo_mcp import (
    DENIAL_RESULT,
    HttpInterposer,
    Interposer,
    _StdioSession,
    arguments_sha256,
    run_stdio,
)
from byoai.recorder.canonical import canonicalize, sha256_hex
from byoai.recorder.denial_latch import denial_latch
from byoai.recorder.ledger import Ledger
from byoai.recorder.mandate import MODEL_MESSAGE, MandateGate
from byoai.recorder.mandate_file import load_mandate_text
from byoai.recorder.verdicts import VerdictRecorder, use_verdict_recorder

REPO = Path(__file__).resolve().parents[2]
ECHO = str(REPO / "tests" / "_mcp_echo_server.py")
SDK_SERVER = str(REPO / "tests" / "_mcp_tools_server.py")
FIXTURES = REPO / "tests" / "fixtures" / "coriqo_mcp"
ENFORCE = FIXTURES / "enforce.mandate.yaml"
SHADOW = FIXTURES / "shadow.mandate.yaml"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv("BYOAI_MANDATE_ENVIRONMENT", raising=False)
    denial_latch().reset()
    yield
    denial_latch().reset()


def file_gate(path: Path) -> MandateGate:
    loaded = load_mandate_text(path.read_text(), path=path)

    async def same(_etag):
        return None, loaded.sha256

    gate = MandateGate(same, agent_id=loaded.agent_name)
    gate.apply_snapshot(loaded.payload(), etag=loaded.sha256)
    return gate


def call(tool: str, msg_id: int | str | None = 1, **arguments) -> dict:
    msg = {"jsonrpc": "2.0", "method": "tools/call",
           "params": {"name": tool, "arguments": arguments}}
    if msg_id is not None:
        msg["id"] = msg_id
    return msg


def env_with_src() -> dict[str, str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [str(REPO / "src"), str(REPO), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    return env


# -- the decision ------------------------------------------------------------


def test_refused_call_is_answered_with_the_fixed_sentence_only():
    interposer = Interposer(file_gate(ENFORCE))
    forward, reply = interposer.gate_request(call("delete_account", 7, account="A-1"))
    assert forward is False
    assert reply == {"jsonrpc": "2.0", "id": 7, "result": DENIAL_RESULT}
    text = json.dumps(reply)
    assert MODEL_MESSAGE in text
    assert "delete_account" not in text and "prohibited" not in text


def test_allowed_call_and_other_methods_go_through():
    interposer = Interposer(file_gate(ENFORCE))
    assert interposer.gate_request(call("search", q="x")) == (True, None)
    assert interposer.gate_request({"jsonrpc": "2.0", "id": 2, "method": "resources/list"}) == (
        True, None)


def test_refused_notification_is_dropped_without_a_reply():
    interposer = Interposer(file_gate(ENFORCE))
    assert interposer.gate_request(call("delete_account", None)) == (False, None)


def test_shadow_lets_everything_through():
    interposer = Interposer(file_gate(SHADOW))
    assert interposer.gate_request(call("delete_account", account="A")) == (True, None)


def test_tools_list_is_filtered_under_enforce_only():
    tools = [{"name": n, "inputSchema": {}} for n in ("search", "transfer_funds", "delete_account")]
    msg = {"jsonrpc": "2.0", "id": 3, "result": {"tools": list(tools), "nextCursor": "c"}}
    assert Interposer(file_gate(ENFORCE)).filter_tools(msg) is True
    assert [t["name"] for t in msg["result"]["tools"]] == ["search", "transfer_funds"]
    assert msg["result"]["nextCursor"] == "c"
    shadow = {"jsonrpc": "2.0", "id": 3, "result": {"tools": list(tools)}}
    assert Interposer(file_gate(SHADOW)).filter_tools(shadow) is False
    assert len(shadow["result"]["tools"]) == 3


def test_decision_and_arguments_hash_reach_the_ledger(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db", "device-test")
    recorder = VerdictRecorder(ledger=ledger, session_id="coriqo-mcp")
    interposer = Interposer(file_gate(ENFORCE), run_id="mcp-run-1")
    with use_verdict_recorder(recorder):
        interposer.gate_request(call("search", q="balance"))
        interposer.gate_request(call("delete_account", account="A-1"))
    rows = [e.event.payload for e in ledger.iter_entries()]
    ledger.close()
    assert [(r["tool"], r["verdict"]) for r in rows] == [
        ("search", "allowed"), ("delete_account", "blocked")]
    assert rows[0]["arguments_sha256"] == sha256_hex(canonicalize({"q": "balance"}))
    assert rows[1]["arguments_sha256"] == arguments_sha256({"account": "A-1"})
    assert rows[1]["run_id"] == "mcp-run-1"
    assert [r["step_index"] for r in rows] == [0, 1]
    # The hash, never the arguments.
    assert "A-1" not in json.dumps(rows)
    assert rows[1]["mandate_version_id"].startswith("sha256:")


def test_arguments_hash_handles_absent_and_odd_arguments():
    assert arguments_sha256(None) == arguments_sha256({})
    assert arguments_sha256({"b": 1, "a": 2}) == arguments_sha256({"a": 2, "b": 1})
    assert arguments_sha256({"a": 1}).startswith("sha256:")


# -- stdio framing -----------------------------------------------------------


def test_unreadable_line_is_answered_and_never_forwarded():
    out: list[bytes] = []
    session = _StdioSession(Interposer(file_gate(ENFORCE)), out.append)
    assert session.from_host(b'{"method": "tools/call", NaN}\n') is None
    assert session.from_host(b'{"jsonrpc":"2.0","id":1,"method":"tools/call","x":NaN}\n') is None
    assert all(json.loads(o)["error"]["code"] == -32700 for o in out)


def test_forwarded_message_is_the_gated_one_reserialised():
    out: list[bytes] = []
    session = _StdioSession(Interposer(file_gate(ENFORCE)), out.append)
    raw = b'{"jsonrpc": "2.0", "id": 1, "method": "tools/call",   "params": {"name": "search"}}\n'
    forwarded = session.from_host(raw)
    assert forwarded is not None and forwarded != raw
    assert json.loads(forwarded) == json.loads(raw)


def test_batch_splits_refused_from_forwarded():
    out: list[bytes] = []
    session = _StdioSession(Interposer(file_gate(ENFORCE)), out.append)
    batch = [call("search", 1), call("delete_account", 2), {"jsonrpc": "2.0", "id": 3,
                                                            "method": "tools/list"}]
    forwarded = session.from_host(json.dumps(batch).encode())
    assert forwarded is not None
    assert [m["id"] for m in json.loads(forwarded)] == [1, 3]
    assert json.loads(out[0]) == [{"jsonrpc": "2.0", "id": 2, "result": DENIAL_RESULT}]
    answer = {"jsonrpc": "2.0", "id": 3, "result": {"tools": [{"name": "delete_account"},
                                                               {"name": "search"}]}}
    filtered = json.loads(session.from_server(json.dumps(answer).encode() + b"\n"))
    assert [t["name"] for t in filtered["result"]["tools"]] == ["search"]


def test_only_answers_to_tools_list_are_filtered():
    session = _StdioSession(Interposer(file_gate(ENFORCE)), lambda _b: None)
    session.from_host(b'{"jsonrpc":"2.0","id":"a","method":"tools/list"}')
    other = json.dumps({"jsonrpc": "2.0", "id": 9,
                        "result": {"tools": [{"name": "delete_account"}]}}).encode()
    assert session.from_server(other) == other


# -- stdio, end to end -------------------------------------------------------


async def test_run_stdio_relays_and_refuses(tmp_path, monkeypatch):
    ran = tmp_path / "ran.txt"
    monkeypatch.setenv("ECHO_SERVER_LOG", str(ran))
    queue: asyncio.Queue[bytes | None] = asyncio.Queue()
    out: list[bytes] = []
    for msg in (
        {"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        call("search", 2, q="x"),
        call("delete_account", 3, account="A"),
    ):
        queue.put_nowait(json.dumps(msg).encode() + b"\n")
    queue.put_nowait(None)
    code = await run_stdio([sys.executable, ECHO], Interposer(file_gate(ENFORCE)),
                           stdin_queue=queue, write_host=out.append, grace_s=5)
    assert code == 0
    replies = {m["id"]: m for m in (json.loads(o) for o in out)}
    assert [t["name"] for t in replies[1]["result"]["tools"]] == ["search", "transfer_funds"]
    assert replies[2]["result"]["isError"] is False
    assert replies[3]["result"] == DENIAL_RESULT
    assert ran.read_text().split() == ["search"]  # the refused call never arrived


def _cli(*args: str) -> list[str]:
    return [sys.executable, "-m", "byoai.integrations.coriqo_mcp", *args]


def test_cli_stdio_records_signed_ledger(tmp_path):
    recorder_dir = tmp_path / "rec"
    lines = [
        {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        call("transfer_funds", 2, amount=5),
        call("delete_account", 3, account="A"),
    ]
    proc = subprocess.run(
        _cli("--mandate", str(ENFORCE), "--recorder-dir", str(recorder_dir), "--",
             sys.executable, ECHO),
        input="".join(json.dumps(m) + "\n" for m in lines).encode(),
        capture_output=True, env=env_with_src(), timeout=60,
    )
    assert proc.returncode == 0, proc.stderr.decode()
    replies = {m["id"]: m for m in map(json.loads, proc.stdout.decode().splitlines())}
    assert replies[3]["result"] == DENIAL_RESULT
    assert "enforce" in proc.stderr.decode()
    ledger = Ledger(recorder_dir / "ledger.db", "reader")
    try:
        verdicts = [e.event.payload for e in ledger.iter_entries()
                    if e.event.kind == "mandate_verdict"]
        checkpoints = ledger.iter_checkpoints()
    finally:
        ledger.close()
    assert [(v["tool"], v["verdict"]) for v in verdicts] == [
        ("transfer_funds", "allowed"), ("delete_account", "blocked")]
    assert all(v["arguments_sha256"].startswith("sha256:") for v in verdicts)
    assert verdicts[0]["arguments_sha256"] == arguments_sha256({"amount": 5})
    # Shutdown flushes a device-signed checkpoint over the verdicts.
    assert checkpoints and checkpoints[-1].get("sig")
    assert checkpoints[-1]["seq_end"] >= 2


def test_cli_refuses_a_broken_mandate(tmp_path):
    bad = tmp_path / "m.yaml"
    bad.write_text("spec: coriqo.mandate/v1\nagent: {name: x}\nmode: maybe\n")
    proc = subprocess.run(_cli("--mandate", str(bad), "--no-record", "--", sys.executable, ECHO),
                          capture_output=True, env=env_with_src(), timeout=30)
    assert proc.returncode == 2
    assert b"mode" in proc.stderr


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX")
def test_sigterm_stops_the_child_too(tmp_path):
    pid_file = tmp_path / "pid"
    env = env_with_src()
    env["ECHO_SERVER_PID"] = str(pid_file)
    proc = subprocess.Popen(
        _cli("--mandate", str(SHADOW), "--no-record", "--grace", "1", "--",
             sys.executable, ECHO),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    )
    try:
        deadline = time.monotonic() + 20
        while not pid_file.exists() or not pid_file.read_text():
            assert time.monotonic() < deadline, "server never started"
            time.sleep(0.05)
        child = int(pid_file.read_text())
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=20)
        deadline = time.monotonic() + 10
        while True:
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                break
            assert time.monotonic() < deadline, "the server outlived coriqo-mcp"
            time.sleep(0.05)
    finally:
        if proc.poll() is None:
            proc.kill()


def _is_error(result) -> bool | None:
    # SDK 2.x names it is_error; 1.x isError.
    return getattr(result, "is_error", getattr(result, "isError", None))


def _texts(result) -> list[str | None]:
    # Only text content is expected back; anything else reads as None.
    return [getattr(c, "text", None) for c in result.content]


async def test_real_sdk_client_and_server_through_coriqo_mcp():
    pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "byoai.integrations.coriqo_mcp", "--mandate", str(ENFORCE),
              "--no-record", "--", sys.executable, SDK_SERVER],
        env=env_with_src(),
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        listed = await session.list_tools()
        assert sorted(t.name for t in listed.tools) == ["search", "transfer_funds"]
        ok = await session.call_tool("search", {"query": "fees"})
        assert _is_error(ok) is False
        assert "results for fees" in (_texts(ok)[0] or "")
        refused = await session.call_tool("delete_account", {"account": "A-1"})
        assert _is_error(refused) is True
        assert _texts(refused) == [MODEL_MESSAGE]


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def test_real_sdk_over_http_through_coriqo_mcp():
    pytest.importorskip("mcp")
    pytest.importorskip("uvicorn")
    from mcp import ClientSession
    from mcp.client.streamable_http import streamable_http_client

    front, back = _free_port(), _free_port()
    proc = subprocess.Popen(  # noqa: ASYNC220 - started once, before the client runs
        _cli("--mandate", str(ENFORCE), "--no-record", "--http",
             "--listen", f"127.0.0.1:{front}", "--upstream", f"http://127.0.0.1:{back}",
             "--grace", "2", "--", sys.executable, SDK_SERVER, "--http", str(back)),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env_with_src(),
    )
    try:
        async with httpx.AsyncClient() as http:
            for _ in range(100):
                try:
                    await http.post(f"http://127.0.0.1:{back}/mcp", content=b"{}", timeout=0.2)
                    await http.get(f"http://127.0.0.1:{front}/", timeout=0.2)
                    break
                except httpx.HTTPError:
                    await asyncio.sleep(0.1)
            else:
                pytest.fail("servers did not start")
        url = f"http://127.0.0.1:{front}/mcp"
        async with streamable_http_client(url) as streams:
            read, write = streams[0], streams[1]
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                assert sorted(t.name for t in listed.tools) == ["search", "transfer_funds"]
                ok = await session.call_tool("search", {"query": "fees"})
                assert _is_error(ok) is False
                refused = await session.call_tool("delete_account", {"account": "A-1"})
                assert _is_error(refused) is True
                assert _texts(refused) == [MODEL_MESSAGE]
    finally:
        proc.send_signal(signal.SIGTERM)
        try:
            await asyncio.to_thread(proc.wait, 20)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proc.kill()


# -- HTTP --------------------------------------------------------------------


class Upstream:
    """A stand-in MCP HTTP server that answers JSON or SSE, and remembers what
    reached it."""

    def __init__(self, mode: str = "json") -> None:
        self.mode = mode
        self.seen: list[dict] = []

    async def __call__(self, scope, receive, send):
        assert scope["type"] == "http"
        body = b""
        while True:
            m = await receive()
            body += m.get("body", b"")
            if not m.get("more_body"):
                break
        msg = json.loads(body) if body else None
        if msg is not None:
            self.seen.append(msg)
        if isinstance(msg, dict) and "id" not in msg:
            await send({"type": "http.response.start", "status": 202, "headers": []})
            await send({"type": "http.response.body", "body": b""})
            return
        tools = [{"name": n} for n in ("search", "transfer_funds", "delete_account")]
        method = msg.get("method") if isinstance(msg, dict) else None
        result = {"tools": tools} if method == "tools/list" else {"content": [], "isError": False}
        answer = {"jsonrpc": "2.0", "id": msg.get("id") if isinstance(msg, dict) else None,
                  "result": result}
        if self.mode == "sse":
            data = (b"event: message\r\nid: 1\r\ndata: " + json.dumps(answer).encode()
                    + b"\r\n\r\n")
            headers = [(b"content-type", b"text/event-stream"), (b"mcp-session-id", b"s1")]
        else:
            data = json.dumps(answer).encode()
            headers = [(b"content-type", b"application/json"), (b"mcp-session-id", b"s1")]
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        await send({"type": "http.response.body", "body": data})


def http_pair(mode: str = "json", mandate: Path = ENFORCE):
    upstream = Upstream(mode)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream))
    app = HttpInterposer(Interposer(file_gate(mandate)), "http://upstream.test", client=client)
    front = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=cast(Any, app)), base_url="http://front"
    )
    return upstream, front


@pytest.mark.parametrize("mode", ["json", "sse"])
async def test_http_filters_tools_list(mode):
    upstream, front = http_pair(mode)
    async with front:
        r = await front.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                             headers={"accept": "application/json, text/event-stream"})
    assert r.status_code == 200
    assert r.headers["mcp-session-id"] == "s1"
    if mode == "sse":
        data = next(ln for ln in r.text.splitlines() if ln.startswith("data:"))
        body = json.loads(data[5:])
        assert "id: 1" in r.text
    else:
        body = r.json()
    assert [t["name"] for t in body["result"]["tools"]] == ["search", "transfer_funds"]


async def test_http_refused_call_never_reaches_upstream():
    upstream, front = http_pair()
    async with front:
        r = await front.post("/mcp", json=call("delete_account", 5, account="A"))
    assert r.status_code == 200
    assert r.json() == {"jsonrpc": "2.0", "id": 5, "result": DENIAL_RESULT}
    assert upstream.seen == []


async def test_http_allowed_call_is_relayed():
    upstream, front = http_pair()
    async with front:
        r = await front.post("/mcp", json=call("search", 6, q="x"))
    assert r.json()["result"]["isError"] is False
    assert upstream.seen[0]["params"]["name"] == "search"


@pytest.mark.parametrize("mode", ["json", "sse"])
async def test_http_batch_mixes_refusals_into_the_answer(mode):
    upstream, front = http_pair(mode)
    async with front:
        r = await front.post("/mcp", json=[call("delete_account", 1), call("search", 2)])
    assert [m["params"]["name"] for m in upstream.seen[0]] == ["search"]
    assert "delete_account" not in r.text
    assert MODEL_MESSAGE in r.text


async def test_http_refuses_what_it_cannot_read():
    upstream, front = http_pair()
    async with front:
        bad = await front.post("/mcp", content=b"{not json",
                               headers={"content-type": "application/json"})
        gz = await front.post("/mcp", content=b"\x1f\x8b...",
                              headers={"content-encoding": "gzip"})
    assert bad.status_code == 400
    assert gz.status_code == 415
    assert upstream.seen == []


async def test_http_gates_a_body_on_any_method():
    upstream, front = http_pair()
    async with front:
        r = await front.request("PUT", "/mcp", json=call("delete_account", 7))
    assert r.json() == {"jsonrpc": "2.0", "id": 7, "result": DENIAL_RESULT}
    assert upstream.seen == []


async def test_http_refuses_a_path_that_could_change_the_upstream_host():
    upstream, _ = http_pair()
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=upstream))
    app = HttpInterposer(Interposer(file_gate(ENFORCE)), "http://upstream.test", client=client)
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {"type": "http", "method": "GET", "path": "@evil.test/mcp",
             "raw_path": b"@evil.test/mcp", "query_string": b"", "headers": []}
    await app(scope, receive, send)
    await client.aclose()
    assert sent[0]["status"] == 400
    assert upstream.seen == []


async def test_http_shadow_changes_nothing():
    upstream, front = http_pair(mandate=SHADOW)
    async with front:
        listed = await front.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        called = await front.post("/mcp", json=call("delete_account", 2))
    assert len(listed.json()["result"]["tools"]) == 3
    assert called.json()["result"]["isError"] is False
    assert len(upstream.seen) == 2


# -- sending decisions to Coriqo ---------------------------------------------


async def test_record_drains_the_outbox_on_close(tmp_path):
    from byoai.integrations.coriqo_mcp import _Record

    class FakeShipper:
        def __init__(self) -> None:
            self.pending = 2

        async def ship_once(self):
            if not self.pending:
                return None
            self.pending -= 1
            return object()

    class FakeRecorder:
        closed = False

        def close(self) -> None:
            FakeRecorder.closed = True

    shipper = FakeShipper()
    record = _Record(FakeRecorder(), None, shipper)
    record.start()
    await record.close()
    assert shipper.pending == 0
    assert FakeRecorder.closed


def test_unenrolled_device_keeps_decisions_local(tmp_path, capsys, monkeypatch):
    import argparse

    from byoai.integrations.coriqo_mcp import _build_recorder

    monkeypatch.delenv("BYOAI_CORIQO_API_KEY", raising=False)
    monkeypatch.delenv("BYOAI_CORIQO_URL", raising=False)
    args = argparse.Namespace(no_record=False, recorder_dir=str(tmp_path / "rec"))
    record = _build_recorder(args, "agt_123")
    assert record is not None
    try:
        assert record.shipping is False
    finally:
        record.recorder.close()
    assert "enroll this device" in capsys.readouterr().err


def test_coriqo_agent_id_comes_from_the_file_agent_id_only(tmp_path):
    import argparse

    from byoai.integrations.coriqo_mcp import _build_gate

    named = argparse.Namespace(mandate=str(ENFORCE), coriqo_agent_id=None, environment=None)
    assert _build_gate(named)[2] is None
    with_id = tmp_path / "m.yaml"
    with_id.write_text(ENFORCE.read_text().replace(
        "  name: payments-assistant", "  name: payments-assistant\n  id: agt_42"))
    gate, _, agent_id = _build_gate(argparse.Namespace(
        mandate=str(with_id), coriqo_agent_id=None, environment=None))
    assert agent_id == "agt_42" and gate.agent_id == "agt_42"


def test_tools_call_without_a_readable_name_is_refused():
    interposer = Interposer(file_gate(SHADOW))
    forward, reply = interposer.gate_request(
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": ["search"]}})
    assert forward is False
    assert reply is not None and reply["error"]["code"] == -32602


def test_a_reused_tools_list_id_is_filtered_each_time():
    session = _StdioSession(Interposer(file_gate(ENFORCE)), lambda _b: None)
    for _ in range(2):
        session.from_host(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    answer = json.dumps({"jsonrpc": "2.0", "id": 1,
                         "result": {"tools": [{"name": "delete_account"}]}}).encode()
    for _ in range(2):
        assert json.loads(session.from_server(answer))["result"]["tools"] == []
    assert session.from_server(answer) == answer  # nothing pending any more


def test_escaped_key_is_still_filtered():
    session = _StdioSession(Interposer(file_gate(ENFORCE)), lambda _b: None)
    session.from_host(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
    escaped = b'{"jsonrpc":"2.0","id":1,"result":{"\\u0074ools":[{"name":"delete_account"}]}}'
    assert json.loads(session.from_server(escaped))["result"]["tools"] == []


async def test_http_session_ids_the_server_never_issued_share_one_run():
    upstream, front = http_pair(mandate=FIXTURES / "halt.mandate.yaml")
    async with front:
        first = await front.post("/mcp", json=call("delete_account", 1),
                                 headers={"mcp-session-id": "made-up-1"})
        second = await front.post("/mcp", json=call("search", 2),
                                  headers={"mcp-session-id": "made-up-2"})
    assert first.json()["result"] == DENIAL_RESULT
    # deny_and_halt_run ended the run; a new invented session id is not a new run.
    assert second.json()["result"] == DENIAL_RESULT
    assert upstream.seen == []
