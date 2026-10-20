"""``coriqo-mcp``: put a mandate gate in front of any MCP server.

::

    coriqo-mcp --mandate coriqo.mandate.yaml -- node server.js
    coriqo-mcp --mandate coriqo.mandate.yaml --http --upstream http://127.0.0.1:9000

The MCP host (Claude Desktop, an agent framework, your own client) starts
``coriqo-mcp`` where it would have started the server. ``coriqo-mcp`` starts
the server as its own child process and sits on the pipe between them:

- every ``tools/call`` is decided by :class:`~byoai.recorder.mandate.MandateGate`
  against the mandate held in memory, with the same denial latch the other
  seams use;
- the decision, and a SHA-256 of the call's arguments, go to the device-signed
  ledger (``byoai.recorder``), which ships to Coriqo when the device is
  enrolled;
- a refused call is answered here, with the one fixed sentence
  (:data:`~byoai.recorder.mandate.MODEL_MESSAGE`) as an error result, and never
  reaches the server;
- under ``enforce``, a ``tools/list`` answer is cut down to the tools the
  mandate allows, so the model is not shown a tool it may not call.

Nothing on this path calls Coriqo. The mandate is a local file (or a cached
snapshot fetched in the background), and the decision reads memory.

``shadow`` (the mandate file's default) changes nothing the host or the server
sees: every call goes through and every call is recorded, with the ones outside
the mandate flagged. ``enforce`` refuses them, as the file's ``on_violation``
says.

What is checked, and what is not, is listed in the README. In short: tool
calls and tool listings are; resources, prompts, sampling and the content of a
tool's result are not.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import importlib
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Awaitable, Callable, Iterable, Sequence
from typing import Any, cast
from urllib.parse import urlsplit

from ..recorder.canonical import canonicalize, sha256_hex
from ..recorder.mandate import MODEL_MESSAGE, MandateError, MandateGate
from ..recorder.proxy_gate import ProxyDecision, ProxyEnforcer
from ..recorder.suspend import SuspendHook, SuspendNotice, WorkerAck, WorkerOutcome, utc_now

__all__ = [
    "DENIAL_RESULT",
    "EXIT_SUSPENDED",
    "ChildStopper",
    "HttpInterposer",
    "Interposer",
    "arguments_sha256",
    "main",
    "run_stdio",
]

log = logging.getLogger("byoai.coriqo_mcp")

#: The result a refused ``tools/call`` gets. An MCP tool error (``isError``)
#: carrying the same fixed sentence every other seam uses, and nothing else:
#: not the tool, not the mandate, not why.
DENIAL_RESULT: dict[str, Any] = {
    "content": [{"type": "text", "text": MODEL_MESSAGE}],
    "isError": True,
}

#: Longest single message accepted from the server on stdio. MCP messages are
#: one JSON document per line, and a tool result can be large.
MAX_LINE_BYTES = 64 * 1024 * 1024

#: Runs (MCP sessions) whose step counters are kept, oldest dropped first.
_MAX_RUNS = 1024

#: How long the child gets to exit after its stdin closes, and again after
#: SIGTERM, before it is killed.
DEFAULT_GRACE_S = 5.0

#: Longest grace period a mandate file's ``x-stop_grace_s`` may set.
MAX_GRACE_S = 600.0

#: Exit status when coriqo-mcp stopped (or never started) the server because
#: the agent is suspended in Coriqo.
EXIT_SUSPENDED = 3


class _BadJson(ValueError):
    pass


def _reject_constant(name: str) -> Any:
    # NaN and the infinities are not JSON. Python accepts them by default; a
    # server's parser may not, and arguments carrying one cannot be hashed.
    raise _BadJson(f"{name} is not valid JSON")


def parse_message(raw: bytes | str) -> Any:
    """A JSON-RPC message (object) or batch (array). Raises ``ValueError``."""
    try:
        value = json.loads(raw, parse_constant=_reject_constant)
    except (_BadJson, ValueError, RecursionError) as exc:
        raise ValueError(str(exc)) from exc
    if not isinstance(value, (dict, list)):
        raise ValueError("a JSON-RPC message is an object or an array")
    return value


def dump_message(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def arguments_sha256(arguments: Any) -> str:
    """SHA-256 of the RFC 8785 canonical JSON of a call's ``arguments``.

    Absent arguments hash as ``{}``. Anything canonical JSON cannot represent
    falls back to sorted-key ``json.dumps``, prefixed so the two can never be
    confused for one another.
    """
    value = {} if arguments is None else arguments
    try:
        return sha256_hex(canonicalize(value))
    except Exception:  # noqa: BLE001 - a hash must never fail a call
        fallback = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
        return "py:" + hashlib.sha256(fallback.encode("utf-8")).hexdigest()


def _checkable_arguments(arguments: Any) -> bool:
    """True when a call's ``arguments`` are absent or an object canonical JSON
    can represent, so the gate can read and hash them without raising."""
    if arguments is None:
        return True
    if not isinstance(arguments, dict):
        return False
    try:
        canonicalize(arguments)
    except Exception:  # noqa: BLE001 - any failure means the gate cannot read it
        return False
    return True


def _id_key(message_id: Any) -> str:
    # 1 and "1" are different JSON-RPC ids.
    return json.dumps(message_id, sort_keys=True)


def _is_request(msg: Any, method: str) -> bool:
    return isinstance(msg, dict) and msg.get("method") == method


def _is_response(msg: Any) -> bool:
    return isinstance(msg, dict) and "method" not in msg and "id" in msg


def parse_error(message: str = "Parse error") -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": message}}


class Interposer:
    """The transport-free part: what to do with one MCP message.

    One per ``coriqo-mcp`` process. A run, for the denial latch and the step
    count, is the stdio connection, or the MCP session on HTTP.
    """

    def __init__(self, gate: MandateGate, *, run_id: str | None = None) -> None:
        self.gate = gate
        self._default_run = run_id or f"mcp-{uuid.uuid4().hex[:16]}"
        self._steps: OrderedDict[str, int] = OrderedDict()
        self._lock = threading.Lock()

    def run_id(self, session: str | None = None) -> str:
        return f"mcp-session-{session}" if session else self._default_run

    def _next_step(self, run_id: str) -> int:
        with self._lock:
            step = self._steps.pop(run_id, 0)
            self._steps[run_id] = step + 1
            while len(self._steps) > _MAX_RUNS:
                self._steps.popitem(last=False)
            return step

    # -- host -> server ----------------------------------------------------

    def decide_call(self, msg: dict[str, Any], *, session: str | None = None) -> ProxyDecision:
        """Decide one ``tools/call`` request and record the decision."""
        raw_params = msg.get("params")
        params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
        name = params.get("name")
        tool = name if isinstance(name, str) else ""
        raw_args = params.get("arguments")
        run_id = self.run_id(session)
        enforcer = ProxyEnforcer(self.gate, run_id=run_id)
        return enforcer.decide(
            tool,
            arguments=raw_args if isinstance(raw_args, dict) else None,
            step_index=self._next_step(run_id),
            arguments_sha256=arguments_sha256(raw_args),
        )

    def gate_request(
        self, msg: Any, *, session: str | None = None
    ) -> tuple[bool, dict[str, Any] | None]:
        """``(forward, reply)`` for one message from the host.

        ``forward`` False means the message stops here. ``reply`` is the
        response to send back to the host instead (``None`` for a refused
        notification, which has no id to answer).
        """
        if not isinstance(msg, dict):
            # A batch element that is not an object (a nested array, a string)
            # is not a JSON-RPC message this side can gate, and a server with
            # a looser parser might still run it. Never forwarded.
            log.warning("coriqo-mcp: refused a message that is not a JSON object")
            return False, {"jsonrpc": "2.0", "id": None,
                           "error": {"code": -32600, "message": "Invalid Request"}}
        if not _is_request(msg, "tools/call"):
            return True, None
        params = msg.get("params")
        if not isinstance(params, dict) or not isinstance(params.get("name"), str):
            # No tool name this side can read is no tool name it can check.
            log.warning("coriqo-mcp: refused a tools/call with no readable tool name")
            return self._invalid_params(msg)
        if not _checkable_arguments(params.get("arguments")):
            # Arguments the gate cannot read (not an object, nested too deep,
            # a lone surrogate) would make the check raise, and a raised check
            # follows the fail-open posture. Refused here instead.
            log.warning("coriqo-mcp: refused a tools/call whose arguments cannot be checked")
            return self._invalid_params(msg)
        decision = self.decide_call(msg, session=session)
        if decision.allowed:
            return True, None
        if "id" not in msg:
            return False, None
        return False, {"jsonrpc": "2.0", "id": msg["id"], "result": dict(DENIAL_RESULT)}

    @staticmethod
    def _invalid_params(msg: dict[str, Any]) -> tuple[bool, dict[str, Any] | None]:
        if "id" not in msg:
            return False, None
        return False, {"jsonrpc": "2.0", "id": msg["id"],
                       "error": {"code": -32602, "message": "Invalid params"}}

    # -- server -> host ----------------------------------------------------

    def filter_tools(self, msg: dict[str, Any]) -> bool:
        """Cut a ``tools/list`` result down to the offered tools, in place.

        Returns True if anything was removed.
        """
        result = msg.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            return False
        tools = result["tools"]
        names = [t.get("name") for t in tools if isinstance(t, dict)]
        offered = set(self.gate.offered_tools(n for n in names if isinstance(n, str)))
        kept = [t for t in tools if isinstance(t, dict) and t.get("name") in offered]
        if len(kept) == len(tools):
            return False
        hidden = len(tools) - len(kept)
        log.info("coriqo-mcp: hid %d tool(s) the mandate does not allow from tools/list", hidden)
        msg["result"] = {**result, "tools": kept}
        return True


# -- stdio -------------------------------------------------------------------


class _StdioSession:
    """One host connection on stdio, with the ids of its pending tools/list."""

    def __init__(self, interposer: Interposer, write_host: Callable[[bytes], None]) -> None:
        self.interposer = interposer
        self.write_host = write_host
        # A count per id, not a set: a host may reuse an id, and each answer
        # must be filtered.
        self._lists: dict[str, int] = {}

    def from_host(self, line: bytes) -> bytes | None:
        """Bytes to write to the server for one line from the host, if any."""
        if not line.strip():
            return None
        try:
            parsed = parse_message(line)
        except ValueError:
            # Never forwarded: a line this side cannot read is a line it cannot
            # gate, and a server with a looser parser might run it.
            log.warning("coriqo-mcp: dropped a line from the host that is not JSON")
            self.write_host(dump_message(parse_error()) + b"\n")
            return None
        batch = isinstance(parsed, list)
        messages = parsed if batch else [parsed]
        forward: list[Any] = []
        replies: list[dict[str, Any]] = []
        for msg in messages:
            go, reply = self.interposer.gate_request(msg)
            if reply is not None:
                replies.append(reply)
            if not go:
                continue
            if _is_request(msg, "tools/list") and "id" in msg:
                key = _id_key(msg["id"])
                self._lists[key] = self._lists.get(key, 0) + 1
            forward.append(msg)
        if replies:
            out = replies if batch else replies[0]
            self.write_host(dump_message(out) + b"\n")
        if not forward:
            return None
        # What the server reads is what was gated: the parsed message, written
        # out again, never the host's original bytes.
        return dump_message(forward if batch else forward[0]) + b"\n"

    def from_server(self, line: bytes) -> bytes:
        """Bytes to write to the host for one line from the server."""
        if not self._lists:
            return line
        try:
            parsed = parse_message(line)
        except ValueError:
            return line
        messages = parsed if isinstance(parsed, list) else [parsed]
        changed = False
        for msg in messages:
            if not _is_response(msg):
                continue
            key = _id_key(msg.get("id"))
            pending = self._lists.get(key, 0)
            if not pending:
                continue
            if pending == 1:
                del self._lists[key]
            else:
                self._lists[key] = pending - 1
            if self.interposer.filter_tools(msg):
                changed = True
        return dump_message(parsed) + b"\n" if changed else line


def _start_stdin_reader(loop: asyncio.AbstractEventLoop) -> asyncio.Queue[bytes | None]:
    """Lines from our stdin, as a queue the relay reads.

    On POSIX, when stdin is a pipe or socket (how an MCP host starts us), it is
    read on the event loop. Otherwise (a console, a regular file, Windows) a
    thread reads it, so the read never blocks the loop.
    """
    queue: asyncio.Queue[bytes | None] = asyncio.Queue()
    stdin = sys.stdin.buffer
    if os.name == "posix" and _is_pipe(stdin):
        reader = asyncio.StreamReader(limit=MAX_LINE_BYTES, loop=loop)

        async def pump_async() -> None:
            try:
                await loop.connect_read_pipe(
                    lambda: asyncio.StreamReaderProtocol(reader, loop=loop), stdin
                )
                while True:
                    line = await reader.readline()
                    if not line:
                        break
                    queue.put_nowait(line)
            except Exception:  # noqa: BLE001 - a broken stdin is EOF
                log.debug("coriqo-mcp: stdin reader stopped", exc_info=True)
            finally:
                queue.put_nowait(None)

        queue_task = loop.create_task(pump_async())
        _BACKGROUND.add(queue_task)
        queue_task.add_done_callback(_BACKGROUND.discard)
        return queue

    def pump() -> None:
        try:
            for line in iter(stdin.readline, b""):
                loop.call_soon_threadsafe(queue.put_nowait, line)
        except Exception:  # noqa: BLE001 - a closed stdin is EOF
            log.debug("coriqo-mcp: stdin reader stopped", exc_info=True)
        finally:
            with contextlib.suppress(RuntimeError):
                loop.call_soon_threadsafe(queue.put_nowait, None)

    threading.Thread(target=pump, name="coriqo-mcp-stdin", daemon=True).start()
    return queue


#: Keeps the stdin pump task referenced for its lifetime.
_BACKGROUND: set[asyncio.Task[None]] = set()


def _is_pipe(stream: Any) -> bool:
    import stat

    try:
        mode = os.fstat(stream.fileno()).st_mode
    except (OSError, ValueError, AttributeError):
        return False
    return stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode)


async def _spawn(command: Sequence[str]) -> asyncio.subprocess.Process:
    kwargs: dict[str, Any] = {}
    if os.name == "posix":
        # Its own process group, so stopping it reaches whatever it started.
        kwargs["start_new_session"] = True
    return await asyncio.create_subprocess_exec(
        *command,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        limit=MAX_LINE_BYTES,
        **kwargs,
    )


def _signal_child(proc: asyncio.subprocess.Process, sig: int) -> None:
    if proc.returncode is not None:
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        if os.name == "posix":
            os.killpg(proc.pid, sig)
        elif sig == getattr(signal, "SIGKILL", None):
            proc.kill()
        else:
            proc.terminate()


async def stop_child(proc: asyncio.subprocess.Process, *, grace_s: float = DEFAULT_GRACE_S) -> int:
    """Wait for the child, then SIGTERM its group, then SIGKILL it."""
    for sig in (None, signal.SIGTERM, getattr(signal, "SIGKILL", signal.SIGTERM)):
        if sig is not None:
            _signal_child(proc, sig)
        try:
            return await asyncio.wait_for(proc.wait(), grace_s)
        except asyncio.TimeoutError:
            continue
    return await proc.wait()


def _group_alive(pgid: int) -> bool:
    if os.name != "posix":
        return False
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


async def _wait_group_gone(pgid: int, until: float) -> None:
    """Until no process is left in group ``pgid``, or ``until`` (monotonic).
    Polled: there is nothing to await for "every process in a group is gone"."""
    while _group_alive(pgid) and time.monotonic() < until:  # noqa: ASYNC110
        await asyncio.sleep(0.05)


class ChildStopper:
    """The ``on_suspend`` hook for the server coriqo-mcp started (TI-25).

    On suspension: SIGTERM to the server's process group, then SIGKILL to the
    group if anything in it is still running after ``grace_s``. Returns a
    :class:`~byoai.recorder.suspend.WorkerAck` with the times, the exit code
    and the last signal sent, which the gate records to the ledger.
    """

    # How long the hook waits for a server that is still starting. Short, so
    # the hook stays inside its timeout budget (grace + 15s).
    START_WAIT_S = 2.0

    def __init__(
        self,
        grace_s: float | None = DEFAULT_GRACE_S,
        *,
        mandate_grace: Callable[[], float | None] | None = None,
        fallback_s: float = DEFAULT_GRACE_S,
    ) -> None:
        # ``grace_s`` is an explicit local setting (--grace) and wins. Without
        # one, the mandate's stop_grace_s is read when the suspension lands
        # (the snapshot that carries the suspension carries it too), then
        # ``fallback_s`` (a file's legacy x-stop_grace_s, or 5 seconds).
        self._explicit = grace_s
        self._mandate_grace = mandate_grace
        self._fallback = fallback_s
        self.triggered = False
        self.ack: WorkerAck | None = None
        self._proc: asyncio.subprocess.Process | None = None
        self._attached = asyncio.Event()
        self._late_stop: asyncio.Task | None = None

    @property
    def grace_s(self) -> float:
        if self._explicit is not None:
            return self._explicit
        from_mandate = self._mandate_grace() if self._mandate_grace is not None else None
        return from_mandate if from_mandate is not None else self._fallback

    @property
    def hook_timeout_s(self) -> float:
        """The hook's timeout budget: the grace period plus 15s, sized for the
        longest grace a mandate may set when the grace comes from the mandate."""
        return (self._explicit if self._explicit is not None else MAX_GRACE_S) + 15.0

    def attach(self, proc: asyncio.subprocess.Process) -> None:
        """The server is running. If the suspension already arrived and the
        hook has answered, the server gets the full stop now (SIGTERM, then
        SIGKILL after the grace period), not a bare SIGTERM."""
        self._proc = proc
        self._attached.set()
        if self.triggered and self.ack is not None:
            self._late_stop = asyncio.ensure_future(self._stop(proc, utc_now()))

    async def __call__(self, notice: SuspendNotice) -> WorkerAck:
        self.triggered = True
        notified_at = utc_now()
        proc = self._proc
        if proc is None:
            # Starting: wait briefly for attach() rather than record "not
            # running" for a server about to run.
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._attached.wait(), self.START_WAIT_S)
            proc = self._proc
        if proc is None or proc.returncode is not None:
            self.ack = WorkerAck(
                worker="mcp-server" if proc is None else f"mcp-server pid {proc.pid}",
                kind="process",
                outcome=WorkerOutcome.NOT_RUNNING,
                notified_at=notified_at,
                acknowledged_at=utc_now(),
                elapsed_s=0.0,
                exit_code=None if proc is None else proc.returncode,
                grace_s=self.grace_s,
                detail=("not started yet; it is stopped the moment it starts"
                        if proc is None else None),
            )
            return self.ack
        print(
            f"coriqo-mcp: agent {notice.agent_id or '?'} is suspended in Coriqo; stopping "
            f"the server (SIGTERM, then SIGKILL after {self.grace_s:g}s)",
            file=sys.stderr,
        )
        self.ack = await self._stop(proc, notified_at)
        return self.ack

    async def _stop(self, proc: asyncio.subprocess.Process, notified_at: Any) -> WorkerAck:
        """SIGTERM the group, SIGKILL whatever is left after the grace period."""
        started = time.monotonic()
        deadline = started + self.grace_s
        last = "SIGTERM"
        _signal_child(proc, signal.SIGTERM)
        code: int | None = None
        try:
            code = await asyncio.wait_for(proc.wait(), self.grace_s)
        except asyncio.TimeoutError:
            pass
        # The leader exiting is not the group exiting: whatever it started is
        # still in the group until it goes too.
        await _wait_group_gone(proc.pid, deadline)
        leader_exited = proc.returncode is not None
        killed = not leader_exited or _group_alive(proc.pid)
        if killed:
            last = "SIGKILL"
            if os.name == "posix":
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(proc.pid, signal.SIGKILL)
            else:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
            with contextlib.suppress(asyncio.TimeoutError):
                code = await asyncio.wait_for(proc.wait(), 10.0)
            # Members it started are reaped by init, not by us; give that a
            # moment so "acknowledged" means the whole group is gone.
            await _wait_group_gone(proc.pid, time.monotonic() + 2.0)
        exited = proc.returncode is not None
        return WorkerAck(
            worker=f"mcp-server pid {proc.pid}",
            kind="process",
            outcome=WorkerOutcome.KILLED if killed else WorkerOutcome.EXITED,
            notified_at=notified_at,
            acknowledged_at=utc_now() if exited else None,
            elapsed_s=round(time.monotonic() - started, 6),
            exit_code=code if code is not None else proc.returncode,
            signal=last,
            grace_s=self.grace_s,
            detail=(
                "still running 10s after SIGKILL" if not exited
                else "the server exited on SIGTERM; processes it started did not"
                if killed and leader_exited else None
            ),
        )


def _install_stop_signals(
    loop: asyncio.AbstractEventLoop, stopping: asyncio.Event
) -> list[int]:
    """SIGTERM, SIGINT and SIGHUP stop the server before coriqo-mcp exits.

    The server runs in its own process group, so a signal sent to ours does
    not reach it; without this it would outlive us.
    """
    installed: list[int] = []
    for name in ("SIGTERM", "SIGINT", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            loop.add_signal_handler(sig, stopping.set)
        except (NotImplementedError, RuntimeError, ValueError):
            continue
        installed.append(sig)
    return installed


async def run_stdio(
    command: Sequence[str],
    interposer: Interposer,
    *,
    grace_s: float = DEFAULT_GRACE_S,
    stdin_queue: asyncio.Queue[bytes | None] | None = None,
    write_host: Callable[[bytes], None] | None = None,
    stopper: ChildStopper | None = None,
) -> int:
    """Run ``command`` as the server and relay stdio through ``interposer``.

    Returns the server's exit code. ``stdin_queue``/``write_host`` replace the
    process's own stdin and stdout, for tests. ``stopper`` is told about the
    server once it is running, so a suspension can stop it.
    """
    loop = asyncio.get_running_loop()
    if write_host is None:
        out = sys.stdout.buffer

        def write_stdout(data: bytes) -> None:
            out.write(data)
            out.flush()

        write_host = write_stdout

    session = _StdioSession(interposer, write_host)
    queue = stdin_queue if stdin_queue is not None else _start_stdin_reader(loop)
    proc = await _spawn(command)
    if stopper is not None:
        stopper.attach(proc)
    assert proc.stdin is not None and proc.stdout is not None
    child_in, child_out = proc.stdin, proc.stdout

    async def host_to_server() -> None:
        try:
            while True:
                line = await queue.get()
                if line is None:
                    break
                data = session.from_host(line)
                if data is not None:
                    child_in.write(data)
                    await child_in.drain()
        except (BrokenPipeError, ConnectionResetError):
            log.info("coriqo-mcp: the server closed its stdin")
        finally:
            with contextlib.suppress(Exception):
                child_in.close()

    async def server_to_host() -> None:
        while True:
            try:
                line = await child_out.readline()
            except ValueError:
                log.error(
                    "coriqo-mcp: the server sent a message over %d bytes; stopping",
                    MAX_LINE_BYTES,
                )
                return
            if not line:
                return
            write_host(session.from_server(line))

    upstream = asyncio.create_task(host_to_server())
    downstream = asyncio.create_task(server_to_host())
    stopping = asyncio.Event()
    installed = _install_stop_signals(loop, stopping)
    stop_wait = asyncio.create_task(stopping.wait())
    try:
        done, _ = await asyncio.wait(
            {upstream, downstream, stop_wait}, return_when=asyncio.FIRST_COMPLETED
        )
        if downstream not in done and stop_wait not in done:
            # The host hung up and the server's stdin is closed. Keep relaying
            # whatever the server still says while it shuts down.
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(asyncio.shield(downstream), grace_s)
    finally:
        for sig in installed:
            with contextlib.suppress(Exception):
                loop.remove_signal_handler(sig)
        stop_wait.cancel()
        if stopping.is_set():
            # We were told to stop: the server gets SIGTERM straight away.
            _signal_child(proc, signal.SIGTERM)
        code = await stop_child(proc, grace_s=grace_s)
        upstream.cancel()
        for task in (upstream, downstream, stop_wait):
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task
    return code


# -- HTTP (streamable HTTP and SSE) ------------------------------------------

_HOP_HEADERS = frozenset(
    {
        "host",
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "content-length",
        "accept-encoding",
    }
)
_DROP_RESPONSE_HEADERS = frozenset(
    {"connection", "keep-alive", "transfer-encoding", "content-length", "content-encoding"}
)


def _sse_event(data: Any) -> bytes:
    return b"event: message\ndata: " + dump_message(data) + b"\n\n"


class _SseFilter:
    """Rewrites ``tools/list`` answers inside an SSE stream, one event at a
    time. Every other event passes through unchanged."""

    def __init__(self, filter_message: Callable[[Any], bool]) -> None:
        self._filter = filter_message
        self._buf = b""

    def feed(self, chunk: bytes) -> bytes:
        self._buf += chunk.replace(b"\r\n", b"\n")
        out = []
        while True:
            cut = self._buf.find(b"\n\n")
            if cut == -1:
                break
            event, self._buf = self._buf[: cut + 2], self._buf[cut + 2 :]
            out.append(self._event(event))
        return b"".join(out)

    def close(self) -> bytes:
        tail, self._buf = self._buf, b""
        return tail

    def _event(self, event: bytes) -> bytes:
        lines = event[:-2].split(b"\n")
        data_lines = [ln for ln in lines if ln.startswith(b"data:")]
        if not data_lines:
            return event
        payload = b"\n".join(
            ln[6:] if ln.startswith(b"data: ") else ln[5:] for ln in data_lines
        )
        try:
            parsed = parse_message(payload)
        except ValueError:
            return event
        if not self._filter(parsed):
            return event
        rebuilt: list[bytes] = []
        placed = False
        for ln in lines:
            if ln.startswith(b"data:"):
                if not placed:
                    rebuilt.append(b"data: " + dump_message(parsed))
                    placed = True
                continue
            rebuilt.append(ln)
        return b"\n".join(rebuilt) + b"\n\n"


class HttpInterposer:
    """An ASGI app that gates MCP over HTTP in front of an upstream server.

    Every request is relayed to ``upstream`` (same path and query), with two
    exceptions for a request with a body: a refused ``tools/call`` is answered here and not
    relayed, and a ``tools/list`` answer is filtered on the way back, whether
    it comes as JSON or inside an SSE stream. A GET (the server-to-client SSE
    stream, or the legacy SSE transport) is relayed with any ``tools/list``
    answer in it filtered the same way.

    A request whose body cannot be read as JSON is refused (400), as is one
    with a ``Content-Encoding``, whatever the method: the server must never run
    a call this side could not read. A request path that is not a plain
    ``/path`` is refused (400), so the relay only ever reaches ``upstream``.
    """

    def __init__(
        self,
        interposer: Interposer,
        upstream: str,
        *,
        client: Any | None = None,
        on_startup: Callable[[], Awaitable[None]] | None = None,
        on_shutdown: Callable[[], Awaitable[None]] | None = None,
    ) -> None:
        import httpx

        parts = urlsplit(upstream)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise ValueError(f"--upstream must be an http(s) URL, got {upstream!r}")
        self.interposer = interposer
        self._origin = f"{parts.scheme}://{parts.netloc}"
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(30.0, read=None))
        self._on_startup = on_startup
        self._on_shutdown = on_shutdown
        self._sessions: OrderedDict[str, None] = OrderedDict()

    def _note_session(self, session_id: str | None) -> None:
        if not session_id:
            return
        self._sessions[session_id] = None
        self._sessions.move_to_end(session_id)
        while len(self._sessions) > _MAX_RUNS:
            self._sessions.popitem(last=False)

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope["type"] != "http":
            return
        await self._http(scope, receive, send)

    async def _lifespan(self, receive: Any, send: Any) -> None:
        while True:
            message = await receive()
            if message["type"] == "lifespan.startup":
                try:
                    if self._on_startup is not None:
                        await self._on_startup()
                except Exception as exc:  # noqa: BLE001
                    await send({"type": "lifespan.startup.failed", "message": str(exc)})
                    return
                await send({"type": "lifespan.startup.complete"})
            elif message["type"] == "lifespan.shutdown":
                with contextlib.suppress(Exception):
                    if self._on_shutdown is not None:
                        await self._on_shutdown()
                with contextlib.suppress(Exception):
                    await self._client.aclose()
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _http(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        method = scope["method"]
        headers = [
            (k.decode("latin-1").lower(), v.decode("latin-1")) for k, v in scope["headers"]
        ]
        lookup = dict(headers)
        # The run is the MCP session, but only a session id the server issued:
        # a client that invented a fresh id per call would otherwise get a fresh
        # latch and step count each time (a stateless server ignores the id).
        claimed = lookup.get("mcp-session-id")
        session = claimed if claimed and claimed in self._sessions else None
        body = await _read_body(receive)

        replies: list[dict[str, Any]] = []
        list_ids: set[str] = set()
        gated_body = bool(body)
        batch = False
        # Any request that carries a body is read and gated, whatever its
        # method: a server that also accepts JSON-RPC on another verb must not
        # get an ungated tools/call through this side.
        if body:
            if lookup.get("content-encoding", "identity").strip().lower() not in {"", "identity"}:
                await _send_json(send, 415, parse_error("Content-Encoding is not supported"))
                return
            try:
                parsed = parse_message(body)
            except ValueError:
                await _send_json(send, 400, parse_error())
                return
            batch = isinstance(parsed, list)
            kept: list[Any] = []
            for msg in parsed if batch else [parsed]:
                go, reply = self.interposer.gate_request(msg, session=session)
                if reply is not None:
                    replies.append(reply)
                if not go:
                    continue
                if _is_request(msg, "tools/list") and "id" in msg:
                    list_ids.add(_id_key(msg["id"]))
                kept.append(msg)
            if not kept:
                if replies:
                    await _send_json(send, 200, replies if batch else replies[0])
                else:
                    await _send_raw(send, 202, [], b"")
                return
            body = dump_message(kept if batch else kept[0])

        def filter_message(parsed: Any) -> bool:
            changed = False
            for msg in parsed if isinstance(parsed, list) else [parsed]:
                if not _is_response(msg):
                    continue
                # On a request with a body, only the answers to its own
                # tools/list requests; on a GET stream (no request of ours to
                # match), any answer shaped like one.
                if gated_body and _id_key(msg.get("id")) not in list_ids:
                    continue
                if self.interposer.filter_tools(msg):
                    changed = True
            return changed

        raw_path = scope.get("raw_path") or scope["path"].encode("utf-8")
        if not raw_path.startswith(b"/"):
            # Only an origin-form path is relayed. Anything else glued after
            # the upstream origin could change the host the request goes to
            # ("@other.host/..."), turning the relay into an open proxy.
            await _send_json(send, 400, parse_error("Bad request path"))
            return
        url = self._origin + raw_path.decode("latin-1")
        if scope.get("query_string"):
            url += "?" + scope["query_string"].decode("latin-1")
        fwd_headers = [(k, v) for k, v in headers if k not in _HOP_HEADERS]
        request = self._client.build_request(method, url, headers=fwd_headers, content=body)
        try:
            response = await self._client.send(request, stream=True)
        except Exception as exc:  # noqa: BLE001
            log.warning("coriqo-mcp: upstream %s did not answer: %s", self._origin, exc)
            await _send_json(
                send, 502, {"jsonrpc": "2.0", "id": None,
                            "error": {"code": -32000, "message": "Upstream MCP server unreachable"}}
            )
            return

        self._note_session(response.headers.get("mcp-session-id"))
        try:
            out_headers = [
                (k.encode("latin-1"), v.encode("latin-1"))
                for k, v in response.headers.multi_items()
                if k.lower() not in _DROP_RESPONSE_HEADERS
            ]
            ctype = response.headers.get("content-type", "").lower()
            if "text/event-stream" in ctype:
                await send({"type": "http.response.start", "status": response.status_code,
                            "headers": out_headers})
                for reply in replies:
                    await send({"type": "http.response.body", "body": _sse_event(reply),
                                "more_body": True})
                sse = _SseFilter(filter_message)
                async for chunk in response.aiter_bytes():
                    data = sse.feed(chunk)
                    if data:
                        await send({"type": "http.response.body", "body": data, "more_body": True})
                await send({"type": "http.response.body", "body": sse.close(), "more_body": False})
                return

            data = await response.aread()
            status = response.status_code
            if "application/json" in ctype and data:
                try:
                    parsed = parse_message(data)
                except ValueError:
                    parsed = None
                if parsed is not None:
                    changed = filter_message(parsed)
                    if replies:
                        merged = (parsed if isinstance(parsed, list) else [parsed]) + replies
                        parsed, changed = merged, True
                    if changed:
                        data = dump_message(parsed)
            elif replies:
                # Upstream had nothing to say (202 for notifications), but a
                # refused call still needs its answer.
                status, data = 200, dump_message(replies if batch else replies[0])
                out_headers = [h for h in out_headers if h[0].lower() != b"content-type"]
                out_headers.append((b"content-type", b"application/json"))
            await _send_raw(send, status, out_headers, data)
        finally:
            await response.aclose()


async def _read_body(receive: Any) -> bytes:
    chunks = []
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body"):
            break
    return b"".join(chunks)


async def _send_raw(
    send: Any, status: int, headers: list[tuple[bytes, bytes]], body: bytes
) -> None:
    headers = [h for h in headers if h[0].lower() != b"content-length"]
    headers.append((b"content-length", str(len(body)).encode()))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


async def _send_json(send: Any, status: int, value: Any) -> None:
    await _send_raw(send, status, [(b"content-type", b"application/json")], dump_message(value))


# -- the command -------------------------------------------------------------

_INSTALL_HINT = (
    "coriqo-mcp signs its record with the 'cryptography' package, which is not installed.\n"
    'Install it with:  pip install --pre "byoai-runtime[coriqo-mcp]"\n'
    "or run without a record (not recommended) with --no-record."
)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="coriqo-mcp",
        description=(
            "Gate an MCP server's tool calls with a Coriqo mandate. Runs the server "
            "as a child process and relays its stdio, or relays an HTTP server."
        ),
        epilog="Example: coriqo-mcp --mandate coriqo.mandate.yaml -- node server.js",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--mandate", metavar="FILE", help="a coriqo.mandate.yaml (v1) to enforce")
    src.add_argument(
        "--coriqo-agent-id",
        metavar="ID",
        help="enforce this agent's approved mandate, fetched from Coriqo and cached "
        "(needs an enrolled device: byoai-recorder-enroll)",
    )
    p.add_argument(
        "--environment",
        help="where this runs (default: $BYOAI_MANDATE_ENVIRONMENT). A mandate for "
        "another environment is treated as no mandate, and on_stale_snapshot decides",
    )
    rec = p.add_mutually_exclusive_group()
    rec.add_argument(
        "--recorder-dir",
        help="ledger and device key directory (default: $BYOAI_RECORDER_DIR or "
        "~/.byoai/recorder)",
    )
    rec.add_argument(
        "--no-record", action="store_true", help="decide calls but write no record"
    )
    p.add_argument("--http", action="store_true", help="relay an HTTP MCP server instead of stdio")
    p.add_argument("--upstream", help="with --http: the server's base URL, e.g. http://127.0.0.1:9000")
    p.add_argument(
        "--listen", default="127.0.0.1:8808", help="with --http: host:port to serve on"
    )
    p.add_argument(
        "--grace", type=float, default=None,
        help="seconds the server gets to exit after SIGTERM before it is killed "
        "(default: the mandate's stop_grace_s, else the file's x-stop_grace_s, else 5)",
    )
    p.add_argument(
        "--on-suspend", action="append", default=[], metavar="MODULE:FUNCTION",
        help="call this function when the agent is suspended in Coriqo, to stop "
        "workers coriqo-mcp does not own (your queue, your workflow engine). "
        "Repeatable. The module must be importable",
    )
    p.add_argument(
        "--on-suspend-timeout", type=float, default=30.0, metavar="SECONDS",
        help="how long each --on-suspend function gets before it is recorded as "
        "timed out (default 30)",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="log decisions to stderr")
    p.add_argument("command", nargs=argparse.REMAINDER, help="-- then the server command")
    return p


def _split_command(argv: list[str]) -> tuple[list[str], list[str]]:
    if "--" in argv:
        i = argv.index("--")
        return argv[:i], argv[i + 1 :]
    return argv, []


def mandate_grace_s(document: Any, where: str = "the mandate file") -> float | None:
    """The file's stop grace period, if it sets a usable one: the v1.1 field
    ``stop_grace_s`` (sealed in the document hash), else the older
    ``x-stop_grace_s`` extension, which readers may ignore and which is not
    part of the hash (MANDATE_SPEC.md §3).
    """
    if not isinstance(document, dict):
        return None
    key = "stop_grace_s" if document.get("stop_grace_s") is not None else "x-stop_grace_s"
    if key not in document:
        return None
    value = document[key]
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0 < value <= MAX_GRACE_S
    ):
        log.warning(
            "coriqo-mcp: %s: %s must be a number of seconds above 0 and "
            "at most %g; ignoring it",
            where, key, MAX_GRACE_S,
        )
        return None
    return float(value)


def _build_gate(
    args: argparse.Namespace,
) -> tuple[MandateGate, str, str | None, float | None]:
    """The gate, a line describing its mandate, the id Coriqo knows the agent
    by (--coriqo-agent-id, or the file's agent.id; a file with only agent.name
    has none), and the file's x-stop_grace_s."""
    if args.mandate:
        from ..recorder.mandate_file import file_mandate_gate

        gate, loaded = file_mandate_gate(args.mandate, environment=args.environment)
        for warning in loaded.warnings:
            log.warning("coriqo-mcp: %s: %s", args.mandate, warning)
        return gate, (
            f"mandate {args.mandate} (sha256:{loaded.sha256[:12]}), mode {loaded.mode}"
        ), loaded.agent_id, mandate_grace_s(loaded.document, args.mandate)
    from ..recorder.mandate import mandate_gate

    gate = mandate_gate(args.coriqo_agent_id, environment=args.environment)
    if not gate.enabled:
        raise MandateError(
            "no Coriqo identity on this device, so there is no mandate to fetch for "
            f"agent {args.coriqo_agent_id}. Enroll it (byoai-recorder-enroll) or use --mandate."
        )
    return gate, f"agent {args.coriqo_agent_id}'s mandate from Coriqo", args.coriqo_agent_id, None


def load_hook(spec: str) -> SuspendHook:
    """``package.module:function`` to the function. Raises ``ValueError``."""
    module_name, sep, attr = spec.partition(":")
    if not sep or not module_name or not attr:
        raise ValueError(f"--on-suspend {spec!r}: write it as module:function")
    try:
        target: Any = importlib.import_module(module_name)
    except ImportError as exc:
        raise ValueError(f"--on-suspend {spec!r}: cannot import {module_name}: {exc}") from exc
    for part in attr.split("."):
        try:
            target = getattr(target, part)
        except AttributeError as exc:
            raise ValueError(f"--on-suspend {spec!r}: {module_name} has no {attr}") from exc
    if not callable(target):
        raise ValueError(f"--on-suspend {spec!r}: {attr} is not callable")
    return cast(SuspendHook, target)


#: How often decisions waiting in the outbox are sent to Coriqo.
SHIP_INTERVAL_S = 5.0


class _Record:
    """The ledger, the verdict recorder, and (on an enrolled device with a
    Coriqo agent id) the loop that sends decisions to Coriqo."""

    def __init__(self, recorder: Any, verdicts: Any, shipper: Any = None,
                 client: Any = None, outbox: Any = None) -> None:
        self.recorder = recorder
        self.verdicts = verdicts
        self._shipper = shipper
        self._client = client
        self._outbox = outbox
        self._task: asyncio.Task[None] | None = None

    @property
    def shipping(self) -> bool:
        return self._shipper is not None

    def start(self) -> None:
        if self._shipper is not None:
            self._task = asyncio.create_task(self._loop())

    async def _drain(self) -> None:
        while await self._shipper.ship_once() is not None:
            pass

    async def _loop(self) -> None:
        delay = SHIP_INTERVAL_S
        while True:
            await asyncio.sleep(delay)
            try:
                await self._drain()
                delay = SHIP_INTERVAL_S
            except Exception as exc:  # noqa: BLE001 - kept in the outbox, retried
                delay = min(delay * 2, 300.0)
                log.warning(
                    "coriqo-mcp: could not send decisions to Coriqo (%s); they stay in "
                    "the local outbox and are retried in %.0fs",
                    exc,
                    delay,
                )

    async def close(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
        if self._shipper is not None:
            try:
                await asyncio.wait_for(self._drain(), 10.0)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "coriqo-mcp: %s; unsent decisions stay in the outbox for the next run",
                    exc or "sending to Coriqo timed out",
                )
        if self._client is not None:
            with contextlib.suppress(Exception):
                await self._client.close()
        if self._outbox is not None:
            self._outbox.close()
        # A suspension's worker_stop_ack is written moments before exit; send
        # it now rather than leave it for the next run.
        self.recorder.close(final_ship=True)


def _build_recorder(args: argparse.Namespace, agent_id: str | None) -> _Record | None:
    if args.no_record:
        log.warning("coriqo-mcp: --no-record: decisions are made but not written down")
        return None
    from ..recorder.integration import Recorder
    from ..recorder.verdicts import VerdictRecorder

    recorder = Recorder(dir=args.recorder_dir)
    shipper = client = outbox = None
    identity = None
    if agent_id:
        from ..recorder.identity import IdentitySource, resolve_identity

        try:
            identity = resolve_identity(key_dir=args.recorder_dir)
        except Exception as exc:  # noqa: BLE001 - a broken enrolment must not stop the gate
            log.warning("coriqo-mcp: cannot read this device's Coriqo enrolment: %s", exc)
        if identity is not None and identity.source != IdentitySource.DEVICE:
            identity = None
    if identity is not None:
        from ..recorder.coriqo_async import AsyncCoriqoAgentsClient
        from ..recorder.verdicts import VerdictOutbox, VerdictShipper

        outbox = VerdictOutbox(recorder.ledger.path.parent / "coriqo_mcp_verdicts.db")
        client = AsyncCoriqoAgentsClient(identity)
        shipper = VerdictShipper(client, outbox)
    else:
        print(
            "coriqo-mcp: decisions stay in the local ledger. To send them to Coriqo, "
            "enroll this device (byoai-recorder-enroll) and set agent.id in the "
            "mandate file, or use --coriqo-agent-id.",
            file=sys.stderr,
        )
    verdicts = VerdictRecorder(
        ledger=recorder.ledger,
        outbox=outbox,
        checkpointer=recorder.checkpointer,
        session_id="coriqo-mcp",
    )
    return _Record(recorder, verdicts, shipper, client, outbox)


def _describe(gate: MandateGate) -> str:
    snap = gate.snapshot
    if snap is None:
        return "no mandate snapshot yet"
    if snap.observing:
        effect = "shadow: every call goes through; calls outside the mandate are flagged"
    elif snap.on_violation == "alert_only":
        effect = "enforce, alert_only: calls outside the mandate go through and are flagged"
    else:
        effect = f"enforce: calls outside the mandate are refused ({snap.on_violation})"
    return effect


async def _amain(args: argparse.Namespace, command: list[str]) -> int:
    from ..errors import ByoAIError
    from ..recorder.verdicts import set_verdict_recorder

    try:
        gate, source, coriqo_agent_id, file_grace = _build_gate(args)
        hooks = [(spec, load_hook(spec)) for spec in args.on_suspend]
    except (ByoAIError, ValueError) as exc:
        print(f"coriqo-mcp: {exc}", file=sys.stderr)
        return 2
    # Normal shutdown (stdin closed) uses the local setting, the file's legacy
    # x-stop_grace_s, then 5s. A suspension uses the stopper's own rule, which
    # puts the mandate's stop_grace_s ahead of the file extension.
    grace = args.grace if args.grace is not None else (file_grace or DEFAULT_GRACE_S)
    # Registered before the first fetch: a mandate that is already suspended
    # when coriqo-mcp starts must reach the hooks too.
    for spec, hook in hooks:
        gate.add_suspend_hook(hook, name=spec, timeout_s=args.on_suspend_timeout)
    stopper = ChildStopper(
        args.grace,
        mandate_grace=lambda: gate.snapshot.stop_grace_s if gate.snapshot is not None else None,
        fallback_s=file_grace or DEFAULT_GRACE_S,
    )
    gate.add_suspend_hook(stopper, name="mcp-server", timeout_s=stopper.hook_timeout_s)
    try:
        record = _build_recorder(args, coriqo_agent_id)
    except ModuleNotFoundError as exc:
        if (exc.name or "").split(".")[0] != "cryptography":
            raise
        print(_INSTALL_HINT, file=sys.stderr)
        return 2
    # Bound before any task is created, so every task inherits it.
    set_verdict_recorder(None if record is None else record.verdicts)
    interposer = Interposer(gate)
    try:
        await gate.start()
        print(f"coriqo-mcp: {source}; {_describe(gate)}", file=sys.stderr)
        if record is not None:
            where = record.recorder.ledger.path
            sent = ", and sending decisions to Coriqo" if record.shipping else ""
            print(f"coriqo-mcp: recording to {where}{sent}", file=sys.stderr)
            record.start()
        snap = gate.snapshot
        if snap is not None and snap.suspended:
            print(
                f"coriqo-mcp: agent {coriqo_agent_id} is suspended in Coriqo "
                f"(status {snap.status!r}); not starting the server. Resume the agent "
                "in Coriqo, on its Enforcement tab, to run it again.",
                file=sys.stderr,
            )
            return EXIT_SUSPENDED
        if args.http:
            code = await _serve_http(args, command, interposer, grace, stopper)
        else:
            code = await run_stdio(command, interposer, grace_s=grace, stopper=stopper)
        if stopper.triggered:
            ack = stopper.ack
            how = f" ({ack.outcome}, {ack.signal}, after {ack.elapsed_s:.2f}s)" if (
                ack is not None and ack.signal) else ""
            print(
                f"coriqo-mcp: agent {coriqo_agent_id} was suspended in Coriqo; the "
                f"server was stopped{how}",
                file=sys.stderr,
            )
            return EXIT_SUSPENDED
        return code
    finally:
        # The hooks write their acknowledgements to the record; let them
        # finish before it closes.
        if not await gate.suspend_hooks.wait(max(args.on_suspend_timeout, stopper.hook_timeout_s) + 5.0):
            log.warning("coriqo-mcp: an on_suspend hook was still running at exit")
        await gate.stop()
        if record is not None:
            await record.close()


async def _serve_http(
    args: argparse.Namespace,
    command: list[str],
    interposer: Interposer,
    grace_s: float = DEFAULT_GRACE_S,
    stopper: ChildStopper | None = None,
) -> int:
    try:
        import uvicorn
    except ModuleNotFoundError:
        print(
            'coriqo-mcp --http needs uvicorn:  pip install --pre "byoai-runtime[coriqo-mcp]"',
            file=sys.stderr,
        )
        return 2
    proc = None
    if command:
        # The server is ours: it starts with us and stops with us.
        proc = await asyncio.create_subprocess_exec(*command, start_new_session=os.name == "posix")
        if stopper is not None:
            stopper.attach(proc)
    host, _, port = args.listen.rpartition(":")
    app = HttpInterposer(interposer, args.upstream)
    config = uvicorn.Config(app, host=host or "127.0.0.1", port=int(port), log_level="warning",
                            lifespan="on")
    server = uvicorn.Server(config)
    print(f"coriqo-mcp: serving on http://{args.listen}, relaying {args.upstream}", file=sys.stderr)
    serve = asyncio.create_task(server.serve())
    waiters: list[asyncio.Future[Any]] = [serve]
    if proc is not None:
        waiters.append(asyncio.ensure_future(proc.wait()))
    try:
        await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
    finally:
        server.should_exit = True
        with contextlib.suppress(Exception):
            await serve
        code = 0
        if proc is not None:
            _signal_child(proc, signal.SIGTERM)
            code = await stop_child(proc, grace_s=grace_s)
    return code


def main(argv: Iterable[str] | None = None) -> None:
    raw = list(sys.argv[1:] if argv is None else argv)
    own, command = _split_command(raw)
    parser = _parser()
    args = parser.parse_args(own)
    if args.command:
        parser.error(
            "put the server command after --, e.g. coriqo-mcp --mandate m.yaml -- node server.js"
        )
    logging.basicConfig(
        stream=sys.stderr,
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(message)s",
    )
    if args.http:
        if not args.upstream:
            parser.error("--http needs --upstream, the URL of the MCP server to relay")
    elif not command:
        parser.error("give the server command after --, e.g. -- node server.js")
    try:
        code = asyncio.run(_amain(args, command))
    except KeyboardInterrupt:
        code = 130
    raise SystemExit(code)


if __name__ == "__main__":
    main()
