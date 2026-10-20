"""TI-25: coriqo-mcp stops the server it owns when the agent is suspended."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from byoai.integrations import coriqo_mcp
from byoai.integrations.coriqo_mcp import (
    EXIT_SUSPENDED,
    ChildStopper,
    Interposer,
    load_hook,
    mandate_grace_s,
    run_stdio,
)
from byoai.recorder.ledger import Ledger
from byoai.recorder.mandate import MandateGate
from byoai.recorder.suspend import SuspendNotice, WorkerOutcome, utc_now
from byoai.recorder.verdicts import VerdictRecorder, use_verdict_recorder

REPO = Path(__file__).resolve().parents[2]
ECHO = str(REPO / "tests" / "_mcp_echo_server.py")
ENFORCE = REPO / "tests" / "fixtures" / "coriqo_mcp" / "enforce.mandate.yaml"

posix_only = pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX")

ACTIVE = {"status": "active", "allowed_tools": ["search"], "mandate_version_id": "mv-9",
          "mandate_enforcement": "enforce"}
SUSPENDED = {**ACTIVE, "status": "suspended"}

#: Ignores SIGTERM, so only SIGKILL stops it.
STUBBORN = (
    "import signal, sys, time\n"
    "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
    "print('ready', flush=True)\n"
    "time.sleep(60)\n"
)
#: Exits on SIGTERM but leaves a child in its group that ignores it.
LEAVES_A_CHILD = (
    "import subprocess, sys, time\n"
    "subprocess.Popen([sys.executable, '-c', "
    "'import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)'])\n"
    "time.sleep(0.3)\n"
    "print('ready', flush=True)\n"
    "time.sleep(60)\n"
)
NOTICE = SuspendNotice("agt_9", "suspended", "mv-9", utc_now())


async def _spawn(code: str) -> asyncio.subprocess.Process:
    proc = await asyncio.create_subprocess_exec(
        sys.executable, "-c", code, stdout=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    assert proc.stdout is not None
    assert (await asyncio.wait_for(proc.stdout.readline(), 10)).strip() == b"ready"
    return proc


async def _never(_etag):
    return None, None


# -- the stopper -------------------------------------------------------------


@posix_only
async def test_server_that_exits_on_sigterm_is_recorded_as_exited():
    proc = await _spawn("import time; print('ready', flush=True); time.sleep(60)")
    stopper = ChildStopper(grace_s=5)
    stopper.attach(proc)
    ack = await stopper(NOTICE)
    assert ack.outcome == WorkerOutcome.EXITED
    assert ack.signal == "SIGTERM"
    assert ack.exit_code == -signal.SIGTERM
    assert ack.acknowledged_at and ack.elapsed_s is not None and ack.elapsed_s < 5
    assert ack.kind == "process" and ack.worker == f"mcp-server pid {proc.pid}"


@posix_only
async def test_server_that_ignores_sigterm_is_killed_after_the_grace_period():
    proc = await _spawn(STUBBORN)
    stopper = ChildStopper(grace_s=0.5)
    stopper.attach(proc)
    ack = await stopper(NOTICE)
    assert ack.outcome == WorkerOutcome.KILLED
    assert ack.signal == "SIGKILL"
    assert ack.exit_code == -signal.SIGKILL
    assert ack.elapsed_s is not None and ack.elapsed_s >= 0.5
    assert ack.grace_s == 0.5


@posix_only
async def test_whatever_the_server_started_is_stopped_too():
    proc = await _spawn(LEAVES_A_CHILD)
    stopper = ChildStopper(grace_s=0.5)
    stopper.attach(proc)
    ack = await stopper(NOTICE)
    # The leader went on SIGTERM; its child did not, so the group got SIGKILL.
    assert ack.outcome == WorkerOutcome.KILLED
    assert not coriqo_mcp._group_alive(proc.pid)


async def test_nothing_running_is_recorded_as_such():
    ack = await ChildStopper()(NOTICE)
    assert ack.outcome == WorkerOutcome.NOT_RUNNING
    assert ack.worker == "mcp-server"


# -- end to end over stdio ---------------------------------------------------


@posix_only
async def test_suspension_mid_session_stops_the_server_and_records_it(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db", "device-test")
    queue: asyncio.Queue[bytes | None] = asyncio.Queue()
    out: list[bytes] = []
    gate = MandateGate(_never, agent_id="agt_9")
    gate.apply_snapshot(ACTIVE)
    stopper = ChildStopper(grace_s=2)
    gate.add_suspend_hook(stopper, name="mcp-server", timeout_s=20)
    with use_verdict_recorder(VerdictRecorder(ledger=ledger)):
        run = asyncio.create_task(
            run_stdio([sys.executable, ECHO], Interposer(gate), stdin_queue=queue,
                      write_host=out.append, grace_s=2, stopper=stopper))
        queue.put_nowait(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                         .encode() + b"\n")
        for _ in range(200):
            if out:
                break
            await asyncio.sleep(0.05)
        assert out, "the server never answered"
        # Coriqo suspends the agent; the next refresh brings it in.
        gate.apply_snapshot(SUSPENDED)
        await asyncio.wait_for(run, 20)
        assert await gate.suspend_hooks.wait(10)
    rows = [e.event.payload for e in ledger.iter_entries() if e.event.kind == "worker_stop_ack"]
    ledger.close()
    assert stopper.triggered
    assert len(rows) == 1
    assert rows[0]["worker"].startswith("mcp-server pid ")
    assert rows[0]["outcome"] in (WorkerOutcome.EXITED, WorkerOutcome.KILLED)
    assert rows[0]["agent_id"] == "agt_9" and rows[0]["mandate_version_id"] == "mv-9"
    assert rows[0]["acknowledged_at"] >= rows[0]["notified_at"] >= rows[0]["observed_at"]


async def test_already_suspended_at_start_never_starts_the_server(monkeypatch, tmp_path):
    started = tmp_path / "started"
    gate = MandateGate(_never, agent_id="agt_9")
    gate.apply_snapshot(SUSPENDED)
    calls: list[SuspendNotice] = []

    def fake_build(_args):
        return gate, "test mandate", "agt_9", None

    monkeypatch.setattr(coriqo_mcp, "_build_gate", fake_build)
    monkeypatch.setattr(coriqo_mcp, "load_hook", lambda spec: calls.append)
    args = argparse.Namespace(no_record=True, http=False, grace=None, on_suspend=["x:y"],
                              on_suspend_timeout=5.0, mandate=None)
    # The snapshot was applied before the hooks existed; a refresh from Coriqo
    # that says the same is the case we model here.
    gate._snapshot = None  # noqa: SLF001 - simulate "not fetched yet"

    async def suspended_source(_etag):
        return SUSPENDED, "e1"

    gate._source = suspended_source  # noqa: SLF001
    code = await coriqo_mcp._amain(
        args, [sys.executable, "-c", f"open({str(started)!r}, 'w').write('x')"])
    assert code == EXIT_SUSPENDED
    assert not started.exists()
    assert len(calls) == 1


# -- configuration -----------------------------------------------------------


def test_grace_from_the_mandate_file_extension():
    assert mandate_grace_s({"x-stop_grace_s": 12}) == 12.0
    assert mandate_grace_s({"x-stop_grace_s": 0.5}) == 0.5
    assert mandate_grace_s({}) is None
    for bad in (0, -1, 601, True, "10", None):
        assert mandate_grace_s({"x-stop_grace_s": bad}) is None


def test_unset_grace_is_five_seconds():
    """Pins today: no flag, no x-stop_grace_s, the server gets 5 seconds."""
    args = coriqo_mcp._parser().parse_args(["--mandate", str(ENFORCE)])
    assert args.grace is None and args.on_suspend == []
    assert coriqo_mcp.DEFAULT_GRACE_S == 5.0
    gate, _, _, file_grace = coriqo_mcp._build_gate(args)
    assert file_grace is None
    assert len(gate.suspend_hooks) == 0


def test_x_stop_grace_s_does_not_change_the_mandate_hash(tmp_path):
    from byoai.recorder.mandate_file import load_mandate_file

    with_grace = tmp_path / "m.yaml"
    with_grace.write_text(ENFORCE.read_text() + "x-stop_grace_s: 20\n")
    assert load_mandate_file(with_grace).sha256 == load_mandate_file(ENFORCE).sha256
    args = coriqo_mcp._parser().parse_args(["--mandate", str(with_grace)])
    assert coriqo_mcp._build_gate(args)[3] == 20.0


def test_load_hook():
    assert load_hook("os.path:join") is os.path.join
    for bad in ("os.path", ":join", "no_such_module_ti25:f", "os.path:nope", "os:sep"):
        with pytest.raises(ValueError):
            load_hook(bad)


def test_cli_refuses_a_hook_it_cannot_load(tmp_path):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(REPO / "src"), str(REPO)])
    proc = subprocess.run(
        [sys.executable, "-m", "byoai.integrations.coriqo_mcp", "--mandate", str(ENFORCE),
         "--no-record", "--on-suspend", "no_such_module_ti25:stop", "--",
         sys.executable, ECHO],
        capture_output=True, env=env, timeout=30,
    )
    assert proc.returncode == 2
    assert b"no_such_module_ti25" in proc.stderr
