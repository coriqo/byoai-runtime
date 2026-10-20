"""TI-25: the on_suspend hook, and each worker's acknowledgement on the ledger."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from byoai.recorder.ledger import Ledger
from byoai.recorder.mandate import MandateGate
from byoai.recorder.suspend import (
    SuspendHooks,
    SuspendNotice,
    WorkerAck,
    WorkerOutcome,
    utc_now,
)
from byoai.recorder.verdicts import VerdictRecorder, use_verdict_recorder

ACTIVE = {"status": "active", "allowed_tools": ["search"], "mandate_version_id": "mv-1"}
SUSPENDED = {**ACTIVE, "status": "suspended"}


async def _never(_etag):
    return None, None


def gate(**kwargs) -> MandateGate:
    return MandateGate(_never, agent_id="agt_1", **kwargs)


def ack_rows(ledger: Ledger) -> list[dict]:
    return [e.event.payload for e in ledger.iter_entries() if e.event.kind == "worker_stop_ack"]


# -- unset is today ----------------------------------------------------------


async def test_no_hook_changes_nothing():
    """A gate built without on_suspend behaves exactly as before: the AD-9
    callback still fires once, and no hook task or thread is started."""
    seen: list[str] = []
    g = gate(on_suspend_observed=lambda snap: seen.append(snap.status))
    assert len(g.suspend_hooks) == 0
    g.apply_snapshot(ACTIVE)
    g.apply_snapshot(SUSPENDED)
    g.apply_snapshot(SUSPENDED)
    assert seen == ["suspended"]
    assert await g.suspend_hooks.wait(0.1)
    assert g.suspend_hooks.acks == []
    assert g.decide("search").reason == "agent_suspended"


# -- when hooks fire ---------------------------------------------------------


async def test_sync_hook_fires_once_on_the_transition(tmp_path):
    calls: list[SuspendNotice] = []
    g = gate(on_suspend=calls.append)
    g.apply_snapshot(ACTIVE)
    assert await g.suspend_hooks.wait(1)
    assert calls == []
    g.apply_snapshot(SUSPENDED)
    g.apply_snapshot(SUSPENDED)  # already suspended: no second call
    assert await g.suspend_hooks.wait(5)
    assert len(calls) == 1
    notice = calls[0]
    assert (notice.agent_id, notice.status, notice.mandate_version_id) == (
        "agt_1", "suspended", "mv-1")
    assert notice.observed_at.endswith("Z")
    # Resumed, then suspended again: a new suspension, a new call.
    g.apply_snapshot(ACTIVE)
    g.apply_snapshot(SUSPENDED)
    assert await g.suspend_hooks.wait(5)
    assert len(calls) == 2


async def test_first_snapshot_already_suspended_fires():
    calls: list[SuspendNotice] = []
    g = gate(on_suspend=[calls.append])
    g.apply_snapshot(SUSPENDED)
    assert await g.suspend_hooks.wait(5)
    assert len(calls) == 1


# -- what is recorded --------------------------------------------------------


async def test_each_hook_is_recorded_with_its_outcome(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db", "device-test")
    recorder = VerdictRecorder(ledger=ledger)

    async def publish(notice):
        await asyncio.sleep(0.01)

    def broken(notice):
        raise RuntimeError("redis://secret-host:6379 refused")

    async def hangs(notice):
        await asyncio.sleep(30)

    with use_verdict_recorder(recorder):
        g = gate()
        g.add_suspend_hook(publish, name="redis-publish")
        g.add_suspend_hook(broken, name="celery-revoke")
        g.add_suspend_hook(hangs, name="temporal-cancel", timeout_s=0.2)
        g.apply_snapshot(SUSPENDED)
        assert await g.suspend_hooks.wait(5)

    rows = {r["worker"]: r for r in ack_rows(ledger)}
    ledger.close()
    assert rows["redis-publish"]["outcome"] == WorkerOutcome.RETURNED
    assert rows["redis-publish"]["acknowledged_at"] >= rows["redis-publish"]["notified_at"]
    assert rows["redis-publish"]["elapsed_s"] >= 0.01
    assert rows["celery-revoke"]["outcome"] == WorkerOutcome.RAISED
    # The exception type, never its message.
    assert rows["celery-revoke"]["detail"] == "RuntimeError"
    assert "secret-host" not in str(rows)
    assert rows["temporal-cancel"]["outcome"] == WorkerOutcome.TIMED_OUT
    assert "acknowledged_at" not in rows["temporal-cancel"]
    for row in rows.values():
        assert row["agent_id"] == "agt_1"
        assert row["mandate_version_id"] == "mv-1"
        assert row["kind"] == "hook"
        assert row["status"] == "suspended"


async def test_a_hook_can_report_its_own_ack(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db", "device-test")
    mine = WorkerAck(worker="pool-7", kind="process", outcome=WorkerOutcome.EXITED,
                     notified_at=utc_now(), acknowledged_at=utc_now(), elapsed_s=0.5,
                     exit_code=0, signal="SIGTERM", grace_s=5.0)
    with use_verdict_recorder(VerdictRecorder(ledger=ledger)):
        g = gate(on_suspend=lambda n: mine)
        g.apply_snapshot(SUSPENDED)
        assert await g.suspend_hooks.wait(5)
    rows = ack_rows(ledger)
    ledger.close()
    assert len(rows) == 1
    assert rows[0]["worker"] == "pool-7" and rows[0]["exit_code"] == 0
    assert rows[0]["signal"] == "SIGTERM"


async def test_no_recorder_means_no_row_and_no_error():
    calls: list[SuspendNotice] = []
    g = gate(on_suspend=calls.append)
    g.apply_snapshot(SUSPENDED)
    assert await g.suspend_hooks.wait(5)
    assert len(calls) == 1
    assert g.suspend_hooks.acks[0].outcome == WorkerOutcome.RETURNED


def test_without_a_loop_hooks_run_in_a_thread_and_still_record(tmp_path):
    """apply_snapshot from plain synchronous code: the hook runs off-thread,
    so the caller is not held up, and the bound recorder still gets the row."""
    ledger = Ledger(tmp_path / "ledger.db", "device-test")
    release = threading.Event()
    where: list[str] = []

    def slow(notice):
        where.append(threading.current_thread().name)
        release.wait(5)

    with use_verdict_recorder(VerdictRecorder(ledger=ledger)):
        g = gate(on_suspend=slow)
        started = time.monotonic()
        g.apply_snapshot(SUSPENDED)
        assert time.monotonic() - started < 1.0  # not blocked on the hook
        release.set()
        assert asyncio.run(g.suspend_hooks.wait(5))
    rows = ack_rows(ledger)
    ledger.close()
    assert len(rows) == 1 and rows[0]["outcome"] == WorkerOutcome.RETURNED
    assert where and where[0] != threading.main_thread().name


def test_a_non_callable_hook_is_refused():
    with pytest.raises(TypeError):
        SuspendHooks(["not a function"])  # type: ignore[list-item]


async def test_a_failing_record_does_not_lose_the_others():
    seen: list[str] = []

    def record(notice, ack):
        if ack.worker == "a":
            raise OSError("disk full")
        seen.append(ack.worker)

    hooks = SuspendHooks(record=record)
    hooks.add(lambda n: None, name="a")
    hooks.add(lambda n: None, name="b")
    acks = await hooks.run(SuspendNotice("agt", "suspended", None, utc_now()))
    assert [a.worker for a in acks] == ["a", "b"]
    assert seen == ["b"]
