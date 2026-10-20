"""Suspend reaches every worker: the ``on_suspend`` hook and its record.

A suspension is decided in Coriqo and travels to the runtime inside the mandate
snapshot (``status: suspended``). From the moment a gate holds that snapshot,
every governed call it decides is denied. That stops the calls this process
makes. It does not stop the work your own queue already handed to other
workers: a Celery task that started before the suspension, a Temporal
workflow mid-activity, a pool of consumers on a Redis or NATS subject.

Coriqo does not run a broadcast for that, and never will: a Coriqo-run pub/sub
in the agent's path would make Coriqo a runtime dependency. Instead the gate
calls hooks you register, on the transition into suspended, and you wire them
to the queue you already run.

::

    from byoai.recorder.mandate import mandate_gate

    gate = mandate_gate("agt_123", on_suspend=stop_my_workers)

A hook takes one :class:`SuspendNotice` and may be a plain function or a
coroutine function. Some shapes, none of which this package depends on::

    # Redis pub/sub: every worker subscribes to the channel and stops itself.
    def stop_my_workers(notice):
        redis_client.publish("agents.stop", json.dumps(notice.to_dict()))

    # NATS
    async def stop_my_workers(notice):
        await nc.publish("agents.stop", json.dumps(notice.to_dict()).encode())

    # Celery: revoke what is queued or running for this agent.
    def stop_my_workers(notice):
        for task_id in task_ids_for(notice.agent_id):
            celery_app.control.revoke(task_id, terminate=True, signal="SIGTERM")

    # Temporal: cancel the agent's running workflows.
    async def stop_my_workers(notice):
        handle = temporal_client.get_workflow_handle(workflow_id_for(notice.agent_id))
        await handle.cancel()

What gets recorded
------------------
Every hook produces one :class:`WorkerAck`: when it was called, when it
returned (or raised, or ran past its time limit), and how long that took. Each
ack is written to the device-signed ledger as a ``worker_stop_ack`` event, so it
ships to Coriqo with the rest of the record and the agent's Enforcement tab can
show when each worker stopped. A hook that wants to report more precisely (a
child process's exit code, for example) returns its own :class:`WorkerAck`.

What a hook's return means
--------------------------
"Returned" means your hook returned: the message was published, the revoke was
sent. It does not mean every consumer has stopped; only your workers know that.
If they can report back, have the hook wait for them and return when they have.

Hooks never stop the suspension itself. A hook that raises or hangs is
recorded as such and logged, and the gate keeps denying every call either way.
"""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import logging
import threading
import time
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import asdict, dataclass
from typing import Any

from .schema import now_ts_device

__all__ = [
    "DEFAULT_HOOK_TIMEOUT_S",
    "SuspendHook",
    "SuspendHooks",
    "SuspendNotice",
    "WorkerAck",
    "WorkerOutcome",
    "record_worker_ack",
    "utc_now",
]

log = logging.getLogger(__name__)

#: How long one hook gets before it is recorded as timed out. The hook is not
#: cancelled if it is a plain function (a thread cannot be), only no longer
#: waited for.
DEFAULT_HOOK_TIMEOUT_S = 30.0


class WorkerOutcome:
    """What a worker's acknowledgement says happened."""

    #: The hook returned.
    RETURNED = "returned"
    #: The hook raised. ``detail`` is the exception's type, never its message.
    RAISED = "raised"
    #: The hook ran past its time limit and was no longer waited for.
    TIMED_OUT = "timed_out"
    #: A child process exited after SIGTERM, inside the grace period.
    EXITED = "exited"
    #: A child process outlived the grace period and was sent SIGKILL.
    KILLED = "killed"
    #: There was no process to stop (it had already exited, or never started).
    NOT_RUNNING = "not_running"


def utc_now() -> str:
    """The device's wall clock, the ledger's format: RFC 3339 UTC with
    microseconds and a ``Z``."""
    return now_ts_device()


@dataclass(frozen=True, slots=True)
class SuspendNotice:
    """What a hook is told: which agent, which mandate, and when this runtime
    saw the suspension."""

    agent_id: str | None
    status: str
    mandate_version_id: str | None
    observed_at: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class WorkerAck:
    """One worker's acknowledgement of a suspension."""

    #: The hook's name, or the process it stopped (``mcp-server pid 4242``).
    worker: str
    #: ``hook`` or ``process``.
    kind: str
    outcome: str
    #: When the hook was called / the first signal was sent.
    notified_at: str
    #: When it returned, raised, or exited. ``None`` if it never did.
    acknowledged_at: str | None
    elapsed_s: float | None
    detail: str | None = None
    exit_code: int | None = None
    #: The last signal sent to a process (``SIGTERM`` or ``SIGKILL``).
    signal: str | None = None
    grace_s: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


#: A hook: called with the notice; may return ``None``, a :class:`WorkerAck`,
#: or an awaitable of either.
SuspendHook = Callable[[SuspendNotice], None | WorkerAck | Awaitable[Any]]


def _hook_name(hook: Callable[..., Any]) -> str:
    name = getattr(hook, "__qualname__", None) or getattr(hook, "__name__", None)
    if not name:
        name = type(hook).__name__
    module = getattr(hook, "__module__", None)
    return f"{module}.{name}" if module and module != "builtins" else str(name)


@dataclass(slots=True)
class _Entry:
    name: str
    hook: SuspendHook
    timeout_s: float


def record_worker_ack(notice: SuspendNotice, ack: WorkerAck) -> bool:
    """Write ``ack`` to the ledger of the verdict recorder bound here.

    Returns whether a row was written. Never raises: a record that cannot be
    written is logged, and the suspension holds regardless.
    """
    from .verdicts import verdict_recorder  # verdicts imports mandate, which imports us

    recorder = verdict_recorder()
    if recorder is None:
        log.info(
            "coriqo: worker %s acknowledged the suspension of %s (%s) but no "
            "recorder is bound, so it is only in this log",
            ack.worker, notice.agent_id, ack.outcome,
        )
        return False
    return recorder.record_worker_ack(notice, ack) is not None


class SuspendHooks:
    """The hooks one gate calls when its agent is suspended.

    ``record`` is where each :class:`WorkerAck` goes; the default writes it to
    the ledger of the bound verdict recorder (:func:`record_worker_ack`).
    """

    def __init__(
        self,
        hooks: SuspendHook | Iterable[SuspendHook] | None = None,
        *,
        timeout_s: float = DEFAULT_HOOK_TIMEOUT_S,
        record: Callable[[SuspendNotice, WorkerAck], Any] | None = None,
    ) -> None:
        self._timeout_s = timeout_s
        self._record = record or record_worker_ack
        self._entries: list[_Entry] = []
        self._lock = threading.Lock()
        self._tasks: set[asyncio.Task[list[WorkerAck]]] = set()
        self._threads: set[threading.Thread] = set()
        self._acks: list[WorkerAck] = []
        if hooks is None:
            return
        if callable(hooks):
            self.add(hooks)
        else:
            for hook in hooks:
                self.add(hook)

    def add(
        self, hook: SuspendHook, *, name: str | None = None, timeout_s: float | None = None
    ) -> None:
        """Register ``hook``. ``name`` is what the record calls this worker."""
        if not callable(hook):
            raise TypeError(f"an on_suspend hook must be callable, not {type(hook).__name__}")
        with self._lock:
            self._entries.append(
                _Entry(name or _hook_name(hook), hook,
                       self._timeout_s if timeout_s is None else timeout_s)
            )

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def acks(self) -> list[WorkerAck]:
        """Every acknowledgement collected so far, oldest first."""
        with self._lock:
            return list(self._acks)

    # -- running -----------------------------------------------------------

    async def run(self, notice: SuspendNotice) -> list[WorkerAck]:
        """Call every hook at once and record each one's acknowledgement."""
        with self._lock:
            entries = list(self._entries)
        if not entries:
            return []
        acks = await asyncio.gather(*(self._run_one(e, notice) for e in entries))
        for ack in acks:
            with self._lock:
                self._acks.append(ack)
            try:
                self._record(notice, ack)
            except Exception:  # noqa: BLE001 - a lost record must not undo the stop
                log.exception("coriqo: could not record the acknowledgement of %s", ack.worker)
        return list(acks)

    async def _run_one(self, entry: _Entry, notice: SuspendNotice) -> WorkerAck:
        notified_at = utc_now()
        started = time.monotonic()

        def done(outcome: str, detail: str | None = None) -> WorkerAck:
            return WorkerAck(
                worker=entry.name,
                kind="hook",
                outcome=outcome,
                notified_at=notified_at,
                acknowledged_at=None if outcome == WorkerOutcome.TIMED_OUT else utc_now(),
                elapsed_s=round(time.monotonic() - started, 6),
                detail=detail,
            )

        async def call() -> Any:
            # A coroutine function, or an object whose __call__ is one.
            if inspect.iscoroutinefunction(entry.hook) or inspect.iscoroutinefunction(
                type(entry.hook).__call__
            ):
                return await entry.hook(notice)  # type: ignore[misc]
            result = await asyncio.to_thread(entry.hook, notice)
            if inspect.isawaitable(result):
                result = await result
            return result

        try:
            result = await asyncio.wait_for(call(), entry.timeout_s)
        except asyncio.TimeoutError:
            log.error(
                "coriqo: on_suspend hook %s did not return within %.0fs; recorded as "
                "timed out. The suspension still applies here.",
                entry.name, entry.timeout_s,
            )
            return done(WorkerOutcome.TIMED_OUT, f"no answer within {entry.timeout_s:g}s")
        except Exception as exc:  # noqa: BLE001 - any hook failure is recorded, not raised
            log.exception(
                "coriqo: on_suspend hook %s failed; the suspension still applies here",
                entry.name,
            )
            # The type only: a message can carry a hostname, a key, a payload.
            return done(WorkerOutcome.RAISED, type(exc).__name__)
        if isinstance(result, WorkerAck):
            return result
        return done(WorkerOutcome.RETURNED)

    def fire(self, notice: SuspendNotice) -> None:
        """Run the hooks without waiting for them.

        On the event loop when one is running in this thread (which is where
        the gate's refresh loop calls from); otherwise in a background thread
        with its own loop, so a synchronous caller is never held up.
        """
        if not len(self):
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            task = loop.create_task(self.run(notice))
            with self._lock:
                self._tasks.add(task)
            task.add_done_callback(self._forget_task)
            return
        # A thread does not inherit context variables; the bound verdict
        # recorder (where acknowledgements are written) is one.
        ctx = contextvars.copy_context()
        thread = threading.Thread(
            target=ctx.run, args=(self._run_in_thread, notice),
            name="coriqo-on-suspend", daemon=True,
        )
        with self._lock:
            self._threads.add(thread)
        thread.start()

    def _forget_task(self, task: asyncio.Task[list[WorkerAck]]) -> None:
        with self._lock:
            self._tasks.discard(task)

    def _run_in_thread(self, notice: SuspendNotice) -> None:
        try:
            asyncio.run(self.run(notice))
        except Exception:  # noqa: BLE001
            log.exception("coriqo: on_suspend hooks failed")
        finally:
            with self._lock:
                self._threads.discard(threading.current_thread())

    async def wait(self, timeout_s: float | None = None) -> bool:
        """Wait for hooks already fired to finish. True if they all did.

        For a process about to exit: without this, a hook still running on the
        loop is cancelled at shutdown and its acknowledgement is never written.
        """
        deadline = None if timeout_s is None else time.monotonic() + timeout_s
        while True:
            with self._lock:
                tasks = list(self._tasks)
                threads = list(self._threads)
            if not tasks and not threads:
                return True
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                return False
            if tasks:
                await asyncio.wait(tasks, timeout=remaining)
            else:
                step = 0.05 if remaining is None else min(0.05, remaining)
                await asyncio.sleep(step)
