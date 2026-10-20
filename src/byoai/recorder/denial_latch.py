"""The denial latch: what happens the *second* time an agent tries a denied tool.

:mod:`byoai.recorder.mandate` decides one call at a time, which leaves a hole
worth naming plainly. A denial stops the call it was about and nothing else, so
a model that ignores the refusal can attempt the same out-of-mandate tool for
as long as the loop keeps turning, and the record shows a row of identical
single denials with nothing tying them together. The interesting fact — *this
agent went at a control it had already been refused, four times in ninety
seconds* — is exactly the fact that fell on the floor.

The latch keeps it. It is keyed on ``(run_id, tool)`` and does three things:

**Refuses repeats without re-evaluating.** A tool already denied for this run
denies again straight from the latch — no scope check, no snapshot read. Partly
because it is cheaper, mostly because it is more honest: the same tool against
the same snapshot cannot decide differently, so re-running the check would only
be theatre. The verdict handed back is the *original* one, re-labelled
:data:`~byoai.recorder.mandate.Reason.REPEAT_DENIED`, so whatever seals it later
sees the mandate version the refusal was actually made against.

**Counts.** :attr:`LatchedDenial.attempts` is the count including this attempt,
and it is on the verdict path rather than only in a log line so that the packet
that seals verdicts can seal the count with them.

**Halts.** At :data:`DEFAULT_HALT_THRESHOLD` attempts the run is over: every
subsequent call *for that run* — any tool, not just the denied one — raises
:class:`~byoai.errors.MandateRunHaltedError`. That is a subclass of
``MandateDeniedError``, so existing handlers keep stopping the call, and an
``isinstance`` check is what tells a supervising loop "this tool is refused, try
another" from "stop scheduling turns for this run".

What deliberately does **not** change is the sentence the model sees. It is the
same fixed :data:`~byoai.recorder.mandate.MODEL_MESSAGE` on the first denial,
the repeat and the halt. Escalating the detail as the agent tries harder would
hand it a hint sheet at precisely the moment it is probing the control.

Which run is this? Which agent?
-------------------------------
:class:`~byoai.recorder.mandate.ProposedAction` carries ``trajectory_id``, and
when it is set that is the run. Failing that, :func:`run_scope` binds one for a
block of calls. When neither is present the two obvious answers are both wrong:
one shared bucket lets unrelated agents in a process halt each other, and no
bucket at all switches the latch off for every integrator who has not threaded
trajectory ids through yet — which on day one is most of them, and the ones who
most need it.

So the fallback identity is the **gate**. One :class:`~byoai.recorder.mandate.MandateGate`
is built per agent per run in every wiring this package encourages, which makes
it the closest thing to a run identity available when nobody named one, and two
gate objects are definitionally two different mandates. The id is held in a
:class:`weakref.WeakKeyDictionary`, so a finished run's bucket goes away with
its gate rather than accumulating. The known imprecision runs the safe way: an
application that reuses one long-lived gate across several sequential runs
shares one bucket until it names them, which latches too eagerly rather than too
late.

Buckets also carry the **principal** — the agent id — alongside the run, because
a delegated sub-agent and its delegator share a run and do not share a scope. A
child's denial must not latch a tool the parent may legitimately still call. The
halt is the exception and is deliberately run-wide: once a run is over, which
agent asks next is beside the point.

Two limits, stated rather than hidden
-------------------------------------
Latch state is per-process and in memory. A run that spans two processes, or a
host that restarts mid-run, starts counting from zero. Persisting it is not
attempted here.

And a process that runs forever cannot remember every run it ever saw, so a
latch keeps at most :data:`DEFAULT_MAX_RUNS` runs and drops the oldest first.
The eviction order is insertion order, which is close enough to age for the
purpose: the runs at risk of being forgotten are the ones that stopped calling
tools a long time ago.
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
import weakref
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, replace

from .mandate import Deny, ProposedAction, Reason

__all__ = [
    "DEFAULT_HALT_THRESHOLD",
    "DEFAULT_MAX_RUNS",
    "LATCHABLE_REASONS",
    "DenialLatch",
    "LatchedDenial",
    "UNIDENTIFIED",
    "current_run_id",
    "denial_latch",
    "is_latchable",
    "resolve_principal",
    "resolve_run_id",
    "run_scope",
    "set_denial_latch",
    "use_denial_latch",
]

log = logging.getLogger(__name__)

#: Attempts at one already-denied tool before the run is halted, counting the
#: first denial. Three, because two is inside the range of an honest retry
#: (a framework re-issuing a turn, a model rephrasing once) and four already
#: means the agent has spent a while working the control.
DEFAULT_HALT_THRESHOLD = 3

_ENV_THRESHOLD = "BYOAI_MANDATE_HALT_THRESHOLD"

#: Runs a latch remembers before it drops the oldest. A bound, not a tuning
#: knob: without one a long-lived process accumulates a bucket per run forever.
DEFAULT_MAX_RUNS = 1024

#: The only denials worth latching: the ones that are decisions about scope.
#:
#: A suspension is lifted, a stale snapshot refreshes, a first snapshot arrives —
#: all three deny under ``fail_closed`` and all three are *transient*, so
#: remembering them would turn one refresh blip into a permanently halted run,
#: which is the outage the refresh path was written to avoid. Only "this tool is
#: not in the approved scope" is a decision that cannot change while the mandate
#: does not.
LATCHABLE_REASONS = frozenset(
    {Reason.OUT_OF_SCOPE, Reason.DELEGATED_OUT_OF_SCOPE}
)


def is_latchable(verdict: Deny) -> bool:
    """Whether ``verdict`` is a scope decision, and so safe to remember."""
    return verdict.reason in LATCHABLE_REASONS

#: Set by :func:`run_scope` — the run id for calls that do not carry one.
_run_id: ContextVar[str | None] = ContextVar("byoai_mandate_run_id", default=None)

#: Fallback run ids, one per gate, for calls that name no run at all. Weak so a
#: finished run's bucket is collected with its gate.
_gate_run_ids: weakref.WeakKeyDictionary[object, str] = weakref.WeakKeyDictionary()
_gate_run_lock = threading.Lock()

#: The principal recorded for a gate that does not know its own agent id.
UNIDENTIFIED = "unidentified-agent"


def _env_threshold() -> int:
    raw = (os.getenv(_ENV_THRESHOLD) or "").strip()
    if not raw:
        return DEFAULT_HALT_THRESHOLD
    try:
        value = int(raw)
    except ValueError:
        log.warning(
            "coriqo: %s=%r is not an integer; using the default of %d",
            _ENV_THRESHOLD,
            raw,
            DEFAULT_HALT_THRESHOLD,
        )
        return DEFAULT_HALT_THRESHOLD
    if value < 1:
        log.warning(
            "coriqo: %s=%d is below 1; using the default of %d",
            _ENV_THRESHOLD,
            value,
            DEFAULT_HALT_THRESHOLD,
        )
        return DEFAULT_HALT_THRESHOLD
    return value


# -- which run ---------------------------------------------------------------


@contextmanager
def run_scope(run_id: str) -> Iterator[str]:
    """Name the run for calls made inside the block.

    For integrators whose tool functions do not receive a trajectory id: bind it
    once around the agent's turn and every governed call inside gets the right
    latch bucket.
    """
    token = _run_id.set(run_id)
    try:
        yield run_id
    finally:
        _run_id.reset(token)


def current_run_id() -> str | None:
    """The run id bound by :func:`run_scope`, if any. Never invents one."""
    return _run_id.get()


def resolve_run_id(action: ProposedAction | str, gate: object | None = None) -> str:
    """The run this call belongs to: its trajectory id, the bound run, or the
    gate's own fallback id."""
    if isinstance(action, ProposedAction) and action.trajectory_id:
        return action.trajectory_id
    bound = _run_id.get()
    if bound:
        return bound
    if gate is None:
        return "anon-run-" + uuid.uuid4().hex[:16]
    with _gate_run_lock:
        run_id = _gate_run_ids.get(gate)
        if run_id is None:
            run_id = "gate-run-" + uuid.uuid4().hex[:16]
            _gate_run_ids[gate] = run_id
        return run_id


def resolve_principal(gate: object | None) -> str:
    """Which agent is asking. Delegator and delegated child share a run and must
    not share a bucket."""
    agent_id = getattr(gate, "agent_id", None)
    return str(agent_id) if agent_id else UNIDENTIFIED


# -- the latch ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class LatchedDenial:
    """One refusal served from the latch rather than from the scope check."""

    run_id: str
    #: The agent that asked — a delegated child is not its delegator.
    principal: str
    tool: str
    #: Attempts at this tool in this run, including the one being refused.
    attempts: int
    #: True once the threshold is reached: the run, not just the call, is over.
    halted: bool
    #: The original denial, re-labelled. Carries the mandate version the refusal
    #: was actually decided against.
    verdict: Deny

    @property
    def reason(self) -> str:
        return self.verdict.reason


class DenialLatch:
    """Per-process memory of which tools have already been denied, per run.

    Buckets are ``(run_id, principal, tool)``; the halt is per ``run_id``,
    because a halted run is over for everyone working inside it.

    Safe to share across threads: everything mutating goes through one lock, and
    the objects handed out are frozen.
    """

    def __init__(
        self, *, threshold: int | None = None, max_runs: int = DEFAULT_MAX_RUNS
    ) -> None:
        self._threshold = _env_threshold() if threshold is None else max(1, threshold)
        self._max_runs = max(1, max_runs)
        self._lock = threading.Lock()
        #: Insertion-ordered, so the oldest run is the first key.
        self._runs: dict[str, None] = {}
        #: The mandate version each principal's buckets were decided against.
        #: Keyed per principal, not per run: a run legitimately holds a
        #: delegator and a delegated child, whose versions differ, and keying it
        #: on the run alone would have each of them wipe the other's buckets on
        #: every call — which defeats the latch entirely for anyone who has a
        #: sub-agent.
        self._versions: dict[tuple[str, str], str | None] = {}
        self._attempts: dict[tuple[str, str, str], int] = {}
        self._first: dict[tuple[str, str, str], Deny] = {}
        self._halted: dict[str, tuple[str, str, int]] = {}

    @property
    def threshold(self) -> int:
        return self._threshold

    # -- reads -------------------------------------------------------------

    def attempts(self, run_id: str, principal: str, tool: str) -> int:
        """How many times ``tool`` has been attempted after a denial in this
        run, by this principal. 0 if it was never denied."""
        with self._lock:
            return self._attempts.get((run_id, principal, tool), 0)

    def is_halted(self, run_id: str) -> bool:
        with self._lock:
            return run_id in self._halted

    def halted_by(self, run_id: str) -> tuple[str, str, int] | None:
        """``(principal, tool, attempts)`` that halted ``run_id``, or ``None``."""
        with self._lock:
            return self._halted.get(run_id)

    # -- writes ------------------------------------------------------------

    def record(
        self,
        run_id: str,
        principal: str,
        verdict: Deny,
        mandate_version_id: str | None = None,
    ) -> LatchedDenial:
        """Register a freshly evaluated denial and return what it means.

        Called with the verdict the gate just produced; the returned
        :class:`LatchedDenial` says whether that denial also ended the run. A
        denial that is not a scope decision (see :data:`LATCHABLE_REASONS`) is
        counted as one attempt and remembered as nothing, because it is not a
        decision that will hold still.
        """
        tool = verdict.tool or "?"
        if not is_latchable(verdict):
            return LatchedDenial(
                run_id=run_id,
                principal=principal,
                tool=tool,
                attempts=1,
                halted=False,
                verdict=verdict,
            )
        key = (run_id, principal, tool)
        with self._lock:
            self._reconcile_version(run_id, principal, mandate_version_id)
            attempts = self._attempts.get(key, 0) + 1
            self._attempts[key] = attempts
            self._first.setdefault(key, verdict)
            # TI-20 on_violation: deny_and_halt_run ends the run on the first
            # scope denial rather than at the repeat threshold.
            halted = attempts >= self._threshold or verdict.halt_run
            if halted:
                self._halted.setdefault(run_id, (principal, tool, attempts))
            self._touch(run_id)
        return LatchedDenial(
            run_id=run_id,
            principal=principal,
            tool=tool,
            attempts=attempts,
            halted=halted,
            verdict=verdict,
        )

    def check(
        self,
        run_id: str,
        principal: str,
        tool: str,
        mandate_version_id: str | None = None,
    ) -> LatchedDenial | None:
        """Refuse from memory, or return ``None`` to let the gate decide.

        Two cases refuse here. A halted run refuses *every* tool, because the run
        is over and what it asked for next is beside the point. A tool already
        denied for this principal in this run refuses without re-evaluating
        scope: the same tool against the same snapshot cannot answer differently.

        ``mandate_version_id`` is the version in hand *now*. When it differs from
        the one the run's buckets were decided against, the buckets go and the
        gate decides again — that is the one case where the answer can have
        changed.
        """
        with self._lock:
            self._reconcile_version(run_id, principal, mandate_version_id)
            halt = self._halted.get(run_id)
            if halt is not None:
                halt_principal, halt_tool, halt_attempts = halt
                original = self._first.get((run_id, halt_principal, halt_tool))
                self._touch(run_id)
                # No per-tool bucket is written here. The run is already over,
                # and a halted loop calling a fresh tool name every turn would
                # otherwise grow this dict without end.
                verdict = _halt_verdict(
                    original,
                    tool=tool,
                    detail=(
                        f"run {run_id} was halted after {halt_attempts} attempts at "
                        f"{halt_tool!r} by {halt_principal}; {tool!r} refused "
                        "without evaluation"
                    ),
                )
                latched = LatchedDenial(
                    run_id=run_id,
                    principal=principal,
                    tool=tool,
                    attempts=halt_attempts,
                    halted=True,
                    verdict=verdict,
                )
            else:
                key = (run_id, principal, tool)
                original = self._first.get(key)
                if original is None:
                    return None
                attempts = self._attempts.get(key, 0) + 1
                self._attempts[key] = attempts
                halted = attempts >= self._threshold
                if halted:
                    self._halted.setdefault(run_id, (principal, tool, attempts))
                self._touch(run_id)
                verdict = _relabel(
                    original,
                    tool=tool,
                    reason=Reason.RUN_HALTED if halted else Reason.REPEAT_DENIED,
                    detail=(
                        f"{tool!r} was already denied in run {run_id}; attempt "
                        f"{attempts} refused from the latch without re-evaluating "
                        "scope"
                        + (
                            f", halting the run at threshold {self._threshold}"
                            if halted
                            else ""
                        )
                    ),
                )
                latched = LatchedDenial(
                    run_id=run_id,
                    principal=principal,
                    tool=tool,
                    attempts=attempts,
                    halted=halted,
                    verdict=verdict,
                )
        log.warning(
            "coriqo: refused from the denial latch - run=%s agent=%s tool=%r "
            "attempts=%d threshold=%d halted=%s",
            run_id,
            principal,
            tool,
            latched.attempts,
            self._threshold,
            latched.halted,
        )
        return latched

    def _touch(self, run_id: str) -> None:
        """Mark ``run_id`` as the most recently seen, evicting the oldest runs
        once the cap is passed. Caller holds the lock."""
        self._runs.pop(run_id, None)
        self._runs[run_id] = None
        while len(self._runs) > self._max_runs:
            oldest = next(iter(self._runs))
            self._forget(oldest)

    def _reconcile_version(
        self, run_id: str, principal: str, version: str | None
    ) -> None:
        """Drop a principal's buckets when the mandate underneath them changed.

        The latch's licence to refuse without re-evaluating is that the answer
        cannot have changed. A new mandate version is precisely the case where it
        can have: someone approved something. So that principal starts again —
        and the run's halt goes too, but only if it was *this* principal that
        halted it, because one agent's new mandate says nothing about what
        another agent did. Caller holds the lock.
        """
        key = (run_id, principal)
        if key not in self._versions:
            self._versions[key] = version
            return
        if self._versions[key] == version:
            return
        self._forget_principal(run_id, principal)
        self._versions[key] = version

    def _forget_principal(self, run_id: str, principal: str) -> None:
        """Caller holds the lock."""
        for key in [
            k for k in self._attempts if k[0] == run_id and k[1] == principal
        ]:
            self._attempts.pop(key, None)
            self._first.pop(key, None)
        halt = self._halted.get(run_id)
        if halt is not None and halt[0] == principal:
            self._halted.pop(run_id, None)

    def _forget(self, run_id: str) -> None:
        """Caller holds the lock."""
        for key in [k for k in self._versions if k[0] == run_id]:
            self._versions.pop(key, None)
        self._runs.pop(run_id, None)
        self._halted.pop(run_id, None)
        for key in [k for k in self._attempts if k[0] == run_id]:
            self._attempts.pop(key, None)
            self._first.pop(key, None)

    def reset(self, run_id: str | None = None) -> None:
        """Forget one run, or all of them. For tests, and for a supervisor that
        has taken its own decision about a halted run."""
        with self._lock:
            if run_id is None:
                self._attempts.clear()
                self._first.clear()
                self._halted.clear()
                self._runs.clear()
                self._versions.clear()
                return
            self._forget(run_id)


def _halt_verdict(original: Deny | None, *, tool: str, detail: str) -> Deny:
    """The verdict for a call on a run that is already over.

    Deliberately *not* the halting denial relabelled. That denial belongs to
    another principal and another tool, and carrying its ``mandate_version_id``
    or ``step_index`` across would have a sealed record claim agent B's call was
    decided against agent A's mandate. Only ``posture`` and ``enforcement``
    survive, because those describe the runtime and the tenant rather than
    whoever was refused.
    """
    if original is None:  # pragma: no cover - only if a halt outlives its cause
        return Deny(reason=Reason.RUN_HALTED, tool=tool, detail=detail)
    return Deny(
        reason=Reason.RUN_HALTED,
        tool=tool,
        posture=original.posture,
        enforcement=original.enforcement,
        detail=detail,
    )


def _relabel(original: Deny | None, *, tool: str, reason: str, detail: str) -> Deny:
    """The stored denial, re-labelled — never a richer one.

    ``mandate_version_id``, ``posture`` and ``enforcement`` come from the
    evaluation that actually happened, so a sealed repeat points at the mandate
    the refusal was made against rather than at whatever is cached now.
    """
    if original is None:  # pragma: no cover - only if a halt outlives its cause
        return Deny(reason=reason, tool=tool, detail=detail)
    return replace(original, reason=reason, tool=tool, detail=detail)


# -- the process-wide latch --------------------------------------------------

_DEFAULT_LATCH = DenialLatch()
_latch: ContextVar[DenialLatch | None] = ContextVar(
    "byoai_denial_latch", default=None
)


def denial_latch() -> DenialLatch:
    """The latch in force here. Process-wide unless :func:`use_denial_latch`
    or :func:`set_denial_latch` bound another."""
    return _latch.get() or _DEFAULT_LATCH


def set_denial_latch(latch: DenialLatch | None):  # noqa: ANN201 - Token[...] alias
    """Bind ``latch`` for this context. Returns the token, to ``reset()``."""
    return _latch.set(latch)


@contextmanager
def use_denial_latch(latch: DenialLatch | None) -> Iterator[DenialLatch]:
    """Bind ``latch`` for the block, then restore the previous one."""
    token = _latch.set(latch)
    try:
        yield latch or _DEFAULT_LATCH
    finally:
        _latch.reset(token)
