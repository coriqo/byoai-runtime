"""The local mandate gate: does this agent's approved scope permit this tool?

Coriqo holds the approved mandate. This module enforces it *here*, inside the
agent's own process, from a cached snapshot refreshed on a background interval.

The one constraint everything else follows from: **the decide path performs no
network I/O.** Asking Coriqo synchronously before every tool call would make
the agent's availability a function of Coriqo's, and no regulated buyer ships
an agent that stops working because a governance service is redeploying. So
:meth:`MandateGate.decide` reads an immutable in-memory snapshot and returns;
:meth:`MandateGate.refresh` is what talks to the network, on a schedule
comfortably inside the snapshot's own ``max_staleness_s``.

Two server fields, two different questions
------------------------------------------
``mandate_enforcement`` (``enforce`` | ``observe``) answers *does a scope
breach count as a violation* — it is the tenant's rollout dial, and ``observe``
is how a bank watches what an agent would have been blocked from doing before
turning the block on.

``enforcement_posture`` (``fail_open`` | ``fail_closed``) answers a question
about this runtime, not about the agent: *what happens when we cannot
evaluate*. They are not the same dial and collapsing them loses the ability to
run an observing agent under a fail-closed posture, which is exactly the
configuration a first rollout wants.

============================================  ==============  ===============
Situation                                     fail_open       fail_closed
============================================  ==============  ===============
fresh, tool in scope                          allow           allow
fresh, out of scope, ``enforce``              deny            deny
fresh, out of scope, ``observe``              allow + flag    allow + flag
stale past ``max_staleness_s``                allow + flag    **deny**
agent suspended                               **deny**        **deny**
no snapshot ever fetched                      allow + flag    **deny**
============================================  ==============  ===============

Suspension denies under both postures: a suspension is a decision Coriqo
already made and this runtime read, not a failure to evaluate. And what trips
the fail-closed branch is *staleness*, not network reachability — a bounded,
configured budget rather than an incidental one. A gate that denied the moment
a request failed would turn every blip into an outage; this one keeps serving
the snapshot it has until that snapshot is older than the tenant said it may
be.

Fields a mandate file adds (TI-20)
----------------------------------
A snapshot carries four more keys when the agent's approved mandate came from
a ``coriqo.mandate.yaml`` that set them, and leaves them out otherwise. Absent,
each one reproduces the behaviour from before it existed:

- ``prohibited_tools``: tools that are outside the mandate whatever else is
  allowed, including when there is no allow-list (``allowed_tools: null``).
  Absent means none.
- ``on_violation``: what a scope violation does under ``enforce``. ``deny``
  (absent) refuses the call; ``deny_and_halt_run`` refuses it and ends the run
  on the first attempt rather than the latch's threshold; ``alert_only``
  allows it and flags it. ``observe`` still blocks nothing, whatever this says.
- ``environment``: where the mandate applies. A gate told which environment it
  runs in (``environment=`` or ``BYOAI_MANDATE_ENVIRONMENT``) treats a mandate
  for another environment as no mandate at all, so the posture decides. A gate
  told nothing does not compare.
- ``output_inspection``: parsed and kept, not acted on yet.

``allowed_tools``: null is not empty
------------------------------------
``null`` means **unrestricted** — no scope constraint on this agent.
``[]`` means **nothing is permitted**. Both are valid on the wire and they are
opposite instructions, so :class:`MandateSnapshot` keeps them apart (``None``
vs ``()``) and never uses a falsy test to tell them apart. Coercing ``null``
into ``[]`` blocks a legitimately unrestricted agent; coercing the other way
opens an agent that was explicitly permitted nothing.

Denials are terminal, and quiet
-------------------------------
A :class:`Deny` is not a tool error. If a denial reaches the model as an
ordinary failure — worse, one naming the tool and the scope — the model does
what a competent agent should do with a failure: rephrase, try an adjacent
tool, and route around the control. So a ``Deny`` carries a single fixed
:data:`MODEL_MESSAGE` for anything the model may see, and everything an
operator needs (which tool, which mandate version, how stale, why) stays in
:attr:`Verdict.detail` and the logs.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from byoai.errors import ByoAIError

from .identity import CoriqoIdentity, resolve_identity

__all__ = [
    "BLOCKING_STATUSES",
    "DEFAULT_MAX_STALENESS_S",
    "MODEL_MESSAGE",
    "Allow",
    "Deny",
    "Enforcement",
    "Flag",
    "MandateGate",
    "MandateSnapshot",
    "Posture",
    "ProposedAction",
    "Reason",
    "RequireApproval",
    "Verdict",
    "ViolationAction",
    "approval_request_id",
    "coriqo_mandate_source",
    "mandate_gate",
]

log = logging.getLogger(__name__)

#: Staleness budget used until a snapshot names its own ``max_staleness_s``.
DEFAULT_MAX_STALENESS_S = 300.0

#: Fraction of the staleness budget the refresh interval targets. Half leaves
#: room for one whole failed refresh (plus its retries) before the snapshot
#: a fail-closed agent depends on ages out.
REFRESH_FRACTION = 0.5

#: Floor on the refresh interval, so a tenant setting a very small staleness
#: budget cannot turn the loop into a busy poll against Coriqo.
MIN_REFRESH_INTERVAL_S = 1.0

#: AD-10: cap on MandateGate._reported_approval_requests, a per-gate dedup
#: set that otherwise grows for the lifetime of the process — see
#: MandateGate._mark_approval_reported.
_MAX_REPORTED_APPROVAL_REQUESTS = 10_000

#: AD-11: the rolling window max_calls_per_minute is measured over. Fixed at
#: 60s rather than derived from the name being configurable, since the wire
#: field itself is called max_calls_per_minute.
_CALL_RATE_WINDOW_S = 60.0

#: AD-11: hard cap on how many distinct trajectories this gate tracks
#: step/cost state for. A trajectory is not otherwise ever "finished" from
#: the gate's point of view, so without a cap a host running many short
#: trajectories over a long process lifetime would leak one dict entry per
#: trajectory forever.
_MAX_TRACKED_TRAJECTORIES = 10_000

#: The only thing a denial ever says where a model can read it. Fixed, and
#: deliberately uninformative: anything richer is a hint sheet for routing
#: around the control.
MODEL_MESSAGE = "This action is not permitted."

#: Agent states that deny outright, under either posture. These are decisions
#: Coriqo made, not failures to evaluate.
BLOCKING_STATUSES = frozenset({"suspended", "retired", "revoked", "decommissioned"})


class Posture:
    """What happens when the gate cannot evaluate."""

    FAIL_OPEN = "fail_open"
    FAIL_CLOSED = "fail_closed"


class Enforcement:
    """Whether a scope breach counts as a violation."""

    ENFORCE = "enforce"
    OBSERVE = "observe"


class Reason:
    """Operator-facing reason codes. Stable strings — they end up in records."""

    IN_SCOPE = "in_scope"
    UNRESTRICTED = "unrestricted"
    OUT_OF_SCOPE = "out_of_scope"
    OUT_OF_SCOPE_OBSERVED = "out_of_scope_observed"
    SNAPSHOT_STALE = "snapshot_stale"
    NO_SNAPSHOT = "no_snapshot"
    AGENT_SUSPENDED = "agent_suspended"
    ENFORCEMENT_UNCONFIGURED = "enforcement_unconfigured"
    #: A tool already denied for this run, refused from the latch without
    #: re-evaluating scope: the answer cannot have changed.
    REPEAT_DENIED = "repeat_denied"
    #: The repeat threshold was reached and the run is over.
    RUN_HALTED = "run_halted"
    #: Inside the delegated agent's own mandate, outside the scope it was
    #: delegated — the intersection, not the child's standing mandate.
    DELEGATED_OUT_OF_SCOPE = "delegated_out_of_scope"
    DELEGATED_OUT_OF_SCOPE_OBSERVED = "delegated_out_of_scope_observed"
    #: The proxy could not tell which agent a request belongs to, so it has no
    #: mandate to decide against. Config, not scope — never latched.
    AGENT_UNRESOLVED = "agent_unresolved"
    #: AD-10: the tool is on the mandate's approval_required_tools list and no
    #: decision has come back yet — denied for now, not a failure to evaluate.
    APPROVAL_REQUIRED = "approval_required"
    #: W-7: the snapshot carries ``reassessment_required: true`` — Coriqo saw
    #: this agent's loaded capabilities drift from what its mandate was last
    #: reviewed against, and wants a human to look before more calls run.
    #: Denied under fail_closed; only flagged (still allowed) under
    #: fail_open/observe, same split as SNAPSHOT_STALE.
    REASSESSMENT_REQUIRED = "reassessment_required"
    #: AD-10: a human approved this exact request_id — this ONE call proceeds;
    #: a later call to the same tool starts as approval_required again.
    APPROVAL_GRANTED = "approval_granted"
    #: AD-10: a human denied this exact request_id.
    APPROVAL_REFUSED = "approval_refused"
    #: AD-11: enforced budgets — checked locally, same tier as scope/
    #: suspension, not a failure to evaluate.
    BUDGET_COST_EXCEEDED = "budget_cost_exceeded"
    BUDGET_CALL_RATE_EXCEEDED = "budget_call_rate_exceeded"
    BUDGET_STEP_LIMIT_EXCEEDED = "budget_step_limit_exceeded"
    #: TI-20: the snapshot names an ``environment`` and this gate was told it
    #: runs somewhere else. That mandate is not for here, so the gate has
    #: nothing it can stand behind and the posture decides, as for
    #: NO_SNAPSHOT.
    ENVIRONMENT_MISMATCH = "environment_mismatch"


class ViolationAction:
    """TI-20 ``on_violation``: what a scope violation does under ``enforce``."""

    DENY = "deny"
    DENY_AND_HALT_RUN = "deny_and_halt_run"
    ALERT_ONLY = "alert_only"


class DelegationPolicy:
    """Whether an agent may hand work to another agent at all."""

    NONE = "none"
    ATTENUATED = "attenuated"


class MandateError(ByoAIError):
    """A mandate snapshot could not be understood."""


# -- what is being asked -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProposedAction:
    """One tool call, before it runs.

    ``trajectory_id``/``step_index`` are carried through to the verdict so the
    packet that records verdicts can seal one onto the right run without
    re-deriving where it came from.
    """

    tool: str
    trajectory_id: str | None = None
    step_index: int | None = None
    arguments: Mapping[str, Any] | None = None

    def __repr__(self) -> str:
        """Never renders ``arguments``.

        A tool's arguments can hold anything the caller passed it, credentials
        included. The dataclass-generated repr would put all of it into any log
        line, traceback or f-string that formats this object — including one an
        integrator writes back into a model's context. The count is enough to
        tell you whether they were captured; read ``.arguments`` deliberately
        when you actually want them.
        """
        n = None if self.arguments is None else len(self.arguments)
        return (
            f"ProposedAction(tool={self.tool!r}, trajectory_id={self.trajectory_id!r}, "
            f"step_index={self.step_index!r}, arguments=<{n} captured>)"
        )


# -- the verdicts ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Verdict:
    """Base of the three verdicts. Never returned directly.

    ``Allow`` and its subclass ``Flag`` both permit the call — a flagged allow
    is "this ran, and it was off-mandate" — so ``isinstance(v, Allow)`` is the
    honest test for *may this proceed*, and :attr:`allowed` says the same thing
    without an import.
    """

    reason: str
    mandate_version_id: str | None = None
    snapshot_age_s: float | None = None
    tool: str | None = None
    posture: str = Posture.FAIL_OPEN
    enforcement: str | None = None
    trajectory_id: str | None = None
    step_index: int | None = None
    #: Operator-facing only. Never put this in a string bound for the model.
    detail: str | None = None
    #: TI-20: set on a scope denial under ``on_violation: deny_and_halt_run``.
    #: The denial latch reads it and halts the run on this first attempt
    #: instead of waiting for its repeat threshold.
    halt_run: bool = False

    def __repr__(self) -> str:
        """Never renders ``detail``.

        ``detail`` says which tool fell outside which mandate — exactly the
        hint sheet a model would need to route around the control, and the
        dataclass-generated repr would hand it to any f-string that formats a
        verdict. ``MandateDeniedError`` already keeps it out of ``str()`` and
        ``repr()``; this closes the same hole one level down, for the verdict
        object itself. Read ``.detail`` explicitly when logging for an operator.
        """
        return (
            f"{type(self).__name__}(reason={self.reason!r}, tool={self.tool!r}, "
            f"verdict={getattr(type(self), '_verdict_word', None)!r}, "
            f"mandate_version_id={self.mandate_version_id!r}, "
            f"snapshot_age_s={self.snapshot_age_s!r}, posture={self.posture!r}, "
            f"enforcement={self.enforcement!r}, detail=<redacted>)"
        )

    @property
    def allowed(self) -> bool:
        raise NotImplementedError  # pragma: no cover - abstract

    @property
    def flagged(self) -> bool:
        """Whether this verdict is worth an operator's attention."""
        return False

    @property
    def verdict(self) -> str:
        """The word Coriqo records: ``allowed``, ``flagged`` or ``blocked``."""
        raise NotImplementedError  # pragma: no cover - abstract


# repr=False so the redacting Verdict.__repr__ is inherited rather than
# regenerated by @dataclass — a generated one would print `detail`.
@dataclass(frozen=True, slots=True, repr=False)
class Allow(Verdict):
    """The call may proceed."""

    _verdict_word = "allowed"

    @property
    def allowed(self) -> bool:
        return True

    @property
    def verdict(self) -> str:
        return "allowed"


# repr=False so the redacting Verdict.__repr__ is inherited rather than
# regenerated by @dataclass — a generated one would print `detail`.
@dataclass(frozen=True, slots=True, repr=False)
class Flag(Allow):
    """The call may proceed, and something about it needs recording.

    A subclass of :class:`Allow` on purpose: an off-mandate call under
    ``observe``, or any call decided from a snapshot the gate is not sure of,
    still runs. Only the record differs.
    """

    _verdict_word = "flagged"

    @property
    def flagged(self) -> bool:
        return True

    @property
    def verdict(self) -> str:
        return "flagged"


# repr=False so the redacting Verdict.__repr__ is inherited rather than
# regenerated by @dataclass — a generated one would print `detail`.
@dataclass(frozen=True, slots=True, repr=False)
class Deny(Verdict):
    """The call must not proceed. Terminal, and non-retryable by construction.

    There is nothing here for a caller to vary and try again: the same action
    against the same snapshot denies again, and the only text the model may see
    is the fixed :attr:`model_message`.
    """

    _verdict_word = "blocked"

    @property
    def allowed(self) -> bool:
        return False

    @property
    def flagged(self) -> bool:
        return True

    @property
    def verdict(self) -> str:
        return "blocked"

    @property
    def model_message(self) -> str:
        """The one sentence a denial may put in front of a model.

        Fixed regardless of why the denial happened. A denial that explained
        itself — "tool ``rm`` is not in mandate v3, which allows ``search``" —
        would be a working set of instructions for getting the job done another
        way.
        """
        return MODEL_MESSAGE


# repr=False so the redacting Verdict.__repr__ is inherited rather than
# regenerated by @dataclass — a generated one would print `detail`.
@dataclass(frozen=True, slots=True, repr=False)
class RequireApproval(Verdict):
    """AD-10: the tool is on the mandate's approval_required_tools list and
    no decision has come back for THIS exact call yet. Denied for now — not
    a failure to evaluate, and not the same shape as :class:`Deny`: unlike a
    scope violation, the SAME action against the SAME snapshot may allow on
    a later decide() once a human resolves it, because a resolution changes
    ``resolved_approvals`` in the cached snapshot itself (delivered on the
    next scheduled fetch, not a live round trip — see MandateGate.decide()).

    ``request_id`` is deterministic — a stable hash of
    (tool, trajectory_id, step_index) — so retrying the identical call
    reports the same pending request rather than minting a new one each
    time, and resolves to the same verdict once Coriqo's decision lands."""

    _verdict_word = "pending_approval"
    request_id: str = ""

    @property
    def allowed(self) -> bool:
        return False

    @property
    def flagged(self) -> bool:
        return True

    @property
    def verdict(self) -> str:
        return "pending_approval"

    @property
    def model_message(self) -> str:
        """Same fixed-message rule as :class:`Deny` — nothing here should
        read to the model as negotiable or retriable with different
        arguments; only a human decision changes the outcome."""
        return MODEL_MESSAGE


# -- the snapshot ------------------------------------------------------------


def _coerce_float(value: Any, fallback: float) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return fallback
    return number if number > 0 else fallback


@dataclass(frozen=True, slots=True)
class MandateSnapshot:
    """One immutable copy of what Coriqo said this agent's mandate is.

    Immutable so :meth:`MandateGate.decide` can read it from any thread without
    a lock held across the evaluation: publishing a new snapshot swaps a
    reference, it never mutates one a decide is mid-way through reading.
    """

    #: ``None`` means *unrestricted*. ``()`` means *nothing is permitted*.
    #: These are opposite instructions; see the module docstring.
    allowed_tools: tuple[str, ...] | None = None
    #: AD-10: tools that are neither allowed nor denied outright — a call to
    #: one of these gets RequireApproval instead of Allow/Deny. Disjoint from
    #: allowed_tools in practice, but not asserted so here; Coriqo owns that.
    approval_required_tools: tuple[str, ...] = ()
    #: AD-10: {request_id: "approved"|"denied"} for requests Coriqo resolved
    #: recently — how a RequireApproval verdict turns into Allow/Deny on a
    #: LATER decide() for the identical call, without any live round trip.
    resolved_approvals: Mapping[str, str] = field(default_factory=dict)
    #: AD-11: enforced budgets — `None` on any of these three means
    #: unrestricted on that dimension, same convention as `allowed_tools`.
    max_run_cost_usd: float | None = None
    max_calls_per_minute: int | None = None
    max_run_steps: int | None = None
    mandate_version_id: str | None = None
    status: str | None = None
    mandate_enforcement: str = Enforcement.ENFORCE
    enforcement_posture: str = Posture.FAIL_OPEN
    max_staleness_s: float = DEFAULT_MAX_STALENESS_S
    delegation_policy: str | None = None
    max_delegation_depth: int | None = None
    served_at: str | None = None
    #: W-7: capability-attestation drift flag. Not present in every schema
    #: version this runtime may talk to — a Coriqo that predates the
    #: capability-versioning work simply never sends it, and this defaults to
    #: False, the same "nothing to see here" reading as its absence. See
    #: Reason.REASSESSMENT_REQUIRED and the TODO on MandateGate.decide().
    reassessment_required: bool = False
    #: TI-20 fields, present on the wire only when a mandate file set them.
    #: Their defaults are the behaviour from before they existed.
    prohibited_tools: tuple[str, ...] = ()
    on_violation: str = ViolationAction.DENY
    environment: str | None = None
    #: Parsed and kept for TI-24; nothing reads it yet.
    output_inspection: Mapping[str, Any] = field(default_factory=dict)
    #: Monotonic reading from when this snapshot was received. Monotonic, not
    #: wall clock, so an NTP correction mid-run cannot make a snapshot look
    #: fresher (or older) than it is.
    received_at: float = 0.0
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_payload(
        cls, payload: Mapping[str, Any], *, received_at: float
    ) -> MandateSnapshot:
        if not isinstance(payload, Mapping):
            raise MandateError("mandate snapshot was not an object")

        tools: tuple[str, ...] | None = None
        raw_tools = payload.get("allowed_tools")
        if raw_tools is not None:
            # An explicit list — including an empty one, which permits nothing.
            if isinstance(raw_tools, str) or not isinstance(raw_tools, Iterable):
                raise MandateError(
                    f"allowed_tools must be a list or null, got {type(raw_tools).__name__}"
                )
            tools = tuple(str(tool) for tool in raw_tools)

        approval_tools: tuple[str, ...] = ()
        raw_approval_tools = payload.get("approval_required_tools")
        if raw_approval_tools:
            approval_tools = tuple(str(tool) for tool in raw_approval_tools)

        prohibited: tuple[str, ...] = ()
        raw_prohibited = payload.get("prohibited_tools")
        if raw_prohibited is not None:
            if isinstance(raw_prohibited, str) or not isinstance(raw_prohibited, Iterable):
                raise MandateError(
                    "prohibited_tools must be a list, got "
                    f"{type(raw_prohibited).__name__}"
                )
            prohibited = tuple(str(tool) for tool in raw_prohibited)

        on_violation = _opt_str(payload.get("on_violation")) or ViolationAction.DENY
        if on_violation not in {
            ViolationAction.DENY,
            ViolationAction.DENY_AND_HALT_RUN,
            ViolationAction.ALERT_ONLY,
        }:
            # An unknown word must not loosen anything: read it as the strictest
            # plain answer, refuse the call, and say so to the operator.
            log.warning(
                "coriqo: unknown on_violation %r in the mandate snapshot; "
                "treating it as deny",
                on_violation,
            )
            on_violation = ViolationAction.DENY

        raw_inspection = payload.get("output_inspection")
        inspection = dict(raw_inspection) if isinstance(raw_inspection, Mapping) else {}

        resolved: dict[str, str] = {}
        raw_resolved = payload.get("resolved_approvals")
        if isinstance(raw_resolved, Mapping):
            resolved = {str(k): str(v) for k, v in raw_resolved.items()}

        return cls(
            allowed_tools=tools,
            approval_required_tools=approval_tools,
            resolved_approvals=resolved,
            max_run_cost_usd=_opt_float(payload.get("max_run_cost_usd")),
            max_calls_per_minute=_opt_int(payload.get("max_calls_per_minute")),
            max_run_steps=_opt_int(payload.get("max_run_steps")),
            mandate_version_id=_opt_str(payload.get("mandate_version_id")),
            status=_opt_str(payload.get("status")),
            mandate_enforcement=(
                _opt_str(payload.get("mandate_enforcement")) or Enforcement.ENFORCE
            ),
            enforcement_posture=(
                _opt_str(payload.get("enforcement_posture")) or Posture.FAIL_OPEN
            ),
            max_staleness_s=_coerce_float(
                payload.get("max_staleness_s"), DEFAULT_MAX_STALENESS_S
            ),
            delegation_policy=_opt_str(payload.get("delegation_policy")),
            max_delegation_depth=_opt_int(payload.get("max_delegation_depth")),
            served_at=_opt_str(payload.get("served_at")),
            reassessment_required=bool(payload.get("reassessment_required", False)),
            prohibited_tools=prohibited,
            on_violation=on_violation,
            environment=_opt_str(payload.get("environment")),
            output_inspection=inspection,
            received_at=received_at,
            raw=dict(payload),
        )

    @property
    def unrestricted(self) -> bool:
        """True only for ``allowed_tools: null``. Never true for ``[]``."""
        return self.allowed_tools is None

    @property
    def suspended(self) -> bool:
        return (self.status or "").lower() in BLOCKING_STATUSES

    @property
    def observing(self) -> bool:
        return self.mandate_enforcement == Enforcement.OBSERVE

    def age_s(self, now: float) -> float:
        return max(0.0, now - self.received_at)

    def is_stale(self, now: float) -> bool:
        return self.age_s(now) > self.max_staleness_s

    def prohibits(self, tool: str) -> bool:
        """TI-20: on the mandate's prohibited list, whatever else is allowed."""
        return tool in self.prohibited_tools

    def permits(self, tool: str) -> bool:
        if self.prohibits(tool):
            return False
        if self.allowed_tools is None:
            return True
        return tool in self.allowed_tools

    @property
    def enforcing_scope(self) -> bool:
        """Whether a scope violation is refused rather than flagged: ``enforce``
        and an ``on_violation`` other than ``alert_only``."""
        return not self.observing and self.on_violation != ViolationAction.ALERT_ONLY

    def offers(self, tool: str) -> bool:
        """Whether a tool should be shown to the model at all.

        In scope, or waiting on a human (an approval-required tool can still
        run once approved). Static: no budget, staleness or suspension, which
        are decided per call.
        """
        return self.permits(tool) or (
            self.requires_approval(tool) and not self.prohibits(tool)
        )

    def requires_approval(self, tool: str) -> bool:
        """AD-10: checked BEFORE permits() in decide() — a tool named here is
        neither allowed nor denied outright, regardless of allowed_tools."""
        return tool in self.approval_required_tools

    def approval_decision(self, request_id: str) -> str | None:
        """"approved" | "denied" | None (still pending, or unknown to this
        snapshot — the same thing from decide()'s point of view: keep
        returning RequireApproval for it)."""
        return self.resolved_approvals.get(request_id)


def approval_request_id(
    tool: str, trajectory_id: str | None, step_index: int | None,
    arguments: Mapping[str, Any] | None = None,
) -> str:
    """AD-10: deterministic per (tool, trajectory_id, step_index, arguments)
    — a retried identical call must compute the SAME id, so it reports/
    resolves to one pending request instead of minting a new one on every
    retry. Not a secret and not signed; it only needs to be stable and (in
    practice) unique per call.

    `arguments` is folded in specifically because `trajectory_id`/
    `step_index` are both optional on `ProposedAction` — without it, two
    genuinely different calls to the same tool with neither field set (a
    supported, common shape) would collide onto one id, and approving one
    would silently approve the other. Pass `action.arguments` through when
    calling this from `decide()`'s own approval branch; a caller with
    neither trajectory tracking nor arguments to distinguish calls is
    relying on Coriqo seeing them as one call, which is the best this can
    do without inventing a signed nonce protocol."""
    from .canonical import canonical_dumps

    args_part = canonical_dumps(dict(arguments)) if arguments else ""
    key = f"{tool}:{trajectory_id or ''}:{step_index if step_index is not None else ''}:{args_part}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _opt_int(value: Any) -> int | None:
    try:
        return None if value is None else int(value)
    except (TypeError, ValueError):
        return None


def _opt_float(value: Any) -> float | None:
    try:
        return None if value is None else float(value)
    except (TypeError, ValueError):
        return None


# -- where snapshots come from -----------------------------------------------

#: A refresh: given the ETag of the snapshot in hand (or ``None``), return
#: ``(payload, etag)``. ``payload is None`` means *unchanged* — Coriqo's 304 —
#: and the gate keeps what it has, with its age reset.
MandateSource = Callable[
    [str | None], Awaitable[tuple[Mapping[str, Any] | None, str | None]]
]


def coriqo_mandate_source(client: Any, coriqo_agent_id: str) -> MandateSource:
    """Adapt an :class:`AsyncCoriqoAgentsClient` to :data:`MandateSource`."""

    async def fetch(
        etag: str | None,
    ) -> tuple[Mapping[str, Any] | None, str | None]:
        return await client.fetch_mandate_conditional(coriqo_agent_id, etag=etag)

    return fetch


# -- the gate ----------------------------------------------------------------


class MandateGate:
    """Decides, locally and without I/O, whether a proposed tool call is in
    the agent's approved scope.

    Construct one per agent, start its refresh loop, and call :meth:`decide`
    from wherever tools are dispatched — including from a worker thread, which
    is where this package already does its publishing.

    A gate built with no :data:`MandateSource` is a working no-op: every action
    is allowed, one line is logged the first time, and nothing is flagged. That
    is what makes this adoptable before a device is enrolled — an unenrolled
    host gets the code path, not a crash.
    """

    def __init__(
        self,
        source: MandateSource | None = None,
        *,
        agent_id: str | None = None,
        default_posture: str | None = None,
        default_max_staleness_s: float | None = None,
        min_refresh_interval_s: float = MIN_REFRESH_INTERVAL_S,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] | None = None,
        on_suspend_observed: Callable[["MandateSnapshot"], None] | None = None,
        report_approval_request: Callable[["RequireApproval"], None] | None = None,
        report_capability_snapshot: Callable[[dict[str, Any]], None] | None = None,
        environment: str | None = None,
    ) -> None:
        """``default_posture`` and ``default_max_staleness_s`` apply only until
        the first snapshot lands; after that the tenant's own values, which
        arrive on every snapshot, win. ``clock`` is monotonic and injectable so
        tests can age a snapshot past its budget without sleeping.

        ``on_suspend_observed`` (AD-9) fires once, synchronously, the moment
        ``apply_snapshot`` sees the agent transition from not-suspended into
        suspended — never on a snapshot that was already suspended, so a
        repeated fetch of the same suspended state doesn't re-fire it. The
        callback itself owns any I/O (e.g. scheduling a background task to
        POST the ack) — MandateGate stays synchronous and does not manage an
        event loop. A callback that raises is logged and swallowed; it must
        never break the fetch that triggered it.

        ``report_approval_request`` (AD-10) is invoked from
        :meth:`report_approval_request` — a method the CALLER invokes
        explicitly after seeing a :class:`RequireApproval` verdict from
        :meth:`decide`, not something ``decide`` fires itself: ``decide``
        stays pure (no I/O, no awaits, no surprises, per its own docstring),
        so reporting a pending call to Coriqo is a second, explicit step —
        exactly like reporting a normal enforcement verdict already is."""
        self._source = source
        self._on_suspend_observed = on_suspend_observed
        self._report_approval_request = report_approval_request
        self._report_capability_snapshot = report_capability_snapshot
        # W-7: the digest last successfully sent (or attempted), so repeated
        # calls to attest_capabilities() with an unchanged tool/prompt/model
        # surface are a no-op — the etag-style skip. There
        # is no server-side field to compare against yet (see
        # capability_digest.py's cross-repo-parity warning), so this is
        # purely local bookkeeping: it prevents re-attesting on every run
        # start within one process, not across processes or restarts.
        self._last_capability_digest: str | None = None
        self._reported_approval_requests: "OrderedDict[str, None]" = OrderedDict()
        # AD-11: enforced budgets — local bookkeeping only, no I/O. A sliding
        # window of call timestamps for the rate ceiling; per-trajectory step
        # counts and accumulated cost for the other two. All under self._lock,
        # same as _snapshot, since decide() must stay safe to call off-thread.
        self._call_timestamps: deque[float] = deque()
        self._trajectory_steps: "OrderedDict[str, set[int]]" = OrderedDict()
        self._trajectory_costs: "OrderedDict[str, float]" = OrderedDict()
        self._agent_id = agent_id
        # TI-20: where this runtime runs. None (the default, and an unset
        # BYOAI_MANDATE_ENVIRONMENT) means the snapshot's environment is not
        # compared, which is how every gate behaved before the field existed.
        self._environment = (
            environment
            if environment is not None
            else (os.getenv("BYOAI_MANDATE_ENVIRONMENT") or "").strip() or None
        )
        self._clock = clock
        self._sleep = sleep or asyncio.sleep
        self._default_posture = default_posture or _env_posture()
        self._default_max_staleness_s = (
            default_max_staleness_s
            if default_max_staleness_s is not None
            else _env_max_staleness()
        )
        self._min_refresh_interval_s = min_refresh_interval_s
        self._lock = threading.Lock()
        self._snapshot: MandateSnapshot | None = None
        self._etag: str | None = None
        self._last_refresh_error: Exception | None = None
        self._noop_logged = False
        self._task: asyncio.Task[None] | None = None
        self._stop = asyncio.Event()

    # -- state -------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """False for a gate with no source — the adopt-before-enrolment no-op."""
        return self._source is not None

    @property
    def agent_id(self) -> str | None:
        return self._agent_id

    @property
    def environment(self) -> str | None:
        """The environment this gate was told it runs in, if any."""
        return self._environment

    def offered_tools(self, names: Iterable[str]) -> list[str]:
        """The subset of ``names`` a model should be shown, in order.

        Everything when the gate is a no-op, or when the mandate in hand only
        flags violations (``observe`` / ``alert_only``): hiding a tool there
        would block it, and those settings block nothing. With no snapshot,
        or one for another environment, the posture decides, as it does for a
        call: ``fail_closed`` shows nothing.
        """
        names = list(names)
        if self._source is None:
            return names
        snapshot = self.snapshot
        if snapshot is None or self._environment_mismatch(snapshot):
            return [] if self.posture == Posture.FAIL_CLOSED else names
        if not snapshot.enforcing_scope:
            return names
        return [name for name in names if snapshot.offers(name)]

    def _environment_mismatch(self, snapshot: MandateSnapshot) -> bool:
        return (
            self._environment is not None
            and snapshot.environment is not None
            and snapshot.environment != self._environment
        )

    @property
    def snapshot(self) -> MandateSnapshot | None:
        with self._lock:
            return self._snapshot

    @property
    def last_refresh_error(self) -> Exception | None:
        with self._lock:
            return self._last_refresh_error

    def snapshot_age_s(self) -> float | None:
        snapshot = self.snapshot
        return None if snapshot is None else snapshot.age_s(self._clock())

    @property
    def latch_version(self) -> str | None:
        """What the denial latch treats as "the mandate in hand".

        One value, asked of the gate, so that both sides of a latch lookup agree.
        A delegated gate answers with the delegation it is running under rather
        than with the child's own snapshot version — see
        :class:`~byoai.recorder.delegation.DelegatedGate`.
        """
        snapshot = self.snapshot
        return None if snapshot is None else snapshot.mandate_version_id

    @property
    def posture(self) -> str:
        snapshot = self.snapshot
        if snapshot is None:
            return self._default_posture
        return snapshot.enforcement_posture

    def apply_snapshot(
        self, payload: Mapping[str, Any], *, etag: str | None = None
    ) -> MandateSnapshot:
        """Install a snapshot directly, as a refresh would.

        Public because the alternative is tests (and anyone wiring a different
        transport) reaching into private state to seed a gate.
        """
        snapshot = MandateSnapshot.from_payload(payload, received_at=self._clock())
        if payload.get("max_staleness_s") is None:
            snapshot = replace(
                snapshot, max_staleness_s=self._default_max_staleness_s
            )
        if payload.get("enforcement_posture") is None:
            snapshot = replace(snapshot, enforcement_posture=self._default_posture)
        with self._lock:
            previous = self._snapshot
            self._snapshot = snapshot
            self._etag = etag
            self._last_refresh_error = None

        # AD-9: fire only on the transition into suspended, not on every
        # fetch of an already-suspended snapshot — the ack is a one-time
        # "I saw this and stopped" report, not a heartbeat.
        if snapshot.suspended and not (previous is not None and previous.suspended) and self._on_suspend_observed:
            try:
                self._on_suspend_observed(snapshot)
            except Exception:
                log.exception(
                    "on_suspend_observed callback failed for agent %s; the suspend itself "
                    "still applies locally, only the ack to Coriqo may be missing",
                    self._agent_id,
                )
        return snapshot

    # -- the decide path: no I/O, no awaits, no surprises -------------------

    def decide(self, action: ProposedAction | str) -> Verdict:
        """Return :class:`Allow`, :class:`Flag` or :class:`Deny` for ``action``.

        Reads memory and returns. No network call, no lock held across an
        evaluation, no awaiting — so it is safe to call from a worker thread
        while the refresh loop is mid-flight on the event loop.
        """
        if isinstance(action, str):
            action = ProposedAction(tool=action)

        if self._source is None:
            self._log_noop_once()
            return Allow(
                reason=Reason.ENFORCEMENT_UNCONFIGURED,
                tool=action.tool,
                posture=self._default_posture,
                trajectory_id=action.trajectory_id,
                step_index=action.step_index,
                detail="no Coriqo identity configured; the mandate gate is a no-op",
            )

        with self._lock:
            snapshot = self._snapshot
        now = self._clock()

        if snapshot is None:
            return self._unevaluable(
                action,
                reason=Reason.NO_SNAPSHOT,
                age=None,
                version=None,
                enforcement=None,
                detail=(
                    "no mandate snapshot has been fetched yet for agent "
                    f"{self._agent_id or '?'}"
                ),
            )

        age = snapshot.age_s(now)

        # A suspension is a decision Coriqo made and this runtime read, so it
        # denies under both postures — it is not a failure to evaluate.
        if snapshot.suspended:
            return Deny(
                reason=Reason.AGENT_SUSPENDED,
                mandate_version_id=snapshot.mandate_version_id,
                snapshot_age_s=age,
                tool=action.tool,
                posture=snapshot.enforcement_posture,
                enforcement=snapshot.mandate_enforcement,
                trajectory_id=action.trajectory_id,
                step_index=action.step_index,
                detail=f"agent status is {snapshot.status!r}",
            )

        # TI-20: a mandate written for another environment is not a mandate
        # for this one. Suspension above still applies (it names the agent,
        # not the environment); past here, the posture decides.
        if self._environment_mismatch(snapshot):
            return self._unevaluable(
                action,
                reason=Reason.ENVIRONMENT_MISMATCH,
                age=age,
                version=snapshot.mandate_version_id,
                enforcement=snapshot.mandate_enforcement,
                posture=snapshot.enforcement_posture,
                detail=(
                    f"the mandate applies to environment {snapshot.environment!r}; "
                    f"this runtime is {self._environment!r}"
                ),
            )

        # W-7 TODO: this is deliberately coarse. `reassessment_required` is a
        # single boolean on the snapshot, not a list of which tools drifted
        # — Coriqo's schema for naming the specific drift-introduced tools
        # was not visible when this was written (see capability_digest.py's
        # cross-repo-parity warning). Once Coriqo's response can name them,
        # narrow this to deny/flag only those tools rather than the whole
        # snapshot; until then, "reassess before anything else runs" is the
        # closest sound reading of a mandate flagged for reassessment under
        # fail_closed, and "flag everything, block nothing" mirrors how
        # SNAPSHOT_STALE is handled under fail_open/observe.
        if snapshot.reassessment_required:
            if snapshot.enforcement_posture == Posture.FAIL_CLOSED:
                return Deny(
                    reason=Reason.REASSESSMENT_REQUIRED,
                    mandate_version_id=snapshot.mandate_version_id,
                    snapshot_age_s=age,
                    tool=action.tool,
                    posture=snapshot.enforcement_posture,
                    enforcement=snapshot.mandate_enforcement,
                    trajectory_id=action.trajectory_id,
                    step_index=action.step_index,
                    detail=(
                        "Coriqo flagged this agent's capabilities for "
                        "reassessment (attested tools/prompt drifted from "
                        "the last-reviewed mandate)"
                    ),
                )
            # fail_open/observe: don't stop the agent, but every verdict from
            # here on is worth an operator's attention, same shape as a Flag
            # from a stale snapshot.
            budget_verdict = self._check_budgets(action, snapshot, age, now)
            if budget_verdict is not None:
                return budget_verdict
            return Flag(
                reason=Reason.REASSESSMENT_REQUIRED,
                mandate_version_id=snapshot.mandate_version_id,
                snapshot_age_s=age,
                tool=action.tool,
                posture=snapshot.enforcement_posture,
                enforcement=snapshot.mandate_enforcement,
                trajectory_id=action.trajectory_id,
                step_index=action.step_index,
                detail=(
                    "Coriqo flagged this agent's capabilities for "
                    "reassessment; running under fail_open, so allowed and "
                    "flagged rather than blocked"
                ),
            )

        if snapshot.is_stale(now):
            return self._unevaluable(
                action,
                reason=Reason.SNAPSHOT_STALE,
                age=age,
                version=snapshot.mandate_version_id,
                enforcement=snapshot.mandate_enforcement,
                posture=snapshot.enforcement_posture,
                detail=(
                    f"snapshot is {age:.1f}s old, past the "
                    f"{snapshot.max_staleness_s:.1f}s budget"
                ),
            )

        # AD-10: checked before permits() — a tool named in
        # approval_required_tools is neither allowed nor denied outright.
        # The SAME call (same request_id) may resolve differently on a
        # LATER decide() once resolved_approvals carries a decision — that
        # arrives on the next scheduled snapshot fetch, never a live round
        # trip from inside this method.
        #
        # Deliberately NOT gated on snapshot.observing, unlike the
        # OUT_OF_SCOPE branch below. Observe mode is a rollout dial for
        # SCOPE — "record what an allowed_tools change would have blocked,
        # block nothing yet" — not a bypass for a control a tenant named
        # explicitly as needing a human before payments/regulatory-filing
        # tools run. Letting an enforcement-mode flip silently wave through
        # every approval-required call would defeat the one thing AD-10
        # exists for; it denies under both postures, the same as
        # AGENT_SUSPENDED above.
        # TI-20: a prohibited tool is outside the mandate even when it is also
        # named for approval — no human sign-off makes a prohibited call fine.
        if snapshot.requires_approval(action.tool) and not snapshot.prohibits(action.tool):
            request_id = approval_request_id(
                action.tool, action.trajectory_id, action.step_index, action.arguments,
            )
            decision = snapshot.approval_decision(request_id)
            common_approval = {
                "mandate_version_id": snapshot.mandate_version_id,
                "snapshot_age_s": age,
                "tool": action.tool,
                "posture": snapshot.enforcement_posture,
                "enforcement": snapshot.mandate_enforcement,
                "trajectory_id": action.trajectory_id,
                "step_index": action.step_index,
            }
            if decision == "approved":
                budget_verdict = self._check_budgets(action, snapshot, age, now)
                if budget_verdict is not None:
                    return budget_verdict
                return Allow(
                    reason=Reason.APPROVAL_GRANTED,
                    detail=f"{action.tool!r} was approved by a human for this specific call",
                    **common_approval,
                )
            if decision == "denied":
                return Deny(
                    reason=Reason.APPROVAL_REFUSED,
                    detail=f"{action.tool!r} was denied by a human for this specific call",
                    **common_approval,
                )
            return RequireApproval(
                reason=Reason.APPROVAL_REQUIRED,
                detail=f"{action.tool!r} requires human approval before it may run",
                request_id=request_id,
                **common_approval,
            )

        if snapshot.permits(action.tool):
            # AD-11: budgets are checked here, immediately before the call is
            # actually permitted to proceed — NOT earlier in this method.
            # Checking (and recording consumption) before the scope/approval
            # gates above would burn rate-window slots and step counts on
            # calls that were going to be denied or parked anyway, starving
            # the trajectory's legitimate calls of budget they never used.
            budget_verdict = self._check_budgets(action, snapshot, age, now)
            if budget_verdict is not None:
                return budget_verdict
            return Allow(
                reason=Reason.UNRESTRICTED if snapshot.unrestricted else Reason.IN_SCOPE,
                mandate_version_id=snapshot.mandate_version_id,
                snapshot_age_s=age,
                tool=action.tool,
                posture=snapshot.enforcement_posture,
                enforcement=snapshot.mandate_enforcement,
                trajectory_id=action.trajectory_id,
                step_index=action.step_index,
            )

        # Out of scope. `observe` is the tenant's rollout dial: record what
        # would have been blocked, block nothing.
        common = {
            "mandate_version_id": snapshot.mandate_version_id,
            "snapshot_age_s": age,
            "tool": action.tool,
            "posture": snapshot.enforcement_posture,
            "enforcement": snapshot.mandate_enforcement,
            "trajectory_id": action.trajectory_id,
            "step_index": action.step_index,
        }
        why = (
            f"{action.tool!r} is on the mandate's prohibited list"
            if snapshot.prohibits(action.tool)
            else f"{action.tool!r} is not in the agent's approved scope"
        )
        if snapshot.observing or snapshot.on_violation == ViolationAction.ALERT_ONLY:
            # Still permitted to run (Flag < Allow) — same budget gate as
            # the in-scope Allow path above, for the same reason.
            budget_verdict = self._check_budgets(action, snapshot, age, now)
            if budget_verdict is not None:
                return budget_verdict
            if snapshot.observing:
                return Flag(
                    reason=Reason.OUT_OF_SCOPE_OBSERVED,
                    detail=f"{why}; enforcement is observe",
                    **common,
                )
            # TI-20 alert_only: enforcing, and the tenant chose to be told
            # rather than to refuse. The reason stays out_of_scope so the
            # record says this was a real violation, not a rollout.
            return Flag(
                reason=Reason.OUT_OF_SCOPE,
                detail=f"{why}; on_violation is alert_only",
                **common,
            )
        halt = snapshot.on_violation == ViolationAction.DENY_AND_HALT_RUN
        return Deny(
            reason=Reason.OUT_OF_SCOPE,
            detail=f"{why}; on_violation is deny_and_halt_run" if halt else why,
            halt_run=halt,
            **common,
        )

    def report_approval_request(self, verdict: "RequireApproval") -> None:
        """AD-10: tell Coriqo about a pending approval-required call.

        Call this once, explicitly, after `decide()` returns a
        RequireApproval — it is NOT fired automatically from `decide()`,
        which stays pure. Deduped per `request_id` for the lifetime of this
        gate: a caller retrying the identical call gets RequireApproval
        again from decide() every time (harmless — Coriqo's own endpoint is
        idempotent on request_id too), but this method only invokes the
        report callback once per id, so a tight retry loop doesn't spam a
        report call on every attempt.

        Best-effort by construction, same posture as the suspend ack: the
        report callback owns its own I/O and must never raise into this
        call; a failure here never changes what decide() already returned.

        Marked reported only AFTER the callback returns without raising —
        not before. The callback itself only SCHEDULES the actual network
        POST (fire-and-forget, same as the suspend ack), so this can't catch
        a failure of the POST itself, but it does catch the synchronous
        failure mode that matters here: no running event loop to schedule
        onto. Marking it reported before that check, as an earlier version
        of this method did, would have permanently suppressed every future
        report attempt for this request_id — including the host's own retry
        of the identical call, the one case this mechanism exists to serve
        — leaving the pending approval invisible in Coriqo's queue forever."""
        if verdict.request_id in self._reported_approval_requests:
            return
        if self._report_approval_request is None:
            return
        try:
            self._report_approval_request(verdict)
        except Exception:
            log.exception(
                "report_approval_request callback failed for request %s (agent %s); "
                "the local denial still applies, only Coriqo's record of it may be missing",
                verdict.request_id, self._agent_id,
            )
            return
        self._mark_approval_reported(verdict.request_id)

    def _mark_approval_reported(self, request_id: str) -> None:
        """Bounded FIFO over _reported_approval_requests — a long-lived host
        process accumulates one entry per distinct approval-required call
        over its lifetime, and unlike request-scoped state elsewhere in this
        module, nothing else here ever shrinks it. Evicting the oldest past
        the cap trades a theoretical, extremely rare re-report of a very
        stale request_id for not leaking memory in the process this module
        is built to run inside for days or weeks."""
        self._reported_approval_requests[request_id] = None
        if len(self._reported_approval_requests) > _MAX_REPORTED_APPROVAL_REQUESTS:
            self._reported_approval_requests.popitem(last=False)

    def attest_capabilities(
        self,
        tools: Iterable[Mapping[str, Any]],
        *,
        system_prompt: str | None = None,
        model_id: str | None = None,
        runtime_version: str | None = None,
        store_system_prompt: bool = False,
        force: bool = False,
    ) -> bool:
        """W-7: report the tool/prompt/model surface this runtime actually
        loaded for this agent, so Coriqo can compare it against what the
        mandate was reviewed against.

        Call this once at run start (with the tools/system prompt/model the
        run is about to use), and again whenever the mandate snapshot
        refreshes if the locally computed digest has changed — the caller
        drives both call sites, the same explicit-second-step shape as
        :meth:`report_approval_request`, since this method (like that one)
        does its own I/O and must never run on :meth:`decide`'s path.

        Returns ``True`` if a report was (attempted to be) sent, ``False`` if
        skipped because the digest matches the last one this gate sent —
        the etag-style skip. There is no
        ``capability_digest`` field on the mandate snapshot to compare
        against yet (Coriqo's side of that addition was not visible when
        this was written), so the comparison is against this gate's own
        last-sent digest instead: correct within one process's lifetime,
        but it does mean a fresh process always attests once on its first
        call, even if an identical process on the same host attested the
        same surface five minutes ago. ``force=True`` bypasses the skip
        entirely (e.g. for a caller that wants to guarantee a fresh
        attestation regardless of local state).

        Best-effort, same posture as the suspend ack and approval report:
        the callback owns its own I/O (typically scheduling
        ``AsyncCoriqoAgentsClient.attest_capability_snapshot`` as a
        fire-and-forget task) and a failure here never raises — it only
        means Coriqo's capability record for this agent may lag what is
        actually running, not that anything local breaks.

        ``store_system_prompt`` defaults to ``False``: the raw prompt text
        is never sent unless the caller explicitly opts in. This runtime has
        no visibility into a Coriqo-side ``store_system_prompt`` policy
        field on the snapshot yet, so "never send it unless asked" is the
        safe default until that field exists and can be read here instead.
        """
        from .capability_digest import compute_capability_digest

        tools_list = list(tools)
        digest, _prompt_hash = compute_capability_digest(
            tools=tools_list, system_prompt=system_prompt, model_id=model_id,
        )
        if not force and digest == self._last_capability_digest:
            return False
        if self._report_capability_snapshot is None:
            return False
        try:
            self._report_capability_snapshot(
                {
                    "tools": tools_list,
                    "system_prompt": system_prompt,
                    "model_id": model_id,
                    "runtime_version": runtime_version,
                    "store_system_prompt": store_system_prompt,
                    "digest": digest,
                }
            )
        except Exception:
            log.exception(
                "capability attestation callback failed for agent %s; "
                "Coriqo's capability record for this agent may now lag "
                "what is actually loaded",
                self._agent_id,
            )
            return False
        self._last_capability_digest = digest
        return True

    def _check_budgets(
        self, action: ProposedAction, snapshot: "MandateSnapshot", age: float, now: float,
    ) -> "Verdict | None":
        """AD-11: call-rate, step, and cost ceilings — `None` if none apply,
        a terminal `Deny` if one is breached. Called from `decide()` ONLY at
        the points where the call is otherwise about to be permitted (the
        in-scope Allow, the observed-out-of-scope Flag, and the approval-
        granted Allow) — never earlier. Checking (and recording consumption)
        before the suspend/staleness/approval/scope gates run would burn
        rate-window slots and step counts on calls that were going to be
        denied or parked for an unrelated reason anyway, starving the
        trajectory's legitimate calls of budget they never actually used.

        All local bookkeeping, no I/O — the same guarantee the rest of
        `decide()` makes. Every branch below both checks and records in one
        pass, so a caller never has to call anything extra for these three
        (unlike AD-10's approval report, which is genuinely a second,
        explicit, I/O-bound step)."""
        common = {
            "mandate_version_id": snapshot.mandate_version_id,
            "snapshot_age_s": age,
            "tool": action.tool,
            "posture": snapshot.enforcement_posture,
            "enforcement": snapshot.mandate_enforcement,
            "trajectory_id": action.trajectory_id,
            "step_index": action.step_index,
        }

        with self._lock:
            if snapshot.max_calls_per_minute is not None:
                window_start = now - _CALL_RATE_WINDOW_S
                while self._call_timestamps and self._call_timestamps[0] < window_start:
                    self._call_timestamps.popleft()
                if len(self._call_timestamps) >= snapshot.max_calls_per_minute:
                    return Deny(
                        reason=Reason.BUDGET_CALL_RATE_EXCEEDED,
                        detail=(
                            f"{len(self._call_timestamps)} calls in the last "
                            f"{_CALL_RATE_WINDOW_S:.0f}s, at the {snapshot.max_calls_per_minute}/min ceiling"
                        ),
                        **common,
                    )

            trajectory_id = action.trajectory_id
            if trajectory_id is not None:
                if snapshot.max_run_steps is not None and action.step_index is not None:
                    steps = self._trajectory_steps.get(trajectory_id)
                    would_be_new_step = steps is None or action.step_index not in steps
                    seen_count = len(steps) if steps is not None else 0
                    if would_be_new_step and seen_count >= snapshot.max_run_steps:
                        return Deny(
                            reason=Reason.BUDGET_STEP_LIMIT_EXCEEDED,
                            detail=f"trajectory {trajectory_id!r} is at its {snapshot.max_run_steps}-step ceiling",
                            **common,
                        )

                if snapshot.max_run_cost_usd is not None:
                    spent = self._trajectory_costs.get(trajectory_id, 0.0)
                    if spent >= snapshot.max_run_cost_usd:
                        return Deny(
                            reason=Reason.BUDGET_COST_EXCEEDED,
                            detail=(
                                f"trajectory {trajectory_id!r} has spent ${spent:.6f} against a "
                                f"${snapshot.max_run_cost_usd:.6f} ceiling"
                            ),
                            **common,
                        )

            # Allowed to proceed against every configured budget — record the
            # attempt now, under the same lock, so a concurrent decide() for
            # the same trajectory/window sees it.
            self._call_timestamps.append(now)
            if trajectory_id is not None and action.step_index is not None:
                self._mark_trajectory_seen(trajectory_id)
                self._trajectory_steps.setdefault(trajectory_id, set()).add(action.step_index)

        return None

    def record_actual_cost(self, trajectory_id: str, cost_usd: float) -> None:
        """AD-11: add `cost_usd` to `trajectory_id`'s running total, checked
        by `_check_budgets` on the NEXT call in that trajectory. Call this
        once the real cost of a completed call is known — `decide()` runs
        before the call, so it cannot know the cost of the call it is
        deciding, only what earlier calls in the same trajectory already
        spent. Local bookkeeping only, no I/O; safe to call from any thread
        under the same lock `decide()` uses."""
        with self._lock:
            self._mark_trajectory_seen(trajectory_id)
            self._trajectory_costs[trajectory_id] = self._trajectory_costs.get(trajectory_id, 0.0) + cost_usd

    def _mark_trajectory_seen(self, trajectory_id: str) -> None:
        """Bounded FIFO over the trajectory dicts — see _MAX_TRACKED_TRAJECTORIES.
        Must be called under self._lock."""
        for tracker in (self._trajectory_steps, self._trajectory_costs):
            if trajectory_id in tracker:
                tracker.move_to_end(trajectory_id)
        if len(self._trajectory_steps) >= _MAX_TRACKED_TRAJECTORIES and trajectory_id not in self._trajectory_steps:
            self._trajectory_steps.popitem(last=False)
        if len(self._trajectory_costs) >= _MAX_TRACKED_TRAJECTORIES and trajectory_id not in self._trajectory_costs:
            self._trajectory_costs.popitem(last=False)

    def _unevaluable(
        self,
        action: ProposedAction,
        *,
        reason: str,
        age: float | None,
        version: str | None,
        enforcement: str | None,
        detail: str,
        posture: str | None = None,
    ) -> Verdict:
        """The fail_open / fail_closed fork, in one place.

        Both branches exist for the same situation — the gate does not have a
        mandate it can stand behind — so they are written once and differ only
        in the verdict class.
        """
        effective = posture or self._default_posture
        fields: dict[str, Any] = {
            "reason": reason,
            "mandate_version_id": version,
            "snapshot_age_s": age,
            "tool": action.tool,
            "posture": effective,
            "enforcement": enforcement,
            "trajectory_id": action.trajectory_id,
            "step_index": action.step_index,
            "detail": detail,
        }
        if effective == Posture.FAIL_CLOSED:
            return Deny(**fields)
        return Flag(**fields)

    def _log_noop_once(self) -> None:
        with self._lock:
            if self._noop_logged:
                return
            self._noop_logged = True
        log.info(
            "coriqo: no mandate source configured, so tool calls are not gated. "
            "Enroll this device (byoai-recorder-enroll) to enforce the agent's "
            "approved mandate."
        )

    # -- the refresh path: the only place that touches the network ---------

    async def refresh(self) -> MandateSnapshot | None:
        """Fetch once. Returns the snapshot now in hand, or ``None`` if there
        still isn't one.

        A ``304`` keeps the cached snapshot and resets its age — the mandate
        did not change, so the copy in memory is current, not merely recent.
        """
        if self._source is None:
            return None
        etag = self._etag
        payload, new_etag = await self._source(etag)
        now = self._clock()
        with self._lock:
            if payload is None:
                # Unchanged. Same mandate, fresh as of now.
                if self._snapshot is not None:
                    self._snapshot = replace(self._snapshot, received_at=now)
                if new_etag:
                    self._etag = new_etag
                self._last_refresh_error = None
                return self._snapshot

        snapshot = self.apply_snapshot(payload, etag=new_etag)
        log.debug(
            "coriqo: mandate refreshed for %s (version=%s, tools=%s)",
            self._agent_id,
            snapshot.mandate_version_id,
            "unrestricted" if snapshot.unrestricted else len(snapshot.allowed_tools or ()),
        )
        return snapshot

    async def refresh_safely(self) -> bool:
        """:meth:`refresh`, with a failure recorded rather than raised.

        A failed refresh must never clear a snapshot that is still inside its
        staleness budget. Dropping a good snapshot on one blip is how a network
        hiccup becomes a fail-closed outage — the snapshot stays, and staleness
        alone decides when it stops counting.
        """
        try:
            await self.refresh()
        except Exception as exc:  # noqa: BLE001 - the loop must survive anything
            with self._lock:
                self._last_refresh_error = exc
                held = self._snapshot
            log.warning(
                "coriqo: mandate refresh failed for %s (%s); %s",
                self._agent_id,
                exc,
                "keeping the cached snapshot" if held else "no snapshot cached yet",
            )
            return False
        return True

    def refresh_interval_s(self) -> float:
        """How long to wait before the next refresh.

        Half the staleness budget the *snapshot in hand* names, so the interval
        follows the agent's own budget once one is known and there is room for
        a whole failed refresh before the snapshot ages out.
        """
        budget = (
            self.snapshot.max_staleness_s
            if self.snapshot is not None
            else self._default_max_staleness_s
        )
        return max(self._min_refresh_interval_s, budget * REFRESH_FRACTION)

    async def start(self) -> None:
        """Fetch once, then keep refreshing in the background.

        The first fetch is awaited so a caller that started the gate before its
        first tool call is not deciding from an empty cache — under
        ``fail_closed`` that first window would deny everything.
        """
        if self._source is None or self._task is not None:
            return
        self._stop = asyncio.Event()
        await self.refresh_safely()
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._stop.set()
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(self._stop.wait(), self.refresh_interval_s())
                return
            except asyncio.TimeoutError:
                pass
            await self.refresh_safely()

    async def __aenter__(self) -> MandateGate:
        await self.start()
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.stop()


# -- construction ------------------------------------------------------------


def _env_posture() -> str:
    value = (os.getenv("BYOAI_MANDATE_POSTURE") or "").strip().lower()
    if value in {Posture.FAIL_OPEN, Posture.FAIL_CLOSED}:
        return value
    return Posture.FAIL_OPEN


def _env_max_staleness() -> float:
    return _coerce_float(
        os.getenv("BYOAI_MANDATE_MAX_STALENESS_S"), DEFAULT_MAX_STALENESS_S
    )


def mandate_gate(
    coriqo_agent_id: str,
    *,
    identity: CoriqoIdentity | None = None,
    client: Any | None = None,
    **kwargs: Any,
) -> MandateGate:
    """Build a gate for ``coriqo_agent_id`` from this host's Coriqo identity.

    With no identity configured on the host — nothing enrolled, no API key —
    this returns the no-op gate rather than raising, so the enforcement code
    path can be adopted before enrolment. A *static API key* identity is
    refused instead, with
    :class:`~byoai.errors.EnforcementIdentityUnavailableError`: that is a
    misconfiguration rather than an absence, and a key carrying
    ``governance:approve`` would let the agent widen its own mandate.
    """
    if client is None:
        if identity is None:
            identity = resolve_identity()
        if identity is None:
            return MandateGate(None, agent_id=coriqo_agent_id, **kwargs)
        identity.require_enforcement()
        from .coriqo_async import AsyncCoriqoAgentsClient

        client = AsyncCoriqoAgentsClient(identity)

    def _on_suspend_observed(snapshot: "MandateSnapshot") -> None:
        # Best-effort: schedule and forget. If there's no running
        # loop (apply_snapshot called outside the async refresh path — e.g.
        # a test seeding a snapshot directly) there is nothing to schedule
        # onto, so log and move on rather than raising out of apply_snapshot.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            log.warning(
                "no running event loop to post the suspend ack for agent %s; "
                "the local suspend still applies, only Coriqo's confirmation may be missing",
                coriqo_agent_id,
            )
            return

        async def _ack() -> None:
            try:
                await client.ack_suspend(
                    coriqo_agent_id, mandate_version_id=snapshot.mandate_version_id,
                )
            except Exception:
                log.exception("failed to post suspend ack for agent %s", coriqo_agent_id)

        loop.create_task(_ack())

    def _report_approval_request(verdict: "RequireApproval") -> None:
        # Same best-effort/schedule-and-forget shape as the suspend ack above.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            log.warning(
                "no running event loop to report approval request %s for agent %s; "
                "the local denial still applies, only Coriqo's record of it may be missing",
                verdict.request_id, coriqo_agent_id,
            )
            return

        async def _report() -> None:
            try:
                await client.request_tool_approval(
                    coriqo_agent_id,
                    request_id=verdict.request_id,
                    tool=verdict.tool,
                    trajectory_id=verdict.trajectory_id,
                    step_index=verdict.step_index,
                    mandate_version_id=verdict.mandate_version_id,
                )
            except Exception:
                log.exception(
                    "failed to report approval request %s for agent %s",
                    verdict.request_id, coriqo_agent_id,
                )

        loop.create_task(_report())

    def _report_capability_snapshot(snapshot: dict[str, Any]) -> None:
        # Same best-effort/schedule-and-forget shape as the suspend ack and
        # approval report above.
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            log.warning(
                "no running event loop to attest capabilities for agent %s; "
                "Coriqo's capability record for this agent may lag what is "
                "actually loaded",
                coriqo_agent_id,
            )
            return

        async def _attest() -> None:
            try:
                await client.attest_capability_snapshot(
                    coriqo_agent_id,
                    tools=snapshot["tools"],
                    system_prompt=snapshot["system_prompt"],
                    model_id=snapshot["model_id"],
                    runtime_version=snapshot["runtime_version"],
                    store_system_prompt=snapshot["store_system_prompt"],
                )
            except Exception:
                log.exception(
                    "failed to attest capability snapshot for agent %s",
                    coriqo_agent_id,
                )

        loop.create_task(_attest())

    return MandateGate(
        coriqo_mandate_source(client, coriqo_agent_id),
        agent_id=coriqo_agent_id,
        on_suspend_observed=_on_suspend_observed,
        report_approval_request=_report_approval_request,
        report_capability_snapshot=_report_capability_snapshot,
        **kwargs,
    )
