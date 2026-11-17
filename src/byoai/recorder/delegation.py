"""Delegated scope attenuation: what an agent may do on someone else's behalf.

Two relations get confused with each other, and only one of them attenuates.

**Nesting** is a sub-run of the *same* agent — a planner step, a retry loop, a
nested trace. One agent, one mandate, and that mandate already scopes the whole
thing. Narrowing a nested run would be narrowing an agent against itself.

**Delegation** is agent A handing work to agent B. Different agents, and the
interesting question is which mandate governs B's tool calls while it is working
for A. Not B's own: for the duration of that work B has *no mandate of its own*,
because nobody approved B to act inside A's task. Its effective scope is the
**intersection** of B's standing mandate with A's effective scope at the moment
of delegation, pinned to A's ``mandate_version_id``.

Intersection is the whole point, and it is one-directional: delegation can only
narrow. If it could widen, spawning a sub-agent would be a route to tools the
parent was refused — and it would be the *easy* route, since a model that has
just been denied is one prompt away from asking a helper to do it. Attenuation
is what makes "delegate it to another agent" a strictly worse idea than doing it
directly, which is the property you want.

The child's standing mandate is untouched by any of this. B is still B when it
runs its own work; the narrowing lives on the :class:`EffectiveScope` built for
one delegated run.

Null is not empty
-----------------
``allowed_tools = None`` means *unrestricted*; ``allowed_tools = []`` means
*nothing is permitted*. Opposite instructions, and a falsy check reads them the
same way — which is exactly how "permitted nothing" becomes "permitted
everything". So :func:`intersect_tools` branches on ``is None`` and nothing
else: unrestricted ∩ X is X, X ∩ unrestricted is X, and anything ∩ ``[]`` is
``[]``.

Two dials from the snapshot
---------------------------
``delegation_policy`` (``none`` | ``attenuated``) says whether this agent may
delegate at all. Anything else — absent, unrecognised — is treated as ``none``:
a snapshot that does not say delegation was approved has not approved it.

``max_delegation_depth`` bounds the chain. ``None`` means the tenant did not
bound it, and ``0`` means no delegation at all, which is why the check is
``is not None`` rather than a truth test.

An **undeclared** delegation — one Coriqo was never told about — gets the empty
scope rather than a refusal. It denies every tool under ``enforce``, which is
the same practical outcome, but it is a decision the record can explain instead
of a crash in the integrator's spawn path.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace

from .mandate import (
    DelegationPolicy,
    Deny,
    Enforcement,
    Flag,
    MandateError,
    MandateGate,
    MandateSnapshot,
    ProposedAction,
    Reason,
    Verdict,
)

__all__ = [
    "DelegatedGate",
    "DelegationRefusedError",
    "EffectiveScope",
    "delegate",
    "delegated_gate",
    "intersect_tools",
]

log = logging.getLogger(__name__)


class DelegationRefusedError(MandateError):
    """One agent tried to hand work to another and the mandate did not allow it.

    Raised where the delegation is set up rather than at the first tool call:
    there is no scope to build, so the integrator wiring the sub-agent up is the
    right person to see it, at the moment they can still not do it.
    """


def intersect_tools(
    parent: Sequence[str] | None, child: Sequence[str] | None
) -> tuple[str, ...] | None:
    """Intersect two tool lists under the null-is-unrestricted rule.

    ``None`` on either side means *no restriction from that side*, so it
    contributes nothing and the other side stands. Only when both are ``None``
    is the result unrestricted. An empty sequence is a real restriction —
    permitting nothing — and survives every intersection.
    """
    if parent is None and child is None:
        return None
    if parent is None:
        return tuple(child or ())  # child is not None here: both None returned above
    if child is None:
        return tuple(parent or ())  # parent is not None here: both None returned above
    permitted = set(child)
    # Parent order, because the parent's mandate is the one being narrowed.
    return tuple(tool for tool in parent if tool in permitted)


@dataclass(frozen=True, slots=True)
class EffectiveScope:
    """What an agent may call for one run — its own mandate, or a narrowed one.

    ``mandate_version_id`` is the version this scope is answerable to. For a
    delegated scope that is the *delegator's* version, because the delegator's
    approval is what the child is acting under.
    """

    #: ``None`` is unrestricted; ``()`` permits nothing. Never conflate them.
    allowed_tools: tuple[str, ...] | None = None
    mandate_version_id: str | None = None
    agent_id: str | None = None
    #: 0 for an agent working under its own mandate.
    depth: int = 0
    #: The delegator's enforcement dial, carried down so the *narrowing* is
    #: enforced (or observed) on the delegator's terms. A child that happens to
    #: be in ``observe`` rollout must not thereby run a tool its delegator was
    #: refused — that would make picking the right sub-agent a way around the
    #: control.
    enforcement: str | None = None
    #: The tightest ``max_delegation_depth`` seen anywhere up the chain. A middle
    #: agent's own generous limit cannot loosen the root's.
    max_depth: int | None = None
    delegated: bool = False
    #: The chain of agent ids this scope descends from, delegator first.
    chain: tuple[str, ...] = ()

    @classmethod
    def from_snapshot(
        cls, snapshot: MandateSnapshot, *, agent_id: str | None = None
    ) -> EffectiveScope:
        return cls(
            allowed_tools=snapshot.allowed_tools,
            mandate_version_id=snapshot.mandate_version_id,
            agent_id=agent_id,
            enforcement=snapshot.mandate_enforcement,
            max_depth=_declared_depth(snapshot),
            chain=() if agent_id is None else (agent_id,),
        )

    @property
    def observing(self) -> bool:
        """Whether a breach of *this* scope is flagged rather than blocked."""
        return self.enforcement == Enforcement.OBSERVE

    @property
    def unrestricted(self) -> bool:
        """True only for ``None``. Never true for ``()``."""
        return self.allowed_tools is None

    def permits(self, tool: str) -> bool:
        if self.allowed_tools is None:
            return True
        return tool in self.allowed_tools


def delegate(
    parent: EffectiveScope,
    *,
    parent_snapshot: MandateSnapshot,
    child_agent_id: str,
    child_tools: Iterable[str] | None = None,
    declared: bool = True,
) -> EffectiveScope:
    """Build the child's effective scope for one delegated run.

    Args:
        parent: the delegator's effective scope *right now* — which is already
            attenuated if the delegator was itself delegated to, so a chain
            narrows monotonically.
        parent_snapshot: the delegator's snapshot, for ``delegation_policy`` and
            ``max_delegation_depth``. These are the delegator's dials: whether
            *this* agent may hand work on is a fact about its own mandate.
        child_agent_id: the agent being handed the work.
        child_tools: the child's own ``allowed_tools`` — ``None`` for a child
            whose standing mandate is unrestricted, in which case the parent's
            scope is the answer on its own.
        declared: whether Coriqo knows about this delegation. ``False`` gets the
            empty scope.

    Raises:
        DelegationRefusedError: the delegator's policy is not ``attenuated``, or
            the chain would pass ``max_delegation_depth``.
    """
    policy = (parent_snapshot.delegation_policy or DelegationPolicy.NONE).lower()
    if policy != DelegationPolicy.ATTENUATED:
        raise DelegationRefusedError(
            f"agent {parent.agent_id or '?'} has delegation_policy="
            f"{parent_snapshot.delegation_policy!r}; it may not delegate to "
            f"{child_agent_id}"
        )

    depth = parent.depth + 1
    limit = _tightest(parent.max_depth, _declared_depth(parent_snapshot))
    if limit is not None and depth > limit:
        raise DelegationRefusedError(
            f"delegating to {child_agent_id} would reach depth {depth}, past the "
            f"max_delegation_depth of {limit}"
        )

    if declared:
        tools = intersect_tools(parent.allowed_tools, _as_tuple(child_tools))
    else:
        # Not a crash and not a silent pass: the empty scope, which denies every
        # tool by rule rather than by accident.
        tools = ()
        log.warning(
            "coriqo: undeclared delegation - %s -> %s; the child gets the empty "
            "scope for this run",
            parent.agent_id or "?",
            child_agent_id,
        )

    return EffectiveScope(
        allowed_tools=tools,
        # Pinned to the delegator's approval, not the child's.
        mandate_version_id=parent.mandate_version_id,
        agent_id=child_agent_id,
        depth=depth,
        # Enforcement attenuates the same way scope does: any ``enforce``
        # anywhere up the chain enforces.
        enforcement=_strictest(parent.enforcement, parent_snapshot.mandate_enforcement),
        max_depth=limit,
        delegated=True,
        chain=parent.chain + (child_agent_id,),
    )


def _declared_depth(snapshot: MandateSnapshot) -> int | None:
    """``max_delegation_depth``, reading an unparseable value as zero.

    ``None`` means the tenant did not bound the chain. A value that was *sent*
    and could not be read as an integer is a different thing entirely, and
    treating it as "unbounded" would let a typo in a payload lift a limit.
    """
    if snapshot.max_delegation_depth is not None:
        return snapshot.max_delegation_depth
    raw = snapshot.raw.get("max_delegation_depth")
    if raw is None:
        return None
    log.warning(
        "coriqo: max_delegation_depth=%r could not be read as an integer; "
        "treating it as 0 (no delegation)",
        raw,
    )
    return 0


def _tightest(left: int | None, right: int | None) -> int | None:
    if left is None:
        return right
    if right is None:
        return left
    return min(left, right)


def _strictest(left: str | None, right: str | None) -> str:
    """``enforce`` beats ``observe``, and an unknown value beats nothing."""
    values = {value for value in (left, right) if value is not None}
    if not values or values == {Enforcement.OBSERVE}:
        return Enforcement.OBSERVE if values else Enforcement.ENFORCE
    return Enforcement.ENFORCE


def _as_tuple(tools: Iterable[str] | None) -> tuple[str, ...] | None:
    if tools is None:
        return None
    if isinstance(tools, str):
        raise MandateError("child tools must be a list or None, not a string")
    return tuple(str(tool) for tool in tools)


class DelegatedGate(MandateGate):
    """A gate for an agent working inside someone else's mandate.

    It wraps the child's own gate rather than replacing it, so everything the
    child's gate already decides — suspension, staleness, the fail-open /
    fail-closed fork, the no-op path on an unenrolled host — still decides, and
    this class only ever *narrows* the result. Subclassing
    :class:`~byoai.recorder.mandate.MandateGate` is deliberate: ``@governed_tool``
    resolves gates by ``isinstance``, so a delegated run needs no separate
    plumbing at the seam.

    It also keeps the **delegator's** gate and asks it first. The pinned
    :class:`EffectiveScope` is a photograph taken when the delegation happened,
    and a photograph cannot notice that the delegator has since been suspended,
    had its mandate narrowed, or gone stale. Consulting the live parent is what
    makes a revocation reach the sub-agent it lent authority to, in the same
    refresh interval it reaches the parent.
    """

    def __init__(
        self,
        inner: MandateGate,
        scope: EffectiveScope,
        *,
        parent: MandateGate | None = None,
    ) -> None:
        super().__init__(None, agent_id=scope.agent_id or inner.agent_id)
        self._inner = inner
        self._scope = scope
        self._parent = parent

    @property
    def scope(self) -> EffectiveScope:
        return self._scope

    @property
    def inner(self) -> MandateGate:
        return self._inner

    @property
    def parent(self) -> MandateGate | None:
        return self._parent

    @property
    def enabled(self) -> bool:
        return self._inner.enabled

    @property
    def snapshot(self) -> MandateSnapshot | None:
        return self._inner.snapshot

    @property
    def posture(self) -> str:
        return self._inner.posture

    @property
    def latch_version(self) -> str | None:
        """Every version this run is answerable to, as one value.

        A delegated call is decided against three things that can each change
        independently: the delegator's live mandate, the delegation pinned at
        hand-off, and the child's own mandate. Any of them changing is a reason
        for the latch to let the gate decide again, and combining them means the
        latch is asked one question with one answer rather than being fed a
        version that appears to flip on every call.
        """
        upstream = None if self._parent is None else self._parent.latch_version
        return f"{upstream}|{self._scope.mandate_version_id}|{self._inner.latch_version}"

    def decide(self, action: ProposedAction | str) -> Verdict:
        if isinstance(action, str):
            action = ProposedAction(tool=action)

        # 1. The delegator, live. Whatever stops the parent stops the child.
        if self._parent is not None:
            upstream = self._parent.decide(action)
            if not upstream.allowed:
                return replace(
                    upstream,
                    detail=(
                        f"{upstream.detail}; refused for "
                        f"{self._scope.agent_id or '?'} acting under delegation "
                        f"from {self._parent.agent_id or '?'}"
                    ),
                )

        # 2. The child's own gate. A delegated agent is still itself.
        base = self._inner.decide(action)
        # The delegated run answers to the delegator's approval, whatever the
        # child's own snapshot happens to be versioned as.
        base = replace(base, mandate_version_id=self._scope.mandate_version_id)
        if not base.allowed:
            return base

        # 3. The scope pinned at the moment of delegation — which is what an
        #    undeclared hand-off (the empty scope) is caught by.
        if self._scope.permits(action.tool):
            return base

        fields = {
            "mandate_version_id": self._scope.mandate_version_id,
            "snapshot_age_s": base.snapshot_age_s,
            "tool": action.tool,
            "posture": base.posture,
            "enforcement": self._scope.enforcement,
            "trajectory_id": action.trajectory_id,
            "step_index": action.step_index,
        }
        detail = (
            f"{action.tool!r} is outside the scope delegated to "
            f"{self._scope.agent_id or '?'} (depth {self._scope.depth}, chain "
            f"{'->'.join(self._scope.chain) or '?'})"
        )
        # The delegator's dial, not the child's: a child in observe rollout must
        # not thereby run a tool its delegator was refused.
        if self._scope.observing:
            return Flag(
                reason=Reason.DELEGATED_OUT_OF_SCOPE_OBSERVED,
                detail=f"{detail}; the delegator's enforcement is observe",
                **fields,
            )
        return Deny(reason=Reason.DELEGATED_OUT_OF_SCOPE, detail=detail, **fields)


def delegated_gate(
    parent_gate: MandateGate,
    child_gate: MandateGate,
    *,
    child_agent_id: str | None = None,
    parent_scope: EffectiveScope | None = None,
    declared: bool = True,
) -> DelegatedGate:
    """Wire two live gates into a delegated one.

    The convenience form of :func:`delegate` for the common case: both agents
    have a gate, and the delegation is happening now. ``parent_scope`` is for
    the second hop of a chain — pass the delegated scope the parent is itself
    running under, so the narrowing accumulates instead of restarting from the
    parent's standing mandate.

    For a chain, pass the middle agent's :class:`DelegatedGate` as
    ``parent_gate``. That is what keeps the root reachable live: a
    ``DelegatedGate`` asks *its* parent first, so a revocation at the root walks
    down the whole chain. Passing the middle agent's plain gate instead pins the
    root's contribution to the scope it had at hand-off and nothing more.
    """
    parent_snapshot = parent_gate.snapshot
    if parent_snapshot is None:
        raise DelegationRefusedError(
            f"agent {parent_gate.agent_id or '?'} has no mandate snapshot, so "
            "there is no scope to delegate from"
        )
    scope = parent_scope or EffectiveScope.from_snapshot(
        parent_snapshot, agent_id=parent_gate.agent_id
    )
    child_snapshot = child_gate.snapshot
    child_tools = None if child_snapshot is None else child_snapshot.allowed_tools
    child = delegate(
        scope,
        parent_snapshot=parent_snapshot,
        child_agent_id=child_agent_id or child_gate.agent_id or "?",
        child_tools=child_tools,
        declared=declared and child_snapshot is not None,
    )
    return DelegatedGate(child_gate, child, parent=parent_gate)
