"""TI-20 snapshot fields: prohibited_tools, on_violation, environment,
output_inspection — and the pin that a snapshot without them behaves exactly
as before they existed."""

from __future__ import annotations

import pytest

from byoai.errors import MandateDeniedError, MandateRunHaltedError
from byoai.recorder.denial_latch import denial_latch
from byoai.recorder.governed_tool import governed_tool
from byoai.recorder.mandate import (
    MODEL_MESSAGE,
    Allow,
    Deny,
    Flag,
    MandateGate,
    Posture,
    ProposedAction,
    Reason,
    RequireApproval,
)
from byoai.recorder.proxy_gate import ProxyEnforcer

from .test_mandate import FakeClock, snapshot_payload

TOOLS = ["search", "transfer_funds", "delete_account", "rm"]
TI20_KEYS = ("prohibited_tools", "on_violation", "environment", "output_inspection")


@pytest.fixture(autouse=True)
def _no_env_environment(monkeypatch):
    monkeypatch.delenv("BYOAI_MANDATE_ENVIRONMENT", raising=False)


def gate(runtime_env: str | None = None, **overrides) -> MandateGate:
    async def never(_etag):  # pragma: no cover - decide does no I/O
        raise AssertionError("decide must not refresh")

    g = MandateGate(never, agent_id="agent-ti20", clock=FakeClock(), environment=runtime_env)
    g.apply_snapshot(snapshot_payload(**overrides))
    return g


def _shape(verdict) -> tuple:
    return (type(verdict).__name__, verdict.reason, verdict.allowed, verdict.detail)


@pytest.mark.parametrize("enforcement", ["enforce", "observe"])
@pytest.mark.parametrize("allowed", [["search"], None, []])
def test_snapshot_without_ti20_keys_decides_as_before(enforcement, allowed):
    """Unset means today: none of the four keys on the wire, and every tool
    decides exactly as an explicitly default-valued snapshot does, with the
    same reasons and operator detail as before TI-20."""
    plain = gate(mandate_enforcement=enforcement, allowed_tools=allowed)
    snap = plain.snapshot
    assert snap is not None
    assert not any(key in snap.raw for key in TI20_KEYS)
    assert snap.prohibited_tools == ()
    assert snap.on_violation == "deny"
    assert snap.environment is None
    assert dict(snap.output_inspection) == {}
    defaulted = gate(
        mandate_enforcement=enforcement,
        allowed_tools=allowed,
        prohibited_tools=[],
        on_violation="deny",
    )
    for tool in TOOLS:
        assert _shape(plain.decide(tool)) == _shape(defaulted.decide(tool))
        assert plain.decide(tool).halt_run is False
    if enforcement == "enforce" and allowed == ["search"]:
        assert plain.decide("rm").detail == "'rm' is not in the agent's approved scope"
    if enforcement == "observe" and allowed == ["search"]:
        assert plain.decide("rm").detail == (
            "'rm' is not in the agent's approved scope; enforcement is observe"
        )


def test_prohibited_denies_with_no_allow_list():
    g = gate(allowed_tools=None, prohibited_tools=["delete_account"])
    assert type(g.decide("search")) is Allow
    verdict = g.decide("delete_account")
    assert isinstance(verdict, Deny)
    assert verdict.reason == Reason.OUT_OF_SCOPE
    assert "prohibited" in (verdict.detail or "")
    assert verdict.model_message == MODEL_MESSAGE


def test_prohibited_wins_over_allowed_and_over_approval():
    g = gate(
        allowed_tools=["delete_account"],
        prohibited_tools=["delete_account"],
        approval_required_tools=["delete_account"],
    )
    verdict = g.decide("delete_account")
    assert isinstance(verdict, Deny)
    assert not isinstance(verdict, RequireApproval)


def test_prohibited_under_shadow_is_flagged_not_blocked():
    g = gate(mandate_enforcement="observe", allowed_tools=None, prohibited_tools=["rm"])
    verdict = g.decide("rm")
    assert type(verdict) is Flag
    assert verdict.reason == Reason.OUT_OF_SCOPE_OBSERVED


def test_alert_only_allows_and_flags_as_a_real_violation():
    g = gate(on_violation="alert_only")
    verdict = g.decide("rm")
    assert type(verdict) is Flag
    assert verdict.allowed
    assert verdict.reason == Reason.OUT_OF_SCOPE
    assert type(g.decide("search")) is Allow


def test_unknown_on_violation_reads_as_deny():
    g = gate(on_violation="shrug")
    assert g.snapshot is not None and g.snapshot.on_violation == "deny"
    assert isinstance(g.decide("rm"), Deny)


def test_deny_and_halt_run_halts_on_the_first_denial():
    g = gate(on_violation="deny_and_halt_run")
    enforcer = ProxyEnforcer(g, run_id="run-halt")
    first = enforcer.decide("rm")
    assert first.denied and first.halted
    assert first.verdict.halt_run is True
    # The run is over: an in-scope tool is refused from the latch too.
    after = enforcer.decide("search")
    assert after.denied and after.halted
    assert after.verdict.reason == Reason.RUN_HALTED


def test_plain_deny_still_waits_for_the_latch_threshold():
    g = gate()
    enforcer = ProxyEnforcer(g, run_id="run-plain")
    assert not enforcer.decide("rm").halted
    assert enforcer.decide("search").allowed


def test_deny_and_halt_run_through_governed_tool_raises_halted():
    g = gate(on_violation="deny_and_halt_run")

    @governed_tool(name="rm", gate=g)
    def rm() -> str:  # pragma: no cover - must not run
        return "ran"

    with pytest.raises(MandateRunHaltedError) as info:
        rm()
    assert str(info.value) == MODEL_MESSAGE


@pytest.mark.parametrize("posture,expect", [(Posture.FAIL_OPEN, Flag), (Posture.FAIL_CLOSED, Deny)])
def test_environment_mismatch_is_decided_by_posture(posture, expect):
    g = gate(runtime_env="production", enforcement_posture=posture, environment="staging")
    verdict = g.decide("search")
    assert type(verdict) is expect
    assert verdict.reason == Reason.ENVIRONMENT_MISMATCH


def test_environment_matches_or_is_not_compared():
    assert type(gate(runtime_env="production", environment="production").decide("search")) is Allow
    # The gate was told nothing: the snapshot's environment is not compared.
    assert type(gate(environment="staging").decide("search")) is Allow
    # The snapshot names none: nothing to compare.
    assert type(gate(runtime_env="production").decide("search")) is Allow


def test_environment_from_env_var(monkeypatch):
    monkeypatch.setenv("BYOAI_MANDATE_ENVIRONMENT", "production")
    g = gate(enforcement_posture=Posture.FAIL_CLOSED, environment="staging")
    assert g.environment == "production"
    assert isinstance(g.decide("search"), Deny)


def test_suspension_still_denies_on_environment_mismatch():
    g = gate(runtime_env="production", status="suspended", environment="staging")
    assert g.decide("search").reason == Reason.AGENT_SUSPENDED


def test_output_inspection_is_kept_and_ignored():
    switches = {"instruction_like": "flag", "secrets": "redact", "pii": "off"}
    g = gate(output_inspection=switches)
    assert g.snapshot is not None and dict(g.snapshot.output_inspection) == switches
    assert type(g.decide("search")) is Allow


def test_offered_tools():
    names = ["search", "transfer_funds", "delete_account", "approve_me"]
    enforce = gate(
        allowed_tools=["search"],
        prohibited_tools=["delete_account"],
        approval_required_tools=["approve_me"],
    )
    assert enforce.offered_tools(names) == ["search", "approve_me"]
    # Shadow and alert_only block nothing, so they hide nothing.
    shadow = gate(mandate_enforcement="observe", allowed_tools=["search"])
    assert shadow.offered_tools(names) == names
    assert gate(on_violation="alert_only").offered_tools(names) == names
    # No gate at all: everything.
    assert MandateGate(None).offered_tools(names) == names


def test_offered_tools_with_no_snapshot_follow_posture():
    async def src(_etag):  # pragma: no cover
        raise AssertionError

    closed = MandateGate(src, default_posture=Posture.FAIL_CLOSED)
    assert closed.offered_tools(["search"]) == []
    opened = MandateGate(src, default_posture=Posture.FAIL_OPEN)
    assert opened.offered_tools(["search"]) == ["search"]


# -- the approval-required fix (found while building TI-21) -----------------


def test_proxy_enforcer_withholds_an_approval_required_call():
    reported: list[RequireApproval] = []

    async def never(_etag):  # pragma: no cover
        raise AssertionError

    g = MandateGate(never, agent_id="a", clock=FakeClock(),
                    report_approval_request=reported.append)
    g.apply_snapshot(snapshot_payload(approval_required_tools=["wire"]))
    decision = ProxyEnforcer(g, run_id="run-approval").decide("wire")
    assert decision.denied
    assert isinstance(decision.verdict, RequireApproval)
    assert len(reported) == 1
    # Not latched: a later snapshot carrying the approval can let it run.
    assert denial_latch().attempts("run-approval", "a", "wire") == 0


def test_governed_tool_refuses_an_approval_required_call():
    g = gate(approval_required_tools=["wire"])
    ran: list[str] = []

    @governed_tool(name="wire", gate=g)
    def wire() -> str:
        ran.append("wire")
        return "sent"

    with pytest.raises(MandateDeniedError) as info:
        wire()
    assert str(info.value) == MODEL_MESSAGE
    assert ran == []


def test_proposed_action_with_ti20_snapshot_keeps_budget_order():
    # A flagged alert_only call still counts against the step budget.
    g = gate(on_violation="alert_only", max_run_steps=1)
    first = g.decide(ProposedAction(tool="rm", trajectory_id="t", step_index=0))
    assert type(first) is Flag
    second = g.decide(ProposedAction(tool="search", trajectory_id="t", step_index=1))
    assert isinstance(second, Deny)
    assert second.reason == Reason.BUDGET_STEP_LIMIT_EXCEEDED


def test_stop_grace_s_is_read_from_the_snapshot_and_bad_values_are_ignored():
    from byoai.recorder.mandate import MandateSnapshot

    def snap(**extra):
        return MandateSnapshot.from_payload({"allowed_tools": None, **extra}, received_at=0.0)

    assert snap().stop_grace_s is None  # absent: the runtime's default applies
    assert snap(stop_grace_s=45).stop_grace_s == 45.0
    for bad in (0, 601, -1, True, "10"):
        assert snap(stop_grace_s=bad).stop_grace_s is None


def test_a_files_stop_grace_s_reaches_the_snapshot_payload():
    from byoai.recorder.mandate_file import snapshot_payload

    base = {"mode": "enforce", "on_stale_snapshot": "fail_open", "max_staleness_s": 300,
            "tools": {"allowed": None, "prohibited": []}, "on_violation": "deny",
            "delegation": {"policy": "none", "max_depth": 3}, "output_inspection": {}}
    assert "stop_grace_s" not in snapshot_payload(base, sha256="0" * 64)
    assert snapshot_payload({**base, "stop_grace_s": 30}, sha256="0" * 64)["stop_grace_s"] == 30
