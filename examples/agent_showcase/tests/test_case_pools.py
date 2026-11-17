"""Case pools and the history backfill.

Every case's cached transcript has to agree with the mock bank's data: a
transcript that looks up an id the mocks don't have would seal an ``error``
result, and a backfilled quarter would be full of them.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

import httpx
import pytest
from examples.agent_showcase import backfill
from examples.agent_showcase.agents.registry import list_agents
from examples.agent_showcase.mocks import case_data
from examples.agent_showcase.mocks.bank import MISFIRE_FRAUD_TRIAGE_DISPATCH
from examples.agent_showcase.runner import FALLBACKS_DIR, AgentRunner

from byoai.recorder import coriqo_agents
from byoai.recorder import integration as recorder_integration
from byoai.recorder.coriqo_agents import AgentRegistration, CoriqoAgentsClient, CoriqoCredentials
from byoai.recorder.schema import now_ts_device, set_device_clock

CASE_AGENTS = [a for a in list_agents() if a.cases]
# Replaying every case through the runner is slow at this pool size; a sample
# per agent covers the runner, and the static check below covers every case.
SAMPLED_CASES = [(agent, case) for agent in CASE_AGENTS for case in agent.cases[:3]]


@pytest.fixture
def recorder_env(tmp_path, monkeypatch):
    monkeypatch.setenv("BYOAI_RECORDER_ENABLED", "1")
    monkeypatch.setenv("BYOAI_RECORDER_DIR", str(tmp_path / "ledger"))
    recorder_integration.reset_recorder_for_tests()
    yield
    recorder_integration.reset_recorder_for_tests()


def test_every_banking_agent_except_bedrock_has_a_varied_pool():
    pools = {a.id: a.cases for a in list_agents() if a.domain == "banking"}
    for agent_id, cases in pools.items():
        if agent_id == "b6-bedrock-sanctions-review":
            assert cases == ()
            continue
        assert len(cases) >= backfill.max_runs(agent_id, 90), agent_id
        assert len({c.id for c in cases}) == len(cases)
        assert len({c.scenario_message for c in cases}) == len(cases)


def test_a_single_recorded_scenario_is_planned_once():
    banking = [a for a in list_agents() if a.domain == "banking"]
    plan = backfill.plan_runs(banking, days=90, seed=7)
    assert sum(run.agent.id == "b6-bedrock-sanctions-review" for run in plan) <= 1


def test_misfire_is_a_minority_of_its_pool():
    b5 = next(a for a in list_agents() if a.id == "b5-misfire-demo")
    wires = [
        c for c in b5.cases
        if any(
            call["name"] == "initiate_wire_transfer"
            for step in json.loads((FALLBACKS_DIR / c.fallback_file).read_text())["steps"]
            for call in step["tool_calls"]
        )
    ]
    assert 1 <= len(wires) <= 0.05 * len(b5.cases)


def _dispatch_for(agent):
    tables = dict(agent.dispatch)
    for sub in agent.sub_agent_tools.values():
        tables.update(sub.dispatch)
    if agent.id == "b5-misfire-demo":
        tables.update(MISFIRE_FRAUD_TRIAGE_DISPATCH)
    return tables


@pytest.mark.parametrize("agent", CASE_AGENTS, ids=[a.id for a in CASE_AGENTS])
def test_every_transcript_tool_call_resolves_in_the_mocks(agent):
    """Generator output agrees with itself: each call a transcript makes,
    including its sub-agents', returns real mock data rather than an error."""
    dispatch = _dispatch_for(agent)
    for case in agent.cases:
        files = [case.fallback_file, *(file for _, file in case.sub_cases.values())]
        for file in files:
            transcript = json.loads((FALLBACKS_DIR / file).read_text())
            assert transcript["steps"][-1]["tool_calls"] == [] and transcript["steps"][-1]["assistant_text"]
            for step in transcript["steps"]:
                for call in step["tool_calls"]:
                    result = dispatch[call["name"]](call["input"])
                    assert not (isinstance(result, dict) and "error" in result), (file, call, result)


def test_no_person_appears_in_two_cases():
    people = (
        [c["name"] for c in case_data.CUSTOMER_HISTORY.values()]
        + [a["applicant_name"] for a in case_data.ONBOARDING_APPLICATIONS.values()]
        + [d["cardholder_name"] for d in case_data.DISPUTES.values()]
        + [a["applicant_name"] for a in case_data.LOAN_APPLICATIONS.values()]
    )
    assert len(people) == len(set(people))
    total = sum(len(a.cases) for a in CASE_AGENTS)
    assert len(people) == total


@pytest.mark.parametrize(("agent", "case"), SAMPLED_CASES, ids=[f"{a.id}:{c.id}" for a, c in SAMPLED_CASES])
async def test_each_case_replays_without_tool_errors(recorder_env, agent, case):
    results = []
    outcome = None
    async for event in AgentRunner(agent, case=case).run(replay=True):
        if event.kind == "tool_result":
            results.append((event.tool_name, event.data["result"]))
        if event.kind == "run_complete":
            outcome = event
    assert outcome is not None and outcome.data["mode"] == "cached"
    assert results
    for name, result in results:
        assert not (isinstance(result, dict) and "error" in result), (name, result)
    assert case.id in outcome.text


def test_for_case_binds_sub_agents_to_the_same_case():
    b2 = next(a for a in list_agents() if a.id == "b2-kyc-onboarding")
    case = b2.cases[3]
    bound = b2.for_case(case)
    sub = bound.sub_agent_tools["sanctions_screen"]
    assert bound.fallback_file == case.fallback_file
    assert sub.fallback_file == case.sub_cases[sub.id][1]
    assert b2.sub_agent_tools["sanctions_screen"].fallback_file != sub.fallback_file


def test_plan_is_deterministic_business_hours_and_domain_scoped():
    banking = [a for a in list_agents() if a.domain == "banking"]
    first = backfill.plan_runs(banking, days=30, seed=7, today=date(2026, 9, 12))
    second = backfill.plan_runs(banking, days=30, seed=7, today=date(2026, 9, 12))
    assert [(r.at, r.agent.id, r.case and r.case.id) for r in first] == [
        (r.at, r.agent.id, r.case and r.case.id) for r in second
    ]
    eastern = ZoneInfo("America/New_York")
    for run in first:
        local = run.at.astimezone(eastern)
        assert local.weekday() < 5
        assert 8 <= local.hour < 18
        assert run.agent.domain == "banking"
    assert [r.at for r in first] == sorted(r.at for r in first)
    assert {r.agent.id for r in first} >= {"b1-fraud-triage", "b4-loan-prequalification"}


@pytest.mark.parametrize("seed", [1, 20260912, 99])
def test_a_ninety_day_plan_never_repeats_a_case(seed):
    banking = [a for a in list_agents() if a.domain == "banking"]
    plan = backfill.plan_runs(banking, days=90, seed=seed, today=date(2026, 9, 12))
    drawn = [(r.agent.id, r.case.id) for r in plan if r.case is not None]
    assert len(drawn) == len(set(drawn))
    for agent_id in backfill.RUNS_PER_DAY:
        runs = sum(1 for r in plan if r.agent.id == agent_id)
        assert runs <= backfill.max_runs(agent_id, 90)


def test_a_plan_larger_than_the_pool_fails_loudly():
    b1 = next(a for a in list_agents() if a.id == "b1-fraud-triage")
    tiny = replace(b1, cases=b1.cases[:5])
    with pytest.raises(backfill.CasePoolExhausted, match="b1-fraud-triage"):
        backfill.plan_runs([tiny], days=30, seed=1, today=date(2026, 9, 12))


def test_device_clock_is_injectable_and_restorable():
    fixed = datetime(2026, 6, 1, 13, 30, tzinfo=timezone.utc)
    previous = set_device_clock(lambda: fixed)
    try:
        assert now_ts_device() == "2026-06-01T13:30:00.000000Z"
    finally:
        set_device_clock(previous)
    assert now_ts_device() != "2026-06-01T13:30:00.000000Z"


def _client(handler, monkeypatch):
    real = httpx.Client

    def factory(**kwargs):
        kwargs.pop("transport", None)
        return real(**kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(coriqo_agents.httpx, "Client", factory)
    return CoriqoAgentsClient(CoriqoCredentials(base_url="http://coriqo.test", api_key="k", tenant_slug="t"))


def test_trajectory_times_are_sent_only_when_given(monkeypatch):
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        return httpx.Response(201, json={"trajectory_id": "tr"})

    client = _client(handler, monkeypatch)
    client.open_trajectory("a", goal="g")
    client.open_trajectory("a", goal="g", started_at="2026-06-01T13:30:00.000000Z")
    client.complete_trajectory("a", "tr")
    client.complete_trajectory("a", "tr", ended_at="2026-06-01T13:31:00.000000Z")
    assert "started_at" not in bodies[0]
    assert bodies[1]["started_at"] == "2026-06-01T13:30:00.000000Z"
    assert bodies[2] == {"status": "completed"}
    assert bodies[3]["ended_at"] == "2026-06-01T13:31:00.000000Z"


def test_registration_sends_use_case_only_when_set():
    assert "use_case" not in AgentRegistration(name="x").to_body()
    assert AgentRegistration(name="x", use_case="fraud-detection").to_body()["use_case"] == "fraud-detection"
