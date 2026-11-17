"""Backfill a realistic run history for the showcase agents.

    python -m examples.agent_showcase.backfill --days 90 --domain banking

Every run goes through the same path a live one does: ``AgentRunner`` replays a
case's cached transcript, the recorder seals each step into the ledger, and
``publish_session`` sends it to Coriqo. The only thing that differs is the
clock. ``ts_device`` is set to when the run is scheduled — business days,
08:00-18:00 US Eastern, steps a few seconds apart — and the trajectory carries
the matching ``started_at``/``ended_at``. ``ts_device`` has never been trusted
for ordering (``seq`` and the hash chain are), which is what makes backdating
it honest rather than a forgery of the ledger.

Runs are generated oldest first, so ledger ``seq`` order and time order agree.
Use a dedicated ``--ledger-dir``: appending a past quarter after today's live
runs in the showcase's own ledger would put the two orders out of step.

Needs ``BYOAI_CORIQO_URL``, ``BYOAI_CORIQO_API_KEY`` and
``BYOAI_CORIQO_TENANT_SLUG`` unless ``--dry-run``.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import random
import sys
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from byoai.recorder.schema import format_ts_device, set_device_clock

from .agents.types import AgentDef, Case

log = logging.getLogger("agent_showcase.backfill")

BUSINESS_TZ = ZoneInfo("America/New_York")
OPEN, CLOSE = time(8, 0), time(18, 0)
# Monday is busiest (weekend backlog), Friday tails off.
WEEKDAY_WEIGHT = {0: 1.15, 1: 1.0, 2: 1.0, 3: 0.95, 4: 0.8}
# What a community bank's agent fleet plausibly handles per business day,
# before the weekday weight. Held payments reach the Bedrock sanctions reviewer
# rarely. tools/generate_cases.py sizes each case pool from this table.
RUNS_PER_DAY = {
    "b1-fraud-triage": (1, 5),
    "b2-kyc-onboarding": (1, 4),
    "b3-dispute-resolution": (0, 3),
    "b4-loan-prequalification": (1, 4),
    "b5-misfire-demo": (0, 2),
    "b6-bedrock-sanctions-review": (0, 1),
}
DEFAULT_RUNS_PER_DAY = (1, 3)


class CasePoolExhausted(RuntimeError):
    """A plan needs more distinct cases than an agent's pool holds."""


def max_runs(agent_id: str, days: int) -> int:
    """The most runs ``plan_runs`` can schedule for one agent over ``days``:
    every business day at the top of its range on the heaviest weekday."""
    high = RUNS_PER_DAY.get(agent_id, DEFAULT_RUNS_PER_DAY)[1]
    business_days = sum(1 for offset in range(days) if (offset % 7) < 5) + 1
    return round(high * max(WEEKDAY_WEIGHT.values())) * business_days


class StepClock:
    """A wall clock that starts where it is set and moves a few seconds on
    every read, so consecutive sealed steps land seconds apart."""

    def __init__(self, rng: random.Random) -> None:
        self._rng = rng
        self.now = datetime.now(timezone.utc)

    def __call__(self) -> datetime:
        current = self.now
        self.now = current + timedelta(seconds=self._rng.uniform(1.2, 7.5))
        return current


@dataclass(frozen=True)
class PlannedRun:
    at: datetime
    agent: AgentDef
    case: Case | None


def _business_days(days: int, today: date) -> list[date]:
    return [
        d
        for d in (today - timedelta(days=offset) for offset in range(days, 0, -1))
        if d.weekday() < 5
    ]


def plan_runs(agents: list[AgentDef], *, days: int, seed: int, today: date | None = None) -> list[PlannedRun]:
    """Cases are drawn without replacement: a real queue never sees the same
    transaction twice, so a plan that would need a repeat raises instead."""
    rng = random.Random(seed)
    slots: dict[str, list[datetime]] = {agent.id: [] for agent in agents}
    for day in _business_days(days, today or datetime.now(BUSINESS_TZ).date()):
        weight = WEEKDAY_WEIGHT[day.weekday()]
        opening = datetime.combine(day, OPEN, BUSINESS_TZ)
        span = (datetime.combine(day, CLOSE, BUSINESS_TZ) - opening).total_seconds()
        for agent in agents:
            low, high = RUNS_PER_DAY.get(agent.id, DEFAULT_RUNS_PER_DAY)
            for _ in range(round(rng.randint(low, high) * weight)):
                slots[agent.id].append((opening + timedelta(seconds=rng.uniform(0, span))).astimezone(timezone.utc))

    planned: list[PlannedRun] = []
    for agent in agents:
        times = sorted(slots[agent.id])
        if not agent.cases:
            # One recorded scenario is one real event; replaying it daily is the
            # exact repetition the case pools exist to avoid.
            planned.extend(PlannedRun(at=at, agent=agent, case=None) for at in times[-1:])
            continue
        if len(times) > len(agent.cases):
            raise CasePoolExhausted(
                f"{agent.id}: plan needs {len(times)} distinct cases, pool has {len(agent.cases)}; "
                "regenerate with tools/generate_cases.py or shorten --days"
            )
        drawn = rng.sample(agent.cases, len(times))
        planned.extend(PlannedRun(at=at, agent=agent, case=case) for at, case in zip(times, drawn, strict=True))
    planned.sort(key=lambda run: (run.at, run.agent.id))
    return planned


def _iso(dt: datetime) -> str:
    return format_ts_device(dt)


async def _execute(planned: list[PlannedRun], *, publish: bool, clock: StepClock) -> dict[str, int]:
    from byoai.recorder.coriqo_agents import (
        CoriqoAgentsClient,
        CoriqoAgentsError,
        CoriqoCredentials,
        publish_session,
    )
    from byoai.recorder.integration import get_recorder

    from . import coriqo_sync
    from .runner import AgentRunner

    recorder = get_recorder()
    if recorder is None:
        raise SystemExit("recorder failed to start; check --ledger-dir is writable")

    agent_map: dict[str, str] = {}
    client = None
    if publish:
        credentials = CoriqoCredentials.from_env()
        if credentials is None:
            raise SystemExit("set BYOAI_CORIQO_URL, BYOAI_CORIQO_API_KEY and BYOAI_CORIQO_TENANT_SLUG, or pass --dry-run")
        agents = list({run.agent.id: run.agent for run in planned}.values())
        agent_map = coriqo_sync.ensure_agents_registered(agents)
        missing = [a.id for a in agents if a.id not in agent_map]
        if missing:
            raise SystemExit(f"could not register with Coriqo: {', '.join(missing)}")
        client = CoriqoAgentsClient(credentials)

    totals = {"runs": 0, "published": 0, "flagged": 0, "failed": 0}
    try:
        for index, run in enumerate(planned, start=1):
            clock.now = run.at
            started_at = _iso(run.at)
            runner = AgentRunner(run.agent, case=run.case)
            final_text = ""
            run_id = None
            async for event in runner.run(replay=True):
                if event.kind == "run_complete":
                    final_text = event.text or ""
                    run_id = event.data["run_id"]
            ended_at = _iso(clock.now)
            totals["runs"] += 1

            if client is not None and run_id is not None:
                try:
                    result = publish_session(
                        client,
                        coriqo_agent_id=agent_map[run.agent.id],
                        ledger=recorder.ledger,
                        session_id=run_id,
                        goal=run.agent.scenario_message if run.case is None else run.case.scenario_message,
                        use_case=run.agent.use_case,
                        final_output=final_text,
                        payload_mode=recorder.payload_mode,
                        inputs_extra={"showcase_agent": run.agent.id, "case_id": run.case.id if run.case else "default"},
                        started_at=started_at,
                        ended_at=ended_at,
                    )
                except CoriqoAgentsError as exc:
                    totals["failed"] += 1
                    log.warning("backfill: %s %s failed to publish: %s", run.agent.id, run_id, exc.detail)
                else:
                    if result is not None:
                        totals["published"] += 1
                        totals["flagged"] += result.status == "flagged"

            if index % 50 == 0 or index == len(planned):
                log.info("backfill: %d/%d runs (%s)", index, len(planned), started_at[:10])
    finally:
        if client is not None:
            client.close()
    return totals


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--days", type=int, default=90, help="calendar days of history ending yesterday")
    parser.add_argument("--domain", choices=["banking", "healthcare", "all"], default="banking")
    parser.add_argument("--seed", type=int, default=20260912, help="same seed, same schedule and cases")
    parser.add_argument("--ledger-dir", default=str(Path.home() / ".byoai" / "backfill-ledger"))
    parser.add_argument("--dry-run", action="store_true", help="run and seal locally, publish nothing")
    parser.add_argument("--limit", type=int, default=None, help="stop after this many runs (oldest first)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # This process exists to fill one ledger; it owns its recorder settings.
    os.environ["BYOAI_RECORDER_ENABLED"] = "1"
    os.environ["BYOAI_RECORDER_DIR"] = args.ledger_dir

    from .agents.registry import list_agents

    agents = [a for a in list_agents() if args.domain == "all" or a.domain == args.domain]
    try:
        planned = plan_runs(agents, days=args.days, seed=args.seed)
    except CasePoolExhausted as exc:
        log.error("backfill: %s", exc)
        return 2
    if args.limit is not None:
        planned = planned[: args.limit]
    if not planned:
        log.info("backfill: nothing to run")
        return 0
    per_agent: dict[str, int] = {}
    for run in planned:
        per_agent[run.agent.name] = per_agent.get(run.agent.name, 0) + 1
    log.info("backfill: %d runs from %s to %s", len(planned), planned[0].at.date(), planned[-1].at.date())
    for name, count in sorted(per_agent.items()):
        log.info("  %-40s %d", name, count)

    clock = StepClock(random.Random(args.seed))
    previous = set_device_clock(clock)
    try:
        totals = asyncio.run(_execute(planned, publish=not args.dry_run, clock=clock))
    finally:
        set_device_clock(previous)
    log.info("backfill: done %s", totals)
    return 1 if totals["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
