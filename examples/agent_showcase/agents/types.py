"""Shared agent definition type. Split out from banking.py/healthcare.py so both
(and the runner's sub-agent spawn path) can share one type without cycles."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from typing import Any


@dataclass(frozen=True)
class Case:
    """One concrete piece of work from an agent's pool: its own prompt and the
    cached transcript that replays it. ``sub_cases`` maps a sub-agent id to the
    (scenario_message, fallback_file) that sub-agent uses for this case."""

    id: str
    scenario_message: str
    fallback_file: str
    sub_cases: dict[str, tuple[str, str]] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentDef:
    id: str
    name: str
    domain: str
    description: str
    system_prompt: str
    tools: list[dict[str, Any]]
    dispatch: dict[str, Callable[[dict[str, Any]], Any]]
    scenario_message: str
    model: str = "claude-sonnet-5"
    provider: str = "anthropic"
    fallback_file: str = ""
    # tool name -> the AgentDef of a sub-agent spawned when that tool is called.
    # The tool's dispatch entry (if any) is ignored for these names; the runner
    # runs a nested AgentRunner instead and its final text becomes the tool result.
    sub_agent_tools: dict[str, AgentDef] = field(default_factory=dict)
    # Business system and regulated use case as a bank's own registry would
    # name them. Empty system falls back to the showcase namespace.
    system: str = ""
    use_case: str | None = None
    cases: tuple[Case, ...] = ()

    def for_case(self, case: Case) -> AgentDef:
        """This agent bound to one case: its prompt and transcript, and its
        sub-agents' too, so a nested run replays the same case."""
        subs = {
            tool: replace(sub, scenario_message=case.sub_cases[sub.id][0], fallback_file=case.sub_cases[sub.id][1])
            if sub.id in case.sub_cases
            else sub
            for tool, sub in self.sub_agent_tools.items()
        }
        return replace(
            self,
            scenario_message=case.scenario_message,
            fallback_file=case.fallback_file,
            sub_agent_tools=subs,
        )

    @property
    def sub_agents(self) -> list[str]:
        return [sub.name for sub in self.sub_agent_tools.values()]

    @property
    def declared_tool_names(self) -> set[str]:
        """Tool names this agent's model-facing schema actually offers. A tool
        call whose name falls outside this set (and isn't a sub-agent trigger)
        was never granted to the model — see is_out_of_scope."""
        return {t["name"] for t in self.tools}

    def is_out_of_scope(self, tool_name: str) -> bool:
        return tool_name not in self.declared_tool_names and tool_name not in self.sub_agent_tools
