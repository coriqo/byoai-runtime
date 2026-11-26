"""AgentRunner: tool-use loop for one demo agent, capture-instrumented.

Every model turn and tool call flows through byoai-runtime's Anthropic
provider and the recorder's public capture API (record_request_body /
record_response_body against real Anthropic wire-format bodies) — the demo
never hand-rolls ledger events.

Sub-agents (B2, B4, H1): a triggering tool name maps to another AgentDef in
``agent.sub_agent_tools``. When the parent's tool loop hits that name, it
runs a nested AgentRunner sharing the parent's trace_id with
parent_span_id=<parent's own span_id>, re-surfaces the sub-run's events
(correctly attributed), and folds the sub-run's final text into the parent's
tool result — this is what gives the span tree its branches.

H1-H4 are labeled provider="openai"/model="gpt-4o" and make real
chat-completions calls via OpenAICompatProvider. The recorder's extractor
only understands Anthropic wire-format bodies, so the OpenAI
live path normalizes each request/response into that shape (text/tool_use
content blocks) before handing it to record_request_body/record_response_body
— the *actual* call on the wire is genuine OpenAI chat-completions; only the
bytes fed to the recorder are re-shaped so one extractor covers both
providers. Missing/invalid credentials for either provider raise
ConfigurationError/ProviderError (both ByoAIError), which the fallback path
below catches — so a run with no API key transparently replays a cached
transcript instead of live-calling.

B6 is provider="bedrock_agent" and is not run by this loop at all. A managed
AWS Bedrock Agent runs its own orchestration inside AWS, so there is no tool
loop here to instrument; the run is invoked (or its recorded trace replayed)
and ``byoai.recorder.bedrock_agent`` normalizes the resulting trace stream
into the same sealed events. Both paths go through that one normalizer, so
the no-credentials replay exercises the live code rather than standing in
for it.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from byoai.errors import ByoAIError, ConfigurationError, ProviderError
from byoai.providers.anthropic import AnthropicProvider
from byoai.providers.openai_compat import OpenAICompatProvider
from byoai.recorder.bedrock_agent import PROVIDER as BEDROCK_AGENT_PROVIDER
from byoai.recorder.bedrock_agent import normalize_run, seal_run
from byoai.recorder.integration import get_recorder
from byoai.recorder.schema import EventKind, new_span_id, new_trace_id
from byoai.types import Message

from .agents.types import AgentDef, Case

log = logging.getLogger("agent_showcase.runner")

MAX_TURNS = 8
FALLBACKS_DIR = Path(__file__).parent / "fallbacks"

# TTL for live OpenAI/Anthropic API calls: once an agent has been called live,
# repeat demo runs within this window replay its fallback transcript instead
# of spending real API credits again. Keeps a "Run" button demo cheap to mash
# without needing a key check on every click. Persisted to disk (see
# LIVE_CALL_STATE_PATH) so the cooldown survives a server restart.
# `force_live=True` bypasses it for a specific run.
LIVE_CALL_TTL_SECONDS = 24 * 60 * 60
LIVE_CALL_STATE_PATH = Path(
    os.environ.get("BYOAI_DEMO_LIVE_CALL_STATE", str(Path.home() / ".byoai" / "agent_showcase_live_calls.json"))
)


def _load_last_live_call() -> dict[str, float]:
    try:
        raw = json.loads(LIVE_CALL_STATE_PATH.read_text())
    except (OSError, ValueError) as exc:
        log.warning("agent_showcase: ignoring unreadable live-call state at %s: %s", LIVE_CALL_STATE_PATH, exc)
        return {}
    if not isinstance(raw, dict):
        return {}
    state: dict[str, float] = {}
    for key, value in raw.items():
        try:
            state[str(key)] = float(value)
        except (TypeError, ValueError):
            log.warning("agent_showcase: dropping malformed live-call state entry %r=%r", key, value)
    return state


def _save_last_live_call(state: dict[str, float]) -> None:
    # Write to a sibling temp file and rename over the target so a reader
    # never observes a partially-written file (json.loads on a torn read
    # would otherwise be caught by _load_last_live_call and silently wipe
    # every agent's cooldown).
    try:
        LIVE_CALL_STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = LIVE_CALL_STATE_PATH.with_suffix(f".{uuid.uuid4().hex[:8]}.tmp")
        tmp_path.write_text(json.dumps(state))
        os.replace(tmp_path, LIVE_CALL_STATE_PATH)
    except OSError:
        log.warning("agent_showcase: failed to persist live-call state to %s", LIVE_CALL_STATE_PATH)


# Loaded lazily (on first cooldown check) rather than at import time, so tests
# that monkeypatch LIVE_CALL_STATE_PATH before the first run() still see their
# own isolated state instead of whatever was on disk at import.
_LAST_LIVE_CALL: dict[str, float] = {}
_live_call_state_loaded = False


def _ensure_live_call_state_loaded() -> None:
    global _live_call_state_loaded
    if not _live_call_state_loaded:
        _LAST_LIVE_CALL.update(_load_last_live_call())
        _live_call_state_loaded = True

# Fallback-transcript replay has no network latency of its own, so without a
# deliberate pace every step fires back-to-back in a handful of milliseconds
# — too fast for a human to see the UI's per-step indicators (heartbeat,
# active card, workflow-graph node) light up. Off by default (0ms) so the
# test suite stays fast/deterministic; start.sh sets
# BYOAI_DEMO_STEP_DELAY_MS for the live demo experience.
FALLBACK_STEP_DELAY_SECONDS = float(os.environ.get("BYOAI_DEMO_STEP_DELAY_MS", "0")) / 1000


@dataclass
class RunEvent:
    """One event surfaced to the UI/SSE stream. Mirrors what the recorder sealed."""

    kind: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    tool_name: str | None = None
    text: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)


def _new_run_id() -> str:
    return "run_" + uuid.uuid4().hex[:12]


class AgentRunner:
    """Runs one agent's canned scenario end-to-end, sealing every step.

    ``trace_id``/``parent_span_id`` are set when this runner is itself a
    sub-agent spawned by another AgentRunner; left as None for a root run,
    in which case a fresh trace and a parentless root span are created.
    """

    def __init__(
        self,
        agent: AgentDef,
        *,
        trace_id: str | None = None,
        parent_span_id: str | None = None,
        run_id: str | None = None,
        case: Case | None = None,
    ) -> None:
        self.agent = agent.for_case(case) if case is not None else agent
        self.case_id = case.id if case is not None else "default"
        self._replay = False
        self.trace_id = trace_id or new_trace_id()
        self.span_id = new_span_id()
        self.parent_span_id = parent_span_id
        self._run_id = run_id

    async def run(
        self,
        *,
        inject_misfire: bool = False,
        force_live: bool = False,
        replay: bool = False,
    ) -> AsyncIterator[RunEvent]:
        """``replay`` skips any live model call and replays the cached
        transcript, for bulk history generation where a key in the
        environment must not turn a backfill into thousands of paid calls."""
        run_id = self._run_id or _new_run_id()
        session_id = run_id
        self._replay = replay
        recorder = get_recorder()
        _ensure_live_call_state_loaded()

        if recorder is not None:
            from byoai.recorder.extract import PartialEvent
            from byoai.recorder.schema import now_monotonic_ns, now_ts_device

            recorder.record(
                PartialEvent(
                    session_id=session_id,
                    kind=EventKind.SESSION_START.value,
                    ts_device=now_ts_device(),
                    ts_monotonic_ns=now_monotonic_ns(),
                    tool_use_id=None,
                    tool_name=None,
                    payload={"agent_id": self.agent.id, "scenario": self.case_id},
                    model=self.agent.model,
                    trace_id=self.trace_id,
                    span_id=self.span_id,
                    parent_span_id=self.parent_span_id,
                )
            )

        final_text = ""
        used_fallback = False
        mode = "live"

        if inject_misfire:
            # Demo-only failure injection: simulate a provider misfire (timeout,
            # bad response, whatever) instead of ever calling out live, so the
            # fallback/detection path can be exercised on demand.
            log.warning("agent_showcase: injected misfire for %s (forced fallback)", self.agent.id)
            yield RunEvent(
                kind="misfire",
                trace_id=self.trace_id,
                span_id=self.span_id,
                parent_span_id=self.parent_span_id,
                data={"reason": "injected_failure_for_demo", "agent_id": self.agent.id},
            )
            used_fallback = True
            mode = "misfire"
            async for event in self._run_fallback(session_id, recorder):
                if event.kind == EventKind.MESSAGE.value and event.text:
                    final_text = event.text
                yield event
        elif replay or (not force_live and self._live_call_on_cooldown()):
            if not replay:
                log.info("agent_showcase: %s within live-call TTL, replaying cached transcript", self.agent.id)
            used_fallback = True
            mode = "cached"
            async for event in self._run_fallback(session_id, recorder):
                if event.kind == EventKind.MESSAGE.value and event.text:
                    final_text = event.text
                yield event
        else:
            try:
                async for event in self._run_live(session_id, recorder):
                    if event.kind == EventKind.MESSAGE.value and event.text:
                        final_text = event.text
                    yield event
                _LAST_LIVE_CALL[self.agent.id] = time.time()
                _save_last_live_call(_LAST_LIVE_CALL)
            except ByoAIError as exc:
                log.warning("agent_showcase: model API error for %s, using fallback transcript", self.agent.id)
                used_fallback = True
                mode = "replay"
                # A ConfigurationError means nobody supplied credentials — a
                # configuration state, not a failure, and the one case where
                # replaying quietly is honest. Anything else is a live call
                # that was attempted and did not work (bad IAM policy, wrong
                # region, an agent alias that isn't published), and a demo
                # that swallowed that would look identical to a working one
                # while never touching AWS. Say which.
                reason = None if isinstance(exc, ConfigurationError) else str(exc)
                async for event in self._run_fallback(session_id, recorder, reason=reason):
                    if event.kind == EventKind.MESSAGE.value and event.text:
                        final_text = event.text
                    yield event
        yield RunEvent(
            kind="run_complete",
            trace_id=self.trace_id,
            span_id=self.span_id,
            parent_span_id=self.parent_span_id,
            text=final_text,
            data={
                "run_id": run_id,
                "used_fallback": used_fallback,
                "mode": mode,
                "provider": self.agent.provider,
            },
        )

    def _live_call_on_cooldown(self) -> bool:
        _ensure_live_call_state_loaded()
        last = _LAST_LIVE_CALL.get(self.agent.id)
        return last is not None and (time.time() - last) < LIVE_CALL_TTL_SECONDS

    async def _run_sub_agent(
        self, sub_agent: AgentDef, session_id: str, recorder: Any
    ) -> AsyncIterator[RunEvent | str]:
        """Runs a sub-agent to completion, re-yielding its events, then yields
        its final text as the last item (str) instead of a RunEvent."""
        sub_runner = AgentRunner(sub_agent, trace_id=self.trace_id, parent_span_id=self.span_id)
        final_text = ""
        async for event in sub_runner.run(replay=self._replay):
            if event.kind == "run_complete":
                final_text = event.text or ""
                continue
            yield event
        yield final_text

    async def _run_live(self, session_id: str, recorder: Any) -> AsyncIterator[RunEvent]:
        if self.agent.provider == BEDROCK_AGENT_PROVIDER:
            async for event in self._run_live_bedrock_agent(session_id, recorder):
                yield event
        elif self.agent.provider == "openai":
            async for event in self._run_live_openai(session_id, recorder):
                yield event
        else:
            async for event in self._run_live_anthropic(session_id, recorder):
                yield event

    async def _run_live_anthropic(self, session_id: str, recorder: Any) -> AsyncIterator[RunEvent]:
        provider = AnthropicProvider(model=self.agent.model)
        messages: list[Message] = [
            Message(role="system", content=self.agent.system_prompt),
            Message(role="user", content=self.agent.scenario_message),
        ]
        try:
            for _turn in range(MAX_TURNS):
                request_body = {
                    "model": self.agent.model,
                    "messages": [m.to_dict() for m in messages if m.role != "system"],
                    "system": self.agent.system_prompt,
                    "tools": self.agent.tools,
                }
                if recorder is not None:
                    recorder.record_request_body(
                        request_body, session_id=session_id, trace_id=self.trace_id, span_id=self.span_id
                    )

                response = await provider.complete(messages, tools=self.agent.tools)

                if recorder is not None and isinstance(response.raw, dict):
                    recorder.record_response_body(
                        response.raw, session_id=session_id, trace_id=self.trace_id, span_id=self.span_id
                    )

                raw = response.raw if isinstance(response.raw, dict) else {}
                blocks = raw.get("content", []) if isinstance(raw.get("content"), list) else []
                tool_calls = [b for b in blocks if isinstance(b, dict) and b.get("type") == "tool_use"]
                text_blocks = [b.get("text", "") for b in blocks if isinstance(b, dict) and b.get("type") == "text"]
                turn_text = "".join(text_blocks)
                if turn_text:
                    yield RunEvent(
                        kind=EventKind.MESSAGE.value,
                        trace_id=self.trace_id,
                        span_id=self.span_id,
                        parent_span_id=self.parent_span_id,
                        text=turn_text,
                    )

                assistant_content = blocks if blocks else turn_text
                messages.append(Message(role="assistant", content=assistant_content))

                if not tool_calls:
                    break

                tool_result_blocks: list[dict[str, Any]] = []
                for call in tool_calls:
                    name = call.get("name") or ""
                    args = call.get("input") or {}
                    yield RunEvent(
                        kind=EventKind.TOOL_USE.value,
                        trace_id=self.trace_id,
                        span_id=self.span_id,
                        parent_span_id=self.parent_span_id,
                        tool_name=name,
                        data=self._tool_use_data(name, args),
                    )
                    result, nested_events = await self._run_tool_call(name, args, session_id, recorder)
                    for nested_event in nested_events:
                        yield nested_event
                    yield RunEvent(
                        kind=EventKind.TOOL_RESULT.value,
                        trace_id=self.trace_id,
                        span_id=self.span_id,
                        parent_span_id=self.parent_span_id,
                        tool_name=name,
                        data={"result": result},
                    )
                    tool_result_blocks.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": call.get("id"),
                            "content": json.dumps(result),
                        }
                    )
                messages.append(Message(role="user", content=tool_result_blocks))
            else:
                log.warning("agent_showcase: %s hit MAX_TURNS without finishing", self.agent.id)
        finally:
            await provider.close()

    @staticmethod
    def _openai_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Anthropic tool schema (name/description/input_schema) -> OpenAI
        function-calling schema (type/function.{name,description,parameters})."""
        return [
            {
                "type": "function",
                "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
                },
            }
            for t in tools
        ]

    @staticmethod
    def _openai_message_to_blocks(message: dict[str, Any]) -> list[dict[str, Any]]:
        """Normalizes an OpenAI chat-completions assistant message into
        Anthropic-shaped content blocks, so the rest of the loop (and the
        recorder's extractor) can treat both providers identically."""
        blocks: list[dict[str, Any]] = []
        content = message.get("content")
        if isinstance(content, str) and content:
            blocks.append({"type": "text", "text": content})
        for call in message.get("tool_calls") or []:
            fn = call.get("function") or {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except (TypeError, ValueError):
                args = {}
            blocks.append(
                {"type": "tool_use", "id": call.get("id"), "name": fn.get("name"), "input": args}
            )
        return blocks

    async def _run_live_openai(self, session_id: str, recorder: Any) -> AsyncIterator[RunEvent]:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            # OpenAICompatProvider (unlike AnthropicProvider) doesn't fail fast on a
            # missing key — it just sends an unauthenticated request to the real API
            # and hangs/errors on the network call. Check here so a missing key falls
            # back to the cached transcript immediately instead of stalling the run.
            raise ConfigurationError(
                "OPENAI_API_KEY is not set; set it to run this agent live, or the demo "
                "falls back to its cached transcript"
            )
        provider = OpenAICompatProvider(model=self.agent.model, api_key=api_key)
        openai_tools = self._openai_tools(self.agent.tools)
        messages: list[Message] = [
            Message(role="system", content=self.agent.system_prompt),
            Message(role="user", content=self.agent.scenario_message),
        ]
        # Anthropic-shaped mirror of `messages`, recorded instead of the raw
        # OpenAI-wire messages above — keeps every recorded request/response
        # in the one shape the recorder's extractor understands, and avoids
        # recording the same tool result twice in two different shapes (once
        # here, once explicitly per tool call below).
        recorder_history: list[dict[str, Any]] = [
            {"role": "user", "content": self.agent.scenario_message}
        ]
        try:
            for _turn in range(MAX_TURNS):
                if recorder is not None:
                    recorder.record_request_body(
                        {
                            "model": self.agent.model,
                            "messages": recorder_history,
                            "system": self.agent.system_prompt,
                            "tools": self.agent.tools,
                        },
                        session_id=session_id, trace_id=self.trace_id, span_id=self.span_id,
                    )

                response = await provider.complete(messages, tools=openai_tools)
                raw = response.raw if isinstance(response.raw, dict) else {}
                choices = raw.get("choices") or [{}]
                choice_message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
                blocks = self._openai_message_to_blocks(choice_message)

                if recorder is not None:
                    recorder.record_response_body(
                        {
                            "id": raw.get("id"),
                            "type": "message",
                            "role": "assistant",
                            "model": raw.get("model", self.agent.model),
                            "content": blocks,
                            "stop_reason": choices[0].get("finish_reason") if isinstance(choices[0], dict) else None,
                        },
                        session_id=session_id, trace_id=self.trace_id, span_id=self.span_id,
                    )

                tool_calls = [b for b in blocks if b.get("type") == "tool_use"]
                text_blocks = [b.get("text", "") for b in blocks if b.get("type") == "text"]
                turn_text = "".join(text_blocks)
                if turn_text:
                    yield RunEvent(
                        kind=EventKind.MESSAGE.value,
                        trace_id=self.trace_id,
                        span_id=self.span_id,
                        parent_span_id=self.parent_span_id,
                        text=turn_text,
                    )

                if not tool_calls:
                    messages.append(Message(role="assistant", content=turn_text))
                    break

                messages.append(
                    Message(
                        role="assistant",
                        content=None,
                        tool_calls=[
                            {
                                "id": b["id"],
                                "type": "function",
                                "function": {"name": b["name"], "arguments": json.dumps(b["input"])},
                            }
                            for b in tool_calls
                        ],
                    )
                )
                recorder_history.append({"role": "assistant", "content": blocks})

                tool_result_blocks: list[dict[str, Any]] = []
                for call in tool_calls:
                    name = call.get("name") or ""
                    args = call.get("input") or {}
                    call_id = call.get("id")
                    yield RunEvent(
                        kind=EventKind.TOOL_USE.value,
                        trace_id=self.trace_id,
                        span_id=self.span_id,
                        parent_span_id=self.parent_span_id,
                        tool_name=name,
                        data=self._tool_use_data(name, args),
                    )
                    result, nested_events = await self._run_tool_call(name, args, session_id, recorder)
                    for nested_event in nested_events:
                        yield nested_event
                    yield RunEvent(
                        kind=EventKind.TOOL_RESULT.value,
                        trace_id=self.trace_id,
                        span_id=self.span_id,
                        parent_span_id=self.parent_span_id,
                        tool_name=name,
                        data={"result": result},
                    )
                    messages.append(Message(role="tool", content=json.dumps(result), tool_call_id=call_id))
                    tool_result_blocks.append(
                        {"type": "tool_result", "tool_use_id": call_id, "content": json.dumps(result)}
                    )
                recorder_history.append({"role": "user", "content": tool_result_blocks})
            else:
                log.warning("agent_showcase: %s hit MAX_TURNS without finishing", self.agent.id)
        finally:
            await provider.close()

    def _tool_use_data(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """Annotates the sealed tool_use event when a tool call falls outside
        the agent's declared tool schema — a mis-fire, prompt-injected action,
        or off-script tool the model was never granted. The event is still
        captured and sealed exactly like any other; this only adds metadata
        so post-hoc analysis (and the UI) can surface it as a policy
        violation without the recorder itself needing to know about scope."""
        data: dict[str, Any] = {"input": args}
        if self.agent.is_out_of_scope(name):
            data["policy_violation"] = True
            data["policy_violation_reason"] = (
                f"'{name}' is not in {self.agent.id}'s declared tool schema "
                f"({sorted(self.agent.declared_tool_names)})"
            )
        return data

    async def _dispatch_tool(self, name: str, args: dict[str, Any], session_id: str, recorder: Any) -> Any:
        """Note: this only returns the final result — callers wanting the
        sub-agent's own per-step events should special-case sub_agent_tools
        themselves, as the live and fallback loops below do."""
        handler = self.agent.dispatch.get(name)
        if handler is None:
            return {"error": f"unknown tool: {name}"}
        try:
            return handler(args)
        except Exception as exc:  # noqa: BLE001 - tool failure surfaces as a result, not a crash
            return {"error": str(exc)}

    async def _run_tool_call(
        self, name: str, args: dict[str, Any], session_id: str, recorder: Any
    ) -> tuple[Any, list[RunEvent]]:
        """Resolve one tool call to a result, plus any nested RunEvents to re-surface
        (populated when the tool routes to a sub-agent)."""
        sub_agent = self.agent.sub_agent_tools.get(name)
        if sub_agent is None:
            return await self._dispatch_tool(name, args, session_id, recorder), []

        nested_events: list[RunEvent] = []
        final_text = ""
        async for item in self._run_sub_agent(sub_agent, session_id, recorder):
            if isinstance(item, str):
                final_text = item
            else:
                nested_events.append(item)
        return {"sub_agent": sub_agent.id, "summary": final_text}, nested_events

    async def _run_fallback(
        self, session_id: str, recorder: Any, *, reason: str | None = None
    ) -> AsyncIterator[RunEvent]:
        """``reason`` is set when the fallback follows a live call that was
        attempted and failed, and left None when there was nothing to attempt."""
        fallback_path = FALLBACKS_DIR / self.agent.fallback_file
        transcript = json.loads(fallback_path.read_text())

        if self.agent.provider == BEDROCK_AGENT_PROVIDER:
            async for event in self._replay_bedrock_trace(
                transcript["chunks"], session_id, recorder, reason=reason
            ):
                yield event
            return

        if recorder is not None:
            from byoai.recorder.extract import PartialEvent
            from byoai.recorder.schema import now_monotonic_ns, now_ts_device

            recorder.record(
                PartialEvent(
                    session_id=session_id,
                    kind=EventKind.API_ERROR.value,
                    ts_device=now_ts_device(),
                    ts_monotonic_ns=now_monotonic_ns(),
                    tool_use_id=None,
                    tool_name=None,
                    # A deliberate replay is not an outage; the ledger should
                    # not claim one happened.
                    payload={
                        "reason": "replay requested, using cached transcript"
                        if self._replay
                        else "model API unavailable, using cached fallback transcript"
                    },
                    model=self.agent.model,
                    trace_id=self.trace_id,
                    span_id=self.span_id,
                    parent_span_id=self.parent_span_id,
                )
            )

        tool_use_id = 0
        for step in transcript["steps"]:
            text = step.get("assistant_text", "")
            if text:
                yield RunEvent(
                    kind=EventKind.MESSAGE.value,
                    trace_id=self.trace_id,
                    span_id=self.span_id,
                    parent_span_id=self.parent_span_id,
                    text=text,
                )
                if recorder is not None:
                    recorder.record_response_body(
                        {
                            "model": self.agent.model,
                            "content": [{"type": "text", "text": text}],
                        },
                        session_id=session_id,
                        trace_id=self.trace_id,
                        span_id=self.span_id,
                    )
                if FALLBACK_STEP_DELAY_SECONDS:
                    await asyncio.sleep(FALLBACK_STEP_DELAY_SECONDS)
            for call in step.get("tool_calls", []):
                tool_use_id += 1
                call_id = f"cached_{tool_use_id}"
                name = call["name"]
                args = call["input"]
                yield RunEvent(
                    kind=EventKind.TOOL_USE.value,
                    trace_id=self.trace_id,
                    span_id=self.span_id,
                    parent_span_id=self.parent_span_id,
                    tool_name=name,
                    data=self._tool_use_data(name, args),
                )
                if recorder is not None:
                    recorder.record_response_body(
                        {
                            "model": self.agent.model,
                            "content": [{"type": "tool_use", "id": call_id, "name": name, "input": args}],
                        },
                        session_id=session_id,
                        trace_id=self.trace_id,
                        span_id=self.span_id,
                    )
                if FALLBACK_STEP_DELAY_SECONDS:
                    await asyncio.sleep(FALLBACK_STEP_DELAY_SECONDS)

                sub_agent = self.agent.sub_agent_tools.get(name)
                if sub_agent is not None:
                    final_text = ""
                    async for item in self._run_sub_agent(sub_agent, session_id, recorder):
                        if isinstance(item, str):
                            final_text = item
                        else:
                            yield item
                    result: Any = {"sub_agent": sub_agent.id, "summary": final_text}
                else:
                    result = await self._dispatch_tool(name, args, session_id, recorder)

                yield RunEvent(
                    kind=EventKind.TOOL_RESULT.value,
                    trace_id=self.trace_id,
                    span_id=self.span_id,
                    parent_span_id=self.parent_span_id,
                    tool_name=name,
                    data={"result": result},
                )
                if recorder is not None:
                    recorder.record_request_body(
                        {
                            "model": self.agent.model,
                            "messages": [
                                {
                                    "role": "user",
                                    "content": [
                                        {
                                            "type": "tool_result",
                                            "tool_use_id": call_id,
                                            "content": json.dumps(result),
                                        }
                                    ],
                                }
                            ],
                        },
                        session_id=session_id,
                        trace_id=self.trace_id,
                        span_id=self.span_id,
                    )
                if FALLBACK_STEP_DELAY_SECONDS:
                    await asyncio.sleep(FALLBACK_STEP_DELAY_SECONDS)

    # ------------------------------------------------- AWS Bedrock Agent (B6)

    async def _run_live_bedrock_agent(
        self, session_id: str, recorder: Any
    ) -> AsyncIterator[RunEvent]:
        """Invoke a real Bedrock agent and seal what its trace reports.

        Raises ``ConfigurationError``/``ProviderError`` — both ``ByoAIError``,
        which ``run()`` already treats as "fall back to the recorded trace".
        That is why an unconfigured demo box shows a working B6 rather than a
        broken one.

        The stream is drained before any event is surfaced. The other agents
        stream because this process is running their loop and knows each step
        as it happens; here AWS owns the loop, and a step is only evidence
        once its observation has arrived to pair with it.
        """
        agent_id = os.environ.get("BYOAI_BEDROCK_AGENT_ID", "").strip()
        alias_id = os.environ.get("BYOAI_BEDROCK_AGENT_ALIAS_ID", "").strip()
        if not agent_id or not alias_id:
            raise ConfigurationError(
                "BYOAI_BEDROCK_AGENT_ID and BYOAI_BEDROCK_AGENT_ALIAS_ID are unset"
            )

        from byoai.recorder.bedrock_agent_source import (
            BedrockAgentSourceError,
            stream_invocation,
        )

        region = os.environ.get("BYOAI_BEDROCK_REGION") or None

        def _invoke() -> list[dict[str, Any]]:
            return list(
                stream_invocation(
                    agent_id=agent_id,
                    agent_alias_id=alias_id,
                    prompt=self.agent.scenario_message,
                    session_id=session_id,
                    region_name=region,
                )
            )

        try:
            # boto3 is synchronous and this runs inside the event loop serving
            # the SSE stream, so the invocation goes to a worker thread rather
            # than stalling every other run in flight.
            chunks = await asyncio.to_thread(_invoke)
        except BedrockAgentSourceError as exc:
            raise ProviderError(str(exc), provider=BEDROCK_AGENT_PROVIDER) from exc

        async for event in self._emit_bedrock_run(chunks, session_id, recorder):
            yield event

    async def _replay_bedrock_trace(
        self,
        chunks: list[dict[str, Any]],
        session_id: str,
        recorder: Any,
        *,
        reason: str | None = None,
    ) -> AsyncIterator[RunEvent]:
        """Replay a recorded ``InvokeAgent`` stream through the live normalizer.

        With no ``reason`` this seals no ``api_error``, unlike the other
        agents' fallbacks: theirs stand in for a model call that failed, while
        this one stands in for an AWS account the demo box does not have —
        a configuration state, not a failure to record as one.

        With a ``reason`` it does, and says it out loud. Someone who has set
        ``BYOAI_BEDROCK_AGENT_ID`` and hit an IAM policy that omits
        ``bedrock:InvokeAgent`` would otherwise watch a run that looks exactly
        like a working one and never learn it never reached AWS.
        """
        if reason is not None:
            yield RunEvent(
                kind=EventKind.API_ERROR.value,
                trace_id=self.trace_id,
                span_id=self.span_id,
                parent_span_id=self.parent_span_id,
                data={"reason": f"Bedrock InvokeAgent failed: {reason}"},
            )
            if recorder is not None:
                from byoai.recorder.extract import PartialEvent
                from byoai.recorder.schema import now_monotonic_ns, now_ts_device

                recorder.record(
                    PartialEvent(
                        session_id=session_id,
                        kind=EventKind.API_ERROR.value,
                        ts_device=now_ts_device(),
                        ts_monotonic_ns=now_monotonic_ns(),
                        tool_use_id=None,
                        tool_name=None,
                        payload={"reason": reason, "source": "bedrock_invoke_agent"},
                        model=self.agent.model,
                        provider=BEDROCK_AGENT_PROVIDER,
                        trace_id=self.trace_id,
                        span_id=self.span_id,
                        parent_span_id=self.parent_span_id,
                    )
                )

        async for event in self._emit_bedrock_run(chunks, session_id, recorder):
            yield event

    async def _emit_bedrock_run(
        self, chunks: list[dict[str, Any]], session_id: str, recorder: Any
    ) -> AsyncIterator[RunEvent]:
        """Seal a normalized Bedrock run, then mirror it to the UI.

        ``record_session_start=False`` because ``run()`` already sealed one for
        this session; two would put a second start in the middle of a chain
        that is supposed to read as one run.
        """
        run = normalize_run(
            chunks,
            session_id=session_id,
            trace_id=self.trace_id,
            span_id=self.span_id,
        )
        if recorder is not None:
            seal_run(recorder, run, record_session_start=False)

        last_text = ""
        for capture in run.captures:
            for event in self._bedrock_capture_events(capture):
                if event.kind == EventKind.MESSAGE.value and event.text:
                    last_text = event.text
                yield event
                if FALLBACK_STEP_DELAY_SECONDS:
                    await asyncio.sleep(FALLBACK_STEP_DELAY_SECONDS)

        # Only when the decision text came from the streamed completion rather
        # than from a finalResponse step — otherwise it has already been
        # yielded and sealed, and repeating it would show the UI a step the
        # ledger does not have.
        if run.final_text and run.final_text != last_text:
            yield RunEvent(
                kind=EventKind.MESSAGE.value,
                trace_id=self.trace_id,
                span_id=self.span_id,
                parent_span_id=self.parent_span_id,
                text=run.final_text,
            )

    def _bedrock_capture_events(self, capture: Any) -> list[RunEvent]:
        """One normalized capture -> the RunEvents the UI shows.

        Deliberately reads the same bodies the recorder sealed rather than the
        raw AWS trace: if these two disagreed, the timeline a demo viewer is
        looking at would not be the timeline that was sealed.
        """
        events: list[RunEvent] = []
        common = {
            "trace_id": self.trace_id,
            "span_id": capture.span_id,
            "parent_span_id": capture.parent_span_id,
        }

        if capture.direction == "direct" and capture.event is not None:
            return [RunEvent(kind=capture.event.kind, data=capture.event.payload, **common)]

        body = capture.body or {}
        if capture.direction == "response":
            for block in body.get("content") or []:
                if block.get("type") == "text":
                    events.append(RunEvent(kind=EventKind.MESSAGE.value, text=block["text"], **common))
                elif block.get("type") == "tool_use":
                    name = block.get("name") or ""
                    events.append(
                        RunEvent(
                            kind=EventKind.TOOL_USE.value,
                            tool_name=name,
                            data=self._tool_use_data(name, block.get("input") or {}),
                            **common,
                        )
                    )
            return events

        for message in body.get("messages") or []:
            for block in message.get("content") or []:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    events.append(
                        RunEvent(
                            kind=EventKind.TOOL_RESULT.value,
                            # Named from the capture, not the body: a
                            # tool_result carries only the id it answers, and
                            # the demo's workflow graph resolves its nodes by
                            # (span, tool name) — an unnamed result leaves
                            # every B6 node spinning as though still running.
                            tool_name=capture.tool_name,
                            data={"result": block.get("content")},
                            **common,
                        )
                    )
        return events
