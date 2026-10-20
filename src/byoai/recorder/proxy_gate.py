"""Seam B: enforce the mandate at the proxy, on the model's own response.

``@governed_tool`` (Seam A) needs the integrator to decorate their tool
functions, and that is a source change to code the buyer frequently does not
own. This module needs nothing from the agent at all: the proxy is already
sitting at ``ANTHROPIC_BASE_URL`` and already parses ``tool_use`` blocks out of
responses, and a component that can read a tool call before the agent sees it
can also refuse it.

The rule is decided by the same :class:`~byoai.recorder.mandate.MandateGate`
Seam A uses, routed through the same :class:`~byoai.recorder.denial_latch.DenialLatch`
and written down by the same :class:`~byoai.recorder.verdicts.VerdictRecorder`.
There is deliberately no second policy path here — two implementations of one
enforcement rule drift, and then one of them is wrong.

What a denial looks like
------------------------
The ``tool_use`` block is **withheld**: it never reaches the agent, so there is
nothing for the agent's dispatcher to execute. In its place goes a synthesized
block carrying the single fixed sentence
(:data:`~byoai.recorder.mandate.MODEL_MESSAGE`) — never the tool name, never
the mandate, never a suggested alternative. At this seam that text lands
directly in the model's next context window, so a denial that explained itself
would be a hint sheet for routing around the control.

Coverage, stated plainly
------------------------
This covers tools the *model requests through the intercepted provider API*. A
tool the agent's own code calls directly — a helper it invokes without asking
the model, an MCP client it drives itself — never appears in a response body
and is invisible here. That is what Seam A is for. The two seams compose;
neither alone is total.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from dataclasses import dataclass
from typing import Any

from .denial_latch import LatchedDenial, denial_latch
from .mandate import (
    MODEL_MESSAGE,
    Allow,
    Deny,
    Flag,
    MandateGate,
    Posture,
    ProposedAction,
    Reason,
    RequireApproval,
    Verdict,
)
from .verdicts import verdict_recorder

__all__ = [
    "AGENT_ID_HEADER",
    "DenialBlockStyle",
    "ProxyDecision",
    "ProxyEnforcer",
    "SseEnforcer",
    "clear_proxy_gates",
    "denial_block",
    "enforce_response_body",
    "proxy_enforcement_enabled",
    "register_proxy_gate",
    "resolve_enforcer",
]

log = logging.getLogger(__name__)

#: The header a caller may send to say which registered agent it is. Read
#: below for why this is a *selector* and not a credential.
AGENT_ID_HEADER = "x-byoai-agent-id"

_ENV_ENABLED = "BYOAI_PROXY_ENFORCEMENT"
_ENV_DENIAL_BLOCK = "BYOAI_PROXY_DENIAL_BLOCK"


class DenialBlockStyle:
    """What shape the synthesized replacement block takes.

    ``tool_result`` is the default and the intent: the agent's loop sees the
    denial where it expects a tool outcome and treats it as an ordinary tool
    failure. ``text`` exists because a ``tool_result`` block inside an
    *assistant* message is not something every provider SDK will parse — a
    strict client can raise on the unexpected block type, which stops the tool
    just as effectively but as a crash rather than as a refusal. Operators
    running such a client set ``BYOAI_PROXY_DENIAL_BLOCK=text`` and get a plain
    text block carrying the same fixed sentence.
    """

    TOOL_RESULT = "tool_result"
    TEXT = "text"


def _denial_style() -> str:
    value = (os.getenv(_ENV_DENIAL_BLOCK) or "").strip().lower()
    if value in {DenialBlockStyle.TOOL_RESULT, DenialBlockStyle.TEXT}:
        return value
    return DenialBlockStyle.TOOL_RESULT


def proxy_enforcement_enabled() -> bool:
    """Whether Seam B is switched on for this process. Off unless asked for."""
    return (os.getenv(_ENV_ENABLED) or "0").strip() == "1"


def denial_block(tool_use_id: str | None, *, style: str | None = None) -> dict[str, Any]:
    """The block that replaces a withheld ``tool_use``.

    Carries :data:`~byoai.recorder.mandate.MODEL_MESSAGE` and nothing else. No
    tool name, no reason, no mandate version — everything an operator needs is
    on the recorded verdict instead.
    """
    if (style or _denial_style()) == DenialBlockStyle.TEXT:
        return {"type": "text", "text": MODEL_MESSAGE}
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id or "",
        "is_error": True,
        "content": [{"type": "text", "text": MODEL_MESSAGE}],
    }


# -- which agent is this request? --------------------------------------------
#
# Getting this wrong has two failure modes and both are bad: enforce one
# agent's mandate on another, or believe you are enforcing and enforce nothing.
#
# So the registry is operator-owned. Gates are registered at process startup
# from configuration the *operator* controls; a request cannot introduce an
# agent identity that was not already configured. That is the whole point: the
# agent is the untrusted party at this seam — it is the thing being governed —
# and a client-supplied agent id that could name any mandate would let it pick
# its own scope by editing one header.
#
# The header is therefore a *selector among already-registered gates*, useful
# when one proxy fronts several agents. It cannot widen anything. A header
# naming an unregistered agent, or an ambiguous request when several gates are
# registered and none was named, is unresolved — and unresolved is decided by
# posture (fail_closed denies, fail_open allows and flags), never by silently
# allowing.

_gates: dict[str, MandateGate] = {}
_gates_lock = threading.Lock()


def register_proxy_gate(gate: MandateGate, *, agent_id: str | None = None) -> None:
    """Register ``gate`` as the mandate for one agent this proxy fronts.

    Call at startup. ``agent_id`` defaults to the gate's own, which is the
    normal case; pass it only when the gate does not know its id.
    """
    resolved = agent_id or gate.agent_id
    if not resolved:
        msg = "register_proxy_gate needs an agent id: the gate does not carry one"
        raise ValueError(msg)
    with _gates_lock:
        _gates[str(resolved)] = gate


def clear_proxy_gates() -> None:
    """Forget every registered gate. Startup reconfiguration and tests."""
    with _gates_lock:
        _gates.clear()


def _lookup(agent_id: str | None) -> tuple[MandateGate | None, str]:
    """Return ``(gate, detail)``. A ``None`` gate means unresolved."""
    with _gates_lock:
        if agent_id:
            gate = _gates.get(agent_id)
            if gate is not None:
                return gate, ""
            return None, (
                f"request named agent_id={agent_id!r}, which is not registered on "
                "this proxy"
            )
        if len(_gates) == 1:
            return next(iter(_gates.values())), ""
        if not _gates:
            return None, "no mandate gate is registered on this proxy"
        return None, (
            f"{len(_gates)} gates are registered and the request named none, so "
            "which mandate applies is ambiguous"
        )


def resolve_enforcer(
    headers: Any,
    *,
    run_id: str,
    posture: str | None = None,
) -> ProxyEnforcer:
    """Build the enforcer for one request.

    ``headers`` is anything with a case-insensitive ``get`` (Starlette's
    ``request.headers`` and a plain lowercase dict both work). ``run_id`` is
    the latch bucket — see :class:`ProxyEnforcer`.
    """
    agent_id = None
    try:
        agent_id = headers.get(AGENT_ID_HEADER)
    except AttributeError:  # pragma: no cover - defensive
        agent_id = None
    gate, detail = _lookup((agent_id or "").strip() or None)
    return ProxyEnforcer(gate, run_id=run_id, unresolved_detail=detail, posture=posture)


# -- the decision ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ProxyDecision:
    """What the proxy does with one ``tool_use`` block."""

    verdict: Verdict
    #: True when the block may reach the agent untouched.
    allowed: bool
    #: True once the latch says this run is over.
    halted: bool = False

    @property
    def denied(self) -> bool:
        return not self.allowed


class ProxyEnforcer:
    """Decides ``tool_use`` blocks for one request, against one agent's gate.

    The latch bucket is the *session*, not the request. An agent that is
    refused a tool and asks for it again next turn arrives as a separate HTTP
    request, and if each request were its own run the third attempt would look
    like the first forever. Keying on the session id — the same value the
    recorder scopes its capture by — means a repeat at the proxy counts toward
    exactly the same halt threshold as a repeat through the decorator, and a
    model cannot get a fresh budget by changing seam.
    """

    def __init__(
        self,
        gate: MandateGate | None,
        *,
        run_id: str,
        unresolved_detail: str = "",
        posture: str | None = None,
    ) -> None:
        self._gate = gate
        self._run_id = run_id
        self._unresolved_detail = unresolved_detail or "no mandate gate for this request"
        self._posture = posture
        self._decisions: list[ProxyDecision] = []

    @property
    def gate(self) -> MandateGate | None:
        return self._gate

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def decisions(self) -> list[ProxyDecision]:
        """Every decision this request made, in order. For logs and tests."""
        return list(self._decisions)

    @property
    def posture(self) -> str:
        if self._posture:
            return self._posture
        if self._gate is not None:
            return self._gate.posture
        env = (os.getenv("BYOAI_MANDATE_POSTURE") or "").strip().lower()
        if env in {Posture.FAIL_OPEN, Posture.FAIL_CLOSED}:
            return env
        return Posture.FAIL_OPEN

    def decide(
        self,
        tool: str,
        *,
        arguments: dict[str, Any] | None = None,
        step_index: int | None = None,
        arguments_sha256: str | None = None,
    ) -> ProxyDecision:
        """Allow, flag or deny one ``tool_use`` block. Never raises.

        ``arguments_sha256``, when given, is written on the verdict's ledger
        record (``coriqo-mcp`` passes one; the provider proxy does not).
        """
        try:
            decision = self._decide(
                tool,
                arguments=arguments,
                step_index=step_index,
                arguments_sha256=arguments_sha256,
            )
        except Exception:  # noqa: BLE001 - enforcement must not break the proxy
            log.exception("coriqo: proxy enforcement failed deciding %r", tool)
            decision = self._unresolved(tool, step_index, "enforcement raised")
        self._decisions.append(decision)
        return decision

    # -- internals ---------------------------------------------------------

    def _decide(
        self,
        tool: str,
        *,
        arguments: dict[str, Any] | None,
        step_index: int | None,
        arguments_sha256: str | None = None,
    ) -> ProxyDecision:
        if self._gate is None:
            return self._unresolved(tool, step_index, self._unresolved_detail)

        action = ProposedAction(
            tool=tool,
            trajectory_id=self._run_id,
            step_index=step_index,
            arguments=arguments,
        )
        latch = denial_latch()
        principal = str(self._gate.agent_id or "unidentified-agent")
        version = self._gate.latch_version

        digest = arguments_sha256
        latched = latch.check(self._run_id, principal, tool, version)
        if latched is not None:
            self._record(latched.verdict, action, principal, latched=latched, digest=digest)
            return ProxyDecision(latched.verdict, allowed=False, halted=latched.halted)

        verdict = self._gate.decide(action)
        if isinstance(verdict, RequireApproval):
            # Waiting on a human: withheld, not latched (a later snapshot can
            # carry the approval), and reported so it reaches the queue. Before
            # this branch a RequireApproval fell into the allow path below,
            # because it is neither an Allow nor a Deny.
            self._gate.report_approval_request(verdict)
            self._record(verdict, action, principal, digest=digest)
            return ProxyDecision(verdict, allowed=False)
        if isinstance(verdict, Allow) or not isinstance(verdict, Deny):
            self._record(verdict, action, principal, digest=digest)
            return ProxyDecision(verdict, allowed=True)

        recorded = latch.record(self._run_id, principal, verdict, version)
        self._record(verdict, action, principal, latched=recorded, digest=digest)
        log.warning(
            "coriqo: withheld a tool_use block at the proxy - %s run=%s attempts=%d%s",
            _operator_detail(verdict),
            self._run_id,
            recorded.attempts,
            " HALTED" if recorded.halted else "",
        )
        return ProxyDecision(verdict, allowed=False, halted=recorded.halted)

    def _unresolved(self, tool: str, step_index: int | None, detail: str) -> ProxyDecision:
        """No gate, or no way to know which one: decide by posture, loudly.

        Never latched. This is a configuration fact, not a scope decision, and
        remembering it would halt a run over a startup ordering problem.
        """
        posture = self.posture
        fields: dict[str, Any] = {
            "reason": Reason.AGENT_UNRESOLVED,
            "tool": tool,
            "posture": posture,
            "trajectory_id": self._run_id,
            "step_index": step_index,
            "detail": detail,
        }
        if posture == Posture.FAIL_CLOSED:
            verdict: Verdict = Deny(**fields)
            allowed = False
        else:
            verdict = Flag(**fields)
            allowed = True
        log.warning(
            "coriqo: proxy could not resolve an agent for this request (%s); "
            "posture=%s so the tool_use for %r was %s",
            detail,
            posture,
            tool,
            "withheld" if not allowed else "allowed and flagged",
        )
        self._record_unresolved(verdict)
        return ProxyDecision(verdict, allowed=allowed)

    def _record(
        self,
        verdict: Verdict,
        action: ProposedAction,
        principal: str,
        *,
        latched: LatchedDenial | None = None,
        digest: str | None = None,
    ) -> None:
        recorder = verdict_recorder()
        if recorder is None or self._gate is None:
            return
        recorder.record(
            verdict,
            agent_id=self._gate.agent_id,
            latched=latched,
            run_id=self._run_id,
            principal=principal,
            argument_count=None if action.arguments is None else len(action.arguments),
            arguments_sha256=digest,
        )

    def _record_unresolved(self, verdict: Verdict) -> None:
        recorder = verdict_recorder()
        if recorder is None:
            return
        recorder.record(verdict, agent_id=None, run_id=self._run_id, principal=None)


def _operator_detail(verdict: Verdict) -> str:
    parts = [f"reason={verdict.reason}", f"tool={verdict.tool!r}", f"posture={verdict.posture}"]
    if verdict.detail:
        parts.append(f"detail={verdict.detail}")
    return " ".join(parts)


# -- non-streaming responses -------------------------------------------------


def enforce_response_body(
    body: dict[str, Any], enforcer: ProxyEnforcer
) -> tuple[dict[str, Any], bool]:
    """Gate every ``tool_use`` block in a complete ``/v1/messages`` response.

    Returns ``(body, changed)``. ``changed`` is False for the overwhelmingly
    common case — no tool call, or every tool call allowed — and the caller
    should then forward the original bytes rather than re-serialize ours.
    """
    content = body.get("content")
    if not isinstance(content, list):
        return body, False

    out: list[Any] = []
    denied = 0
    survivors = 0
    for step, block in enumerate(content):
        if not isinstance(block, dict) or block.get("type") != "tool_use":
            out.append(block)
            continue
        arguments = block.get("input") if isinstance(block.get("input"), dict) else None
        decision = enforcer.decide(
            str(block.get("name") or ""), arguments=arguments, step_index=step
        )
        if decision.allowed:
            out.append(block)
            survivors += 1
        else:
            denied += 1
            out.append(denial_block(block.get("id")))

    if not denied:
        return body, False
    body = dict(body)
    body["content"] = out
    if survivors == 0 and body.get("stop_reason") == "tool_use":
        # Leaving stop_reason as tool_use on a message with no tool_use block
        # left is a shape no agent loop expects: the common `while
        # stop_reason == "tool_use"` spins with nothing to dispatch. end_turn
        # is the honest description of what the agent now holds.
        body["stop_reason"] = "end_turn"
    return body, True


# -- streaming ---------------------------------------------------------------

_FRAME_SEP = b"\n\n"


@dataclass(slots=True)
class _Held:
    """One ``tool_use`` content block, held while it is still incomplete."""

    index: int
    tool_use_id: str | None
    name: str | None
    frames: list[bytes]
    json_parts: list[str]


class SseEnforcer:
    """Gate ``tool_use`` blocks in an SSE stream, without buffering the response.

    Bytes go in, bytes come out, and the only thing ever held back is the
    frames of a ``tool_use`` block that has not finished yet (plus at most one
    partially-received SSE frame, which no client could have parsed anyway).
    Text frames — the tokens a human is watching appear — are never delayed.

    The hold is not a compromise on latency, it is what makes the decision
    possible at all: a ``tool_use`` block is not actionable until its arguments
    are complete, so the point the block finishes is both the earliest moment
    the gate *can* decide and the last moment before the agent could act. The
    decision itself reads memory and returns.
    """

    def __init__(self, enforcer: ProxyEnforcer, *, style: str | None = None) -> None:
        self._enforcer = enforcer
        self._style = style
        self._buf = bytearray()
        self._held: dict[int, _Held] = {}
        self._denied = 0
        self._survivors = 0
        self._step = 0
        self._closed = False

    @property
    def denied(self) -> int:
        return self._denied

    @property
    def halted(self) -> bool:
        return any(d.halted for d in self._enforcer.decisions)

    def feed(self, chunk: bytes) -> bytes:
        """Return the bytes to forward downstream for ``chunk``."""
        if self._closed or not chunk:
            return b""
        self._buf.extend(chunk)
        out = bytearray()
        while True:
            cut = self._buf.find(_FRAME_SEP)
            if cut == -1:
                break
            frame = bytes(self._buf[: cut + len(_FRAME_SEP)])
            del self._buf[: cut + len(_FRAME_SEP)]
            out.extend(self._frame(frame))
        return bytes(out)

    def close(self) -> bytes:
        """Flush anything still held. Idempotent.

        A stream that ends mid-``tool_use`` never produced a complete tool call,
        so the held frames are dropped rather than released: forwarding a
        half-announced tool call the gate never got to see would be the one
        outcome this seam exists to prevent.
        """
        if self._closed:
            return b""
        self._closed = True
        for held in self._held.values():
            log.warning(
                "coriqo: stream ended mid-tool_use (index=%d tool=%r); the "
                "incomplete block was dropped rather than forwarded ungated",
                held.index,
                held.name,
            )
        self._held.clear()
        tail = bytes(self._buf)
        self._buf.clear()
        return tail

    # -- internals ---------------------------------------------------------

    def _frame(self, frame: bytes) -> bytes:
        data = _frame_data(frame)
        if data is None:
            # Not a data frame we understand (a comment, a keep-alive, an
            # unparsable line). Held blocks aside, it goes straight out.
            return self._passthrough(frame, None)

        etype = data.get("type")
        index = data.get("index")

        if etype == "content_block_start" and _is_tool_use(data):
            block = data.get("content_block") or {}
            idx = int(index) if isinstance(index, int) else -1
            self._held[idx] = _Held(
                index=idx,
                tool_use_id=block.get("id"),
                name=block.get("name"),
                frames=[frame],
                json_parts=[],
            )
            return b""

        if isinstance(index, int) and index in self._held:
            held = self._held[index]
            if etype == "content_block_delta":
                delta = data.get("delta") or {}
                if delta.get("type") == "input_json_delta":
                    held.json_parts.append(str(delta.get("partial_json") or ""))
                held.frames.append(frame)
                return b""
            if etype == "content_block_stop":
                return self._resolve(held, frame)
            held.frames.append(frame)
            return b""

        if etype == "message_delta" and self._denied and self._survivors == 0:
            rewritten = _rewrite_stop_reason(frame, data)
            if rewritten is not None:
                return rewritten

        return self._passthrough(frame, etype)

    def _passthrough(self, frame: bytes, _etype: str | None) -> bytes:
        return frame

    def _resolve(self, held: _Held, stop_frame: bytes) -> bytes:
        del self._held[held.index]
        arguments = _parse_input("".join(held.json_parts))
        step = self._step
        self._step += 1
        decision = self._enforcer.decide(
            held.name or "", arguments=arguments, step_index=step
        )
        if decision.allowed:
            self._survivors += 1
            return b"".join([*held.frames, stop_frame])
        self._denied += 1
        return _denial_frames(held.index, held.tool_use_id, style=self._style)


def _frame_data(frame: bytes) -> dict[str, Any] | None:
    """The JSON of an SSE frame's ``data:`` line, or None."""
    for raw in frame.split(b"\n"):
        line = raw[:-1] if raw.endswith(b"\r") else raw
        if not line.startswith(b"data:"):
            continue
        try:
            parsed = json.loads(line[len(b"data:") :].strip())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


def _is_tool_use(data: dict[str, Any]) -> bool:
    block = data.get("content_block")
    return isinstance(block, dict) and block.get("type") == "tool_use"


def _parse_input(raw: str) -> dict[str, Any] | None:
    if not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _sse(event: str, data: dict[str, Any]) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n".encode()


def _denial_frames(index: int, tool_use_id: str | None, *, style: str | None) -> bytes:
    """The block that goes out in place of a withheld ``tool_use``.

    Emitted at the same content-block index so the message the client
    assembles has no hole in it.
    """
    block = denial_block(tool_use_id, style=style)
    return _sse(
        "content_block_start",
        {"type": "content_block_start", "index": index, "content_block": block},
    ) + _sse("content_block_stop", {"type": "content_block_stop", "index": index})


def _rewrite_stop_reason(frame: bytes, data: dict[str, Any]) -> bytes | None:
    """Turn ``stop_reason: tool_use`` into ``end_turn`` when nothing survived."""
    delta = data.get("delta")
    if not isinstance(delta, dict) or delta.get("stop_reason") != "tool_use":
        return None
    patched = dict(data)
    patched["delta"] = {**delta, "stop_reason": "end_turn"}
    event = _frame_event_name(frame) or "message_delta"
    return _sse(event, patched)


def _frame_event_name(frame: bytes) -> str | None:
    for raw in frame.split(b"\n"):
        line = raw[:-1] if raw.endswith(b"\r") else raw
        if line.startswith(b"event:"):
            return line[len(b"event:") :].strip().decode("utf-8", errors="replace")
    return None


# -- startup wiring ----------------------------------------------------------

_ENV_AGENT_IDS = "BYOAI_MANDATE_AGENT_ID"


async def start_proxy_enforcement() -> list[MandateGate]:
    """Build, register and start a gate per configured agent id.

    Returns the gates it started so the caller can stop them on shutdown. An
    empty list means enforcement is off, or is on with nothing configured —
    and the second case is loud, because "enforcing" with no gate registered
    is the failure that looks like success.
    """
    if not proxy_enforcement_enabled():
        return []
    from .mandate import mandate_gate

    raw = (os.getenv(_ENV_AGENT_IDS) or "").strip()
    ids = [part.strip() for part in raw.split(",") if part.strip()]
    if not ids:
        log.warning(
            "coriqo: %s=1 but %s names no agent, so no mandate gate is "
            "registered and every tool_use will be treated as unresolved",
            _ENV_ENABLED,
            _ENV_AGENT_IDS,
        )
        return []
    started: list[MandateGate] = []
    for agent_id in ids:
        # Deliberately not caught. `mandate_gate` raises only for an identity
        # that cannot enforce — a static API key, which is a misconfiguration
        # rather than an absence — and the error names the enrolment command.
        # A proxy that boots claiming to enforce while enforcing nothing is
        # the failure mode worth refusing to start over.
        gate = mandate_gate(agent_id)
        register_proxy_gate(gate)
        await gate.start()
        started.append(gate)
        log.info("coriqo: proxy enforcement active for agent %s", agent_id)
    return started


async def stop_proxy_enforcement(gates: list[MandateGate]) -> None:
    for gate in gates:
        try:
            await gate.stop()
        except Exception:  # noqa: BLE001
            log.exception("coriqo: failed to stop a mandate gate")
    clear_proxy_gates()
