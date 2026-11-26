"""Seam B: what the proxy does to a ``tool_use`` block before the agent sees it.

The gate itself is covered in ``test_mandate.py`` and the latch in
``test_denial_latch.py``; what matters here is the seam. No network — gates are
seeded with ``apply_snapshot``, and the SSE bytes are hand-built so a test can
choose exactly where a chunk boundary falls.
"""

from __future__ import annotations

import json

import pytest

from byoai.recorder.denial_latch import DenialLatch, use_denial_latch
from byoai.recorder.mandate import (
    MODEL_MESSAGE,
    Deny,
    MandateGate,
    Posture,
    Reason,
)
from byoai.recorder.proxy_gate import (
    AGENT_ID_HEADER,
    DenialBlockStyle,
    ProxyEnforcer,
    SseEnforcer,
    clear_proxy_gates,
    enforce_response_body,
    register_proxy_gate,
    resolve_enforcer,
)
from byoai.recorder.verdicts import VerdictRecorder, use_verdict_recorder

_AGENT = "coriqo-agent-1"
_RUN = "sess_proxy_1"


def snapshot_payload(**overrides) -> dict:
    payload = {
        "mandate_version_id": "mv_1",
        "allowed_tools": ["search"],
        "status": "approved",
        "mandate_enforcement": "enforce",
        "enforcement_posture": Posture.FAIL_OPEN,
        "max_staleness_s": 60,
    }
    payload.update(overrides)
    return payload


def gate_with(*, agent_id: str = _AGENT, **overrides) -> MandateGate:
    async def never_called(_etag):  # pragma: no cover - decide does no I/O
        raise AssertionError("the decide path must not refresh")

    gate = MandateGate(never_called, agent_id=agent_id)
    gate.apply_snapshot(snapshot_payload(**overrides))
    return gate


def enforcer(gate: MandateGate | None = None, *, run_id: str = _RUN, **kwargs) -> ProxyEnforcer:
    return ProxyEnforcer(gate if gate is not None else gate_with(), run_id=run_id, **kwargs)


@pytest.fixture(autouse=True)
def _clean_registry():
    clear_proxy_gates()
    yield
    clear_proxy_gates()


@pytest.fixture(autouse=True)
def _isolated_latch():
    """Each test gets its own latch; the process-wide one is shared by design."""
    with use_denial_latch(DenialLatch()):
        yield


class RecordingRecorder(VerdictRecorder):
    """A VerdictRecorder with no ledger and no outbox that keeps what it saw."""

    def __init__(self) -> None:
        super().__init__(ledger=None, outbox=None, device_id="dev_test")
        self.seen: list[tuple[str, str | None]] = []

    def record(self, verdict, **kwargs):  # type: ignore[override]
        self.seen.append((verdict.verdict, verdict.tool))
        return super().record(verdict, **kwargs)


# -- response bodies ---------------------------------------------------------


def tool_use_body(name: str = "search", *, block_id: str = "toolu_1") -> dict:
    return {
        "id": "msg_1",
        "type": "message",
        "role": "assistant",
        "stop_reason": "tool_use",
        "content": [
            {"type": "text", "text": "Looking that up."},
            {"type": "tool_use", "id": block_id, "name": name, "input": {"q": "rates"}},
        ],
    }


def test_allowed_tool_use_passes_through_untouched():
    body = tool_use_body("search")
    original = json.loads(json.dumps(body))

    gated, changed = enforce_response_body(body, enforcer())

    assert changed is False
    assert gated == original


def test_non_tool_response_is_untouched():
    body = {
        "type": "message",
        "stop_reason": "end_turn",
        "content": [{"type": "text", "text": "hi"}],
    }
    original = json.loads(json.dumps(body))

    gated, changed = enforce_response_body(body, enforcer())

    assert changed is False
    assert gated == original


def test_denied_tool_use_is_withheld_and_replaced():
    body = tool_use_body("wire_transfer")

    gated, changed = enforce_response_body(body, enforcer())

    assert changed is True
    kinds = [block["type"] for block in gated["content"]]
    assert "tool_use" not in kinds
    assert kinds == ["text", "tool_result"]
    # The agent never learns the tool was even requested.
    assert "wire_transfer" not in json.dumps(gated)


def test_synthesized_result_carries_only_the_fixed_message():
    body = tool_use_body("wire_transfer")

    gated, _ = enforce_response_body(body, enforcer())
    replacement = gated["content"][-1]

    assert replacement["is_error"] is True
    assert replacement["tool_use_id"] == "toolu_1"
    assert replacement["content"] == [{"type": "text", "text": MODEL_MESSAGE}]
    # Nothing operator-facing leaks: not the mandate, not the reason, not the
    # scope the call missed.
    text = json.dumps(replacement)
    for leak in ("mv_1", "out_of_scope", "wire_transfer", "search", "mandate"):
        assert leak not in text


def test_stop_reason_becomes_end_turn_when_nothing_survived():
    gated, _ = enforce_response_body(tool_use_body("wire_transfer"), enforcer())
    assert gated["stop_reason"] == "end_turn"


def test_stop_reason_is_left_alone_when_a_tool_use_survives():
    body = tool_use_body("wire_transfer")
    body["content"].append(
        {"type": "tool_use", "id": "toolu_2", "name": "search", "input": {}}
    )

    gated, _ = enforce_response_body(body, enforcer())

    assert gated["stop_reason"] == "tool_use"
    assert [b["type"] for b in gated["content"]] == ["text", "tool_result", "tool_use"]


def test_text_denial_style_for_clients_that_reject_tool_result_blocks(monkeypatch):
    monkeypatch.setenv("BYOAI_PROXY_DENIAL_BLOCK", DenialBlockStyle.TEXT)

    gated, _ = enforce_response_body(tool_use_body("wire_transfer"), enforcer())

    assert gated["content"][-1] == {"type": "text", "text": MODEL_MESSAGE}


# -- verdict recording -------------------------------------------------------


def test_allow_flag_and_deny_are_all_recorded():
    recorder = RecordingRecorder()
    with use_verdict_recorder(recorder):
        enforce_response_body(tool_use_body("search"), enforcer())
        enforce_response_body(
            tool_use_body("wire_transfer"),
            enforcer(gate_with(mandate_enforcement="observe"), run_id="sess_observe"),
        )
        enforce_response_body(
            tool_use_body("wire_transfer"), enforcer(run_id="sess_deny")
        )

    assert recorder.seen == [
        ("allowed", "search"),
        ("flagged", "wire_transfer"),
        ("blocked", "wire_transfer"),
    ]


# -- the latch ---------------------------------------------------------------


def test_repeats_at_the_proxy_count_toward_the_same_halt_threshold():
    enf = enforcer()

    first = enf.decide("wire_transfer")
    second = enf.decide("wire_transfer")
    third = enf.decide("wire_transfer")

    assert [d.denied for d in (first, second, third)] == [True, True, True]
    assert [d.verdict.reason for d in (first, second, third)] == [
        Reason.OUT_OF_SCOPE,
        Reason.REPEAT_DENIED,
        Reason.RUN_HALTED,
    ]
    assert [d.halted for d in (first, second, third)] == [False, False, True]

    # The run is over: even an in-scope tool is refused now.
    after = enf.decide("search")
    assert after.denied
    assert after.verdict.reason == Reason.RUN_HALTED


def test_a_decorator_denial_and_a_proxy_denial_share_one_budget():
    """Changing seam must not buy a fresh budget."""
    from byoai.errors import MandateDeniedError, MandateRunHaltedError
    from byoai.recorder.governed_tool import governed_tool, use_gate

    gate = gate_with()

    @governed_tool(name="wire_transfer")
    def wire_transfer() -> str:  # pragma: no cover - never runs
        raise AssertionError("a denied tool must not execute")

    with use_gate(gate):
        # Attempt one goes through the decorator, in the same run.
        from byoai.recorder.denial_latch import run_scope

        with run_scope(_RUN), pytest.raises(MandateDeniedError):
            wire_transfer()

        enf = ProxyEnforcer(gate, run_id=_RUN)
        assert enf.decide("wire_transfer").verdict.reason == Reason.REPEAT_DENIED
        third = enf.decide("wire_transfer")
        assert third.halted
        assert third.verdict.reason == Reason.RUN_HALTED

        with run_scope(_RUN), pytest.raises(MandateRunHaltedError):
            wire_transfer()


# -- agent identity ----------------------------------------------------------


def test_a_registered_gate_is_found_without_a_header():
    register_proxy_gate(gate_with())
    enf = resolve_enforcer({}, run_id=_RUN)
    assert enf.gate is not None
    assert enf.decide("search").allowed


def test_a_header_selects_among_several_registered_gates():
    register_proxy_gate(gate_with(agent_id="agt_a", allowed_tools=["search"]))
    register_proxy_gate(gate_with(agent_id="agt_b", allowed_tools=["wire_transfer"]))

    a = resolve_enforcer({AGENT_ID_HEADER: "agt_a"}, run_id="run_a")
    b = resolve_enforcer({AGENT_ID_HEADER: "agt_b"}, run_id="run_b")

    assert a.decide("search").allowed
    assert a.decide("wire_transfer").denied
    assert b.decide("wire_transfer").allowed


def test_an_unknown_agent_id_never_introduces_a_new_identity():
    """The header selects among configured gates; it is not a credential."""
    register_proxy_gate(gate_with(agent_id="agt_a"))

    enf = resolve_enforcer(
        {AGENT_ID_HEADER: "agt_invented"}, run_id=_RUN, posture=Posture.FAIL_CLOSED
    )

    assert enf.gate is None
    decision = enf.decide("search")
    assert decision.denied
    assert decision.verdict.reason == Reason.AGENT_UNRESOLVED


def test_ambiguous_request_with_several_gates_is_unresolved():
    register_proxy_gate(gate_with(agent_id="agt_a"))
    register_proxy_gate(gate_with(agent_id="agt_b"))

    enf = resolve_enforcer({}, run_id=_RUN, posture=Posture.FAIL_CLOSED)

    assert enf.decide("search").denied


def test_unresolved_agent_fails_per_posture_not_silently_open():
    closed = resolve_enforcer({}, run_id=_RUN, posture=Posture.FAIL_CLOSED)
    opened = resolve_enforcer({}, run_id=_RUN, posture=Posture.FAIL_OPEN)

    closed_decision = closed.decide("wire_transfer")
    open_decision = opened.decide("wire_transfer")

    assert closed_decision.denied
    assert isinstance(closed_decision.verdict, Deny)
    # fail_open still allows — but never silently: it is a Flag, and it is
    # recorded like every other verdict.
    assert open_decision.allowed
    assert open_decision.verdict.flagged
    assert open_decision.verdict.reason == Reason.AGENT_UNRESOLVED


def test_an_unresolved_denial_never_halts_the_run():
    """Config trouble is not a scope decision, so it must not latch."""
    enf = resolve_enforcer({}, run_id=_RUN, posture=Posture.FAIL_CLOSED)
    for _ in range(5):
        decision = enf.decide("search")
        assert decision.verdict.reason == Reason.AGENT_UNRESOLVED
        assert decision.halted is False


def test_unresolved_verdicts_are_still_recorded():
    recorder = RecordingRecorder()
    with use_verdict_recorder(recorder):
        resolve_enforcer({}, run_id=_RUN, posture=Posture.FAIL_CLOSED).decide("search")
    assert recorder.seen == [("blocked", "search")]


# -- streaming ---------------------------------------------------------------


def sse(event: str, data: dict) -> bytes:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n".encode()


def tool_use_stream(name: str = "search", *, block_id: str = "toolu_1") -> list[bytes]:
    return [
        sse("message_start", {"type": "message_start", "message": {"id": "msg_1"}}),
        sse(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "text", "text": ""},
            },
        ),
        sse(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": "Looking that up."},
            },
        ),
        sse("content_block_stop", {"type": "content_block_stop", "index": 0}),
        sse(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 1,
                "content_block": {"type": "tool_use", "id": block_id, "name": name, "input": {}},
            },
        ),
        sse(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": '{"q": "ra'},
            },
        ),
        sse(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 1,
                "delta": {"type": "input_json_delta", "partial_json": 'tes"}'},
            },
        ),
        sse("content_block_stop", {"type": "content_block_stop", "index": 1}),
        sse(
            "message_delta",
            {"type": "message_delta", "delta": {"stop_reason": "tool_use"}, "usage": {}},
        ),
        sse("message_stop", {"type": "message_stop"}),
    ]


def drive(frames: list[bytes], enf: ProxyEnforcer, *, chunk_size: int | None = None) -> bytes:
    stream = SseEnforcer(enf)
    raw = b"".join(frames)
    out = bytearray()
    if chunk_size is None:
        for frame in frames:
            out.extend(stream.feed(frame))
    else:
        for i in range(0, len(raw), chunk_size):
            out.extend(stream.feed(raw[i : i + chunk_size]))
    out.extend(stream.close())
    return bytes(out)


def test_allowed_stream_is_forwarded_byte_identical():
    frames = tool_use_stream("search")
    assert drive(frames, enforcer()) == b"".join(frames)


@pytest.mark.parametrize("chunk_size", [1, 7, 64, 4096])
def test_chunk_boundaries_do_not_change_the_output(chunk_size):
    frames = tool_use_stream("search")
    assert drive(frames, enforcer(), chunk_size=chunk_size) == b"".join(frames)


def test_stream_denial_withholds_the_block_and_replaces_it():
    out = drive(tool_use_stream("wire_transfer"), enforcer())

    assert b"wire_transfer" not in out
    assert b'"type":"tool_use"' not in out and b'"type": "tool_use"' not in out
    assert MODEL_MESSAGE.encode() in out
    # The text block before it survived untouched.
    assert b"Looking that up." in out
    # And the message no longer claims to be waiting on a tool.
    assert b'"stop_reason": "end_turn"' in out or b'"stop_reason":"end_turn"' in out


def test_stream_denies_mid_stream_without_buffering_the_response():
    """The decision lands at content_block_stop, not at the end of the response.

    Everything before the tool block is already downstream by the time the
    gate is consulted, and everything held back is one incomplete tool call.
    """
    frames = tool_use_stream("wire_transfer")
    stream = SseEnforcer(enforcer())

    emitted = [stream.feed(frame) for frame in frames]

    # Text frames went straight out, in the same feed() that received them.
    assert emitted[0] == frames[0]
    assert emitted[2] == frames[2]
    # The tool_use start and its deltas were held: nothing came back.
    assert emitted[4] == b""
    assert emitted[5] == b""
    assert emitted[6] == b""
    # The decision — and the replacement — land on content_block_stop, three
    # frames before the stream ends.
    assert MODEL_MESSAGE.encode() in emitted[7]
    assert stream.denied == 1


def test_text_only_stream_is_untouched():
    frames = [
        sse("message_start", {"type": "message_start", "message": {"id": "msg_1"}}),
        sse(
            "content_block_start",
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text"}},
        ),
        sse("content_block_stop", {"type": "content_block_stop", "index": 0}),
        sse(
            "message_delta",
            {"type": "message_delta", "delta": {"stop_reason": "end_turn"}},
        ),
    ]
    assert drive(frames, enforcer()) == b"".join(frames)


def test_a_stream_cut_mid_tool_use_never_releases_the_block():
    frames = tool_use_stream("search")[:7]  # start + deltas, no content_block_stop
    out = drive(frames, enforcer())

    assert b'"type":"tool_use"' not in out and b'"type": "tool_use"' not in out
    assert b'"q": "ra' not in out


def test_repeats_across_two_streamed_turns_halt_the_run():
    enf = enforcer()
    reasons = []
    for _ in range(3):
        drive(tool_use_stream("wire_transfer"), enf)
        reasons.append(enf.decisions[-1].verdict.reason)

    assert reasons == [Reason.OUT_OF_SCOPE, Reason.REPEAT_DENIED, Reason.RUN_HALTED]


def test_tool_use_arguments_reach_the_gate_for_approval():
    """RP-6: the proxy passes the block's input to the gate as the call's
    arguments, so an approval request can carry them under payload mode full."""
    seen = []

    class Recording(MandateGate):
        def decide(self, action):
            seen.append(action)
            return super().decide(action)

    async def never_called(_etag):  # pragma: no cover
        raise AssertionError("the decide path must not refresh")

    gate = Recording(never_called, agent_id=_AGENT)
    gate.apply_snapshot(snapshot_payload())
    enforce_response_body(tool_use_body("search"), enforcer(gate))

    assert seen and seen[0].arguments == {"q": "rates"}
