"""``@governed_tool``: what a verdict does to a real function call.

The gate itself is covered in ``test_mandate.py``; what matters here is the
seam. Every test uses a side-effecting function, because "the wrapped function
did not run" is the entire claim and a return value alone cannot prove it.
No network — gates are seeded with ``apply_snapshot``.
"""

from __future__ import annotations

import asyncio
import inspect
import logging

import pytest

from byoai.errors import ByoAIError, EnforcementIdentityUnavailableError, MandateDeniedError
from byoai.recorder.coriqo_agents import CoriqoCredentials
from byoai.recorder.governed_tool import (
    _default_gate,
    default_gate,
    governed_tool,
    set_default_gate,
    use_gate,
)
from byoai.recorder.identity import CoriqoIdentity
from byoai.recorder.mandate import (
    MODEL_MESSAGE,
    Deny,
    MandateGate,
    Posture,
    Reason,
    mandate_gate,
)

_AGENT = "coriqo-agent-1"


class Spy:
    """Records that the body actually executed."""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple, dict]] = []

    def __call__(self, *args, **kwargs) -> None:
        self.calls.append((args, kwargs))

    @property
    def ran(self) -> bool:
        return bool(self.calls)


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


def gate_with(**overrides) -> MandateGate:
    async def never_called(_etag):  # pragma: no cover - decide does no I/O
        raise AssertionError("the decide path must not refresh")

    gate = MandateGate(never_called, agent_id=_AGENT)
    gate.apply_snapshot(snapshot_payload(**overrides))
    return gate


@pytest.fixture(autouse=True)
def _no_leaked_default():
    """Every test starts with nothing bound, and leaves nothing bound."""
    with use_gate(None):
        yield


# -- allow -------------------------------------------------------------------


def test_an_in_scope_call_runs_and_returns_its_value():
    spy = Spy()

    @governed_tool
    def search(q):
        spy(q)
        return f"hits:{q}"

    with use_gate(gate_with()):
        assert search("rates") == "hits:rates"
    assert spy.ran


async def test_an_in_scope_async_call_runs_and_returns_its_value():
    spy = Spy()

    @governed_tool
    async def search(q):
        await asyncio.sleep(0)
        spy(q)
        return f"hits:{q}"

    with use_gate(gate_with()):
        assert await search("rates") == "hits:rates"
    assert spy.ran


def test_arguments_and_return_values_pass_through_untouched():
    @governed_tool
    def search(a, b=2, *rest, key=None, **extra):
        return (a, b, rest, key, extra)

    sentinel = object()
    with use_gate(gate_with()):
        got = search(1, 3, 4, 5, key=sentinel, other="x")
    assert got == (1, 3, (4, 5), sentinel, {"other": "x"})


def test_the_wrapped_function_raises_its_own_errors_unchanged():
    @governed_tool
    def search():
        raise ValueError("the tool itself failed")

    with use_gate(gate_with()), pytest.raises(ValueError, match="the tool itself failed"):
        search()


# -- flag is not a block -----------------------------------------------------


def test_an_off_mandate_call_under_observe_still_runs():
    """`observe` is the rollout dial: record what would have been blocked."""
    spy = Spy()

    @governed_tool
    def rm(path):
        spy(path)
        return "gone"

    with use_gate(gate_with(mandate_enforcement="observe")):
        assert rm("/etc") == "gone"
    assert spy.ran, "a flag is not a block"


async def test_an_async_off_mandate_call_under_observe_still_runs():
    spy = Spy()

    @governed_tool
    async def rm(path):
        spy(path)
        return "gone"

    with use_gate(gate_with(mandate_enforcement="observe")):
        assert await rm("/etc") == "gone"
    assert spy.ran


def test_a_stale_snapshot_under_fail_open_flags_and_still_runs():
    spy = Spy()

    @governed_tool
    def search():
        spy()

    gate = MandateGate(None, agent_id=_AGENT)  # no source: the no-op gate
    with use_gate(gate):
        search()
    assert spy.ran


# -- deny --------------------------------------------------------------------


def test_a_denied_call_never_reaches_the_function():
    spy = Spy()

    @governed_tool
    def rm(path):
        spy(path)
        return "gone"

    with use_gate(gate_with()), pytest.raises(MandateDeniedError):
        rm("/etc")
    assert not spy.ran, "the denied function must not have run at all"


async def test_a_denied_async_call_never_reaches_the_function():
    spy = Spy()

    @governed_tool
    async def rm(path):
        spy(path)
        return "gone"

    with use_gate(gate_with()), pytest.raises(MandateDeniedError):
        await rm("/etc")
    assert not spy.ran


def test_the_raised_error_carries_the_verdict_for_the_operator():
    @governed_tool
    def rm(path):  # pragma: no cover - never runs
        raise AssertionError

    with use_gate(gate_with()), pytest.raises(MandateDeniedError) as caught:
        rm("/etc")

    exc = caught.value
    assert isinstance(exc.verdict, Deny)
    assert exc.verdict.reason == Reason.OUT_OF_SCOPE
    assert exc.verdict.mandate_version_id == "mv_1"
    assert exc.tool == "rm"
    assert "mv_1" in exc.operator_detail and "rm" in exc.operator_detail


def test_a_denial_derives_from_byoai_error_not_a_provider_type():
    assert issubclass(MandateDeniedError, ByoAIError)


def test_nothing_about_a_denial_invites_a_retry():
    """A retryable-looking denial is one the model routes around."""
    with use_gate(gate_with()):
        gate = default_gate()
        assert gate is not None
        exc = MandateDeniedError(gate.decide("rm"))

    assert exc.retryable is False
    assert not hasattr(exc, "retry_after")
    assert not isinstance(exc, TimeoutError)


def test_the_model_facing_text_is_the_fixed_sentence_and_only_that():
    """`str(exc)` is what frameworks feed back into the model's context."""
    denials = {
        "out of scope": gate_with(),
        "suspended agent": gate_with(status="suspended"),
        "unrestricted but retired": gate_with(allowed_tools=None, status="retired"),
    }
    messages = set()
    for label, gate in denials.items():
        verdict = gate.decide("wire_transfer")
        assert isinstance(verdict, Deny), label
        exc = MandateDeniedError(verdict)
        messages.add(str(exc))
        assert exc.model_message == MODEL_MESSAGE
        for leak in ("wire_transfer", "mv_1", verdict.reason):
            assert leak not in str(exc), label
            assert leak not in repr(exc), label

    assert messages == {MODEL_MESSAGE}, "every denial reads identically to the model"


def test_a_fail_closed_gate_with_no_snapshot_denies_before_the_function_runs():
    spy = Spy()

    @governed_tool
    def search():
        spy()

    async def never_called(_etag):  # pragma: no cover
        raise AssertionError

    gate = MandateGate(
        never_called, agent_id=_AGENT, default_posture=Posture.FAIL_CLOSED
    )
    with use_gate(gate), pytest.raises(MandateDeniedError):
        search()
    assert not spy.ran


def test_a_denial_is_logged_for_the_operator(caplog):
    @governed_tool
    def rm(path):  # pragma: no cover - never runs
        raise AssertionError

    with caplog.at_level(logging.WARNING, logger="byoai.recorder.governed_tool"):
        with use_gate(gate_with()), pytest.raises(MandateDeniedError):
            rm("/etc")

    assert any("blocked tool call" in r.getMessage() for r in caplog.records)


# -- introspection -----------------------------------------------------------


def test_the_wrapper_looks_exactly_like_the_tool_it_wraps():
    @governed_tool
    def search(query: str, limit: int = 10) -> str:
        """Search the corpus."""
        return query

    assert search.__name__ == "search"
    assert search.__doc__ == "Search the corpus."
    assert inspect.signature(search) == inspect.signature(search.__wrapped__)
    assert list(inspect.signature(search).parameters) == ["query", "limit"]
    assert inspect.signature(search).parameters["limit"].default == 10


async def test_an_async_wrapper_is_still_a_coroutine_function():
    @governed_tool
    async def search(query: str) -> str:
        """Search the corpus."""
        return query

    assert inspect.iscoroutinefunction(search)
    assert search.__name__ == "search"
    assert search.__doc__ == "Search the corpus."
    assert inspect.signature(search) == inspect.signature(search.__wrapped__)
    assert list(inspect.signature(search).parameters) == ["query"]


def test_the_tool_name_defaults_to_the_function_name():
    @governed_tool
    def search():
        return "ok"

    with use_gate(gate_with(allowed_tools=["search"])):
        assert search() == "ok"


def test_the_tool_name_is_overridable():
    """The Python name and the name Coriqo approved are not always the same."""

    @governed_tool(name="search")
    def corpus_search_v2():
        return "ok"

    with use_gate(gate_with(allowed_tools=["search"])):
        assert corpus_search_v2() == "ok"

    with use_gate(gate_with(allowed_tools=["corpus_search_v2"])):
        with pytest.raises(MandateDeniedError) as caught:
            corpus_search_v2()
    assert caught.value.tool == "search", "the override, not __name__, is decided on"


def test_the_decorator_works_bare_and_called():
    @governed_tool
    def a():
        return "a"

    @governed_tool()
    def b():
        return "b"

    with use_gate(gate_with(allowed_tools=["a", "b"])):
        assert (a(), b()) == ("a", "b")


def test_arguments_are_carried_onto_the_proposed_action():
    seen = []

    class Recording(MandateGate):
        def decide(self, action):
            seen.append(action)
            return super().decide(action)

    gate = Recording(None, agent_id=_AGENT)

    @governed_tool(capture_arguments=True)
    def search(query, limit=10):
        return "ok"

    with use_gate(gate):
        search("rates", limit=3)

    assert seen[0].tool == "search"
    assert seen[0].arguments == {"query": "rates", "limit": 3}


def test_captured_arguments_gate_the_approval_request_on_payload_mode(monkeypatch):
    """RP-6: the arguments `governed_tool` captures are sent to Coriqo with an
    approval request only under payload mode full."""
    from byoai.recorder.mandate import approval_args

    seen = []

    class Recording(MandateGate):
        def decide(self, action):
            seen.append(action)
            return super().decide(action)

    gate = Recording(None, agent_id=_AGENT)

    @governed_tool(capture_arguments=True)
    def wire(amount_usd):
        return "ok"

    with use_gate(gate):
        wire(amount_usd=5)

    monkeypatch.setenv("BYOAI_RECORDER_PAYLOAD_MODE", "full")
    assert approval_args(seen[0].arguments) == {"amount_usd": 5}
    monkeypatch.setenv("BYOAI_RECORDER_PAYLOAD_MODE", "redacted")
    assert approval_args(seen[0].arguments) is None


def test_arguments_are_not_captured_by_default():
    """Capture is opt-in: a governed tool's arguments routinely hold account
    numbers and credentials, and nothing redacts them yet."""
    seen = []

    class Recording(MandateGate):
        def decide(self, action):
            seen.append(action)
            return super().decide(action)

    gate = Recording(None, agent_id=_AGENT)

    @governed_tool
    def search(query, limit=10):
        return "ok"

    with use_gate(gate):
        search("rates", limit=3)

    assert seen[0].tool == "search"
    assert seen[0].arguments is None


def test_argument_capture_can_be_turned_off():
    seen = []

    class Recording(MandateGate):
        def decide(self, action):
            seen.append(action)
            return super().decide(action)

    @governed_tool(capture_arguments=False)
    def search(secret):
        return "ok"

    with use_gate(Recording(None, agent_id=_AGENT)):
        search("hunter2")

    assert seen[0].arguments is None


def test_a_bad_call_still_raises_the_functions_own_type_error():
    @governed_tool
    def search(query):
        return query

    with use_gate(gate_with()), pytest.raises(TypeError):
        search()  # type: ignore[call-arg]


# -- gate resolution ---------------------------------------------------------


def test_an_explicit_gate_beats_the_context_default():
    permissive = gate_with(allowed_tools=None)

    @governed_tool(gate=permissive)
    def rm(path):
        return "gone"

    with use_gate(gate_with()):  # would deny `rm`
        assert rm("/etc") == "gone"


def test_a_gate_factory_is_evaluated_per_call_not_at_decoration():
    """Tools are defined at import time; gates are built at startup."""
    holder: dict[str, MandateGate | None] = {"gate": None}

    @governed_tool(gate=lambda: holder["gate"])
    def rm(path):
        return "gone"

    assert rm("/etc") == "gone", "no gate yet: adoptable before enrolment"

    holder["gate"] = gate_with()
    with pytest.raises(MandateDeniedError):
        rm("/etc")


def test_a_factory_returning_none_falls_back_to_the_context_default():
    @governed_tool(gate=lambda: None)
    def rm(path):
        return "gone"

    with use_gate(gate_with()), pytest.raises(MandateDeniedError):
        rm("/etc")


def test_use_gate_restores_the_previous_binding():
    outer = gate_with()
    inner = gate_with(allowed_tools=None)

    with use_gate(outer):
        assert default_gate() is outer
        with use_gate(inner):
            assert default_gate() is inner
        assert default_gate() is outer
    assert default_gate() is None


def test_set_default_gate_returns_a_token_that_resets():
    """The startup-time form: bind once, keep the token to unwind."""
    gate = gate_with()
    token = set_default_gate(gate)
    try:
        assert default_gate() is gate
    finally:
        _default_gate.reset(token)
    assert default_gate() is None


async def test_two_concurrent_agents_do_not_share_a_mandate():
    """A ContextVar, not a module global — one process, two mandates."""
    results: dict[str, object] = {}

    @governed_tool
    def rm(path):
        return "gone"

    async def agent(label: str, gate: MandateGate) -> None:
        with use_gate(gate):
            await asyncio.sleep(0)
            try:
                results[label] = rm("/etc")
            except MandateDeniedError as exc:
                results[label] = exc

    await asyncio.gather(
        agent("strict", gate_with()),
        agent("open", gate_with(allowed_tools=None)),
    )

    assert isinstance(results["strict"], MandateDeniedError)
    assert results["open"] == "gone"


# -- adoptable before enrolment ---------------------------------------------


def test_with_no_coriqo_identity_the_decorator_is_a_no_op_that_runs_the_function(
    monkeypatch, caplog, tmp_path
):
    monkeypatch.delenv("BYOAI_CORIQO_API_KEY", raising=False)
    monkeypatch.setenv("BYOAI_RECORDER_HOME", str(tmp_path))
    spy = Spy()

    @governed_tool
    def rm(path):
        spy(path)
        return "gone"

    gate = mandate_gate(_AGENT)
    assert not gate.enabled

    with caplog.at_level(logging.INFO, logger="byoai.recorder.mandate"):
        with use_gate(gate):
            assert rm("/etc") == "gone"
            assert rm("/tmp") == "gone"

    assert spy.calls == [(("/etc",), {}), (("/tmp",), {})]
    assert sum("not gated" in r.message for r in caplog.records) == 1, "logged once"


def test_a_static_api_key_identity_is_refused_rather_than_silently_ungated():
    identity = CoriqoIdentity.from_credentials(
        CoriqoCredentials(
            base_url="https://coriqo.test", api_key="cq_sa_test", tenant_slug="acme_bank"
        )
    )
    with pytest.raises(EnforcementIdentityUnavailableError):
        mandate_gate(_AGENT, identity=identity)


def test_with_nothing_bound_at_all_the_function_still_runs():
    spy = Spy()

    @governed_tool
    def rm(path):
        spy(path)
        return "gone"

    assert rm("/etc") == "gone"
    assert spy.ran
