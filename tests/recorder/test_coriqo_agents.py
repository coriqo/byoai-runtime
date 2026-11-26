"""Publishing recorded runs to Coriqo's agent governance API.

Distinct from test_shipper.py / test_end_to_end_sync.py, which cover the device
ledger sync (``/v1/enroll`` + ``/v1/ingest/batch``). This covers the other
integration: Coriqo's shipped ``/api/v1/agents/…`` API.

The fakes here reproduce behavior verified against a live local Coriqo on
2026-08-13, after its agents-SDK-ergonomics work landed — in particular that
``external_id`` makes registration idempotent (200 = already existed, 201 =
created, and a repeat call does not apply payload changes), that
``/traces/batch`` is all-or-nothing but reports per-trace status, and that
external grounding anchors are held outside the integrity calculation.
"""

from __future__ import annotations

import json
from collections.abc import Iterator

import httpx
import pytest

from byoai.recorder.coriqo_agents import (
    GROUNDING_SYSTEM,
    GUARDRAIL_CONTROL_SYSTEM,
    MAX_TRACE_BATCH,
    AgentRegistration,
    AgentSuspendedError,
    CoriqoAgentsClient,
    CoriqoAgentsError,
    CoriqoCredentials,
    ensure_registered,
    publish_session,
    read_external_controls,
    read_tool_steps,
)
from byoai.recorder.keys import load_or_create_device_key
from byoai.recorder.ledger import Ledger
from byoai.recorder.redact import PayloadMode
from byoai.recorder.schema import EventKind

from .conftest import make_event

_CORIQO_AGENT = "coriqo-agent-1"


def _client(handler) -> CoriqoAgentsClient:
    return CoriqoAgentsClient(
        CoriqoCredentials(
            base_url="https://coriqo.test", api_key="cq_sa_test", tenant_slug="acme_bank"
        ),
        http_client=httpx.Client(
            base_url="https://coriqo.test",
            headers={"X-API-Key": "cq_sa_test", "X-Tenant-Slug": "acme_bank"},
            transport=httpx.MockTransport(handler),
        ),
    )


@pytest.fixture
def ledger(tmp_path) -> Iterator[Ledger]:
    key = load_or_create_device_key(tmp_path)
    led = Ledger(tmp_path / "ledger.db", device_id=key.device_id)
    yield led
    led.close()


def _seal_run(ledger: Ledger, session_id: str, tools: list[str]) -> list[dict[str, str]]:
    """Seals a tool_use/tool_result pair per tool, returning each step's hashes."""
    device_id = "dev_test"
    sealed = []
    for i, tool in enumerate(tools):
        tool_use_id = f"toolu_{i}"
        use = ledger.append(
            make_event(
                device_id,
                session_id,
                EventKind.TOOL_USE,
                payload={"cmd": tool, "n": i},
                tool_use_id=tool_use_id,
                tool_name=tool,
            )
        )
        result = ledger.append(
            make_event(
                device_id,
                session_id,
                EventKind.TOOL_RESULT,
                payload={"out": f"{tool}-done"},
                tool_use_id=tool_use_id,
                tool_name=None,
            )
        )
        assert use is not None and result is not None
        sealed.append(
            {
                "args_hash": use.event.payload_hash,
                "result_hash": result.event.payload_hash,
                "entry_hash": use.entry_hash,
            }
        )
    return sealed


def _batch_handler(traces_seen, *, flagged_steps=()):
    """Stands in for /traces/batch, flagging the given step indexes."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/trajectories"):
            return httpx.Response(201, json={"trajectory_id": "traj-1"})
        if path.endswith("/complete"):
            traces_seen.setdefault("completions", []).append(json.loads(request.content))
            return httpx.Response(200, json={})
        if path.endswith("/traces/batch"):
            body = json.loads(request.content)
            traces_seen.setdefault("batches", []).append(body["traces"])
            out = []
            for t in body["traces"]:
                is_flagged = t["step_index"] in flagged_steps
                out.append(
                    {
                        "trace_id": f"t{t['step_index']}",
                        "step_index": t["step_index"],
                        "status": "flagged" if is_flagged else "recorded",
                        "flag_reason": "outside mandate" if is_flagged else None,
                    }
                )
            return httpx.Response(
                201,
                json={
                    "recorded": len(out),
                    "flagged": sum(1 for t in out if t["status"] == "flagged"),
                    "traces": out,
                },
            )
        if path.endswith("/external-controls"):
            body = json.loads(request.content)
            traces_seen.setdefault("controls", []).append(body)
            return httpx.Response(
                201,
                json={"recorded": len(body["controls"]), "skipped": 0, "controls": []},
            )
        raise AssertionError(f"unexpected {request.method} {path}")

    return handler


# -- credentials -----------------------------------------------------------


def test_credentials_are_off_without_a_url(monkeypatch):
    monkeypatch.delenv("BYOAI_CORIQO_URL", raising=False)
    assert CoriqoCredentials.from_env() is None


def test_partial_credentials_are_treated_as_a_misconfiguration(monkeypatch):
    """A URL with no key is a typo, not a request to publish anonymously."""
    monkeypatch.setenv("BYOAI_CORIQO_URL", "https://coriqo.test")
    monkeypatch.delenv("BYOAI_CORIQO_API_KEY", raising=False)
    monkeypatch.setenv("BYOAI_CORIQO_TENANT_SLUG", "acme_bank")
    assert CoriqoCredentials.from_env() is None


def test_credentials_from_env_strip_a_trailing_slash(monkeypatch):
    monkeypatch.setenv("BYOAI_CORIQO_URL", "https://coriqo.test/")
    monkeypatch.setenv("BYOAI_CORIQO_API_KEY", "cq_sa_x")
    monkeypatch.setenv("BYOAI_CORIQO_TENANT_SLUG", "acme_bank")
    creds = CoriqoCredentials.from_env()
    assert creds is not None and creds.base_url == "https://coriqo.test"


# -- registration ----------------------------------------------------------


def test_registration_sends_an_external_id_derived_from_the_key():
    """external_id is what makes this idempotent, so it must always be sent —
    without it Coriqo creates a fresh agent on every startup."""
    posted = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append(json.loads(request.content))
        assert request.headers["x-api-key"] == "cq_sa_test"
        assert request.headers["x-tenant-slug"] == "acme_bank"
        return httpx.Response(201, json={"agent_id": "a1"})

    with _client(handler) as client:
        resolved = ensure_registered(
            client,
            {"local-1": AgentRegistration(name="One", allowed_tools=("x", "y"))},
            external_id_prefix="myapp:",
        )

    assert resolved == {"local-1": "a1"}
    assert posted[0]["external_id"] == "myapp:local-1"
    assert posted[0]["allowed_tools"] == ["x", "y"]


def test_an_explicit_external_id_is_not_overridden():
    posted = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append(json.loads(request.content))
        return httpx.Response(201, json={"agent_id": "a1"})

    with _client(handler) as client:
        ensure_registered(
            client,
            {"local-1": AgentRegistration(name="One", external_id="chosen-by-caller")},
            external_id_prefix="myapp:",
        )
    assert posted[0]["external_id"] == "chosen-by-caller"


def test_an_already_registered_agent_returns_its_existing_id():
    """Coriqo answers 200 with the existing agent rather than creating a second
    copy, which is what lets this run on every startup."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"agent_id": "already-there"})

    with _client(handler) as client:
        resolved = ensure_registered(client, {"local-1": AgentRegistration(name="One")})
    assert resolved == {"local-1": "already-there"}


def test_registration_reports_whether_it_created_the_agent():
    def created(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"agent_id": "a1"})

    def existing(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"agent_id": "a1"})

    with _client(created) as client:
        assert client.register_agent(AgentRegistration(name="One"))[1] is True
    with _client(existing) as client:
        assert client.register_agent(AgentRegistration(name="One"))[1] is False


def test_registration_body_omits_fields_coriqo_does_not_declare():
    """Coriqo's request schemas are strict (extra='forbid'), so a spare key is
    a 422 rather than being silently dropped."""
    body = AgentRegistration(name="One").to_body()
    assert set(body) == {"name", "mandate", "system", "risk_tier", "allowed_tools", "owner_id"}
    with_extras = AgentRegistration(
        name="One", external_id="e", mandate_enforcement="observe"
    ).to_body()
    assert with_extras["mandate_enforcement"] == "observe"


def test_ensure_registered_raises_when_coriqo_refuses():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"detail": "Role 'governance:approve' required"})

    with _client(handler) as client:
        with pytest.raises(CoriqoAgentsError) as excinfo:
            ensure_registered(client, {"local-1": AgentRegistration(name="One")})
    assert excinfo.value.status_code == 403


def test_ensure_registered_raises_if_no_agent_id_comes_back():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"validation_status": "in_review"})

    with _client(handler) as client:
        with pytest.raises(CoriqoAgentsError):
            ensure_registered(client, {"local-1": AgentRegistration(name="One")})


def test_list_agents_pages_past_the_server_cap():
    """Coriqo caps limit at 200 per request. A caller using this to decide
    whether an agent exists would register duplicates for everything past the
    first page if it didn't follow the offset."""
    total = 450
    seen_offsets = []

    def handler(request: httpx.Request) -> httpx.Response:
        offset = int(request.url.params["offset"])
        limit = int(request.url.params["limit"])
        seen_offsets.append(offset)
        page = [
            {"agent_id": f"a{i}", "name": f"n{i}"}
            for i in range(offset, min(offset + limit, total))
        ]
        return httpx.Response(200, json={"items": page, "total": total, "offset": offset})

    with _client(handler) as client:
        agents = client.list_agents()
    assert len(agents) == total
    assert seen_offsets == [0, 200, 400]


def test_list_agents_stops_on_an_empty_page_even_if_total_disagrees():
    """A miscounted total must not spin the pager forever."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"items": [], "total": 999, "offset": 0})

    with _client(handler) as client:
        assert client.list_agents() == []


def test_list_agents_honors_an_explicit_limit():
    def handler(request: httpx.Request) -> httpx.Response:
        requested = int(request.url.params["limit"])
        assert requested <= 200
        return httpx.Response(
            200,
            json={"items": [{"agent_id": f"a{i}"} for i in range(requested)], "total": 500},
        )

    with _client(handler) as client:
        assert len(client.list_agents(limit=50)) == 50


# -- reading sealed steps --------------------------------------------------


def test_read_tool_steps_pairs_by_tool_use_id(ledger):
    sealed = _seal_run(ledger, "run_1", ["get_transaction", "flag_decision"])
    steps = read_tool_steps(ledger, "run_1")

    assert [s.tool_name for s in steps] == ["get_transaction", "flag_decision"]
    assert [s.index for s in steps] == [0, 1]
    # The published hashes must be the ledger's own — that shared digest is
    # what ties a Coriqo trace to the sealed row behind it.
    for step, expected in zip(steps, sealed, strict=True):
        assert step.args_hash == expected["args_hash"]
        assert step.result_hash == expected["result_hash"]
        assert step.entry_hash == expected["entry_hash"]


def test_read_tool_steps_ignores_other_sessions(ledger):
    _seal_run(ledger, "run_1", ["a"])
    _seal_run(ledger, "run_2", ["b", "c"])
    assert [s.tool_name for s in read_tool_steps(ledger, "run_2")] == ["b", "c"]


def test_an_unpaired_tool_use_still_publishes_with_no_result_hash(ledger):
    ledger.append(
        make_event("dev_test", "run_1", EventKind.TOOL_USE, tool_use_id="toolu_x", tool_name="hung")
    )
    steps = read_tool_steps(ledger, "run_1")
    assert len(steps) == 1 and steps[0].result_hash is None


def test_read_tool_steps_is_empty_for_an_unknown_session(ledger):
    assert read_tool_steps(ledger, "nope") == []


def test_events_without_a_tool_use_id_are_never_paired(ledger):
    """extract.py stores tool_use_id=None when a transcript's id field wasn't a
    string. Those must not collide on the None key: without a guard, the
    results dict keeps only the last one and an unrelated malformed tool_use
    gets published carrying that result's hash and latency as its own evidence
    — a wrong result_hash sealed into Coriqo as governance evidence, invisible
    without cross-checking the raw ledger.
    """
    own_result_hashes = []
    for i in (0, 1):
        ledger.append(
            _event_without_ids(EventKind.TOOL_USE, {"cmd": f"malformed_{i}"}, f"tool_{i}")
        )
        result = ledger.append(
            _event_without_ids(EventKind.TOOL_RESULT, {"out": f"result_{i}"}, None)
        )
        assert result is not None
        own_result_hashes.append(result.event.payload_hash)

    steps = read_tool_steps(ledger, "run_malformed")
    assert [s.tool_name for s in steps] == ["tool_0", "tool_1"]
    for step in steps:
        assert step.result_hash is None, (
            f"{step.tool_name} was paired with an unrelated result: {step.result_hash}"
        )
        assert step.latency_ms is None
    # The results themselves were sealed and remain in the ledger; they just
    # can't be attributed to a specific call.
    assert len(set(own_result_hashes)) == 2


def _event_without_ids(kind: EventKind, payload: dict, tool_name: str | None):
    """A ledger event with ``tool_use_id`` genuinely None.

    conftest's ``make_event`` substitutes a generated id for a falsy one, which
    is the right default everywhere else but would hide exactly the case under
    test here.
    """
    import time
    import uuid

    from byoai.recorder.canonical import canonicalize, sha256_hex
    from byoai.recorder.schema import (
        EVENT_SCHEMA_VERSION,
        AgentEvent,
        new_span_id,
        new_trace_id,
    )

    return AgentEvent(
        schema_version=EVENT_SCHEMA_VERSION,
        event_id="evt_" + uuid.uuid4().hex,
        device_id="dev_test",
        session_id="run_malformed",
        seq=0,
        kind=kind.value,
        ts_device="2026-08-13T12:00:00.000000Z",
        ts_monotonic_ns=time.monotonic_ns(),
        tool_use_id=None,
        tool_name=tool_name,
        payload=payload,
        payload_hash=sha256_hex(canonicalize(payload)),
        model="claude-opus-4-20250514",
        provider="anthropic",
        trace_id=new_trace_id(),
        span_id=new_span_id(),
    )


# -- publishing ------------------------------------------------------------


def test_publish_session_sends_one_batch_with_ledger_hashes(ledger):
    sealed = _seal_run(ledger, "run_1", ["get_transaction", "flag_decision"])
    seen: dict = {}

    with _client(_batch_handler(seen)) as client:
        result = publish_session(
            client,
            coriqo_agent_id=_CORIQO_AGENT,
            ledger=ledger,
            session_id="run_1",
            goal="triage it",
            final_output="cleared",
        )

    assert result is not None
    assert (result.recorded, result.flagged, result.status) == (2, 0, "completed")
    # One batch request for the whole run, not one per step.
    assert len(seen["batches"]) == 1
    assert seen["completions"] == [{"status": "completed"}]

    traces = seen["batches"][0]
    for i, trace in enumerate(traces):
        call = trace["tool_calls"][0]
        assert call["args_hash"] == sealed[i]["args_hash"]
        assert call["result_hash"] == sealed[i]["result_hash"]
        assert trace["step_index"] == i
        assert trace["trajectory_id"] == "traj-1"
        # Raw arguments must never be on the wire — the hashes already commit
        # to them, and `inputs` reaches Coriqo before being hashed there.
        assert "args" not in call and "result" not in call
        assert set(trace["inputs"]) == {"session_id", "step", "tool"}

    # Only the last step carries the run's decision text.
    assert [t["output"] for t in traces] == [None, "cleared"]


def test_publish_session_redacts_pii_in_final_output_by_default(ledger):
    """`payload_mode` defaults to `redacted`, matching the recorder's own
    default — a decision's readable text is bound by the same policy as the
    tool payloads that produced it, not shipped raw regardless of mode."""
    _seal_run(ledger, "run_1", ["get_transaction", "flag_decision"])
    seen: dict = {}

    with _client(_batch_handler(seen)) as client:
        publish_session(
            client,
            coriqo_agent_id=_CORIQO_AGENT,
            ledger=ledger,
            session_id="run_1",
            final_output="Approved for user@example.com, SSN 123-45-6789 on file.",
        )

    outputs = [t["output"] for t in seen["batches"][0] if t["output"] is not None]
    assert len(outputs) == 1
    assert "user@example.com" not in outputs[0]
    assert "123-45-6789" not in outputs[0]
    assert "[REDACTED:email]" in outputs[0]
    assert "[REDACTED:ssn]" in outputs[0]


def test_publish_session_ships_final_output_unchanged_under_full_mode(ledger):
    _seal_run(ledger, "run_1", ["get_transaction", "flag_decision"])
    seen: dict = {}
    text = "Approved for user@example.com, SSN 123-45-6789 on file."

    with _client(_batch_handler(seen)) as client:
        publish_session(
            client,
            coriqo_agent_id=_CORIQO_AGENT,
            ledger=ledger,
            session_id="run_1",
            final_output=text,
            payload_mode=PayloadMode.FULL,
        )

    outputs = [t["output"] for t in seen["batches"][0] if t["output"] is not None]
    assert outputs == [text]


def test_publish_session_drops_final_output_under_hash_only_mode(ledger):
    _seal_run(ledger, "run_1", ["get_transaction", "flag_decision"])
    seen: dict = {}

    with _client(_batch_handler(seen)) as client:
        publish_session(
            client,
            coriqo_agent_id=_CORIQO_AGENT,
            ledger=ledger,
            session_id="run_1",
            final_output="Approved for user@example.com.",
            payload_mode=PayloadMode.HASH_ONLY,
        )

    assert all(t["output"] is None for t in seen["batches"][0])


def test_publish_session_drops_final_output_when_hash_only_is_given_as_text(ledger):
    _seal_run(ledger, "run_1", ["get_transaction", "flag_decision"])
    seen: dict = {}

    with _client(_batch_handler(seen)) as client:
        publish_session(
            client,
            coriqo_agent_id=_CORIQO_AGENT,
            ledger=ledger,
            session_id="run_1",
            final_output="Approved for user@example.com.",
            payload_mode="hash-only",
        )

    assert all(t["output"] is None for t in seen["batches"][0])


def test_publish_session_uses_a_custom_redactor_under_redacted_mode(ledger):
    """A caller who needs detection beyond fixed-shape patterns (e.g. names)
    supplies their own TextRedactor instead of the default scanner."""
    _seal_run(ledger, "run_1", ["get_transaction", "flag_decision"])
    seen: dict = {}

    def redact_everything(text: str) -> str:
        return "[REDACTED:custom]"

    with _client(_batch_handler(seen)) as client:
        publish_session(
            client,
            coriqo_agent_id=_CORIQO_AGENT,
            ledger=ledger,
            session_id="run_1",
            final_output="Approved for Priya Kestrel.",
            payload_mode=PayloadMode.REDACTED,
            redactor=redact_everything,
        )

    outputs = [t["output"] for t in seen["batches"][0] if t["output"] is not None]
    assert outputs == ["[REDACTED:custom]"]


def test_publish_session_never_calls_redactor_outside_redacted_mode(ledger):
    _seal_run(ledger, "run_1", ["get_transaction", "flag_decision"])
    seen: dict = {}
    calls: list[str] = []

    def tracking_redactor(text: str) -> str:
        calls.append(text)
        return text

    with _client(_batch_handler(seen)) as client:
        publish_session(
            client,
            coriqo_agent_id=_CORIQO_AGENT,
            ledger=ledger,
            session_id="run_1",
            final_output="Approved for Priya Kestrel.",
            payload_mode=PayloadMode.FULL,
            redactor=tracking_redactor,
        )

    assert calls == []


def test_each_trace_cites_its_sealed_ledger_row_as_an_external_anchor(ledger):
    """Coriqo holds external anchors outside its integrity scoring, so citing a
    hash it has no copy of adds provenance without distorting the score."""
    sealed = _seal_run(ledger, "run_1", ["a", "b"])
    seen: dict = {}

    with _client(_batch_handler(seen)) as client:
        publish_session(client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_1")

    for i, trace in enumerate(seen["batches"][0]):
        assert trace["grounding_refs"] == [
            {"type": "external", "id": sealed[i]["entry_hash"], "system": GROUNDING_SYSTEM}
        ]


def test_grounding_anchors_can_be_turned_off(ledger):
    _seal_run(ledger, "run_1", ["a"])
    seen: dict = {}

    with _client(_batch_handler(seen)) as client:
        publish_session(
            client,
            coriqo_agent_id=_CORIQO_AGENT,
            ledger=ledger,
            session_id="run_1",
            ground_in_ledger=False,
        )
    assert seen["batches"][0][0]["grounding_refs"] is None


def test_a_long_run_is_split_across_batches(ledger):
    """Coriqo caps a batch at 200 traces, so a longer run has to be chunked
    rather than 422'd."""
    _seal_run(ledger, "run_1", [f"tool_{i}" for i in range(MAX_TRACE_BATCH + 5)])
    seen: dict = {}

    with _client(_batch_handler(seen)) as client:
        result = publish_session(
            client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_1"
        )

    assert [len(b) for b in seen["batches"]] == [MAX_TRACE_BATCH, 5]
    assert result is not None and result.recorded == MAX_TRACE_BATCH + 5


def test_publish_session_returns_none_when_nothing_was_sealed(ledger):
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should not have called Coriqo")

    with _client(handler) as client:
        assert (
            publish_session(
                client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_none"
            )
            is None
        )


def test_a_flagged_step_completes_the_trajectory_as_flagged(ledger):
    """A run that went outside its mandate should not close looking clean."""
    _seal_run(ledger, "run_1", ["ok_tool", "initiate_wire_transfer"])
    seen: dict = {}

    with _client(_batch_handler(seen, flagged_steps={1})) as client:
        result = publish_session(
            client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_1"
        )

    assert result is not None and result.flagged == 1
    assert result.status == "flagged"
    assert seen["completions"] == [{"status": "flagged"}]


def test_a_nested_run_passes_its_parent_trajectory(ledger):
    _seal_run(ledger, "run_1", ["a"])
    opened = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/trajectories"):
            opened.append(json.loads(request.content))
            return httpx.Response(201, json={"trajectory_id": "child"})
        if path.endswith("/complete"):
            return httpx.Response(200, json={})
        return httpx.Response(201, json={"recorded": 1, "flagged": 0, "traces": []})

    with _client(handler) as client:
        publish_session(
            client,
            coriqo_agent_id=_CORIQO_AGENT,
            ledger=ledger,
            session_id="run_1",
            parent_trajectory_id="parent-traj",
        )
    assert opened[0]["parent_trajectory_id"] == "parent-traj"


def test_malformed_counts_do_not_crash_a_publish(ledger):
    """Counts are reporting figures, not control flow. A ValueError here would
    escape the handler that closes the trajectory and strand it open."""
    _seal_run(ledger, "run_1", ["a"])
    completions = []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/trajectories"):
            return httpx.Response(201, json={"trajectory_id": "traj-1"})
        if path.endswith("/complete"):
            completions.append(json.loads(request.content))
            return httpx.Response(200, json={})
        return httpx.Response(201, json={"recorded": None, "flagged": "not-a-number", "traces": []})

    with _client(handler) as client:
        result = publish_session(
            client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_1"
        )

    assert result is not None
    assert (result.recorded, result.flagged) == (0, 0)
    assert completions == [{"status": "completed"}], "the trajectory was left open"


def test_numeric_string_counts_are_still_counted(ledger):
    """A JSON encoder that quotes its numbers is reporting a real count —
    zeroing it would undercount silently."""
    _seal_run(ledger, "run_1", ["a", "b"])

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/trajectories"):
            return httpx.Response(201, json={"trajectory_id": "traj-1"})
        if path.endswith("/complete"):
            return httpx.Response(200, json={})
        return httpx.Response(201, json={"recorded": "2", "flagged": "1", "traces": []})

    with _client(handler) as client:
        result = publish_session(
            client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_1"
        )

    assert result is not None
    assert (result.recorded, result.flagged) == (2, 1)
    # A flagged step still drives the trajectory's closing status.
    assert result.status == "flagged"


def test_a_failure_mid_run_still_closes_the_trajectory(ledger):
    """An abandoned open trajectory sits in Coriqo as permanently in-progress
    and blocks its parent from ever completing. Since callers typically log and
    carry on, nothing else would come back to close it."""
    _seal_run(ledger, "run_1", [f"tool_{i}" for i in range(MAX_TRACE_BATCH + 5)])
    completions = []
    batches = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal batches
        path = request.url.path
        if path.endswith("/trajectories"):
            return httpx.Response(201, json={"trajectory_id": "traj-1"})
        if path.endswith("/complete"):
            completions.append(json.loads(request.content))
            return httpx.Response(200, json={})
        batches += 1
        if batches == 2:
            return httpx.Response(422, json={"detail": "batch 2 rejected"})
        return httpx.Response(201, json={"recorded": MAX_TRACE_BATCH, "flagged": 0, "traces": []})

    with _client(handler) as client:
        with pytest.raises(CoriqoAgentsError):
            publish_session(
                client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_1"
            )

    assert completions == [{"status": "flagged"}], "the open trajectory was not closed"


def test_a_cleanup_failure_does_not_mask_the_real_error(ledger):
    """The completion attempt runs while a real failure is propagating, so its
    own error must not replace the one the caller needs to see."""
    _seal_run(ledger, "run_1", ["a"])

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/trajectories"):
            return httpx.Response(201, json={"trajectory_id": "traj-1"})
        if path.endswith("/complete"):
            return httpx.Response(500, json={"detail": "cleanup also broke"})
        return httpx.Response(422, json={"detail": "the real failure"})

    with _client(handler) as client:
        with pytest.raises(CoriqoAgentsError) as excinfo:
            publish_session(
                client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_1"
            )
    assert excinfo.value.status_code == 422
    assert "the real failure" in excinfo.value.detail


def test_a_rejected_batch_raises_rather_than_reporting_partial_success(ledger):
    """Coriqo records none of a rejected batch, so reporting anything else
    would claim evidence that isn't there."""
    _seal_run(ledger, "run_1", ["a", "b"])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/trajectories"):
            return httpx.Response(201, json={"trajectory_id": "traj-1"})
        return httpx.Response(
            422, json={"detail": "Decision 1 of 2 was rejected, so none were recorded"}
        )

    with _client(handler) as client:
        with pytest.raises(CoriqoAgentsError) as excinfo:
            publish_session(
                client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_1"
            )
    assert excinfo.value.status_code == 422


def test_a_suspended_agent_raises(ledger):
    _seal_run(ledger, "run_1", ["a"])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/trajectories"):
            return httpx.Response(201, json={"trajectory_id": "traj-1"})
        return httpx.Response(423, json={"detail": "agent suspended by governance"})

    with _client(handler) as client:
        with pytest.raises(AgentSuspendedError):
            publish_session(
                client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_1"
            )


def test_publish_session_raises_if_the_trajectory_cannot_be_opened(ledger):
    _seal_run(ledger, "run_1", ["a"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"detail": "agent has no mandate version yet"})

    with _client(handler) as client:
        with pytest.raises(CoriqoAgentsError) as excinfo:
            publish_session(
                client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_1"
            )
    assert excinfo.value.status_code == 409


def test_a_trajectory_response_without_an_id_raises_instead_of_a_keyerror(ledger):
    """The module promises a Coriqo problem never escapes as something a
    caller's `except CoriqoAgentsError` would miss."""
    _seal_run(ledger, "run_1", ["a"])

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"goal": "but no trajectory_id"})

    with _client(handler) as client:
        with pytest.raises(CoriqoAgentsError):
            publish_session(
                client, coriqo_agent_id=_CORIQO_AGENT, ledger=ledger, session_id="run_1"
            )


def test_record_traces_rejects_an_oversized_batch_before_sending(ledger):
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("should not have sent an over-limit batch")

    with _client(handler) as client:
        with pytest.raises(ValueError):
            client.record_traces(_CORIQO_AGENT, [{"step_index": i} for i in range(201)])
        with pytest.raises(ValueError):
            client.record_traces(_CORIQO_AGENT, [])


# -- client error handling -------------------------------------------------


def test_a_network_failure_surfaces_as_a_coriqo_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    with _client(handler) as client:
        with pytest.raises(CoriqoAgentsError) as excinfo:
            client.list_agents()
    assert excinfo.value.status_code is None


def test_a_2xx_with_a_non_json_body_is_still_a_coriqo_error():
    """A proxy or maintenance page intercepting the request isn't a Coriqo
    response — one `except CoriqoAgentsError` should cover it."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>maintenance</html>")

    with _client(handler) as client:
        with pytest.raises(CoriqoAgentsError):
            client.list_agents()


def test_a_caller_supplied_http_client_is_not_closed():
    """Closing a shared client out from under its owner would break its next
    use elsewhere in the process."""
    http_client = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200)))
    client = CoriqoAgentsClient(
        CoriqoCredentials(base_url="https://coriqo.test", api_key="k", tenant_slug="t"),
        http_client=http_client,
    )
    client.close()
    assert not http_client.is_closed
    http_client.close()


# -- third-party enforcement decisions -------------------------------------


def _guardrail_payload(assessments, *, stage="output"):
    """The payload byoai.recorder.bedrock_agent seals for an intervention.

    Built through the real `guardrail_categories`, not by hand: the whole point
    of the `categories` key is that redaction trusts what that function
    guarantees, so a fixture that spelled it independently could drift into
    asserting a guarantee the code no longer makes.
    """
    from byoai.recorder.bedrock_agent import guardrail_categories

    key = "output_assessments" if stage == "output" else "input_assessments"
    return {
        "action": "INTERVENED",
        "stage": stage,
        "bedrock_trace_id": "demo-4",
        "categories": guardrail_categories(assessments),
        key: assessments,
    }


_TOPIC_ASSESSMENT = [{"topicPolicy": {"topics": [{"name": "LegalAdvice", "action": "BLOCKED"}]}}]


def _seal_guardrail(ledger: Ledger, session_id: str, payload=None) -> str:
    entry = ledger.append(
        make_event(
            "dev_test",
            session_id,
            EventKind.GUARDRAIL_INTERVENTION,
            payload=payload if payload is not None else _guardrail_payload(_TOPIC_ASSESSMENT),
            tool_use_id=None,
            tool_name=None,
        )
    )
    assert entry is not None
    return entry.entry_hash


def test_read_external_controls_normalizes_a_guardrail(ledger):
    entry_hash = _seal_guardrail(ledger, "run_1")
    controls = read_external_controls(ledger, "run_1")

    assert len(controls) == 1
    control = controls[0]
    assert control.control_system == GUARDRAIL_CONTROL_SYSTEM
    assert (control.action, control.stage) == ("intervened", "output")
    assert control.categories == [{"policy": "topic", "name": "LegalAdvice", "action": "BLOCKED"}]
    # The anchor is the sealed row's own chain link — Coriqo's idempotency key
    # and what resolves the published row back to its bytes.
    assert control.entry_hash == entry_hash


def test_an_input_side_intervention_is_not_reported_as_an_output_one(ledger):
    """A guardrail stopping the prompt and one stopping the answer mean
    different things to a reviewer."""
    _seal_guardrail(
        ledger,
        "run_1",
        _guardrail_payload(
            [{"topicPolicy": {"topics": [{"name": "InsiderTrading", "action": "BLOCKED"}]}}],
            stage="input",
        ),
    )
    control = read_external_controls(ledger, "run_1")[0]
    assert control.stage == "input"
    assert control.categories == [
        {"policy": "topic", "name": "InsiderTrading", "action": "BLOCKED"}
    ]


def test_tool_steps_and_control_events_never_read_each_other(ledger):
    """A control firing must not arrive as a tool call: Coriqo mandate-checks
    tool calls, so publishing one there would flag the agent for a control
    that worked."""
    _seal_run(ledger, "run_1", ["screen_party"])
    _seal_guardrail(ledger, "run_1")

    assert [s.tool_name for s in read_tool_steps(ledger, "run_1")] == ["screen_party"]
    assert len(read_external_controls(ledger, "run_1")) == 1


def test_publish_session_ships_control_events_after_the_steps(ledger):
    _seal_run(ledger, "run_1", ["screen_party", "lookup"])
    entry_hash = _seal_guardrail(ledger, "run_1")
    seen: dict = {}

    with _client(_batch_handler(seen)) as client:
        result = publish_session(
            client,
            coriqo_agent_id="agent-1",
            ledger=ledger,
            session_id="run_1",
        )

    assert result is not None
    assert result.external_controls == 1
    # Counted apart from `flagged`: one is the agent breaching its mandate, the
    # other is someone else's control firing.
    assert result.flagged == 0 and result.status == "completed"

    posted = seen["controls"][0]
    assert posted["trajectory_id"] == "traj-1"
    control = posted["controls"][0]
    assert control["control_system"] == GUARDRAIL_CONTROL_SYSTEM
    assert control["evidence_ref"] == entry_hash
    assert control["evidence_system"] == GROUNDING_SYSTEM


def test_a_run_with_no_interventions_posts_nothing(ledger):
    _seal_run(ledger, "run_1", ["screen_party"])
    seen: dict = {}
    with _client(_batch_handler(seen)) as client:
        result = publish_session(
            client,
            coriqo_agent_id="agent-1",
            ledger=ledger,
            session_id="run_1",
        )
    assert result is not None and result.external_controls == 0
    assert "controls" not in seen


def test_a_coriqo_too_old_to_know_the_endpoint_does_not_break_the_run(ledger):
    """The endpoint does not exist before migration 0314. A 404 there must not
    turn a fully recorded run into a stranded one — the ledger keeps the
    authoritative copy either way."""
    _seal_run(ledger, "run_1", ["screen_party"])
    _seal_guardrail(ledger, "run_1")
    seen: dict = {}
    inner = _batch_handler(seen)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/external-controls"):
            return httpx.Response(404, json={"detail": "Not Found"})
        return inner(request)

    with _client(handler) as client:
        result = publish_session(
            client,
            coriqo_agent_id="agent-1",
            ledger=ledger,
            session_id="run_1",
        )

    assert result is not None
    assert result.external_controls == 0
    # The run still closed cleanly — that is the whole point.
    assert result.status == "completed"
    assert seen["completions"] == [{"status": "completed"}]


def test_control_events_are_not_grounded_when_grounding_is_off(ledger):
    _seal_run(ledger, "run_1", ["screen_party"])
    _seal_guardrail(ledger, "run_1")
    seen: dict = {}
    with _client(_batch_handler(seen)) as client:
        publish_session(
            client,
            coriqo_agent_id="agent-1",
            ledger=ledger,
            session_id="run_1",
            ground_in_ledger=False,
        )
    control = seen["controls"][0]["controls"][0]
    assert control["evidence_ref"] is None and control["evidence_system"] is None
