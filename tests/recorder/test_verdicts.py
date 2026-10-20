"""Verdict recording and batched shipping.

Everything here runs against a real sqlite ledger and outbox in ``tmp_path``
and an ``httpx.MockTransport``, so no test touches a network or a clock it does
not control. What is being asserted, in one sentence each: the record exists
whether or not Coriqo does, a repeat is legible as a repeat, and nothing that
was captured from a tool's arguments ever leaves the process.
"""

from __future__ import annotations

import json

import httpx
import pytest

from byoai.errors import MandateDeniedError, MandateRunHaltedError
from byoai.recorder.coriqo_agents import CoriqoAgentsError, CoriqoCredentials
from byoai.recorder.coriqo_async import (
    ENFORCEMENT_PREFIX,
    AsyncCoriqoAgentsClient,
    RetryPolicy,
)
from byoai.recorder.delegation import DelegationPolicy, delegated_gate
from byoai.recorder.denial_latch import DenialLatch, use_denial_latch
from byoai.recorder.governed_tool import governed_tool, use_gate
from byoai.recorder.identity import CoriqoIdentity
from byoai.recorder.keys import load_or_create_device_key
from byoai.recorder.ledger import Ledger
from byoai.recorder.mandate import MandateGate, ProposedAction
from byoai.recorder.schema import EVENT_SCHEMA_VERSION_V1, AgentEvent, EventKind, event_digest
from byoai.recorder.verdicts import (
    MAX_VERDICT_BATCH,
    VerdictOutbox,
    VerdictRecorder,
    VerdictShipper,
    ledger_payload,
    use_verdict_recorder,
)

_AGENT = "coriqo-agent-1"
_BASE = "https://coriqo.test"
_BATCH_PATH = f"{ENFORCEMENT_PREFIX}/agents/{_AGENT}/verdicts/batch"


# -- wiring ----------------------------------------------------------------


def _gate(tmp_path, *, tools=("search",), enforcement="enforce", agent_id=_AGENT):
    gate = MandateGate(lambda etag=None: None, agent_id=agent_id)
    gate.apply_snapshot(
        {
            "allowed_tools": list(tools),
            "mandate_version_id": "mv_1",
            "mandate_enforcement": enforcement,
            "enforcement_posture": "fail_closed",
        }
    )
    return gate


@pytest.fixture
def recorder(tmp_path):
    ledger = Ledger(tmp_path / "ledger.db", "dev_test")
    outbox = VerdictOutbox(tmp_path / "verdicts.db")
    rec = VerdictRecorder(ledger=ledger, outbox=outbox, device_id="dev_test")
    yield rec
    ledger.close()
    outbox.close()


def _verdict_events(ledger: Ledger) -> list[dict]:
    return [
        e.event.payload
        for e in ledger.iter_entries()
        if e.event.kind == EventKind.MANDATE_VERDICT.value
    ]


def _device_client(handler, tmp_path, **kwargs) -> AsyncCoriqoAgentsClient:
    key = load_or_create_device_key(tmp_path)
    identity = CoriqoIdentity.from_device(
        base_url=_BASE, device_id=key.device_id, signer=key, tenant_slug="acme_bank"
    )
    return AsyncCoriqoAgentsClient(
        identity,
        tenant_slug="acme_bank",
        http_client=httpx.AsyncClient(
            base_url=_BASE, transport=httpx.MockTransport(handler)
        ),
        sleep=_no_sleep,
        **kwargs,
    )


async def _no_sleep(_delay: float) -> None:
    return None


# -- every verdict kind is recorded ----------------------------------------


def test_allow_flag_and_deny_are_all_recorded(tmp_path, recorder):
    """The denominator matters: 9 denials out of 4,120 calls is a different
    sentence from 9 denials, and only a record that keeps allows can say it."""

    @governed_tool
    def search(q: str) -> str:
        return q

    @governed_tool
    def wire(amount: int) -> int:
        return amount

    with use_verdict_recorder(recorder):
        with use_gate(_gate(tmp_path)):
            search("q")
        # observe: off-mandate but permitted, so it flags rather than blocks
        with use_gate(_gate(tmp_path, enforcement="observe")):
            wire(1)
        with use_gate(_gate(tmp_path)), pytest.raises(MandateDeniedError):
            wire(2)

    recorded = _verdict_events(recorder.ledger)
    assert [(r["tool"], r["verdict"]) for r in recorded] == [
        ("search", "allowed"),
        ("wire", "flagged"),
        ("wire", "blocked"),
    ]
    for row in recorded:
        assert row["mandate_version_id"] == "mv_1"
        assert row["snapshot_age_s"] is not None
        assert row["reason"]
    assert recorder.outbox.pending_count() == 3
    # Every row names its run, allows included — otherwise "9 off-mandate calls
    # out of 4,120" cannot be computed for a run, which is why allows are kept.
    assert all(r["run_id"] and r["principal"] for r in recorded)


def test_recorded_verdicts_carry_the_run_and_step(tmp_path, recorder):
    gate = _gate(tmp_path)
    with use_verdict_recorder(recorder):
        gate_verdict = gate.decide(
            ProposedAction(tool="search", trajectory_id="traj_9", step_index=4)
        )
        recorder.record(gate_verdict, agent_id=_AGENT)

    row = _verdict_events(recorder.ledger)[0]
    assert row["trajectory_id"] == "traj_9"
    assert row["step_index"] == 4


# -- a repeat is not another first denial ----------------------------------


def test_repeat_and_halt_are_distinguishable_from_a_first_denial(tmp_path, recorder):
    @governed_tool
    def wire(amount: int) -> int:
        return amount

    latch = DenialLatch(threshold=3)
    with use_verdict_recorder(recorder), use_denial_latch(latch), use_gate(
        _gate(tmp_path)
    ):
        for _ in range(2):
            with pytest.raises(MandateDeniedError):
                wire(1)
        with pytest.raises(MandateRunHaltedError):
            wire(1)

    rows = _verdict_events(recorder.ledger)
    assert [(r["reason"], r["attempts"], r["latched"], r["halted"]) for r in rows] == [
        ("out_of_scope", 1, False, False),
        ("repeat_denied", 2, True, False),
        ("run_halted", 3, True, True),
    ]
    # All three are blocked, and all three name one run — so "four attempts at
    # one denied tool, then the run halted" is readable off the record.
    assert {r["verdict"] for r in rows} == {"blocked"}
    assert len({r["run_id"] for r in rows}) == 1

    # The reason code is what carries the distinction onto the wire, too.
    shipped = [r["body"] for r in recorder.outbox.rows()]
    assert [r["reason"] for r in shipped] == [
        "out_of_scope",
        "repeat_denied",
        "run_halted",
    ]


# -- Coriqo being down changes nothing about the record --------------------


async def test_a_denial_is_recorded_with_coriqo_unreachable(tmp_path, recorder):
    def handler(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    @governed_tool
    def wire(amount: int) -> int:
        return amount

    with use_verdict_recorder(recorder), use_gate(_gate(tmp_path)):
        with pytest.raises(MandateDeniedError):
            wire(1)

    assert [r["verdict"] for r in _verdict_events(recorder.ledger)] == ["blocked"]

    client = _device_client(handler, tmp_path, retry=RetryPolicy(attempts=2))
    shipper = VerdictShipper(client, recorder.outbox)
    with pytest.raises(CoriqoAgentsError):
        await shipper.ship_once()
    await client.close()

    # Still recorded, still queued: shipping is downstream of the record.
    assert [r["verdict"] for r in _verdict_events(recorder.ledger)] == ["blocked"]
    assert recorder.outbox.pending_count() == 1


async def test_a_shipping_failure_keeps_the_verdict_and_its_batch_key(
    tmp_path, recorder
):
    """A failed batch is resent under the key it already had, so the retry is
    the same batch rather than a second one."""
    seen: list[dict] = []
    fail = {"yes": True}

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        if fail["yes"]:
            return httpx.Response(503, json={"detail": "redeploying"})
        return httpx.Response(200, json={"accepted": len(body["verdicts"])})

    recorder.record(_deny(tmp_path), agent_id=_AGENT)
    client = _device_client(handler, tmp_path, retry=RetryPolicy(attempts=1))
    shipper = VerdictShipper(client, recorder.outbox)

    with pytest.raises(CoriqoAgentsError):
        await shipper.ship_once()
    assert recorder.outbox.pending_count() == 1

    fail["yes"] = False
    result = await shipper.ship_once()
    await client.close()

    assert result is not None and result.accepted == 1
    assert recorder.outbox.pending_count() == 0
    assert seen[0]["batch_key"] == seen[1]["batch_key"]


def _deny(tmp_path):
    gate = _gate(tmp_path)
    return gate.decide(ProposedAction(tool="wire"))


# -- decide() still does no I/O --------------------------------------------


def test_decide_records_nothing_and_touches_no_socket(tmp_path, recorder, monkeypatch):
    """Recording lives at the enforcement seam, not inside the gate. If it ever
    moves, an agent's availability starts depending on a disk and a network,
    which is the property the whole gate design exists to keep."""

    def explode(*_a, **_k):  # pragma: no cover - only runs on a regression
        raise AssertionError("decide() opened a socket")

    monkeypatch.setattr(httpx.Client, "send", explode)
    monkeypatch.setattr(httpx.AsyncClient, "send", explode)

    gate = _gate(tmp_path)
    with use_verdict_recorder(recorder):
        for tool in ("search", "wire", "search"):
            gate.decide(ProposedAction(tool=tool))

    assert _verdict_events(recorder.ledger) == []
    assert recorder.outbox.pending_count() == 0


# -- batching --------------------------------------------------------------


async def test_batches_are_capped_at_two_hundred(tmp_path, recorder):
    sizes: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        sizes.append(len(body["verdicts"]))
        return httpx.Response(200, json={"accepted": len(body["verdicts"])})

    verdict = _deny(tmp_path)
    for _ in range(250):
        recorder.record(verdict, agent_id=_AGENT)

    client = _device_client(handler, tmp_path)
    results = await VerdictShipper(client, recorder.outbox).drain()
    await client.close()

    assert sizes == [MAX_VERDICT_BATCH, 50]
    assert [r.shipped for r in results] == [200, 50]
    assert recorder.outbox.pending_count() == 0


async def test_an_over_cap_batch_is_refused_before_it_is_sent(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("an over-cap batch should never reach the network")

    client = _device_client(handler, tmp_path)
    with pytest.raises(ValueError, match="at most 200"):
        await client.record_verdict_batch(
            _AGENT, verdicts=[{"tool": "t", "verdict": "allowed"}] * 201
        )
    await client.close()


async def test_snapshot_age_goes_out_in_whole_seconds(tmp_path):
    """Coriqo takes ``snapshot_age_s`` as an integer and refuses a fractional
    one with a 422 for the whole batch, which the shipper parks for good. Found
    running coriqo-mcp against a real Coriqo: every batch with a real age was
    lost. Rounded up on the way out; the ledger keeps the exact float."""
    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(201, json={"recorded": 3})

    client = _device_client(handler, tmp_path)
    await client.record_verdict_batch(
        _AGENT,
        verdicts=[
            {"tool": "a", "verdict": "allowed", "snapshot_age_s": 1.4},
            {"tool": "b", "verdict": "allowed", "snapshot_age_s": 0.0},
            {"tool": "c", "verdict": "allowed", "snapshot_age_s": None},
        ],
    )
    await client.close()
    ages = [v["snapshot_age_s"] for v in sent[0]["verdicts"]]
    assert ages == [2, 0, None]
    assert all(type(a) is int for a in ages[:2])


async def test_a_connect_error_names_its_kind(tmp_path):
    """httpx's ConnectError often has an empty message; the operator log used
    to read "request to ... failed: " with nothing after it."""

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("", request=request)

    client = _device_client(handler, tmp_path)
    with pytest.raises(CoriqoAgentsError, match="failed: ConnectError"):
        await client.fetch_mandate(_AGENT)
    await client.close()


async def test_a_reasonless_block_is_refused_before_it_is_sent(tmp_path):
    def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("a reasonless blocked verdict should not be sent")

    client = _device_client(handler, tmp_path)
    with pytest.raises(ValueError, match="needs a reason"):
        await client.record_verdict_batch(
            _AGENT, verdicts=[{"tool": "wire", "verdict": "blocked", "reason": ""}]
        )
    await client.close()


# -- retry, replay, and the one status that is not retried -----------------


async def test_a_409_is_retried_under_the_same_batch_key(tmp_path, recorder):
    """409 there means two copies of one batch raced a unique index and this
    one lost — the server is asking for the retry."""
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        seen.append(body)
        if len(seen) == 1:
            return httpx.Response(409, json={"detail": "batch_key in flight, retry"})
        return httpx.Response(200, json={"accepted": 1})

    recorder.record(_deny(tmp_path), agent_id=_AGENT)
    client = _device_client(handler, tmp_path, retry=RetryPolicy(attempts=3))
    result = await VerdictShipper(client, recorder.outbox).ship_once()
    await client.close()

    assert len(seen) == 2
    assert seen[0]["batch_key"] == seen[1]["batch_key"]
    assert result is not None and result.accepted == 1
    assert recorder.outbox.pending_count() == 0


async def test_a_duplicate_replay_is_treated_as_delivered(tmp_path, recorder):
    """Coriqo replaying a stored result sealed nothing new, so resending it
    again would be the only way to make it wrong."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"duplicate": True, "accepted": 0})

    recorder.record(_deny(tmp_path), agent_id=_AGENT)
    client = _device_client(handler, tmp_path)
    shipper = VerdictShipper(client, recorder.outbox)

    result = await shipper.ship_once()
    assert result is not None and result.duplicate is True
    assert recorder.outbox.pending_count() == 0
    assert await shipper.ship_once() is None
    await client.close()


async def test_a_422_is_not_retried_and_the_batch_is_parked(tmp_path, recorder):
    """A verdict naming another agent's mandate version is a 422. Resending it
    cannot make it true, so the batch stops — but it is parked, not dropped."""
    attempts: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(
            422, json={"detail": "mandate_version_id belongs to another agent"}
        )

    recorder.record(_deny(tmp_path), agent_id=_AGENT)
    client = _device_client(handler, tmp_path, retry=RetryPolicy(attempts=3))
    shipper = VerdictShipper(client, recorder.outbox)

    result = await shipper.ship_once()
    await client.close()

    assert len(attempts) == 1
    assert result is not None and result.rejected is True
    assert recorder.outbox.pending_count() == 0
    parked = recorder.outbox.rows(state="rejected")
    assert len(parked) == 1 and "another agent" in parked[0]["note"]
    # The record itself is untouched by any of this.
    assert len(_verdict_events(recorder.ledger)) == 1


# -- stale mandate versions are surfaced, not rejected ---------------------


async def test_a_stale_snapshot_is_reported_back_to_the_operator(
    tmp_path, recorder, caplog
):
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "accepted": 2,
                "anchor_mandate_version_id": "mv_7",
                "evaluated_mandate_version_ids": ["mv_1", "mv_7"],
                "stale_mandate_version_count": 1,
            },
        )

    verdict = _deny(tmp_path)
    recorder.record(verdict, agent_id=_AGENT)
    recorder.record(verdict, agent_id=_AGENT)

    client = _device_client(handler, tmp_path)
    with caplog.at_level("WARNING"):
        result = await VerdictShipper(client, recorder.outbox).ship_once()
    await client.close()

    assert result is not None
    assert result.stale is True
    assert result.stale_mandate_version_count == 1
    assert result.anchor_mandate_version_id == "mv_7"
    assert "snapshot has drifted" in caplog.text


# -- captured arguments never leave the process ----------------------------


async def test_captured_arguments_are_counted_and_never_shipped(tmp_path, recorder):
    sent: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={"accepted": 1})

    @governed_tool(capture_arguments=True)
    def wire(iban: str, api_key: str) -> str:
        return iban

    with use_verdict_recorder(recorder), use_gate(_gate(tmp_path)):
        with pytest.raises(MandateDeniedError):
            wire("DE89370400440532013000", "sk-live-secret")

    row = _verdict_events(recorder.ledger)[0]
    assert row["arguments_captured"] == 2
    blob = json.dumps(row)
    assert "DE89370400440532013000" not in blob
    assert "sk-live-secret" not in blob
    assert "iban" not in blob  # not even the parameter names

    client = _device_client(handler, tmp_path)
    await VerdictShipper(client, recorder.outbox).ship_once()
    await client.close()

    wire_blob = json.dumps(sent)
    assert "DE89370400440532013000" not in wire_blob
    assert "sk-live-secret" not in wire_blob
    assert set(sent[0]["verdicts"][0]) == {
        "tool",
        "verdict",
        "reason",
        "mandate_version_id",
        "snapshot_age_s",
        "trajectory_id",
        "step_index",
        "decided_at",
    }


# -- the endpoint refuses a static key ------------------------------------


async def test_a_static_api_key_cannot_ship_verdicts(tmp_path):
    from byoai.errors import EnforcementIdentityUnavailableError

    def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("a static key must not reach the enforcement path")

    client = AsyncCoriqoAgentsClient(
        CoriqoIdentity.from_credentials(
            CoriqoCredentials(
                base_url=_BASE, api_key="cq_sa_test", tenant_slug="acme_bank"
            )
        ),
        http_client=httpx.AsyncClient(
            base_url=_BASE, transport=httpx.MockTransport(handler)
        ),
    )
    with pytest.raises(EnforcementIdentityUnavailableError):
        await client.record_verdict_batch(
            _AGENT,
            verdicts=[{"tool": "wire", "verdict": "blocked", "reason": "out_of_scope"}],
        )
    await client.close()


# -- the outbox's own invariants -------------------------------------------


def test_a_claimed_batch_resumes_whole_even_under_a_smaller_limit(recorder, tmp_path):
    """Half of a claimed batch must never ship alone. The other half carries the
    same batch_key, so it would come back ``duplicate: true`` and be marked
    delivered having been sealed nowhere."""
    verdict = _deny(tmp_path)
    for _ in range(10):
        recorder.record(verdict, agent_id=_AGENT)

    first = recorder.outbox.claim(limit=10)
    assert first is not None and len(first) == 10

    # A crash before the answer, then a shipper reconfigured with a smaller cap.
    resumed = recorder.outbox.claim(limit=3)
    assert resumed is not None
    assert resumed.batch_key == first.batch_key
    assert resumed.ids == first.ids


def test_one_batch_never_mixes_two_agents(recorder, tmp_path):
    """The endpoint is addressed per agent, so a batch that spanned two would be
    posting one agent's verdicts to the other's chain."""
    verdict = _deny(tmp_path)
    recorder.record(verdict, agent_id="agent-a")
    recorder.record(verdict, agent_id="agent-b")

    first = recorder.outbox.claim()
    assert first is not None and first.agent_id == "agent-a" and len(first) == 1
    recorder.outbox.mark_shipped(first.ids)

    second = recorder.outbox.claim()
    assert second is not None and second.agent_id == "agent-b"
    assert second.batch_key != first.batch_key


async def test_a_replay_of_a_differently_sized_batch_is_parked(tmp_path, recorder):
    """``duplicate`` means Coriqo holds *a* batch under this key, not that it
    holds these rows. A size mismatch is not something to mark delivered."""

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"duplicate": True, "verdict_count": 7})

    recorder.record(_deny(tmp_path), agent_id=_AGENT)
    client = _device_client(handler, tmp_path)
    result = await VerdictShipper(client, recorder.outbox).ship_once()
    await client.close()

    assert result is not None and result.rejected is True
    assert len(recorder.outbox.rows(state="rejected")) == 1


async def test_a_batch_the_client_refuses_to_build_does_not_starve_the_queue(
    tmp_path, recorder
):
    """A ValueError is the same permanent statement a 422 is, made earlier. Left
    to propagate it would keep the batch claimed forever and every verdict
    behind it would never ship."""

    def handler(_request: httpx.Request) -> httpx.Response:  # pragma: no cover
        raise AssertionError("a batch the client refuses should not be sent")

    class _Reasonless:
        reason = ""
        verdict = "blocked"
        tool = "wire"
        mandate_version_id = "mv_1"
        snapshot_age_s = 0.1
        trajectory_id = None
        step_index = None
        posture = "fail_closed"
        enforcement = "enforce"
        detail = None

    recorder.record(_Reasonless(), agent_id=_AGENT)
    recorder.record(_deny(tmp_path), agent_id=_AGENT)

    client = _device_client(handler, tmp_path)
    shipper = VerdictShipper(client, recorder.outbox, max_batch=1)
    parked = await shipper.ship_once()
    assert parked is not None and parked.rejected is True
    await client.close()

    assert len(recorder.outbox.rows(state="rejected")) == 1
    assert recorder.outbox.pending_count() == 1  # the good one is still shippable


# -- AIR-7b: resource / on_behalf_of captured at record time -----------------


def _delegated_gate(tmp_path, *, tools=("search",)):
    """A child gate running under a delegated (attenuated) scope."""
    parent = MandateGate(lambda etag=None: None, agent_id="agent-parent")
    parent.apply_snapshot(
        {
            "allowed_tools": list(tools) + ["extra_tool"],
            "mandate_version_id": "mv_parent",
            "mandate_enforcement": "enforce",
            "enforcement_posture": "fail_closed",
            "delegation_policy": DelegationPolicy.ATTENUATED,
        }
    )
    child = MandateGate(lambda etag=None: None, agent_id="agent-child")
    child.apply_snapshot(
        {
            "allowed_tools": list(tools),
            "mandate_version_id": "mv_child",
            "mandate_enforcement": "enforce",
            "enforcement_posture": "fail_closed",
        }
    )
    return delegated_gate(parent, child, child_agent_id="agent-child")


def test_a_non_delegated_call_has_an_empty_on_behalf_of(tmp_path, recorder):
    @governed_tool
    def search(q: str) -> str:
        return q

    with use_verdict_recorder(recorder), use_gate(_gate(tmp_path)):
        search("q")

    row = _verdict_events(recorder.ledger)[0]
    assert row["on_behalf_of"] == []
    assert row["resource"] == "search"


def test_a_delegated_calls_on_behalf_of_matches_the_effective_scope_chain(
    tmp_path, recorder
):
    @governed_tool
    def search(q: str) -> str:
        return q

    gate = _delegated_gate(tmp_path)
    assert gate.scope.chain == ("agent-parent", "agent-child")

    with use_verdict_recorder(recorder), use_gate(gate):
        search("q")

    row = _verdict_events(recorder.ledger)[0]
    assert row["on_behalf_of"] == ["agent-parent", "agent-child"]
    assert row["on_behalf_of"] == list(gate.scope.chain), "delegator first"


def test_resource_matches_the_exact_tool_string_checked_against_the_mandate(
    tmp_path, recorder
):
    @governed_tool(name="payments.refund")
    def refund(amount: int) -> int:
        return amount

    with use_verdict_recorder(recorder), use_gate(_gate(tmp_path, tools=("payments.refund",))):
        refund(5)

    row = _verdict_events(recorder.ledger)[0]
    assert row["resource"] == "payments.refund"


def test_an_event_sealed_before_this_packet_still_digests_identically():
    """A v1 row, with no resource/on_behalf_of keys in its payload, must
    reproduce the exact digest it was sealed with — this packet adds new keys
    to *new* payloads only, and never touches an already-written one."""
    payload = {
        "tool": "search",
        "verdict": "allowed",
        "reason": "in_scope",
        "mandate_version_id": "mv_1",
        "snapshot_age_s": 1.0,
        "trajectory_id": None,
        "step_index": None,
        "decided_at": "2026-01-01T00:00:00.000000Z",
        "agent_id": "agent-1",
        "posture": "fail_closed",
        "enforcement": "enforce",
        "detail": None,
        "run_id": "run-1",
        "principal": "agent-1",
        "attempts": None,
        "latched": False,
        "halted": False,
        "arguments_captured": None,
        # deliberately no "resource" / "on_behalf_of" keys: this is what a
        # payload sealed before AIR-7b landed looks like.
    }
    event = AgentEvent(
        schema_version=EVENT_SCHEMA_VERSION_V1,
        event_id="evt_pin",
        device_id="dev_1",
        session_id="mandate",
        seq=1,
        kind=EventKind.MANDATE_VERDICT.value,
        ts_device="2026-01-01T00:00:00.000000Z",
        ts_monotonic_ns=0,
        tool_use_id=None,
        tool_name="search",
        payload=payload,
        payload_hash="sha256:" + "0" * 64,  # not recomputed by event_digest
        model=None,
        provider="coriqo-mandate",
        trace_id="",
        span_id="",
    )
    # Pinned expected digest, computed once against the payload shape above
    # (before AIR-7b existed) and hardcoded here as a regression guard: if this
    # ever changes, something touched what a pre-existing v1 event hashes to.
    assert event_digest(event) == (
        "sha256:82b734d5179f5e156e027ec60c714e608011e61897d8b949d38b4f0603e6b230"
    )


def test_ledger_payload_omits_on_behalf_of_entries_when_scope_is_not_delegated():
    payload = ledger_payload(
        _deny_verdict_stub(),
        agent_id="agent-1",
        effective_scope=None,
    )
    assert payload["on_behalf_of"] == []


def _deny_verdict_stub():
    class _V:
        reason = "out_of_scope"
        verdict = "blocked"
        tool = "wire"
        mandate_version_id = "mv_1"
        snapshot_age_s = 0.1
        trajectory_id = None
        step_index = None
        posture = "fail_closed"
        enforcement = "enforce"
        detail = None

    return _V()
