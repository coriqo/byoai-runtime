"""What the Bedrock model-invocation log reader seals, and how it links a run (W10).

Fixtures are synthetic records built from the AWS record format (see the README beside them).
Each test sweeps them through a fake log source into a real ledger and reads the ledger back.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

from byoai.recorder.bedrock_invocation_log import (
    PROVIDER,
    MemoryLinkIndex,
    deterministic_id,
    normalize,
    parse_record,
)
from byoai.recorder.bedrock_invocation_log_source import STATE_DB_NAME, LogEvent, StateDB, Sweeper
from byoai.recorder.canonical import canonicalize, sha256_hex
from byoai.recorder.extract import PartialEvent
from byoai.recorder.integration import Recorder
from byoai.recorder.redact import PayloadMode
from byoai.recorder.verify import verify_ledger

FIXTURES = Path(__file__).parent / "fixtures" / "bedrock_invocation_log"
LOG_GROUP = "/aws/bedrock/modelinvocations"
ARN = "arn:aws:logs:eu-west-1:111122223333:log-group:/aws/bedrock/modelinvocations"


def lines(*names: str) -> list[str]:
    return [line for name in names for line in (FIXTURES / name).read_text().splitlines() if line]


def ts_ms(line: str) -> int:
    try:
        stamp = json.loads(line).get("timestamp")
    except ValueError:
        stamp = None
    if not stamp:
        return int(datetime.fromisoformat("2026-11-12T08:00:00+00:00").timestamp() * 1000)
    return int(datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp() * 1000)


class FakeSource:
    """A log group holding the given lines; S3 objects by path; every call recorded."""

    def __init__(
        self,
        messages: list[str],
        *,
        s3: dict[str, bytes] | None = None,
        s3_error: str | None = None,
    ) -> None:
        self.log_group = LOG_GROUP
        self.region = "eu-west-1"
        self.messages = messages
        self.s3 = s3 or {}
        self.s3_error = s3_error
        self.windows: list[tuple[int, int]] = []

    def describe(self) -> dict[str, str]:
        return {"arn": ARN, "account_id": "111122223333"}

    def logging_configuration(self) -> dict:
        return {"enabled": True, "cloudwatch": True, "text_delivery": True, "large_data_s3": True}

    def events(self, start_ms: int, end_ms: int):
        self.windows.append((start_ms, end_ms))
        for message in sorted(self.messages, key=ts_ms):
            if start_ms <= ts_ms(message) <= end_ms:
                yield LogEvent(message, ts_ms(message), ts_ms(message) + 2000)

    def read_s3(self, path: str, max_bytes: int) -> bytes:
        from byoai.recorder.bedrock_invocation_log_source import S3ReadError

        if self.s3_error:
            raise S3ReadError(self.s3_error)
        return self.s3[path]


NOW = ts_ms('{"timestamp": "2026-11-12T16:00:00Z"}') / 1000


def sweep(
    tmp_path: Path,
    messages: list[str],
    *,
    mode: PayloadMode = PayloadMode.FULL,
    scope: str = "tool_calls",
    now: float = NOW,
    source: FakeSource | None = None,
    recorder: Recorder | None = None,
    link_gap: int = 60,
) -> tuple[Recorder, dict]:
    recorder = recorder or Recorder(dir=tmp_path, payload_mode=mode)
    state = StateDB(tmp_path / STATE_DB_NAME)
    sweeper = Sweeper(
        recorder=recorder,
        source=source or FakeSource(messages),
        state=state,
        fetch_config=lambda: ({"scope": scope, "link_gap_minutes": link_gap}, "sha"),
        clock=lambda: now,
    )
    status = sweeper.sweep()
    state.close()
    return recorder, status


def entries(recorder: Recorder) -> list:
    return [e for e in recorder.ledger.iter_entries() if e.event.provider == PROVIDER]


def _reader_entries(recorder: Recorder) -> list:
    """Every entry except the recorder's own heartbeats."""
    return [e for e in recorder.ledger.iter_entries() if e.event.kind != "heartbeat"]


def by_kind(recorder: Recorder, kind: str) -> list:
    return [e.event for e in entries(recorder) if e.event.kind == kind]


@pytest.fixture
def recorder(tmp_path):
    r = Recorder(dir=tmp_path, payload_mode=PayloadMode.FULL)
    yield r
    r.close()


def test_a_tool_call_and_its_result_in_the_next_call_seal_into_one_session(tmp_path, recorder):
    sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), recorder=recorder)

    kinds = [e.event.kind for e in entries(recorder)]
    sessions = {e.event.session_id for e in entries(recorder)}

    assert kinds == ["session_start", "message", "tool_use", "tool_result", "message"]
    assert sessions == {"bil_req-A"}


def test_the_result_carries_the_tool_name_of_the_call_it_answers(tmp_path, recorder):
    sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), recorder=recorder)

    result = by_kind(recorder, "tool_result")[0]

    assert result.tool_name == "get_payment_status" and result.payload["linked"] is True


def test_two_tool_calls_in_one_response_each_pair_with_their_own_result(tmp_path, recorder):
    sweep(tmp_path, lines("converse_two_tools_one_response.jsonl"), recorder=recorder)

    uses = {e.tool_use_id for e in by_kind(recorder, "tool_use")}
    results = {e.tool_use_id for e in by_kind(recorder, "tool_result")}

    assert uses == results == {"tooluse_one", "tooluse_two"}
    assert len({e.event.session_id for e in entries(recorder)}) == 1


def test_prompts_and_system_text_are_not_sealed(tmp_path, recorder):
    sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), recorder=recorder)

    sealed = json.dumps([e.event.payload for e in entries(recorder)])

    assert "Can pay_5512 be released?" not in sealed and "You release held payments." not in sealed


def test_a_text_only_call_is_not_sealed_under_tool_call_scope(tmp_path, recorder):
    _, status = sweep(tmp_path, lines("converse_text_only.jsonl"), recorder=recorder)

    assert entries(recorder) == [] and status["counts"]["out_of_scope"] == 1


def test_a_text_only_call_is_sealed_under_all_calls_scope(tmp_path, recorder):
    sweep(tmp_path, lines("converse_text_only.jsonl"), recorder=recorder, scope="all_calls")

    assert [e.event.kind for e in entries(recorder)] == ["session_start", "message"]


def test_interleaved_runs_from_one_role_stay_in_separate_sessions(tmp_path, recorder):
    sweep(tmp_path, lines("converse_parallel_runs_same_role.jsonl"), recorder=recorder)

    sessions = {e.tool_use_id: e.session_id for e in by_kind(recorder, "tool_result")}

    assert sessions == {"tooluse_p1": "bil_req-P1", "tooluse_p2": "bil_req-P2"}


def test_a_result_from_another_caller_does_not_join_the_session(tmp_path, recorder):
    _, status = sweep(tmp_path, lines("converse_other_caller_cites_id.jsonl"), recorder=recorder)

    result = by_kind(recorder, "tool_result")[0]

    assert result.session_id == "bil_req-O2"
    assert result.payload["linked"] is False and result.payload["link_refused"] == "caller"
    assert status["counts"]["links_refused"] == 1


def test_a_result_after_the_link_limit_starts_a_new_session_marked_unlinked(tmp_path, recorder):
    call, answer = lines("converse_tool_round_trip.jsonl")
    sweep(tmp_path, [call], recorder=recorder, now=ts_ms(call) / 1000 + 600)
    late = json.loads(answer)
    late["timestamp"] = "2026-11-12T10:20:00Z"  # 66 minutes after the call; the limit is 60

    sweep(
        tmp_path,
        [call, json.dumps(late)],
        recorder=recorder,
        now=ts_ms(json.dumps(late)) / 1000 + 600,
    )

    result = by_kind(recorder, "tool_result")[0]
    assert result.session_id == "bil_req-B" and result.payload["link_refused"] == "time"


def test_a_result_whose_call_was_never_logged_is_sealed_unlinked_and_the_verifier_reports_an_orphan(
    tmp_path, recorder
):
    _, status = sweep(tmp_path, lines("converse_tool_round_trip.jsonl")[1:], recorder=recorder)
    recorder.checkpointer.flush()

    report = verify_ledger(tmp_path / "ledger.db")

    assert by_kind(recorder, "tool_result")[0].payload["linked"] is False
    assert status["counts"]["results_without_call"] == 1
    assert "tooluse_Q1aZ" in report.orphan_tool_results


def test_a_call_with_no_result_is_reported_not_invented(tmp_path, recorder):
    call = lines("converse_tool_round_trip.jsonl")[0]
    _, waiting = sweep(tmp_path, [call], recorder=recorder, now=ts_ms(call) / 1000 + 600)

    _, given_up = sweep(tmp_path, [call], recorder=recorder, now=ts_ms(call) / 1000 + 6 * 3600)

    assert by_kind(recorder, "tool_result") == []
    assert waiting["counts"]["tool_calls_awaiting_result"] == 1
    assert given_up["counts"]["tool_calls_no_result_in_log"] == 1
    assert given_up["counts"]["tool_calls_awaiting_result"] == 0


def test_sweeping_the_same_window_twice_seals_nothing_new(tmp_path, recorder):
    sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), recorder=recorder)
    first = len(entries(recorder))

    (tmp_path / STATE_DB_NAME).unlink()  # a lost watermark re-reads the whole window
    _, status = sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), recorder=recorder)

    assert len(entries(recorder)) == first and status["counts"]["already_sealed"] == first


@pytest.mark.parametrize("strict", [False, True])
def test_a_resweep_never_writes_a_record_failure_marker(tmp_path, strict):
    recorder = Recorder(dir=tmp_path, payload_mode=PayloadMode.FULL, strict_mode=strict)
    try:
        sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), recorder=recorder)
        (tmp_path / STATE_DB_NAME).unlink()
        sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), recorder=recorder)

        kinds = [e.event.kind for e in recorder.ledger.iter_entries()]
    finally:
        recorder.close()
    assert "record_failure" not in kinds


def test_overlapping_windows_link_a_result_to_a_call_sealed_in_the_previous_sweep(
    tmp_path, recorder
):
    call, result = lines("converse_tool_round_trip.jsonl")
    sweep(tmp_path, [call], recorder=recorder, now=ts_ms(call) / 1000 + 600)

    sweep(tmp_path, [call, result], recorder=recorder, now=ts_ms(result) / 1000 + 600)

    assert by_kind(recorder, "tool_result")[0].session_id == "bil_req-A"


def test_event_ids_are_the_same_on_two_machines_for_the_same_record(tmp_path):
    first, _ = sweep(tmp_path / "one", lines("converse_tool_round_trip.jsonl"))
    second, _ = sweep(tmp_path / "two", lines("converse_tool_round_trip.jsonl"))
    try:
        assert [e.event.event_id for e in entries(first)] == [
            e.event.event_id for e in entries(second)
        ]
    finally:
        first.close()
        second.close()


def test_events_carry_the_log_time_not_the_sweep_time(tmp_path, recorder):
    sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), recorder=recorder)

    assert by_kind(recorder, "tool_use")[0].ts_device.startswith("2026-11-12T09:14:03")


@pytest.mark.parametrize("mode", list(PayloadMode))
def test_every_event_is_marked_with_the_invocation_log_provider(tmp_path, mode):
    recorder, _ = sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), mode=mode)
    try:
        assert {e.event.provider for e in _reader_entries(recorder)} == {PROVIDER}
    finally:
        recorder.close()


def test_payload_hash_commits_to_the_raw_payload_in_every_mode(tmp_path):
    hashes = []
    for mode in PayloadMode:
        recorder, _ = sweep(
            tmp_path / mode.value, lines("converse_tool_round_trip.jsonl"), mode=mode
        )
        hashes.append([e.event.payload_hash for e in entries(recorder)])
        recorder.close()
    assert hashes[0] == hashes[1] == hashes[2]


def test_session_start_names_the_tools_offered_and_the_config_digest(tmp_path, recorder):
    sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), recorder=recorder)

    start = by_kind(recorder, "session_start")[0].payload
    config = json.loads(lines("converse_tool_round_trip.jsonl")[0])["input"]["inputBodyJson"][
        "toolConfig"
    ]

    assert start["tools_offered"] == ["get_payment_status"] and start["tool_choice"] == "auto"
    assert start["tool_config_sha256"] == sha256_hex(canonicalize(config)).split(":", 1)[1]


def test_tools_offered_survive_redacted_mode(tmp_path):
    recorder, _ = sweep(
        tmp_path, lines("converse_tool_round_trip.jsonl"), mode=PayloadMode.REDACTED
    )
    try:
        start = by_kind(recorder, "session_start")[0].payload
    finally:
        recorder.close()
    assert start["tools_offered"] == ["get_payment_status"] and start["source"] == PROVIDER


def test_a_converse_stream_record_seals_the_same_events_as_its_non_stream_twin(tmp_path):
    plain, _ = sweep(tmp_path / "plain", lines("converse_tool_round_trip.jsonl")[:1])
    streamed, _ = sweep(tmp_path / "stream", lines("converse_stream_events.jsonl"))
    try:

        def shape(r):
            return [
                (
                    e.event.kind,
                    e.event.tool_use_id,
                    e.event.payload.get("input"),
                    e.event.payload.get("text"),
                )
                for e in entries(r)
            ]

        assert shape(plain) == shape(streamed)
    finally:
        plain.close()
        streamed.close()


def test_an_unfinished_streamed_tool_block_is_sealed_as_stream_aborted(tmp_path, recorder):
    sweep(tmp_path, lines("converse_stream_aborted.jsonl"), recorder=recorder)

    aborted = by_kind(recorder, "stream_aborted")

    assert len(aborted) == 1 and aborted[0].tool_use_id == "tooluse_Q1aZ"
    assert aborted[0].payload["partial_json"] == '{"payment_'


def test_anthropic_invoke_model_bodies_go_through_the_existing_extractor(tmp_path, recorder):
    sweep(tmp_path, lines("anthropic_invoke_model_tools.jsonl"), recorder=recorder)

    use, result = by_kind(recorder, "tool_use")[0], by_kind(recorder, "tool_result")[0]

    assert (
        use.payload["input"] == {"payment_id": "pay_5512"} and result.session_id == use.session_id
    )
    assert by_kind(recorder, "session_start")[0].payload["tools_offered"] == ["get_payment_status"]


def test_anthropic_streamed_chunks_are_read_like_a_live_stream(tmp_path, recorder):
    sweep(tmp_path, lines("anthropic_invoke_stream.jsonl"), recorder=recorder)

    assert by_kind(recorder, "tool_use")[0].payload["input"] == {"payment_id": "pay_5512"}


def test_a_large_body_is_read_from_s3_when_permitted(tmp_path, recorder):
    import gzip

    body = json.loads(lines("converse_tool_round_trip.jsonl")[0])["input"]["inputBodyJson"]
    path = "s3://sandbox-bucket/bedrock-large/111122223333/req-L1/input.json.gz"
    source = FakeSource(
        lines("large_body_s3.jsonl"), s3={path: gzip.compress(json.dumps(body).encode())}
    )

    sweep(tmp_path, [], recorder=recorder, source=source)

    assert by_kind(recorder, "session_start")[0].payload["tools_offered"] == ["get_payment_status"]


def test_an_unreadable_s3_body_is_counted_and_the_other_side_still_seals(tmp_path, recorder):
    source = FakeSource(lines("large_body_s3.jsonl"), s3_error="access_denied")

    _, status = sweep(tmp_path, [], recorder=recorder, source=source)

    assert status["counts"]["body_in_s3_unread"] == {"access_denied": 1}
    assert [e.tool_use_id for e in by_kind(recorder, "tool_use")] == ["tooluse_L1"]


def test_a_body_dropped_for_size_is_counted_not_guessed(tmp_path, recorder):
    _, status = sweep(tmp_path, lines("large_body_absent.jsonl"), recorder=recorder)

    assert status["counts"]["body_missing_over_100kb"] == 1
    assert by_kind(recorder, "tool_result") == []


def test_non_json_and_foreign_records_are_counted_and_do_not_stop_the_sweep(tmp_path, recorder):
    _, status = sweep(
        tmp_path, lines("mixed_noise.jsonl", "converse_tool_round_trip.jsonl"), recorder=recorder
    )

    counts = status["counts"]
    assert counts["not_json"] == 1 and counts["not_invocation_log"] == 1
    assert sum(counts["unsupported_shape"].values()) == 2
    assert len(by_kind(recorder, "tool_use")) == 1 and status["status"] == "ok"


def test_a_guardrail_intervention_seals_policy_names_only(tmp_path, recorder):
    sweep(tmp_path, lines("error_and_guardrail.jsonl"), recorder=recorder)

    intervention = by_kind(recorder, "guardrail_intervention")[0].payload

    assert intervention["categories"] == [{"policy": "pii", "name": "EMAIL", "action": "BLOCKED"}]
    assert "jane.doe@bank.example" not in json.dumps(intervention)


def test_an_error_record_seals_an_api_error(tmp_path, recorder):
    sweep(tmp_path, lines("error_and_guardrail.jsonl"), recorder=recorder)

    errors = by_kind(recorder, "api_error")

    assert [e.payload["error_code"] for e in errors] == ["ValidationException"]


def test_a_throttled_call_logged_without_bodies_seals_an_api_error(tmp_path, recorder):
    sweep(tmp_path, lines("error_without_body.jsonl"), recorder=recorder)

    errors = by_kind(recorder, "api_error")

    assert [e.payload["error_code"] for e in errors] == ["ThrottlingException"]


def test_partial_event_without_event_id_still_gets_a_random_one(tmp_path, recorder):
    partial = PartialEvent(
        session_id="s",
        kind="message",
        ts_device="2026-11-12T00:00:00.000000Z",
        ts_monotonic_ns=1,
        tool_use_id=None,
        tool_name=None,
        payload={"text": "x"},
        model=None,
    )

    recorder.record(partial)
    recorder.record(partial)

    ids = [e.event.event_id for e in _reader_entries(recorder)]
    assert len(ids) == 2 and len(set(ids)) == 2 and all(i.startswith("evt_") for i in ids)


def test_two_results_without_a_tool_use_id_are_both_kept():
    record = json.loads(lines("converse_tool_round_trip.jsonl")[1])
    record["input"]["inputBodyJson"]["messages"][-1]["content"] = [
        {"toolResult": {"content": [{"text": "a"}]}},
        {"toolResult": {"content": [{"text": "b"}]}},
    ]

    result = normalize(parse_record(json.dumps(record)), index=MemoryLinkIndex())

    ids = [p.event_id for p in result.partials if p.kind == "tool_result"]
    assert len(ids) == 2 and len(set(ids)) == 2


def test_a_stream_chunk_that_does_not_decode_is_counted():
    record = json.loads(lines("anthropic_invoke_stream.jsonl")[0])
    record["output"]["outputBodyJson"].append({"chunk": {"bytes": "not base64 !"}})

    result = normalize(parse_record(json.dumps(record)), index=MemoryLinkIndex())

    assert result.counters.get("stream_chunks_undecodable") == 1


def test_ids_are_derived_from_account_region_request_and_slot():
    record = parse_record(lines("converse_tool_round_trip.jsonl")[0])

    result = normalize(record, index=MemoryLinkIndex())

    start = result.partials[0]
    assert (
        start.event_id
        == "evt_" + deterministic_id("111122223333", "eu-west-1", "req-A", "session_start")[:32]
    )
