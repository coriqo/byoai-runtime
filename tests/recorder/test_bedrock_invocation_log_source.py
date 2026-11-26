"""The Bedrock log reader's sweep, state, AWS calls and the two Coriqo routes it uses (W10).

Fakes only: a fake log source or fake boto-shaped clients, an injected clock, httpx's
MockTransport for Coriqo. No network.
"""

from __future__ import annotations

import gzip
import json
import sqlite3
import threading
import time

import httpx
import pytest

from byoai.recorder.bedrock_invocation_log import IndexedCall
from byoai.recorder.bedrock_invocation_log_source import (
    CAPTURE_CONFIG_PATH,
    CONFIG_DEFAULTS,
    SOURCE_STATE_PATH,
    STATE_DB_NAME,
    AwsLogSource,
    ReaderBusy,
    S3ReadError,
    SourceError,
    StateDB,
    Sweeper,
    config_sha256,
    coriqo_config_fetcher,
    coriqo_status_poster,
    effective_config,
    reader_lock,
)
from byoai.recorder.integration import Recorder
from byoai.recorder.redact import PayloadMode
from byoai.recorder.shipper import Shipper

from .test_bedrock_invocation_log import ARN, NOW, FakeSource, entries, lines, sweep, ts_ms


@pytest.fixture
def recorder(tmp_path):
    r = Recorder(dir=tmp_path, payload_mode=PayloadMode.FULL)
    yield r
    r.close()


def make_sweeper(
    tmp_path, recorder, source, *, fetch=None, posted=None, now=NOW
) -> tuple[Sweeper, StateDB]:
    state = StateDB(tmp_path / STATE_DB_NAME)
    sweeper = Sweeper(
        recorder=recorder,
        source=source,
        state=state,
        fetch_config=fetch,
        post_status=posted.append if posted is not None else None,
        clock=lambda: now,
    )
    return sweeper, state


# -- the sweep ----------------------------------------------------------------------------


def test_the_watermark_moves_only_after_every_record_is_sealed(tmp_path, recorder, monkeypatch):
    sweeper, state = make_sweeper(
        tmp_path, recorder, FakeSource(lines("converse_tool_round_trip.jsonl"))
    )

    def fail(_partials):
        raise RuntimeError("disk full")

    monkeypatch.setattr(recorder, "record_many", fail)
    status = sweeper.sweep()

    assert (status["status"], status["reason"]) == ("error", "reader_error")
    assert state.watermark(ARN) is None
    state.close()


def test_a_crash_mid_sweep_resumes_without_duplicates(tmp_path, recorder, monkeypatch):
    messages = lines("converse_tool_round_trip.jsonl")
    sweeper, state = make_sweeper(tmp_path, recorder, FakeSource(messages))
    real = recorder.record_many

    def half_then_crash(partials):
        real(partials[:2])
        raise RuntimeError("killed")

    monkeypatch.setattr(recorder, "record_many", half_then_crash)
    assert sweeper.sweep()["status"] == "error"
    monkeypatch.setattr(recorder, "record_many", real)
    state.close()

    sweep(tmp_path, messages, recorder=recorder)

    ids = [e.event.event_id for e in entries(recorder)]
    assert len(ids) == len(set(ids)) == 5


def test_a_refused_log_read_ends_in_a_posted_status(tmp_path, recorder):
    class Denied(Exception):
        response = {"Error": {"Code": "AccessDeniedException"}}

    class Logs:
        def describe_log_groups(self, **_kw):
            return {"logGroups": [{"logGroupName": "/g", "arn": ARN}]}

        def filter_log_events(self, **_kw):
            raise Denied()

    posted: list[dict] = []
    source = AwsLogSource(log_group="/g", region="eu-west-1", logs=Logs())
    sweeper, state = make_sweeper(tmp_path, recorder, source, posted=posted)

    status = sweeper.sweep()

    assert (status["status"], status["reason"]) == ("error", "access_denied_logs")
    assert posted == [status]
    state.close()


def test_a_record_that_cannot_be_read_does_not_hold_the_watermark(tmp_path, recorder):
    bad = json.loads(lines("converse_tool_round_trip.jsonl")[0])
    bad["requestId"] = "req-bad"
    bad["input"]["inputBodyJson"]["toolConfig"]["tools"] = [{"toolSpec": "not an object"}]
    messages = [json.dumps(bad), *lines("converse_tool_round_trip.jsonl")]
    sweeper, state = make_sweeper(tmp_path, recorder, FakeSource(messages))

    status = sweeper.sweep()

    assert status["status"] == "ok" and status["counts"]["record_failed"] == 1
    assert state.watermark(ARN) is not None
    state.close()


def test_a_lost_state_file_is_reported_on_the_first_sweep_only(tmp_path, recorder):
    earlier = tmp_path / "earlier"
    earlier.mkdir()
    sweep(earlier, lines("converse_tool_round_trip.jsonl"), recorder=recorder)
    sweeper, state = make_sweeper(tmp_path, recorder, FakeSource([]))

    first, second = sweeper.sweep()["reason"], sweeper.sweep()["reason"]

    assert (first, second) == ("state_recreated", None)
    state.close()


def test_a_lost_state_file_outranks_a_warning(tmp_path, recorder):
    earlier = tmp_path / "earlier"
    earlier.mkdir()
    sweep(earlier, lines("converse_tool_round_trip.jsonl"), recorder=recorder)
    sweeper, state = make_sweeper(
        tmp_path, recorder, FakeSource([]), fetch=lambda: ({"paused": True}, "s")
    )

    status = sweeper.sweep()

    assert (status["status"], status["reason"]) == ("paused", "state_recreated")
    state.close()


def test_a_lost_state_file_is_reported_after_a_failed_first_sweep(tmp_path, recorder):
    earlier = tmp_path / "earlier"
    earlier.mkdir()
    sweep(earlier, lines("converse_tool_round_trip.jsonl"), recorder=recorder)

    class Unreachable(FakeSource):
        def describe(self):
            raise SourceError("log_group_not_found")

    sweeper, state = make_sweeper(tmp_path, recorder, Unreachable([]))
    first = sweeper.sweep()
    sweeper.source = FakeSource([])
    second = sweeper.sweep()

    assert (first["reason"], second["reason"]) == ("log_group_not_found", "state_recreated")
    state.close()


def test_a_lost_state_file_is_reported_again_when_its_status_was_not_delivered(
    tmp_path, recorder
):
    earlier = tmp_path / "earlier"
    earlier.mkdir()
    sweep(earlier, lines("converse_tool_round_trip.jsonl"), recorder=recorder)
    delivered: list[dict] = []
    attempts = iter([False, True])

    def post(status: dict) -> None:
        if not next(attempts):
            raise httpx.ConnectError("Coriqo unreachable")
        delivered.append(status)

    state = StateDB(tmp_path / STATE_DB_NAME)
    sweeper = Sweeper(
        recorder=recorder, source=FakeSource([]), state=state, post_status=post, clock=lambda: NOW
    )
    sweeper.sweep()
    sweeper.sweep()

    assert [s["reason"] for s in delivered] == ["state_recreated"]
    state.close()


def test_settings_that_cannot_be_cached_end_in_a_posted_status(tmp_path, recorder, monkeypatch):
    posted: list[dict] = []
    sweeper, state = make_sweeper(
        tmp_path, recorder, FakeSource([]), posted=posted, fetch=lambda: ({}, "s")
    )

    def broken(*_args):
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(state, "cache_config", broken)
    status = sweeper.sweep()

    assert (status["status"], status["reason"]) == ("error", "reader_error")
    assert posted == [status]
    state.close()


def test_a_record_scope_undoes_its_index_writes_when_it_fails(tmp_path):
    state = StateDB(tmp_path / STATE_DB_NAME)
    call = IndexedCall(
        tool_use_id="tu_1", account="111122223333", region="eu-west-1", principal="p",
        ts_ms=1, request_id="r", session_id="s", trace_id="t", span_id="sp", tool_name="x",
    )

    with pytest.raises(ValueError), state.record_scope():
        state.put(call)
        raise ValueError("bad record")

    assert state.get("tu_1") is None
    state.close()


def test_a_window_older_than_catch_up_is_declared_as_a_gap(tmp_path, recorder):
    posted: list[dict] = []
    sweeper, state = make_sweeper(
        tmp_path,
        recorder,
        FakeSource([]),
        posted=posted,
        fetch=lambda: ({"first_backfill_hours": 720, "max_catchup_hours": 24}, "s"),
    )

    status = sweeper.sweep()

    assert len(status["gaps"]) == 1 and posted[0]["gaps"] == status["gaps"]
    state.close()


def test_throttling_retries_then_reports_without_moving_the_watermark(tmp_path, recorder):
    class Throttled(Exception):
        response = {"Error": {"Code": "ThrottlingException"}}

    class Logs:
        calls = 0

        def describe_log_groups(self, **_kw):
            return {
                "logGroups": [{"logGroupName": "/aws/bedrock/modelinvocations", "arn": ARN + ":*"}]
            }

        def filter_log_events(self, **_kw):
            Logs.calls += 1
            raise Throttled()

    sleeps: list[float] = []
    source = AwsLogSource(
        log_group="/aws/bedrock/modelinvocations",
        region="eu-west-1",
        logs=Logs(),
        sleep=sleeps.append,
    )
    sweeper, state = make_sweeper(tmp_path, recorder, source)

    status = sweeper.sweep()

    assert status["status"] == "error" and status["reason"] == "throttled"
    assert Logs.calls == 5 and len(sleeps) == 4 and sleeps[1] > sleeps[0] / 2
    assert state.watermark(ARN) is None
    state.close()


def test_paused_setting_reads_nothing_and_reports_paused(tmp_path, recorder):
    source = FakeSource(lines("converse_tool_round_trip.jsonl"))
    sweeper, state = make_sweeper(tmp_path, recorder, source, fetch=lambda: ({"paused": True}, "s"))

    status = sweeper.sweep()

    assert status["status"] == "paused" and source.windows == [] and entries(recorder) == []
    state.close()


def test_settings_from_coriqo_are_used_and_cached_when_coriqo_is_unreachable(tmp_path, recorder):
    sweeper, state = make_sweeper(
        tmp_path, recorder, FakeSource([]), fetch=lambda: ({"scope": "all_calls"}, "s")
    )
    assert sweeper.config() == ({**CONFIG_DEFAULTS, "scope": "all_calls"}, "coriqo")

    def unreachable():
        raise httpx.ConnectError("down")

    sweeper._fetch_config = unreachable

    config, origin = sweeper.config()
    status = sweeper.sweep()

    assert (config["scope"], origin) == ("all_calls", "cache")
    assert status["config_source"] == "cache" and status["reason"] == "config_unreachable"
    state.close()


def test_with_no_coriqo_and_no_cache_coriqos_defaults_apply(tmp_path, recorder):
    sweeper, state = make_sweeper(tmp_path, recorder, FakeSource([]))

    assert sweeper.config() == (CONFIG_DEFAULTS, "defaults")
    state.close()


def test_an_out_of_bounds_value_keeps_the_default():
    assert (
        effective_config({"interval_minutes": 0, "scope": "everything", "paused": "yes"})
        == CONFIG_DEFAULTS
    )


def test_status_is_posted_after_an_empty_sweep(tmp_path, recorder):
    posted: list[dict] = []
    sweeper, state = make_sweeper(tmp_path, recorder, FakeSource([]), posted=posted)

    sweeper.sweep()

    assert len(posted) == 1
    status = posted[0]
    assert status["kind"] == "bedrock_invocation_log" and status["status"] == "ok"
    assert status["counts"]["records_read"] == 0 and status["config_sha256"] == config_sha256(
        CONFIG_DEFAULTS
    )
    assert (
        status["log_group"] == "/aws/bedrock/modelinvocations" and status["payload_mode"] == "full"
    )
    state.close()


def test_a_lost_state_db_is_reported_as_recreated(tmp_path, recorder):
    sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), recorder=recorder)
    (tmp_path / STATE_DB_NAME).unlink()

    _, status = sweep(tmp_path, [], recorder=recorder)

    assert status["reason"] == "state_recreated"


def test_a_second_reader_on_the_same_directory_refuses_to_start(tmp_path):
    with reader_lock(tmp_path), pytest.raises(ReaderBusy), reader_lock(tmp_path):
        pass


def test_once_mode_drains_all_sealed_events_before_exit(tmp_path, recorder):
    sweep(tmp_path, lines("converse_tool_round_trip.jsonl"), recorder=recorder)
    recorder._shipper = object()  # enrolled: something ships in the background
    last = recorder.ledger.next_seq - 1

    def ship_later():
        time.sleep(0.3)
        recorder.ledger.set_synced_up_to(last)
        recorder.ledger.set_synced_checkpoint_up_to(recorder.ledger.latest_checkpoint()["seq_end"])

    threading.Thread(target=ship_later).start()

    assert recorder.drain(5.0) is True
    recorder._shipper = None


def test_drain_says_so_when_the_device_is_not_enrolled(recorder):
    assert recorder.drain(0.1) is False


# -- AWS -----------------------------------------------------------------------------------


class _Body:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def read(self, n: int) -> bytes:
        return self.data[:n]


def test_filter_log_events_is_paged_until_the_token_stops():
    class Logs:
        def __init__(self):
            self.seen: list[dict] = []

        def filter_log_events(self, **kw):
            self.seen.append(kw)
            if "nextToken" not in kw:
                return {
                    "events": [{"message": "a", "timestamp": 1, "ingestionTime": 3}],
                    "nextToken": "t1",
                }
            return {"events": [{"message": "b", "timestamp": 2}]}

    logs = Logs()
    source = AwsLogSource(log_group="/g", region="eu-west-1", logs=logs)

    got = [e.message for e in source.events(0, 10)]

    assert (
        got == ["a", "b"]
        and logs.seen[0]["logGroupName"] == "/g"
        and logs.seen[1]["nextToken"] == "t1"
    )


def test_a_log_group_arn_is_read_with_its_identifier():
    class Logs:
        kw: dict = {}

        def filter_log_events(self, **kw):
            Logs.kw = kw
            return {"events": []}

    list(AwsLogSource(log_group=ARN, region="eu-west-1", logs=Logs()).events(0, 1))

    assert Logs.kw["logGroupIdentifier"] == ARN and "logGroupName" not in Logs.kw


def test_a_missing_or_refused_log_group_is_a_named_reason():
    class Denied(Exception):
        response = {"Error": {"Code": "AccessDeniedException"}}

    class Logs:
        def describe_log_groups(self, **_kw):
            raise Denied()

    class Empty:
        def describe_log_groups(self, **_kw):
            return {"logGroups": []}

    with pytest.raises(SourceError) as denied:
        AwsLogSource(log_group="/g", region="r", logs=Logs()).describe()
    with pytest.raises(SourceError) as missing:
        AwsLogSource(log_group="/g", region="r", logs=Empty()).describe()

    assert (denied.value.reason, missing.value.reason) == (
        "access_denied_logs",
        "log_group_not_found",
    )


def test_an_s3_body_over_the_cap_is_refused_before_it_is_read():
    class S3:
        def get_object(self, **_kw):
            return {"ContentLength": 11, "Body": _Body(b"x" * 11)}

    with pytest.raises(S3ReadError) as over:
        AwsLogSource(log_group="/g", region="r", logs=None, s3=S3()).read_s3("s3://b/k", 10)

    assert over.value.reason == "over_cap"


def test_logging_configuration_without_the_permission_reads_unknown():
    class Denied(Exception):
        response = {"Error": {"Code": "AccessDeniedException"}}

    class Bedrock:
        def get_model_invocation_logging_configuration(self):
            raise Denied()

    assert (
        AwsLogSource(
            log_group="/g", region="r", logs=None, bedrock=Bedrock()
        ).logging_configuration()
        == "unknown"
    )


# -- the two Coriqo routes ------------------------------------------------------------------------


def test_capture_config_is_a_device_signed_get_with_the_tenant(recorder):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"bedrock_log": {"scope": "all_calls"}, "sha256": "abc"})

    fetch = coriqo_config_fetcher(
        base_url="https://coriqo.test",
        tenant_slug="acme",
        signer=recorder.key,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )

    values, sha = fetch()

    assert (values, sha) == ({"scope": "all_calls"}, "abc")
    request = seen[0]
    assert request.method == "GET" and request.url.path == CAPTURE_CONFIG_PATH
    assert request.headers["X-Tenant-Slug"] == "acme"
    assert any(h.lower().startswith("x-coriqo-") and "sig" in h.lower() for h in request.headers)


def test_the_status_block_is_posted_signed_with_device_and_sent_at(tmp_path, recorder):
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == SOURCE_STATE_PATH and request.headers["x-coriqo-signature"]
        bodies.append(json.loads(gzip.decompress(request.content)))
        return httpx.Response(200, json={"ok": True})

    recorder._shipper = Shipper(
        recorder.ledger,
        recorder.key,
        coriqo_base_url="https://coriqo.test",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    try:
        sweeper, state = make_sweeper(tmp_path, recorder, FakeSource([]))
        sweeper._post_status = coriqo_status_poster(recorder)
        sweeper.sweep()
        state.close()
    finally:
        recorder._shipper.close()
        recorder._shipper = None

    body = bodies[0]
    assert set(body) == {"device_id", "sent_at", "source_state"}
    assert body["device_id"] == recorder.key.device_id and body["sent_at"].endswith("Z")
    assert body["source_state"]["kind"] == "bedrock_invocation_log"


def test_a_record_inside_the_window_is_read_once_per_sweep(tmp_path, recorder):
    source = FakeSource(lines("converse_tool_round_trip.jsonl"))

    sweep(tmp_path, [], recorder=recorder, source=source)

    ((start, end),) = source.windows
    assert end < NOW * 1000 and start <= ts_ms(lines("converse_tool_round_trip.jsonl")[0])
