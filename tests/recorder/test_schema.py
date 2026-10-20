"""Tests for the recorder event schema."""

from __future__ import annotations

import dataclasses
import re
import time
from datetime import datetime, timezone

import pytest

from byoai.recorder.canonical import canonicalize, sha256_hex
from byoai.recorder.schema import (
    EVENT_SCHEMA_VERSION,
    EVENT_SCHEMA_VERSION_V1,
    AgentEvent,
    EventKind,
    event_digest,
    new_event_id,
    new_span_id,
    new_trace_id,
    now_monotonic_ns,
    now_ts_device,
)

RFC3339_MICROS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")


def make_event(**overrides: object) -> AgentEvent:
    base: dict[str, object] = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": "evt_" + "0" * 32,
        "device_id": "dev_01HQ",
        "session_id": "ses_01HQ",
        "seq": 4471,
        "kind": EventKind.TOOL_USE.value,
        "ts_device": "2026-08-05T14:22:31.442123Z",
        "ts_monotonic_ns": 123456789012345,
        "tool_use_id": "toolu_01ABC",
        "tool_name": "Bash",
        "payload": {"command": "ls -la", "cwd": "/tmp"},
        "payload_hash": "sha256:" + "9f" * 32,
        "model": "claude-opus-5",
        "provider": "anthropic",
        "trace_id": "tr_" + "1" * 32,
        "span_id": "sp_" + "2" * 32,
        "parent_span_id": None,
        "continues_from": None,
    }
    base.update(overrides)
    return AgentEvent(**base)  # type: ignore[arg-type]


def make_v1_event(**overrides: object) -> AgentEvent:
    """A legacy pre-trace-attribution event, as if loaded off a v1 ledger row."""
    base: dict[str, object] = {
        "schema_version": EVENT_SCHEMA_VERSION_V1,
        "event_id": "evt_" + "0" * 32,
        "device_id": "dev_01HQ",
        "session_id": "ses_01HQ",
        "seq": 4471,
        "kind": EventKind.TOOL_USE.value,
        "ts_device": "2026-08-05T14:22:31.442123Z",
        "ts_monotonic_ns": 123456789012345,
        "tool_use_id": "toolu_01ABC",
        "tool_name": "Bash",
        "payload": {"command": "ls -la", "cwd": "/tmp"},
        "payload_hash": "sha256:" + "9f" * 32,
        "model": "claude-opus-5",
        "provider": "anthropic",
        # Legacy rows carry placeholder trace/span values (see ledger.py's
        # _row_to_entry) — never observable via to_dict()/the digest.
        "trace_id": "",
        "span_id": "",
        "parent_span_id": None,
        "continues_from": None,
    }
    base.update(overrides)
    return AgentEvent(**base)  # type: ignore[arg-type]


class TestEventKind:
    def test_is_a_str_enum(self) -> None:
        assert EventKind.TOOL_USE == "tool_use"
        assert EventKind("tool_result") is EventKind.TOOL_RESULT

    def test_covers_the_contract_kinds(self) -> None:
        assert {k.value for k in EventKind} == {
            "tool_use",
            "tool_result",
            "message",
            "api_error",
            "record_failure",
            "session_start",
            "key_rotated",
            "stream_aborted",
            "parse_failure",
            "mandate_verdict",
            # Added with the Bedrock Agent seam: a third party's guardrail
            # firing mid-run is neither our verdict nor a failure.
            "guardrail_intervention",
            # TI-25: a worker acknowledging a suspension (hook or process).
            "worker_stop_ack",
        }


class TestAgentEvent:
    def test_schema_version_constant(self) -> None:
        assert EVENT_SCHEMA_VERSION == "2"
        assert EVENT_SCHEMA_VERSION_V1 == "1"
        assert make_event().schema_version == "2"

    def test_is_frozen(self) -> None:
        event = make_event()
        with pytest.raises(dataclasses.FrozenInstanceError):
            event.seq = 5  # type: ignore[misc]

    def test_uses_slots(self) -> None:
        event = make_event()
        assert not hasattr(event, "__dict__")
        assert AgentEvent.__slots__
        # No per-instance dict means undeclared attributes cannot be attached.
        with pytest.raises((AttributeError, TypeError, dataclasses.FrozenInstanceError)):
            event.extra = 1  # type: ignore[attr-defined]

    def test_field_order_matches_the_contract(self) -> None:
        assert [f.name for f in dataclasses.fields(AgentEvent)] == [
            "schema_version",
            "event_id",
            "device_id",
            "session_id",
            "seq",
            "kind",
            "ts_device",
            "ts_monotonic_ns",
            "tool_use_id",
            "tool_name",
            "payload",
            "payload_hash",
            "model",
            "provider",
            "trace_id",
            "span_id",
            "parent_span_id",
            "continues_from",
        ]

    def test_optional_fields_accept_none(self) -> None:
        event = make_event(tool_use_id=None, tool_name=None, model=None)
        assert event.tool_use_id is None
        assert event.to_dict()["model"] is None


class TestRoundTrip:
    def test_to_dict_from_dict(self) -> None:
        event = make_event()
        assert AgentEvent.from_dict(event.to_dict()) == event

    def test_to_dict_is_json_shaped(self) -> None:
        data = make_event().to_dict()
        assert data["kind"] == "tool_use"
        assert data["payload"] == {"command": "ls -la", "cwd": "/tmp"}
        assert canonicalize(data)  # canonicalizable without a custom encoder

    def test_from_dict_rejects_missing_field(self) -> None:
        data = make_event().to_dict()
        del data["provider"]
        with pytest.raises(ValueError, match="missing event fields"):
            AgentEvent.from_dict(data)

    def test_from_dict_rejects_unknown_field(self) -> None:
        data = make_event().to_dict()
        data["witness"] = "kernel"
        with pytest.raises(ValueError, match="unknown event fields"):
            AgentEvent.from_dict(data)

    def test_from_dict_ignores_key_order(self) -> None:
        event = make_event()
        shuffled = dict(reversed(list(event.to_dict().items())))
        assert AgentEvent.from_dict(shuffled) == event


class TestEventDigest:
    def test_prefixed_sha256(self) -> None:
        digest = event_digest(make_event())
        assert digest.startswith("sha256:")
        assert len(digest) == len("sha256:") + 64

    def test_matches_canonical_hash(self) -> None:
        event = make_event()
        assert event_digest(event) == sha256_hex(canonicalize(event.to_dict()))

    def test_deterministic_across_payload_key_order(self) -> None:
        a = make_event(payload={"b": 1, "a": {"y": 2, "x": 3}})
        b = make_event(payload={"a": {"x": 3, "y": 2}, "b": 1})
        assert event_digest(a) == event_digest(b)

    def test_deterministic_across_construction_order(self) -> None:
        event = make_event()
        rebuilt = AgentEvent.from_dict(dict(reversed(list(event.to_dict().items()))))
        assert event_digest(rebuilt) == event_digest(event)

    def test_changes_when_any_field_changes(self) -> None:
        baseline = event_digest(make_event())
        for field, value in (
            ("seq", 4472),
            ("kind", "tool_result"),
            ("tool_name", "Write"),
            ("payload", {"command": "rm -rf /"}),
            ("ts_device", "2026-08-05T14:22:31.442124Z"),
            ("ts_monotonic_ns", 123456789012346),
            ("model", None),
        ):
            assert event_digest(make_event(**{field: value})) != baseline

    def test_stable_value_is_pinned_v2(self) -> None:
        """A fixed v2 event hashes to a fixed digest — a third party must be
        able to reproduce this without running our code. Trace fields are
        included in the preimage for v2."""
        expected = sha256_hex(
            canonicalize(
                {
                    "schema_version": "2",
                    "event_id": "evt_" + "0" * 32,
                    "device_id": "dev_01HQ",
                    "session_id": "ses_01HQ",
                    "seq": 4471,
                    "kind": "tool_use",
                    "ts_device": "2026-08-05T14:22:31.442123Z",
                    "ts_monotonic_ns": 123456789012345,
                    "tool_use_id": "toolu_01ABC",
                    "tool_name": "Bash",
                    "payload": {"command": "ls -la", "cwd": "/tmp"},
                    "payload_hash": "sha256:" + "9f" * 32,
                    "model": "claude-opus-5",
                    "provider": "anthropic",
                    "trace_id": "tr_" + "1" * 32,
                    "span_id": "sp_" + "2" * 32,
                    "parent_span_id": None,
                    "continues_from": None,
                }
            )
        )
        assert event_digest(make_event()) == expected

    def test_stable_value_is_pinned_v1(self) -> None:
        """A fixed pre-migration (v1) event hashes to exactly the digest it
        would have gotten before trace attribution existed — no trace fields
        anywhere in the preimage, even though the AgentEvent object now has
        those attributes. This is what makes re-verifying an old ledger row
        after the v2 migration still work (see verify.py)."""
        expected = sha256_hex(
            canonicalize(
                {
                    "schema_version": "1",
                    "event_id": "evt_" + "0" * 32,
                    "device_id": "dev_01HQ",
                    "session_id": "ses_01HQ",
                    "seq": 4471,
                    "kind": "tool_use",
                    "ts_device": "2026-08-05T14:22:31.442123Z",
                    "ts_monotonic_ns": 123456789012345,
                    "tool_use_id": "toolu_01ABC",
                    "tool_name": "Bash",
                    "payload": {"command": "ls -la", "cwd": "/tmp"},
                    "payload_hash": "sha256:" + "9f" * 32,
                    "model": "claude-opus-5",
                    "provider": "anthropic",
                }
            )
        )
        assert event_digest(make_v1_event()) == expected

    def test_v1_to_dict_omits_trace_fields(self) -> None:
        d = make_v1_event().to_dict()
        assert "trace_id" not in d
        assert "span_id" not in d
        assert "parent_span_id" not in d
        assert "continues_from" not in d

    def test_v1_digest_unaffected_by_placeholder_trace_values(self) -> None:
        """Different in-memory placeholder trace/span values on a v1 event
        must not change its digest — they are never part of the preimage."""
        a = make_v1_event(trace_id="", span_id="")
        b = make_v1_event(trace_id=new_trace_id(), span_id=new_span_id())
        assert event_digest(a) == event_digest(b)

    def test_v2_digest_changes_when_trace_id_changes(self) -> None:
        baseline = event_digest(make_event())
        assert event_digest(make_event(trace_id="tr_" + "9" * 32)) != baseline

    def test_v2_digest_changes_when_parent_span_id_changes(self) -> None:
        baseline = event_digest(make_event())
        assert event_digest(make_event(parent_span_id="sp_" + "9" * 32)) != baseline


class TestIdsAndClocks:
    def test_event_id_shape(self) -> None:
        event_id = new_event_id()
        assert re.fullmatch(r"evt_[0-9a-f]{32}", event_id)

    def test_event_ids_are_unique(self) -> None:
        assert len({new_event_id() for _ in range(1000)}) == 1000

    def test_ts_device_is_rfc3339_utc_micros(self) -> None:
        ts = now_ts_device()
        assert RFC3339_MICROS.fullmatch(ts), ts

    def test_ts_device_parses_back_to_now(self) -> None:
        ts = now_ts_device()
        parsed = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
            tzinfo=timezone.utc
        )
        delta = abs((datetime.now(timezone.utc) - parsed).total_seconds())
        assert delta < 5

    def test_ts_device_pads_microseconds(self) -> None:
        """Zero/short microsecond values must stay six digits, or lexical
        ordering of timestamps silently breaks."""
        for _ in range(200):
            assert RFC3339_MICROS.fullmatch(now_ts_device())

    def test_monotonic_never_goes_backwards(self) -> None:
        first = now_monotonic_ns()
        second = now_monotonic_ns()
        assert isinstance(first, int)
        assert second >= first
        assert second - first < 1_000_000_000

    def test_monotonic_matches_stdlib_clock(self) -> None:
        before = time.monotonic_ns()
        value = now_monotonic_ns()
        after = time.monotonic_ns()
        assert before <= value <= after
