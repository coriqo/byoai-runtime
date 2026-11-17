"""Tests for trace attribution (trace_id/span_id/parent_span_id/
continues_from) and the v1 -> v2 additive schema migration that carries it.

Three things this file has to prove:

1. The fields flow correctly end to end (top-level agent, sub-agent,
   resumed-session link) through :class:`AgentEvent`.
2. The "sealed lineage for free" claim: because ``event_digest()`` hashes the
   whole ``AgentEvent.to_dict()`` (see schema.py), tampering with
   ``trace_id``/``parent_span_id`` on a v2 event changes ``entry_hash`` just
   like tampering with any other field — no separate fold-in step needed.
2. A ledger file written before this migration (no trace columns at all)
   opens without error, keeps verifying, and appends new v2 rows correctly.
"""

from __future__ import annotations

import sqlite3

from byoai.recorder.canonical import canonicalize, sha256_hex
from byoai.recorder.ledger import Ledger, compute_entry_hash
from byoai.recorder.schema import (
    EVENT_SCHEMA_VERSION,
    EVENT_SCHEMA_VERSION_V1,
    EventKind,
    event_digest,
    new_span_id,
    new_trace_id,
)
from byoai.recorder.verify import verify_ledger

from .conftest import make_event

DEVICE = "dev_trace_test"


# ---------------------------------------------------------------------------
# (a) / (b): trace_id/span_id/parent_span_id flow correctly
# ---------------------------------------------------------------------------


class TestTraceFlow:
    def test_top_level_event_has_trace_id_and_no_parent(self, tmp_path):
        ledger = Ledger(tmp_path / "ledger.db", DEVICE)
        try:
            trace_id = new_trace_id()
            span_id = new_span_id()
            event = make_event(
                DEVICE,
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=None,
            )
            entry = ledger.append(event)
        finally:
            ledger.close()

        assert entry is not None
        assert entry.event.trace_id == trace_id
        assert entry.event.span_id == span_id
        assert entry.event.parent_span_id is None
        assert entry.event.continues_from is None

    def test_sub_agent_event_shares_trace_id_and_points_at_parent_span(self, tmp_path):
        ledger = Ledger(tmp_path / "ledger.db", DEVICE)
        try:
            trace_id = new_trace_id()
            parent_span_id = new_span_id()
            root = make_event(DEVICE, trace_id=trace_id, span_id=parent_span_id)
            ledger.append(root)

            sub_span_id = new_span_id()
            sub_agent_event = make_event(
                DEVICE,
                trace_id=trace_id,
                span_id=sub_span_id,
                parent_span_id=parent_span_id,
            )
            entry = ledger.append(sub_agent_event)
        finally:
            ledger.close()

        assert entry is not None
        # Same logical run as the parent...
        assert entry.event.trace_id == trace_id
        # ...but attributed to a distinct invocation, spawned by the parent's
        # span.
        assert entry.event.span_id == sub_span_id
        assert entry.event.span_id != parent_span_id
        assert entry.event.parent_span_id == parent_span_id

    def test_continues_from_links_a_resumed_session_to_the_prior_trace(self):
        prior_trace_id = new_trace_id()
        event = make_event(DEVICE, continues_from=prior_trace_id)
        assert event.continues_from == prior_trace_id
        # A resumed session is a NEW trace (own trace_id), just linked back —
        # not a continuation of the old trace_id itself.
        assert event.trace_id != prior_trace_id


# ---------------------------------------------------------------------------
# (c) "sealed lineage for free": tampering with trace fields breaks the hash
# ---------------------------------------------------------------------------


class TestTraceFieldsFeedTheDigest:
    def test_entry_hash_changes_if_trace_id_is_tampered_with(self):
        # tool_use_id is pinned to the same fixed value on both calls —
        # make_event() randomizes it by default, and if it weren't pinned the
        # two events would differ in tool_use_id too, so the assertion below
        # would still pass even if trace_id were dropped from event_digest()
        # entirely. Pinning makes trace_id the ONLY field under test.
        fixed_tool_use_id = "toolu_fixed_trace_test"
        baseline = make_event(DEVICE, tool_use_id=fixed_tool_use_id)
        tampered = make_event(
            DEVICE,
            trace_id="tr_" + "f" * 32,
            tool_use_id=fixed_tool_use_id,
        )
        # Same payload/seq/etc, only trace_id differs.
        object.__setattr__(tampered, "event_id", baseline.event_id)
        object.__setattr__(tampered, "span_id", baseline.span_id)
        object.__setattr__(tampered, "ts_device", baseline.ts_device)
        object.__setattr__(tampered, "ts_monotonic_ns", baseline.ts_monotonic_ns)
        assert event_digest(tampered) != event_digest(baseline)

    def test_entry_hash_changes_if_parent_span_id_is_tampered_with(self):
        # Same rationale as above: pin tool_use_id (and everything else not
        # under test) so parent_span_id is the ONLY field that differs.
        fixed_tool_use_id = "toolu_fixed_parent_span_test"
        baseline = make_event(
            DEVICE, parent_span_id="sp_" + "1" * 32, tool_use_id=fixed_tool_use_id
        )
        tampered = make_event(
            DEVICE,
            trace_id=baseline.trace_id,
            span_id=baseline.span_id,
            parent_span_id="sp_" + "2" * 32,
            tool_use_id=fixed_tool_use_id,
        )
        object.__setattr__(tampered, "event_id", baseline.event_id)
        object.__setattr__(tampered, "ts_device", baseline.ts_device)
        object.__setattr__(tampered, "ts_monotonic_ns", baseline.ts_monotonic_ns)
        assert event_digest(tampered) != event_digest(baseline)

    def test_post_hoc_row_edit_of_trace_id_breaks_the_chain(self, tmp_path):
        """End-to-end version of the same claim: editing trace_id directly in
        the SQLite row (as an attacker with file access would) must be
        detectable by the offline verifier, exactly like editing any other
        column — because trace_id is inside the hashed payload, not metadata
        alongside it."""
        path = tmp_path / "ledger.db"
        ledger = Ledger(path, DEVICE)
        try:
            ledger.append(make_event(DEVICE))
            ledger.append(make_event(DEVICE))
        finally:
            ledger.close()

        conn = sqlite3.connect(str(path))
        try:
            conn.execute(
                "UPDATE agent_events SET trace_id = ? WHERE seq = 1",
                ("tr_" + "e" * 32,),
            )
            conn.commit()
        finally:
            conn.close()

        report = verify_ledger(path)
        assert report.ok is False
        assert 1 in report.broken_links


# ---------------------------------------------------------------------------
# (d) migration: a pre-existing v1 ledger file opens and keeps working
# ---------------------------------------------------------------------------

_V1_DDL = """
CREATE TABLE agent_events (
    seq             INTEGER PRIMARY KEY,
    event_id        TEXT NOT NULL UNIQUE,
    schema_version  TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    kind            TEXT NOT NULL,
    ts_device       TEXT NOT NULL,
    ts_monotonic_ns INTEGER NOT NULL,
    tool_use_id     TEXT,
    tool_name       TEXT,
    payload         TEXT NOT NULL,
    payload_hash    TEXT NOT NULL,
    model           TEXT,
    provider        TEXT NOT NULL,
    event_digest    TEXT NOT NULL,
    prev_hash       TEXT NOT NULL,
    entry_hash      TEXT NOT NULL
);
CREATE INDEX idx_agent_events_session ON agent_events(session_id);
CREATE INDEX idx_agent_events_tool_use ON agent_events(tool_use_id);

CREATE TABLE checkpoints (
    seq_end     INTEGER PRIMARY KEY,
    device_id   TEXT NOT NULL,
    seq_start   INTEGER NOT NULL,
    chain_head  TEXT NOT NULL,
    ts_device   TEXT NOT NULL,
    sig         TEXT NOT NULL,
    body        TEXT NOT NULL
);

CREATE TABLE sync_state (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    synced_up_to_seq  INTEGER NOT NULL DEFAULT 0,
    updated_at        TEXT NOT NULL
);
"""

GENESIS_PREV_HASH = "sha256:" + "00" * 32


def _v1_event_dict(seq: int) -> dict:
    payload = {"n": seq}
    return {
        "seq": seq,
        "schema_version": EVENT_SCHEMA_VERSION_V1,
        "event_id": f"evt_v1_{seq:04d}",
        "device_id": DEVICE,
        "session_id": "sess_legacy",
        "kind": EventKind.TOOL_USE.value,
        "ts_device": f"2026-01-0{seq}T00:00:00.000000Z",
        "ts_monotonic_ns": 1_000_000 * seq,
        "tool_use_id": None,
        "tool_name": None,
        "payload": payload,
        "payload_hash": sha256_hex(canonicalize(payload)),
        "model": None,
        "provider": "anthropic",
    }


def _build_v1_ledger(path) -> None:
    """Hand-build a v1-shaped ledger file: pre-migration schema, real
    hash-chained rows, no trace columns anywhere."""
    conn = sqlite3.connect(str(path))
    try:
        conn.executescript(_V1_DDL)
        prev = GENESIS_PREV_HASH
        for seq in (1, 2, 3):
            event = _v1_event_dict(seq)
            digest = sha256_hex(canonicalize(event))
            entry_hash = compute_entry_hash(prev, seq, digest)
            conn.execute(
                "INSERT INTO agent_events (seq, event_id, schema_version, device_id, "
                "session_id, kind, ts_device, ts_monotonic_ns, tool_use_id, tool_name, "
                "payload, payload_hash, model, provider, event_digest, prev_hash, "
                "entry_hash) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    seq,
                    event["event_id"],
                    event["schema_version"],
                    event["device_id"],
                    event["session_id"],
                    event["kind"],
                    event["ts_device"],
                    event["ts_monotonic_ns"],
                    event["tool_use_id"],
                    event["tool_name"],
                    canonicalize(event["payload"]).decode("utf-8"),
                    event["payload_hash"],
                    event["model"],
                    event["provider"],
                    digest,
                    prev,
                    entry_hash,
                ),
            )
            prev = entry_hash
        conn.commit()
    finally:
        conn.close()


class TestV1Migration:
    def test_v1_ledger_opens_without_error(self, tmp_path):
        path = tmp_path / "legacy.db"
        _build_v1_ledger(path)

        ledger = Ledger(path, DEVICE)
        try:
            entries = ledger.read_range(1, 3)
        finally:
            ledger.close()

        assert [e.seq for e in entries] == [1, 2, 3]
        assert all(e.event.schema_version == EVENT_SCHEMA_VERSION_V1 for e in entries)

    def test_migrated_columns_are_null_for_legacy_rows(self, tmp_path):
        path = tmp_path / "legacy.db"
        _build_v1_ledger(path)

        ledger = Ledger(path, DEVICE)
        ledger.close()

        conn = sqlite3.connect(str(path))
        try:
            row = conn.execute(
                "SELECT trace_id, span_id, parent_span_id, continues_from "
                "FROM agent_events WHERE seq = 1"
            ).fetchone()
        finally:
            conn.close()
        assert row == (None, None, None, None)

    def test_new_events_append_correctly_after_migration(self, tmp_path):
        path = tmp_path / "legacy.db"
        _build_v1_ledger(path)

        ledger = Ledger(path, DEVICE)
        try:
            trace_id = new_trace_id()
            span_id = new_span_id()
            new_event = make_event(DEVICE, trace_id=trace_id, span_id=span_id)
            entry = ledger.append(new_event)
        finally:
            ledger.close()

        assert entry is not None
        assert entry.seq == 4
        assert entry.event.schema_version == EVENT_SCHEMA_VERSION
        assert entry.event.trace_id == trace_id
        assert entry.event.span_id == span_id

        conn = sqlite3.connect(str(path))
        try:
            row = conn.execute(
                "SELECT schema_version, trace_id, span_id FROM agent_events WHERE seq = 4"
            ).fetchone()
        finally:
            conn.close()
        assert row == (EVENT_SCHEMA_VERSION, trace_id, span_id)

    def test_verify_ledger_succeeds_on_a_mixed_v1_v2_ledger(self, tmp_path):
        """The realistic post-migration scenario: some rows predate trace
        attribution, some don't. The offline verifier must accept both
        without falsely reporting a broken link on the legacy rows (which
        would happen if it naively hashed the new NULL columns into rows
        that never had them at write time)."""
        path = tmp_path / "mixed.db"
        _build_v1_ledger(path)

        ledger = Ledger(path, DEVICE)
        try:
            for _ in range(3):
                ledger.append(make_event(DEVICE))
        finally:
            ledger.close()

        report = verify_ledger(path)
        assert report.ok is True
        assert report.broken_links == []
        assert report.entries_checked == 6
