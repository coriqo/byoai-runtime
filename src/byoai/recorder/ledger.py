"""
ledger.py — the per-device, hash-chained, append-only event ledger.

One SQLite file per device. Every appended event gets a monotonic ``seq`` and
an ``entry_hash`` that commits to the previous entry's hash, so any later edit
to a persisted row — payload, timestamp, tool name, anything — breaks the chain
at exactly the row that was touched and at every row after it. That is the
whole point: the ledger is not trusted storage, it is *evidence* whose
tampering is detectable offline by a third party.

Design notes:

- Chain per device, never one global chain (``docs/seal-format.md`` §5). Writes serialize
  within a single Ledger instance only, so N devices scale linearly.
- WAL + ``synchronous=NORMAL``: readers (the verifier, checkpointer) never
  block on an in-flight append, and an append costs a single fsync-free write.
  NORMAL can lose the last transactions on an OS-level crash — that shows up
  as a *gap*, which ``missing_ranges()`` reports honestly, rather than as a
  silently rewritten history.
- One transaction per append. Batching would be faster and would also mean an
  unrecorded action could be lost after the proxy already let it through.
- Thread-safe: the proxy calls this from async handlers (usually via
  ``asyncio.to_thread``), so a single connection opened with
  ``check_same_thread=False`` is guarded by one lock that covers
  read-head → hash → write as one critical section.
- Resume from disk on open: after a crash the chain continues from the last
  persisted ``entry_hash``; it never restarts at genesis.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from byoai.recorder.canonical import canonicalize, sha256_hex
from byoai.recorder.schema import (
    EVENT_SCHEMA_VERSION,
    AgentEvent,
    EventKind,
    event_digest,
    new_event_id,
    new_span_id,
    new_trace_id,
    now_monotonic_ns,
    now_ts_device,
)

log = logging.getLogger(__name__)

# The chain's fixed starting point. An empty ledger's head is genesis, so a
# verifier can tell "nothing was ever recorded" apart from "the first entries
# were deleted" (the latter leaves seq 1's prev_hash != genesis or a gap).
GENESIS_PREV_HASH = "sha256:" + "00" * 32

# record_failure markers are device-level bookkeeping, not tied to any one
# agent session (the dropped events may span several) — same pattern as
# rotation.py's ROTATION_SESSION_ID sentinel for KEY_ROTATED events.
_RECORD_FAILURE_SESSION_ID = "_record_failure"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_events (
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
    entry_hash      TEXT NOT NULL,
    trace_id        TEXT,
    span_id         TEXT,
    parent_span_id  TEXT,
    continues_from  TEXT
);
CREATE INDEX IF NOT EXISTS idx_agent_events_session ON agent_events(session_id);
CREATE INDEX IF NOT EXISTS idx_agent_events_tool_use ON agent_events(tool_use_id);

CREATE TABLE IF NOT EXISTS checkpoints (
    seq_end     INTEGER PRIMARY KEY,
    device_id   TEXT NOT NULL,
    seq_start   INTEGER NOT NULL,
    chain_head  TEXT NOT NULL,
    ts_device   TEXT NOT NULL,
    sig         TEXT NOT NULL,
    body        TEXT NOT NULL
);

-- Single-row table: how far a shipper has confirmed delivery to Coriqo.
-- Lives in the ledger itself (not shipper-process memory) so "what's been
-- synced" survives a proxy restart exactly like the chain it describes.
CREATE TABLE IF NOT EXISTS sync_state (
    id                           INTEGER PRIMARY KEY CHECK (id = 1),
    synced_up_to_seq             INTEGER NOT NULL DEFAULT 0,
    synced_checkpoint_up_to_seq  INTEGER NOT NULL DEFAULT 0,
    synced_attestation_up_to_seq INTEGER NOT NULL DEFAULT 0,
    updated_at                   TEXT NOT NULL
);
"""


class LedgerWriteError(RuntimeError):
    """A ledger write failed while ``strict_mode`` was on.

    The caller (the proxy) turns this into a 503: in a regulated deployment an
    action the ledger could not record must not be allowed to happen.
    """


@dataclass(frozen=True, slots=True)
class LedgerEntry:
    """One persisted row: the event plus its position in the chain."""

    seq: int
    prev_hash: str
    entry_hash: str
    event_digest: str
    event: AgentEvent


def compute_entry_hash(prev_hash: str, seq: int, digest: str) -> str:
    """The chain link: sha256 over the canonical {prev_hash, seq, event_digest}.

    Exposed at module level so the offline verifier recomputes links with the
    exact same function the writer used, instead of a re-implementation that
    can drift.
    """
    return sha256_hex(
        canonicalize({"prev_hash": prev_hash, "seq": seq, "event_digest": digest})
    )


class Ledger:
    """Append-only hash-chained event log for a single device."""

    def __init__(
        self, path: str | Path, device_id: str, *, strict_mode: bool = False
    ) -> None:
        self.path = Path(path)
        self.device_id = device_id
        self.strict_mode = strict_mode

        # One lock for everything: append's read-head/hash/insert must be
        # atomic against other appends, and sqlite3 objects are not safe to
        # use concurrently from multiple threads even with check_same_thread
        # disabled.
        self._lock = threading.RLock()
        self._closed = False
        # Write failures swallowed in non-strict mode, drained into a
        # record_failure marker on the next successful append.
        self._pending_failures: list[dict[str, Any]] = []

        os.makedirs(self.path.parent or Path("."), exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        try:
            # Ledgers created before checkpoint shipping existed have
            # sync_state without this column; CREATE TABLE IF NOT EXISTS
            # above is a no-op against them.
            self._conn.execute(
                "ALTER TABLE sync_state ADD COLUMN "
                "synced_checkpoint_up_to_seq INTEGER NOT NULL DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass  # column already present
        try:
            # Ledgers created before attestation shipping existed (AIR-7c)
            # have sync_state without this column either; same migration
            # shape as synced_checkpoint_up_to_seq above.
            self._conn.execute(
                "ALTER TABLE sync_state ADD COLUMN "
                "synced_attestation_up_to_seq INTEGER NOT NULL DEFAULT 0"
            )
        except sqlite3.OperationalError:
            pass  # column already present

        # Ledgers created before schema v2 (trace attribution)
        # have agent_events without these columns; CREATE TABLE IF NOT EXISTS
        # above is a no-op against them, same pattern as sync_state above.
        # Existing rows get NULL in all four — they stay v1-shaped (their
        # schema_version column is untouched), so schema.py's
        # AgentEvent.to_dict()/event_digest() continue to treat them as v1
        # and never fold these NULLs into the digest. New rows are always v2
        # and populate all four.
        for column in ("trace_id", "span_id", "parent_span_id", "continues_from"):
            try:
                self._conn.execute(f"ALTER TABLE agent_events ADD COLUMN {column} TEXT")
            except sqlite3.OperationalError:
                pass  # column already present
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_agent_events_trace ON agent_events(trace_id)"
        )

        self._head, self._next_seq = self._resume()

    # ---------------------------------------------------------------- state

    def _resume(self) -> tuple[str, int]:
        """Restore the chain head from disk so a crash resumes, not restarts."""
        row = self._conn.execute(
            "SELECT seq, entry_hash, kind, payload FROM agent_events "
            "ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return GENESIS_PREV_HASH, 1
        self._warn_if_head_is_a_foreign_rotation(row)
        return row[1], row[0] + 1

    def _warn_if_head_is_a_foreign_rotation(self, row: tuple) -> None:
        """Detect (best-effort, log-only) the "out-of-process rotation"
        footgun: if some *other* process rotated this
        device's key (its own ``rotate_key`` CLI invocation, or a sibling
        process holding the same key material) while this ``Ledger`` object
        was already open, this object's in-memory ``device_id`` is now
        retired — everything it appends from here on will fail verification
        as stale-key usage. This can't be prevented (there is no hot-reload
        of keys by design, see ``docs/seal-format.md`` §7), but a loud,
        immediate log beats silently producing entries that turn out to be unverifiable much later.

        ``row`` is the positional ``(seq, entry_hash, kind, payload)`` tuple
        from :meth:`_resume`'s own query — this connection has no row
        factory set, unlike the read-only one the verifier uses.
        """
        try:
            _seq, _entry_hash, kind, payload_text = row
            if kind != _kind_value(EventKind.KEY_ROTATED):
                return
            payload = json.loads(payload_text) if isinstance(payload_text, str) else {}
            if payload.get("old_device_id") == self.device_id:
                log.error(
                    "ledger %s: the head event is a key_rotated that retired "
                    "this ledger's own device_id (%s) — some other process "
                    "rotated this device's key while this Ledger instance was "
                    "open (or is being reopened after that happened). Every "
                    "entry appended from this instance from now on will fail "
                    "verification as stale-key usage. Restart the recorder "
                    "process to pick up the new key.",
                    self.path,
                    self.device_id,
                )
        except (KeyError, TypeError, ValueError):  # pragma: no cover - defensive
            pass

    @property
    def head(self) -> str:
        with self._lock:
            return self._head

    def snapshot(
        self, clock: Callable[[], float] | None = None
    ) -> tuple[int, str, float | None]:
        """``(last_seq, head, now)`` read together under the ledger lock.

        The head is read from the file, not from this object's memory, so a
        second writer on the same ledger (another worker process) cannot make
        it stale: the hash is the one that belongs to that seq. ``clock``, when
        given, is read inside the same lock, so a checkpoint's time cannot fall
        on the wrong side of an entry that was appended around it. A checkpoint
        signs this triple, never a head or time read separately."""
        with self._lock:
            self._require_open()
            row = self._conn.execute(
                "SELECT seq, entry_hash FROM agent_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if row is None:
                self._head, self._next_seq = GENESIS_PREV_HASH, 1
            else:
                self._head, self._next_seq = row[1], row[0] + 1
            return self._next_seq - 1, self._head, (clock() if clock is not None else None)

    # A forked child must not use the parent's SQLite connection, but it also
    # must not open a new one until it actually uses the ledger: a child that
    # only execs (``subprocess`` with ``preexec_fn``) would otherwise open a
    # connection and start threads before exec. So the child hook only swaps the
    # lock and sets this flag; the reopen happens on first use of ``_conn``.
    _needs_reopen = False
    #: Called once, in the child, right after the lazy reopen (the recorder
    #: starts its heartbeat thread here).
    after_reopen: Callable[[], None] | None = None

    @property
    def _conn(self) -> sqlite3.Connection:
        if self._needs_reopen:
            self._reopen_now()
        return self._conn_

    @_conn.setter
    def _conn(self, value: sqlite3.Connection) -> None:
        self._conn_ = value

    def mark_forked_in_child(self) -> None:
        """Called in a forked child: swap in a fresh lock (one a vanished thread
        held would never release) and reopen the connection on first use."""
        self._lock = threading.RLock()
        if not self._closed:
            self._needs_reopen = True

    def _reopen_now(self) -> None:
        self._needs_reopen = False
        if not hasattr(self, "_abandoned_conns"):
            self._abandoned_conns: list[sqlite3.Connection] = []
        # Referenced, never closed here: closing an inherited handle in the
        # child can disturb the parent's file locks.
        self._abandoned_conns.append(self._conn_)
        self._conn_ = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self._conn_.execute("PRAGMA journal_mode=WAL")
        self._conn_.execute("PRAGMA synchronous=NORMAL")
        self._head, self._next_seq = self._resume()
        callback = self.after_reopen
        if callback is not None:
            try:
                callback()
            except Exception:  # noqa: BLE001
                log.exception("ledger: after-fork callback failed")

    @property
    def next_seq(self) -> int:
        with self._lock:
            return self._next_seq

    # --------------------------------------------------------------- append

    def append(self, event: AgentEvent) -> LedgerEntry | None:
        return self._append(event, None)

    def _append(
        self,
        event: AgentEvent | None,
        builder: Callable[[int], AgentEvent] | None,
    ) -> LedgerEntry | None:
        """Assign a seq, link it into the chain, and commit it in one transaction.

        Returns the persisted entry. Returns ``None`` only in the non-strict
        failure path, where the write is dropped, logged loudly, and remembered
        so the next successful append carries a ``record_failure`` marker
        (contract deviation: the contract types this as ``LedgerEntry``, but
        there is no honest entry to return when nothing was persisted).
        """
        with self._lock:
            def _for_log() -> AgentEvent:
                if event is not None:
                    return event
                assert builder is not None
                try:
                    return builder(self._next_seq - 1)
                except Exception:  # noqa: BLE001 - a failure to log must not raise
                    # The builder is what failed; do not run it again inside the
                    # handler. A minimal stand-in carries the failure record.
                    return AgentEvent(
                        schema_version=EVENT_SCHEMA_VERSION, event_id=new_event_id(),
                        device_id=self.device_id, session_id="", seq=0, kind="unknown",
                        ts_device=now_ts_device(), ts_monotonic_ns=now_monotonic_ns(),
                        tool_use_id=None, tool_name=None, payload={}, payload_hash="",
                        model=None, provider="byoai-recorder", trace_id="", span_id="",
                    )

            if self._closed:
                # A closed ledger is a write failure like any other — route
                # it through _on_write_failure so strict_mode governs it
                # too, instead of _require_open()'s unconditional raise
                # (which would crash the request path even in the default,
                # non-strict "never break the caller" mode). But a closed
                # ledger will never append again, so it can never drain a
                # queued record_failure marker either — queuing one here
                # would just grow _pending_failures forever. _on_write_failure
                # already logs loudly, which is the only durable record a
                # closed ledger can still produce.
                self._on_write_failure(
                    _for_log(),
                    RuntimeError(f"ledger {self.path} is closed"), queue=False,
                )
                return None
            if self._pending_failures:
                self._drain_failures()
            try:
                return self._append_locked(event, builder)
            except Exception as exc:  # noqa: BLE001 - policy decision below
                self._on_write_failure(_for_log(), exc)
                return None

    def append_stamped(
        self, build: Callable[[int], AgentEvent]
    ) -> LedgerEntry | None:
        """Append the event ``build(last_seq)`` returns. ``last_seq`` is the
        seq just before the one this entry is written at (0 when empty). It is
        computed inside the write, after any queued ``record_failure`` marker
        has been written and after a stale-head resync, so it is exactly
        ``seq - 1`` of the stored entry. Same failure policy as :meth:`append`."""
        return self._append(None, build)

    def last_entry_of_kind(self, kind: Any) -> LedgerEntry | None:
        """The newest entry whose ``kind`` matches, or ``None``."""
        with self._lock:
            self._require_open()
            row = self._conn.execute(
                "SELECT * FROM agent_events WHERE kind = ? ORDER BY seq DESC LIMIT 1",
                (_kind_value(kind),),
            ).fetchone()
        return _row_to_entry(row) if row is not None else None

    def _append_locked(
        self,
        event: AgentEvent | None,
        builder: Callable[[int], AgentEvent] | None = None,
    ) -> LedgerEntry:
        # Up to two attempts: the in-memory (_head, _next_seq) pair can go
        # stale if something else advanced the on-disk chain out from under
        # this Ledger object without going through it — e.g. `coriqo-verify`'s
        # sibling `rotate_key` CLI appending a KEY_ROTATED event to the same
        # ledger file while this process still has it open (a second Ledger
        # instance on one file). The first INSERT then collides on the
        # `seq` primary key (or, if seq happens to still be free, some other
        # writer's row), which SQLite reports as an IntegrityError. Rather
        # than fail every append from then on (dropping events silently in
        # non-strict mode), resync from disk once and retry with the correct
        # seq/prev_hash before giving up.
        for attempt in range(2):
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                # Read the head again inside the write lock: another process
                # writing the same file may have appended since this object
                # last looked, and a retry outside the lock can lose that race.
                row = self._conn.execute(
                    "SELECT seq, entry_hash FROM agent_events ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                if row is None:
                    self._head, self._next_seq = GENESIS_PREV_HASH, 1
                elif row[0] + 1 != self._next_seq or row[1] != self._head:
                    self._head, self._next_seq = row[1], row[0] + 1
                seq = self._next_seq
                prev_hash = self._head
                # The event carries the seq that is actually written, so the
                # digest commits to its position too — a row cannot be reordered
                # or replayed at a different seq without breaking its own digest.
                if builder is not None:
                    event = builder(seq - 1)
                assert event is not None
                stamped = _with_seq(event, seq)
                digest = event_digest(stamped)
                entry_hash = compute_entry_hash(prev_hash, seq, digest)
                self._conn.execute(
                    "INSERT INTO agent_events (seq, event_id, schema_version, device_id, "
                    "session_id, kind, ts_device, ts_monotonic_ns, tool_use_id, tool_name, "
                    "payload, payload_hash, model, provider, event_digest, prev_hash, "
                    "entry_hash, trace_id, span_id, parent_span_id, continues_from) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        seq,
                        stamped.event_id,
                        stamped.schema_version,
                        stamped.device_id,
                        stamped.session_id,
                        _kind_value(stamped.kind),
                        stamped.ts_device,
                        stamped.ts_monotonic_ns,
                        stamped.tool_use_id,
                        stamped.tool_name,
                        canonicalize(stamped.payload).decode("utf-8"),
                        stamped.payload_hash,
                        stamped.model,
                        stamped.provider,
                        digest,
                        prev_hash,
                        entry_hash,
                        stamped.trace_id,
                        stamped.span_id,
                        stamped.parent_span_id,
                        stamped.continues_from,
                    ),
                )
            except sqlite3.IntegrityError:
                try:
                    self._conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                if attempt == 0:
                    # Re-read the real head (max seq + its entry_hash) from
                    # the DB and rebuild prev_hash/next_seq from it, same as
                    # a fresh Ledger opening this file would on startup —
                    # _resume() is exactly that logic, already correct.
                    self._head, self._next_seq = self._resume()
                    continue
                raise
            except BaseException:
                # Including KeyboardInterrupt: a transaction left open would make
                # every later append fail ("cannot start a transaction within a
                # transaction") and lock other processes out of the file.
                self._rollback_quietly()
                raise
            else:
                try:
                    self._conn.execute("COMMIT")
                except BaseException:
                    # A failed COMMIT (e.g. a transient disk I/O error) must
                    # not leave the connection wedged inside an open
                    # transaction — the next append()'s BEGIN IMMEDIATE
                    # would then fail forever with "cannot start a
                    # transaction within a transaction". Roll back so the
                    # ledger recovers and the *next* append can succeed;
                    # this append itself still surfaces the failure to the
                    # caller (via the existing except Exception / strict
                    # mode handling one level up).
                    self._rollback_quietly()
                    raise
                # Only advance in-memory chain state after the row is
                # durable, so a failed write cannot leave the head pointing
                # at an entry nobody has.
                self._head = entry_hash
                self._next_seq = seq + 1
                return LedgerEntry(
                    seq=seq,
                    prev_hash=prev_hash,
                    entry_hash=entry_hash,
                    event_digest=digest,
                    event=stamped,
                )
        raise AssertionError("unreachable: loop always returns or raises")

    def _rollback_quietly(self) -> None:
        try:
            if self._conn.in_transaction:
                self._conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass

    def _on_write_failure(self, event: AgentEvent, exc: Exception, *, queue: bool = True) -> None:
        log.error(
            "ledger write failed for event %s (kind=%s, session=%s): %s",
            getattr(event, "event_id", "?"),
            _kind_value(getattr(event, "kind", "?")),
            getattr(event, "session_id", "?"),
            exc,
        )
        if self.strict_mode:
            raise LedgerWriteError(
                f"failed to record event {getattr(event, 'event_id', '?')}: {exc}"
            ) from exc
        if not queue:
            return
        self._pending_failures.append(
            {
                "event_id": getattr(event, "event_id", None),
                "kind": _kind_value(getattr(event, "kind", None)),
                "session_id": getattr(event, "session_id", None),
                "tool_use_id": getattr(event, "tool_use_id", None),
                "error": f"{type(exc).__name__}: {exc}",
                "ts_device": now_ts_device(),
            }
        )

    def _drain_failures(self) -> None:
        """Write one record_failure marker covering everything we dropped.

        Best-effort by construction: if the marker itself cannot be written the
        failures stay pending and we try again on the next append, rather than
        recursing or losing the fact that something went unrecorded.
        """
        failures = list(self._pending_failures)
        payload: dict[str, Any] = {
            "reason": "ledger_write_failed",
            "dropped_count": len(failures),
            "dropped": failures,
        }
        marker = AgentEvent(
            schema_version=EVENT_SCHEMA_VERSION,
            event_id=new_event_id(),
            device_id=self.device_id,
            # The dropped events span whatever sessions were mid-write when
            # the failure occurred, not necessarily just the last one — the
            # full per-event session_id is preserved in payload["dropped"],
            # so this marker uses a device-level sentinel rather than
            # misattributing every dropped session's failure to only the
            # last one (a session_id-scoped query for an earlier session
            # would otherwise never find that its writes were dropped).
            session_id=_RECORD_FAILURE_SESSION_ID,
            seq=0,
            kind=_kind_value(EventKind.RECORD_FAILURE),
            ts_device=now_ts_device(),
            ts_monotonic_ns=now_monotonic_ns(),
            tool_use_id=None,
            tool_name=None,
            payload=payload,
            payload_hash=sha256_hex(canonicalize(payload)),
            model=None,
            # Recorder-internal bookkeeping, not a real provider call —
            # matches the "recorder" provider convention KEY_ROTATED uses.
            provider="recorder",
            # A record_failure marker isn't part of any agent's own logical
            # run; give it its own root trace/span rather than borrowing one
            # from a dropped event we may not have full context for.
            trace_id=new_trace_id(),
            span_id=new_span_id(),
            parent_span_id=None,
            continues_from=None,
        )
        try:
            self._append_locked(marker)
        except Exception as exc:  # noqa: BLE001 - never raise from the marker path
            log.error("could not write record_failure marker: %s", exc)
            return
        self._pending_failures.clear()

    # ----------------------------------------------------------------- read

    def read_range(self, start: int, end: int) -> list[LedgerEntry]:
        """Entries with ``start <= seq <= end`` (both inclusive), in seq order."""
        with self._lock:
            self._require_open()
            rows = self._conn.execute(
                "SELECT * FROM agent_events WHERE seq >= ? AND seq <= ? ORDER BY seq",
                (start, end),
            ).fetchall()
        return [_row_to_entry(r) for r in rows]

    def read_session(self, session_id: str) -> list[LedgerEntry]:
        """Every entry belonging to one session, in seq order.

        A session is one agent invocation, so this is how a caller
        reconstructs a single run from the ledger alone — no in-memory app
        state involved. Note that a sub-agent invocation gets its own
        ``session_id`` while sharing the parent's ``trace_id``, so this
        returns one agent's own steps, not a whole trace tree.
        """
        with self._lock:
            self._require_open()
            rows = self._conn.execute(
                "SELECT * FROM agent_events WHERE session_id = ? ORDER BY seq",
                (session_id,),
            ).fetchall()
        return [_row_to_entry(r) for r in rows]

    def iter_entries(self) -> Iterator[LedgerEntry]:
        """Stream the whole chain in seq order without loading it all at once.

        Only holds the lock while actually touching the connection (opening
        the cursor, fetching each batch, closing it) — never across a
        ``yield`` — so a slow consumer of this generator cannot block
        concurrent ``append()`` calls for the duration of the scan.
        """
        with self._lock:
            self._require_open()
            cur = self._conn.execute("SELECT * FROM agent_events ORDER BY seq")
        try:
            while True:
                with self._lock:
                    # Re-check on every batch: close() can run between
                    # batches (that's the whole point of not holding the
                    # lock across yield), and fetchmany() on an already
                    # -closed sqlite connection raises sqlite3.ProgrammingError
                    # instead of the ledger's own closed-ledger error.
                    self._require_open()
                    rows = cur.fetchmany(256)
                if not rows:
                    return
                for row in rows:
                    yield _row_to_entry(row)
        finally:
            with self._lock:
                if not self._closed:
                    cur.close()

    def missing_ranges(self) -> list[tuple[int, int]]:
        """Inclusive (start, end) seq ranges that should exist but do not.

        A gap means events were lost (crash before commit) or deleted. Either
        way it is a finding, not something to paper over.
        """
        with self._lock:
            self._require_open()
            seqs = [r[0] for r in self._conn.execute("SELECT seq FROM agent_events ORDER BY seq")]
        if not seqs:
            return []
        gaps: list[tuple[int, int]] = []
        # The chain is defined to start at seq 1, so a missing prefix is a gap.
        if seqs[0] > 1:
            gaps.append((1, seqs[0] - 1))
        for prev, cur in zip(seqs, seqs[1:], strict=False):
            if cur > prev + 1:
                gaps.append((prev + 1, cur - 1))
        return gaps

    # ------------------------------------------------------------- sync

    def read_unsynced(self, limit: int | None = None) -> list[LedgerEntry]:
        """Entries after the sync watermark, in seq order.

        This is what a shipper batches and sends. It does not move the
        watermark — call :meth:`set_synced_up_to` only after the server has
        confirmed the batch, so a crash mid-ship just means the next attempt
        resends a few already-accepted rows (safe: the server dedupes on
        ``entry_hash``).
        """
        with self._lock:
            self._require_open()
            sql = "SELECT * FROM agent_events WHERE seq > ? ORDER BY seq"
            params: tuple[Any, ...] = (self._get_synced_up_to_locked(),)
            if limit is not None:
                sql += " LIMIT ?"
                params = (*params, limit)
            rows = self._conn.execute(sql, params).fetchall()
        return [_row_to_entry(r) for r in rows]

    def get_synced_up_to(self) -> int:
        """The highest seq the shipper has confirmed Coriqo received. 0 if never shipped."""
        with self._lock:
            self._require_open()
            return self._get_synced_up_to_locked()

    def _get_synced_up_to_locked(self) -> int:
        row = self._conn.execute(
            "SELECT synced_up_to_seq FROM sync_state WHERE id = 1"
        ).fetchone()
        return row[0] if row is not None else 0

    def set_synced_up_to(self, seq: int) -> None:
        """Advance the watermark. Refuses to move it backwards or past the chain head.

        Both would silently hide unsynced data: moving it backwards would
        make already-confirmed rows look unsynced again (harmless but
        wasteful); moving it past the head would make rows that were never
        written look synced, which a real gap could exploit.
        """
        with self._lock:
            self._require_open()
            current = self._get_synced_up_to_locked()
            if seq < current:
                raise ValueError(
                    f"refusing to move sync watermark backwards: {seq} < {current}"
                )
            if seq > self._next_seq - 1:
                raise ValueError(
                    f"refusing to mark seq {seq} synced: chain head is at {self._next_seq - 1}"
                )
            self._conn.execute(
                "INSERT INTO sync_state (id, synced_up_to_seq, updated_at) VALUES (1, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET synced_up_to_seq = excluded.synced_up_to_seq, "
                "updated_at = excluded.updated_at",
                (seq, now_ts_device()),
            )

    # ---------------------------------------------------------- checkpoints

    def append_checkpoint(self, cp: dict) -> None:
        """Persist a signed checkpoint (written by the checkpointer).

        Insert-if-absent by ``seq_end``: a second checkpoint arriving for a
        ``seq_end`` that already has one (e.g. a retried emit, or two
        concurrent checkpointers racing) must never silently overwrite the
        original — the row keyed only by ``seq_end`` was previously
        ``INSERT OR REPLACE``, which let a later checkpoint quietly replace
        an earlier one covering the exact same range, discarding whichever
        signature/chain_head lost the race with no record it ever existed.
        If a row is already there with different content, the original is
        kept and the collision is logged, never raised from this hot path.
        """
        body = canonicalize(cp).decode("utf-8")
        with self._lock:
            self._require_open()
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                existing = self._conn.execute(
                    "SELECT body FROM checkpoints WHERE seq_end = ?",
                    (int(cp["seq_end"]),),
                ).fetchone()
                if existing is not None:
                    self._conn.execute("COMMIT")
                    if existing[0] != body:
                        log.warning(
                            "checkpoint seq_end=%s already recorded with different "
                            "content; keeping the original, discarding this one",
                            cp["seq_end"],
                        )
                    return
                self._conn.execute(
                    "INSERT INTO checkpoints (seq_end, device_id, seq_start, "
                    "chain_head, ts_device, sig, body) VALUES (?,?,?,?,?,?,?)",
                    (
                        int(cp["seq_end"]),
                        cp["device_id"],
                        int(cp["seq_start"]),
                        cp["chain_head"],
                        cp["ts_device"],
                        cp["sig"],
                        body,
                    ),
                )
                self._conn.execute("COMMIT")
            except BaseException:
                self._rollback_quietly()
                raise

    def latest_checkpoint(self) -> dict | None:
        with self._lock:
            self._require_open()
            row = self._conn.execute(
                "SELECT body FROM checkpoints ORDER BY seq_end DESC LIMIT 1"
            ).fetchone()
        return None if row is None else json.loads(row[0])

    def iter_checkpoints(self) -> list[dict]:
        with self._lock:
            self._require_open()
            rows = self._conn.execute(
                "SELECT body FROM checkpoints ORDER BY seq_end"
            ).fetchall()
        return [json.loads(r[0]) for r in rows]

    # ---------------------------------------------------- checkpoint sync

    def read_unsynced_checkpoints(self, limit: int | None = None) -> list[dict]:
        """Checkpoints after the checkpoint sync watermark, in seq_end order.

        Mirrors :meth:`read_unsynced` for entries: this is what a shipper
        batches to ``/v1/checkpoints/batch``. Does not move the watermark.
        """
        with self._lock:
            self._require_open()
            sql = "SELECT body FROM checkpoints WHERE seq_end > ? ORDER BY seq_end"
            params: tuple[Any, ...] = (self._get_synced_checkpoint_up_to_locked(),)
            if limit is not None:
                sql += " LIMIT ?"
                params = (*params, limit)
            rows = self._conn.execute(sql, params).fetchall()
        return [json.loads(r[0]) for r in rows]

    def get_synced_checkpoint_up_to(self) -> int:
        """Highest checkpoint ``seq_end`` Coriqo has confirmed receiving. 0 if never shipped."""
        with self._lock:
            self._require_open()
            return self._get_synced_checkpoint_up_to_locked()

    def _get_synced_checkpoint_up_to_locked(self) -> int:
        row = self._conn.execute(
            "SELECT synced_checkpoint_up_to_seq FROM sync_state WHERE id = 1"
        ).fetchone()
        return row[0] if row is not None else 0

    def set_synced_checkpoint_up_to(self, seq: int) -> None:
        """Advance the checkpoint watermark. Refuses to move it backwards or
        past the newest checkpoint's seq_end, for the same reasons as
        :meth:`set_synced_up_to`."""
        with self._lock:
            self._require_open()
            current = self._get_synced_checkpoint_up_to_locked()
            if seq < current:
                raise ValueError(
                    f"refusing to move checkpoint sync watermark backwards: {seq} < {current}"
                )
            latest = self._conn.execute(
                "SELECT MAX(seq_end) FROM checkpoints"
            ).fetchone()[0]
            if latest is None or seq > latest:
                raise ValueError(
                    f"refusing to mark checkpoint seq_end {seq} synced: "
                    f"latest checkpoint is at {latest}"
                )
            self._conn.execute(
                "INSERT INTO sync_state (id, synced_up_to_seq, synced_checkpoint_up_to_seq, "
                "updated_at) VALUES (1, 0, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "synced_checkpoint_up_to_seq = excluded.synced_checkpoint_up_to_seq, "
                "updated_at = excluded.updated_at",
                (seq, now_ts_device()),
            )

    # --------------------------------------------------------- attestation sync

    def read_checkpoints_pending_attestation(self, limit: int | None = None) -> list[dict]:
        """Checkpoints after the attestation sync watermark, in seq_end order.

        Mirrors :meth:`read_unsynced_checkpoints`, but against the
        attestation watermark rather than the checkpoint-ship watermark: a
        checkpoint already shipped to ``/v1/checkpoints/batch`` can still be
        pending its CEI attestation, since the two cursors advance
        independently over the same ``seq_end`` id-space. Does not
        move the watermark.
        """
        with self._lock:
            self._require_open()
            sql = "SELECT body FROM checkpoints WHERE seq_end > ? ORDER BY seq_end"
            params: tuple[Any, ...] = (self._get_synced_attestation_up_to_locked(),)
            if limit is not None:
                sql += " LIMIT ?"
                params = (*params, limit)
            rows = self._conn.execute(sql, params).fetchall()
        return [json.loads(r[0]) for r in rows]

    def get_synced_attestation_up_to(self) -> int:
        """Highest checkpoint ``seq_end`` sealed as a CEI attestation on
        Coriqo. 0 if never shipped.

        Mirrors :meth:`get_synced_checkpoint_up_to` exactly: an attestation
        envelope (AIR-7c, ``recorder/attestation.py::build_envelope``) seals
        the same ``(seq_start, seq_end)`` window a checkpoint already defines
        (one windowing scheme, not two), so this watermark lives in
        the same ``seq_end`` id-space as the checkpoint watermark, as a
        sibling column, not a second one derived independently.
        """
        with self._lock:
            self._require_open()
            return self._get_synced_attestation_up_to_locked()

    def _get_synced_attestation_up_to_locked(self) -> int:
        row = self._conn.execute(
            "SELECT synced_attestation_up_to_seq FROM sync_state WHERE id = 1"
        ).fetchone()
        return row[0] if row is not None else 0

    def set_synced_attestation_up_to(self, seq: int) -> None:
        """Advance the attestation watermark. Refuses to move it backwards or
        past the newest checkpoint's ``seq_end``, for the same reasons as
        :meth:`set_synced_checkpoint_up_to`."""
        with self._lock:
            self._require_open()
            current = self._get_synced_attestation_up_to_locked()
            if seq < current:
                raise ValueError(
                    f"refusing to move attestation sync watermark backwards: {seq} < {current}"
                )
            latest = self._conn.execute(
                "SELECT MAX(seq_end) FROM checkpoints"
            ).fetchone()[0]
            if latest is None or seq > latest:
                raise ValueError(
                    f"refusing to mark attestation seq_end {seq} synced: "
                    f"latest checkpoint is at {latest}"
                )
            self._conn.execute(
                "INSERT INTO sync_state (id, synced_up_to_seq, synced_attestation_up_to_seq, "
                "updated_at) VALUES (1, 0, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "synced_attestation_up_to_seq = excluded.synced_attestation_up_to_seq, "
                "updated_at = excluded.updated_at",
                (seq, now_ts_device()),
            )

    # ---------------------------------------------------------------- close

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._conn.close()
            except sqlite3.Error as exc:
                log.warning("error closing ledger %s: %s", self.path, exc)

    def _require_open(self) -> None:
        if self._closed:
            raise LedgerWriteError(f"ledger {self.path} is closed")

    def __enter__(self) -> Ledger:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def _kind_value(kind: Any) -> Any:
    """Accept either an EventKind or the bare string the dataclass declares."""
    return kind.value if isinstance(kind, EventKind) else kind


def _with_seq(event: AgentEvent, seq: int) -> AgentEvent:
    """Return the event stamped with its assigned seq (AgentEvent is frozen)."""
    if getattr(event, "seq", None) == seq:
        return event
    fields = {
        "schema_version": event.schema_version,
        "event_id": event.event_id,
        "device_id": event.device_id,
        "session_id": event.session_id,
        "seq": seq,
        "kind": _kind_value(event.kind),
        "ts_device": event.ts_device,
        "ts_monotonic_ns": event.ts_monotonic_ns,
        "tool_use_id": event.tool_use_id,
        "tool_name": event.tool_name,
        "payload": event.payload,
        "payload_hash": event.payload_hash,
        "model": event.model,
        "provider": event.provider,
        "trace_id": event.trace_id,
        "span_id": event.span_id,
        "parent_span_id": event.parent_span_id,
        "continues_from": event.continues_from,
    }
    return AgentEvent(**fields)


def _row_to_entry(row: tuple) -> LedgerEntry:
    (
        seq,
        event_id,
        schema_version,
        device_id,
        session_id,
        kind,
        ts_device,
        ts_monotonic_ns,
        tool_use_id,
        tool_name,
        payload,
        payload_hash,
        model,
        provider,
        digest,
        prev_hash,
        entry_hash,
        trace_id,
        span_id,
        parent_span_id,
        continues_from,
    ) = row
    # Pre-migration (v1) rows have NULL trace_id/span_id (the columns did not
    # exist when they were written). AgentEvent.trace_id/span_id are typed as
    # required strings, so substitute inert placeholders here — schema.py's
    # to_dict()/event_digest() suppress the v2-only fields entirely for
    # schema_version == "1" rows, so these placeholders never affect the
    # digest and are never observed as real trace data.
    event = AgentEvent(
        schema_version=schema_version,
        event_id=event_id,
        device_id=device_id,
        session_id=session_id,
        seq=seq,
        kind=kind,
        ts_device=ts_device,
        ts_monotonic_ns=ts_monotonic_ns,
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        payload=json.loads(payload),
        payload_hash=payload_hash,
        model=model,
        provider=provider,
        trace_id=trace_id if trace_id is not None else "",
        span_id=span_id if span_id is not None else "",
        parent_span_id=parent_span_id,
        continues_from=continues_from,
    )
    return LedgerEntry(
        seq=seq,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        event_digest=digest,
        event=event,
    )
