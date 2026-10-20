"""Verdict recording: what the gate decided, written down where it survives.

:mod:`byoai.recorder.mandate` decides and :mod:`byoai.recorder.governed_tool`
enforces, and until this module existed the decision reached the integrator's
process logs and stopped there. A control whose only trace is a log line is not
evidence, and the evidence is the product.

Three rules shape everything here.

**The local ledger is the authoritative record.** A verdict is appended to the
same hash-chained :class:`~byoai.recorder.ledger.Ledger` the recorder already
keeps, as an ordinary :data:`~byoai.recorder.schema.EventKind.MANDATE_VERDICT`
event. Whether Coriqo is reachable has nothing to do with whether a denial gets
written down; shipping is strictly downstream of the write. Recording a verdict
is never allowed to raise into the tool call — a ledger that cannot write loses
a row and logs loudly, it does not turn a governed tool into a failing one.

**Recording is not on the decide path.** :meth:`MandateGate.decide
<byoai.recorder.mandate.MandateGate.decide>` still reads memory and returns,
with no I/O of any kind. Everything in this module runs *after* the verdict
exists, from ``governed_tool``'s enforcement seam, so the property that makes
the gate safe to call from anywhere is untouched.

**All three verdicts are recorded, not just denials.** ``allowed`` is the
denominator. "This agent made 4,120 tool calls, 9 of them outside its mandate"
is a different and much more useful sentence than "9 denials happened", and
only the first one can be produced from a record that keeps allows too.

Repeats and halts are not N identical rows
------------------------------------------
The fact worth having is not *a tool was denied*. It is *the agent went back at
a control it had already been refused, four times, and then the run stopped*.
The denial latch already counts that; this module seals it. A first denial
records ``reason: out_of_scope``; the second attempt records
``reason: repeat_denied`` with ``attempts: 2``; the attempt that trips the
threshold records ``reason: run_halted`` with ``halted: true``. The reason code
carries the distinction on the wire, and the local ledger event carries the
count, the run, the principal and the halt flag alongside it.

The outbox
----------
Shipping reads from a small sqlite outbox rather than from the ledger. The
ledger's own sync watermark belongs to the entry-ingest path, which ships the
whole chain contiguously; verdict batches are a second, differently-shaped
delivery of the same facts (Coriqo seals one governance event per batch), and
giving them their own queue keeps one from stalling the other.

Rows are claimed under a ``batch_key`` that is written down *before* the request
goes out, so a resend after a crash, a timeout or a 409 carries the same key —
which is what makes retrying a write safe here. Nothing is marked shipped until
Coriqo has answered, so a shipping failure costs a duplicate delivery at worst,
never a lost verdict.

What this costs the call path
-----------------------------
The ledger append and the outbox insert happen inline, on the same thread as
the tool call, for every governed call including allows. That is a local sqlite
write on each side, which is cheap but not free, and inside an async tool it
happens on the event loop. Correctness is protected — a failed write cannot fail
a call — but latency is not: a locked or slow ledger file slows every governed
call. Moving the outbox write off-thread is the obvious next step and is not
attempted here.

Arguments are not recorded
--------------------------
``@governed_tool(capture_arguments=True)`` binds a call's arguments onto the
:class:`~byoai.recorder.mandate.ProposedAction`, and a governed tool's arguments
routinely hold account numbers and credentials. Nothing redacts them yet, so
this module records **how many** were captured and never a key or a value —
not in the local ledger, and certainly not on the wire.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonicalize, sha256_hex
from .delegation import EffectiveScope
from .denial_latch import LatchedDenial
from .ledger import Ledger, LedgerEntry
from .mandate import Verdict
from .schema import (
    EVENT_SCHEMA_VERSION,
    AgentEvent,
    EventKind,
    new_event_id,
    new_span_id,
    new_trace_id,
    now_monotonic_ns,
    now_ts_device,
)

__all__ = [
    "MAX_VERDICT_BATCH",
    "ClaimedBatch",
    "VerdictOutbox",
    "VerdictRecorder",
    "VerdictShipper",
    "VerdictShipResult",
    "ledger_payload",
    "set_verdict_recorder",
    "use_verdict_recorder",
    "verdict_recorder",
    "wire_verdict",
]

log = logging.getLogger(__name__)

#: Verdicts Coriqo accepts in one batch. Over-cap is a 422, so the cap is
#: enforced here rather than discovered there.
MAX_VERDICT_BATCH = 200

#: The wire fields Coriqo's batch endpoint knows about. Anything else a local
#: record carries — the latch count, the operator detail, the posture — stays
#: local.
_WIRE_FIELDS = (
    "tool",
    "verdict",
    "reason",
    "mandate_version_id",
    "snapshot_age_s",
    "trajectory_id",
    "step_index",
    "decided_at",
)

_OUTBOX_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_verdicts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id   TEXT NOT NULL,
    batch_key  TEXT,
    state      TEXT NOT NULL DEFAULT 'pending',
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    note       TEXT
);
CREATE INDEX IF NOT EXISTS idx_pending_verdicts_state
    ON pending_verdicts(state, agent_id, id);
"""


# -- shaping a verdict -------------------------------------------------------


def wire_verdict(
    verdict: Verdict, *, decided_at: str | None = None
) -> dict[str, Any]:
    """The verdict as Coriqo's batch endpoint wants it.

    ``reason`` is always populated — every verdict this runtime produces
    carries a reason code — which is what keeps a ``flagged`` or ``blocked``
    row from being the 422 the server owes a reasonless one.
    """
    return {
        "tool": verdict.tool,
        "verdict": verdict.verdict,
        "reason": verdict.reason,
        "mandate_version_id": verdict.mandate_version_id,
        "snapshot_age_s": verdict.snapshot_age_s,
        "trajectory_id": verdict.trajectory_id,
        "step_index": verdict.step_index,
        "decided_at": decided_at or now_ts_device(),
    }


def ledger_payload(
    verdict: Verdict,
    *,
    agent_id: str | None,
    latched: LatchedDenial | None = None,
    run_id: str | None = None,
    principal: str | None = None,
    argument_count: int | None = None,
    decided_at: str | None = None,
    effective_scope: EffectiveScope | None = None,
    arguments_sha256: str | None = None,
) -> dict[str, Any]:
    """The fuller local record: the wire fields plus what only an operator sees.

    ``attempts``/``halted``/``run_id`` are what make a latched repeat legible
    as a repeat rather than as another first denial, and ``detail`` is the
    operator sentence that is deliberately kept away from the model.
    ``argument_count`` is a count and never the arguments.

    ``arguments_sha256`` (TI-21) is the SHA-256 of the canonical JSON of the
    arguments, for a caller that hashes them (``coriqo-mcp`` does). The key is
    added only when a hash is given, so every record written without one keeps
    exactly the payload it had before.

    ``run_id``/``principal`` are passed in rather than read off ``latched``,
    which only exists for denials. An allow that did not name its run cannot be
    counted against the denials in that run, and the denominator — "4,120 calls,
    9 of them off-mandate" — is the whole reason allows are recorded.

    ``resource``/``on_behalf_of`` (AIR-7b) are
    the two fields the future CEI envelope builder needs and that are not
    captured anywhere else today:

    - ``resource`` is ``verdict.tool`` — the exact string
      :class:`~byoai.recorder.mandate.ProposedAction` was checked against the
      mandate with (``verdict.tool`` is set from ``action.tool`` in
      ``mandate.py``, so this is the same value as
      ``action.tool``, with no separate plumbing needed).
    - ``on_behalf_of`` is ``list(effective_scope.chain)``, delegator first,
      when ``effective_scope.delegated`` is true; an empty list otherwise (a
      call under the agent's own mandate is on nobody's behalf).

    These live inside ``payload`` rather than as new ``AgentEvent`` dataclass
    fields — see the docstring on ``VerdictRecorder._append`` for why, and for
    why that choice needs none of ``schema.py``'s v1/v2 field-suppression
    machinery to keep a pre-existing event's digest unchanged.
    """
    payload = dict(wire_verdict(verdict, decided_at=decided_at))
    on_behalf_of = (
        list(effective_scope.chain)
        if effective_scope is not None and effective_scope.delegated
        else []
    )
    payload.update(
        {
            "agent_id": agent_id,
            "posture": verdict.posture,
            "enforcement": verdict.enforcement,
            "detail": verdict.detail,
            "run_id": run_id or (latched.run_id if latched is not None else None),
            "principal": principal
            or (latched.principal if latched is not None else None),
            "attempts": latched.attempts if latched is not None else None,
            "latched": bool(latched is not None and latched.attempts > 1),
            "halted": bool(latched is not None and latched.halted),
            "arguments_captured": argument_count,
            "resource": verdict.tool,
            "on_behalf_of": on_behalf_of,
        }
    )
    if arguments_sha256 is not None:
        payload["arguments_sha256"] = arguments_sha256
    return payload


# -- the outbox --------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ClaimedBatch:
    """One batch of verdicts held under a stable ``batch_key``."""

    agent_id: str
    batch_key: str
    ids: tuple[int, ...]
    verdicts: tuple[dict[str, Any], ...]

    def __len__(self) -> int:
        return len(self.ids)


class VerdictOutbox:
    """Durable queue of verdicts waiting to be shipped.

    Separate from the ledger on purpose: the ledger is the record and must not
    be gated on delivery, while this is a delivery queue that a shipper drains.
    A row leaves ``pending`` only once Coriqo has answered about it.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        self._closed = False
        os.makedirs(self.path.parent or Path("."), exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.path), check_same_thread=False, isolation_level=None
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_OUTBOX_SCHEMA)

    def add(self, agent_id: str, body: dict[str, Any]) -> int:
        """Enqueue one verdict. Returns its row id."""
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO pending_verdicts (agent_id, batch_key, state, body, "
                "created_at) VALUES (?, NULL, 'pending', ?, ?)",
                (agent_id, json.dumps(body, sort_keys=True), now_ts_device()),
            )
            return int(cur.lastrowid or 0)

    def pending_count(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM pending_verdicts WHERE state = 'pending'"
            ).fetchone()
            return int(row[0]) if row else 0

    def claim(self, *, limit: int = MAX_VERDICT_BATCH) -> ClaimedBatch | None:
        """Take the next batch, or resume one a previous attempt already took.

        A batch that was claimed but never confirmed keeps its ``batch_key``,
        so the resend is the same batch as far as Coriqo is concerned and
        replays rather than seals twice. Only one agent's verdicts go in a
        batch — the endpoint is per agent.
        """
        limit = max(1, min(int(limit), MAX_VERDICT_BATCH))
        with self._lock:
            resumed = self._resume_claimed()
            if resumed is not None:
                return resumed

            # BEGIN IMMEDIATE, because the connection is in autocommit and one
            # outbox file can be opened by more than one process. Without it,
            # two claimers can read the same unclaimed rows between the SELECT
            # and the UPDATE and stamp two different batch_keys on them, which
            # ships the same verdicts twice and seals two governance events —
            # exactly the double-count batch_key exists to prevent.
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                rows = self._conn.execute(
                    "SELECT id, agent_id, batch_key, body FROM pending_verdicts "
                    "WHERE state = 'pending' AND batch_key IS NULL ORDER BY id LIMIT ?",
                    (limit,),
                ).fetchall()
                if not rows:
                    self._conn.execute("ROLLBACK")
                    return None
                agent_id = rows[0][1]
                rows = [r for r in rows if r[1] == agent_id]
                batch_key = "vb_" + uuid.uuid4().hex
                self._conn.execute(
                    "UPDATE pending_verdicts SET batch_key = ? WHERE id IN "
                    f"({','.join('?' * len(rows))})",
                    (batch_key, *[r[0] for r in rows]),
                )
            except Exception:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")
            return _batch(agent_id, batch_key, rows)

    def _resume_claimed(self) -> ClaimedBatch | None:
        """The whole of an already-claimed batch, or ``None``. Caller holds the lock.

        Deliberately ignores ``limit``. A batch that was claimed and never
        confirmed must go back out *entire*: shipping half of it under the key
        the other half also carries means the first half seals, the second half
        comes back ``duplicate: true``, and those verdicts are marked delivered
        having been sealed nowhere. Resuming a 200-row batch through a shipper
        later reconfigured with a smaller ``max_batch`` is all it would take.
        """
        head = self._conn.execute(
            "SELECT agent_id, batch_key FROM pending_verdicts "
            "WHERE state = 'pending' AND batch_key IS NOT NULL ORDER BY id LIMIT 1"
        ).fetchone()
        if head is None:
            return None
        agent_id, batch_key = head[0], head[1]
        rows = self._conn.execute(
            "SELECT id, agent_id, batch_key, body FROM pending_verdicts "
            "WHERE state = 'pending' AND batch_key = ? AND agent_id = ? ORDER BY id",
            (batch_key, agent_id),
        ).fetchall()
        return _batch(agent_id, batch_key, rows)

    def mark_shipped(self, ids: Sequence[int]) -> None:
        self._set_state(ids, "shipped", None)

    def mark_rejected(self, ids: Sequence[int], note: str) -> None:
        """Park a batch Coriqo refused outright.

        A 422 is a statement about the batch, not about the network, so
        resending it forever would be a loop that never ends. The rows stay in
        the outbox (and in the ledger, which is the record) marked with why —
        dropping them would be the one thing this module exists to prevent.
        """
        self._set_state(ids, "rejected", note[:500])

    def _set_state(self, ids: Sequence[int], state: str, note: str | None) -> None:
        if not ids:
            return
        with self._lock:
            self._conn.execute(
                f"UPDATE pending_verdicts SET state = ?, note = ? WHERE id IN "
                f"({','.join('?' * len(ids))})",
                (state, note, *ids),
            )

    def rows(self, state: str | None = None) -> list[dict[str, Any]]:
        """Every row, or every row in one state. For operators and tests."""
        with self._lock:
            sql = "SELECT id, agent_id, batch_key, state, body, note FROM pending_verdicts"
            params: tuple[Any, ...] = ()
            if state is not None:
                sql += " WHERE state = ?"
                params = (state,)
            rows = self._conn.execute(sql + " ORDER BY id", params).fetchall()
        return [
            {
                "id": r[0],
                "agent_id": r[1],
                "batch_key": r[2],
                "state": r[3],
                "body": json.loads(r[4]),
                "note": r[5],
            }
            for r in rows
        ]

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._conn.close()

    def __enter__(self) -> VerdictOutbox:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _batch(agent_id: str, batch_key: str, rows: list[tuple]) -> ClaimedBatch:
    return ClaimedBatch(
        agent_id=agent_id,
        batch_key=batch_key,
        ids=tuple(int(r[0]) for r in rows),
        verdicts=tuple(json.loads(r[3]) for r in rows),
    )


# -- recording ---------------------------------------------------------------


class VerdictRecorder:
    """Writes a verdict to the ledger, then queues it for shipping.

    Either half is optional: a host with a ledger and no outbox keeps a record
    it never ships, and a host with an outbox and no ledger is a configuration
    this module allows but does not recommend. Neither half is allowed to raise
    into a tool call.
    """

    def __init__(
        self,
        *,
        ledger: Ledger | None = None,
        outbox: VerdictOutbox | None = None,
        device_id: str | None = None,
        session_id: str = "mandate",
        trace_id: str | None = None,
        checkpointer: Any | None = None,
    ) -> None:
        """``checkpointer`` (TI-21) is a
        :class:`~byoai.recorder.checkpoint.Checkpointer` over the same ledger.
        When given, every verdict appended is noted to it, so verdicts get the
        device-signed checkpoints that the recorder's own events get. Without
        one, nothing changes."""
        self._ledger = ledger
        self._outbox = outbox
        self._checkpointer = checkpointer
        self._device_id = device_id or (ledger.device_id if ledger else "unknown-device")
        self._session_id = session_id
        self._trace_id = trace_id or new_trace_id()

    @property
    def ledger(self) -> Ledger | None:
        return self._ledger

    @property
    def outbox(self) -> VerdictOutbox | None:
        return self._outbox

    def record(
        self,
        verdict: Verdict,
        *,
        agent_id: str | None = None,
        latched: LatchedDenial | None = None,
        run_id: str | None = None,
        principal: str | None = None,
        argument_count: int | None = None,
        effective_scope: EffectiveScope | None = None,
        arguments_sha256: str | None = None,
    ) -> LedgerEntry | None:
        """Record one verdict. Returns the ledger entry, if one was written.

        Never raises. A verdict that cannot be written down is logged at
        ``ERROR`` and the call it belongs to proceeds (or is refused) exactly as
        it would have — a governance recorder that breaks the agent it is
        recording gets turned off, and then there is no record at all.

        ``effective_scope`` (AIR-7b) is the delegated scope the call ran
        under, if any — passed through from ``governed_tool``'s resolved gate
        so ``ledger_payload`` can capture ``on_behalf_of``. ``None`` for a
        call under the agent's own mandate.
        """
        try:
            decided_at = now_ts_device()
            payload = ledger_payload(
                verdict,
                agent_id=agent_id,
                latched=latched,
                run_id=run_id,
                principal=principal,
                argument_count=argument_count,
                decided_at=decided_at,
                effective_scope=effective_scope,
                arguments_sha256=arguments_sha256,
            )
            entry = self._append(verdict, payload)
            if entry is not None and self._checkpointer is not None:
                self._checkpointer.note(entry.seq)
            self._enqueue(agent_id, verdict, decided_at)
            return entry
        except Exception:  # noqa: BLE001 - policy: recording never breaks a call
            log.exception("coriqo: failed to record a mandate verdict")
            return None

    def record_worker_ack(self, notice: Any, ack: Any) -> LedgerEntry | None:
        """TI-25: seal one worker's acknowledgement of a suspension.

        ``notice`` is a :class:`~byoai.recorder.suspend.SuspendNotice` and
        ``ack`` a :class:`~byoai.recorder.suspend.WorkerAck`. Written as a
        ``worker_stop_ack`` ledger event, which ships with the rest of the
        ledger; the verdict outbox is not involved, because this is not a
        verdict. Never raises, same as :meth:`record`.
        """
        if self._ledger is None:
            return None
        try:
            payload: dict[str, Any] = {
                "agent_id": notice.agent_id,
                "status": notice.status,
                "mandate_version_id": notice.mandate_version_id,
                "observed_at": notice.observed_at,
                **ack.to_dict(),
            }
            entry = self._append_event(
                EventKind.WORKER_STOP_ACK,
                payload,
                ts_device=ack.acknowledged_at or now_ts_device(),
                tool_name=None,
                session_id=f"suspend-{notice.agent_id or 'agent'}",
            )
            if entry is not None and self._checkpointer is not None:
                self._checkpointer.note(entry.seq)
            return entry
        except Exception:  # noqa: BLE001 - recording never undoes the stop
            log.exception("coriqo: failed to record a worker's suspend acknowledgement")
            return None

    def _append(self, verdict: Verdict, payload: dict[str, Any]) -> LedgerEntry | None:
        """Seal the ``AgentEvent`` for one verdict.

        AIR-7b design decision: ``resource``
        and ``on_behalf_of`` are carried inside ``payload`` (set by
        ``ledger_payload``) rather than as new ``AgentEvent`` dataclass fields.

        The alternative — real fields, versioned additively the way
        ``schema.py``'s v1/v2 split handled ``trace_id``/``span_id`` — would
        need a third schema version (v2 already made those fields required)
        plus matching columns and migration logic in ``ledger.py``
        (``_row_to_entry``, ``_with_seq``, the CREATE TABLE). That is real
        weight for two fields that are naturally payload data: ``payload`` is
        already hashed into ``payload_hash`` and into ``event_digest()`` via
        ``AgentEvent.to_dict()``, so putting them there gets the same
        "captured and covered by the digest" property for free.

        This still satisfies the "must not change the digest of an event
        sealed before this packet" requirement, for a simpler reason than
        ``_V2_ONLY_FIELDS`` needs: a pre-existing ledger row's ``payload`` was
        already written and its digest already computed before this packet
        existed, so it has no ``resource``/``on_behalf_of`` keys and never
        will — nothing here rewrites old rows. Only events sealed from now on
        get the new keys, and their digest is computed once, at write time,
        over whatever ``payload`` holds then.
        """
        return self._append_event(
            EventKind.MANDATE_VERDICT,
            payload,
            ts_device=payload["decided_at"],
            tool_name=verdict.tool,
            session_id=payload.get("run_id") or self._session_id,
        )

    def _append_event(
        self,
        kind: EventKind,
        payload: dict[str, Any],
        *,
        ts_device: str,
        tool_name: str | None,
        session_id: str,
    ) -> LedgerEntry | None:
        if self._ledger is None:
            return None
        event = AgentEvent(
            schema_version=EVENT_SCHEMA_VERSION,
            event_id=new_event_id(),
            device_id=self._device_id,
            session_id=session_id,
            seq=0,  # the ledger assigns the real one
            kind=kind.value,
            ts_device=ts_device,
            ts_monotonic_ns=now_monotonic_ns(),
            tool_use_id=None,
            tool_name=tool_name,
            payload=payload,
            payload_hash=sha256_hex(canonicalize(payload)),
            model=None,
            provider="coriqo-mandate",
            trace_id=self._trace_id,
            span_id=new_span_id(),
        )
        return self._ledger.append(event)

    def _enqueue(
        self, agent_id: str | None, verdict: Verdict, decided_at: str
    ) -> None:
        if self._outbox is None:
            return
        if not agent_id:
            # Nothing to POST it to. The ledger already has it, which is the
            # record; shipping needs an agent the endpoint is addressed by.
            log.debug(
                "coriqo: verdict for %r recorded locally but not queued - no agent id",
                verdict.tool,
            )
            return
        self._outbox.add(agent_id, wire_verdict(verdict, decided_at=decided_at))


_recorder: ContextVar[VerdictRecorder | None] = ContextVar(
    "byoai_verdict_recorder", default=None
)


def verdict_recorder() -> VerdictRecorder | None:
    """The recorder bound in this context, if any. ``None`` records nothing."""
    return _recorder.get()


def set_verdict_recorder(recorder: VerdictRecorder | None):  # noqa: ANN201 - Token[...]
    """Bind ``recorder`` for this context. Returns the token, to ``reset()``."""
    return _recorder.set(recorder)


@contextmanager
def use_verdict_recorder(
    recorder: VerdictRecorder | None,
) -> Iterator[VerdictRecorder | None]:
    """Bind ``recorder`` for the block, then restore the previous one."""
    token = _recorder.set(recorder)
    try:
        yield recorder
    finally:
        _recorder.reset(token)


# -- shipping ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VerdictShipResult:
    """What one batch delivery came back with."""

    agent_id: str
    batch_key: str
    shipped: int
    duplicate: bool
    accepted: int
    stale_mandate_version_count: int
    anchor_mandate_version_id: str | None
    rejected: bool = False

    @property
    def stale(self) -> bool:
        return self.stale_mandate_version_count > 0


class VerdictShipper:
    """Drains a :class:`VerdictOutbox` into Coriqo's verdict batch endpoint.

    One batch per call, so the caller owns the loop and its backoff.
    """

    def __init__(
        self,
        client: Any,
        outbox: VerdictOutbox,
        *,
        max_batch: int = MAX_VERDICT_BATCH,
    ) -> None:
        self._client = client
        self._outbox = outbox
        self._max_batch = max(1, min(int(max_batch), MAX_VERDICT_BATCH))

    async def ship_once(self) -> VerdictShipResult | None:
        """Ship one batch. ``None`` if there was nothing pending.

        A 422 means the batch itself is wrong — over-cap, a reasonless
        ``blocked``, a mandate version belonging to another agent — and no
        amount of resending fixes any of those, so the batch is parked and the
        loop moves on. A ``ValueError`` from the client is the same statement
        made before the request was built and is parked the same way: left to
        propagate it would be a poison pill, since the batch stays claimed and
        every verdict queued behind it starves. Anything else propagates with
        the batch still claimed, so the next attempt resends it under the same
        ``batch_key``.
        """
        batch = self._outbox.claim(limit=self._max_batch)
        if batch is None:
            return None

        try:
            body = await self._client.record_verdict_batch(
                batch.agent_id,
                verdicts=list(batch.verdicts),
                batch_key=batch.batch_key,
            )
        except Exception as exc:  # noqa: BLE001 - status inspected below
            if _is_unprocessable(exc):
                log.error(
                    "coriqo: Coriqo refused verdict batch %s for agent %s and it "
                    "will not be resent (it stays in the local ledger and outbox): %s",
                    batch.batch_key,
                    batch.agent_id,
                    exc,
                )
                self._outbox.mark_rejected(batch.ids, str(exc))
                return VerdictShipResult(
                    agent_id=batch.agent_id,
                    batch_key=batch.batch_key,
                    shipped=len(batch),
                    duplicate=False,
                    accepted=0,
                    stale_mandate_version_count=0,
                    anchor_mandate_version_id=None,
                    rejected=True,
                )
            raise

        body = body if isinstance(body, dict) else {}
        duplicate = bool(body.get("duplicate"))
        stale = _int(body.get("stale_mandate_version_count"))

        # A replay says "I already hold a batch under this key" — not "I hold
        # these rows". If the stored batch is a different size from the one in
        # hand, marking these rows delivered would be recording a seal that
        # never covered them, so they are parked for a human instead.
        # Only an explicit count is usable here. ``accepted`` on a replay is
        # naturally 0 — nothing new was sealed — and reading that as the stored
        # batch size would park every legitimate duplicate.
        stored = body.get("verdict_count")
        if duplicate and stored is not None and _int(stored) != len(batch):
            note = (
                f"Coriqo replayed batch {batch.batch_key} holding {_int(stored)} "
                f"verdicts, but this host has {len(batch)} under that key"
            )
            log.error("coriqo: %s; parking them rather than marking them shipped", note)
            self._outbox.mark_rejected(batch.ids, note)
            return VerdictShipResult(
                agent_id=batch.agent_id,
                batch_key=batch.batch_key,
                shipped=len(batch),
                duplicate=True,
                accepted=0,
                stale_mandate_version_count=stale,
                anchor_mandate_version_id=body.get("anchor_mandate_version_id"),
                rejected=True,
            )

        result = VerdictShipResult(
            agent_id=batch.agent_id,
            batch_key=batch.batch_key,
            shipped=len(batch),
            duplicate=duplicate,
            accepted=_int(body.get("accepted", len(batch))),
            stale_mandate_version_count=stale,
            anchor_mandate_version_id=body.get("anchor_mandate_version_id"),
        )
        # Replaying a stored result is a success, not a failure: the batch is
        # already sealed on Coriqo's side, so marking it shipped is the honest
        # thing to do and the only thing that stops the loop resending it.
        self._outbox.mark_shipped(batch.ids)

        if stale:
            log.warning(
                "coriqo: %d of %d verdicts in batch %s were decided against a "
                "mandate version that is no longer current (anchor is %s). This "
                "host's snapshot has drifted - check the refresh loop.",
                stale,
                len(batch),
                batch.batch_key,
                result.anchor_mandate_version_id,
            )
        if duplicate:
            log.info(
                "coriqo: verdict batch %s was already recorded; Coriqo replayed "
                "the stored result and sealed nothing new",
                batch.batch_key,
            )
        return result

    async def drain(self, *, max_batches: int = 100) -> list[VerdictShipResult]:
        """Ship until the outbox is empty or ``max_batches`` have gone out."""
        results: list[VerdictShipResult] = []
        for _ in range(max_batches):
            result = await self.ship_once()
            if result is None:
                break
            results.append(result)
        return results


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _is_unprocessable(exc: Exception) -> bool:
    """Whether ``exc`` says the batch is malformed rather than that Coriqo is
    busy — a 422 from the server, or the client refusing to build the request
    at all. Both are permanent for these rows, and both must park rather than
    propagate: a batch that keeps failing stays claimed, and everything queued
    behind it never ships."""
    return isinstance(exc, ValueError) or getattr(exc, "status_code", None) == 422
