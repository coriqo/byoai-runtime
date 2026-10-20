"""Event schema for the agent recorder.

One immutable record type (:class:`AgentEvent`) plus the helpers that make it
hashable in a way a third party can reproduce: canonical dict form, a
deterministic digest, and the capture clocks.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, fields
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from .canonical import canonicalize, sha256_hex

__all__ = [
    "EVENT_SCHEMA_VERSION",
    "EVENT_SCHEMA_VERSION_V1",
    "AgentEvent",
    "EventKind",
    "canonicalize",
    "event_digest",
    "format_ts_device",
    "new_event_id",
    "new_trace_id",
    "new_span_id",
    "now_monotonic_ns",
    "now_ts_device",
    "set_device_clock",
    "sha256_hex",
]

# v1: no trace attribution fields. v2: adds trace_id/span_id/
# parent_span_id/continues_from. Kept as two constants (not just "current"
# and "legacy") because ledger.py and verify.py both need to name the old
# version explicitly when deciding which fields feed a given row's digest.
EVENT_SCHEMA_VERSION_V1 = "1"
EVENT_SCHEMA_VERSION = "2"

# Fields that exist only from schema v2 onward. A v1 event's to_dict() must
# never include these — they were not part of the payload whose digest is
# already sealed in the ledger, so including them (even as None) would change
# the digest of every pre-existing row. See event_digest()/to_dict() below and
# ledger.py's migration notes.
_V2_ONLY_FIELDS = frozenset({"trace_id", "span_id", "parent_span_id", "continues_from"})


class EventKind(str, Enum):
    """Kinds of event the recorder can seal."""

    TOOL_USE = "tool_use"
    TOOL_RESULT = "tool_result"
    MESSAGE = "message"
    API_ERROR = "api_error"
    RECORD_FAILURE = "record_failure"
    SESSION_START = "session_start"
    STREAM_ABORTED = "stream_aborted"
    PARSE_FAILURE = "parse_failure"
    KEY_ROTATED = "key_rotated"
    #: One mandate gate decision — allowed, flagged or blocked alike.
    #: Written by byoai.recorder.verdicts, which is also where the reason
    #: codes that tell a first denial from a latched repeat are set.
    MANDATE_VERDICT = "mandate_verdict"
    #: A third-party guardrail that actually fired mid-run — today only AWS
    #: Bedrock's, sealed by byoai.recorder.bedrock_agent. Distinct from
    #: MANDATE_VERDICT because the decision was not ours and carries none of
    #: our reason codes; distinct from API_ERROR because nothing failed.
    GUARDRAIL_INTERVENTION = "guardrail_intervention"
    #: TI-25: one worker's acknowledgement that the agent was suspended — an
    #: ``on_suspend`` hook returning, or a child process exiting after
    #: SIGTERM/SIGKILL. Written by byoai.recorder.verdicts from
    #: byoai.recorder.suspend.
    WORKER_STOP_ACK = "worker_stop_ack"


@dataclass(frozen=True, slots=True)
class AgentEvent:
    """A single sealed observation about an agent's behaviour.

    ``seq`` is assigned by the ledger at write time; everything else is filled
    in at capture. The instance is frozen because a digest over a mutable
    record is not evidence.
    """

    schema_version: str
    event_id: str
    device_id: str
    session_id: str
    seq: int
    kind: str
    ts_device: str
    ts_monotonic_ns: int
    tool_use_id: str | None
    tool_name: str | None
    payload: dict[str, Any]
    payload_hash: str
    model: str | None
    provider: str
    # v2 trace attribution. trace_id/span_id are required for
    # every event captured going forward; parent_span_id/continues_from are
    # nullable (absent means "top-level agent" / "not a resumed session").
    # Legacy v1 rows loaded off disk get placeholder "" values here (see
    # ledger.py's _row_to_entry) — never observable via to_dict()/the hash,
    # since those are suppressed for schema_version == "1" below.
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    continues_from: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Plain-JSON dict form. Key order is irrelevant to the digest.

        For a v1 event, the v2-only trace fields are omitted entirely (not
        emitted as null) so that recomputing the digest of a pre-existing v1
        ledger row reproduces exactly what was hashed at write time, before
        those fields existed.
        """
        d = {f.name: getattr(self, f.name) for f in fields(self)}
        if self.schema_version == EVENT_SCHEMA_VERSION_V1:
            for name in _V2_ONLY_FIELDS:
                d.pop(name, None)
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AgentEvent:
        """Inverse of :meth:`to_dict`. Rejects missing or unknown fields.

        A v1-shaped dict (``schema_version == "1"``) is allowed to omit the
        v2-only trace fields; they are filled in with inert placeholders so
        construction succeeds, matching what :meth:`to_dict` does in reverse.
        """
        names = {f.name for f in fields(cls)}
        is_v1 = data.get("schema_version") == EVENT_SCHEMA_VERSION_V1
        expected = names - _V2_ONLY_FIELDS if is_v1 else names
        missing = expected - data.keys()
        if missing:
            raise ValueError(f"missing event fields: {sorted(missing)}")
        unknown = data.keys() - expected
        if unknown:
            raise ValueError(f"unknown event fields: {sorted(unknown)}")
        kwargs = {name: data[name] for name in expected}
        if is_v1:
            kwargs.setdefault("trace_id", "")
            kwargs.setdefault("span_id", "")
            kwargs.setdefault("parent_span_id", None)
            kwargs.setdefault("continues_from", None)
        return cls(**kwargs)


def event_digest(event: AgentEvent) -> str:
    """``"sha256:<hex>"`` over the canonical JSON of the whole event.

    Deterministic: canonicalization sorts keys, so the digest does not depend
    on insertion order anywhere in the event or its payload.
    """
    return sha256_hex(canonicalize(event.to_dict()))


def new_event_id() -> str:
    """Fresh ``evt_``-prefixed identifier."""
    return "evt_" + uuid.uuid4().hex


def new_trace_id() -> str:
    """Fresh ``tr_``-prefixed identifier for the root of one logical run."""
    return "tr_" + uuid.uuid4().hex


def new_span_id() -> str:
    """Fresh ``sp_``-prefixed identifier for one agent invocation."""
    return "sp_" + uuid.uuid4().hex


def format_ts_device(dt: datetime) -> str:
    """Format an arbitrary UTC ``datetime`` as RFC3339 with microsecond
    precision, e.g. ``2026-08-05T14:22:31.442123Z``. Pure formatting — no
    clock access — so any caller with its own datetime (e.g. one derived from
    an epoch timestamp) can share the exact same shape as :func:`now_ts_device`.
    """
    utc = dt.astimezone(timezone.utc) if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond:06d}Z"


_device_clock: Callable[[], datetime] | None = None


def set_device_clock(clock: Callable[[], datetime] | None) -> Callable[[], datetime] | None:
    """Replace the wall clock behind :func:`now_ts_device`; ``None`` restores
    the real one. Returns the previous clock so a caller can put it back.

    For replaying or backfilling recorded work at the time it happened. It is
    safe to expose because ``ts_device`` was never trusted: ordering and
    integrity come from ``seq`` and the hash chain, not from this value."""
    global _device_clock
    previous = _device_clock
    _device_clock = clock
    return previous


def now_ts_device() -> str:
    """RFC3339 UTC timestamp with microsecond precision, e.g.
    ``2026-08-05T14:22:31.442123Z``. Untrusted host clock — ordering comes
    from ``seq``, never from this value."""
    clock = _device_clock
    return format_ts_device(clock() if clock is not None else datetime.now(timezone.utc))


def now_monotonic_ns() -> int:
    """Monotonic capture counter, immune to wall-clock adjustment."""
    return time.monotonic_ns()
