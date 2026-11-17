"""Signed checkpoints over the device chain (``docs/seal-format.md`` §8).

Every ``every_events`` events or ``every_seconds`` seconds — whichever comes
first — the device emits::

    {device_id, seq_start, seq_end, chain_head, ts_device, sig}

where ``sig`` covers ``canonicalize(checkpoint minus sig)``. The checkpoint is
what a tenant-level Merkle tree is built over, so it must be reproducible byte
for byte by an offline verifier holding only the ledger and the public key.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from byoai.recorder.canonical import canonicalize
from byoai.recorder.keys import DeviceKey
from byoai.recorder.ledger import LedgerHeadError
from byoai.recorder.schema import format_ts_device

if TYPE_CHECKING:  # pragma: no cover
    from byoai.recorder.ledger import Ledger

__all__ = [
    "DEFAULT_EVERY_EVENTS",
    "DEFAULT_EVERY_SECONDS",
    "Checkpointer",
    "checkpoint_signing_bytes",
    "verify_checkpoint",
]

DEFAULT_EVERY_EVENTS = 256
DEFAULT_EVERY_SECONDS = 60.0

# Field order is irrelevant to the signature (canonicalization sorts keys) but
# the set of signed fields is not: everything except `sig` is covered.
_SIG_FIELD = "sig"


def checkpoint_signing_bytes(checkpoint: dict[str, Any]) -> bytes:
    """The exact bytes a checkpoint signature covers."""
    return canonicalize({k: v for k, v in checkpoint.items() if k != _SIG_FIELD})


def verify_checkpoint(checkpoint: dict[str, Any], public_key_b64: str) -> bool:
    """True if ``checkpoint`` carries a valid signature for ``public_key_b64``."""
    sig = checkpoint.get(_SIG_FIELD)
    if not isinstance(sig, str):
        return False
    return DeviceKey.verify(public_key_b64, checkpoint_signing_bytes(checkpoint), sig)


def _rfc3339_utc(epoch_seconds: float) -> str:
    return format_ts_device(datetime.fromtimestamp(epoch_seconds, tz=timezone.utc))


class Checkpointer:
    """Emit a signed checkpoint every N events or T seconds, whichever first.

    Call :meth:`note` with each seq the ledger assigned. Call :meth:`flush` on
    shutdown: it emits a final checkpoint covering any events that have not been
    checkpointed yet, and returns ``None`` when there are none — a shutdown must
    never write an empty or duplicate checkpoint.
    """

    def __init__(
        self,
        ledger: Ledger,
        key: DeviceKey,
        *,
        every_events: int = DEFAULT_EVERY_EVENTS,
        every_seconds: float = DEFAULT_EVERY_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
    ) -> None:
        if every_events < 1:
            raise ValueError("every_events must be >= 1")
        if every_seconds <= 0:
            raise ValueError("every_seconds must be > 0")
        self._ledger = ledger
        self._key = key
        self._every_events = every_events
        self._every_seconds = every_seconds
        self._monotonic = monotonic
        self._wall_clock = wall_clock

        # note() runs on request threads and, since C2, on the heartbeat
        # thread too; the pending window must change under one lock.
        self._lock = threading.RLock()
        self._pending_start: int | None = None
        self._pending_end: int | None = None
        self._pending_count = 0
        self._window_started_at = monotonic()
        self._last_emitted_end: int | None = None

    # -- introspection ----------------------------------------------------

    @property
    def pending_events(self) -> int:
        return self._pending_count

    @property
    def last_checkpointed_seq(self) -> int | None:
        return self._last_emitted_end

    # -- driving ----------------------------------------------------------

    def note(self, seq: int) -> dict | None:
        with self._lock:
            return self._note(seq)

    def _note(self, seq: int) -> dict | None:
        """Record that the ledger appended ``seq``. Returns a checkpoint if due."""
        if self._last_emitted_end is not None and seq <= self._last_emitted_end:
            # Noted late: a checkpoint already covers it (threads can note out
            # of seq order, since append and note are not one atomic step).
            return None
        if self._pending_start is None:
            self._pending_start = seq
            # The clock window starts with the first uncheckpointed event, not
            # at construction: an idle recorder must not emit empty checkpoints.
            self._window_started_at = self._monotonic()
        self._pending_start = min(self._pending_start, seq)
        self._pending_end = seq if self._pending_end is None else max(self._pending_end, seq)
        self._pending_count += 1

        if self._pending_count >= self._every_events:
            return self._emit()
        if self._monotonic() - self._window_started_at >= self._every_seconds:
            return self._emit()
        return None

    def tick(self) -> dict | None:
        with self._lock:
            return self._tick()

    def _tick(self) -> dict | None:
        """Emit if the time trigger has fired, without a new event arriving."""
        if self._pending_count == 0:
            return None
        if self._monotonic() - self._window_started_at >= self._every_seconds:
            return self._emit()
        return None

    def flush(self) -> dict | None:
        with self._lock:
            return self._flush()

    def _flush(self) -> dict | None:
        """Force a checkpoint on shutdown. ``None`` if nothing is pending."""
        if self._pending_count == 0:
            return None
        return self._emit()

    # -- internals --------------------------------------------------------

    def _emit(self) -> dict | None:
        assert self._pending_start is not None and self._pending_end is not None
        seq_start, seq_end = self._pending_start, self._pending_end
        snapshot = getattr(self._ledger, "snapshot", None)
        if snapshot is not None:
            # Cover everything written so far and sign the hash that belongs
            # to that seq, both read under the ledger lock. Reading ``head``
            # separately signs whatever another thread appended meanwhile.
            try:
                last_seq, chain_head, snapped_at = snapshot(self._wall_clock)
            except LedgerHeadError:
                # The ledger already logged it and queued a record_failure.
                # Sign nothing; keep the pending window so a later try can.
                return None
            if self._last_emitted_end is not None and last_seq <= self._last_emitted_end:
                return None  # nothing verified beyond what is already signed
            seq_end = max(seq_end, last_seq)
            if self._last_emitted_end is not None:
                seq_start = min(seq_start, self._last_emitted_end + 1)
        else:
            chain_head = self._ledger.head
            snapped_at = self._wall_clock()
        checkpoint: dict[str, Any] = {
            "device_id": self._key.device_id,
            "seq_start": seq_start,
            "seq_end": seq_end,
            "chain_head": chain_head,
            "ts_device": _rfc3339_utc(snapped_at),
        }
        checkpoint[_SIG_FIELD] = self._key.sign(checkpoint_signing_bytes(checkpoint))

        self._ledger.append_checkpoint(checkpoint)

        self._last_emitted_end = seq_end
        self._pending_start = None
        self._pending_end = None
        self._pending_count = 0
        self._window_started_at = self._monotonic()
        return checkpoint
