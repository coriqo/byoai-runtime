"""Signed heartbeat: a liveness entry in the hash chain (completeness C2).

While the recorder process runs, it writes one ``heartbeat`` entry every
``interval_s`` seconds. It is a normal chain entry: it takes the next ``seq``,
links to the previous entry, and is covered by the device-signed checkpoints
like any other. Its payload is ``{last_seq, device_time, interval_s}``.

What a verifier may conclude from one is narrow and stated in
``docs/seal-format.md`` section 4.4: at ``device_time`` the process was alive
and had written the chain up to ``last_seq``. A stretch with no heartbeat
means the process was not running, or could not write. It says nothing about
actions taken outside the recorder.

This is separate from the resend heartbeat in
``byoai.integrations.shield_publish``, which re-sends the last accepted seal
as a transport keep-alive and adds nothing to the chain.

Cadence rules:

* Never while the process is not running (the loop lives in the process).
* At most one on start. If the newest heartbeat in the ledger is younger than
  the interval, start writes none and the first one falls due when that one
  ages out, so a crash loop cannot flood the chain.
* Never a catch-up burst: after a late tick the next one is a full interval
  away, not a backlog of missed ones.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

from .canonical import canonicalize, sha256_hex
from .ledger import Ledger, LedgerEntry
from .redact import RUNTIME_AUTHORED
from .schema import (
    EVENT_SCHEMA_VERSION,
    AgentEvent,
    EventKind,
    format_ts_device,
    new_event_id,
    new_span_id,
    new_trace_id,
    now_monotonic_ns,
)

__all__ = [
    "DEFAULT_HEARTBEAT_INTERVAL_S",
    "HEARTBEAT_SESSION_ID",
    "HeartbeatEmitter",
    "boot_id",
    "hashed_boot_id",
    "build_heartbeat_event",
    "write_disabled_marker",
    "heartbeat_interval_from_env",
]

log = logging.getLogger("byoai.recorder")

DEFAULT_HEARTBEAT_INTERVAL_S = 900.0
HEARTBEAT_SESSION_ID = "byoai-heartbeat"
ENV_VAR = "BYOAI_RECORDER_HEARTBEAT_SECONDS"


def heartbeat_interval_from_env(environ: dict[str, str] | None = None) -> float:
    """Interval in seconds from ``BYOAI_RECORDER_HEARTBEAT_SECONDS``.

    Unset or empty gives the default (900). ``0`` turns the heartbeat off.
    Anything unparseable or negative falls back to the default with a warning,
    never to "off": a typo must not silently stop the liveness record.
    """
    import os

    raw = (environ if environ is not None else os.environ).get(ENV_VAR, "").strip()
    if not raw:
        return DEFAULT_HEARTBEAT_INTERVAL_S
    try:
        value = float(raw)
    except ValueError:
        value = -1.0
    if value < 0 or value != value or value == float("inf"):
        log.warning(
            "recorder: %s=%r is not a number of seconds >= 0, using %ds",
            ENV_VAR, raw, int(DEFAULT_HEARTBEAT_INTERVAL_S),
        )
        return DEFAULT_HEARTBEAT_INTERVAL_S
    return value


def _parse_device_time(value: object) -> float | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def boot_id() -> str | None:
    """An identifier of this boot of the host, or ``None`` when the platform
    gives none cheaply and without a subprocess. Linux: the kernel's
    ``boot_id``. macOS: ``kern.boottime`` through ``sysctlbyname`` (the kernel
    can adjust it when the clock is stepped, which only makes a verifier skip a
    comparison). Used to compare the monotonic counter only within one boot."""
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="ascii") as fh:
            value = fh.read().strip()
            if value:
                return value
    except OSError:
        pass
    try:
        import ctypes
        import ctypes.util
        import sys

        if sys.platform != "darwin":
            return None
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        buf = ctypes.create_string_buffer(16)
        size = ctypes.c_size_t(16)
        if libc.sysctlbyname(b"kern.boottime", buf, ctypes.byref(size), None, 0) != 0:
            return None
        return f"boottime:{int.from_bytes(buf.raw[:8], 'little')}"
    except Exception:  # noqa: BLE001 - optional hint, never an error
        return None


_BOOT_ID = boot_id()


def hashed_boot_id(device_id: str, raw: str) -> str:
    """What goes into a signed, shared ledger: ``sha256(device_id || raw)[:16]``
    in hex. The raw value (on macOS the exact boot time) is not stored; a
    verifier only compares two of these for equality within one record."""
    return hashlib.sha256((device_id + raw).encode("utf-8")).hexdigest()[:16]


def build_heartbeat_event(
    device_id: str, last_seq: int, interval_s: float, now: float,
    monotonic_ns: int | None = None,
) -> AgentEvent:
    """The ``heartbeat`` event for ``last_seq`` at wall time ``now``.

    ``interval_s == 0`` is the "heartbeats disabled" declaration (see
    :func:`write_disabled_marker`).
    """
    device_time = format_ts_device(datetime.fromtimestamp(now, tz=timezone.utc))
    # Stored in full in every payload mode: the fields are numbers and a
    # timestamp the recorder wrote itself, so there is nothing to redact, and
    # payload_hash == H(C(payload)) can be checked. interval_s is an integer
    # when whole, so the usual setting hashes the same in every language's
    # canonical-JSON encoder.
    interval = float(interval_s)
    payload = {
        "last_seq": last_seq,
        "device_time": device_time,
        "interval_s": int(interval) if interval.is_integer() else interval,
    }
    if _BOOT_ID is not None:
        # New entries only; an old entry's payload (and hash) is unchanged.
        payload["boot_id"] = hashed_boot_id(device_id, _BOOT_ID)
    return AgentEvent(
        schema_version=EVENT_SCHEMA_VERSION,
        event_id=new_event_id(),
        device_id=device_id,
        session_id=HEARTBEAT_SESSION_ID,
        seq=0,  # stamped by the ledger
        kind=EventKind.HEARTBEAT.value,
        ts_device=device_time,
        ts_monotonic_ns=now_monotonic_ns() if monotonic_ns is None else monotonic_ns,
        tool_use_id=None,
        tool_name=None,
        payload=payload,
        payload_hash=sha256_hex(canonicalize(payload)),
        model=None,
        provider="byoai-recorder",
        trace_id=new_trace_id(),
        span_id=new_span_id(),
    )


def write_disabled_marker(
    ledger: Ledger,
    device_id: str,
    *,
    wall_clock: Callable[[], float] = time.time,
) -> LedgerEntry | None:
    """Write one signed ``heartbeat`` entry declaring ``interval_s: 0``, so the
    chain itself says heartbeats were off from this point. Skipped when the
    newest heartbeat in the ledger is already such a marker, so restarts with
    heartbeats still off do not add entries."""
    last = ledger.last_entry_of_kind(EventKind.HEARTBEAT)
    if last is not None and isinstance(last.event.payload, dict) \
            and last.event.payload.get("interval_s") == 0:
        return None
    return ledger.append_stamped(
        lambda last_seq: build_heartbeat_event(device_id, last_seq, 0, wall_clock()),
        payload_mode=RUNTIME_AUTHORED,
    )


class HeartbeatEmitter:
    """Writes heartbeat entries on a schedule. Clocks are injectable so tests
    never sleep."""

    def __init__(
        self,
        ledger: Ledger,
        device_id: str,
        *,
        interval_s: float = DEFAULT_HEARTBEAT_INTERVAL_S,
        on_entry: Callable[[LedgerEntry], None] | None = None,
        wall_clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if interval_s <= 0:
            raise ValueError("interval_s must be > 0 (use 0 in the env var to disable)")
        self._ledger = ledger
        self._device_id = device_id
        self.interval_s = float(interval_s)
        self._on_entry = on_entry
        self._wall = wall_clock
        self._mono = monotonic
        self._next_due: float | None = None  # monotonic; None until start()

    # ------------------------------------------------------------ schedule

    def start(self) -> LedgerEntry | None:
        """Arm the schedule. Writes the one start heartbeat unless the newest
        one in the ledger is still younger than the interval."""
        last = self._ledger.last_entry_of_kind(EventKind.HEARTBEAT)
        payload = last.event.payload if last is not None else None
        if isinstance(payload, dict) and payload.get("interval_s") != 0:
            # (a "disabled" marker is not a liveness reading)
            t = _parse_device_time(payload.get("device_time"))
            age = None if t is None else self._wall() - t
            if age is not None and 0 <= age < self.interval_s:
                self._next_due = self._mono() + (self.interval_s - age)
                return None
        return self._emit()

    def tick(self) -> LedgerEntry | None:
        """Write one heartbeat if one is due. Never more than one per call."""
        if self._next_due is None:
            return self.start()
        if self._mono() >= self._next_due:
            return self._emit()
        return None

    def seconds_until_due(self) -> float:
        if self._next_due is None:
            return 0.0
        return max(0.0, self._next_due - self._mono())

    def run_forever(self, *, stop: threading.Event) -> None:
        """Loop until ``stop`` is set. Never raises."""
        try:
            self.start()
        except Exception:  # noqa: BLE001
            log.exception("recorder: heartbeat start failed")
            self._next_due = self._mono() + self.interval_s
        while not stop.wait(max(0.05, min(self.seconds_until_due(), self.interval_s))):
            try:
                self.tick()
            except Exception:  # noqa: BLE001 - liveness must never take the process down
                log.exception("recorder: heartbeat failed")
                self._next_due = self._mono() + self.interval_s

    # ------------------------------------------------------------- writing

    def _emit(self) -> LedgerEntry | None:
        # Re-arm first: a failed write waits a full interval instead of
        # retrying in a tight loop.
        self._next_due = self._mono() + self.interval_s

        def build(last_seq: int) -> AgentEvent:
            return build_heartbeat_event(
                self._device_id, last_seq, self.interval_s, self._wall(),
                int(self._mono() * 1e9),
            )

        entry = self._ledger.append_stamped(build, payload_mode=RUNTIME_AUTHORED)
        if entry is not None and self._on_entry is not None:
            try:
                self._on_entry(entry)
            except Exception:  # noqa: BLE001
                log.exception("recorder: heartbeat callback failed")
        return entry
