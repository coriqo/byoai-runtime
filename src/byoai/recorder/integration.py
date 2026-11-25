"""Wires the recorder's capture pipeline into a running proxy.

Everything else in this package is a pure library. This module is the one
place that owns process-lifetime state: the on-disk ledger, the device key,
and the checkpoint scheduler, all gated behind ``BYOAI_RECORDER_ENABLED``.

Failure posture: recording must never add latency to or block the
token stream, and it must never crash the request path. Every public method
here swallows its own exceptions except for the one case called out
explicitly — ``strict_mode`` plus a ledger write failure — which the caller
is expected to turn into a 503.
"""

from __future__ import annotations

import logging
import os
import secrets
import threading
import weakref
from pathlib import Path
from typing import TYPE_CHECKING

from .canonical import canonicalize, sha256_hex
from .extract import PartialEvent, StreamExtractor, extract_request_events, extract_response_events
from .ledger import Ledger, LedgerWriteError
from .redact import PayloadMode, apply_payload_mode
from .schema import AgentEvent, new_event_id

if TYPE_CHECKING:
    from .checkpoint import Checkpointer
    from .keys import DeviceKey
    from .shipper import Shipper

log = logging.getLogger("byoai.recorder")

#: Recorders that need their heartbeat thread restarted in a forked child.
_LIVE_RECORDERS: weakref.WeakSet[Recorder] = weakref.WeakSet()


#: Per-thread: the ledger locks THIS thread took in ``_before_fork``, so
#: ``_after_fork_in_parent`` releases exactly those and never one that another
#: forking thread owns.
_FORK_LOCAL = threading.local()
#: How long ``fork()`` may wait for a busy ledger before going ahead without it.
FORK_LOCK_TIMEOUT_S = 1.0
_fork_warned = False


def _held() -> list[threading.RLock]:
    held = getattr(_FORK_LOCAL, "held", None)
    if held is None:
        held = _FORK_LOCAL.held = []
    return held


def _before_fork() -> None:
    # Hold every live ledger's lock across fork(), so no thread of ours is inside
    # SQLite when the child is cloned (a child that inherits a half-finished
    # SQLite call can deadlock on its first query). Fixed order (by id) so two
    # threads, or two Recorders, never lock in opposite orders. Bounded wait: a
    # fork (also ``subprocess`` with ``preexec_fn``) must not stall behind a slow
    # append; on timeout go ahead without that lock and warn once.
    global _fork_warned
    try:
        locks = sorted((rec.ledger._lock for rec in list(_LIVE_RECORDERS)), key=id)
    except RuntimeError:  # the set changed while copying; skip rather than fail fork
        return
    held = _held()
    for lock in locks:
        if lock.acquire(timeout=FORK_LOCK_TIMEOUT_S):
            held.append(lock)
        elif not _fork_warned:
            _fork_warned = True
            log.warning(
                "recorder: a ledger write was still running after %.0fs; forking without "
                "its lock (the child reopens its own connection)", FORK_LOCK_TIMEOUT_S,
            )


def _after_fork_in_parent() -> None:
    held = _held()
    while held:
        held.pop().release()


def _restart_after_fork() -> None:
    # Only cheap state swaps here. A child that just execs (subprocess with
    # preexec_fn) must not open a connection or start a thread: the ledger
    # reopens, and the heartbeat restarts, on the child's first use of it.
    _held().clear()  # the child's copies of the parent's locks are replaced below
    for rec in list(_LIVE_RECORDERS):
        rec._after_fork_in_child()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(
        before=_before_fork,
        after_in_parent=_after_fork_in_parent,
        after_in_child=_restart_after_fork,
    )

__all__ = ["Recorder", "get_recorder", "reset_recorder_for_tests"]


def _default_dir() -> Path:
    return Path(os.getenv("BYOAI_RECORDER_DIR", str(Path.home() / ".byoai" / "recorder")))


class Recorder:
    """Promotes captured events into the sealed ledger for one device."""

    def __init__(
        self,
        *,
        dir: Path | str | None = None,  # noqa: A002
        strict_mode: bool | None = None,
        payload_mode: PayloadMode = PayloadMode.REDACTED,
    ) -> None:
        # Imported lazily: both need `cryptography`, which lives behind the
        # `byoai-runtime[recorder]` extra. A base install must be able to
        # import this module (and the rest of the proxy) without it —
        # cryptography is only required once recording is actually enabled.
        from .checkpoint import Checkpointer
        from .keys import load_or_create_device_key

        base = Path(dir) if dir is not None else _default_dir()
        base.mkdir(parents=True, exist_ok=True)
        self.strict_mode = (
            strict_mode
            if strict_mode is not None
            else os.getenv("BYOAI_RECORDER_STRICT", "0") == "1"
        )
        self.payload_mode = payload_mode
        # Per-process/session salt for low-entropy field hashing in redacted
        # mode. Generated once and held for the instance's
        # lifetime — not per-event.
        self._session_salt = secrets.token_hex(16)
        self.key: DeviceKey = load_or_create_device_key(base)
        self.ledger = Ledger(base / "ledger.db", self.key.device_id, strict_mode=self.strict_mode)
        self.checkpointer: Checkpointer = Checkpointer(self.ledger, self.key)

        self._heartbeat_stop: threading.Event | None = None
        self._heartbeat_thread: threading.Thread | None = None
        self._heartbeat_interval_s = 0.0
        self._shipper: Shipper | None = None
        self._shipper_stop: threading.Event | None = None
        self._shipper_thread: threading.Thread | None = None
        self._start_shipper(base)

        self._receipt_fetcher = None
        self._start_receipt_fetcher()

        self._start_heartbeat()
        _LIVE_RECORDERS.add(self)

    def runtime_info(self) -> dict | None:
        """What this process may tell a server about itself: ``None`` unless
        the heartbeat thread is running, so ``heartbeat_chain_v1`` is never
        claimed while heartbeats are off or failed to start. The server should
        treat it as self-asserted (covered only by the body signature)."""
        t = self._heartbeat_thread
        if t is None or not t.is_alive() or self._heartbeat_interval_s <= 0:
            return None
        from .shipper import runtime_info as _info

        return _info(self._heartbeat_interval_s)

    def _after_fork_in_child(self) -> None:
        """Mark this recorder as forked. Nothing is opened or started here.

        The ledger gets a fresh lock (one a vanished thread held would never
        release) and reopens its own SQLite connection on first use; the
        heartbeat thread restarts at that moment too, so a child that only
        execs does neither. Each forked worker that uses the ledger writes its
        own heartbeats into the shared ledger: N workers write N times the
        volume, and under ``gunicorn --preload`` the master heartbeats too
        (N + 1 writers).
        """
        self.ledger.mark_forked_in_child()
        self.checkpointer._lock = threading.RLock()
        self._heartbeat_stop = None
        self._heartbeat_thread = None
        if self._heartbeat_interval_s > 0:
            self.ledger.after_reopen = self._restart_heartbeat_in_child

    def _restart_heartbeat_in_child(self) -> None:
        log.warning(
            "recorder: forked; restarting the heartbeat thread in pid %d "
            "(the shipper thread is not restarted)", os.getpid(),
        )
        self._start_heartbeat()

    def _start_heartbeat(self) -> None:
        """Write a signed ``heartbeat`` chain entry on a timer (C2).

        ``BYOAI_RECORDER_HEARTBEAT_SECONDS`` sets the interval (default 900,
        ``0`` = off). Runs only while this process runs; see
        :mod:`byoai.recorder.heartbeat` for the cadence rules.
        """
        from .heartbeat import HeartbeatEmitter, heartbeat_interval_from_env

        interval = heartbeat_interval_from_env()
        self._heartbeat_interval_s = interval
        if interval <= 0:
            log.info("recorder: heartbeat off (BYOAI_RECORDER_HEARTBEAT_SECONDS=0)")
            # Say so in the chain: a verifier must not read "no heartbeats"
            # as "none were written" when the operator turned them off.
            try:
                from .heartbeat import write_disabled_marker

                entry = write_disabled_marker(self.ledger, self.key.device_id)
                if entry is not None:
                    self.checkpointer.note(entry.seq)
            except Exception:  # noqa: BLE001
                log.exception("recorder: could not write the heartbeat-disabled marker")
            return
        try:
            emitter = HeartbeatEmitter(
                self.ledger,
                self.key.device_id,
                interval_s=interval,
                on_entry=self._after_heartbeat,
            )
            self._heartbeat_stop = threading.Event()
            self._heartbeat_thread = threading.Thread(
                target=emitter.run_forever,
                kwargs={"stop": self._heartbeat_stop},
                name="byoai-recorder-heartbeat",
                daemon=True,
            )
            self._heartbeat_thread.start()
        except Exception:  # noqa: BLE001
            log.exception("recorder: failed to start heartbeat")
            self._heartbeat_stop = None
            self._heartbeat_thread = None

    def _after_heartbeat(self, entry) -> None:
        # Feed the checkpoint window like any other entry. The next note (the
        # next heartbeat at the latest) fires the time trigger, so an idle
        # recorder gets about one checkpoint per two heartbeats, and close()
        # flushes the rest.
        self.checkpointer.note(entry.seq)

    def _start_receipt_fetcher(self) -> None:
        """Fetch evidence receipts in the background (R-3).

        OFF by default. Set ``BYOAI_RECORDER_RECEIPTS=1`` to turn it on. It
        stays off until Coriqo's ``/api/v1/receipts`` route is deployed; flip
        the default to on after that merge. Needs the Coriqo agents credentials
        in the environment. Receipt GETs are signed with this recorder's device
        key, not the API key.
        """
        if os.getenv("BYOAI_RECORDER_RECEIPTS", "0") != "1":
            return
        client = None
        try:
            from .coriqo_agents import CoriqoAgentsClient, CoriqoCredentials
            from .receipts import ReceiptFetcher, ReceiptStore

            creds = CoriqoCredentials.from_env()
            if creds is None:
                return
            client = CoriqoAgentsClient(creds, device_signer=self.key)
            self._receipt_fetcher = ReceiptFetcher(
                client, ReceiptStore.for_ledger(self.ledger), owns_client=True
            ).start()
        except Exception:  # noqa: BLE001
            log.exception("recorder: failed to start receipt fetcher")
            self._receipt_fetcher = None
            if client is not None:
                client.close()

    def _start_shipper(self, base: Path) -> None:
        # Shipping requires both an enrolled device (we need a device_id
        # Coriqo recognizes) and a configured Coriqo URL. Either being
        # absent just means "not shipping yet" — not an error.
        from .enroll import EnrollmentError, load_enrollment_state
        from .shipper import Shipper

        try:
            state = load_enrollment_state(base)
        except EnrollmentError:
            log.exception("recorder: enrollment state is corrupt, shipper disabled")
            return
        if state is None:
            log.info("recorder: not enrolled, shipper disabled (run byoai-recorder-enroll)")
            return
        try:
            self._shipper = Shipper(
                self.ledger,
                self.key,
                coriqo_base_url=state.coriqo_base_url,
                tenant_slug=state.tenant_slug,
                runtime_info=self.runtime_info,
                payload_mode=self.payload_mode.value,
            )
            self._shipper_stop = threading.Event()
            self._shipper_thread = threading.Thread(
                target=self._shipper.run_forever,
                kwargs={"stop": self._shipper_stop},
                name="byoai-recorder-shipper",
                daemon=True,
            )
            self._shipper_thread.start()
        except Exception:  # noqa: BLE001
            log.exception("recorder: failed to start shipper, will not sync to Coriqo")
            self._shipper = None
            self._shipper_stop = None
            self._shipper_thread = None

    def close(self, *, final_ship: bool = False) -> None:
        """Stop the shipper and close the ledger.

        ``final_ship`` sends what is still unsent once more after the shipper
        thread has stopped. Without it, an entry written in the last few
        seconds before exit waits on disk for the next run. A process that
        writes its last word on the way out (coriqo-mcp's record of stopping
        its server, TI-25) passes True. A failure is logged, not raised.
        """
        if self._heartbeat_stop is not None:
            self._heartbeat_stop.set()
        if self._heartbeat_thread is not None:
            self._heartbeat_thread.join(timeout=5.0)
        if self._receipt_fetcher is not None:
            self._receipt_fetcher.stop()  # closes its client once the thread has exited
        try:
            if self._shipper_stop is not None:
                self._shipper_stop.set()
            if self._shipper_thread is not None:
                self._shipper_thread.join(timeout=5.0)
            if (
                final_ship
                and self._shipper is not None
                and not (self._shipper_thread is not None and self._shipper_thread.is_alive())
            ):
                try:
                    self._shipper.ship_once()
                except Exception as exc:  # noqa: BLE001 - unsent entries stay on disk
                    log.warning(
                        "recorder: last send before exit failed (%s); the entries "
                        "stay in the ledger and go with the next run", exc,
                    )
            if self._shipper is not None:
                self._shipper.close()
        finally:
            try:
                self.checkpointer.flush()
            finally:
                self.ledger.close()

    # ------------------------------------------------------------- capture

    def _promote(self, partial: PartialEvent) -> AgentEvent:
        # payload_hash always commits to the RAW, unredacted payload —
        # this must never change regardless of payload_mode.
        payload_hash = sha256_hex(canonicalize(partial.payload))
        shipped_payload = apply_payload_mode(
            partial.payload, self.payload_mode, session_salt=self._session_salt,
            kind=partial.kind,
        )
        return AgentEvent(
            schema_version=partial.schema_version,
            event_id=new_event_id(),
            device_id=self.key.device_id,
            session_id=partial.session_id,
            seq=0,  # stamped by Ledger.append
            kind=partial.kind,
            ts_device=partial.ts_device,
            ts_monotonic_ns=partial.ts_monotonic_ns,
            tool_use_id=partial.tool_use_id,
            tool_name=partial.tool_name,
            payload=shipped_payload,
            payload_hash=payload_hash,
            model=partial.model,
            provider=partial.provider,
            trace_id=partial.trace_id,
            span_id=partial.span_id,
            parent_span_id=partial.parent_span_id,
            continues_from=partial.continues_from,
        )

    def record(self, partial: PartialEvent) -> None:
        """Append one captured event. May raise ``LedgerWriteError`` in strict mode."""
        event = self._promote(partial)
        try:
            entry = self.ledger.append(event, payload_mode=self.payload_mode.value)
        except LedgerWriteError:
            raise
        except Exception:  # noqa: BLE001 - never let a capture bug break the proxy
            log.exception("recorder: failed to append event kind=%s", partial.kind)
            return
        if entry is not None:
            try:
                self.checkpointer.note(entry.seq)
            except Exception:  # noqa: BLE001
                log.exception("recorder: checkpoint scheduling failed")

    def record_many(self, partials: list[PartialEvent]) -> None:
        for partial in partials:
            self.record(partial)

    def record_request_body(
        self,
        body: dict,
        *,
        session_id: str,
        trace_id: str = "",
        span_id: str = "",
        parent_span_id: str | None = None,
        continues_from: str | None = None,
    ) -> None:
        try:
            partials = extract_request_events(
                body,
                session_id=session_id,
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_span_id,
                continues_from=continues_from,
            )
        except Exception:  # noqa: BLE001
            log.exception("recorder: request extraction failed")
            return
        self.record_many(partials)

    def record_response_body(
        self,
        body: dict,
        *,
        session_id: str,
        trace_id: str = "",
        span_id: str = "",
        parent_span_id: str | None = None,
        continues_from: str | None = None,
    ) -> None:
        try:
            partials = extract_response_events(
                body,
                session_id=session_id,
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_span_id,
                continues_from=continues_from,
            )
        except Exception:  # noqa: BLE001
            log.exception("recorder: response extraction failed")
            return
        self.record_many(partials)

    def new_stream_extractor(
        self,
        *,
        session_id: str,
        model: str | None,
        trace_id: str = "",
        span_id: str = "",
        parent_span_id: str | None = None,
        continues_from: str | None = None,
    ) -> StreamExtractor:
        return StreamExtractor(
            session_id=session_id,
            model=model,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            continues_from=continues_from,
        )

    def feed_stream_chunk(self, extractor: StreamExtractor, chunk: bytes) -> None:
        try:
            partials = extractor.feed(chunk)
        except Exception:  # noqa: BLE001
            log.exception("recorder: stream extraction failed")
            return
        self.record_many(partials)

    def close_stream_extractor(self, extractor: StreamExtractor) -> None:
        try:
            partials = extractor.close()
        except Exception:  # noqa: BLE001
            log.exception("recorder: stream close extraction failed")
            return
        self.record_many(partials)


_recorder: Recorder | None = None
_recorder_checked = False


def get_recorder() -> Recorder | None:
    """Return the process-wide Recorder, or None if disabled/unavailable.

    Enabled via ``BYOAI_RECORDER_ENABLED=1``. Construction failures (e.g. an
    unwritable ledger directory) are logged and treated as disabled rather
    than crashing the proxy on import/startup.
    """
    global _recorder, _recorder_checked
    if _recorder_checked:
        return _recorder
    _recorder_checked = True
    if os.getenv("BYOAI_RECORDER_ENABLED", "0") != "1":
        return None
    try:
        mode_raw = os.getenv("BYOAI_RECORDER_PAYLOAD_MODE", PayloadMode.REDACTED.value)
        try:
            payload_mode = PayloadMode(mode_raw)
        except ValueError:
            log.warning(
                "recorder: unrecognized BYOAI_RECORDER_PAYLOAD_MODE=%r, falling back to redacted",
                mode_raw,
            )
            payload_mode = PayloadMode.REDACTED
        _recorder = Recorder(payload_mode=payload_mode)
    except Exception:  # noqa: BLE001
        log.exception("recorder: failed to initialize, recording disabled for this process")
        _recorder = None
    return _recorder


def reset_recorder_for_tests() -> None:
    """Test-only hook: drop the cached singleton so the next get_recorder() re-reads env."""
    global _recorder, _recorder_checked
    if _recorder is not None:
        _recorder.close()
    _recorder = None
    _recorder_checked = False
