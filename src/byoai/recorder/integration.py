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

        self._shipper: Shipper | None = None
        self._shipper_stop: threading.Event | None = None
        self._shipper_thread: threading.Thread | None = None
        self._start_shipper(base)

        self._receipt_fetcher = None
        self._start_receipt_fetcher()

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
            entry = self.ledger.append(event)
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
