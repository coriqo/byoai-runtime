"""Recorder.__init__ only starts the background shipper thread once this
device has enrollment state on disk; an unenrolled device just records
locally, same as before Phase 1.
"""

from __future__ import annotations

from dataclasses import asdict

from byoai.recorder.enroll import ENROLLMENT_FILENAME, EnrollmentState
from byoai.recorder.integration import Recorder


def test_no_shipper_without_enrollment(tmp_path):
    recorder = Recorder(dir=tmp_path)
    try:
        assert recorder._shipper is None
        assert recorder._shipper_thread is None
    finally:
        recorder.close()


def test_record_after_close_does_not_crash_in_non_strict_mode(tmp_path):
    # Non-strict mode's contract is "recording must never crash the
    # caller." A closed ledger (e.g. a shutdown race) is a write failure
    # like any other and must be swallowed the same way, not raise.
    import time

    from byoai.recorder.extract import PartialEvent
    from byoai.recorder.schema import EventKind

    recorder = Recorder(dir=tmp_path, strict_mode=False)
    recorder.close()

    recorder.record(
        PartialEvent(
            session_id="sess_1",
            kind=EventKind.TOOL_USE.value,
            ts_device="2026-08-10T12:00:00.000000Z",
            ts_monotonic_ns=time.monotonic_ns(),
            tool_use_id="toolu_1",
            tool_name="Bash",
            payload={"command": "ls"},
            model=None,
        )
    )


def test_no_shipper_when_enrollment_state_is_corrupt(tmp_path):
    # A truncated/corrupt enrollment.json must degrade to "not shipping,"
    # not crash Recorder construction and take local recording down with it.
    recorder = Recorder(dir=tmp_path)
    recorder.close()

    (tmp_path / ENROLLMENT_FILENAME).write_text("{not valid json")

    recorder2 = Recorder(dir=tmp_path)
    try:
        assert recorder2._shipper is None
        assert recorder2._shipper_thread is None
    finally:
        recorder2.close()


def test_shipper_starts_when_enrolled(tmp_path):
    # Enroll manually (no network) by writing enrollment.json the same way
    # enroll() would, using this recorder's own device_id once it exists.
    recorder = Recorder(dir=tmp_path)
    device_id = recorder.key.device_id
    recorder.close()

    import json

    state = EnrollmentState(
        device_id=device_id,
        coriqo_base_url="https://coriqo.example.com",
        enrolled_at="2026-01-01T00:00:00Z",
    )
    (tmp_path / ENROLLMENT_FILENAME).write_text(json.dumps(asdict(state)))

    recorder2 = Recorder(dir=tmp_path)
    try:
        assert recorder2._shipper is not None
        assert recorder2._shipper_thread is not None
        assert recorder2._shipper_thread.is_alive()
    finally:
        recorder2.close()
    assert not recorder2._shipper_thread.is_alive()


class _CountingShipper:
    def __init__(self, fail: bool = False) -> None:
        self.shipped = 0
        self.closed = False
        self.fail = fail

    def ship_once(self):
        self.shipped += 1
        if self.fail:
            raise RuntimeError("coriqo unreachable")

    def close(self) -> None:
        self.closed = True


def test_close_sends_once_more_only_when_asked(tmp_path):
    # TI-25: coriqo-mcp writes its worker_stop_ack moments before exit. With
    # final_ship the entry is sent on the way out; a plain close() is as before.
    plain = Recorder(dir=tmp_path / "a")
    plain._shipper = shipper = _CountingShipper()
    plain.close()
    assert shipper.shipped == 0 and shipper.closed

    asked = Recorder(dir=tmp_path / "b")
    asked._shipper = shipper = _CountingShipper()
    asked.close(final_ship=True)
    assert shipper.shipped == 1 and shipper.closed


def test_final_ship_failure_is_logged_not_raised(tmp_path):
    recorder = Recorder(dir=tmp_path)
    recorder._shipper = shipper = _CountingShipper(fail=True)
    recorder.close(final_ship=True)
    assert shipper.shipped == 1 and shipper.closed
