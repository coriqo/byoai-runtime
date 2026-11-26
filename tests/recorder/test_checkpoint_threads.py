"""Checkpoints stay verifiable when several threads append and note at once.

Request threads and the heartbeat thread each do ``ledger.append`` and then
``checkpointer.note(seq)``. The two steps are not atomic, so notes can arrive
out of seq order. The checkpoint must still cover a real window and sign the
chain hash that belongs to its ``seq_end``.
"""

from __future__ import annotations

import threading

from tests.recorder.conftest import make_event

from byoai.recorder.checkpoint import Checkpointer
from byoai.recorder.heartbeat import HeartbeatEmitter
from byoai.recorder.keys import load_or_create_device_key
from byoai.recorder.ledger import Ledger
from byoai.recorder.verify import verify_ledger


def test_out_of_order_notes_sign_the_hash_at_seq_end(tmp_path):
    key = load_or_create_device_key(tmp_path / "k")
    led = Ledger(tmp_path / "l.db", key.device_id)
    cp = Checkpointer(led, key, every_events=2)
    hb = HeartbeatEmitter(led, key.device_id, interval_s=900)
    a = led.append(make_event(key.device_id))  # request thread: appended, not yet noted
    h = hb._emit()  # heartbeat thread appends seq 2
    cp.note(h.seq)  # ... and notes first
    out = cp.note(a.seq)  # request thread notes seq 1 late
    cp.flush()
    led.close()
    assert out is None or out["seq_start"] <= out["seq_end"]
    report = verify_ledger(tmp_path / "l.db", public_key_b64=key.public_key_b64)
    assert report.ok, report.to_dict()
    assert report.bad_signatures == []


def test_thousands_of_threaded_appends_verify_ok(tmp_path):
    key = load_or_create_device_key(tmp_path / "k")
    led = Ledger(tmp_path / "l.db", key.device_id)
    cp = Checkpointer(led, key, every_events=7)
    hb = HeartbeatEmitter(led, key.device_id, interval_s=900, on_entry=lambda e: cp.note(e.seq))
    errors: list[BaseException] = []
    stop = threading.Event()

    def request_thread():
        try:
            for _ in range(400):
                e = led.append(make_event(key.device_id))
                cp.note(e.seq)
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    def heartbeat_thread():
        try:
            while not stop.is_set():
                hb._emit()
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    workers = [threading.Thread(target=request_thread) for _ in range(8)]
    hbt = threading.Thread(target=heartbeat_thread)
    hbt.start()
    for t in workers:
        t.start()
    for t in workers:
        t.join()
    stop.set()
    hbt.join()
    cp.flush()
    total = led.next_seq - 1
    led.close()
    assert not errors, errors
    assert total >= 3200
    report = verify_ledger(tmp_path / "l.db", public_key_b64=key.public_key_b64)
    assert report.ok, {k: v for k, v in report.to_dict().items() if v and k != "notes"}
    assert report.bad_signatures == [] and report.gaps == []
    assert report.unsigned_tail is None
