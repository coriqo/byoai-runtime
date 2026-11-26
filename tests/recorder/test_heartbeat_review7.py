"""Round-5 review fixes: a backwards clock never hides a heartbeats-off window,
and a ledger refuses to adopt or sign a head it cannot verify."""

from __future__ import annotations

import sqlite3

import pytest
from tests.recorder.conftest import make_event

from byoai.recorder import heartbeat as hbmod
from byoai.recorder.checkpoint import Checkpointer
from byoai.recorder.heartbeat import HeartbeatEmitter, boot_id, write_disabled_marker
from byoai.recorder.keys import load_or_create_device_key
from byoai.recorder.ledger import Ledger, LedgerHeadError, LedgerWriteError
from byoai.recorder.verify import verify_ledger

T0 = 1_800_000_000.0
POLICY = 1800


class Clk:
    def __init__(self, w=T0, m=100.0):
        self.w, self.m = w, m

    def wall(self):
        return self.w

    def mono(self):
        return self.m


def _rig(tmp_path):
    key = load_or_create_device_key(tmp_path / "k")
    led = Ledger(tmp_path / "l.db", key.device_id)
    c = Clk()
    cp = Checkpointer(led, key, wall_clock=c.wall, monotonic=c.mono)
    hb = HeartbeatEmitter(led, key.device_id, interval_s=900, wall_clock=c.wall,
                          monotonic=c.mono)
    return key, led, c, cp, hb


def _verify(tmp_path, key, **kw):
    kw.setdefault("max_heartbeat_silence_seconds", POLICY)
    return verify_ledger(tmp_path / "l.db", public_key_b64=key.public_key_b64, **kw)


# -- A: a backwards clock does not skip other rules ----------------------------


def test_off_marker_then_a_backwards_heartbeat_is_still_a_disabled_window(tmp_path):
    key, led, c, cp, hb = _rig(tmp_path)
    m = write_disabled_marker(led, key.device_id, wall_clock=c.wall)
    c.w -= 100  # the next heartbeat is dated EARLIER than the marker
    h = hb._emit()
    cp.note(h.seq)
    cp.flush()
    led.close()
    r = _verify(tmp_path, key)
    assert not r.ok
    assert [s["name"] for s in r.heartbeat_silences] == [f"off:{m.seq}"]
    assert r.clock_findings  # and the backwards step is still noted
    assert _verify(tmp_path, key, heartbeat_gaps_allowed=[f"off:{m.seq}"]).ok


@pytest.mark.skipif(boot_id() is None, reason="platform gives no boot id")
def test_backwards_clock_outage_in_one_boot_is_caught_by_the_monotonic_gap(tmp_path):
    key, led, c, cp, hb = _rig(tmp_path)
    cp.note(hb._emit().seq)
    c.w -= 50  # wall clock set back ...
    c.m += 3 * 3600  # ... across a 3 h outage the monotonic counter saw
    cp.note(hb._emit().seq)
    cp.flush()
    led.close()
    r = _verify(tmp_path, key)  # no --strict-clock
    assert not r.ok
    assert [s["name"] for s in r.heartbeat_silences] == ["1-2"]
    assert r.heartbeat_silences[0]["seconds"] == pytest.approx(3 * 3600)


@pytest.mark.skipif(boot_id() is None, reason="platform gives no boot id")
def test_an_honest_ntp_step_back_still_passes(tmp_path):
    key, led, c, cp, hb = _rig(tmp_path)
    cp.note(hb._emit().seq)
    c.w -= 5
    c.m += 0.5  # monotonic delta small: nothing was lost
    cp.note(hb._emit().seq)
    cp.flush()
    led.close()
    r = _verify(tmp_path, key)
    assert r.ok, r.to_dict()
    assert r.clock_findings
    assert not _verify(tmp_path, key, strict_clock=True).ok


def test_backwards_spacing_without_a_boot_id_is_unknown_and_says_so(tmp_path, monkeypatch):
    monkeypatch.setattr(hbmod, "_BOOT_ID", None)
    key, led, c, cp, hb = _rig(tmp_path)
    cp.note(hb._emit().seq)
    c.w -= 50
    c.m += 3 * 3600
    cp.note(hb._emit().seq)
    cp.flush()
    led.close()
    r = _verify(tmp_path, key)
    assert r.ok
    assert any("cannot be judged; pass --strict-clock to fail it" in n for n in r.notes)
    assert not _verify(tmp_path, key, strict_clock=True).ok


# -- B: forward-only resync ---------------------------------------------------


def _raw(tmp_path, sql, *args):
    con = sqlite3.connect(tmp_path / "l.db")
    con.execute(sql, args)
    con.commit()
    con.close()


def test_truncated_file_is_not_adopted_by_append_or_snapshot(tmp_path, caplog):
    led = Ledger(tmp_path / "l.db", "d")
    for _ in range(3):
        led.append(make_event("d"))
    _raw(tmp_path, "DELETE FROM agent_events WHERE seq > 1")
    with caplog.at_level("ERROR"):
        assert led.append(make_event("d")) is None  # non-strict: dropped, recorded
    assert any("ledger_head_changed" in r.message and str(tmp_path / "l.db") in r.message
               for r in caplog.records)
    assert "ledger_head_changed" in led._pending_failures[-1]["error"]
    with pytest.raises(LedgerHeadError):
        led.snapshot()
    led.close()


def test_rewritten_history_is_not_adopted(tmp_path):
    led = Ledger(tmp_path / "l.db", "d")
    for _ in range(3):
        led.append(make_event("d"))
    _raw(tmp_path, "UPDATE agent_events SET entry_hash = 'sha256:' || hex(randomblob(32)) "
                   "WHERE seq = 3")
    with pytest.raises(LedgerHeadError, match="ledger_head_changed"):
        led.snapshot()
    led.close()


def test_strict_mode_raises_on_a_changed_head(tmp_path):
    led = Ledger(tmp_path / "l.db", "d", strict_mode=True)
    led.append(make_event("d"))
    led.append(make_event("d"))
    _raw(tmp_path, "DELETE FROM agent_events WHERE seq > 1")
    with pytest.raises(LedgerWriteError):
        led.append(make_event("d"))
    led.close()


def test_checkpointer_signs_nothing_when_the_head_changed(tmp_path):
    key = load_or_create_device_key(tmp_path / "k")
    led = Ledger(tmp_path / "l.db", key.device_id)
    cp = Checkpointer(led, key)
    for _ in range(3):
        cp.note(led.append(make_event(key.device_id)).seq)
    _raw(tmp_path, "DELETE FROM agent_events WHERE seq > 1")
    assert cp.flush() is None
    assert led.iter_checkpoints() == []
    assert any("ledger_head_changed" in f["error"] for f in led._pending_failures)
    led.close()


def test_a_head_that_is_simply_ahead_is_adopted(tmp_path):
    a = Ledger(tmp_path / "l.db", "d")
    b = Ledger(tmp_path / "l.db", "d")
    a.append(make_event("d"))
    b.append(make_event("d"))
    b.append(make_event("d"))
    assert a.snapshot()[0] == 3
    assert a.append(make_event("d")).seq == 4
    a.close()
    b.close()


# -- C: rows another writer added are re-derived before signing ---------------


def test_forged_foreign_row_is_not_signed_over(tmp_path, caplog):
    key = load_or_create_device_key(tmp_path / "k")
    a = Ledger(tmp_path / "l.db", key.device_id)
    b = Ledger(tmp_path / "l.db", key.device_id)
    cp = Checkpointer(a, key)
    cp.note(a.append(make_event(key.device_id)).seq)  # seq 1, ours
    b.append(make_event(key.device_id))  # seq 2, genuine
    b.append(make_event(key.device_id))  # seq 3
    _raw(tmp_path, "UPDATE agent_events SET payload = '{\"forged\": 1}' WHERE seq = 3")
    with caplog.at_level("ERROR"):
        c = cp.flush()
    assert c is not None and c["seq_end"] == 1  # not beyond our own verified head
    assert any("ledger_rows_unverified" in r.message for r in caplog.records)
    assert any("ledger_rows_unverified" in f["error"] for f in a._pending_failures)
    assert a.append(make_event(key.device_id)) is None  # will not chain onto them
    a.close()
    b.close()


def test_genuine_foreign_rows_are_verified_and_signed(tmp_path):
    key = load_or_create_device_key(tmp_path / "k")
    a = Ledger(tmp_path / "l.db", key.device_id)
    b = Ledger(tmp_path / "l.db", key.device_id)
    cp = Checkpointer(a, key)
    cp.note(a.append(make_event(key.device_id)).seq)
    for _ in range(3):
        b.append(make_event(key.device_id))
    c = cp.flush()
    assert c["seq_end"] == 4
    a.close()
    b.close()
    assert verify_ledger(tmp_path / "l.db", public_key_b64=key.public_key_b64).ok
