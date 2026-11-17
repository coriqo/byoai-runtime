"""Round-3 review fixes for the heartbeat: honest records must verify, clock
rules are advisory unless asked, multi-writer ledgers stay consistent."""

from __future__ import annotations

import json
import os
import threading

import pytest
from tests.recorder.conftest import make_event

from byoai.recorder.checkpoint import Checkpointer
from byoai.recorder.heartbeat import HeartbeatEmitter
from byoai.recorder.keys import load_or_create_device_key
from byoai.recorder.ledger import Ledger
from byoai.recorder.verify import VerifyError, verify_bundle, verify_ledger

START = 1_800_000_000.0
POLICY = 1800


class Clk:
    def __init__(self, w=START, m=100.0):
        self.w, self.m = w, m

    def wall(self):
        return self.w

    def mono(self):
        return self.m

    def step(self, dw, dm):
        self.w += dw
        self.m += dm


def _rig(tmp_path):
    key = load_or_create_device_key(tmp_path / "k")
    led = Ledger(tmp_path / "l.db", key.device_id)
    c = Clk()
    cp = Checkpointer(led, key, wall_clock=c.wall, monotonic=c.mono)
    hb = HeartbeatEmitter(led, key.device_id, interval_s=900, wall_clock=c.wall,
                          monotonic=c.mono)
    return key, led, c, cp, hb


def _beat(c, cp, hb, dw, dm):
    c.step(dw, dm)
    e = hb._emit()
    cp.note(e.seq)
    cp.flush()


def _verify(tmp_path, key, **kw):
    kw.setdefault("max_heartbeat_silence_seconds", POLICY)
    return verify_ledger(tmp_path / "l.db", public_key_b64=key.public_key_b64, **kw)


# -- H1: two writers on one ledger file --------------------------------------


def test_snapshot_reads_the_real_head_not_this_process_view(tmp_path):
    a = Ledger(tmp_path / "l.db", "d")
    b = Ledger(tmp_path / "l.db", "d")
    a.append(make_event("d"))
    b.append(make_event("d"))
    b.append(make_event("d"))
    assert a.snapshot()[0] == 3  # a's in-memory view said 1


def test_two_worker_processes_on_one_file_verify_ok_with_the_check_on(tmp_path):
    key = load_or_create_device_key(tmp_path / "k")
    c = Clk()
    A = Ledger(tmp_path / "l.db", key.device_id)
    B = Ledger(tmp_path / "l.db", key.device_id)
    cpA = Checkpointer(A, key, wall_clock=c.wall, monotonic=c.mono)
    cpB = Checkpointer(B, key, wall_clock=c.wall, monotonic=c.mono)
    hbA = HeartbeatEmitter(A, key.device_id, interval_s=900, wall_clock=c.wall,
                           monotonic=c.mono)
    cpB.note(B.append(make_event(key.device_id)).seq)
    for _ in range(3):
        c.step(900, 900)
        cpA.note(hbA._emit().seq)
    c.step(60, 60)
    cpB.flush()
    c.step(10, 10)
    cpA.flush()
    A.close()
    B.close()
    r = _verify(tmp_path, key, strict_clock=True)
    assert r.ok, r.to_dict()
    assert r.clock_findings == [] and r.bad_signatures == []


def test_concurrent_appends_from_two_ledger_objects_lose_nothing(tmp_path):
    a = Ledger(tmp_path / "l.db", "d")
    b = Ledger(tmp_path / "l.db", "d")
    errs = []

    def run(led):
        try:
            for _ in range(150):
                assert led.append(make_event("d")) is not None
        except BaseException as exc:  # noqa: BLE001
            errs.append(exc)

    ts = [threading.Thread(target=run, args=(x,)) for x in (a, b)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    a.close()
    b.close()
    assert not errs
    r = verify_ledger(tmp_path / "l.db")
    assert r.entries_checked == 300 and r.gaps == [] and r.broken_links == []


# -- advisory clock rules ------------------------------------------------------

HONEST = {
    "copied-to-other-host": [(0, 0), (900, 900), (900, 86400 * 10)],
    "ntp-step-back-15s": [(0, 0), (900 - 15, 900)],
    "ntp-step-back-2s": [(0, 0), (-2 + 0.5, 0.5)],
}


@pytest.mark.parametrize("name", sorted(HONEST))
def test_honest_clock_oddities_pass_by_default_and_are_noted(tmp_path, name):
    key, led, c, cp, hb = _rig(tmp_path)
    for dw, dm in HONEST[name]:
        _beat(c, cp, hb, dw, dm)
    led.close()
    r = _verify(tmp_path, key)
    assert r.ok, r.to_dict()
    assert r.clock_findings  # reported, labelled, not failing
    strict = _verify(tmp_path, key, strict_clock=True)
    assert not strict.ok


def test_strict_clock_notes_can_be_accepted_by_seq(tmp_path):
    key, led, c, cp, hb = _rig(tmp_path)
    for dw, dm in HONEST["ntp-step-back-15s"]:
        _beat(c, cp, hb, dw, dm)
    led.close()
    seqs = {f["seq"] for f in _verify(tmp_path, key).clock_findings}
    assert _verify(tmp_path, key, strict_clock=True, clock_notes_accepted=seqs).ok


def test_sleep_gap_fails_and_is_acceptable_by_name(tmp_path):
    key, led, c, cp, hb = _rig(tmp_path)
    _beat(c, cp, hb, 0, 0)
    _beat(c, cp, hb, 8 * 3600, 900)  # laptop asleep 8h
    led.close()
    r = _verify(tmp_path, key)
    assert not r.ok and r.heartbeat_silences[0]["name"] == "1-2"
    assert _verify(tmp_path, key, heartbeat_gaps_allowed=["1-2"]).ok
    assert _verify(tmp_path, key, heartbeat_gaps_allowed=[(1, 2)]).ok


# -- H6: off windows are named by their marker --------------------------------


def test_off_window_accepted_by_marker_stays_accepted_as_the_record_grows(tmp_path):
    from byoai.recorder.heartbeat import write_disabled_marker

    key = load_or_create_device_key(tmp_path / "k")
    led = Ledger(tmp_path / "l.db", key.device_id)
    cp = Checkpointer(led, key)
    m = write_disabled_marker(led, key.device_id)
    cp.note(m.seq)
    cp.flush()
    r = _verify(tmp_path, key)
    assert not r.ok and r.heartbeat_silences[0]["name"] == f"off:{m.seq}"
    assert _verify(tmp_path, key, heartbeat_gaps_allowed=[f"off:{m.seq}"]).ok
    for _ in range(5):  # still growing, heartbeats still off
        cp.note(led.append(make_event(key.device_id)).seq)
    cp.flush()
    led.close()
    assert _verify(tmp_path, key, heartbeat_gaps_allowed=[f"off:{m.seq}"]).ok


def test_tail_is_named_by_the_last_heartbeat(tmp_path):
    from dataclasses import replace

    key, led, c, cp, hb = _rig(tmp_path)
    _beat(c, cp, hb, 0, 0)
    led.append(replace(make_event(key.device_id), ts_device="2027-02-01T00:00:00.000000Z"))
    led.close()
    r = _verify(tmp_path, key)
    assert r.heartbeat_silences[0]["name"] == "tail:1"
    assert _verify(tmp_path, key, heartbeat_gaps_allowed=["tail:1"]).ok


def test_bad_gap_names_are_refused(tmp_path):
    key, led, *_ = _rig(tmp_path)
    led.close()
    for bad in ("off:x", "tail:", "1-", "zz", (1,), "off"):
        with pytest.raises(VerifyError):
            _verify(tmp_path, key, heartbeat_gaps_allowed=[bad])


# -- H7 ------------------------------------------------------------------------


def test_policy_stricter_than_the_declared_interval_is_noted(tmp_path):
    key, led, c, cp, hb = _rig(tmp_path)
    _beat(c, cp, hb, 0, 0)
    led.close()
    r = _verify(tmp_path, key, max_heartbeat_silence_seconds=100)
    assert any("stricter than the interval the device declared" in n for n in r.notes)
    r2 = _verify(tmp_path, key, max_heartbeat_silence_seconds=5000)
    assert not any("stricter" in n for n in r2.notes)


# -- D2: bundle cannot be passed by stripping --------------------------------


def _bundle(tmp_path, key):
    led = Ledger(tmp_path / "l.db", key.device_id)
    entries = [{"seq": e.seq, "prev_hash": e.prev_hash, "entry_hash": e.entry_hash,
                "event": e.event.to_dict()} for e in led.iter_entries()]
    cps = [{"checkpoint": x, "epoch_index": None, "inclusion_proof": None}
           for x in led.iter_checkpoints()]
    led.close()
    return {"device": {"device_id": key.device_id, "public_key_b64": key.public_key_b64},
            "entries": entries, "checkpoints": cps, "epochs": []}


def test_empty_bundles_fail_with_the_check_on(tmp_path):
    for b in ({}, {"entries": []}):
        assert not verify_bundle(b, max_heartbeat_silence_seconds=POLICY).ok


def test_bundle_without_signed_checkpoints_fails_with_the_check_on(tmp_path):
    key, led, c, cp, hb = _rig(tmp_path)
    _beat(c, cp, hb, 0, 0)
    _beat(c, cp, hb, 900, 900)
    led.close()
    b = _bundle(tmp_path, key)
    assert verify_bundle(b, max_heartbeat_silence_seconds=POLICY).ok
    b["checkpoints"] = []
    assert not verify_bundle(b, max_heartbeat_silence_seconds=POLICY).ok
    assert verify_bundle(b).ok  # check off: as before


def test_bundle_cli_fails_empty_and_unsigned(tmp_path, capsys):
    from byoai.recorder.cli import main

    f = tmp_path / "b.json"
    f.write_text("{}")
    assert main(["bundle", str(f), "--skip-anchors", "--max-heartbeat-silence", "1800"]) == 1
    capsys.readouterr()


# -- D3 ------------------------------------------------------------------------


def test_bad_interval_in_a_heartbeat_payload_is_a_finding(tmp_path):
    key, led, c, cp, hb = _rig(tmp_path)
    _beat(c, cp, hb, 0, 0)
    led.close()
    b = _bundle(tmp_path, key)
    for bad in ("fast", -5, None, True, float("nan")):
        bb = json.loads(json.dumps(b))
        ev = bb["entries"][0]["event"]
        ev["payload"]["interval_s"] = bad if bad == bad else "nan"
        r = verify_bundle(bb, max_heartbeat_silence_seconds=POLICY)
        assert not r.ok
        assert any("interval_s" in m for m in r.malformed_bundle), bad


def test_epoch_end_is_kept_per_checkpoint_not_per_seq_end(tmp_path):
    key, led, c, cp, hb = _rig(tmp_path)
    _beat(c, cp, hb, 0, 0)
    led.close()
    b = _bundle(tmp_path, key)
    good = b["checkpoints"][0]
    dup = json.loads(json.dumps(good))
    good["epoch_index"] = 0
    dup["epoch_index"] = 1  # same seq_end, a later epoch that ended before the heartbeat
    b["checkpoints"] = [good, dup]
    b["epochs"] = [
        {"epoch_index": 0, "root": "00" * 32, "epoch_end": "2030-01-01T00:00:00Z"},
        {"epoch_index": 1, "root": "00" * 32, "epoch_end": "2001-01-01T00:00:00Z"},
    ]
    r = verify_bundle(b, max_heartbeat_silence_seconds=POLICY)
    assert any("tenant epoch" in f["reason"] for f in r.clock_findings)


# -- D4 ------------------------------------------------------------------------


def test_checkpoint_time_is_read_inside_the_ledger_lock(tmp_path):
    key = load_or_create_device_key(tmp_path / "k")
    led = Ledger(tmp_path / "l.db", key.device_id)
    owned = []

    def wall():
        owned.append(led._lock._is_owned())
        return START

    cp = Checkpointer(led, key, wall_clock=wall)
    cp.note(led.append(make_event(key.device_id)).seq)
    cp.flush()
    led.close()
    assert owned and all(owned)


# -- D1: fork ------------------------------------------------------------------


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork (POSIX)")
def test_fork_child_gets_its_own_connection_and_both_sides_write(tmp_path, monkeypatch):
    from byoai.recorder.integration import Recorder

    monkeypatch.setenv("BYOAI_RECORDER_HEARTBEAT_SECONDS", "3600")
    rec = Recorder(dir=tmp_path / "rec")
    parent_conn = rec.ledger._conn
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            if rec.ledger._conn is not parent_conn:
                for _ in range(40):
                    rec.ledger.append(make_event(rec.key.device_id))
                code = 0
        finally:
            os._exit(code)
    for _ in range(40):
        rec.ledger.append(make_event(rec.key.device_id))
    _, status = os.waitpid(pid, 0)
    rec.checkpointer.flush()
    key = rec.key
    rec.close()
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    r = verify_ledger(tmp_path / "rec" / "ledger.db", public_key_b64=key.public_key_b64)
    assert r.ok, r.to_dict()
    assert r.entries_checked >= 81


# -- H2: boot id ----------------------------------------------------------------


def test_new_heartbeats_carry_a_hashed_boot_id_when_the_platform_gives_one(tmp_path):
    from byoai.recorder.heartbeat import boot_id, hashed_boot_id

    key, led, c, cp, hb = _rig(tmp_path)
    e = hb._emit()
    led.close()
    raw = boot_id()
    if raw is None:
        assert "boot_id" not in e.event.payload
    else:
        got = e.event.payload["boot_id"]
        assert got == hashed_boot_id(key.device_id, raw)
        assert len(got) == 16 and raw not in got  # not the raw boot id / boot time
