"""C2: the signed heartbeat chain entry.

Emission cadence runs on a fake clock (nothing sleeps). Verification covers
chain continuity with heartbeats between tool events, a signed checkpoint over
them, and the opt-in silence check on a ledger and on a bundle.
"""

from __future__ import annotations

import json

import pytest
from tests.recorder.conftest import make_event

from byoai.recorder import verify as verify_mod
from byoai.recorder.checkpoint import Checkpointer
from byoai.recorder.cli import main as verify_cli
from byoai.recorder.heartbeat import (
    DEFAULT_HEARTBEAT_INTERVAL_S,
    HeartbeatEmitter,
    heartbeat_interval_from_env,
)
from byoai.recorder.keys import load_or_create_device_key
from byoai.recorder.ledger import Ledger
from byoai.recorder.schema import EventKind
from byoai.recorder.verify import verify_bundle, verify_ledger

T0 = 1_790_000_000.0  # fixed epoch seconds, later than make_event's fixed ts_device
INTERVAL = 900


class FakeClock:
    """One clock behind both the wall and the monotonic reading."""

    def __init__(self, start: float = T0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


@pytest.fixture
def ledger(tmp_path):
    led = Ledger(tmp_path / "ledger.db", "dev_hb")
    yield led
    led.close()


def _emitter(ledger, clock, *, interval=INTERVAL, on_entry=None):
    return HeartbeatEmitter(
        ledger, "dev_hb", interval_s=interval, on_entry=on_entry,
        wall_clock=clock, monotonic=clock,
    )


def _heartbeats(ledger):
    return [e for e in ledger.iter_entries() if e.event.kind == EventKind.HEARTBEAT.value]


# -- cadence ------------------------------------------------------------------


def test_start_writes_exactly_one_heartbeat(ledger):
    clock = FakeClock()
    hb = _emitter(ledger, clock)
    first = hb.start()
    assert first is not None
    assert first.event.kind == "heartbeat"
    assert len(_heartbeats(ledger)) == 1


def test_no_heartbeat_before_the_interval_and_one_at_it(ledger):
    clock = FakeClock()
    hb = _emitter(ledger, clock)
    hb.start()
    clock.advance(INTERVAL - 1)
    assert hb.tick() is None
    clock.advance(1)
    assert hb.tick() is not None
    assert hb.tick() is None  # same instant: not again
    assert len(_heartbeats(ledger)) == 2


def test_a_long_stall_gives_one_heartbeat_not_a_backlog(ledger):
    clock = FakeClock()
    hb = _emitter(ledger, clock)
    hb.start()
    clock.advance(INTERVAL * 10)  # process suspended, then wakes
    assert hb.tick() is not None
    assert hb.tick() is None
    assert len(_heartbeats(ledger)) == 2
    assert hb.seconds_until_due() == INTERVAL


def test_payload_is_last_seq_device_time_interval(ledger):
    clock = FakeClock()
    ledger.append(make_event("dev_hb"))
    ledger.append(make_event("dev_hb"))
    entry = _emitter(ledger, clock).start()
    assert entry.seq == 3
    p = entry.event.payload
    assert set(p) - {"boot_id"} == {"last_seq", "device_time", "interval_s"}
    assert p["last_seq"] == 2
    assert p["interval_s"] == INTERVAL and isinstance(p["interval_s"], int)
    assert p["device_time"].endswith("Z") and p["device_time"].startswith("2026-")
    # Stored in full, so the payload hash is checkable by anyone.
    from byoai.recorder.canonical import canonicalize, sha256_hex

    assert entry.event.payload_hash == sha256_hex(canonicalize(p))


def test_empty_chain_heartbeat_has_last_seq_zero(ledger):
    entry = _emitter(ledger, FakeClock()).start()
    assert entry.seq == 1 and entry.event.payload["last_seq"] == 0


def test_interval_must_be_positive(ledger):
    with pytest.raises(ValueError):
        HeartbeatEmitter(ledger, "dev_hb", interval_s=0)


# -- restart ------------------------------------------------------------------


def test_restart_inside_the_interval_writes_none_and_schedules_the_rest(ledger):
    clock = FakeClock()
    _emitter(ledger, clock).start()
    clock.advance(300)
    again = _emitter(ledger, clock)  # a new process, same ledger
    assert again.start() is None
    assert again.seconds_until_due() == pytest.approx(INTERVAL - 300)
    clock.advance(INTERVAL - 300)
    assert again.tick() is not None
    assert len(_heartbeats(ledger)) == 2


def test_crash_loop_cannot_flood_the_chain(ledger):
    clock = FakeClock()
    for _ in range(20):
        _emitter(ledger, clock).start()
        clock.advance(5)  # restarts seconds apart
    assert len(_heartbeats(ledger)) == 1


def test_restart_after_a_long_gap_writes_one_on_start(ledger):
    clock = FakeClock()
    _emitter(ledger, clock).start()
    clock.advance(INTERVAL * 5)  # process was down
    again = _emitter(ledger, clock)
    assert again.start() is not None
    assert again.tick() is None
    assert len(_heartbeats(ledger)) == 2


def test_clock_set_back_does_not_suppress_the_start_heartbeat(ledger):
    clock = FakeClock()
    _emitter(ledger, clock).start()
    clock.advance(-3600)  # newest heartbeat is "in the future"
    assert _emitter(ledger, clock).start() is not None


def test_a_failing_write_waits_a_full_interval(ledger, monkeypatch):
    clock = FakeClock()
    hb = _emitter(ledger, clock)
    hb.start()
    clock.advance(INTERVAL)
    monkeypatch.setattr(ledger, "append_stamped", lambda b, **_kw: None)  # non-strict drop
    assert hb.tick() is None
    assert hb.seconds_until_due() == INTERVAL  # no tight retry loop


def test_disabled_nothing_written_when_not_started(ledger):
    assert _heartbeats(ledger) == []


# -- env ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw, expected",
    [(None, 900.0), ("", 900.0), ("5", 5.0), ("0", 0.0), ("0.5", 0.5),
     ("abc", 900.0), ("-3", 900.0), ("nan", 900.0), ("inf", 900.0)],
)
def test_interval_from_env(raw, expected):
    env = {} if raw is None else {"BYOAI_RECORDER_HEARTBEAT_SECONDS": raw}
    assert heartbeat_interval_from_env(env) == expected
    assert DEFAULT_HEARTBEAT_INTERVAL_S == 900.0


def test_recorder_off_with_zero_and_on_by_default(tmp_path, monkeypatch):
    from byoai.recorder.integration import Recorder

    monkeypatch.setenv("BYOAI_RECORDER_HEARTBEAT_SECONDS", "0")
    r = Recorder(dir=tmp_path / "off")
    try:
        assert r._heartbeat_thread is None
    finally:
        r.close()

    monkeypatch.setenv("BYOAI_RECORDER_HEARTBEAT_SECONDS", "3600")
    r = Recorder(dir=tmp_path / "on")
    try:
        assert r._heartbeat_thread is not None
        r._heartbeat_thread.join(timeout=3)  # start() writes once, then it waits
        # Wait for the start heartbeat via the ledger, bounded, no sleep.
        for _ in range(200):
            if r.ledger.last_entry_of_kind("heartbeat") is not None:
                break
            r._heartbeat_thread.join(timeout=0.02)
        assert r.ledger.last_entry_of_kind("heartbeat") is not None
    finally:
        r.close()


# -- chain continuity and signatures -----------------------------------------


def test_heartbeats_interleaved_with_tool_events_keep_the_chain_intact(tmp_path):
    key = load_or_create_device_key(tmp_path)
    led = Ledger(tmp_path / "ledger.db", key.device_id)
    clock = FakeClock()
    cp = Checkpointer(led, key, every_events=10_000, every_seconds=10_000.0,
                      monotonic=clock, wall_clock=clock)

    def note(entry):
        cp.note(entry.seq)

    hb = HeartbeatEmitter(led, key.device_id, interval_s=INTERVAL, on_entry=note,
                          wall_clock=clock, monotonic=clock)
    try:
        hb.start()
        for _ in range(3):
            e = led.append(make_event(key.device_id))
            cp.note(e.seq)
            clock.advance(INTERVAL)
            hb.tick()
        assert cp.flush() is not None
        kinds = [e.event.kind for e in led.iter_entries()]
        assert kinds == ["heartbeat", "tool_use", "heartbeat", "tool_use",
                         "heartbeat", "tool_use", "heartbeat"]
        report = verify_ledger(tmp_path / "ledger.db", public_key_b64=key.public_key_b64)
        assert report.ok, report.notes
        assert report.gaps == [] and report.broken_links == []
        assert report.signatures_verified and report.unsigned_tail is None
    finally:
        led.close()


def test_tampering_with_a_heartbeat_payload_breaks_the_chain(tmp_path):
    import sqlite3

    led = Ledger(tmp_path / "ledger.db", "dev_hb")
    clock = FakeClock()
    _emitter(led, clock).start()
    led.close()
    conn = sqlite3.connect(tmp_path / "ledger.db")
    row = conn.execute("SELECT payload FROM agent_events WHERE seq = 1").fetchone()
    forged = json.loads(row[0])
    forged["last_seq"] = 99
    conn.execute("UPDATE agent_events SET payload = ? WHERE seq = 1", (json.dumps(forged),))
    conn.commit()
    conn.close()
    assert not verify_ledger(tmp_path / "ledger.db").ok


# -- silence check ------------------------------------------------------------


def _ledger_with_window(tmp_path, *, down_for: int):
    """Heartbeats at T0 and T0+900, a tool event, then ``down_for`` seconds of
    nothing (process killed), a restart heartbeat, one more on schedule, and a
    device-signed checkpoint over all of it."""
    path = tmp_path / "ledger.db"
    key = load_or_create_device_key(tmp_path / "k")
    led = Ledger(path, "dev_hb")
    clock = FakeClock()
    _emitter(led, clock).start()  # seq 1
    clock.advance(INTERVAL)
    hb = _emitter(led, clock)
    hb.tick() or hb.start()  # seq 2
    led.append(make_event("dev_hb"))  # seq 3
    clock.advance(down_for)
    hb2 = _emitter(led, clock)
    hb2.start()  # seq 4 (after the gap)
    clock.advance(INTERVAL)
    hb2.tick()  # seq 5
    cp = Checkpointer(led, key, monotonic=clock, wall_clock=clock)
    cp.note(1)
    cp.flush()
    led.close()
    return path


def _bundle_from(path) -> dict:
    key = load_or_create_device_key(path.parent / "k")
    led = Ledger(path, "dev_hb")
    try:
        entries = [
            {"seq": e.seq, "prev_hash": e.prev_hash, "entry_hash": e.entry_hash,
             "event": e.event.to_dict()}
            for e in led.iter_entries()
        ]
        cps = [{"checkpoint": c, "epoch_index": None, "inclusion_proof": None}
               for c in led.iter_checkpoints()]
    finally:
        led.close()
    return {"device": {"device_id": "dev_hb", "public_key_b64": key.public_key_b64},
            "entries": entries, "checkpoints": cps, "epochs": []}


def test_silence_check_is_off_by_default(tmp_path):
    path = _ledger_with_window(tmp_path, down_for=7200)
    assert verify_ledger(path).ok
    assert verify_bundle(_bundle_from(path)).ok
    assert verify_ledger(path).heartbeats_checked == 0


def test_ledger_passes_when_spacing_is_within_policy(tmp_path):
    path = _ledger_with_window(tmp_path, down_for=INTERVAL)
    report = verify_ledger(path, max_heartbeat_silence_seconds=INTERVAL * 1.5)
    assert report.ok, report.notes
    assert report.heartbeats_checked == 4
    assert report.heartbeat_silences == []


def test_ledger_silence_is_flagged_with_the_window(tmp_path):
    path = _ledger_with_window(tmp_path, down_for=7200)
    report = verify_ledger(path, max_heartbeat_silence_seconds=INTERVAL * 1.5)
    assert not report.ok
    assert len(report.heartbeat_silences) == 1
    gap = report.heartbeat_silences[0]
    assert (gap["from_seq"], gap["to_seq"]) == (2, 4)
    assert gap["seconds"] == pytest.approx(7200)


def test_listed_gap_is_accepted_and_noted(tmp_path):
    path = _ledger_with_window(tmp_path, down_for=7200)
    report = verify_ledger(
        path, max_heartbeat_silence_seconds=INTERVAL * 1.5,
        heartbeat_gaps_allowed=[(2, 4)],
    )
    assert report.ok
    assert any("accepted by the caller" in n for n in report.notes)


def test_a_listed_gap_does_not_cover_a_different_one(tmp_path):
    path = _ledger_with_window(tmp_path, down_for=7200)
    report = verify_ledger(
        path, max_heartbeat_silence_seconds=INTERVAL * 1.5,
        heartbeat_gaps_allowed=[(1, 2)],
    )
    assert not report.ok


def test_bundle_silence_fail_and_pass(tmp_path):
    path = _ledger_with_window(tmp_path, down_for=7200)
    bundle = _bundle_from(path)
    bad = verify_bundle(bundle, max_heartbeat_silence_seconds=INTERVAL * 1.5)
    assert not bad.ok
    assert [(g["from_seq"], g["to_seq"]) for g in bad.heartbeat_silences] == [(2, 4)]
    good = verify_bundle(
        bundle, max_heartbeat_silence_seconds=INTERVAL * 1.5,
        heartbeat_gaps_allowed=[(2, 4)],
    )
    assert good.ok
    assert verify_bundle(bundle, max_heartbeat_silence_seconds=10_000).ok


def test_no_heartbeats_with_the_check_on_is_a_note_not_a_failure(tmp_path):
    led = Ledger(tmp_path / "ledger.db", "dev_hb")
    led.append(make_event("dev_hb"))
    led.close()
    report = verify_ledger(tmp_path / "ledger.db", max_heartbeat_silence_seconds=60)
    assert report.ok
    assert any("no heartbeat entries" in n for n in report.notes)


def test_unreadable_heartbeat_time_fails_closed_when_check_is_on(tmp_path):
    path = _ledger_with_window(tmp_path, down_for=INTERVAL)
    bundle = _bundle_from(path)
    ev = bundle["entries"][0]["event"]
    ev["payload"] = {"last_seq": 0, "device_time": "not a time", "interval_s": 900}
    ev["ts_device"] = "also not a time"
    report = verify_bundle(bundle, max_heartbeat_silence_seconds=INTERVAL * 2)
    assert not report.ok  # the edit also breaks the hash; the malformed note is there too
    assert any("no readable device_time" in m for m in report.malformed_bundle)


def test_heartbeat_dated_backwards_is_a_clock_note_and_fails_only_when_strict(tmp_path):
    path = tmp_path / "ledger.db"
    led = Ledger(path, "dev_hb")
    clock = FakeClock()
    _emitter(led, clock).start()
    clock.advance(-5000)
    led_hb = _emitter(led, clock)
    led_hb._next_due = 0.0
    led_hb.tick()
    led.close()
    report = verify_ledger(path, max_heartbeat_silence_seconds=10_000)
    assert report.ok
    assert any("went backwards" in f["reason"] for f in report.clock_findings)
    assert not verify_ledger(path, max_heartbeat_silence_seconds=10_000, strict_clock=True).ok
    assert verify_ledger(path).ok  # check off: unchanged


def test_cli_flags_flag_the_window_and_accept_a_listed_gap(tmp_path, capsys):
    path = _ledger_with_window(tmp_path, down_for=7200)
    assert verify_cli([str(path)]) == 0
    capsys.readouterr()
    code = verify_cli([str(path), "--max-heartbeat-silence", "1350"])
    out = capsys.readouterr().out
    assert code != 0
    assert "heartbeat gap" in out and "seq 2 and seq 4" in out
    code = verify_cli([str(path), "--max-heartbeat-silence", "1350",
                       "--heartbeat-gap", "2-4"])
    assert code == 0


def test_cli_rejects_a_bad_gap_argument(tmp_path):
    path = _ledger_with_window(tmp_path, down_for=INTERVAL)
    with pytest.raises(SystemExit):
        verify_cli([str(path), "--max-heartbeat-silence", "60", "--heartbeat-gap", "x"])


def test_heartbeat_is_a_known_event_kind():
    assert EventKind.HEARTBEAT.value == "heartbeat"
    assert verify_mod.EventKind is EventKind


# -- capability signal --------------------------------------------------------


def _ship(tmp_path, monkeypatch, runtime_info):
    from byoai.recorder.shipper import Shipper

    key = load_or_create_device_key(tmp_path)
    led = Ledger(tmp_path / "ledger.db", key.device_id)
    sent = {}

    def fake_post(self, path, body):
        sent[path] = body
        if path.endswith("checkpoints/batch"):
            return {"accepted": 1, "duplicates": 0,
                    "rejected": [{"seq_end": 1, "reason": "x"}]}
        return {"accepted": len(body["entries"]), "duplicates": 0, "gaps": []}

    monkeypatch.setattr(Shipper, "_post_signed_batch", fake_post)
    try:
        cp = Checkpointer(led, key, every_events=1000)
        HeartbeatEmitter(led, key.device_id, interval_s=INTERVAL).start()
        cp.note(1)
        cp.flush()
        s = Shipper(led, key, coriqo_base_url="http://x.test", runtime_info=runtime_info)
        s.ship_once()
        res = s.ship_checkpoints_once()
        s.close()
    finally:
        led.close()
    return sent, res


def test_batches_carry_the_capability_when_heartbeats_run(tmp_path, monkeypatch):
    from byoai.recorder.shipper import runtime_info

    sent, res = _ship(tmp_path, monkeypatch, lambda: runtime_info(INTERVAL))
    ing = sent["/v1/ingest/batch"]
    assert ing["runtime"]["capabilities"] == ["heartbeat_chain_v1"]
    assert ing["runtime"]["heartbeat_interval_s"] == INTERVAL
    assert set(ing) == {"device_id", "entries", "runtime"}
    assert ing["entries"][0]["event"]["kind"] == "heartbeat"
    assert sent["/v1/checkpoints/batch"]["runtime"] == ing["runtime"]
    # A rejected checkpoint still parses via its seq_end and holds the watermark.
    assert res.synced_checkpoint_up_to == 0


def test_no_capability_when_not_wired_or_when_it_reports_none(tmp_path, monkeypatch):
    for info in (None, lambda: None):
        sent, _ = _ship(tmp_path / str(id(info)), monkeypatch, info)
        assert set(sent["/v1/ingest/batch"]) == {"device_id", "entries"}
        assert set(sent["/v1/checkpoints/batch"]) == {"device_id", "checkpoints"}


def test_recorder_claims_the_capability_only_while_the_thread_runs(tmp_path, monkeypatch):
    from byoai.recorder.integration import Recorder

    monkeypatch.setenv("BYOAI_RECORDER_HEARTBEAT_SECONDS", "0")
    off = Recorder(dir=tmp_path / "off")
    try:
        assert off.runtime_info() is None
    finally:
        off.close()
    monkeypatch.setenv("BYOAI_RECORDER_HEARTBEAT_SECONDS", "3600")
    on = Recorder(dir=tmp_path / "on")
    try:
        info = on.runtime_info()
        assert info["capabilities"] == ["heartbeat_chain_v1"]
        assert info["heartbeat_interval_s"] == 3600
        on._heartbeat_stop.set()
        on._heartbeat_thread.join(timeout=5)
        assert on.runtime_info() is None  # thread gone: no claim
    finally:
        on.close()


# -- review fixes ----------------------------------------------------------------


class SplitClock:
    """Wall and monotonic clocks that can move independently."""

    def __init__(self, wall: float = T0, mono: float = 50_000.0) -> None:
        self.wall = wall
        self.mono = mono

    def wall_clock(self) -> float:
        return self.wall

    def monotonic(self) -> float:
        return self.mono

    def advance(self, seconds: float, *, wall: bool = True) -> None:
        self.mono += seconds
        if wall:
            self.wall += seconds


def _split_emitter(led, c):
    return HeartbeatEmitter(led, "dev_hb", interval_s=INTERVAL,
                            wall_clock=c.wall_clock, monotonic=c.monotonic)


def test_clock_set_back_across_an_outage_is_flagged_by_the_monotonic_counter(tmp_path):
    # 3 real hours pass (monotonic) while the wall clock is set so the restart
    # heartbeat reads 901s after the first: spacing alone would pass.
    path = tmp_path / "ledger.db"
    led = Ledger(path, "dev_hb")
    c = SplitClock()
    _split_emitter(led, c).start()
    c.mono += 3 * 3600
    c.wall += 901
    _split_emitter(led, c).start()
    led.close()
    report = verify_ledger(path, max_heartbeat_silence_seconds=1000)
    assert report.ok  # advisory
    assert any("set back" in f["reason"] for f in report.clock_findings)


def test_a_slept_laptop_is_not_flagged(tmp_path):
    path = tmp_path / "ledger.db"
    led = Ledger(path, "dev_hb")
    c = SplitClock()
    _split_emitter(led, c).start()
    c.wall += 3 * 3600  # asleep: wall advances, the monotonic counter does not
    c.mono += 5
    _split_emitter(led, c).start()
    led.close()
    report = verify_ledger(path, max_heartbeat_silence_seconds=1000)
    assert report.clock_findings == []
    # The long gap, and no clock finding.
    assert [s["kind"] for s in report.heartbeat_silences] == ["spacing"]


def test_heartbeat_outside_its_signed_checkpoint_is_flagged(tmp_path):
    key = load_or_create_device_key(tmp_path / "k")
    path = tmp_path / "ledger.db"
    led = Ledger(path, key.device_id)
    c = SplitClock()
    cp = Checkpointer(led, key, every_events=10_000, every_seconds=10_000.0,
                      monotonic=c.monotonic, wall_clock=lambda: T0 - 7200)  # checkpoint clock
    hb = HeartbeatEmitter(led, key.device_id, interval_s=INTERVAL, wall_clock=c.wall_clock,
                          monotonic=c.monotonic, on_entry=lambda e: cp.note(e.seq))
    hb.start()
    cp.flush()
    led.close()
    report = verify_ledger(path, max_heartbeat_silence_seconds=1000)
    assert any("covers it" in f["reason"] for f in report.clock_findings)
    assert report.ok
    assert not verify_ledger(path, max_heartbeat_silence_seconds=1000, strict_clock=True).ok


def test_bundle_epoch_end_bounds_heartbeat_time(tmp_path):
    path = _ledger_with_window(tmp_path, down_for=INTERVAL)
    bundle = _bundle_from(path)
    bundle["checkpoints"] = [{
        "checkpoint": {"device_id": "dev_hb", "seq_start": 1, "seq_end": 5,
                       "chain_head": "x", "ts_device": "2026-12-01T00:00:00.000000Z"},
        "epoch_index": 0, "inclusion_proof": None,
    }]
    bundle["epochs"] = [{"epoch_index": 0, "root": "00" * 32,
                         "epoch_end": "2026-01-01T00:00:00Z"}]
    report = verify_bundle(bundle, max_heartbeat_silence_seconds=INTERVAL * 2)
    assert any("tenant epoch" in f["reason"] for f in report.clock_findings)
    assert not verify_bundle(bundle, max_heartbeat_silence_seconds=INTERVAL * 2,
                             strict_clock=True).ok


def test_record_with_no_heartbeats_fails_with_the_check_on(tmp_path):
    path = tmp_path / "ledger.db"
    led = Ledger(path, "dev_hb")
    led.append(make_event("dev_hb"))
    e2 = make_event("dev_hb")
    from dataclasses import replace

    led.append(replace(e2, ts_device="2026-08-10T14:00:00.000000Z"))  # 2h later
    led.close()
    assert verify_ledger(path).ok  # off by default
    r = verify_ledger(path, max_heartbeat_silence_seconds=900)
    assert r.no_heartbeats and not r.ok
    assert verify_ledger(path, max_heartbeat_silence_seconds=900,
                         allow_no_heartbeats=True).ok
    assert not verify_bundle(_bundle_from(path), max_heartbeat_silence_seconds=900).ok


def test_heartbeats_stripped_from_a_chain_cannot_pass(tmp_path):
    # Removing entries breaks the chain (gaps) and the check also fails.
    path = _ledger_with_window(tmp_path, down_for=INTERVAL)
    bundle = _bundle_from(path)
    bundle["entries"] = [e for e in bundle["entries"] if e["event"]["kind"] != "heartbeat"]
    r = verify_bundle(bundle, max_heartbeat_silence_seconds=INTERVAL * 2)
    assert not r.ok and r.gaps


def test_tail_after_the_last_heartbeat_is_judged(tmp_path):
    path = tmp_path / "ledger.db"
    led = Ledger(path, "dev_hb")
    c = SplitClock()
    _split_emitter(led, c).start()  # seq 1 at T0
    from dataclasses import replace

    late = replace(make_event("dev_hb"),
                   ts_device="2026-10-20T00:00:00.000000Z")  # a day+ after T0
    led.append(late)
    led.close()
    r = verify_ledger(path, max_heartbeat_silence_seconds=INTERVAL * 2)
    assert not r.ok
    assert [s["kind"] for s in r.heartbeat_silences] == ["tail"]
    assert verify_ledger(path, max_heartbeat_silence_seconds=INTERVAL * 2,
                         heartbeat_gaps_allowed=["tail:1"]).ok


def test_disabled_marker_is_written_once_and_reported_as_not_covered(tmp_path, monkeypatch):
    from byoai.recorder.heartbeat import write_disabled_marker
    from byoai.recorder.integration import Recorder

    monkeypatch.setenv("BYOAI_RECORDER_HEARTBEAT_SECONDS", "0")
    d = tmp_path / "rec"
    for _ in range(3):  # restarts with heartbeats still off
        r = Recorder(dir=d)
        r.close()
    led = Ledger(d / "ledger.db", "x")
    beats = _heartbeats(led)
    assert len(beats) == 1 and beats[0].event.payload["interval_s"] == 0
    assert write_disabled_marker(led, "x") is None
    led.close()
    report = verify_ledger(d / "ledger.db", max_heartbeat_silence_seconds=900)
    assert not report.ok
    assert [s["kind"] for s in report.heartbeat_silences] == ["disabled"]
    assert verify_ledger(d / "ledger.db", max_heartbeat_silence_seconds=900).heartbeats_checked == 1
    assert verify_ledger(d / "ledger.db").ok  # check off


def test_policy_must_be_finite_and_positive(tmp_path, capsys):
    from byoai.recorder.verify import VerifyError

    path = _ledger_with_window(tmp_path, down_for=INTERVAL)
    for bad in (float("nan"), float("inf"), 0, -5, True):
        with pytest.raises(VerifyError):
            verify_ledger(path, max_heartbeat_silence_seconds=bad)
        with pytest.raises(VerifyError):
            verify_bundle(_bundle_from(path), max_heartbeat_silence_seconds=bad)
    for bad in ("nan", "inf", "0", "-1", "abc"):
        with pytest.raises(SystemExit) as exc:
            verify_cli([str(path), "--max-heartbeat-silence", bad])
        assert exc.value.code == 2
    capsys.readouterr()


def test_bundle_subcommand_runs_the_check(tmp_path, capsys):
    path = _ledger_with_window(tmp_path, down_for=7200)
    f = tmp_path / "bundle.json"
    f.write_text(json.dumps(_bundle_from(path)))
    assert verify_cli(["bundle", str(f), "--skip-anchors"]) == 0
    capsys.readouterr()
    code = verify_cli(["bundle", str(f), "--skip-anchors", "--max-heartbeat-silence", "1350"])
    out = capsys.readouterr().out
    assert code == 1 and "heartbeat gap" in out and "seq 2 and seq 4" in out
    assert verify_cli(["bundle", str(f), "--skip-anchors", "--max-heartbeat-silence", "1350",
                       "--heartbeat-gap", "2-4"]) == 0
    assert verify_cli(["bundle", str(tmp_path / "nope.json")]) == 2


def test_last_seq_is_seq_minus_one_after_a_failure_marker_is_drained(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "ledger.db", "dev_hb")
    led.append(make_event("dev_hb"))  # seq 1
    led._pending_failures.append(
        {"event_id": "e", "kind": "tool_use", "session_id": "s", "tool_use_id": None,
         "error": "boom", "ts_device": "2026-08-10T12:00:00.000000Z"}
    )
    entry = _emitter(led, FakeClock()).start()
    kinds = [e.event.kind for e in led.iter_entries()]
    assert kinds == ["tool_use", "record_failure", "heartbeat"]
    assert entry.seq == 3 and entry.event.payload["last_seq"] == 2
    led.close()


def test_last_seq_survives_a_stale_head_resync(tmp_path):
    path = tmp_path / "ledger.db"
    a = Ledger(path, "dev_hb")
    b = Ledger(path, "dev_hb")  # a second writer on the same file
    a.append(make_event("dev_hb"))
    a.append(make_event("dev_hb"))
    entry = _emitter(b, FakeClock()).start()  # b's in-memory head is stale
    assert entry.seq == 3 and entry.event.payload["last_seq"] == 2
    a.close()
    b.close()


@pytest.mark.skipif(not hasattr(__import__("os"), "fork"), reason="needs os.fork (POSIX)")
def test_heartbeat_thread_restarts_in_a_forked_child(tmp_path, monkeypatch):
    import os
    import time

    from byoai.recorder.integration import Recorder

    monkeypatch.setenv("BYOAI_RECORDER_HEARTBEAT_SECONDS", "1")
    rec = Recorder(dir=tmp_path / "rec")
    try:
        parent_thread = rec._heartbeat_thread
        pid = os.fork()
        if pid == 0:  # child
            code = 1
            try:
                rec.ledger.snapshot()  # first use in the child restarts the thread
                t = rec._heartbeat_thread
                if t is not None and t is not parent_thread and t.is_alive():
                    before = rec.ledger.last_entry_of_kind("heartbeat").seq
                    deadline = time.time() + 6
                    while time.time() < deadline:
                        if rec.ledger.last_entry_of_kind("heartbeat").seq > before:
                            code = 0
                            break
                        time.sleep(0.1)
            finally:
                os._exit(code)
        _, status = os.waitpid(pid, 0)
        assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    finally:
        rec.close()


def test_volume_over_a_simulated_day_at_the_default_interval(tmp_path):
    """Measured numbers quoted in CONFIGURATION.md."""
    key = load_or_create_device_key(tmp_path / "k")
    led = Ledger(tmp_path / "ledger.db", key.device_id)
    c = SplitClock()
    cp = Checkpointer(led, key, monotonic=c.monotonic, wall_clock=c.wall_clock)
    hb = HeartbeatEmitter(led, key.device_id, interval_s=INTERVAL, wall_clock=c.wall_clock,
                          monotonic=c.monotonic, on_entry=lambda e: cp.note(e.seq))
    hb.start()
    for _ in range(24 * 3600 // INTERVAL):
        c.advance(INTERVAL)
        hb.tick()
    beats = len(_heartbeats(led))
    checkpoints = len(led.iter_checkpoints())
    led.close()
    assert beats == 97  # start + 96
    # About one checkpoint per two idle heartbeats, never one per heartbeat.
    assert checkpoints <= beats // 2 + 1, (beats, checkpoints)
    print(f"idle day at {INTERVAL}s: {beats} heartbeats, {checkpoints} checkpoints")
