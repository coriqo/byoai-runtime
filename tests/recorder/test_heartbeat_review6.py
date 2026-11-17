"""Round-4 review fixes: fork safety, rollback on any exception, builder
failures in non-strict mode, boot id privacy."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import textwrap

import pytest
from tests.recorder.conftest import make_event

from byoai.recorder.ledger import Ledger, LedgerWriteError
from byoai.recorder.verify import verify_bundle, verify_ledger

needs_fork = pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork (POSIX)")


def _run(code: str, timeout: float = 90.0) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(p for p in sys.path if p)
    env["BYOAI_RECORDER_HEARTBEAT_SECONDS"] = "3600"
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], env=env,
                          capture_output=True, text=True, timeout=timeout)


# -- 1. two threads forking at once -------------------------------------------


@needs_fork
def test_concurrent_forks_never_strand_the_ledger_lock():
    r = _run('''
        import faulthandler, os, sys, tempfile, threading
        faulthandler.dump_traceback_later(60, exit=True)
        from byoai.recorder import integration as I
        rec = I.Recorder(dir=tempfile.mkdtemp())
        errs = []
        sys.setswitchinterval(1e-6)
        sys.unraisablehook = lambda u: errs.append(repr(u.exc_value))
        def forker():
            for _ in range(150):
                pid = os.fork()
                if pid == 0:
                    os._exit(0)
                os.waitpid(pid, 0)
        ts = [threading.Thread(target=forker) for _ in range(4)]
        [t.start() for t in ts]
        [t.join(timeout=50) for t in ts]
        print("hung", any(t.is_alive() for t in ts), "errs", errs,
              "lock", rec.ledger._lock.acquire(timeout=3))
        sys.stdout.flush()
        os._exit(0)
    ''')
    assert r.returncode == 0, r.stderr[-500:]
    assert "hung False errs [] lock True" in r.stdout, (r.stdout, r.stderr[-500:])


# -- 2. KeyboardInterrupt inside the write -------------------------------------


def test_keyboard_interrupt_mid_append_rolls_back(tmp_path):
    led = Ledger(tmp_path / "l.db", "d")

    def interrupted(_last):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        led.append_stamped(interrupted)
    assert not led._conn.in_transaction
    assert led.append(make_event("d")) is not None  # the next append works
    other = sqlite3.connect(tmp_path / "l.db", timeout=0.5)
    other.execute("BEGIN IMMEDIATE")  # another process can write
    other.execute("ROLLBACK")
    other.close()
    led.close()
    assert verify_ledger(tmp_path / "l.db").ok


def test_keyboard_interrupt_during_commit_rolls_back(tmp_path, monkeypatch):
    led = Ledger(tmp_path / "l.db", "d")
    real = led._conn

    class Proxy:
        def __init__(self, conn):
            self._c = conn

        def execute(self, sql, *a):
            if sql == "COMMIT":
                raise KeyboardInterrupt
            return self._c.execute(sql, *a)

        @property
        def in_transaction(self):
            return self._c.in_transaction

    led._conn_ = Proxy(real)
    with pytest.raises(KeyboardInterrupt):
        led.append(make_event("d"))
    led._conn_ = real
    assert not real.in_transaction
    assert led.append(make_event("d")) is not None
    led.close()


# -- 3. builder raising ---------------------------------------------------------


def test_builder_error_in_non_strict_mode_does_not_raise_and_is_recorded(tmp_path):
    led = Ledger(tmp_path / "l.db", "d", strict_mode=False)
    calls = []

    def boom(_last):
        calls.append(1)
        raise ValueError("builder boom")

    assert led.append_stamped(boom) is None
    assert len(calls) == 1 or len(calls) == 2  # never an unhandled second raise
    assert len(led._pending_failures) == 1
    assert "builder boom" in led._pending_failures[0]["error"]
    assert not led._conn.in_transaction
    assert led.append(make_event("d")) is not None
    kinds = [e.event.kind for e in led.iter_entries()]
    assert "record_failure" in kinds
    led.close()


def test_builder_error_on_a_closed_non_strict_ledger_does_not_raise(tmp_path):
    led = Ledger(tmp_path / "l.db", "d", strict_mode=False)
    led.close()

    def boom(_last):
        raise ValueError("builder boom")

    assert led.append_stamped(boom) is None


def test_builder_error_in_strict_mode_still_raises(tmp_path):
    led = Ledger(tmp_path / "l.db", "d", strict_mode=True)

    def boom(_last):
        raise ValueError("builder boom")

    with pytest.raises(LedgerWriteError):
        led.append_stamped(boom)
    led.close()


# -- 4. fork + exec (subprocess preexec_fn) -------------------------------------


@needs_fork
def test_preexec_child_opens_no_connection_and_starts_no_thread():
    r = _run('''
        import os, subprocess, tempfile, threading
        from byoai.recorder import integration as I
        rec = I.Recorder(dir=tempfile.mkdtemp())
        def pre():
            os.write(2, ("CHILD threads=%s abandoned=%s pending=%s\\n" % (
                sorted(t.name for t in threading.enumerate()),
                len(getattr(rec.ledger, "_abandoned_conns", [])),
                rec.ledger._needs_reopen)).encode())
        subprocess.run(["true"], preexec_fn=pre)
        rec.close()
    ''')
    assert r.returncode == 0, r.stderr[-500:]
    line = [ln for ln in r.stderr.splitlines() if ln.startswith("CHILD")][0]
    assert "threads=['MainThread']" in line and "abandoned=0" in line, line
    assert "pending=True" in line  # reopen is deferred to first use


@needs_fork
def test_fork_does_not_wait_long_for_a_busy_ledger():
    r = _run('''
        import logging, subprocess, tempfile, threading, time
        logging.basicConfig()
        from byoai.recorder import integration as I
        rec = I.Recorder(dir=tempfile.mkdtemp())
        ev = threading.Event()
        def hold():
            with rec.ledger._lock:
                ev.set()
                time.sleep(4)
        threading.Thread(target=hold, daemon=True).start()
        ev.wait()
        t = time.time()
        subprocess.run(["true"], preexec_fn=lambda: None)
        print("SPAWN_S", round(time.time() - t, 2))
    ''')
    assert r.returncode == 0, r.stderr[-500:]
    secs = float(r.stdout.split("SPAWN_S")[1].split()[0])
    assert secs < 2.5, secs  # bounded wait (1 s), not the 4 s the append held the lock
    assert r.stderr.count("forking without its lock") == 1


@needs_fork
def test_child_that_uses_the_ledger_reopens_and_heartbeats(tmp_path, monkeypatch):
    from byoai.recorder.integration import Recorder

    monkeypatch.setenv("BYOAI_RECORDER_HEARTBEAT_SECONDS", "3600")
    rec = Recorder(dir=tmp_path / "rec")
    parent_conn = rec.ledger._conn
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            n = rec.ledger.snapshot()[0]  # first use: reopens, restarts the heartbeat
            if rec.ledger._conn is not parent_conn and rec._heartbeat_thread is not None:
                for _ in range(20):
                    rec.ledger.append(make_event(rec.key.device_id))
                code = 0 if n >= 1 else 2
        finally:
            os._exit(code)
    for _ in range(20):
        rec.ledger.append(make_event(rec.key.device_id))
    _, status = os.waitpid(pid, 0)
    rec.checkpointer.flush()
    key = rec.key
    rec.close()
    assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    assert verify_ledger(tmp_path / "rec" / "ledger.db", public_key_b64=key.public_key_b64).ok


# -- 5. boot id privacy ----------------------------------------------------------


def test_old_and_raw_format_boot_ids_are_handled(tmp_path):
    from tests.recorder.test_heartbeat_review3 import Clk, _bundle, _rig

    key, led, c, cp, hb = _rig(tmp_path)
    for dw, dm in [(0, 0), (900, 900), (900, 900)]:
        c.step(dw, dm)
        cp.note(hb._emit().seq)
    cp.flush()
    led.close()
    b = _bundle(tmp_path, key)
    ev = [e["event"] for e in b["entries"] if e["event"]["kind"] == "heartbeat"]
    ev[0]["payload"].pop("boot_id", None)  # an old entry without the field
    ev[1]["payload"]["boot_id"] = "boottime:1794572554"  # the raw format
    r = verify_bundle(b, max_heartbeat_silence_seconds=1800)  # hashes break; must not raise
    assert r.broken_links  # edited payloads are tamper, reported not crashed
    assert Clk  # keep import used
