"""What coriqo-mcp adds to a tool call, measured.

Two numbers, printed with ``-s`` and recorded in the README:

1. the decision itself (``Interposer.gate_request``: gate, latch, hash, and a
   ledger write), in process;
2. a whole ``tools/call`` round trip over stdio through ``coriqo-mcp``, against
   the same round trip straight to the server, with the record on.

The assertions are loose ceilings so a slow CI runner does not fail the build;
the README quotes the measured numbers and the machine, not these ceilings.
Run: ``pytest tests/integrations/test_coriqo_mcp_benchmark.py -s``
"""

from __future__ import annotations

import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

import pytest

from byoai.integrations.coriqo_mcp import Interposer
from byoai.recorder.denial_latch import denial_latch
from byoai.recorder.ledger import Ledger
from byoai.recorder.verdicts import VerdictRecorder, use_verdict_recorder

from .test_coriqo_mcp import ECHO, ENFORCE, _cli, call, env_with_src, file_gate

CALLS = 300
WARMUP = 30


def _percentiles(samples: list[float]) -> tuple[float, float]:
    ordered = sorted(samples)
    return statistics.median(ordered), ordered[int(len(ordered) * 0.95) - 1]


def test_decision_cost_in_process(tmp_path):
    denial_latch().reset()
    ledger = Ledger(tmp_path / "ledger.db", "bench-device")
    interposer = Interposer(file_gate(ENFORCE))
    samples: list[float] = []
    with use_verdict_recorder(VerdictRecorder(ledger=ledger)):
        for i in range(WARMUP + CALLS):
            msg = call("search", i, query="quarterly fees", limit=10)
            start = time.perf_counter()
            interposer.gate_request(msg)
            if i >= WARMUP:
                samples.append(time.perf_counter() - start)
    ledger.close()
    p50, p95 = _percentiles(samples)
    print(f"\ncoriqo-mcp decision + ledger write: p50 {p50 * 1e6:.0f} us, p95 {p95 * 1e6:.0f} us")
    assert p50 < 0.05


def _round_trips(argv: list[str], env: dict[str, str]) -> list[float]:
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, env=env)
    assert proc.stdin is not None and proc.stdout is not None
    samples: list[float] = []
    try:
        for i in range(WARMUP + CALLS):
            line = json.dumps(call("search", i, query="quarterly fees", limit=10)) + "\n"
            start = time.perf_counter()
            proc.stdin.write(line.encode())
            proc.stdin.flush()
            reply = json.loads(proc.stdout.readline())
            elapsed = time.perf_counter() - start
            assert reply["id"] == i
            if i >= WARMUP:
                samples.append(elapsed)
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)
    return samples


@pytest.mark.skipif(sys.platform == "win32", reason="line-buffered pipes differ on Windows")
def test_stdio_round_trip_overhead(tmp_path):
    env = env_with_src()
    direct = _round_trips([sys.executable, ECHO], env)
    wrapped = _round_trips(
        _cli("--mandate", str(ENFORCE), "--recorder-dir", str(tmp_path / "rec"), "--",
             sys.executable, ECHO),
        env,
    )
    d50, d95 = _percentiles(direct)
    w50, w95 = _percentiles(wrapped)
    print(
        f"\nstdio tools/call round trip over {CALLS} calls: direct p50 {d50 * 1e3:.3f} ms "
        f"p95 {d95 * 1e3:.3f} ms; through coriqo-mcp p50 {w50 * 1e3:.3f} ms "
        f"p95 {w95 * 1e3:.3f} ms; added p50 {(w50 - d50) * 1e3:.3f} ms"
    )
    assert w50 - d50 < 0.05
    assert Path(tmp_path / "rec" / "ledger.db").exists()
