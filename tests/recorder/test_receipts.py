"""R-3: every sent trace is tracked, reconciled with the response, and receipts are verified."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import threading
import time
import types
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from byoai.recorder.coriqo_agents import (
    CoriqoAgentsClient,
    CoriqoAgentsError,
    CoriqoCredentials,
    publish_session,
)
from byoai.recorder.keys import DeviceKey, load_or_create_device_key
from byoai.recorder.ledger import Ledger
from byoai.recorder.receipts import (
    ReceiptFetcher,
    ReceiptStore,
    ReceiptStoreError,
    fetch_receipts,
)
from byoai.recorder.schema import EventKind
from byoai.recorder.verify import verify_ledger, verify_receipts

from .conftest import make_event

LATER = datetime.now(timezone.utc) + timedelta(hours=2)
OLD = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()


def _h(obj):
    """Independent restatement of Coriqo's canonical hash (not the code under test)."""
    if obj is None:
        return None
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(raw.encode()).hexdigest()


def _client(handler, signer=None, api_key_header=False) -> CoriqoAgentsClient:
    http = httpx.Client(
        base_url="https://c.test",
        transport=httpx.MockTransport(handler),
        headers={"X-API-Key": "k"} if api_key_header else None,
    )
    return CoriqoAgentsClient(
        CoriqoCredentials(base_url="https://c.test", api_key="k", tenant_slug="t"),
        http_client=http,
        device_signer=signer,
    )


def _server(swallow=(), empty_hash=(), sealed=(), bad_input=(), bad_output=(), status=None,
            short_count=False):
    """Acknowledges traces with an event_hash and honest echoed hashes.

    swallow: step indexes omitted from the response. empty_hash: step indexes
    returned with an empty event_hash. bad_*: echo a wrong hash. status: fixed
    status for receipt GETs."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/trajectories"):
            return httpx.Response(201, json={"trajectory_id": "traj-1"})
        if path.endswith("/complete"):
            return httpx.Response(200, json={})
        if path.endswith("/traces/batch"):
            body = json.loads(request.content)
            out = []
            for t in body["traces"]:
                i = t["step_index"]
                if i in swallow:
                    continue
                out.append({
                    "trace_id": f"t{i}", "step_index": i, "status": "recorded",
                    "event_hash": "" if i in empty_hash else f"h{i}",
                    "input_hash": "0" * 64 if i in bad_input else _h(t["inputs"]),
                    "output_hash": "f" * 64 if i in bad_output else _h(t["output"]),
                })
            n = len(body["traces"]) if short_count else len(out)
            return httpx.Response(201, json={"recorded": n, "flagged": 0, "traces": out})
        if "/receipts/" in path:
            if status is not None:
                return httpx.Response(status, json={"detail": "nope"})
            h = path.rsplit("/", 1)[1]
            if h in sealed:
                return httpx.Response(200, json={"status": "sealed", "event_hash": h})
            return httpx.Response(202, json={"status": "pending"})
        raise AssertionError(path)

    return handler


def _ledger(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    key = load_or_create_device_key(tmp_path)
    led = Ledger(tmp_path / "ledger.db", device_id=key.device_id)
    for i in range(2):
        led.append(make_event("dev", "run_1", EventKind.TOOL_USE, payload={"i": i}, tool_use_id=f"u{i}", tool_name=f"t{i}"))
        led.append(make_event("dev", "run_1", EventKind.TOOL_RESULT, payload={"i": i}, tool_use_id=f"u{i}", tool_name=f"t{i}"))
    return led


def _publish(led, handler):
    with _client(handler) as c:
        publish_session(c, coriqo_agent_id="a", ledger=led, session_id="run_1")


def _rows(led):
    return {r["key"]: r for r in ReceiptStore.for_ledger(led).entries()}


def _sent(store, i, event_hash=None, sent_at=OLD):
    store.record_sent("s", i, input_hash=None, output_hash=None, sent_at=sent_at)
    if event_hash:
        store.record_ack("s", i, {"event_hash": event_hash})


# -- 1. every sent trace is tracked; a swallowed one is flagged ---------------


def test_publish_writes_a_row_per_sent_step_keyed_by_session_and_step(tmp_path):
    led = _ledger(tmp_path)
    _publish(led, _server())
    rows = _rows(led)
    assert set(rows) == {"traj-1/run_1#0", "traj-1/run_1#1"}
    assert rows["traj-1/run_1#0"]["event_hash"] == "h0" and rows["traj-1/run_1#1"]["event_hash"] == "h1"
    led.close()


@pytest.mark.parametrize(
    "kw", [{"swallow": (1,)}, {"empty_hash": (1,)}, {"swallow": (1,), "short_count": True}]
)
def test_swallowed_or_unhashed_event_is_an_unacknowledged_finding_for_exactly_that_step(tmp_path, kw):
    led = _ledger(tmp_path)
    _publish(led, _server(**kw))
    rows = _rows(led)
    assert rows["traj-1/run_1#0"]["event_hash"] == "h0"
    assert rows["traj-1/run_1#1"]["event_hash"] is None  # the row exists although nothing came back
    store = ReceiptStore.for_ledger(led)
    rep = verify_receipts(store.path, overdue_after_seconds=3600, now=LATER, allow_unchecked=True)
    assert rep["unacknowledged"] == ["traj-1/run_1#1"]
    assert rep["ok"] is False
    young = verify_receipts(store.path, overdue_after_seconds=3600, allow_unchecked=True)
    assert young["unacknowledged"] == []
    led.close()


def test_request_that_fails_midway_still_leaves_unacknowledged_rows(tmp_path):
    led = _ledger(tmp_path)

    def handler(request):
        if request.url.path.endswith("/traces/batch"):
            return httpx.Response(500, text="boom")
        return _server()(request)

    with _client(handler) as c, pytest.raises(CoriqoAgentsError):
        publish_session(c, coriqo_agent_id="a", ledger=led, session_id="run_1")
    rows = _rows(led)
    assert set(rows) == {"traj-1/run_1#0", "traj-1/run_1#1"}
    assert all(r["event_hash"] is None for r in rows.values())
    assert all(r["rejected"]["status"] == 500 for r in rows.values())
    led.close()


# -- 2. content alteration ---------------------------------------------------


def test_echoed_hash_that_differs_from_what_was_sent_is_content_mismatch(tmp_path):
    led = _ledger(tmp_path)
    _publish(led, _server(bad_input=(0,), bad_output=(1,)))
    rep = verify_receipts(ReceiptStore.for_ledger(led).path, allow_unchecked=True)
    got = {m["key"]: m["fields"] for m in rep["content_mismatch"]}
    assert got == {"traj-1/run_1#0": ["input_hash"], "traj-1/run_1#1": ["output_hash"]}
    assert rep["ok"] is False
    assert any("does not show the sealed event hash" in n for n in rep["notes"])
    led.close()


def test_honest_echo_is_not_a_mismatch(tmp_path):
    led = _ledger(tmp_path)
    _publish(led, _server())
    rep = verify_receipts(ReceiptStore.for_ledger(led).path, allow_unchecked=True)
    assert rep["content_mismatch"] == [] and rep["ok"] is True
    led.close()


def test_mismatch_is_rechecked_at_verify_time_even_if_ack_time_said_clean(tmp_path):
    led = _ledger(tmp_path)
    _publish(led, _server())
    store = ReceiptStore.for_ledger(led)
    data = json.loads(store.path.read_text())
    data["entries"]["traj-1/run_1#1"]["echoed_output_hash"] = "ab" * 32  # store edited afterwards
    store.path.write_text(json.dumps(data))
    rep = verify_receipts(store.path, allow_unchecked=True)
    assert [m["key"] for m in rep["content_mismatch"]] == ["traj-1/run_1#1"]
    led.close()


# -- fetch ---------------------------------------------------------------------


def test_fetch_stores_only_sealed_and_skips_young_rows(tmp_path):
    led = _ledger(tmp_path)
    _publish(led, _server(sealed=("h0",)))
    store = ReceiptStore.for_ledger(led)
    with _client(_server(sealed=("h0",))) as c:
        assert fetch_receipts(c, store, min_age_seconds=10**6) == 0  # too young
        assert fetch_receipts(c, store, min_age_seconds=0, now=LATER) == 1
    got = {r["key"]: bool(r.get("bundle")) for r in store.entries()}
    assert got == {"traj-1/run_1#0": True, "traj-1/run_1#1": False}
    led.close()


def test_fetch_failure_is_silent_and_does_not_raise(tmp_path):
    led = _ledger(tmp_path)
    _publish(led, _server())
    with _client(lambda r: httpx.Response(500, text="down")) as c:
        assert fetch_receipts(c, ReceiptStore.for_ledger(led), min_age_seconds=0) == 0
    led.close()


def test_overdue_receipt_is_reported(tmp_path):
    led = _ledger(tmp_path)
    _publish(led, _server(sealed=("h0",)))
    store = ReceiptStore.for_ledger(led)
    with _client(_server(sealed=("h0",))) as c:
        fetch_receipts(c, store, min_age_seconds=0)
    rep = verify_receipts(store.path, overdue_after_seconds=3600, now=LATER, allow_unchecked=True)
    assert rep["receipt_overdue"] == ["traj-1/run_1#1"] and rep["ok"] is False
    led.close()


@pytest.mark.parametrize("status", [404, 403])
def test_persistent_receipt_route_refusal_is_receipts_unavailable(tmp_path, status):
    led = _ledger(tmp_path / "a")
    _publish(led, _server())
    store = ReceiptStore.for_ledger(led)
    with _client(_server(status=status)) as c:
        for _ in range(3):
            fetch_receipts(c, store, min_age_seconds=0)
    rep = verify_receipts(store.path, allow_unchecked=True)
    assert {u["key"] for u in rep["receipts_unavailable"]} == {"traj-1/run_1#0", "traj-1/run_1#1"}
    assert all(u["status"] == status for u in rep["receipts_unavailable"])
    assert rep["receipt_overdue"] == [] and rep["ok"] is False

    led2 = _ledger(tmp_path / "b")  # a single refusal is not yet "unavailable"
    _publish(led2, _server())
    store2 = ReceiptStore.for_ledger(led2)
    with _client(_server(status=status)) as c:
        fetch_receipts(c, store2, min_age_seconds=0)
    assert verify_receipts(store2.path, allow_unchecked=True)["receipts_unavailable"] == []
    led.close()
    led2.close()


def test_fetch_pass_is_bounded_and_honours_stop(tmp_path):
    store = ReceiptStore(tmp_path / "r.json")
    for i in range(5):
        _sent(store, i, f"h{i}")
    seen = []

    class C:
        def get_receipt(self, h):
            seen.append(h)
            return {"status": "sealed", "event_hash": h}

    assert fetch_receipts(C(), store, min_age_seconds=0, max_rows=2) == 2
    assert len(seen) == 2
    seen.clear()
    calls = {"n": 0}

    def stop():
        calls["n"] += 1
        return calls["n"] > 1  # allow one row, then stop

    fetch_receipts(C(), store, min_age_seconds=0, should_stop=stop)
    assert len(seen) == 1


# -- 7. fetcher lifecycle -----------------------------------------------------


class _Client:
    def __init__(self, hang=None):
        self.closed = False
        self.hang = hang

    def get_receipt(self, h):
        if self.hang:
            self.hang.wait(5)
        return None

    def close(self):
        self.closed = True


def test_fetcher_runs_first_pass_immediately_and_closes_owned_client_after_exit(tmp_path):
    store = ReceiptStore(tmp_path / "r.json")
    _sent(store, 0, "h1")
    fetcher = ReceiptFetcher(_client(_server(sealed={"h1"})), store, interval_seconds=3600,
                             min_age_seconds=0).start()
    deadline = time.time() + 5
    while time.time() < deadline and not store.entries()[0].get("bundle"):
        time.sleep(0.02)
    assert store.entries()[0].get("bundle")  # interval is an hour: only an immediate pass explains this
    assert fetcher.stop() is True
    assert not fetcher._thread.is_alive()


def test_stop_does_not_close_client_while_thread_is_still_inside_a_fetch(tmp_path):
    store = ReceiptStore(tmp_path / "r.json")
    _sent(store, 0, "h1")
    gate = threading.Event()
    c = _Client(hang=gate)
    fetcher = ReceiptFetcher(c, store, interval_seconds=3600, min_age_seconds=0, owns_client=True).start()
    time.sleep(0.2)  # thread is now blocked in get_receipt
    assert fetcher.stop(timeout=0.1) is False
    assert c.closed is False
    gate.set()
    assert fetcher.stop(timeout=5) is True
    assert c.closed is True


def test_start_failure_closes_owned_client(tmp_path):
    c = _Client()
    fetcher = ReceiptFetcher(c, ReceiptStore(tmp_path / "r.json"), owns_client=True)

    class Boom:
        def start(self):
            raise RuntimeError("cannot start thread")

    fetcher._thread = Boom()
    with pytest.raises(RuntimeError):
        fetcher.start()
    assert c.closed is True


def test_unowned_client_is_never_closed(tmp_path):
    c = _Client()
    f = ReceiptFetcher(c, ReceiptStore(tmp_path / "r.json"), interval_seconds=0.01, min_age_seconds=0).start()
    assert f.stop() is True
    assert c.closed is False


# -- 4. store integrity ------------------------------------------------------


def test_concurrent_publish_and_fetch_threads_lose_no_rows(tmp_path):
    path = tmp_path / "r.json"
    n_writers, per = 4, 15
    errors = []
    seed = ReceiptStore(path)
    for i in range(per):
        _sent(seed, i, f"seed{i}")

    def writer(w):
        try:
            s = ReceiptStore(path)  # separate instance, as publisher and fetcher would be
            for i in range(per):
                s.record_sent(f"w{w}", i, input_hash=None, output_hash=None)
                s.record_ack(f"w{w}", i, {"event_hash": f"w{w}h{i}"})
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    class C:
        def get_receipt(self, h):
            return {"status": "sealed", "event_hash": h}

    def fetcher():
        try:
            fetch_receipts(C(), ReceiptStore(path), min_age_seconds=1800, max_rows=1000)
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(w,)) for w in range(n_writers)]
    threads += [threading.Thread(target=fetcher) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    rows = {r["key"]: r for r in ReceiptStore(path).entries()}
    want = {f"w{w}#{i}" for w in range(n_writers) for i in range(per)} | {f"s#{i}" for i in range(per)}
    assert set(rows) == want
    assert all(rows[f"w{w}#{i}"]["event_hash"] == f"w{w}h{i}" for w in range(n_writers) for i in range(per))
    assert all(rows[f"s#{i}"].get("bundle") for i in range(per))  # the fetcher's writes survived too


def test_two_store_instances_share_one_lock_per_resolved_path(tmp_path):
    (tmp_path / "sub").mkdir()
    a = ReceiptStore(tmp_path / "r.json")
    b = ReceiptStore(tmp_path / "sub" / ".." / "r.json")
    assert a._lock is b._lock


def test_corrupt_store_is_an_error_in_verify_and_is_not_overwritten(tmp_path):
    path = tmp_path / "r.json"
    path.write_text("{not json")
    rep = verify_receipts(path, allow_unchecked=True)
    assert rep["ok"] is False and "corrupt" in rep["store_error"]
    with pytest.raises(ReceiptStoreError):
        ReceiptStore(path).record_sent("s", 0, input_hash=None, output_hash=None)
    assert path.read_text() == "{not json"


def test_save_leaves_no_temp_files_behind(tmp_path):
    s = ReceiptStore(tmp_path / "r.json")
    for i in range(3):
        s.record_sent("s", i, input_hash=None, output_hash=None)
    assert [p.name for p in tmp_path.iterdir() if p.suffix == ".tmp"] == []


# -- 5/6/8. verify behaviour -------------------------------------------------


def test_empty_store_is_no_receipts_tracked_not_a_pass(tmp_path):
    rep = verify_receipts(tmp_path / "missing.json")
    assert rep["no_receipts_tracked"] is True and rep["ok"] is False
    assert "no receipts tracked" in rep["reasons"][0]
    assert verify_receipts(tmp_path / "missing.json", allow_unchecked=True)["ok"] is True


def test_malformed_rows_are_findings_not_crashes(tmp_path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"version": 2, "entries": {
        "a": {"key": "a", "event_hash": "h"},
        "b": {"key": "b", "sent_at": "not-a-date", "event_hash": None},
        "c": "junk",
    }}))
    rep = verify_receipts(path, allow_unchecked=True)
    assert {m.get("key") or m.get("row") for m in rep["malformed"]} == {"a", "b", 2}
    assert rep["ok"] is False


def _stub_verifier(monkeypatch, fn):
    mod = types.ModuleType("coriqo_agents.receipts")
    mod.verify_receipt = fn
    monkeypatch.setitem(sys.modules, "coriqo_agents", types.ModuleType("coriqo_agents"))
    monkeypatch.setitem(sys.modules, "coriqo_agents.receipts", mod)


def _store_with_bundles(tmp_path, hashes=("h0", "h1")):
    store = ReceiptStore(tmp_path / "r.json")
    for i, h in enumerate(hashes):
        _sent(store, i, h)
        store.store_bundle(f"s#{i}", {"event_hash": h})
    return store


def test_failed_bundle_is_reported_by_key(tmp_path, monkeypatch):
    _stub_verifier(monkeypatch, lambda b, k=None, allow_unpinned=False: {"ok": b["event_hash"] == "h0"})
    rep = verify_receipts(_store_with_bundles(tmp_path).path, public_key_pem="PEM")
    assert rep["failed"] == ["s#1"] and not rep["ok"]


def test_pinned_key_is_passed_through_and_unpinned_is_flagged(tmp_path, monkeypatch):
    seen = []

    def fake(bundle, key=None, allow_unpinned=False):
        seen.append((key, allow_unpinned))
        return {"ok": True}

    _stub_verifier(monkeypatch, fake)
    store = _store_with_bundles(tmp_path)
    pinned = verify_receipts(store.path, public_key_pem="PEM")
    assert pinned["ok"] is True and seen == [("PEM", False)] * 2
    unpinned = verify_receipts(store.path)
    assert unpinned["ok"] is False and unpinned["unpinned"] is True
    assert any("pinned" in r for r in unpinned["reasons"])
    assert verify_receipts(store.path, allow_unchecked=True)["ok"] is True


def test_without_sdk_bundles_are_not_checked_and_fail_unless_allowed(tmp_path, monkeypatch):
    monkeypatch.setitem(sys.modules, "coriqo_agents", None)
    monkeypatch.setitem(sys.modules, "coriqo_agents.receipts", None)
    store = _store_with_bundles(tmp_path, ("h0",))
    rep = verify_receipts(store.path, public_key_pem="PEM")
    assert rep["not_checked"] == ["s#0"] and rep["with_receipt"] == 1 and rep["ok"] is False
    assert verify_receipts(store.path, public_key_pem="PEM", allow_unchecked=True)["ok"] is True


def test_verify_ledger_folds_receipts_into_ok(tmp_path):
    led = _ledger(tmp_path)
    _publish(led, _server(swallow=(1,)))
    store = ReceiptStore.for_ledger(led)
    led.close()
    assert verify_ledger(tmp_path / "ledger.db").receipts is None
    rep = verify_ledger(tmp_path / "ledger.db", receipts_path=store.path,
                        receipt_overdue_after_seconds=0, allow_unchecked_receipts=True)
    assert rep.receipts["unacknowledged"] == ["traj-1/run_1#1"]
    assert rep.ok is False


def test_cli_receipt_flags(tmp_path, capsys):
    from byoai.recorder.cli import main

    ledger = _ledger(tmp_path)
    path = tmp_path / "ledger.db"
    store = ReceiptStore(tmp_path / "r.json")
    _sent(store, 0, None, sent_at=(datetime.now(timezone.utc) - timedelta(hours=5)).isoformat())
    ledger.close()
    args = [str(path), "--receipts", str(tmp_path / "r.json"), "--receipt-overdue-after", "60"]
    code = main(args + ["--json", "--allow-unchecked-receipts"])
    out = json.loads(capsys.readouterr().out)
    assert out["receipts"]["unacknowledged"] == ["s#0"]
    assert code == 1
    main(args)
    text = capsys.readouterr().out
    assert "unsigned local file" in text and "RECEIPTS: FAIL" in text


# -- 9. device-signed fetch --------------------------------------------------


def test_receipt_get_is_device_signed_and_drops_the_api_key(tmp_path):
    key = load_or_create_device_key(tmp_path)
    seen = {}

    def handler(request):
        seen["headers"] = dict(request.headers)
        seen["body"] = request.content
        return httpx.Response(200, json={"status": "sealed", "event_hash": "hx"})

    with _client(handler, signer=key, api_key_header=True) as c:
        assert c.get_receipt("hx")["event_hash"] == "hx"
    hdr = seen["headers"]
    assert "x-api-key" not in hdr
    assert {"x-coriqo-signature", "x-coriqo-public-key", "x-coriqo-timestamp", "x-coriqo-device"} <= set(hdr)
    assert hdr["x-coriqo-device"] == key.device_id
    assert hdr["x-coriqo-public-key"] == base64.b64decode(key.public_key_b64).hex()
    assert seen["body"] == b""
    payload = json.dumps({
        "body_sha256": hashlib.sha256(b"").hexdigest(),
        "method": "GET",
        "path": "/api/v1/receipts/hx",
        "public_key": hdr["x-coriqo-public-key"],
        "timestamp": hdr["x-coriqo-timestamp"],
    }, sort_keys=True, separators=(",", ":")).encode()
    sig = "ed25519:" + base64.b64encode(bytes.fromhex(hdr["x-coriqo-signature"])).decode()
    assert DeviceKey.verify(key.public_key_b64, payload, sig)


def test_without_a_device_signer_the_api_key_is_used():
    seen = {}

    def handler(request):
        seen.update(dict(request.headers))
        return httpx.Response(202, json={"status": "pending"})

    with _client(handler, api_key_header=True) as c:
        assert c.get_receipt("hx") is None
    assert seen["x-api-key"] == "k" and "x-coriqo-signature" not in seen


# -- 3. default off ----------------------------------------------------------


def test_recorder_receipt_fetcher_is_off_unless_explicitly_enabled(tmp_path, monkeypatch):
    from byoai.recorder.integration import Recorder

    monkeypatch.setenv("BYOAI_CORIQO_URL", "https://c.test")
    monkeypatch.setenv("BYOAI_CORIQO_API_KEY", "k")
    monkeypatch.setenv("BYOAI_CORIQO_TENANT_SLUG", "t")
    monkeypatch.delenv("BYOAI_RECORDER_RECEIPTS", raising=False)
    off = Recorder(dir=tmp_path / "off")
    try:
        assert off._receipt_fetcher is None
    finally:
        off.close()
    monkeypatch.setenv("BYOAI_RECORDER_RECEIPTS", "1")
    on = Recorder(dir=tmp_path / "on")
    try:
        assert on._receipt_fetcher is not None
    finally:
        on.close()


# -- 10. conformance against the real SDK verifier ---------------------------

# Run with a coriqo checkout that has the SDK:
#   CORIQO_SDK_PATH=/path/to/coriqo/sdk/coriqo-agents \
#     PYTHONPATH=src python -m pytest tests/recorder/test_receipts.py -q
# seal-verifier/testdata is found two levels above the SDK dir's parent
# (<coriqo>/sdk/coriqo-agents -> <coriqo>/seal-verifier/testdata).
_SDK = Path(os.environ["CORIQO_SDK_PATH"]) if os.environ.get("CORIQO_SDK_PATH") else None
_TD = _SDK.parent.parent / "seal-verifier" / "testdata" if _SDK else None


@pytest.fixture
def real_verifier(monkeypatch):
    if _SDK is None:
        pytest.skip("CORIQO_SDK_PATH not set (path to coriqo/sdk/coriqo-agents)")
    if not _SDK.exists() or not _TD.exists():
        pytest.skip(f"CORIQO_SDK_PATH={_SDK} or its seal-verifier/testdata not present")
    monkeypatch.syspath_prepend(str(_SDK))
    for name in [m for m in sys.modules if m == "coriqo_agents" or m.startswith("coriqo_agents.")]:
        monkeypatch.delitem(sys.modules, name)
    try:
        from coriqo_agents.receipts import verify_receipt  # pyright: ignore[reportMissingImports]  # sibling SDK put on sys.path just above
    except ImportError as exc:
        pytest.skip(f"coriqo_agents.receipts not importable: {exc}")
    return verify_receipt


def test_real_sdk_verifier_accepts_a_pinned_genuine_bundle_and_rejects_a_tampered_one(tmp_path, real_verifier):
    key = (_TD / "pubkey.pem").read_text()
    good = json.loads((_TD / "proof.json").read_text())
    bad = json.loads((_TD / "proof.json").read_text())
    bad["leaf_input"] = ("0" if bad["leaf_input"][0] != "0" else "1") + bad["leaf_input"][1:]
    store = ReceiptStore(tmp_path / "r.json")
    for i, (h, b) in enumerate((("good", good), ("bad", bad))):
        _sent(store, i, h)
        store.store_bundle(f"s#{i}", b)
    rep = verify_receipts(store.path, public_key_pem=key)
    assert rep["failed"] == ["s#1"]
    assert rep["results"]["s#0"]["ok"] is True
    assert rep["not_checked"] == [] and rep["unpinned"] is False

    # The genuine bundle with no pinned key: the real verifier reports key_pinned
    # as not_checked; we flag it and fail unless explicitly allowed.
    only_good = ReceiptStore(tmp_path / "g.json")
    _sent(only_good, 0, "good")
    only_good.store_bundle("s#0", good)
    unpinned = verify_receipts(only_good.path)
    assert unpinned["ok"] is False and unpinned["failed"] == [] and unpinned["unpinned"] is True
    assert verify_receipts(only_good.path, allow_unchecked=True)["ok"] is True


# -- review fixes ------------------------------------------------------------


def test_fetch_error_clears_when_route_answers_even_if_event_still_pending(tmp_path):
    led = _ledger(tmp_path)
    _publish(led, _server())
    store = ReceiptStore.for_ledger(led)
    with _client(_server(status=404)) as c:
        for _ in range(3):
            fetch_receipts(c, store, min_age_seconds=0)
    assert len(verify_receipts(store.path, allow_unchecked=True)["receipts_unavailable"]) == 2
    with _client(_server()) as c:  # route deployed; events still pending (202)
        assert fetch_receipts(c, store, min_age_seconds=0) == 0
    rows = _rows(led)
    assert all("fetch_error" not in r for r in rows.values())
    assert verify_receipts(store.path, allow_unchecked=True)["receipts_unavailable"] == []
    led.close()


def test_same_session_published_twice_keeps_both_trajectories(tmp_path):
    led = _ledger(tmp_path)
    for n, prefix in ((1, "a"), (2, "b")):
        def handler(request, n=n, prefix=prefix):
            path = request.url.path
            if path.endswith("/trajectories"):
                return httpx.Response(201, json={"trajectory_id": f"traj-{n}"})
            if path.endswith("/traces/batch"):
                body = json.loads(request.content)
                return httpx.Response(201, json={"recorded": 2, "flagged": 0, "traces": [
                    {"step_index": t["step_index"], "status": "recorded",
                     "event_hash": f"{prefix}{t['step_index']}",
                     "input_hash": _h(t["inputs"]), "output_hash": _h(t["output"])}
                    for t in body["traces"]]})
            return _server()(request)
        _publish(led, handler)
    rows = _rows(led)
    assert {k: r["event_hash"] for k, r in rows.items()} == {
        "traj-1/run_1#0": "a0", "traj-1/run_1#1": "a1",
        "traj-2/run_1#0": "b0", "traj-2/run_1#1": "b1"}
    fetched = []

    def rh(request):
        fetched.append(request.url.path.rsplit("/", 1)[1])
        return httpx.Response(200, json={"status": "sealed"})
    with _client(rh) as c:
        assert fetch_receipts(c, ReceiptStore.for_ledger(led), min_age_seconds=0) == 4
    assert sorted(fetched) == ["a0", "a1", "b0", "b1"]
    led.close()


def test_legacy_format_rows_are_still_read(tmp_path):
    store = ReceiptStore(tmp_path / "r.json")
    _sent(store, 0, "hh")  # legacy s#0 key
    rep = verify_receipts(store.path, overdue_after_seconds=3600, now=LATER, allow_unchecked=True)
    assert rep["acknowledged"] == 1 and rep["receipt_overdue"] == ["s#0"]


@pytest.mark.parametrize("status", [400, 423])
def test_rejected_batch_is_batch_rejected_not_unacknowledged(tmp_path, status):
    led = _ledger(tmp_path)

    def handler(request):
        if request.url.path.endswith("/traces/batch"):
            return httpx.Response(status, json={"detail": "no"})
        return _server()(request)

    with _client(handler) as c, pytest.raises(CoriqoAgentsError):
        publish_session(c, coriqo_agent_id="a", ledger=led, session_id="run_1")
    store = ReceiptStore.for_ledger(led)
    rep = verify_receipts(store.path, overdue_after_seconds=3600, now=LATER, allow_unchecked=True)
    assert rep["unacknowledged"] == []
    assert rep["batch_rejected"] == [
        {"key": "traj-1/run_1#0", "status": status}, {"key": "traj-1/run_1#1", "status": status}]
    assert rep["ok"] is False and any("rejected" in r for r in rep["reasons"])
    # waivable by forget()
    for k in list(_rows(led)):
        assert store.forget(k) is True
    assert store.forget("nope") is False
    # (an emptied store reports no_receipts_tracked, so re-check with a fresh row)
    led.close()


def test_rejected_row_is_waived_by_resend(tmp_path):
    store = ReceiptStore(tmp_path / "r.json")
    store.record_sent("s", 0, input_hash=None, output_hash=None, sent_at=OLD)
    store.mark_rejected("s", 0, 423)
    assert verify_receipts(store.path, now=LATER, allow_unchecked=True)["batch_rejected"] == [
        {"key": "s#0", "status": 423}]
    store.record_sent("s", 0, input_hash=None, output_hash=None)  # re-send
    store.record_ack("s", 0, {"event_hash": "h", "input_hash": None, "output_hash": None})
    rep = verify_receipts(store.path, now=LATER, allow_unchecked=True)
    assert rep["batch_rejected"] == [] and rep["acknowledged"] == 1


def test_republish_rejected_batch_clears_flag_and_updates_hashes(tmp_path):
    """A batch rejected with 400, then re-published with same session/step but
    different payload content, should clear the rejected flag and not report a
    stale mismatch on verify."""
    store = ReceiptStore(tmp_path / "r.json")
    # Initial publish with payload A, gets rejected
    input_hash_a = _h({"a": 1})
    output_hash_a = _h({"result": "a"})
    store.record_sent("s", 0, input_hash=input_hash_a, output_hash=output_hash_a, sent_at=OLD)
    store.mark_rejected("s", 0, 400)
    rep = verify_receipts(store.path, now=LATER, allow_unchecked=True)
    assert rep["batch_rejected"] == [{"key": "s#0", "status": 400}]
    assert rep["acknowledged"] == 0

    # Re-publish with payload B (different hashes), gets acknowledged
    input_hash_b = _h({"b": 2})
    output_hash_b = _h({"result": "b"})
    store.record_sent("s", 0, input_hash=input_hash_b, output_hash=output_hash_b)  # re-send
    # Server acknowledges with the new hashes
    store.record_ack("s", 0, {
        "event_hash": "h0",
        "input_hash": input_hash_b,
        "output_hash": output_hash_b,
    })
    # Verify: rejected flag is gone, hashes match, no content_mismatch
    # The row has an event_hash but no bundle yet, so allow_pending waives the
    # receipt_overdue check. The critical assertion is that the hashes were updated.
    rep = verify_receipts(store.path, now=LATER, allow_unchecked=True, allow_pending=True)
    assert rep["batch_rejected"] == []
    assert rep["acknowledged"] == 1
    assert rep["content_mismatch"] == []
    assert rep["ok"] is True


def test_swallowed_event_in_a_200_is_unacknowledged_not_rejected(tmp_path):
    led = _ledger(tmp_path)
    _publish(led, _server(swallow=(1,)))
    rows = _rows(led)
    assert "rejected" not in rows["traj-1/run_1#1"]
    rep = verify_receipts(ReceiptStore.for_ledger(led).path, overdue_after_seconds=3600,
                          now=LATER, allow_unchecked=True)
    assert rep["unacknowledged"] == ["traj-1/run_1#1"] and rep["batch_rejected"] == []
    led.close()


def test_cli_forget_rejected_drops_only_rejected_rows(tmp_path, capsys):
    from byoai.recorder.cli import main

    led = _ledger(tmp_path)
    store = ReceiptStore(tmp_path / "r.json")
    _sent(store, 0, "h0")
    store.record_sent("s", 1, input_hash=None, output_hash=None, sent_at=OLD)
    store.mark_rejected("s", 1, 400)
    led.close()
    args = [str(tmp_path / "ledger.db"), "--receipts", str(store.path), "--json",
            "--allow-unchecked-receipts"]
    main(args)
    assert json.loads(capsys.readouterr().out)["receipts"]["batch_rejected"] == [
        {"key": "s#1", "status": 400}]
    main(args + ["--forget-rejected"])
    assert json.loads(capsys.readouterr().out)["receipts"]["batch_rejected"] == []
    assert [r["key"] for r in store.entries()] == ["s#0"]


def test_allow_pending_receipts_waives_overdue_but_still_lists_it(tmp_path):
    from byoai.recorder.cli import main

    store = ReceiptStore(tmp_path / "r.json")
    _sent(store, 0, "h0")
    strict = verify_receipts(store.path, overdue_after_seconds=60, allow_unchecked=True)
    assert strict["ok"] is False and strict["receipt_overdue"] == ["s#0"]
    waived = verify_receipts(store.path, overdue_after_seconds=60, allow_unchecked=True,
                             allow_pending=True)
    assert waived["ok"] is True and waived["receipt_overdue"] == ["s#0"]
    # not a blanket waiver: an unacknowledged row still fails
    store.record_sent("s", 1, input_hash=None, output_hash=None, sent_at=OLD)
    assert verify_receipts(store.path, overdue_after_seconds=60, allow_unchecked=True,
                           allow_pending=True)["ok"] is False
    # CLI flag
    led = _ledger(tmp_path / "l")
    led.close()
    s2 = ReceiptStore(tmp_path / "r2.json")
    _sent(s2, 0, "h0")
    a = [str(tmp_path / "l" / "ledger.db"), "--receipts", str(s2.path),
         "--receipt-overdue-after", "60", "--allow-unchecked-receipts"]
    assert main(a) == 1
    assert main(a + ["--allow-pending-receipts"]) == 0
