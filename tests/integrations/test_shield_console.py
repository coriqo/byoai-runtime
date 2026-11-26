"""The fleet console served by ONE Mac — /v1/console/fleet* on local Shield.

The contract these endpoints answer is the same zod schema the console SPA
validates (web/src/api/schemas.ts); the honesty rules they must keep are in
``byoai.integrations.shield_console``'s docstring. Each test here pins one of
those rules: what is knowable locally is reported, what is not, is null.
"""
from __future__ import annotations

import json
import time as _time
from datetime import datetime, timedelta, timezone

import pytest

from byoai.integrations.shield import Feed, ShieldConfig
from byoai.integrations.shield_console import ShieldConsoleAPI


class StubPublisher:
    """Publisher.status() stand-in; the real one only speaks when enrolled."""

    def __init__(self, **overrides):
        self._status = {"connected": False, "tenant": None, "last_height": 0,
                        "last_sent_at": None, **overrides}

    def status(self):
        return dict(self._status)


def make_cfg(tmp_path):
    ledger = tmp_path / "captures.jsonl"
    ledger.write_text("")
    return ShieldConfig(
        ledger=ledger,
        seal_path=tmp_path / "sealchain.json",
        key_dir=tmp_path / "keys",
        policy_path=tmp_path / "policy.json",
        managed_policy_path=tmp_path / "managed_policy.json",
        sig_every=4, max_interactions=100,
    )


def rows(n=8, *, denied_at=None, age_minutes=5):
    """Rows stamped `age_minutes` ago (default: five, so every stamp is in the
    past and inside the console's default 24 h window, the way live traffic
    arriving before the request is)."""
    base = datetime.now() - timedelta(minutes=age_minutes)
    out = []
    for i in range(n):
        when = (base + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
        kind = "desktop.chat.request"
        row = {"wall_clock": when, "kind": kind, "app": "claude", "chars": 20 + i}
        if denied_at is not None and i == denied_at:
            row = {"wall_clock": when, "kind": "desktop.verdict.denied",
                   "app": "claude", "verdict": "blocked", "chars": 12}
        out.append(row)
    return out


def make_api(cfg, publisher=None, seed=None):
    cfg.ledger.write_text("".join(json.dumps(r) + "\n" for r in (seed or [])))
    feed = Feed(cfg)
    feed.scan_initial()
    return ShieldConsoleAPI(cfg, feed, publisher or StubPublisher())


def get(api, route, **query):
    qs = {k: [str(v)] for k, v in query.items()}
    qs.setdefault("tenant", ["acme-prod"])
    code, body = api.handle("/v1/console" + route, qs)
    return code, json.loads(body)


# ------------------------------------------------------------- the empty case


def test_never_seen_device_is_the_fourth_state_not_broken(tmp_path):
    api = make_api(make_cfg(tmp_path))
    _, summary = get(api, "/fleet")
    assert summary["coverage"] == {"reporting": 0, "enrolled": 1,
                                   "silent": 0, "never_seen": 1}
    # Zero entries means no verdict exists — not "broken", and above all not
    # the green tick an empty screen would otherwise imply.
    assert summary["integrity"] == {"intact": 0, "broken": 0,
                                    "unverified": 0, "no_verdict": 1}
    assert summary["ingest"]["last_batch_at"] is None
    assert summary["open_findings"] == 0
    assert summary["local"]["sealed_total"] == 0

    _, devices = get(api, "/fleet/devices")
    assert devices["devices"][0]["liveness"] == "never_seen"
    assert devices["devices"][0]["integrity"] == "unverified"

    _, cov = get(api, "/fleet/coverage")
    assert [d["device_id"] for d in cov["never_seen"]] == \
        [devices["devices"][0]["device_id"]]
    assert cov["silent"] == []
    assert "one Mac's Shield" in cov["blind_spot"]["statement"]


def test_not_connected_means_the_ship_line_is_unknown(tmp_path):
    # Backlog, ship lag and countersignature are receiving-side facts. With
    # no fleet server configured, "0 unsynced" would claim a health nobody
    # measured — null is the contract's answer.
    api = make_api(make_cfg(tmp_path), seed=rows(6))
    _, summary = get(api, "/fleet")
    assert summary["ingest"]["backlog_entries"] is None
    assert summary["ingest"]["oldest_unshipped_at"] is None
    assert summary["ingest"]["checkpoints_pending"] is None
    _, cov = get(api, "/fleet/coverage")
    assert "not connected" in cov["blind_spot"]["statement"]
    _, devices = get(api, "/fleet/devices")
    assert devices["devices"][0]["batches_received"] is None


# ------------------------------------------------------- a live, intact chain


def test_intact_chain_reports_real_coverage_and_rates(tmp_path):
    api = make_api(make_cfg(tmp_path), seed=rows(8, denied_at=3))
    _, summary = get(api, "/fleet")
    assert summary["coverage"] == {"reporting": 1, "enrolled": 1,
                                   "silent": 0, "never_seen": 0}
    # Eight entries sealed, every one re-hashed by this very request, the
    # checkpoint (sig_every=4) signed and signature-valid: intact is EARNED
    # here, not deferred to a verify job.
    assert summary["integrity"]["intact"] == 1
    assert summary["integrity"]["broken"] == 0
    assert summary["ingest"]["entries_received"] == 8
    assert summary["ingest"]["last_batch_at"].endswith("Z")
    series = summary["ingest"]["rate_series"]
    assert len(series) == 1440 and sum(series) == 8
    assert summary["local"]["merkle_root"] and summary["local"]["incidents"] == 0
    assert summary["open_findings"] == 0

    _, devices = get(api, "/fleet/devices")
    dev = devices["devices"][0]
    assert dev["integrity"] == "intact"
    assert dev["key_state"] == "verified"
    assert dev["last_seq_received"] == 8
    assert "desktop:claude" in dev["agent_ids"]

    _, cov = get(api, "/fleet/coverage")
    # The walk is the read, so on this host nothing sits "stored but never
    # verified" — the one empty list on the coverage screen that is true.
    assert cov["unverified_ranges"] == []
    assert cov["never_seen"] == [] and cov["silent"] == []


def test_browser_rows_are_stamped_in_utc_and_land_in_their_real_minute(tmp_path):
    """Desktop rows carry the server's local wall clock; browser rows reformatted
    the relay's UTC `sent_at` into the same two fields. Reading both as local
    — or both as UTC — shifts one source by the machine's offset: browser seals
    would land hours in the future and drop out of every window, which on a
    browser-only Mac is the whole fleet."""
    now = datetime.now(timezone.utc)
    sent = (now - timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows_ = [{"kind": "browser.chat.request", "app": "claude", "chars": 40,
              "sent_at": sent,
              "wall_clock": (now - timedelta(minutes=4)).astimezone()
                            .strftime("%Y-%m-%d %H:%M:%S")}]
    api = make_api(make_cfg(tmp_path), seed=rows_)
    _, summary = get(api, "/fleet")
    assert summary["coverage"]["reporting"] == 1
    assert summary["ingest"]["entries_received"] == 1
    # The seal's effective instant is the relay's UTC stamp, not that stamp
    # re-shifted by the local offset: within a minute of the send, never in
    # the future.
    batch = datetime.fromisoformat(summary["ingest"]["last_batch_at"].replace("Z", "+00:00"))
    sent_dt = datetime.fromisoformat(sent.replace("Z", "+00:00"))
    # The seal's effective instant is the relay's UTC stamp itself — neither
    # re-shifted by the local offset nor dropped as untrustworthy.
    assert abs((batch - sent_dt).total_seconds()) < 2
    assert batch <= datetime.now(timezone.utc)


def test_enrolled_at_is_the_first_seal_not_a_file_write(tmp_path):
    api = make_api(make_cfg(tmp_path), seed=rows(3, age_minutes=20))
    _, devices = get(api, "/fleet/devices")
    dev = devices["devices"][0]
    assert dev["enrolled_at"] <= dev["last_batch_at"]
    first = datetime.fromisoformat(dev["enrolled_at"].replace("Z", "+00:00"))
    assert abs((datetime.now(timezone.utc) - first).total_seconds() - 20 * 60) < 120


def test_local_verdicts_feed_the_denial_panel(tmp_path):
    api = make_api(make_cfg(tmp_path), seed=rows(8, denied_at=3))
    _, summary = get(api, "/fleet")
    denial = summary["denial"]
    assert denial["denied"] == 1
    assert denial["tool_use_total"] == 8
    assert round(denial["denied_per_1k"], 1) == round(1 / 8 * 1000, 1)
    # Nothing was loaded from before the window, so there is no comparison —
    # and the panel must not be handed a 0.0 to mistake for "unchanged".
    assert denial["previous_per_1k"] is None
    assert denial["top_refused"][0]["count"] == 1


def test_window_bounds_are_respected(tmp_path):
    api = make_api(make_cfg(tmp_path), seed=rows(6, age_minutes=90))
    now = datetime.now(timezone.utc)
    frm = (now - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    to = now.isoformat().replace("+00:00", "Z")
    _, summary = get(api, "/fleet", **{"from": frm, to: to})
    assert summary["ingest"]["entries_received"] == 0   # all rows predate the window
    assert summary["coverage"]["reporting"] == 0
    assert summary["coverage"]["silent"] == 1
    assert summary["ingest"]["rate_flat_for_minutes"] >= 60


def test_a_floor_to_the_minute_live_window_still_sees_this_minute(tmp_path):
    """The SPA floors `to` to the minute for stable cache keys. Seals that
    land in the still-running minute are the fleet's live heartbeat — a live
    window must read to now, while an archived `to` stays exactly as wide as
    it was named."""
    api = make_api(make_cfg(tmp_path), seed=rows(3, age_minutes=0))  # stamps: ~now
    now = datetime.now(timezone.utc)
    floored = now.replace(second=0, microsecond=0)  # exactly what the SPA floor does
    iso = lambda dt: dt.isoformat().replace("+00:00", "Z")  # noqa: E731
    _, summary = get(api, "/fleet", **{"from": iso(floored - timedelta(hours=24)),
                                       "to": iso(floored)})
    assert summary["ingest"]["entries_received"] >= 1  # current-minute seals counted
    archived = (now - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
    archived_to = (now - timedelta(hours=1)).isoformat().replace("+00:00", "Z")
    _, past = get(api, "/fleet", **{"from": archived, "to": archived_to})
    assert past["ingest"]["entries_received"] == 0     # the named slice stays closed


# ------------------------------------------------- what a broken chain looks like


def test_tampered_entry_surfaces_as_a_finding_not_a_pass(tmp_path):
    cfg = make_cfg(tmp_path)
    api = make_api(cfg, seed=rows(6))
    log = cfg.seal_path.with_name("sealchain.log.jsonl")
    lines = log.read_text().splitlines()
    victim = json.loads(lines[2])
    victim["payload"]["chars"] = 9999            # edit, seal left untouched
    lines[2] = json.dumps(victim)
    log.write_text("\n".join(lines) + "\n")

    _, summary = get(api, "/fleet")
    assert summary["integrity"]["broken"] == 1
    assert summary["open_findings"] >= 1
    _, findings = get(api, "/fleet/findings")
    assert findings["total"] == len(findings["findings"]) >= 1
    kinds = {f["kind"] for f in findings["findings"]}
    assert "broken_links" in kinds
    assert all(f["severity"] == "bad" for f in findings["findings"])
    assert all(f["device_id"] == summary["local"]["device_id"]
               for f in findings["findings"])


def test_connected_ship_state_is_reported_not_guessed(tmp_path):
    # last_height=2 of 4 sealed entries: the two newest are unsent by
    # definition, and the signed checkpoint (height 4) is pending.
    pub = StubPublisher(connected=True, tenant="acme", last_height=2,
                        last_sent_at="2026-09-26T00:00:00Z")
    api = make_api(make_cfg(tmp_path), publisher=pub, seed=rows(4))
    _, summary = get(api, "/fleet")
    assert summary["ingest"]["backlog_entries"] == 2
    assert summary["ingest"]["backlog_devices"] == 1
    assert summary["ingest"]["checkpoints_pending"] == 1
    assert summary["ingest"]["oldest_unshipped_at"].endswith("Z")
    _, cov = get(api, "/fleet/coverage")
    assert cov["checkpoint_gaps"]["sessions_without_checkpoint"] == 1
    assert cov["checkpoint_gaps"]["detail"][0]["count"] == 2


# ------------------------------------------------------------ wire-shape guards


def test_404_and_missing_tenant(tmp_path):
    api = make_api(make_cfg(tmp_path))
    code, body = api.handle("/v1/console/fleet/nonesuch", {"tenant": ["t"]})
    assert code == 404 and json.loads(body)["error"] == "not found"
    assert api.handle("/v1/console/fleet", {})[0] == 400


def test_summary_carries_the_shapes_the_spa_parses(tmp_path):
    """One belt-and-braces pass over field types — the zod contract catches
    drift at runtime; this catches it before a release ships it."""
    api = make_api(make_cfg(tmp_path), seed=rows(5))
    _, s = get(api, "/fleet")
    assert isinstance(s["window"]["from"], str)
    assert set(s["inclusion"]) == {"devices_included", "devices_enrolled"}
    assert set(s["coverage"]) == {"reporting", "enrolled", "silent", "never_seen"}
    assert set(s["integrity"]) == {"intact", "broken", "unverified", "no_verdict"}
    assert all(isinstance(v, int) for v in s["ingest"]["rate_series"])
    assert set(s["denial"]) == {"denied_per_1k", "previous_per_1k", "denied",
                                "flagged", "tool_use_total", "top_refused"}
    assert all(set(r) == {"tool", "reason", "count"} for r in s["denial"]["top_refused"])
    _, d = get(api, "/fleet/devices")
    row = d["devices"][0]
    assert {"device_id", "host", "agent_ids", "liveness", "enrolled_at",
            "last_batch_at", "last_seq_received", "expected_interval_s",
            "quiet_for_s", "overdue_multiple", "ship_lag_s", "key_state",
            "integrity", "batches_received"} <= set(row)
    _, c = get(api, "/fleet/coverage")
    assert c["blind_spot"]["basis"] == "device_enrolments"
    assert set(c["checkpoint_gaps"]) == {"sessions_without_checkpoint",
                                         "checkpoints_never_countersigned",
                                         "detail"}
    assert c["ungoverned_agents"] == []


# ------------------------------------------------------------ served by the app


def _serve(cfg):
    import socket
    import threading
    import urllib.request

    from byoai.integrations.shield import serve
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    threading.Thread(target=serve, args=(cfg, "127.0.0.1", port), daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/api/policy", timeout=0.2)
            return base
        except Exception:
            _time.sleep(0.05)
    raise RuntimeError("shield server did not start")


def test_the_real_server_answers_the_fleet_routes(tmp_path):
    import urllib.request
    cfg = make_cfg(tmp_path)
    cfg.ledger.write_text("".join(json.dumps(r) + "\n" for r in rows(4)))
    base = _serve(cfg)
    with urllib.request.urlopen(base + "/v1/console/fleet?tenant=acme-prod", timeout=5) as r:
        assert r.status == 200
        body = json.loads(r.read())
    assert body["integrity"]["intact"] == 1
    assert body["coverage"]["reporting"] == 1
    # A request addressed off localhost must not answer, same as every other
    # endpoint: the Host guard runs before the fleet router.
    import urllib.error
    req = urllib.request.Request(base + "/v1/console/fleet?tenant=x")
    req.add_header("Host", "example.com")
    try:
        urllib.request.urlopen(req, timeout=5)
        raise AssertionError("a remote Host must not read the local fleet")
    except urllib.error.HTTPError as exc:
        assert exc.code == 403


# ------------------------------------------------------- the verdict stream


def _seed_verdict_rows(base):
    """7 plain sends, 1 denied, 1 flagged (legacy row with PII in its prompt)."""
    from datetime import timedelta as _td
    out = []
    for i in range(7):
        out.append({"wall_clock": (base + _td(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"),
                    "kind": "desktop.chat.request", "app": "claude", "chars": 20 + i})
    out.append({"wall_clock": (base + _td(seconds=7)).strftime("%Y-%m-%d %H:%M:%S"),
                "kind": "desktop.verdict.denied", "app": "claude", "verdict": "blocked",
                "chars": 12})
    out.append({"wall_clock": (base + _td(seconds=8)).strftime("%Y-%m-%d %H:%M:%S"),
                "kind": "desktop.chat.request", "target": "claude.ai",
                "prompt": "forward this to j.rivers@gmail.com please"})
    return out


def test_verdicts_stream_counts_local_decisions(tmp_path):
    from datetime import timedelta as _td
    base = datetime.now() - _td(minutes=6)
    api = make_api(make_cfg(tmp_path), seed=_seed_verdict_rows(base))
    code, stream = get(api, "/verdicts")
    assert code == 200
    assert stream["rollup"] == {"allowed": 7, "flagged": 1, "denied": 1}
    assert stream["enforcement"] == "enforce"
    # The would-have-been-stopped counter is an observe-mode question; under
    # enforcement it is null, not a 0 claiming the check ran and found none.
    assert stream["observe_flagged"] is None
    assert stream["latches"] == []
    assert len(stream["verdicts"]) == 9
    row = next(v for v in stream["verdicts"] if v["verdict"] == "denied")
    assert row["device_id"] == stream["verdicts"][0]["device_id"]
    assert row["seq"] is not None and row["seq"] >= 1
    assert row["reason"] is not None


def test_verdicts_latch_counts_repeats_after_the_first_denial(tmp_path):
    from datetime import timedelta as _td
    base = datetime.now() - _td(minutes=6)
    rows_ = _seed_verdict_rows(base)
    rows_.append({"wall_clock": (base + _td(seconds=9)).strftime("%Y-%m-%d %H:%M:%S"),
                  "kind": "desktop.verdict.denied", "app": "claude",
                  "verdict": "blocked", "chars": 30})
    api = make_api(make_cfg(tmp_path), seed=rows_)
    _, stream = get(api, "/verdicts")
    assert stream["rollup"]["denied"] == 2
    assert len(stream["latches"]) == 1
    latch = stream["latches"][0]
    assert latch["attempts"] == 1  # one repeat after the first denial
    assert latch["surface"].endswith("desktop")


def test_verdicts_observe_mode_reports_the_would_have_been_stopped_count(tmp_path):
    from datetime import timedelta as _td

    from byoai.integrations.shield import default_policy, save_policy
    cfg = make_cfg(tmp_path)
    pol = default_policy()
    pol["mode"] = "observe"
    save_policy(cfg, pol)
    base = datetime.now() - _td(minutes=6)
    api = make_api(cfg, seed=_seed_verdict_rows(base))
    _, stream = get(api, "/verdicts")
    assert stream["enforcement"] == "observe"
    assert stream["observe_flagged"] == stream["rollup"]["flagged"] == 1


# ------------------------------------------------------------ the ledger


def test_ledger_is_the_whole_chain_not_the_feed_window(tmp_path):
    """The ledger reads the seal log — deeper than every in-memory screen."""
    api = make_api(make_cfg(tmp_path), seed=rows(9, denied_at=4))
    code, led = get(api, "/ledger")
    assert code == 200
    assert led["head"]["height"] == 9 and led["head"]["sealed_total"] == 9
    assert led["head"]["root"] and led["head"]["as_of"].endswith("Z")
    # Heights contiguous: missing_ranges reports the contiguity the scan just
    # proved, so [] here is a result, not a stored assertion.
    assert led["missing_ranges"] == []
    assert len(led["entries"]) == 9
    newest, oldest = led["entries"][0], led["entries"][-1]
    assert newest["seq"] == 9 and oldest["seq"] == 1
    assert led["next_cursor"] is None
    # Sessions and trajectories are ship-side rollups: null on this host,
    # distinct from the [] that would claim "computed, none found".
    assert led["sessions"] is None and led["trajectories"] is None
    kinds = {e["kind"] for e in led["entries"]}
    assert kinds == {"message", "mandate_verdict"}
    row = next(e for e in led["entries"] if e["status"] == "blocked")
    assert row["kind"] == "mandate_verdict"


def test_ledger_pages_by_cursor_not_by_offset(tmp_path):
    api = make_api(make_cfg(tmp_path), seed=rows(9, denied_at=4))
    _, first = get(api, "/ledger", limit=4)
    assert [e["seq"] for e in first["entries"]] == [9, 8, 7, 6]
    assert first["next_cursor"] == "6"
    _, second = get(api, "/ledger", limit=4, before=first["next_cursor"])
    assert [e["seq"] for e in second["entries"]] == [5, 4, 3, 2]
    _, last = get(api, "/ledger", limit=4, before=second["next_cursor"])
    assert [e["seq"] for e in last["entries"]] == [1]
    assert last["next_cursor"] is None   # no empty trailing page offered


def test_entry_detail_addresses_a_seq_beside_its_device(tmp_path):
    api = make_api(make_cfg(tmp_path), seed=rows(8, denied_at=3))
    _, led = get(api, "/ledger")
    dev = led["entries"][0]["device_id"]
    code, raw = api.handle(f"/v1/console/entries/{dev}/5", {"tenant": ["acme-prod"]})
    assert code == 200
    body = json.loads(raw)
    assert body["entry"]["seq"] == 5
    assert body["entry"]["seal"].startswith(body["entry"]["seal"][:8])
    # The payload is the stored shape; the proof is the fold path; the
    # checkpoint says whether it covers this height — the offline-verify
    # story at row level, with no message text anywhere.
    assert "text" not in json.dumps(body["payload"]).lower() or "text_hmac" in body["payload"]
    assert body["proof"]["root_hex"]
    assert body["proof"]["steps"], "expected at least one sibling step"
    assert body["checkpoint"]["covers_this_entry"] is True
    # A seq beyond the head: absent is not a sealed fact — the chain has no
    # such entry and the 404 says so in those words.
    code, body = api.handle(f"/v1/console/entries/{dev}/999", {"tenant": ["acme-prod"]})
    assert code == 404
    assert "no entry at" in json.loads(body)["error"]
    # The wrong device says "this host has no such ledger" — not "no such seq".
    code, body = api.handle("/v1/console/entries/dev_other/1", {"tenant": ["acme-prod"]})
    assert code == 404
    assert "no ledger for that device" in json.loads(body)["error"]


def test_ledger_respects_the_window(tmp_path):
    api = make_api(make_cfg(tmp_path), seed=rows(6, age_minutes=90))
    now = datetime.now(timezone.utc)
    frm = (now - timedelta(minutes=30)).isoformat().replace("+00:00", "Z")
    _, led = get(api, "/ledger", **{"from": frm})
    assert led["entries"] == []          # all rows predate the window
    assert led["head"]["sealed_total"] == 6  # the chain still holds them


# ------------------------------------------------------------ enrollment


def test_enrollment_unenrolled_says_so_without_faking_a_recipient(tmp_path):
    api = make_api(make_cfg(tmp_path), seed=rows(5))
    code, e = get(api, "/enrollment")
    assert code == 200
    assert e["connection"]["connected"] is False
    assert e["connection"]["unsent_entries"] is None  # no ship line to be behind on
    assert e["managed"] is None
    # Seal-only sharing means the disclosure panel is absent, and the page
    # renders "seal only" from that null rather than inventing a recipient.
    assert e["sharing"] is None
    assert e["chain"]["sealed_total"] == 5
    assert e["chain"]["root"] is not None
    assert e["stored"]["rows_with_text"] == 0
    assert e["stored"]["paths"]["seal_log"].endswith("sealchain.log.jsonl")
    assert e["stored"]["paths"]["managed_policy"] is None  # never managed


def test_enrollment_connected_reports_ship_line_from_live_state(tmp_path):
    pub = StubPublisher(connected=True, tenant="acme", base_url="https://cq.test",
                        last_height=3, last_sent_at=1.0, next_attempt_at=0.0,
                        every_hours=2.0, has_new=True, needs_attention=False,
                        sync={"pending": 4, "last_sent_at": None, "last_error": None})
    api = make_api(make_cfg(tmp_path), publisher=pub, seed=rows(6))
    _, e = get(api, "/enrollment")
    c = e["connection"]
    assert c["connected"] is True
    assert c["remote_tenant"] == "acme"
    assert c["unsent_entries"] == 3   # 6 sealed (approx height) minus last_height
    # next_attempt_at of 0 means "no backoff in force" and normalises to None,
    # not the 1970 epoch — a never is never a date.
    assert c["next_attempt_at"] is None
    assert c["sync_pending"] == 4


def test_enrollment_ignores_an_unsigned_local_sync_level(tmp_path):
    """Privacy invariant: only a signed managed policy may raise what leaves
    the device. A hand-edited local `sync: events` must NOT surface a sharing
    disclosure — load_policy rewrites it back to seal. The endpoint inherits
    that and must not re-widen the hole."""
    from byoai.integrations.shield import default_policy, save_policy
    cfg = make_cfg(tmp_path)
    pol = default_policy()
    pol["sync"] = "events"
    save_policy(cfg, pol)
    api = make_api(cfg, seed=rows(4))
    _, e = get(api, "/enrollment")
    # No signed managed policy present, so sharing collapses to seal → None,
    # and the page renders "seal only" rather than disclosing a recipient the
    # device never agreed to.
    assert e["sharing"] is None
    assert e["managed"] is None
    assert e["policy"]["sync"] == "seal"


@pytest.mark.parametrize("zone", ["America/Chicago", "Asia/Tokyo"])
def test_a_browser_send_in_the_verdict_stream_keeps_its_real_minute(tmp_path, monkeypatch, zone):
    """Feed items show browser sends in local time (the seal keeps the
    extension's UTC stamp). Reading such an item as UTC again would move it
    by the offset: hours into the past west of UTC, into the future (and out
    of every window) east of it."""
    monkeypatch.setenv("TZ", zone)
    _time.tzset()
    try:
        now = datetime.now(timezone.utc)
        sent = now - timedelta(minutes=4)
        api = make_api(make_cfg(tmp_path), seed=[{
            "kind": "browser.chat.request", "app": "claude", "chars": 40,
            "sent_at": sent.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "wall_clock": sent.astimezone().strftime("%Y-%m-%d %H:%M:%S")}])
        _, out = get(api, "/verdicts")
        [row] = out["verdicts"]
        shown = datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        assert abs((shown - sent).total_seconds()) < 2
    finally:
        monkeypatch.delenv("TZ")
        _time.tzset()
