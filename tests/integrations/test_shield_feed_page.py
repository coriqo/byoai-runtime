"""GET /api/feed paging: bounds, filters, a stable anchor, no silent cut-off."""
import json

from byoai.integrations.shield import Feed, ShieldConfig, feed_page


def make_feed(tmp_path, n, cap=100):
    ledger = tmp_path / "captures.jsonl"
    rows = [{"wall_clock": f"2026-09-{1 + i // 24:02d} {i % 24:02d}:00:00",
             "kind": "desktop.chat.request", "target": "claude.ai",
             "prompt": ("mail j.rivers@gmail.com please " if i % 5 == 0 else "plain ") + f"msg {i}"}
            for i in range(n)]
    ledger.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    cfg = ShieldConfig(
        ledger=ledger, seal_path=tmp_path / "sealchain.json", key_dir=tmp_path / "keys",
        policy_path=tmp_path / "policy.json", managed_policy_path=tmp_path / "m.json",
        sig_every=4, max_interactions=cap)
    feed = Feed(cfg)
    feed.scan_initial()
    return feed


def q(**kw):
    return {k: [str(v)] for k, v in kw.items()}


def test_no_parameters_is_what_it_always_returned(tmp_path):
    feed = make_feed(tmp_path, 70)
    out = feed_page(feed, {})
    assert out["limit"] == 60 and out["offset"] == 0 and len(out["items"]) == 60
    assert out["total"] == 70 and out["has_more"] is True
    assert out["items"][0]["id"] == list(feed.items)[0]["id"]      # newest first
    assert out["newer"] == 0 and out["capacity"] == 100


def test_limit_is_bounded_and_echoed(tmp_path):
    feed = make_feed(tmp_path, 250, cap=400)
    assert feed_page(feed, q(limit=9999))["limit"] == 200
    assert len(feed_page(feed, q(limit=9999))["items"]) == 200
    assert feed_page(feed, q(limit=0))["limit"] == 1
    assert feed_page(feed, q(limit="abc"))["limit"] == 60
    out = feed_page(feed, q(offset=-5))
    assert out["offset"] == 0
    assert feed_page(feed, q(offset=10_000))["items"] == []


def test_pages_cover_every_row_once(tmp_path):
    feed = make_feed(tmp_path, 95)
    seen, off = [], 0
    while True:
        out = feed_page(feed, q(limit=25, offset=off))
        seen += [it["id"] for it in out["items"]]
        if not out["has_more"]:
            break
        off += 25
    assert seen == [it["id"] for it in feed.items]


def test_filters_apply_before_paging(tmp_path):
    feed = make_feed(tmp_path, 50)
    flagged = [it for it in feed.items if it["tier"] == "warn"]
    assert flagged
    out = feed_page(feed, q(need="warn", limit=3))
    assert out["matched"] == len(flagged) and len(out["items"]) == 3
    assert all(it["tier"] == "warn" for it in out["items"])
    assert feed_page(feed, q(need="bogus"))["matched"] == len(feed.items)
    day = list(feed.items)[0]["date"]
    since = feed_page(feed, q(since=day))
    assert since["matched"] == sum(1 for it in feed.items if it["date"] >= day)


def test_anchor_keeps_a_page_while_new_rows_arrive(tmp_path):
    feed = make_feed(tmp_path, 40)
    anchor = list(feed.items)[0]["id"]
    before = [it["id"] for it in feed_page(feed, q(limit=10, offset=10, anchor=anchor))["items"]]
    with feed.cfg.ledger.open("a") as fh:
        for i in range(3):
            fh.write(json.dumps({"wall_clock": "2026-10-01 00:00:00", "kind": "desktop.chat.request",
                                 "target": "claude.ai", "prompt": f"late {i}"}) + "\n")
    feed.poll()
    out = feed_page(feed, q(limit=10, offset=10, anchor=anchor))
    assert [it["id"] for it in out["items"]] == before
    assert out["newer"] == 3 and out["total"] == 43
    # without the anchor the same offset has shifted
    assert [it["id"] for it in feed_page(feed, q(limit=10, offset=10))["items"]] != before
    assert feed_page(feed, q(anchor="gone"))["newer"] == 0          # aged-out anchor is ignored


def test_rows_past_capacity_are_reported_not_hidden(tmp_path):
    feed = make_feed(tmp_path, 30, cap=20)
    out = feed_page(feed, q(limit=200))
    assert out["total"] == 20 and out["capacity"] == 20 and len(out["items"]) == 20


def test_focus_returns_the_row_off_the_page(tmp_path):
    feed = make_feed(tmp_path, 30)
    oldest = list(feed.items)[-1]["id"]
    out = feed_page(feed, q(limit=5, focus=oldest))
    assert out["focus_item"]["id"] == oldest and oldest not in [i["id"] for i in out["items"]]
    assert feed_page(feed, q(focus="nope"))["focus_item"] is None
    assert not any(k.startswith("_") for k in out["focus_item"])
