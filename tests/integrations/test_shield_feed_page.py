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


# ---- legacy rows: every flag tier served is one the window's schema names ----

CONTRACT = {"agent", "high", "pii", "conduct"}


def make_legacy_feed(tmp_path):
    ledger = tmp_path / "captures.jsonl"
    rows = [
        {"wall_clock": "2026-09-01 09:00:00", "kind": "tool.call", "tool": "execute",
         "input_preview": "api_key = sk-abcdefghijklmnop1234 refund"},
        {"wall_clock": "2026-09-01 09:01:00", "kind": "desktop.chat.request",
         "prompt": "my password: hunter2hunter2 please"},
        {"wall_clock": "2026-09-01 09:02:00", "kind": "desktop.chat.request",
         "prompt": "plain message"},
    ]
    ledger.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    cfg = ShieldConfig(
        ledger=ledger, seal_path=tmp_path / "sealchain.json", key_dir=tmp_path / "keys",
        policy_path=tmp_path / "policy.json", managed_policy_path=tmp_path / "m.json",
        sig_every=4, max_interactions=100)
    feed = Feed(cfg)
    feed.scan_initial()
    return feed


def test_legacy_rows_serve_only_contract_tiers(tmp_path):
    feed = make_legacy_feed(tmp_path)
    internal = {f["tier"] for it in feed.items for f in it["flags"]}
    assert internal & {"secret", "flag"}          # the rows really are legacy-shaped
    out = feed_page(feed, {})
    served = {f["tier"] for it in out["items"] for f in it["flags"]}
    assert served and served <= CONTRACT
    assert len(out["items"]) == 3 and out["total"] == 3


def test_a_credential_in_a_legacy_row_is_high_risk(tmp_path):
    feed = make_legacy_feed(tmp_path)
    out = feed_page(feed, q(need="bad"))
    assert out["matched"] == 2 and {i["tier"] for i in out["items"]} == {"bad"}
    assert out["counts"]["high_risk"] == 2
    assert {f["tier"] for f in out["items"][0]["flags"]} >= {"high"}


def test_serving_does_not_change_stored_flags_or_seals(tmp_path):
    feed = make_legacy_feed(tmp_path)
    before = [(it["flags"], it["seal"]) for it in feed.items]
    feed_page(feed, {})
    assert [(it["flags"], it["seal"]) for it in feed.items] == before
    assert any(f["tier"] == "secret" for it in feed.items for f in it["flags"])


def test_response_matches_the_window_fixture(tmp_path):
    """Records the response the web schema test parses (web/src/api/fixtures)."""
    import os
    feed = make_legacy_feed(tmp_path)
    out = feed_page(feed, {})
    path = os.path.join(os.path.dirname(__file__), "..", "..", "web", "src", "api",
                        "fixtures", "feed_legacy_rows.json")
    with open(path) as fh:
        recorded = json.load(fh)
    assert {f["tier"] for it in recorded["items"] for f in it["flags"]} <= CONTRACT
    assert [i["tier"] for i in out["items"]] == [i["tier"] for i in recorded["items"]]


# ---- the Ledger and Trust lists: sealed, search and exact summary ----

def add_unsealed(feed, n=4):
    """Rows with no seal yet (a tool call still running), newest first."""
    for it in list(feed.items)[:n]:
        it["seal"] = ""


def test_sealed_keeps_only_rows_with_a_seal_before_paging(tmp_path):
    feed = make_feed(tmp_path, 60)
    add_unsealed(feed)
    sealed = [it for it in feed.items if it.get("seal")]
    assert len(sealed) == 56
    out = feed_page(feed, q(sealed=1, limit=10, offset=50))
    assert out["matched"] == 56 and len(out["items"]) == 6 and out["has_more"] is False
    assert all(it["seal"] for it in out["items"])
    assert out["total"] == 60                       # what Shield holds is still honest
    assert feed_page(feed, {})["matched"] == 60      # no parameter: as before
    assert feed_page(feed, q(sealed=0))["matched"] == 60


def test_sealed_combines_with_filters_and_counts_the_filtered_list(tmp_path):
    feed = make_feed(tmp_path, 60)
    add_unsealed(feed, 10)
    want = [it for it in feed.items if it.get("seal") and it["tier"] == "warn"]
    out = feed_page(feed, q(sealed=1, need="warn", limit=2, offset=2))
    assert out["matched"] == len(want) and out["items"][0]["id"] == want[2]["id"]
    assert out["has_more"] is (len(want) > 4)


def test_sealed_page_holds_still_under_an_anchor(tmp_path):
    feed = make_feed(tmp_path, 40)
    anchor = list(feed.items)[0]["id"]
    before = [i["id"] for i in feed_page(feed, q(sealed=1, limit=10, offset=10, anchor=anchor))["items"]]
    with feed.cfg.ledger.open("a") as fh:
        for i in range(3):
            fh.write(json.dumps({"wall_clock": "2026-10-01 00:00:00", "kind": "desktop.chat.request",
                                 "target": "claude.ai", "prompt": f"late {i}"}) + "\n")
    feed.poll()
    out = feed_page(feed, q(sealed=1, limit=10, offset=10, anchor=anchor))
    assert [i["id"] for i in out["items"]] == before
    assert out["newer"] == 3 and out["matched"] == 40


def test_search_filters_before_paging_on_text_app_and_rule_words(tmp_path):
    feed = make_feed(tmp_path, 50)
    hits = [it for it in feed.items if any(f["rule"] == "emails" for f in it["flags"])]
    assert hits
    for word in ("email address", "EMAILS", "emails"):
        assert feed_page(feed, q(q=word, limit=2))["matched"] == len(hits)
    assert feed_page(feed, q(q="no such words anywhere"))["matched"] == 0
    assert feed_page(feed, q(q="  "))["matched"] == 50          # blank means no search


def test_summary_is_exact_over_every_row_not_the_page(tmp_path):
    feed = make_feed(tmp_path, 60)
    day = list(feed.items)[0]["date"]
    out = feed_page(feed, q(limit=5, offset=20, need="bad", summary_since=day))
    rows = [it for it in feed.items if it["date"] >= day]
    s = out["summary"]
    assert s["checked"] == len(rows)
    assert s["flagged"] == sum(it["tier"] == "warn" for it in rows) > 0
    assert s["high_risk"] == sum(it["tier"] == "bad" for it in rows)
    assert s["browser"] + s["mcp"] <= s["checked"]
    assert feed_page(feed, q(summary_since=""))["summary"]["checked"] == 60   # all time
    assert "summary" not in feed_page(feed, {})                                # opt in


def test_legacy_rows_still_page_and_count(tmp_path):
    feed = make_legacy_feed(tmp_path)
    out = feed_page(feed, q(sealed=1, limit=1, summary_since=""))
    # the running tool call has no seal yet, so the sealed list holds two of three
    assert out["matched"] == 2 and out["total"] == 3 and len(out["items"]) == 1 and out["has_more"] is True
    assert out["summary"]["high_risk"] == 2
    assert {f["tier"] for it in out["items"] for f in it["flags"]} <= CONTRACT
    assert feed_page(feed, q(q="credential"))["matched"] >= 1


def test_newer_counts_only_arrivals_this_view_would_show(tmp_path):
    feed = make_feed(tmp_path, 20)
    anchor = list(feed.items)[0]["id"]
    with feed.cfg.ledger.open("a") as fh:
        for text in ["plain a", "mail x.y@gmail.com now", "plain b"]:
            fh.write(json.dumps({"wall_clock": "2026-10-01 00:00:00", "kind": "desktop.chat.request",
                                 "target": "claude.ai", "prompt": text}) + "\n")
    feed.poll()
    assert feed_page(feed, q(anchor=anchor))["newer"] == 3
    assert feed_page(feed, q(anchor=anchor, need="warn"))["newer"] == 1
