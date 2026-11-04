"""Promoted shield engine — rules, redaction, and the Merkle seal chain."""
from __future__ import annotations

import json
from pathlib import Path

from byoai.integrations.shield import (
    ShieldConfig, Feed, flags_for, redact, default_policy, load_policy,
    SealChain, MAX_INTERACTIONS, save_policy, merge_policy,
)


def make_cfg(tmp_path):
    ledger = tmp_path / "captures.jsonl"
    ledger.write_text("")
    return ShieldConfig(
        ledger=ledger,
        seal_path=tmp_path / "sealchain.json",
        key_dir=tmp_path / "keys",
        policy_path=tmp_path / "policy.json",
        # Never the real ~/.byoai/shield/managed_policy.json default in tests.
        managed_policy_path=tmp_path / "managed_policy.json",
        sig_every=4, max_interactions=100,
    )


def test_pii_rules_and_redaction():
    text = "refund my order, email j.rivers@gmail.com card 4242424242424242"
    flags = flags_for(text)
    rules = {r for _, r, _ in flags}
    assert {"emails", "cards", "tool_intent"} <= rules
    out = redact(text)
    assert "j.rivers@" not in out and "4242424242424242" not in out
    assert "[EMAIL_1]" in out and "[CARD_1]" in out


def test_executable_masquerade_is_a_signal_that_never_stops_a_send():
    from byoai.integrations.shield import evaluate
    text = "please open invoice_2026.pdf.exe"
    assert any(tier == "flag" for tier, _, _ in flags_for(text))
    assert evaluate(text, default_policy())[0] == "log"


def test_reply_pii_echo_flagged():
    flags = flags_for("your receipt, sent to j.rivers@gmail.com")
    assert any(r == "reply_pii_echo" for _, r, _ in flags)


def test_seal_chain_roundtrip_and_tamper(tmp_path):
    cfg = make_cfg(tmp_path)
    chain = SealChain(cfg)
    s1 = chain.stamp({"interaction": "a", "ts": "14:00", "text_redacted": "hi"})
    chain.stamp({"interaction": "b", "ts": "14:05", "text_redacted": "yo"})
    v = chain.verify_chain()
    assert v["tamper_evident"] is True and v["entries"] == 2

    rc = chain.receipt(s1)
    proof = rc["merkle"]["proof"]
    assert proof["root_hex"] == rc["merkle"]["checkpoint"]["root_hex"]
    assert rc["merkle"]["checkpoint"]["sig"].startswith("ed25519:")

    lines = chain.log_path.read_text().splitlines()
    first = json.loads(lines[0])
    first["payload"]["ts"] = "EDITED"                # edit, seal left as it was
    lines[0] = json.dumps(first)
    chain.log_path.write_text("\n".join(lines) + "\n")
    reborn = SealChain(make_cfg(tmp_path))
    assert reborn.verify_chain()["tamper_evident"] is False


def test_feed_pagination_counts(tmp_path):
    cfg = make_cfg(tmp_path)
    rows = [{"wall_clock": "2026-09-24 10:0%d:00" % i,
             "kind": "desktop.chat.request", "target": "claude.ai",
             "prompt": f"checkpoint smoke {i} fill"} for i in range(6)]
    cfg.ledger.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    feed = Feed(cfg)
    feed.scan_initial()
    assert feed.counts()["checked"] == 6
    assert feed.seals.height == 6


def test_policy_roundtrip(tmp_path):
    cfg = make_cfg(tmp_path)
    p = default_policy()
    p["mode"] = "redact"
    from byoai.integrations.shield import save_policy
    save_policy(cfg, p)
    assert load_policy(cfg)["mode"] == "redact"


# ------------------------------------------------------------- privacy-first

import os
import time as _time

import pytest

from byoai.integrations.shield import (
    apply_policy_update, fingerprint, inspect_text, privacy_report,
    redact_json_body, scrub_ledger,
)

SECRET = "email j.rivers@gmail.com about card 4242424242424242"


@pytest.fixture
def key_path(tmp_path, monkeypatch):
    path = tmp_path / "fp.key"
    monkeypatch.setattr("byoai.integrations.shield.FINGERPRINT_KEY", path)
    # default args were bound at import; route every call through tmp_path
    import byoai.integrations.shield as sh
    real = sh._fingerprint_key
    monkeypatch.setattr(sh, "_fingerprint_key", lambda p=path: real(path))
    return path


def test_defaults_are_privacy_first():
    """Pinned: a Mac that never opens Settings redacts, keeps no text, keeps
    30 days and shows the notice."""
    p = default_policy()
    assert p["mode"] == "redact"
    assert p["keep_text"] is False
    assert p["retention_days"] == 30
    assert p["notice"] is True


def test_pre_privacy_first_file_is_read_as_privacy_first(tmp_path):
    """Pinned: a policy.json from before privacy-first (no version) holding the
    old UI's saved default is read as redact with no stored text; the app
    toggles in it are kept."""
    cfg = make_cfg(tmp_path)
    cfg.policy_path.write_text(json.dumps(
        {"mode": "observe", "keep_text": True, "apps": {"chatgpt": True}}))
    p = load_policy(cfg)
    assert p["mode"] == "redact" and p["keep_text"] is False
    assert p["apps"]["chatgpt"] is True


def test_block_is_kept_when_upgrading(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.policy_path.write_text(json.dumps({"mode": "block"}))
    assert load_policy(cfg)["mode"] == "block"


def test_a_newer_policy_file_is_not_downgraded(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.policy_path.write_text(json.dumps({"policy_version": 3, "mode": "observe"}))
    assert load_policy(cfg)["mode"] == "observe"


def test_a_confirmed_choice_after_the_upgrade_is_kept(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.policy_path.write_text(json.dumps({"policy_version": 2, "mode": "observe"}))
    assert load_policy(cfg)["mode"] == "observe"


def test_weakening_needs_acknowledgement():
    p = default_policy()
    for change in ({"mode": "observe"}, {"keep_text": True}):
        with pytest.raises(ValueError, match="less private"):
            apply_policy_update(p, change)
        out = apply_policy_update(p, {**change, "acknowledge": "less_private"})
        assert "acknowledge" not in out
    # tightening, or re-saving an already-weaker setting, needs nothing
    observe = apply_policy_update(p, {"mode": "observe", "acknowledge": "less_private"})
    assert apply_policy_update(observe, {"mode": "redact"})["mode"] == "redact"
    assert apply_policy_update(observe, {"retention_days": 7})["mode"] == "observe"


def test_inspect_text_keeps_no_text_by_default(key_path):
    facts = inspect_text(SECRET, default_policy(), key_path=key_path)
    blob = json.dumps(facts)
    assert "j.rivers" not in blob and "4242" not in blob
    assert "preview" not in facts
    assert facts["chars"] == len(SECRET)
    assert {"pii:emails", "pii:cards"} <= set(facts["flags"])
    assert facts["text_hmac"].startswith("hmac-sha256:")


def test_inspect_text_preview_is_redacted_when_opted_in(key_path):
    facts = inspect_text(SECRET, {**default_policy(), "keep_text": True},
                         key_path=key_path)
    assert "[EMAIL_1]" in facts["preview"]
    assert "j.rivers" not in facts["preview"]


def test_fingerprint_is_keyed_stable_and_private(tmp_path):
    k1, k2 = tmp_path / "a.key", tmp_path / "b.key"
    assert fingerprint("123-45-6789", k1) == fingerprint("123-45-6789", k1)
    assert fingerprint("123-45-6789", k1) != fingerprint("123-45-6789", k2)
    assert os.stat(k1).st_mode & 0o777 == 0o600


def test_redact_json_body_only_touches_message_fields():
    body = {"conversation_uuid": "555-123-4567-ab", "timezone": "America/Chicago",
            "prompt": "call me on 555-123-4567 or mail a@b.co"}
    out, rules = redact_json_body(json.dumps(body))
    parsed = json.loads(out)
    assert parsed["conversation_uuid"] == "555-123-4567-ab"
    assert parsed["prompt"] == "call me on [PHONE_1] or mail [EMAIL_1]"
    assert rules == ["emails", "phone_numbers"]

    api = {"model": "claude-x", "messages": [
        {"role": "user", "content": [{"type": "text", "text": "ssn 123-45-6789"}]}]}
    out, rules = redact_json_body(json.dumps(api))
    assert "123-45-6789" not in out and rules == ["ssn_like"]


def test_redact_json_body_leaves_clean_and_non_json_bodies_alone():
    raw = json.dumps({"prompt": "reset my password please"})
    assert redact_json_body(raw) == (raw, [])     # the word is a flag, not PII
    assert redact_json_body("not json") == ("not json", [])


def test_policy_update_validates_every_field():
    p = default_policy()
    assert apply_policy_update(p, {"retention_days": 90})["retention_days"] == 90
    for bad in ({"mode": "spy"}, {"retention_days": 45}, {"keep_text": "yes"},
                {"notice": 1}, {"apps": {"claude": "on"}}):
        with pytest.raises(ValueError):
            apply_policy_update(p, bad)


def test_scrub_removes_text_and_applies_retention(tmp_path, key_path):
    cfg = make_cfg(tmp_path)
    old = _time.strftime("%Y-%m-%d %H:%M:%S",
                         _time.localtime(_time.time() - 40 * 86400))
    now = _time.strftime("%Y-%m-%d %H:%M:%S")
    rows = [
        {"wall_clock": old, "kind": "desktop.chat.request", "prompt": "old one"},
        {"wall_clock": now, "kind": "desktop.chat.request", "prompt": SECRET},
        {"wall_clock": now, "kind": "tool.call", "tool": "execute",
         "input_preview": "refund j.rivers@gmail.com"},
        {"wall_clock": now, "kind": "desktop.meta", "target": "claude.ai"},
    ]
    cfg.ledger.write_text("".join(json.dumps(r) + "\n" for r in rows))

    before = privacy_report(cfg)
    assert before["rows_with_text"] == 3 and before["rows_past_retention"] == 1

    result = scrub_ledger(cfg, key_path)
    assert result == {"scrubbed": 2, "deleted": 1, "ledger_rows": 3}
    text = cfg.ledger.read_text()
    assert "j.rivers" not in text and "4242" not in text and "old one" not in text

    after = privacy_report(cfg)
    assert after["rows_with_text"] == 0 and after["rows_past_retention"] == 0
    scrubbed = json.loads(text.splitlines()[0])
    assert "chars" not in scrubbed   # a 200-char cut is not the message length
    assert "pii:emails" in scrubbed["flags"]


def test_feed_shows_and_seals_no_text_by_default(tmp_path, key_path):
    cfg = make_cfg(tmp_path)
    facts = inspect_text(SECRET, default_policy(), key_path=key_path)
    rows = [
        {"wall_clock": "2026-09-25 09:00:00", "kind": "desktop.chat.request",
         "app": "claude", "verdict": "redacted(2)", **facts},
        # a pre-PF row still holding text on disk
        {"wall_clock": "2026-09-25 09:01:00", "kind": "desktop.chat.request",
         "target": "claude.ai", "prompt": SECRET},
        {"wall_clock": "2026-09-25 09:02:00", "kind": "desktop.verdict.denied",
         "app": "claude", "verdict": "blocked",
         **inspect_text("password: hunter2", default_policy(), key_path=key_path)},
    ]
    cfg.ledger.write_text("".join(json.dumps(r) + "\n" for r in rows))
    feed = Feed(cfg)
    feed.scan_initial()
    items = list(feed.items)
    blocked, legacy, fresh = items
    assert fresh["verb"] == f"Message to Claude · {len(SECRET)} characters"
    assert legacy["verb"] == "Message to Claude · sent before privacy settings"
    assert blocked["status"] == "blocked" and blocked["tier"] == "bad"
    assert "stopped" in blocked["verb"]
    sealed = ((tmp_path / "sealchain.json").read_text()
              + (tmp_path / "sealchain.log.jsonl").read_text())
    assert "j.rivers" not in sealed and "hunter2" not in sealed
    assert "text_redacted" not in sealed
    assert feed.seals.verify_chain()["tamper_evident"] is True


def test_poll_before_first_scan_does_not_double_absorb(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.ledger.write_text(json.dumps({"wall_clock": "2026-09-25 09:00:00",
                                      "kind": "desktop.chat.request",
                                      "app": "claude", "chars": 5}) + "\n")
    feed = Feed(cfg)
    assert feed.poll() == 0          # watcher got there first
    feed.scan_initial()
    feed.poll()
    assert feed.counts()["checked"] == 1 and feed.seals.height == 1


def test_idle_poll_skips_the_read_and_still_sees_new_rows(tmp_path):
    cfg = make_cfg(tmp_path)
    row = {"wall_clock": "2026-09-25 09:00:00", "kind": "desktop.chat.request",
           "app": "claude", "chars": 5}
    cfg.ledger.write_text(json.dumps(row) + "\n")
    feed = Feed(cfg)
    feed.scan_initial()
    assert feed.poll() == 0
    reads = []
    real = Path.read_text
    Path.read_text = lambda self, *a, **k: (reads.append(self), real(self, *a, **k))[1]
    try:
        assert feed.poll() == 0 and feed.poll() == 0
        assert [r for r in reads if r == cfg.ledger] == []   # nothing changed: no read
    finally:
        Path.read_text = real
    with cfg.ledger.open("a") as f:
        f.write(json.dumps(row) + "\n")
    assert feed.poll() == 1


# -------------------------------------------------------- review follow-ups


def _tool_rows(*rows):
    return "".join(json.dumps({"wall_clock": "2026-09-25 09:00:00", **r}) + "\n"
                   for r in rows)


def test_overlapping_tool_calls_seal_their_own_results(tmp_path):
    cfg = make_cfg(tmp_path)
    who = {"user_id": "u1"}
    cfg.ledger.write_text(_tool_rows(
        {"kind": "tool.call", "tool": "execute", "identity": who, "call_id": "A", "chars": 3},
        {"kind": "tool.call", "tool": "execute", "identity": who, "call_id": "B", "chars": 4},
        {"kind": "tool.result", "tool": "execute", "identity": who, "call_id": "A",
         "latency_ms": 11},
        {"kind": "tool.error", "tool": "execute", "identity": who, "call_id": "B"},
    ))
    feed = Feed(cfg)
    feed.scan_initial()
    by_call = {it["call_id"]: it for it in feed.items}
    assert by_call["A"]["status"] == "answered" and by_call["A"]["latency_ms"] == 11
    assert by_call["B"]["status"] == "failed" and by_call["B"]["seal"]


def test_rows_without_call_id_close_the_oldest_call(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.ledger.write_text(_tool_rows(
        {"kind": "tool.call", "tool": "execute", "chars": 1},
        {"kind": "tool.call", "tool": "execute", "chars": 2},
        {"kind": "tool.result", "tool": "execute", "latency_ms": 5},
    ))
    feed = Feed(cfg)
    feed.scan_initial()
    newest, oldest = list(feed.items)
    assert oldest["status"] == "answered" and newest["status"] == "running"


def test_harsh_reply_is_a_conduct_flag_not_pii():
    assert ("conduct", "reply_toxic") in [(t, r) for t, r, _ in flags_for("you idiot")]


def test_uncovered_apps_cannot_be_turned_on():
    with pytest.raises(ValueError, match="nope"):
        apply_policy_update(default_policy(), {"apps": {"nope": True}})
    assert apply_policy_update(default_policy(),
                               {"apps": {"chatgpt": True}})["apps"]["chatgpt"]


def test_input_only_apps_can_be_turned_on():
    # Gemini and Copilot are checked by the extension's input gate, not their traffic.
    out = apply_policy_update(default_policy(), {"apps": {"gemini": True, "copilot": True}})
    assert out["apps"]["gemini"] and out["apps"]["copilot"]


def test_chatgpt_and_openai_bodies_are_redacted():
    web = {"action": "next", "messages": [{"id": "m1", "author": {"role": "user"},
            "content": {"content_type": "text", "parts": ["mail a@b.co"]}}]}
    out, rules = redact_json_body(json.dumps(web))
    assert json.loads(out)["messages"][0]["content"]["parts"] == ["mail [EMAIL_1]"]
    assert rules == ["emails"]
    responses = {"model": "gpt-x", "input": "ssn 123-45-6789"}
    out, _ = redact_json_body(json.dumps(responses))
    assert json.loads(out)["input"] == "ssn [SSN_1]"


# ------------------------------------------------------ one UI, served here


def _serve(cfg):
    import socket
    import threading
    from byoai.integrations.shield import serve
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    threading.Thread(target=serve, args=(cfg, "127.0.0.1", port), daemon=True).start()
    import urllib.request
    base = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/api/policy", timeout=0.2)
            break
        except Exception:
            _time.sleep(0.05)
    return base


def _get(url):
    import urllib.error
    import urllib.request

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    try:
        r = opener.open(url, timeout=2)
        return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def test_server_serves_the_app_and_both_api_prefixes(tmp_path, monkeypatch):
    from byoai.agent_context_cache import console
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    (static / "index.html").write_text("<div id=root>app</div>")
    (static / "assets" / "a.js").write_text("console.log(1)")
    monkeypatch.setattr(console, "STATIC_DIR", static)
    monkeypatch.setattr(console, "INDEX_FILE", static / "index.html")
    base = _serve(make_cfg(tmp_path))

    code, headers, _ = _get(base + "/")
    assert code == 302 and headers["Location"] == "/shield"
    assert _get(base + "/shield")[2] == b"<div id=root>app</div>"
    assert _get(base + "/shield/anything")[0] == 200            # client route
    assert _get(base + "/console/acme/shield")[0] == 200         # old link, redirected in-app
    code, headers, body = _get(base + "/console/assets/a.js")
    assert code == 200 and "javascript" in headers["Content-Type"]
    assert _get(base + "/console/assets/gone-abc123.js")[0] == 404  # not the app page
    assert json.loads(_get(base + "/shield-api/policy")[2])["mode"] == "redact"
    assert json.loads(_get(base + "/api/policy")[2])["mode"] == "redact"
    assert _get(base + "/api/nope")[0] == 404
    assert _get(base + "/../../etc/passwd")[0] == 404


def test_server_says_how_to_build_when_the_app_is_missing(tmp_path, monkeypatch):
    from byoai.agent_context_cache import console
    monkeypatch.setattr(console, "STATIC_DIR", tmp_path / "none")
    monkeypatch.setattr(console, "INDEX_FILE", tmp_path / "none" / "index.html")
    base = _serve(make_cfg(tmp_path))
    code, _, body = _get(base + "/shield")
    assert code == 503 and b"npm" in body


# ------------------------------------------- other sites can't drive Shield

from byoai.integrations.shield import clean_browser_row, request_problem


def _post(url, body, headers):
    import urllib.error
    import urllib.request
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers=headers, method="POST")
    try:
        r = urllib.request.urlopen(req, timeout=2)
        return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_a_web_page_cannot_weaken_shield(tmp_path):
    base = _serve(make_cfg(tmp_path))
    weaken = {"mode": "observe", "acknowledge": "less_private"}
    # a form/text POST from any site: no JSON content type
    assert _post(base + "/api/policy", weaken, {"Content-Type": "text/plain"})[0] == 415
    # JSON from another site (would need a preflight; Origin gives it away)
    code, _ = _post(base + "/api/policy", weaken, {
        "Content-Type": "application/json", "Origin": "https://evil.example"})
    assert code == 403
    # DNS rebinding: the page's own hostname pointed at 127.0.0.1
    code, _ = _post(base + "/api/policy", weaken, {
        "Content-Type": "application/json", "Host": "evil.example:17831"})
    assert code == 403
    assert json.loads(_get(base + "/api/policy")[2])["mode"] == "redact"
    # Shield's own page still can
    code, body = _post(base + "/api/policy", weaken, {
        "Content-Type": "application/json", "Origin": base})
    assert code == 200 and body["mode"] == "observe"


def test_only_the_extension_can_send_browser_rows(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    base = _serve(cfg)
    rows = {"rows": [{"kind": "browser.chat.request", "app": "claude", "chars": 12,
                      "prompt": "email j.rivers@gmail.com", "wire": "/api/x"}]}
    json_h = {"Content-Type": "application/json"}
    assert _post(base + "/api/browser", rows, {**json_h, "Origin": "https://claude.ai"})[0] == 403
    assert _post(base + "/api/browser", rows, json_h)[0] == 403
    code, body = _post(base + "/api/browser", rows,
                       {**json_h, "Origin": "chrome-extension://abcdef"})
    assert code == 200 and body["accepted"] == 1
    stored = cfg.ledger.read_text()
    assert "j.rivers" not in stored and '"chars": 12' in stored
    # pinned to one extension id
    monkeypatch.setenv("BYOAI_SHIELD_EXTENSION_IDS", "trusted-id")
    assert _post(base + "/api/browser", rows,
                 {**json_h, "Origin": "chrome-extension://abcdef"})[0] == 403
    assert _post(base + "/api/browser", rows,
                 {**json_h, "Origin": "chrome-extension://trusted-id"})[0] == 200


def test_browser_rows_keep_only_known_fields():
    row = clean_browser_row({"kind": "browser.chat.request", "app": "claude",
                             "chars": 5, "prompt": "secret", "preview": "x",
                             "wire": "w" * 500, "ok": True})
    assert row is not None and set(row) == {"kind", "wall_clock", "app", "chars", "wire", "ok"}
    assert len(row["wire"]) == 60
    assert clean_browser_row({"kind": "desktop.chat.request"}) is None
    assert clean_browser_row({"kind": "browser.chat.request", "app": "evil",
                              "chars": True})["kind"] == "browser.chat.request"


def test_request_problem_allows_local_pages_and_get():
    ok_host = {"Host": "127.0.0.1:17831"}
    assert request_problem("GET", "/api/feed", ok_host) is None
    assert request_problem("GET", "/api/feed", {"Host": "attacker.test"}) is not None
    # Same-origin write: the origin must name the very host:port the request
    # was addressed to — Shield's own page — not merely "some localhost port".
    assert request_problem("POST", "/api/policy", {
        **ok_host, "Content-Type": "application/json; charset=utf-8",
        "Origin": "http://127.0.0.1:17831"}) is None
    # A different localhost port is another process, not Shield's page —
    # anything running there can't weaken Shield.
    assert request_problem("POST", "/api/policy", {
        **ok_host, "Content-Type": "application/json",
        "Origin": "http://localhost:9999"}) is not None


# ------------------------------------------- identity + login item


def test_identity_proves_the_device_key_over_the_callers_nonce(tmp_path):
    from byoai.integrations.shield import IDENTITY_PREFIX
    from byoai.recorder.keys import DeviceKey
    base = _serve(make_cfg(tmp_path))
    nonce = "ab" * 16
    code, _, body = _get(f"{base}/api/identity?nonce={nonce}")
    doc = json.loads(body)
    assert code == 200
    assert DeviceKey.verify(doc["public_key"], IDENTITY_PREFIX + nonce.encode(), doc["sig"])
    # a recorded answer does not verify against a different nonce
    assert not DeviceKey.verify(doc["public_key"], IDENTITY_PREFIX + b"cd" * 16, doc["sig"])
    # no nonce, or a malformed one, is refused rather than signed
    assert _get(f"{base}/api/identity")[0] == 404
    assert _get(f"{base}/api/identity?nonce=zz")[0] == 404


def test_login_item_plist_is_low_priority_and_backs_off(tmp_path):
    from byoai.integrations.shield_login import build_plist
    plist = build_plist(tmp_path / "captures.jsonl", 17831, python="/usr/bin/python3",
                        log_dir=tmp_path)
    assert plist["ProgramArguments"][-2:] == ["--port", "17831"]
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] == {"SuccessfulExit": False}   # restart on failure only
    assert plist["ThrottleInterval"] >= 30                   # a taken port is not a busy loop
    assert plist["LowPriorityIO"] is True and plist["Nice"] > 0


# ------------------------------------------------------------ hardening


def _stamped_chain(tmp_path, n=6):
    cfg = make_cfg(tmp_path)
    chain = SealChain(cfg)
    for i in range(n):
        chain.stamp({"interaction": f"i{i}", "chars": i})
    chain.sign_checkpoint()
    return cfg, chain


def _rewrite_log(chain, mutate):
    lines = [json.loads(x) for x in chain.log_path.read_text().splitlines()]
    mutate(lines)
    chain.log_path.write_text("".join(json.dumps(x) + "\n" for x in lines))


def test_an_edited_entry_with_a_recomputed_seal_is_still_caught(tmp_path):
    cfg, chain = _stamped_chain(tmp_path)
    assert chain.verify_chain()["tamper_evident"] is True

    def edit(lines):
        e = lines[2]
        e["payload"]["chars"] = 999                       # the edit
        leaf = chain._leaf(e["payload"])
        e["leaf_hash"], e["seal"] = leaf.hex(), leaf.hex()[:16]   # the cover-up
    _rewrite_log(chain, edit)
    v = SealChain(cfg).verify_chain()
    assert v["tamper_evident"] is False
    assert v["checkpoint_matches_entries"] is False


def test_the_whole_history_is_covered_not_just_the_last_512(tmp_path):
    cfg = make_cfg(tmp_path)
    chain = SealChain(cfg)
    for i in range(700):
        chain.stamp({"interaction": f"i{i}", "chars": i})
    assert chain.verify_chain()["tamper_evident"] is True

    def edit(lines):
        e = lines[3]                                       # far outside the window
        e["payload"]["chars"] = -1
        leaf = chain._leaf(e["payload"])
        e["leaf_hash"], e["seal"] = leaf.hex(), leaf.hex()[:16]
    _rewrite_log(chain, edit)
    assert SealChain(cfg).verify_chain()["tamper_evident"] is False


def test_cutting_entries_off_the_end_is_caught(tmp_path):
    cfg, chain = _stamped_chain(tmp_path, n=6)
    _rewrite_log(chain, lambda lines: lines.__delitem__(slice(-2, None)))
    v = SealChain(cfg).verify_chain()
    assert v["tamper_evident"] is False and v["checkpoint_matches_entries"] is False


def test_a_torn_last_line_from_a_crash_is_dropped_quietly(tmp_path):
    cfg, chain = _stamped_chain(tmp_path, n=3)
    with chain.log_path.open("a") as fh:
        fh.write('{"height": 4, "pay')                    # power cut mid-write
    reborn = SealChain(cfg)
    assert reborn.height == 3 and reborn.incidents == []
    reborn.stamp({"interaction": "next"})
    assert SealChain(cfg).height == 4


def test_a_broken_log_is_kept_and_the_intact_part_carried_over(tmp_path):
    cfg, chain = _stamped_chain(tmp_path, n=5)
    lines = chain.log_path.read_text().splitlines()
    lines[3] = lines[3].replace('"chars": 3', '"chars": 33')
    chain.log_path.write_text("\n".join(lines) + "\n")
    reborn = SealChain(cfg)
    assert reborn.height == 3
    assert reborn.incidents[0]["what"] == "chain_broken"
    assert list(tmp_path.glob("sealchain.log.jsonl.broken-*"))
    assert reborn.verify_chain()["tamper_evident"] is False


def test_an_unreadable_state_file_is_kept_and_recorded_not_silently_reset(tmp_path):
    cfg, chain = _stamped_chain(tmp_path)
    cfg.seal_path.write_text("{ not json")
    reborn = SealChain(cfg)
    assert reborn.incidents[0]["what"] == "chain_unreadable"
    assert reborn.verify_chain()["tamper_evident"] is False
    kept = list(tmp_path.glob("sealchain.json.unreadable-*"))
    assert len(kept) == 1 and kept[0].read_text() == "{ not json"
    assert SealChain(cfg).incidents                    # and it survives a restart


def test_an_edit_made_while_shield_is_running_is_found(tmp_path):
    cfg, chain = _stamped_chain(tmp_path)
    assert chain.verify_chain()["tamper_evident"] is True
    _rewrite_log(chain, lambda lines: lines[1]["payload"].__setitem__("chars", 555))
    assert chain.verify_chain()["tamper_evident"] is False


def test_a_format_1_chain_file_is_carried_over(tmp_path):
    cfg = make_cfg(tmp_path)
    from byoai.recorder.merkle import checkpoint_leaf_hash
    old = [{"height": i, "payload": {"interaction": f"o{i}"},
            "seal": checkpoint_leaf_hash({"interaction": f"o{i}"}).hex()[:16],
            "leaf_hash": checkpoint_leaf_hash({"interaction": f"o{i}"}).hex()}
           for i in (1, 2, 3)]
    cfg.seal_path.write_text(json.dumps({"entries": old, "checkpoint": None}))
    chain = SealChain(cfg)
    assert chain.height == 3 and chain.verify_chain()["tamper_evident"] is True
    assert SealChain(cfg).height == 3


def test_the_sealed_total_never_shrinks_and_nothing_is_trimmed(tmp_path):
    cfg, chain = _stamped_chain(tmp_path, n=5)
    for i in range(600):
        chain.stamp({"interaction": f"x{i}"})
    assert chain.total == 605 and chain.verify_chain()["sealed_total"] == 605
    assert SealChain(cfg).total == 605


def test_restarting_does_not_seal_the_ledger_again(tmp_path):
    cfg = make_cfg(tmp_path)
    rows = [{"wall_clock": "2026-09-25 09:00:00", "kind": "desktop.chat.request",
             "app": "claude", "chars": n} for n in (5, 5, 9)]   # two identical sends
    cfg.ledger.write_text("".join(json.dumps(r) + "\n" for r in rows))
    feed = Feed(cfg)
    feed.scan_initial()
    assert feed.seals.total == 3
    for _ in range(3):                                          # three restarts
        again = Feed(cfg)
        again.scan_initial()
        assert again.seals.total == 3
    with cfg.ledger.open("a") as fh:                            # a new row still seals
        fh.write(json.dumps(rows[0]) + "\n")
    again.poll()
    assert again.seals.total == 4


def test_shield_files_are_written_private_and_atomically(tmp_path):
    import os
    from byoai.integrations.shield import atomic_write_private
    target = tmp_path / "state.json"
    atomic_write_private(target, "one")
    atomic_write_private(target, "two")
    assert target.read_text() == "two"
    assert [p.name for p in tmp_path.iterdir()] == ["state.json"]   # no temp left
    if os.name == "posix":
        assert (target.stat().st_mode & 0o777) == 0o600


def test_a_browser_row_is_sealed_before_the_request_returns(tmp_path):
    base = _serve(make_cfg(tmp_path))
    ext = {"Content-Type": "application/json",
           "Origin": "chrome-extension://abcdefghijklmnopabcdefghijklmnop"}
    code, out = _post(base + "/api/browser", {"rows": [{
        "kind": "browser.chat.request", "app": "claude", "chars": 7,
        "row_id": "r-1"}]}, ext)
    assert code == 200 and out["accepted"] == 1 and out["sealed_total"] == 1
    assert json.loads(_get(base + "/api/verify")[2])["sealed_total"] == 1


def test_linux_unit_and_windows_task_are_low_priority_and_run_as_the_user(tmp_path):
    from byoai.integrations.shield_login import (
        build_unit, windows_command, windows_create_args)
    ledger = tmp_path / "my ledger" / "captures.jsonl"       # a space in the path
    unit = build_unit(ledger, 17831, python="/usr/bin/python3", log_dir=tmp_path)
    assert f'ExecStart="/usr/bin/python3" "-m" "byoai.integrations.shield" "{ledger}" "--port" "17831"' in unit
    assert "Restart=on-failure" in unit and "RestartSec=30" in unit
    assert "Nice=5" in unit and "IOSchedulingClass=idle" in unit
    assert "WantedBy=default.target" in unit                  # user unit, no root
    cmd = windows_command(Path("C:/data/captures.jsonl"), 17831, python="C:/Py/python.exe")
    assert cmd.endswith('"--port" "17831"') and '"byoai.integrations.shield"' in cmd
    args = windows_create_args(Path("C:/data/captures.jsonl"), 17831, python="C:/Py/python.exe")
    assert args[:2] == ["schtasks", "/Create"]
    assert "ONLOGON" in args and args[args.index("/RL") + 1] == "LIMITED"   # no elevation


# ------------------------------------------------------- review follow-ups


def _ledger_rows(n):
    return [{"wall_clock": "2026-09-25 09:00:00", "kind": "desktop.chat.request",
             "app": "claude", "chars": 10 + i} for i in range(n)]


def test_rows_lost_to_a_broken_log_line_are_sealed_again_from_the_ledger(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg.ledger.write_text("".join(json.dumps(r) + "\n" for r in _ledger_rows(6)))
    feed = Feed(cfg)
    feed.scan_initial()
    assert feed.seals.total == 6
    log = feed.seals.log_path
    lines = log.read_text().splitlines()
    lines[2] = lines[2].replace('"chars": 12', '"chars": 99')       # one bad line
    log.write_text("\n".join(lines) + "\n")
    again = Feed(cfg)
    again.scan_initial()
    # the entries after the bad line are back in the live chain, not just the prefix
    assert again.seals.total == 6
    assert any(i["what"] == "chain_broken" for i in again.seals.incidents)
    assert list(tmp_path.glob("sealchain.log.jsonl.broken-*"))


@pytest.mark.parametrize("value", ["", "abc", "70000", "-1", " "])
def test_a_bad_port_setting_does_not_crash_the_import(value):
    import subprocess, sys
    out = subprocess.run(
        [sys.executable, "-c",
         "import byoai.integrations.shield as s; print(s.DEFAULT_PORT)"],
        env={**os.environ, "BYOAI_SHIELD_PORT": value},
        capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "17831"
    assert "BYOAI_SHIELD_PORT" in out.stderr           # and says why


def test_a_ledger_read_that_fails_once_is_retried_not_skipped(tmp_path, monkeypatch):
    cfg = make_cfg(tmp_path)
    feed = Feed(cfg)
    feed.scan_initial()
    with cfg.ledger.open("a") as fh:
        fh.write(json.dumps(_ledger_rows(1)[0]) + "\n")
    real = Path.read_text
    calls = {"n": 0}

    def flaky(self, *a, **kw):
        if self == cfg.ledger and calls["n"] == 0:
            calls["n"] += 1
            raise PermissionError("locked by another process")   # Windows file lock
        return real(self, *a, **kw)
    monkeypatch.setattr(Path, "read_text", flaky)
    feed.poll()
    feed.poll()
    assert feed.seals.total == 1


def test_a_burst_of_rows_signs_one_checkpoint_that_covers_them_all(tmp_path):
    cfg = make_cfg(tmp_path)
    cfg = ShieldConfig(ledger=cfg.ledger, seal_path=cfg.seal_path, key_dir=cfg.key_dir,
                       policy_path=cfg.policy_path, sig_every=1, max_interactions=100)
    feed = Feed(cfg)
    feed.scan_initial()
    signed = []
    orig = feed.seals._sign_checkpoint
    feed.seals._sign_checkpoint = lambda: signed.append(1) or orig()
    with cfg.ledger.open("a") as fh:
        for r in _ledger_rows(40):
            fh.write(json.dumps(r) + "\n")
    feed.poll()
    assert feed.seals.total == 40
    assert len(signed) <= 2
    v = feed.seals.verify_chain()
    assert v["tamper_evident"] is True and feed.seals.checkpoint["height"] == 40


def _v1_file(cfg, n, *, signed_over=None, total=None, height=None):
    from byoai.recorder.merkle import MerkleTree, checkpoint_leaf_hash
    entries, leaves = [], []
    for i in range(1, n + 1):
        leaf = checkpoint_leaf_hash({"interaction": f"o{i}"})
        leaves.append(leaf)
        entries.append({"height": i, "payload": {"interaction": f"o{i}"},
                        "seal": leaf.hex()[:16], "leaf_hash": leaf.hex()})
    over = leaves if signed_over is None else leaves[:signed_over]
    cp = {"kind": "byoai.shield.checkpoint.v1", "root_hex": MerkleTree(over).root.hex(),
          "height": height or len(over), "ts": "2026-01-01T00:00:00Z", "device_id": "d",
          "public_key_b64": "k", "sig": "s"}
    cfg.seal_path.write_text(json.dumps({"entries": entries, "checkpoint": cp,
                                         "total": total or n}))


def test_an_upgrade_keeps_the_old_signed_checkpoint_when_it_still_matches(tmp_path):
    cfg = make_cfg(tmp_path)
    _v1_file(cfg, 4)
    old = cfg.seal_path.read_text()
    chain = SealChain(cfg)
    assert chain.checkpoint and chain.checkpoint["height"] == 4
    assert chain.incidents == []
    assert [p.read_text() for p in tmp_path.glob("sealchain.json.v1-*")] == [old]


def test_an_upgrade_says_so_when_the_old_checkpoint_cannot_be_kept(tmp_path):
    cfg = make_cfg(tmp_path)
    _v1_file(cfg, 4, height=7, total=7)                # signed over entries the old format trimmed
    chain = SealChain(cfg)
    kinds = [i["what"] for i in chain.incidents]
    assert "checkpoint_mismatch" not in kinds          # not a false tamper alarm
    assert "migrated" in kinds
    assert list(tmp_path.glob("sealchain.json.v1-*"))


def test_an_upgrade_does_not_make_the_sealed_total_shrink(tmp_path):
    cfg = make_cfg(tmp_path)
    _v1_file(cfg, 4, height=700, total=700)            # the extension remembers 700
    chain = SealChain(cfg)
    assert chain.total == 700 and chain.verify_chain()["sealed_total"] == 700
    chain.stamp({"interaction": "next"})
    assert SealChain(cfg).total == 701


@pytest.mark.parametrize("bad_total", [10**12, "lots", None, True, 2])
def test_an_edited_entry_count_in_the_old_file_is_not_trusted(tmp_path, bad_total):
    cfg = make_cfg(tmp_path)
    _v1_file(cfg, 4)
    state = json.loads(cfg.seal_path.read_text())
    state["total"] = bad_total
    cfg.seal_path.write_text(json.dumps(state))
    chain = SealChain(cfg)                              # starts, and counts what it holds
    assert chain.total == 4


def test_a_mismatch_in_an_old_file_is_still_reported_as_tampering(tmp_path):
    cfg = make_cfg(tmp_path)
    _v1_file(cfg, 4)
    state = json.loads(cfg.seal_path.read_text())
    state["entries"][1]["payload"]["interaction"] = "edited"       # covered by the checkpoint
    leaf = SealChain._leaf(None, state["entries"][1]["payload"])
    state["entries"][1]["leaf_hash"], state["entries"][1]["seal"] = leaf.hex(), leaf.hex()[:16]
    cfg.seal_path.write_text(json.dumps(state))
    kinds = [i["what"] for i in SealChain(cfg).incidents]
    assert "checkpoint_mismatch" in kinds and "migrated" not in kinds


def test_the_store_package_omits_the_dev_key_and_ships_what_the_manifest_names(tmp_path):
    import importlib.util, zipfile
    spec = importlib.util.spec_from_file_location(
        "package_extension", Path(__file__).resolve().parents[2] / "scripts" / "package_extension.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    store = zipfile.ZipFile(mod.build(tmp_path / "s"))
    dev = zipfile.ZipFile(mod.build(tmp_path / "d", keep_key=True))
    assert "key" not in json.loads(store.read("manifest.json"))
    assert "key" in json.loads(dev.read("manifest.json"))
    m = json.loads(store.read("manifest.json"))
    names = set(store.namelist())
    wanted = {m["background"]["service_worker"], m["action"]["default_popup"], "welcome.html",
              "welcome.js", "popup.js", "PRIVACY.md"}
    for cs in m["content_scripts"]:
        wanted.update(cs["js"])
    assert wanted <= names
    assert not any(n.endswith(".DS_Store") for n in names)
    assert "tabs" not in m["permissions"]


def test_the_minified_store_package_keeps_every_file_and_shared_names(tmp_path):
    import importlib.util, zipfile
    spec = importlib.util.spec_from_file_location(
        "package_extension", Path(__file__).resolve().parents[2] / "scripts" / "package_extension.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    if not mod.ESBUILD.exists():
        pytest.skip("esbuild not installed (npm ci in web/)")
    plain = zipfile.ZipFile(mod.build(tmp_path / "p"))
    small = zipfile.ZipFile(mod.build(tmp_path / "m", minify=True))
    assert set(small.namelist()) == set(plain.namelist())
    for name in (n for n in small.namelist() if n.endswith(".js")):
        code = small.read(name).decode()
        assert "sourceMappingURL" not in code
        assert len(code) <= len(plain.read(name))
    # The scripts talk to each other through these names; minifying must keep them.
    assert "__shieldRules" in small.read("shield-rules.js").decode()
    assert "SHIELD_CONSENT_VERSION" in small.read("consent.js").decode()
    assert "key" not in json.loads(small.read("manifest.json"))


def _run_launcher(block):
    import subprocess, sys
    code = (f"import sys; sys.modules[{block!r}] = None; "
            "from byoai.integrations.shield_launcher import main; main()")
    return subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)


def test_the_shield_command_says_how_to_install_a_missing_signing_library():
    out = _run_launcher("cryptography")
    assert out.returncode == 1
    assert "byoai-runtime[shield]" in out.stderr and "Traceback" not in out.stderr


def test_the_shield_command_does_not_hide_other_import_errors():
    out = _run_launcher("byoai.recorder.merkle")
    assert out.returncode != 0
    assert "Traceback" in out.stderr and "byoai-runtime[shield]" not in out.stderr


def test_importing_shield_without_the_signing_library_is_a_plain_import_error():
    import subprocess, sys
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys; sys.modules['cryptography'] = None\n"
         "try:\n    import byoai.integrations.shield\n"
         "except ImportError as e:\n    print('ImportError'); raise SystemExit(0)\n"
         "raise SystemExit('imported without raising')"],
        capture_output=True, text=True)
    assert out.returncode == 0 and "ImportError" in out.stdout      # a library import must not exit the host


def test_the_shield_extra_exists_and_the_all_extra_includes_it():
    import re
    text = (Path(__file__).resolve().parents[2] / "pyproject.toml").read_text()
    assert re.search(r'^shield = \["cryptography', text, re.M)
    assert "recorder,shield]" in text


def test_the_extension_declares_icons_that_exist_at_the_stated_sizes():
    import struct
    root = Path(__file__).resolve().parents[2] / "src" / "byoai" / "browser_extension"
    m = json.loads((root / "manifest.json").read_text())
    assert set(m["icons"]) == {"16", "32", "48", "128"}          # the store needs a 128 icon
    assert m["action"]["default_icon"] == m["icons"]
    for size, rel in m["icons"].items():
        raw = (root / rel).read_bytes()
        assert raw[:8] == b"\x89PNG\r\n\x1a\n"
        width, height = struct.unpack(">II", raw[16:24])
        assert (width, height) == (int(size), int(size))


# ------------------------------------------------------- Shield managed mode
#
# Signed managed policy: Coriqo signs a policy envelope, the device verifies
# and applies it. These tests
# cover the pure verify/apply/effective-policy logic in shield.py; the
# publisher's polling, key-pinning and HTTP-level (locked key, managed field)
# behaviour is covered in test_shield_publish.py and further down here.

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from byoai.integrations.shield import apply_managed_envelope, load_managed_policy
from byoai.recorder.canonical import canonicalize

# Coriqo signs with its own server key, not a device key: lowercase hex of the
# raw 32-byte public key and the raw 64-byte signature, no "ed25519:" prefix —
# unlike byoai.recorder.keys.DeviceKey. These fixtures build server-shaped
# envelopes so the tests exercise the real wire format, not DeviceKey's.


def _server_key():
    return Ed25519PrivateKey.generate()


def _pub_hex(key) -> str:
    return key.public_key().public_bytes_raw().hex()


def _envelope(key, **doc_overrides):
    doc = {
        "policy_id": "pol_1", "version": 1, "tenant_slug": "acme",
        "device_id": None, "issued_at": "2026-09-26T10:00:00Z",
        "key_id": "coriqo-v1", "managed_by": "Acme IT",
        "policy": {"mode": "block", "apps": {"claude": True}, "keep_text": False,
                   "retention_days": 7, "notice": True},
        "locked": ["mode", "apps", "keep_text", "retention_days", "notice"],
    }
    doc.update(doc_overrides)
    return {"document": doc, "signature": key.sign(canonicalize(doc)).hex()}


def test_a_good_signature_applies_and_locks_the_listed_keys(tmp_path):
    key = _server_key()
    path = tmp_path / "managed.json"
    result = apply_managed_envelope(_envelope(key), tenant_slug="acme", device_id="dev-1",
                                    public_key=_pub_hex(key), path=path)
    assert result == {"ok": True, "error": None}
    stored = load_managed_policy(path)
    assert stored["envelope"]["document"]["version"] == 1


def test_a_device_override_applies_to_its_own_device(tmp_path):
    key = _server_key()
    path = tmp_path / "managed.json"
    env = _envelope(key, device_id="dev-1")
    result = apply_managed_envelope(env, tenant_slug="acme", device_id="dev-1",
                                    public_key=_pub_hex(key), path=path)
    assert result["ok"] is True


def test_locked_keys_override_the_local_policy(tmp_path):
    cfg = make_cfg(tmp_path)
    key = _server_key()
    save_policy(cfg, merge_policy({"mode": "redact"}))
    apply_managed_envelope(_envelope(key), tenant_slug="acme", device_id="dev-1",
                           public_key=_pub_hex(key), path=cfg.managed_policy_path)
    p = load_policy(cfg)
    assert p["mode"] == "block" and p["apps"]["claude"] is True and p["retention_days"] == 7


def test_bad_signature_is_refused_and_keeps_the_previous_policy(tmp_path):
    key = _server_key()
    path = tmp_path / "managed.json"
    apply_managed_envelope(_envelope(key), tenant_slug="acme", device_id="dev-1",
                           public_key=_pub_hex(key), path=path)
    bad = _envelope(key, version=2)
    bad["signature"] = bad["signature"][:-4] + "abcd"
    result = apply_managed_envelope(bad, tenant_slug="acme", device_id="dev-1",
                                    public_key=_pub_hex(key), path=path)
    assert result["ok"] is False and "signature" in result["error"]
    assert load_managed_policy(path)["envelope"]["document"]["version"] == 1


def test_wrong_tenant_is_refused_and_keeps_the_previous_policy(tmp_path):
    key = _server_key()
    path = tmp_path / "managed.json"
    apply_managed_envelope(_envelope(key), tenant_slug="acme", device_id="dev-1",
                           public_key=_pub_hex(key), path=path)
    other = _envelope(key, version=2, tenant_slug="other_co")
    result = apply_managed_envelope(other, tenant_slug="acme", device_id="dev-1",
                                    public_key=_pub_hex(key), path=path)
    assert result["ok"] is False and "tenant" in result["error"]
    assert load_managed_policy(path)["envelope"]["document"]["version"] == 1


def test_another_devices_override_is_refused(tmp_path):
    key = _server_key()
    path = tmp_path / "managed.json"
    apply_managed_envelope(_envelope(key), tenant_slug="acme", device_id="dev-1",
                           public_key=_pub_hex(key), path=path)
    other = _envelope(key, version=2, device_id="dev-2")
    result = apply_managed_envelope(other, tenant_slug="acme", device_id="dev-1",
                                    public_key=_pub_hex(key), path=path)
    assert result["ok"] is False and "device" in result["error"]
    assert load_managed_policy(path)["envelope"]["document"]["version"] == 1


def test_rollback_is_refused_and_keeps_the_previous_policy(tmp_path):
    key = _server_key()
    path = tmp_path / "managed.json"
    apply_managed_envelope(_envelope(key, version=5), tenant_slug="acme", device_id="dev-1",
                           public_key=_pub_hex(key), path=path)
    older = _envelope(key, version=3)
    result = apply_managed_envelope(older, tenant_slug="acme", device_id="dev-1",
                                    public_key=_pub_hex(key), path=path)
    assert result["ok"] is False and "rollback" in result["error"]
    same = _envelope(key, version=5)
    result = apply_managed_envelope(same, tenant_slug="acme", device_id="dev-1",
                                    public_key=_pub_hex(key), path=path)
    assert result["ok"] is False and "rollback" in result["error"]
    assert load_managed_policy(path)["envelope"]["document"]["version"] == 5


def test_an_unknown_key_id_is_refused(tmp_path):
    key = _server_key()
    path = tmp_path / "managed.json"
    result = apply_managed_envelope(_envelope(key), tenant_slug="acme", device_id="dev-1",
                                    public_key=None, path=path)
    assert result["ok"] is False and "unknown key" in result["error"]
    assert load_managed_policy(path) is None


def test_policy_null_unmanages_the_device(tmp_path):
    cfg = make_cfg(tmp_path)
    key = _server_key()
    save_policy(cfg, merge_policy({"mode": "redact"}))
    apply_managed_envelope(_envelope(key), tenant_slug="acme", device_id="dev-1",
                           public_key=_pub_hex(key), path=cfg.managed_policy_path)
    assert load_policy(cfg)["mode"] == "block"
    unmanage = _envelope(key, version=2, policy=None, locked=[])
    result = apply_managed_envelope(unmanage, tenant_slug="acme", device_id="dev-1",
                                    public_key=_pub_hex(key), path=cfg.managed_policy_path)
    assert result["ok"] is True
    # a signed policy:null still counts against rollback for the next envelope
    stored = load_managed_policy(cfg.managed_policy_path)
    assert stored["envelope"]["document"]["version"] == 2
    assert load_policy(cfg)["mode"] == "redact"       # back to the local choice


def test_get_policy_reports_managed_state(tmp_path):
    cfg = make_cfg(tmp_path)
    key = _server_key()
    apply_managed_envelope(_envelope(key), tenant_slug="acme", device_id="dev-1",
                           public_key=_pub_hex(key), path=cfg.managed_policy_path)
    base = _serve(cfg)
    body = json.loads(_get(base + "/api/policy")[2])
    assert body["managed"]["by"] == "Acme IT"
    assert body["managed"]["version"] == 1
    assert set(body["managed"]["locked"]) == {"mode", "apps", "keep_text",
                                              "retention_days", "notice"}


def test_post_policy_refuses_a_locked_key(tmp_path):
    cfg = make_cfg(tmp_path)
    key = _server_key()
    apply_managed_envelope(_envelope(key, locked=["mode"]), tenant_slug="acme",
                           device_id="dev-1", public_key=_pub_hex(key),
                           path=cfg.managed_policy_path)
    base = _serve(cfg)
    code, body = _post(base + "/api/policy", {"mode": "observe", "acknowledge": "less_private"},
                       {"Content-Type": "application/json", "Origin": base})
    assert code == 409 and "Acme IT" in body["error"]
    # a key that isn't locked still saves
    code, body = _post(base + "/api/policy", {"notice": False},
                       {"Content-Type": "application/json", "Origin": base})
    assert code == 200 and body["notice"] is False


def test_interop_vector_matches_coriqos_canonical_bytes_and_signature(tmp_path):
    """A fixed vector: a hardcoded seed, a hardcoded document, and the exact
    hex signature Coriqo's ``canonical_bytes`` (``json.dumps(sort_keys=True,
    separators=(",", ":"), ensure_ascii=False)``) produces for it — computed
    independently of this codebase. If :func:`canonicalize` ever stops being
    byte-identical to that for a policy document, this is the test that
    catches it, not a round-trip through our own signer."""
    seed = bytes(range(32))
    pub_hex = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    sig_hex = ("4cd9984b0be1385acd08ac7ec6d4db211749c9d68dfbed0e5a07f16d8964cfa"
              "9092cd261f4203b930753a8dc6205870fe68e1ce2b45a3401e92245ae461863"
              "04")
    doc = {
        "policy_id": "pol_interop_1", "version": 1, "tenant_slug": "acme",
        "device_id": None, "issued_at": "2026-09-26T10:00:00Z",
        "key_id": "coriqo-v1", "managed_by": "Acme IT",
        "policy": {"mode": "block", "apps": {"claude": True}, "keep_text": False,
                   "retention_days": 7, "notice": True},
        "locked": ["mode"],
    }
    assert canonicalize(doc) == (
        b'{"device_id":null,"issued_at":"2026-09-26T10:00:00Z","key_id":"coriqo-v1",'
        b'"locked":["mode"],"managed_by":"Acme IT","policy":{"apps":{"claude":true},'
        b'"keep_text":false,"mode":"block","notice":true,"retention_days":7},'
        b'"policy_id":"pol_interop_1","tenant_slug":"acme","version":1}'
    )
    envelope = {"document": doc, "signature": sig_hex}
    path = tmp_path / "managed.json"
    result = apply_managed_envelope(envelope, tenant_slug="acme", device_id="dev-1",
                                    public_key=pub_hex, path=path)
    assert result == {"ok": True, "error": None}
    del seed  # not needed to verify; recorded for anyone regenerating the vector


def _managed_sync(tmp_path, cfg, *, by, sync, locked=("sync",)):
    (tmp_path / "managed_policy.json").write_text(json.dumps({
        "fetched_at": "2026-09-26T09:00:00Z",
        "envelope": {"signature": "x", "document": {
            "version": 1, "managed_by": by, "locked": list(locked),
            "policy": {"sync": sync}}}}))


def test_sharing_is_disclosed_even_when_no_organisation_is_named(tmp_path):
    cfg = make_cfg(tmp_path)
    _managed_sync(tmp_path, cfg, by=None, sync="events")
    got = json.loads(_get(_serve(cfg) + "/api/policy")[2])
    assert got["sync"] == "events"
    assert got["sharing"]["by"] == "Your administrator"
    assert "Never what you wrote" in got["sharing"]["words"]


def test_sharing_names_the_organisation_at_seal_level(tmp_path):
    cfg = make_cfg(tmp_path)
    _managed_sync(tmp_path, cfg, by="Contoso IT", sync="seal")
    got = json.loads(_get(_serve(cfg) + "/api/policy")[2])
    assert got["sharing"]["level"] == "seal" and got["sharing"]["by"] == "Contoso IT"


def test_local_file_cannot_turn_sync_on(tmp_path):
    cfg = make_cfg(tmp_path)
    (tmp_path / "policy.json").write_text(json.dumps({"sync": "events"}))
    got = json.loads(_get(_serve(cfg) + "/api/policy")[2])
    assert got["sync"] == "seal" and "sharing" not in got
    # ...nor can an unlocked managed value
    _managed_sync(tmp_path, cfg, by="Contoso IT", sync="events", locked=("mode",))
    from byoai.integrations.shield import load_policy
    assert load_policy(cfg)["sync"] == "seal"


# ------------------------------------------------- browser-side redaction

_CASES = Path(__file__).resolve().parents[1] / "fixtures" / "shield_redaction_cases.json"


def test_the_shared_redaction_cases_hold_for_the_python_rules():
    """The extension's page capture is checked against the same file
    (web/tests/extension/redaction.test.mjs); both passing is what keeps the
    desktop proxy and the browser from disagreeing about a personal detail."""
    from byoai.integrations.shield import (
        action_for,
        evaluate,
        flags_for,
        message_text,
        redact_json_body,
    )
    for case in json.loads(_CASES.read_text())["cases"]:
        raw = case.get("raw") or json.dumps(case["body"])
        want, mode = case["expect"], case["mode"]
        policy = {**default_policy(), "mode": mode}
        if case.get("actions"):
            policy["actions"] = {**policy["actions"], **case["actions"]}
        try:
            body = json.loads(raw)
        except ValueError:
            body = None
        text = message_text(body) if isinstance(body, dict) else ""
        assert (len(text) if text else len(raw)) == want["chars"], case["name"]
        assert [f"{t}:{r}" for t, r, _ in flags_for(text)
                if not r.startswith("reply_")] == want["flags"], case["name"]
        action, rules = evaluate(text, policy)
        if "action" in want:
            assert action == want["action"], case["name"]
        if action == "block":
            assert [r for r in rules if action_for(r, policy) == "block"] == want["blocked"], case["name"]
            assert want["verdict"] == "blocked", case["name"]
            continue
        if mode == "observe":
            assert want["body"] is None and want["verdict"] == "observe", case["name"]
            continue
        out, hit = redact_json_body(raw, policy)
        if action == "warn":  # the proxy has no prompt, so it redacts
            assert json.loads(out) == {**(body or {}), **want["warn_redacts"]}, case["name"]
            continue
        assert hit == want["redactions"], case["name"]
        assert (json.loads(out) if hit else None) == want["body"], case["name"]
        assert want["verdict"] == (f"redacted({len(hit)})" if hit else mode), case["name"]


def test_the_extension_rules_file_is_generated_from_the_python_rules():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gen_extension_rules",
        Path(__file__).resolve().parents[2] / "scripts" / "gen_extension_rules.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.TARGET.read_text() == mod.render(), (
        "shield-rules.js is out of date: run python scripts/gen_extension_rules.py")


def test_the_extension_sites_file_is_generated_from_sites_json():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "gen_extension_rules",
        Path(__file__).resolve().parents[2] / "scripts" / "gen_extension_rules.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.SITES_TARGET.read_text() == mod.render_sites(), (
        "shield-sites.js is out of date: run python scripts/gen_extension_rules.py")
    sites = json.loads(mod.SITES_SOURCE.read_text())["sites"]
    assert {s["app"] for s in sites} >= {"claude", "chatgpt", "gemini", "copilot"}
    for s in sites:
        assert set(s) >= {"hosts", "compose", "send", "chat_paths", "upload"}
    # Every host the extension runs on has a profile, and the manifest loads the shared files in both worlds.
    manifest = json.loads((mod.SITES_SOURCE.parent / "manifest.json").read_text())
    hosts = {h for s in sites for h in s["hosts"]}
    for entry in manifest["content_scripts"]:
        assert {m.split("//")[1].split("/")[0] for m in entry["matches"]} == hosts
        js = entry["js"]
        # The shared engine reads the rules and the site list, and both scripts read the engine.
    isolated = next(e for e in manifest["content_scripts"] if "world" not in e)
    page = next(e for e in manifest["content_scripts"] if e.get("world") == "MAIN")
    assert isolated["js"][-1] == "content-relay.js" and page["js"][-1] == "content.js"
    pj = page["js"]
    assert pj.index("shield-rules.js") < pj.index("shield-core.js") < pj.index("content.js")
    assert pj.index("shield-sites.js") < pj.index("shield-core.js")
    # Chrome injects a file once per frame: no file may be listed in both worlds
    # (found live: the isolated world never got the site profiles). The isolated
    # world loads its own generated bundle first.
    assert not set(isolated["js"]) & set(pj)
    assert isolated["js"][0] == "shield-iso.js"
    assert mod.ISO_TARGET.read_text() == mod.render_iso(), (
        "shield-iso.js is out of date: run python scripts/gen_extension_rules.py")
    # The host -> app map is not written by hand anywhere else in the extension.
    ext = mod.SITES_SOURCE.parent
    for name in ("shield-core.js", "content.js", "content-relay.js"):
        assert "'claude.ai': 'claude'" not in (ext / name).read_text(), name


def test_browser_rows_keep_rule_names_but_nothing_else():
    row = clean_browser_row({
        "kind": "browser.chat.request", "app": "chatgpt", "chars": 47,
        "flags": ["pii:emails", "pii:emails", "pii:abdul@coriqo.io", 7, "secret:credential_assign",
                  "flag:tool_intent", "high:credential_block"],
        "redactions": ["emails", "abdul@coriqo.io", "password_said", "openai_key"],
        "verdict": "redacted(1)"})
    assert row["flags"] == ["pii:emails", "secret:credential_assign", "flag:tool_intent"]
    assert row["redactions"] == ["emails", "openai_key"]  # password_said is a flag, never replaced
    assert row["verdict"] == "redacted(1)"
    assert "verdict" not in clean_browser_row({"kind": "browser.chat.request",
                                               "verdict": "sent abdul@coriqo.io"})


def test_a_redacted_or_stopped_browser_send_shows_what_shield_did(tmp_path):
    base = _serve(make_cfg(tmp_path))
    ext = {"Content-Type": "application/json",
           "Origin": "chrome-extension://abcdefghijklmnopabcdefghijklmnop"}
    code, _ = _post(base + "/api/browser", {"rows": [
        {"kind": "browser.chat.request", "app": "claude", "chars": 47, "row_id": "r-redacted",
         "flags": ["pii:emails"], "redactions": ["emails"], "verdict": "redacted(1)"},
        {"kind": "browser.chat.request", "app": "claude", "chars": 37, "row_id": "r-blocked",
         "flags": ["secret:aws_access_key"], "verdict": "blocked"},
        {"kind": "browser.chat.request", "app": "claude", "chars": 5, "row_id": "r-old-extension"},
    ]}, ext)
    assert code == 200
    items = json.loads(_get(base + "/api/feed")[2])["items"]
    old, stopped, redacted = items[:3]
    assert redacted["redactions"] == ["emails"] and redacted["tier"] == "warn"
    assert [f["rule"] for f in redacted["flags"]] == ["emails"]
    assert stopped["status"] == "blocked" and stopped["tier"] == "bad"
    assert "stopped in this browser" in stopped["verb"]
    assert old["flags"] == [] and old["redactions"] == []


def test_a_browser_send_shows_in_local_time_and_is_sealed_once(tmp_path, monkeypatch):
    """The extension stamps sends in UTC; the person reads this Mac's time.
    The seal keeps the UTC stamp, so reading the ledger again (a restart)
    finds every browser row already sealed rather than sealing it anew."""
    import time as _time
    monkeypatch.setenv("TZ", "America/Chicago")
    _time.tzset()
    try:
        cfg = make_cfg(tmp_path)
        cfg.ledger.write_text(json.dumps({
            "kind": "browser.chat.request", "app": "chatgpt", "chars": 47,
            "sent_at": "2026-09-28T18:18:56.238Z", "wall_clock": "2026-09-28 13:18:58",
            "row_id": "04b52d1a-8537-4889-9b91-4b6dd77b8999"}) + "\n")
        feed = Feed(cfg)
        feed.scan_initial()
        item = feed.items[0]
        assert (item["date"], item["ts"]) == ("2026-09-28", "13:18:56")
        sealed = feed.seals.total
        again = Feed(cfg)
        again.scan_initial()
        assert again.items[0]["ts"] == "13:18:56"
        assert again.seals.total == sealed == 1
    finally:
        monkeypatch.delenv("TZ")
        _time.tzset()


def test_a_reply_row_keeps_tool_names_and_nothing_else():
    row = clean_browser_row({"kind": "browser.chat.reply", "app": "chatgpt",
                             "tools": ["web.run", "web.run", "rm -rf /", 3, "x" * 49],
                             "sources": 9, "text": "It is sunny"})
    assert row["tools"] == ["web.run"] and row["sources"] == 9
    assert "text" not in row
    assert "sources" not in clean_browser_row({"kind": "browser.chat.reply", "sources": -1})


def test_tools_land_on_their_message_and_are_sealed_once(tmp_path):
    cfg = make_cfg(tmp_path)
    rows_ = [
        {"kind": "browser.chat.request", "app": "chatgpt", "chars": 5, "row_id": "a" * 8,
         "sent_at": "2026-09-28T18:00:00Z", "wall_clock": "2026-09-28 13:00:00"},
        {"kind": "browser.chat.request", "app": "chatgpt", "chars": 36, "row_id": "b" * 8,
         "sent_at": "2026-09-28T18:30:00Z", "wall_clock": "2026-09-28 13:30:00"},
        {"kind": "browser.chat.status", "app": "chatgpt", "ok": True, "status": 200},
        {"kind": "browser.chat.reply", "app": "chatgpt", "tools": ["web.run"], "sources": 9},
    ]
    cfg.ledger.write_text("".join(json.dumps(r) + "\n" for r in rows_))
    feed = Feed(cfg)
    feed.scan_initial()
    newest, older = feed.items[0], feed.items[1]
    assert newest["tools"] == ["web.run"] and newest["sources"] == 9
    assert older["tools"] == [] and older["sources"] is None
    sealed = feed.seals.total
    again = Feed(cfg)
    again.scan_initial()                     # a restart replays the ledger
    assert again.seals.total == sealed and again.items[0]["seal"] == newest["seal"]


def test_a_failed_browser_send_marks_the_newest_message(tmp_path):
    cfg = make_cfg(tmp_path)
    rows_ = [
        {"kind": "browser.chat.request", "app": "claude", "chars": 5, "row_id": "c" * 8},
        {"kind": "browser.chat.request", "app": "claude", "chars": 6, "row_id": "d" * 8},
        {"kind": "browser.chat.status", "app": "claude", "ok": False, "status": 500},
    ]
    cfg.ledger.write_text("".join(json.dumps(r) + "\n" for r in rows_))
    feed = Feed(cfg)
    feed.scan_initial()
    assert [it["status"] for it in feed.items] == ["failed", "answered"]


def test_a_late_reply_finds_its_own_message_by_send_id(tmp_path):
    """Send A in one tab, send B in another, then A's reply (with a web
    search) finishes: the tools belong to A, not to B, the newer one."""
    cfg = make_cfg(tmp_path)
    rows_ = [
        {"kind": "browser.chat.request", "app": "chatgpt", "chars": 5, "row_id": "e" * 8, "send_id": "send-aaaa"},
        {"kind": "browser.chat.request", "app": "chatgpt", "chars": 6, "row_id": "f" * 8, "send_id": "send-bbbb"},
        {"kind": "browser.chat.reply", "app": "chatgpt", "send_id": "send-aaaa", "tools": ["web.run"], "sources": 3},
    ]
    cfg.ledger.write_text("".join(json.dumps(r) + "\n" for r in rows_))
    feed = Feed(cfg)
    feed.scan_initial()
    b, a = feed.items[0], feed.items[1]
    assert (a["tools"], a["sources"]) == (["web.run"], 3)
    assert (b["tools"], b["sources"]) == ([], None)
    assert clean_browser_row({"kind": "browser.chat.reply", "send_id": "x y"}).get("send_id") is None


def _independent_checkpoint_check(cp: dict) -> bool:
    """Ed25519 over sha256(0x00 || JCS(checkpoint minus sig)), written without
    the runtime's helpers: the same rule Coriqo's device-receipt ingest applies."""
    import base64
    import hashlib
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    body = {k: v for k, v in cp.items() if k not in ("sig", "signature")}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8")
    digest = hashlib.sha256(b"\x00" + canon).digest()
    sig = base64.b64decode(cp["sig"].removeprefix("ed25519:"))
    key = Ed25519PublicKey.from_public_bytes(base64.b64decode(cp["public_key_b64"]))
    try:
        key.verify(sig, digest)
        return True
    except InvalidSignature:
        return False


def test_receipt_checkpoint_signature_verifies_from_receipt_alone(tmp_path):
    from byoai.recorder.keys import DeviceKey
    from byoai.recorder.merkle import checkpoint_leaf_hash

    chain = SealChain(make_cfg(tmp_path))
    s1 = chain.stamp({"interaction": "a", "ts": "14:00"})
    chain.stamp({"interaction": "b", "ts": "14:05"})
    cp = chain.receipt(s1)["merkle"]["checkpoint"]
    assert cp["kind"] == "byoai.shield.checkpoint.v1" and cp["ts"]
    assert cp == chain.checkpoint                     # byte-for-byte as signed

    def runtime_ok(c):
        body = {k: v for k, v in c.items() if k != "sig"}
        return DeviceKey.verify(c["public_key_b64"], checkpoint_leaf_hash(body), c["sig"])

    assert runtime_ok(cp) and _independent_checkpoint_check(cp)
    for field, value in (("kind", "byoai.shield.checkpoint.v0"),
                         ("ts", "2000-01-01T00:00:00Z")):
        bad = dict(cp, **{field: value})
        assert not runtime_ok(bad) and not _independent_checkpoint_check(bad)
    for field in ("kind", "ts"):
        bad = {k: v for k, v in cp.items() if k != field}
        assert not runtime_ok(bad) and not _independent_checkpoint_check(bad)
