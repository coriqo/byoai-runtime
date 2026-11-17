"""Shield Sync event builder: the allowlist is the privacy guarantee."""
import json

import pytest

from byoai.integrations import shield
from byoai.integrations.shield_sync import (
    EVENT_FIELDS,
    aggregate_daily,
    build_event,
    level_words,
    sync_level,
)

SECRET = "4111 1111 1111 1111"
DEV = "dev_abc123"


def item(**over):
    base = {
        "id": "b3f1c0ffee", "source": "desktop", "surface": "Claude · desktop",
        "ts": "10:02:11", "date": "2026-09-26", "status": "answered",
        "tool": None, "identity": {},
        "flags": [{"tier": "pii", "rule": "cards"}],
        "seal": "a1b2c3d4e5f60718", "usage": {}, "latency_ms": None,
        "verdict": "redacted(1)", "chars": 184, "redactions": ["cards"],
        "reply": None,
    }
    base.update(over)
    return base


def test_event_has_exactly_the_allowlisted_fields():
    ev = build_event(item(), device_id=DEV)
    assert tuple(ev) == EVENT_FIELDS
    assert ev["app"] == "claude" and ev["kind"] == "message"
    assert ev["verdict"] == "redacted" and ev["redactions"] == 1
    assert ev["flags"] == [{"tier": "pii", "rule": "cards"}]


def test_no_text_field_survives_even_when_stuffed_into_the_item():
    """Invariant 1: every text-bearing key Shield knows, planted on the item."""
    stuffed = item(**{f: SECRET for f in shield.TEXT_FIELDS},
                   verb=f"Message: {SECRET}", text_hmac="deadbeef" * 8,
                   text_redacted=SECRET, _seal_payload={"x": SECRET},
                   identity={"client_name": SECRET},
                   flags=[{"tier": "pii", "rule": "cards", "match": SECRET,
                           "text": SECRET}])
    ev = build_event(stuffed, device_id=DEV)
    blob = json.dumps(ev)
    assert SECRET not in blob and "deadbeef" not in blob
    assert set(ev) == set(EVENT_FIELDS)
    assert set(ev["flags"][0]) == {"tier", "rule"}


def test_matched_text_from_flags_for_never_leaves():
    """Invariant 3: flags_for's third element is the matched snippet."""
    flags = shield.flags_for("write to ana.private@contoso.example today")
    assert any("ana.private" in m for _, _, m in flags)  # exists on the device
    feed_flags = [{"tier": t, "rule": r, "match": m} for t, r, m in flags]
    ev = build_event(item(flags=feed_flags), device_id=DEV)
    assert "ana.private" not in json.dumps(ev)


@pytest.mark.parametrize("over", [
    {"seal": ""},                    # running tool call: not sealed yet
    {"seal": "not hex!"},
    {"id": None},
    {"source": "telepathy"},
    {"date": "yesterday"},
])
def test_unsyncable_items_are_skipped(over):
    assert build_event(item(**over), device_id=DEV) is None


def test_bad_device_id_is_refused():
    assert build_event(item(), device_id="") is None
    assert build_event(item(), device_id="dev with spaces") is None


def test_mcp_names_are_charset_and_length_checked():
    ok = build_event(item(source="mcp", surface="Cursor", tool="search_files"),
                     device_id=DEV)
    assert ok["app"] == "Cursor" and ok["kind"] == "tool_call"
    assert ok["tool"] == "search_files"
    bad = build_event(item(source="mcp", surface="ok<script>" + "x" * 40,
                           tool="rm -rf /; " + SECRET), device_id=DEV)
    assert bad["app"] == "other" and bad["tool"] is None


def test_message_events_carry_no_tool():
    assert build_event(item(tool="search_files"), device_id=DEV)["tool"] is None


def test_chars_must_be_a_sane_integer():
    for bad in (True, -1, "184", 10**9, None):
        assert build_event(item(chars=bad), device_id=DEV)["chars"] is None


def test_unknown_rule_ids_are_dropped():
    ev = build_event(item(flags=[{"tier": "pii", "rule": "cards"},
                                 {"tier": "pii", "rule": SECRET},
                                 {"tier": "made_up", "rule": "emails"},
                                 "junk"]), device_id=DEV)
    assert ev["flags"] == [{"tier": "pii", "rule": "cards"}]


@pytest.mark.parametrize("over,expect", [
    ({"status": "blocked", "verdict": "blocked"}, "blocked"),
    ({"verdict": "redacted(2)"}, "redacted"),
    ({"verdict": "redact", "redactions": []}, "allowed"),
    ({"verdict": "observe", "redactions": []}, "observed"),
    ({"source": "browser", "surface": "ChatGPT · browser", "verdict": None,
      "redactions": []}, "observed"),
])
def test_verdicts(over, expect):
    assert build_event(item(**over), device_id=DEV)["verdict"] == expect


def test_person_id_is_validated():
    assert build_event(item(), device_id=DEV, person_id="per_1")["person_id"] == "per_1"
    assert build_event(item(), device_id=DEV, person_id="Ana <ana@x>")["person_id"] is None


def test_daily_totals_are_aggregated_on_device():
    evs = [build_event(item(id=f"row{i:04d}xx", verdict=v, redactions=r,
                            flags=f), device_id=DEV)
           for i, (v, r, f) in enumerate([
               ("redacted(1)", ["cards"], [{"tier": "pii", "rule": "cards"}]),
               ("redact", [], []),
               ("blocked", [], [{"tier": "high", "rule": "aws_key"}]),
           ])]
    evs[2]["app"] = "chatgpt"
    rows = aggregate_daily(evs)
    assert rows == [
        {"date": "2026-09-26", "app": "chatgpt", "messages": 1,
         "flags": {"high:aws_key": 1}, "redacted": 0, "blocked": 1},
        {"date": "2026-09-26", "app": "claude", "messages": 2,
         "flags": {"pii:cards": 1}, "redacted": 1, "blocked": 0},
    ]


def test_sync_level_defaults_to_seal_and_ignores_garbage():
    assert sync_level({}) == "seal"
    assert sync_level({"sync": "everything"}) == "seal"
    assert sync_level({"sync": "daily"}) == "daily"
    assert sync_level(shield.default_policy()) == "seal"


def test_level_words_name_the_organisation():
    assert "Contoso IT" in level_words("events", "Contoso IT")
    assert "Never what you wrote" in level_words("events", "Contoso IT")


def test_managed_policy_validates_sync_and_can_lock_it():
    assert "sync" in shield.MANAGED_LOCKABLE_KEYS
    shield._validate_managed_policy({"sync": "daily"})
    with pytest.raises(ValueError, match="sync"):
        shield._validate_managed_policy({"sync": "full_text"})


def test_feed_items_are_local_time_for_every_source(monkeypatch):
    """The feed shows browser rows (stamped in UTC by the extension) in this
    Mac's local time like every other row, so every item converts the same
    way. Reading a browser item as UTC would shift it by the offset again."""
    import time
    monkeypatch.setenv("TZ", "America/New_York")
    time.tzset()
    try:
        b = build_event(item(source="browser", surface="ChatGPT · browser"), device_id=DEV)
        d = build_event(item(), device_id=DEV)
        assert b["occurred_at"] == d["occurred_at"] == "2026-09-26T14:02:11Z"   # EDT is UTC-4
        late = build_event(item(ts="23:30:00"), device_id=DEV)
        assert aggregate_daily([late])[0]["date"] == "2026-09-26"  # local day
    finally:
        monkeypatch.undo()
        time.tzset()
