"""Enrolment tokens: single-use, expiry, revoke, hash-only at rest."""

from __future__ import annotations

from byoai.shield_server.store import ServerStore, hash_token


def test_token_is_single_use(tmp_path):
    store = ServerStore(tmp_path / "s.db")
    token = store.mint_token(label="mac1")
    ok, reason, _label = store.redeem_token(token, device_id="dev_a")
    assert ok and reason == ""
    ok2, reason2, _label2 = store.redeem_token(token, device_id="dev_b")
    assert not ok2 and reason2 == "used"


def test_unknown_token_is_invalid(tmp_path):
    store = ServerStore(tmp_path / "s.db")
    ok, reason, _label = store.redeem_token("shieldtok_bogus", device_id="dev_a")
    assert not ok and reason == "invalid"


def test_expired_token_is_refused(tmp_path):
    store = ServerStore(tmp_path / "s.db")
    token = store.mint_token(ttl_seconds=-1)  # already in the past
    ok, reason, _label = store.redeem_token(token, device_id="dev_a")
    assert not ok and reason == "expired"


def test_revoked_token_is_refused(tmp_path):
    store = ServerStore(tmp_path / "s.db")
    token = store.mint_token()
    rows = store.list_tokens()
    assert store.revoke_token(rows[0].token_hash)
    ok, reason, _label = store.redeem_token(token, device_id="dev_a")
    assert not ok and reason == "revoked"


def test_revoking_twice_is_a_no_op(tmp_path):
    store = ServerStore(tmp_path / "s.db")
    token = store.mint_token()
    token_hash = hash_token(token)
    assert store.revoke_token(token_hash)
    assert not store.revoke_token(token_hash)


def test_tokens_are_hash_only_at_rest(tmp_path):
    store = ServerStore(tmp_path / "s.db")
    token = store.mint_token()
    store._conn.execute("PRAGMA wal_checkpoint(FULL)")  # flush WAL into the main file
    with open(tmp_path / "s.db", "rb") as fh:
        raw = fh.read()
    assert token.encode() not in raw
    assert hash_token(token).encode() in raw


def test_list_tokens_reports_status(tmp_path):
    store = ServerStore(tmp_path / "s.db")
    store.mint_token(label="active")
    used = store.mint_token(label="used")
    store.redeem_token(used, device_id="dev_x")
    rows = {r.label: r for r in store.list_tokens()}
    assert rows["active"].status == "active"
    assert rows["used"].status == "used"
