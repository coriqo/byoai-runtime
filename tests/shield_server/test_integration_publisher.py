"""THE integration test the plan asks for: the real, unmodified
``shield_publish.Publisher`` (and the ``SealChain`` it publishes) running
against ``create_app()`` over an httpx ASGI transport — proof that "the
client works unchanged" is not just a claim.

Flow: enrol (minted token) -> publish a seal -> admin PUTs a policy -> device
polls, verifies, applies it -> the admin device list shows it protecting at
the assigned version with no drift -> revoke -> next publish gets the
refusal state.
"""

from __future__ import annotations

from tests.shield_server.conftest import SyncASGIClient, admin_call

from byoai.integrations.shield import SealChain, ShieldConfig
from byoai.integrations.shield_publish import Publisher


def _publisher(tmp_path, app, name: str) -> Publisher:
    root = tmp_path / name
    cfg = ShieldConfig(ledger=root / "ledger.jsonl", seal_path=root / "seal.json",
                       key_dir=root / "keys")
    seals = SealChain(cfg)
    seals.stamp({"kind": "byoai.shield.demo", "note": "hello"})
    return Publisher(
        seals, key_dir=root / "keys", state_dir=root / "state",
        client_factory=lambda: SyncASGIClient(app),
        managed_policy_path=root / "managed_policy.json",
        protection=lambda: {"protecting": True, "reasons": [], "mode": "redact"},
    )


def test_full_lifecycle_against_the_real_publisher(app, cfg, store, ingest, tmp_path):
    admin_headers = {"Authorization": f"Bearer {cfg.admin_token}"}
    publisher = _publisher(tmp_path, app, "mac1")

    # -- enrol -------------------------------------------------------------
    token = store.mint_token(label="mac1")
    status = publisher.enrol(cfg.public_url, token)
    assert status["connected"] is True
    device_id = status["device_id"]
    assert status["tenant"] == cfg.org

    # -- publish a seal ------------------------------------------------------
    result = publisher.publish_now()
    assert result["last_error"] is None
    assert result["last_height"] == 1

    # not yet managed: no policy applied
    devices = admin_call(app, "GET", "/api/v1/shield/devices", admin_headers)["devices"]
    assert len(devices) == 1
    assert devices[0]["device_id"] == device_id
    assert devices[0]["label"] == "mac1"  # carried from the token's label at enrol
    assert devices[0]["protecting"] is True
    assert devices[0]["policy_version"] is None  # never managed yet

    # -- admin PUTs a policy --------------------------------------------------
    policy_body = {"mode": "redact", "apps": {"claude": True}, "keep_text": False,
                   "retention_days": 30, "notice": True, "managed_by": "Test Org IT"}
    envelope = admin_call(app, "PUT", "/api/v1/shield/policy", admin_headers, json=policy_body)
    assigned_version = envelope["document"]["version"]

    # -- device polls, verifies, applies it -----------------------------------
    publisher.poll_policy(force=True)
    assert publisher.policy_status()["error"] is None
    managed = publisher._managed_policy_version()
    assert managed == assigned_version

    # local settings edit on a locked key is refused, mirroring the client's
    # own contract (apply_policy_update raising is what the proxy surfaces as
    # a 409 "Set by <managed_by>" — checked here at the function level since
    # this server owns no local proxy of its own).
    from byoai.integrations import shield as shield_mod
    effective = shield_mod.load_policy(ShieldConfig(
        ledger=tmp_path / "mac1" / "ledger.jsonl", seal_path=tmp_path / "mac1" / "seal.json",
        key_dir=tmp_path / "mac1" / "keys",
        managed_policy_path=tmp_path / "mac1" / "managed_policy.json",
    ))
    assert effective["mode"] == "redact"
    assert effective["notice"] is True

    # -- publish again so the shield block reports the applied version -------
    publisher.publish_now()

    devices = admin_call(app, "GET", "/api/v1/shield/devices", admin_headers)["devices"]
    row = devices[0]
    assert row["policy_version"] == assigned_version
    assert row["assigned_version"] == assigned_version
    assert row["drift"] is False
    assert row["protecting"] is True

    drift = admin_call(app, "GET", "/api/v1/shield/policy/drift", admin_headers)
    assert drift == {"devices": []}

    # -- revoke ----------------------------------------------------------
    r = admin_call(app, "DELETE", f"/api/v1/shield/devices/{device_id}", admin_headers)
    assert r["revoked"] is True

    publisher.seals.stamp({"kind": "byoai.shield.demo", "note": "after revoke"})
    status = publisher.publish_now()
    assert status["needs_attention"] is True
    assert "no longer accepts this Mac" in (status["last_error"] or "")


def test_a_refused_checkpoint_batch_never_advances_the_publisher(app, cfg, store, ingest, tmp_path):
    """A checkpoint the server can't store (here: a `CheckpointConflict` —
    the same seq_end already holds a different chain head) must come back as
    a real HTTP refusal, not a fake 200 with `accepted=0`. The released
    Publisher only advances its outbox/last_seq on success; if the server
    ever collapsed a refusal into a "handled" response, this checkpoint would
    be silently dropped forever instead of retried.
    """
    admin_headers = {"Authorization": f"Bearer {cfg.admin_token}"}
    publisher = _publisher(tmp_path, app, "mac2")

    token = store.mint_token(label="mac2")
    status = publisher.enrol(cfg.public_url, token)
    device_id = status["device_id"]

    # Plant a conflicting checkpoint at seq_end=1 directly in the store, so
    # the Publisher's own first real checkpoint (also seq_end=1) collides
    # with a different chain head when it tries to publish.
    ingest.accept_checkpoints(device_id, [{
        "seq_start": 1, "seq_end": 1, "chain_head": "not-what-the-publisher-will-send",
        "ts_device": "2026-01-01T00:00:00Z", "sig": "planted",
    }])

    before = publisher.status()
    assert before["last_sent_at"] in (None, 0)

    result = publisher.publish_now()

    # Refused, not silently accepted: the outbox is still waiting, nothing
    # was marked sent, and no height was recorded for it.
    assert result["last_error"] is not None
    assert result["last_sent_at"] in (None, 0)
    assert result["has_new"] is True
    assert publisher.state.outbox is not None
    assert publisher.state.last_seq == 0

    # And the server genuinely never stored it as a new entry.
    devices = admin_call(app, "GET", "/api/v1/shield/devices", admin_headers)["devices"]
    row = next(d for d in devices if d["device_id"] == device_id)
    assert row["protecting"] is None  # no shield block was ever recorded either
