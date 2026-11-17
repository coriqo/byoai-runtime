"""Policy: monotonic versions, override-delete re-issue, signed null,
validation 400, unknown device 404."""

from __future__ import annotations

import threading

import pytest

from byoai.shield_server import policy as policy_mod


def _write_default(store, signer, org, **overrides):
    body = {"mode": "redact", "apps": {"claude": True}, "keep_text": False,
            "retention_days": 30, "notice": True}
    body.update(overrides)
    return policy_mod.write_policy(store, signer, device_id=None, org=org,
                                   policy=body, managed_by="Test Org", locked=None)


def test_versions_are_monotonic_across_default_and_override(store, signer, cfg):
    r1 = _write_default(store, signer, cfg.org)
    r2 = policy_mod.write_policy(store, signer, device_id="dev_a", org=cfg.org,
                                 policy={"mode": "block", "apps": {"claude": True},
                                        "keep_text": False, "retention_days": 7,
                                        "notice": True},
                                 managed_by="Test Org", locked=None)
    r3 = _write_default(store, signer, cfg.org, mode="observe")
    assert r1.version < r2.version < r3.version


def test_override_delete_reissues_default_above_it(store, signer, cfg):
    default_row = _write_default(store, signer, cfg.org)
    override_row = policy_mod.write_policy(
        store, signer, device_id="dev_a", org=cfg.org,
        policy={"mode": "block", "apps": {"claude": True}, "keep_text": False,
               "retention_days": 7, "notice": True},
        managed_by="Test Org", locked=None,
    )
    assert override_row.version > default_row.version
    released = policy_mod.release_device_override(store, signer, device_id="dev_a", org=cfg.org)
    # Re-issued default, strictly above the override it retires — a device
    # holding the override's version must never see this as a rollback.
    assert released.version > override_row.version
    assert released.document["policy"] == default_row.document["policy"]
    assert released.device_id is None


def test_override_delete_with_no_default_signs_null(store, signer, cfg):
    policy_mod.write_policy(
        store, signer, device_id="dev_a", org=cfg.org,
        policy={"mode": "block", "apps": {"claude": True}, "keep_text": False,
               "retention_days": 7, "notice": True},
        managed_by="Test Org", locked=None,
    )
    released = policy_mod.release_device_override(store, signer, device_id="dev_a", org=cfg.org)
    assert released.document["policy"] is None
    assert released.device_id == "dev_a"


def test_default_delete_signs_null(store, signer, cfg):
    _write_default(store, signer, cfg.org)
    tombstone = policy_mod.write_policy(store, signer, device_id=None, org=cfg.org,
                                        policy=None, managed_by="", locked=None)
    assert tombstone.document["policy"] is None
    row = policy_mod.resolve_effective(store, device_id="dev_never_had_override")
    assert row is not None
    assert row.document["policy"] is None


def test_resolve_effective_prefers_override_over_default(store, signer, cfg):
    _write_default(store, signer, cfg.org, mode="observe")
    policy_mod.write_policy(
        store, signer, device_id="dev_a", org=cfg.org,
        policy={"mode": "block", "apps": {"claude": True}, "keep_text": False,
               "retention_days": 7, "notice": True},
        managed_by="Override Org", locked=None,
    )
    row = policy_mod.resolve_effective(store, device_id="dev_a")
    assert row.document["policy"]["mode"] == "block"
    other = policy_mod.resolve_effective(store, device_id="dev_b")
    assert other.document["policy"]["mode"] == "observe"


@pytest.mark.parametrize("bad_field,bad_value", [
    ("mode", "delete_everything"),
    ("retention_days", 14),
    ("keep_text", "yes"),
    ("notice", 1),
    ("apps", "claude"),
])
def test_validation_refuses_bad_fields(bad_field, bad_value, store, signer, cfg):
    body = {"mode": "redact", "apps": {"claude": True}, "keep_text": False,
            "retention_days": 30, "notice": True}
    body[bad_field] = bad_value
    with pytest.raises(policy_mod.PolicyValidationError):
        policy_mod.write_policy(store, signer, device_id=None, org=cfg.org,
                                policy=body, managed_by="Test Org", locked=None)


def test_concurrent_writes_never_collide_on_the_same_version(store, signer, cfg):
    """next_version() -> build -> sign -> insert used to be three separate
    critical sections (read the lock, release it, then take it again for the
    insert), so two threads could both read the same "next" version and race
    to insert it — the loser hit the unique index as an uncaught
    UnknownVersionRace/500. write_policy now holds one lock across the whole
    thing via ServerStore.write_policy_locked."""
    n = 25
    barrier = threading.Barrier(n)
    results: list[object] = [None] * n
    errors: list[BaseException] = []

    def worker(i: int) -> None:
        barrier.wait()  # maximise the chance of an actual race, not a queue
        try:
            results[i] = _write_default(store, signer, cfg.org, mode="redact")
        except BaseException as exc:  # noqa: BLE001 - a race surfacing as an
            # exception here IS the bug fix 5 exists to close; capture it
            # rather than letting pytest report a bare thread crash.
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"concurrent policy writes raised: {errors!r}"
    versions = sorted(r.version for r in results)
    assert versions == list(range(1, n + 1)), "every write must land a distinct, contiguous version"


def test_signature_verifies_and_rollback_is_structural(store, signer, cfg):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from byoai.recorder.canonical import canonicalize

    row = _write_default(store, signer, cfg.org)
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(signer.public_key_hex))
    pub.verify(bytes.fromhex(row.signature), canonicalize(row.document))  # no raise = valid

    row2 = _write_default(store, signer, cfg.org, mode="observe")
    assert row2.version == row.version + 1
    # "Rollback" isn't a runtime check here — it's structural: resolve always
    # returns the highest-version row, so there is no way to get row's older
    # content back out for this key without inserting a still-higher version.
    assert policy_mod.resolve_effective(store, device_id="anyone").version == row2.version
