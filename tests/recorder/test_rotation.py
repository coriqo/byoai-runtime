"""Tests for device key rotation and revocation (``docs/seal-format.md`` §7).

Uses the real :class:`Ledger` and :func:`rotate_key` — unlike
``test_verify.py``, this module exercises the writer, not just the
verifier, so a hand-built sqlite fixture would just be redundant.
"""

from __future__ import annotations

import base64
import os

import pytest

from byoai.recorder.canonical import canonicalize
from byoai.recorder.keys import (
    PRIVATE_KEY_FILENAME,
    PUBLIC_KEY_FILENAME,
    load_or_create_device_key,
)
from byoai.recorder.ledger import Ledger
from byoai.recorder.rotation import rotate_key
from byoai.recorder.schema import (
    EVENT_SCHEMA_VERSION,
    AgentEvent,
    EventKind,
    new_event_id,
    new_span_id,
    new_trace_id,
    now_monotonic_ns,
)
from byoai.recorder.verify import verify_ledger

from .conftest import make_event


def _make_ledger(tmp_path, name="ledger.db"):
    key_dir = tmp_path / "keys"
    old_key = load_or_create_device_key(key_dir)
    ledger = Ledger(tmp_path / name, device_id=old_key.device_id)
    return key_dir, old_key, ledger


def _append_event(ledger: Ledger, device_id: str, kind: str, session_id: str = "ses_1") -> None:
    """Delegates to conftest.make_event() rather than hand-building an
    AgentEvent, so this file automatically picks up new/changed fields on
    the shared factory instead of needing a manual follow-up edit each time
    (see the trace_id/span_id migration, which required exactly that)."""
    event = make_event(
        device_id,
        session_id=session_id,
        kind=EventKind(kind),
        tool_name=None,
        payload={"n": 1},
    )
    ledger.append(event)


def test_rotate_key_produces_a_different_key_on_disk(tmp_path):
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        old_priv_bytes = (key_dir / PRIVATE_KEY_FILENAME).read_bytes()
        old_pub_text = (key_dir / PUBLIC_KEY_FILENAME).read_text()

        new_key = rotate_key(key_dir, ledger, reason="rotation")

        assert new_key.device_id != old_key.device_id
        assert new_key.public_key_b64 != old_key.public_key_b64

        new_priv_bytes = (key_dir / PRIVATE_KEY_FILENAME).read_bytes()
        new_pub_text = (key_dir / PUBLIC_KEY_FILENAME).read_text()
        assert new_priv_bytes != old_priv_bytes
        assert new_pub_text.strip() != old_pub_text.strip()

        # Loading from key_dir now yields the new key, not the old one.
        reloaded = load_or_create_device_key(key_dir)
        assert reloaded.device_id == new_key.device_id
    finally:
        ledger.close()


def test_rotate_key_leaves_old_key_intact_when_ledger_append_fails(tmp_path):
    """Regression test: if ledger.append() fails after the new key is
    generated, the old key must remain on disk and loadable, and no
    KEY_ROTATED event must exist — this is what makes the failure
    recoverable (retry rotation) instead of unreconcilable (old key gone,
    no ledger record of why the device_id changed)."""
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    old_priv_bytes = (key_dir / PRIVATE_KEY_FILENAME).read_bytes()
    old_pub_text = (key_dir / PUBLIC_KEY_FILENAME).read_text()

    ledger.append = lambda event: None  # simulate a full-disk / I/O failure

    try:
        with pytest.raises(RuntimeError, match="staged but NOT promoted"):
            rotate_key(key_dir, ledger, reason="rotation")
    finally:
        ledger.close()

    # The old key files are untouched.
    assert (key_dir / PRIVATE_KEY_FILENAME).read_bytes() == old_priv_bytes
    assert (key_dir / PUBLIC_KEY_FILENAME).read_text() == old_pub_text

    # The old key is still loadable and yields the same device identity.
    reloaded = load_or_create_device_key(key_dir)
    assert reloaded.device_id == old_key.device_id

    # No archived/promoted key files were created — promotion never ran.
    assert not (key_dir / f".rotated-{old_key.device_id}.{PRIVATE_KEY_FILENAME}").exists()
    assert not (key_dir / f".rotated-{old_key.device_id}.{PUBLIC_KEY_FILENAME}").exists()

    # The staged new key is left behind in the pending directory (it will
    # simply be overwritten on a retried rotation).
    pending_dir = key_dir / ".pending-rotation"
    assert (pending_dir / PRIVATE_KEY_FILENAME).exists()
    assert (pending_dir / PUBLIC_KEY_FILENAME).exists()

    # No KEY_ROTATED event was recorded in the ledger.
    report = verify_ledger(tmp_path / "ledger.db")
    assert report.key_rotations == []


def test_promotion_crash_never_falls_back_to_a_random_key(tmp_path, monkeypatch):
    """Regression test for the confirmed bug in the previous version of
    ``_promote_staged_key``: it used two SEPARATE ``os.replace`` calls
    (archive-old, then promote-new), leaving a window with no live private
    key file at all if the process crashed in between. The next
    ``load_or_create_device_key`` call would then see "no key" and silently
    generate a brand-new, never-cross-signed random identity — even though
    the KEY_ROTATED event for the *staged* key was already durably
    committed to the ledger.

    This simulates a crash at every plausible point during/after promotion
    by interrupting ``os.replace`` inside ``byoai.recorder.keys`` after 0, 1,
    and 2 calls, and asserts that in every case the NEXT
    ``load_or_create_device_key`` call — modeling the next process
    startup — deterministically recovers the correct (new, staged) device
    identity rather than ever minting a fresh random one.
    """
    import byoai.recorder.keys as keys_module

    real_replace = os.replace

    # Crash points, counted only among os.replace calls that happen *after*
    # the ledger append has already succeeded (i.e. during
    # _mark_promotion_confirmed / _finish_pending_rotation — the promotion
    # phase itself, which is what the buggy version raced):
    #   0 -> marker write itself fails: promotion never gets confirmed, so
    #        recovery must land back on the OLD key (safe, not random —
    #        rotation simply needs retrying).
    #   1 -> marker written (confirmed) but the public-key replace fails:
    #        recovery must finish promotion and land on the NEW key.
    #   2 -> marker + public replace done, private-key replace fails: same,
    #        recovery must finish promotion and land on the NEW key. This is
    #        exactly the historically buggy window (no live private key
    #        immediately after this replace is interrupted).
    for crash_after_n_replaces in (0, 1, 2):
        key_dir, old_key, ledger = _make_ledger(
            tmp_path, name=f"ledger-{crash_after_n_replaces}.db"
        )

        state = {"append_done": False, "n": 0}
        real_append = ledger.append

        def wrapped_append(event, _real=real_append, _state=state):
            entry = _real(event)
            _state["append_done"] = True
            return entry

        monkeypatch.setattr(ledger, "append", wrapped_append)

        def flaky_replace(src, dst, _n=crash_after_n_replaces, _state=state):
            if _state["append_done"]:
                if _state["n"] >= _n:
                    raise OSError("simulated crash mid os.replace")
                _state["n"] += 1
            return real_replace(src, dst)

        monkeypatch.setattr(keys_module.os, "replace", flaky_replace)
        try:
            with pytest.raises(OSError, match="simulated crash"):
                rotate_key(key_dir, ledger, reason="rotation")
        finally:
            ledger.close()
            monkeypatch.setattr(keys_module.os, "replace", real_replace)

        # The KEY_ROTATED event is committed either way (append happened
        # before any of these simulated crash points); read the new
        # device_id it recorded so we know what a *correct* recovery to the
        # new key looks like.
        report = verify_ledger(tmp_path / f"ledger-{crash_after_n_replaces}.db")
        expected_new_device_id = report.key_rotations[0]["new_device_id"]

        # Simulate the next process startup.
        recovered = load_or_create_device_key(key_dir)

        # Above all: never a third, freshly-generated random identity that
        # matches neither the old nor the new expected device_id. That was
        # the original bug.
        assert recovered.device_id in (old_key.device_id, expected_new_device_id), (
            f"crash after {crash_after_n_replaces} promotion-phase os.replace call(s): "
            f"recovered a device_id ({recovered.device_id!r}) that is neither the old "
            f"({old_key.device_id!r}) nor the new staged key ({expected_new_device_id!r}) — "
            "this means load_or_create_device_key fell back to generating a fresh, "
            "never-cross-signed random key instead of recovering deterministically"
        )

        if crash_after_n_replaces == 0:
            # Promotion was never confirmed (marker write itself failed):
            # staying on the old key is the safe, expected outcome.
            assert recovered.device_id == old_key.device_id
        else:
            # Promotion was confirmed before the crash: it must always be
            # finished on next load, landing on the new key.
            assert recovered.device_id == expected_new_device_id

        # A second load must be stable (idempotent reconciliation, no
        # further identity churn either way).
        assert load_or_create_device_key(key_dir).device_id == recovered.device_id


def test_key_rotated_event_has_verifiable_cross_signature(tmp_path):
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        new_key = rotate_key(key_dir, ledger, reason="rotation")
    finally:
        ledger.close()

    report = verify_ledger(
        tmp_path / "ledger.db",
        device_public_keys={old_key.device_id: old_key.public_key_b64},
    )
    assert len(report.key_rotations) == 1
    rotation = report.key_rotations[0]
    assert rotation["old_device_id"] == old_key.device_id
    assert rotation["new_device_id"] == new_key.device_id
    assert rotation["cross_signature_verified"] is True
    assert report.ok is True


def test_entries_after_rotation_use_the_new_key(tmp_path):
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        _append_event(ledger, old_key.device_id, EventKind.MESSAGE.value)
        new_key = rotate_key(key_dir, ledger, reason="rotation")
        # Ledger object itself doesn't auto-switch device_id; a real Recorder
        # would reopen/reassign, but appends after rotation should be made
        # under the new identity.
        ledger.device_id = new_key.device_id
        _append_event(ledger, new_key.device_id, EventKind.MESSAGE.value)
    finally:
        ledger.close()

    report = verify_ledger(
        tmp_path / "ledger.db",
        device_public_keys={old_key.device_id: old_key.public_key_b64},
    )
    assert old_key.device_id in report.device_ids
    assert new_key.device_id in report.device_ids
    assert report.ok is True
    assert report.stale_key_usage == []


def test_verify_ledger_does_not_flag_rotation_boundary_as_broken_chain(tmp_path):
    """The whole point of cross-signing: a device_id change right after
    KEY_ROTATED must never be reported as chain tampering."""
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        _append_event(ledger, old_key.device_id, EventKind.SESSION_START.value)
        new_key = rotate_key(key_dir, ledger, reason="rotation")
        ledger.device_id = new_key.device_id
        _append_event(ledger, new_key.device_id, EventKind.MESSAGE.value)
        _append_event(ledger, new_key.device_id, EventKind.MESSAGE.value)
    finally:
        ledger.close()

    report = verify_ledger(
        tmp_path / "ledger.db",
        device_public_keys={old_key.device_id: old_key.public_key_b64},
    )
    assert report.broken_links == []
    assert report.gaps == []
    assert report.stale_key_usage == []
    assert report.ok is True


def test_stale_key_usage_detected_even_with_backdated_ts_device(tmp_path):
    """A compromised pre-rotation key can keep forging entries under the old
    device_id after rotation. If it backdates ts_device to before the
    rotation's effective_epoch, a check gated on ts_device would miss it —
    ts_device is a device-controlled, untrusted wall-clock string (see
    schema.now_ts_device()'s docstring). Detection must instead be based on
    seq, which the ledger assigns at write time in strict append order and
    the forging device cannot control."""
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        _append_event(ledger, old_key.device_id, EventKind.SESSION_START.value)
        rotate_key(key_dir, ledger, reason="compromise")

        # Forged entry: still signed/attributed to the retired old device_id,
        # but with ts_device deliberately backdated to well before the
        # rotation event's effective_epoch, simulating an attacker who
        # controls the device clock trying to evade a ts_device-based check.
        forged_event = AgentEvent(
            schema_version=EVENT_SCHEMA_VERSION,
            event_id=new_event_id(),
            device_id=old_key.device_id,
            session_id="ses_1",
            seq=0,
            kind=EventKind.MESSAGE.value,
            ts_device="2000-01-01T00:00:00Z",
            ts_monotonic_ns=now_monotonic_ns(),
            tool_use_id=None,
            tool_name=None,
            payload={"n": 1},
            payload_hash="sha256:" + "00" * 32,
            model=None,
            provider="anthropic",
            trace_id=new_trace_id(),
            span_id=new_span_id(),
            parent_span_id=None,
            continues_from=None,
        )
        forged_entry = ledger.append(forged_event)
    finally:
        ledger.close()

    report = verify_ledger(
        tmp_path / "ledger.db",
        device_public_keys={old_key.device_id: old_key.public_key_b64},
    )
    assert forged_entry is not None
    assert report.stale_key_usage == [forged_entry.seq]
    assert report.ok is False


def test_verify_ledger_flags_forged_cross_signature(tmp_path):
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        rotate_key(key_dir, ledger, reason="rotation")
    finally:
        ledger.close()

    # Tamper the cross_signature stored in the ledger row directly.
    import json
    import sqlite3

    conn = sqlite3.connect(tmp_path / "ledger.db")
    row = conn.execute(
        "SELECT seq, payload FROM agent_events WHERE kind = ?", (EventKind.KEY_ROTATED.value,)
    ).fetchone()
    seq, payload_json = row
    payload = json.loads(payload_json)
    payload["cross_signature"] = "ed25519:" + base64.b64encode(b"\x00" * 64).decode()
    conn.execute(
        "UPDATE agent_events SET payload = ? WHERE seq = ?", (json.dumps(payload), seq)
    )
    conn.commit()
    conn.close()

    report = verify_ledger(
        tmp_path / "ledger.db",
        device_public_keys={old_key.device_id: old_key.public_key_b64},
    )
    # payload_hash / entry_hash no longer match the tampered payload, so this
    # is caught as a broken link (tamper-evidence) *and* the cross-signature
    # itself must not verify.
    assert report.ok is False
    rotation = report.key_rotations[0]
    assert rotation["cross_signature_verified"] is False


def test_verify_ledger_flags_forged_new_public_key_without_breaking_chain_detection(tmp_path):
    """A forged new_public_key alone (chain hash consistent because we also
    patch payload_hash/entry_hash to match) must still fail cross-sig check."""
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        rotate_key(key_dir, ledger, reason="rotation")
    finally:
        ledger.close()

    bogus_pub = base64.b64encode(b"\x01" * 32).decode()

    import json
    import sqlite3

    from byoai.recorder.canonical import sha256_hex

    conn = sqlite3.connect(tmp_path / "ledger.db")
    row = conn.execute(
        "SELECT seq, payload FROM agent_events WHERE kind = ?", (EventKind.KEY_ROTATED.value,)
    ).fetchone()
    seq, payload_json = row
    payload = json.loads(payload_json)
    payload["new_public_key"] = bogus_pub
    new_payload_hash = sha256_hex(canonicalize(payload))
    conn.execute(
        "UPDATE agent_events SET payload = ?, payload_hash = ? WHERE seq = ?",
        (json.dumps(payload), new_payload_hash, seq),
    )
    conn.commit()
    conn.close()

    report = verify_ledger(
        tmp_path / "ledger.db",
        device_public_keys={old_key.device_id: old_key.public_key_b64},
    )
    rotation = report.key_rotations[0]
    assert rotation["cross_signature_verified"] is False
    assert report.ok is False


def test_revocation_reason_and_effective_epoch_recorded(tmp_path):
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        new_key = rotate_key(key_dir, ledger, reason="revocation")
    finally:
        ledger.close()

    report = verify_ledger(
        tmp_path / "ledger.db",
        device_public_keys={old_key.device_id: old_key.public_key_b64},
    )
    rotation = report.key_rotations[0]
    assert rotation["reason"] == "revocation"
    assert rotation["effective_epoch"]
    assert rotation["new_device_id"] == new_key.device_id


def test_rotate_key_rejects_unknown_reason(tmp_path):
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        with pytest.raises(ValueError):
            rotate_key(key_dir, ledger, reason="not_a_real_reason")
    finally:
        ledger.close()


def test_rotation_without_pubkey_is_unchecked_not_failed(tmp_path):
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        rotate_key(key_dir, ledger, reason="rotation")
    finally:
        ledger.close()

    report = verify_ledger(tmp_path / "ledger.db")
    rotation = report.key_rotations[0]
    assert rotation["cross_signature_verified"] is None
    assert report.ok is True
    assert any("NOT checked" in note for note in report.notes)


def test_rotate_cli(tmp_path, capsys):
    from byoai.recorder.rotation import rotate_cli

    key_dir = tmp_path / "keys"
    old_key = load_or_create_device_key(key_dir)
    ledger_path = tmp_path / "device.db"
    ledger = Ledger(ledger_path, device_id=old_key.device_id)
    ledger.close()

    rc = rotate_cli(
        ["--key-dir", str(key_dir), "--ledger", str(ledger_path), "--reason", "compromise"]
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert old_key.device_id in out
    assert "->" in out

    new_key = load_or_create_device_key(key_dir)
    assert new_key.device_id != old_key.device_id

    report = verify_ledger(
        ledger_path, device_public_keys={old_key.device_id: old_key.public_key_b64}
    )
    assert report.key_rotations[0]["reason"] == "compromise"
    assert report.key_rotations[0]["cross_signature_verified"] is True


def _emit_checkpoint(ledger, key, seq_start, seq_end, ts="2026-08-10T12:00:00.000000Z"):
    from byoai.recorder.checkpoint import checkpoint_signing_bytes

    cp = {
        "device_id": key.device_id,
        "seq_start": seq_start,
        "seq_end": seq_end,
        "chain_head": ledger.head,
        "ts_device": ts,
    }
    cp["sig"] = key.sign(checkpoint_signing_bytes(cp))
    ledger.append_checkpoint(cp)
    return cp


def test_verify_ledger_checks_checkpoints_across_key_rotation(tmp_path):
    """Regression test for ``docs/seal-format.md`` §11.2: level 2 used to check every
    checkpoint against a single pinned key, which cannot pass once a
    checkpoint after the rotation is signed with the new key. verify_ledger
    must build a key timeline from the chain walk instead, so checkpoints on
    both sides of a (cross-signature-verified) rotation verify in one run."""
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        _append_event(ledger, old_key.device_id, "message")
        _append_event(ledger, old_key.device_id, "message")
        _emit_checkpoint(ledger, old_key, 1, 2)

        new_key = rotate_key(key_dir, ledger, reason="rotation")
        rotation_seq = ledger.next_seq - 1  # the KEY_ROTATED event just appended

        _append_event(ledger, new_key.device_id, "message")
        _append_event(ledger, new_key.device_id, "message")
        last_seq = ledger.next_seq - 1
        _emit_checkpoint(ledger, new_key, rotation_seq + 1, last_seq)

        report = verify_ledger(
            ledger.path,
            public_key_b64=old_key.public_key_b64,
            device_public_keys={old_key.device_id: old_key.public_key_b64},
        )
        assert report.ok, report.notes
        assert report.checkpoints_checked == 2
        assert report.bad_signatures == []
        assert report.key_rotations[0]["cross_signature_verified"] is True
    finally:
        ledger.close()


def test_verify_ledger_reports_forged_new_device_id_in_rotation(tmp_path):
    """The live rotation-timeline walk's other check: new_device_id must actually be
    derive_device_id(new_public_key), not merely whatever string the
    payload claims. A mismatch is a note, not a hard failure by itself —
    but it must be visible."""
    key_dir, old_key, ledger = _make_ledger(tmp_path)
    try:
        _append_event(ledger, old_key.device_id, "message")
        rotate_key(key_dir, ledger, reason="rotation")

        # Tamper the already-written KEY_ROTATED event's new_device_id
        # directly in the DB, bypassing the writer entirely (this must never
        # be reachable via rotate_key() itself — only a hand-edited/forged
        # ledger row exercises it).
        import json
        import sqlite3

        conn = sqlite3.connect(str(ledger.path))
        row = conn.execute(
            "SELECT seq, payload FROM agent_events WHERE kind = 'key_rotated'"
        ).fetchone()
        seq, payload_text = row
        payload = json.loads(payload_text)
        payload["new_device_id"] = "dev_NOT_THE_REAL_ONE"
        conn.execute(
            "UPDATE agent_events SET payload = ? WHERE seq = ?",
            (json.dumps(payload), seq),
        )
        conn.commit()
        conn.close()

        report = verify_ledger(ledger.path)
        assert report.key_rotations[0]["device_id_matches_public_key"] is False
        assert any("does not match" in n for n in report.notes)
    finally:
        ledger.close()


def test_verify_ledger_rejects_re_rotation_forged_by_a_retired_key(tmp_path):
    """Critical regression: a device that holds a RETIRED key (e.g. an
    attacker who compromised the pre-rotation key, or a stale sibling
    process) must not be able to take over the key timeline by forging a
    second ``key_rotated`` event, cross-signed correctly with that retired
    key and correctly labeled with its own (now-retired) device_id.

    Before the fix, ``_check_rotation`` looked the cross-signing key up in
    ``device_public_keys`` by whatever ``old_device_id`` the payload itself
    claimed — so a rotation "A -> C" signed by the retired key A verified
    just fine, even though the real timeline had already moved on to B.
    ``verify_ledger`` reported ``ok=True``. The fix builds the active
    key/id live during the chain walk (from ``public_key_b64``, the
    caller's pinned/starting key) and only accepts a rotation whose
    ``old_device_id`` matches the walk's own current ``active_id`` — a
    forged rotation from a retired key fails that check and is reported as
    forged, and does not advance the timeline.
    """
    import dataclasses

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from byoai.recorder.canonical import sha256_hex
    from byoai.recorder.keys import DeviceKey

    key_dir, key_a, ledger = _make_ledger(tmp_path)
    try:
        _append_event(ledger, key_a.device_id, "message")
        _emit_checkpoint(ledger, key_a, 1, 1)

        # Legitimate rotation: A -> B.
        key_b = rotate_key(key_dir, ledger, reason="rotation")
        _append_event(ledger, key_b.device_id, "message")
        _emit_checkpoint(ledger, key_b, 3, 3)

        # Attacker still holds retired key A and forges a second rotation,
        # A -> C, correctly cross-signed with A and correctly labeled.
        key_c = DeviceKey(Ed25519PrivateKey.generate())
        signed_fields = {
            "old_device_id": key_a.device_id,
            "new_device_id": key_c.device_id,
            "new_public_key": key_c.public_key_b64,
        }
        payload = {
            **signed_fields,
            "cross_signature": key_a.sign(canonicalize(signed_fields)),
            "reason": "rotation",
            "effective_epoch": "2026-01-01T00:00:00.000000Z",
        }
        forged_event = make_event(
            key_b.device_id,
            session_id="ses_1",
            kind=EventKind.KEY_ROTATED,
            tool_name=None,
            payload=payload,
        )
        forged_event = dataclasses.replace(
            forged_event, payload_hash=sha256_hex(canonicalize(payload))
        )
        ledger.append(forged_event)

        for _ in range(3):
            _append_event(ledger, key_c.device_id, "message")
        _emit_checkpoint(ledger, key_c, 5, ledger.next_seq - 1)

        report = verify_ledger(
            ledger.path,
            public_key_b64=key_a.public_key_b64,
            device_public_keys={key_a.device_id: key_a.public_key_b64},
        )

        assert report.ok is False
        # The forged rotation must not verify as a valid takeover of the
        # timeline: entries the attacker wrote under key_c's device_id are
        # attributed to a device that was never legitimately made active.
        assert report.stale_key_usage, report.notes
        # Two rotations share old_device_id == key_a.device_id (the real one
        # and the forged one); find the one claiming key_c as new.
        forged = next(
            r for r in report.key_rotations if r["new_device_id"] == key_c.device_id
        )
        assert forged["valid"] is False
        assert any("REJECTED" in n or "forged" in n.lower() for n in report.notes)
    finally:
        ledger.close()


def test_pinned_key_must_be_the_key_active_at_seq_1_not_the_current_key(tmp_path):
    """``docs/seal-format.md`` §7 / CLI --pubkey and pinned_device_public_key_b64: the
    pinned key is the STARTING key the caller trusts — the key active at
    the very first entry (seq 1) — never the device's current key after a
    rotation the caller doesn't yet know about. Pinning A (the first key,
    who legitimately rotates to B) must verify cleanly; pinning B (the
    current key) must fail with a finding that says why, not silently
    behave as if the whole chain had always belonged to B."""
    key_dir, key_a, ledger = _make_ledger(tmp_path)
    try:
        key_b = rotate_key(key_dir, ledger, reason="rotation")
        _append_event(ledger, key_b.device_id, "message")
        _emit_checkpoint(ledger, key_b, 1, 2)
    finally:
        ledger.close()

    report_pin_a = verify_ledger(ledger.path, public_key_b64=key_a.public_key_b64)
    assert report_pin_a.ok is True
    assert report_pin_a.key_rotations[0]["valid"] is True

    report_pin_b = verify_ledger(ledger.path, public_key_b64=key_b.public_key_b64)
    assert report_pin_b.ok is False
    assert any(
        "does not match" in n or "REJECTED" in n or "stale" in n.lower()
        for n in report_pin_b.notes
    ), report_pin_b.notes
