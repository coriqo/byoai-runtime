"""Device key rotation and revocation for the agent recorder
(``docs/seal-format.md`` §7).

Rotation replaces a device's Ed25519 keypair while preserving verifiable
continuity of the ledger's hash chain across the key boundary: the OLD key
cross-signs the NEW public key, the new key material is staged to disk
*without* touching the live key files, and only once that cross-signature is
durably sealed into the ledger as a ``KEY_ROTATED`` event does the staged
key get promoted to the live filenames (and the old key archived). This
ordering guarantees three independent safety properties instead of trading
one for another: the new private key is never lost to a crash (it is
durably staged before the ledger append is attempted), the old key is never
destroyed unless the ledger append actually succeeded (so a failed or
interrupted append always leaves the device able to keep operating, and
retrying rotation, under its old identity — never in the state of a
device_id change with no matching KEY_ROTATED event to explain it), and
once the KEY_ROTATED event *has* been committed, promotion of the staged
key to the live filenames can never be lost to a crash either: promotion
(``keys._finish_pending_rotation``) changes what counts as "the live key"
via a single atomic ``os.replace`` rather than two separate replaces with a
gap between them, and ``load_or_create_device_key`` reconciles any
leftover staged key on every load before ever considering "no live key ->
generate a new one". So there is no reachable crash point, before or after
a KEY_ROTATED event, that causes the device to silently start using a
fresh, never-cross-signed random identity.

Revocation reuses the same mechanism with ``reason="revocation"`` (or
``"compromise"``): the event's ``effective_epoch`` marks the point after
which entries still attributed to the old device are no longer trusted,
while entries signed before it remain valid (``docs/seal-format.md`` §7).

Client-side only. Anchoring the revocation event externally (Coriqo) is out
of scope here; it will ship like any other ledger event via the shipper.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import canonicalize, sha256_hex
from .keys import DeviceKey, _mark_promotion_confirmed, load_or_create_device_key
from .ledger import Ledger
from .redact import RUNTIME_AUTHORED
from .schema import (
    EVENT_SCHEMA_VERSION,
    AgentEvent,
    EventKind,
    new_event_id,
    new_span_id,
    new_trace_id,
    now_monotonic_ns,
    now_ts_device,
)

__all__ = ["ROTATION_SESSION_ID", "rotate_key", "rotate_cli"]

# KEY_ROTATED events are device-level, not tied to any particular agent
# session, but AgentEvent.session_id is required — this sentinel makes that
# explicit rather than reusing a real session_id.
ROTATION_SESSION_ID = "_key_rotation"

_VALID_REASONS = frozenset({"rotation", "revocation", "compromise"})


def rotate_key(
    key_dir: Path,
    ledger: Ledger,
    *,
    reason: str = "rotation",
) -> DeviceKey:
    """Rotate this device's Ed25519 key, cross-signed for chain continuity.

    Generates a new keypair, has the CURRENT on-disk key cross-sign the new
    public key, and durably *stages* the new key files under a pending-
    rotation subdirectory (not the live filenames). Only after the
    ``KEY_ROTATED`` event has been successfully appended to ``ledger`` —
    signed as the OLD device — is the staged key promoted into the live
    ``PRIVATE_KEY_FILENAME``/``PUBLIC_KEY_FILENAME`` location, with the old
    key archived alongside it rather than deleted.

    This order means a crash or failure at any point leaves the device in a
    recoverable state:

    * Staging happens before the ledger append, so the new private key is
      never the *only* copy anywhere that can vanish — it is fsync'd to disk
      before anything durable is attempted against the ledger.
    * The live key files are only ever touched *after* the ledger append is
      confirmed to have succeeded, so a failed append (or a crash between
      staging and promotion) leaves the OLD key fully intact and loadable —
      the device keeps operating under its old identity and rotation can be
      retried cleanly. This avoids the previous bug where the old key file
      was overwritten before the append was confirmed: if the append then
      failed, the old key was gone but the ledger's chain still ended on
      entries signed by the old device_id, with no KEY_ROTATED event to
      explain the eventual device_id change on next load.

    ``ledger`` must belong to the same device being rotated (its
    ``device_id`` should match the old key's, since the event needs to be
    appended under that identity before it changes).
    """
    if reason not in _VALID_REASONS:
        raise ValueError(f"reason must be one of {sorted(_VALID_REASONS)}, got {reason!r}")

    key_dir = Path(key_dir)
    old_key = load_or_create_device_key(key_dir)

    new_private = Ed25519PrivateKey.generate()
    new_key = DeviceKey(new_private)

    old_device_id = old_key.device_id
    new_device_id = new_key.device_id
    new_public_key = new_key.public_key_b64

    signed_fields = {
        "old_device_id": old_device_id,
        "new_device_id": new_device_id,
        "new_public_key": new_public_key,
    }
    cross_signature = old_key.sign(canonicalize(signed_fields))

    payload = {
        **signed_fields,
        "cross_signature": cross_signature,
        "reason": reason,
        "effective_epoch": now_ts_device(),
    }
    payload_hash = sha256_hex(canonicalize(payload))

    event = AgentEvent(
        schema_version=EVENT_SCHEMA_VERSION,
        event_id=new_event_id(),
        device_id=old_device_id,
        session_id=ROTATION_SESSION_ID,
        seq=0,  # stamped by Ledger.append
        kind=EventKind.KEY_ROTATED.value,
        ts_device=now_ts_device(),
        ts_monotonic_ns=now_monotonic_ns(),
        tool_use_id=None,
        tool_name=None,
        payload=payload,
        payload_hash=payload_hash,
        model=None,
        provider="recorder",
        # Device-level event, not tied to any agent run.
        trace_id=new_trace_id(),
        span_id=new_span_id(),
        parent_span_id=None,
        continues_from=None,
    )
    # Staged before the event is appended: the new private key only ever
    # exists in memory until this call, so if the process dies before this
    # completes, no ledger record commits to a device_id whose key was lost.
    # Staging is deliberately NOT the live key location, and a merely-staged
    # (unconfirmed) key is never promoted by load_or_create_device_key() —
    # see PROMOTION_CONFIRMED_MARKER — so a crash after this point but before
    # the ledger append is confirmed leaves the device still safely operating
    # under the OLD key on next startup, exactly as if rotation had never
    # been attempted.
    _stage_new_key(key_dir, new_private, new_key)

    entry = ledger.append(event, payload_mode=RUNTIME_AUTHORED)
    if entry is None:
        raise RuntimeError(
            "failed to append KEY_ROTATED event to the ledger — the new key "
            "was staged but NOT promoted, so the old key is still live and "
            "loadable; retry rotation (the stale staged key will simply be "
            "overwritten) or investigate the ledger before rotating again"
        )

    # Only now, with the cross-signed handoff durably recorded, mark the
    # staged key confirmed (so a crash from this point on is self-healing —
    # load_or_create_device_key will finish the promotion on next startup
    # rather than ever falling back to generating a new random key) and
    # promote it: archive the old key (not delete — it remains useful for
    # verifying entries signed before the rotation boundary) and promote the
    # staged new key into the live filenames.
    _mark_promotion_confirmed(key_dir, old_device_id=old_device_id)
    _promote_staged_key(key_dir, old_device_id)

    return new_key


def _pending_dir(key_dir: Path) -> Path:
    from .keys import PENDING_ROTATION_DIRNAME

    return key_dir / PENDING_ROTATION_DIRNAME


def _stage_new_key(key_dir: Path, new_private: Ed25519PrivateKey, new_key: DeviceKey) -> None:
    from .keys import PRIVATE_KEY_FILENAME, PUBLIC_KEY_FILENAME, atomic_write_bytes

    key_dir.mkdir(parents=True, exist_ok=True)
    pending_dir = _pending_dir(key_dir)
    pending_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(
        pending_dir / PRIVATE_KEY_FILENAME,
        new_private.private_bytes_raw(),
        mode=0o600,
        prefix=".devkey-",
    )
    atomic_write_bytes(
        pending_dir / PUBLIC_KEY_FILENAME,
        (new_key.public_key_b64 + "\n").encode("ascii"),
        mode=0o644,
        prefix=".devpub-",
    )


def _promote_staged_key(key_dir: Path, old_device_id: str) -> None:
    """Archive the current live key and promote the staged new key in its
    place. Only called after the KEY_ROTATED event is durably appended.

    Delegates to :func:`byoai.recorder.keys._finish_pending_rotation`, which
    is written so the *only* filesystem step that changes whether a live
    private key file exists is a single atomic ``os.replace`` of the staged
    key into the live path — never two separate replaces with a gap between
    them. That matters because ``load_or_create_device_key`` treats "no live
    private key file" as "generate a brand new random identity"; with a two-
    step archive-then-promote, a crash between the steps used to hit exactly
    that window and silently mint an uncross-signed identity even though the
    KEY_ROTATED event for the *staged* key was already durably committed.

    ``load_or_create_device_key`` also calls the same helper unconditionally
    on every load, so if this function itself is interrupted by a crash, the
    very next call to ``load_or_create_device_key`` (recorder startup)
    finishes the promotion from whatever partial state was left on disk
    instead of ever falling back to generating a new key.
    """
    from .keys import _finish_pending_rotation

    _finish_pending_rotation(key_dir, old_device_id=old_device_id)


def rotate_cli(argv: list[str] | None = None) -> int:
    """CLI entry point: ``byoai-recorder-rotate-key --key-dir <dir> [--reason <r>]
    --ledger <path>``."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="byoai-recorder-rotate-key",
        description="Rotate this device's agent recorder key, cross-signed for chain continuity.",
    )
    parser.add_argument(
        "--key-dir",
        required=True,
        type=Path,
        help="Directory holding the device key files.",
    )
    parser.add_argument(
        "--ledger",
        required=True,
        type=Path,
        help="Path to this device's ledger SQLite file.",
    )
    parser.add_argument(
        "--reason",
        default="rotation",
        choices=sorted(_VALID_REASONS),
        help="Why the key is being rotated (default: rotation).",
    )
    args = parser.parse_args(argv)

    old_key = load_or_create_device_key(args.key_dir)
    ledger = Ledger(args.ledger, device_id=old_key.device_id)
    try:
        new_key = rotate_key(args.key_dir, ledger, reason=args.reason)
    finally:
        ledger.close()

    print(f"rotated device key: {old_key.device_id} -> {new_key.device_id}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(rotate_cli())
