"""Build, sign and resolve signed Shield policy envelopes.

Matches Coriqo's signed-policy wire shape exactly. This is an independent
implementation of the same format, not a shared import:

* ``canonicalize`` = :func:`byoai.recorder.canonical.canonicalize` — the
  same byte-identical scheme both repos use.
* ``signature`` = lowercase hex of the raw 64-byte Ed25519 signature over
  ``canonicalize(document)``. ``policy_key.public_key`` = lowercase hex of
  the raw 32-byte public key. This is NOT :class:`byoai.recorder.keys.DeviceKey`'s
  ``"ed25519:<base64>"`` format — Coriqo signs with its own server key, and
  this server does the same with its own.
* One monotonic version counter for the whole org (not per device): see
  :meth:`byoai.shield_server.store.ServerStore.write_policy_locked`. Rows are
  append-only, so "whatever a device should now have" is always the highest
  version row for its key.
* ``policy: null`` = "this device/org is no longer managed", signed the same
  as any other document.
* Deleting a device override re-issues the org default at a fresh version
  (or a signed ``policy: null`` when there is no default), so a device never
  receives a version lower than one it already holds.
"""

from __future__ import annotations

import os
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from byoai.integrations.shield_extra_sites import validate_extra_sites
from byoai.recorder.canonical import canonicalize
from byoai.shield_server.store import PolicyRow, ServerStore

__all__ = [
    "LOCKABLE_KEYS",
    "MODES",
    "pick_effective",
    "PolicyValidationError",
    "RETENTION_DAYS",
    "PolicySigner",
    "as_envelope",
    "build_document",
    "load_or_create_signing_key",
    "release_device_override",
    "resolve_effective",
    "validate_locked",
    "validate_policy",
    "write_policy",
]

MODES = {"observe", "redact", "block"}
RETENTION_DAYS = {7, 30, 90, 365}
LOCKABLE_KEYS = ("mode", "apps", "keep_text", "retention_days", "notice", "extra_sites")


class PolicyValidationError(ValueError):
    """A policy block that fails the same rules Shield's own
    ``apply_policy_update`` enforces locally. Surfaced as 400 by the routes."""


def validate_policy(policy: dict[str, Any]) -> dict[str, Any]:
    """Validate and normalize a ``policy`` block. Kept in sync deliberately
    with ``byoai.integrations.shield.apply_policy_update`` /
    ``_validate_managed_policy`` — the server must never be able to author a
    policy the device itself would refuse."""
    if not isinstance(policy, dict):
        raise PolicyValidationError("policy must be an object")
    mode = policy.get("mode")
    if mode not in MODES:
        raise PolicyValidationError(f"mode must be one of {sorted(MODES)}")
    retention_days = policy.get("retention_days")
    if retention_days not in RETENTION_DAYS:
        raise PolicyValidationError(
            "retention_days must be one of " + ", ".join(str(v) for v in sorted(RETENTION_DAYS))
        )
    keep_text = policy.get("keep_text")
    if not isinstance(keep_text, bool):
        raise PolicyValidationError("keep_text must be true or false")
    notice = policy.get("notice")
    if not isinstance(notice, bool):
        raise PolicyValidationError("notice must be true or false")
    apps = policy.get("apps")
    if not isinstance(apps, dict) or not apps:
        raise PolicyValidationError("apps must be a non-empty object mapping app name to true/false")
    normalized_apps: dict[str, bool] = {}
    for key, value in apps.items():
        if not isinstance(key, str) or not isinstance(value, bool):
            raise PolicyValidationError("apps must map string app names to true/false")
        normalized_apps[key] = value
    normalized = {
        "mode": mode, "apps": normalized_apps, "keep_text": keep_text,
        "retention_days": retention_days, "notice": notice,
    }
    # Only written when the admin set it, so every policy made before this key
    # existed signs to the same document as before.
    if "extra_sites" in policy:
        try:
            normalized["extra_sites"] = validate_extra_sites(policy["extra_sites"])
        except ValueError as exc:
            raise PolicyValidationError(str(exc)) from exc
    return normalized


def validate_locked(locked: list[str] | None) -> list[str]:
    if locked is None:
        return list(LOCKABLE_KEYS)
    if not isinstance(locked, list) or not all(isinstance(k, str) for k in locked):
        raise PolicyValidationError("locked must be a list of strings")
    unknown = sorted(set(locked) - set(LOCKABLE_KEYS))
    if unknown:
        raise PolicyValidationError(f"locked has unknown keys: {unknown}")
    return locked


class PolicySigner:
    """The Ed25519 key this server signs policy envelopes with. Generated on
    first run in the data dir; ``key_id`` is ``shield-server-<first 8 hex of
    pubkey>``, per the plan."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        raw_public = private_key.public_key().public_bytes_raw()
        self._public_key_hex = raw_public.hex()
        self.key_id = f"shield-server-{self._public_key_hex[:8]}"

    @property
    def public_key_hex(self) -> str:
        return self._public_key_hex

    def public_key_pem(self) -> str:
        from cryptography.hazmat.primitives import serialization
        pem = self._private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("ascii")

    def sign(self, document: dict[str, Any]) -> str:
        return self._private_key.sign(canonicalize(document)).hex()


def load_or_create_signing_key(path: Path) -> PolicySigner:
    path = Path(path)
    if path.exists():
        raw = path.read_bytes()
        if len(raw) != 32:
            raise ValueError(f"signing key at {path} is {len(raw)} bytes, expected 32 — corrupt")
        private_key = Ed25519PrivateKey.from_private_bytes(raw)
        return PolicySigner(private_key)
    path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    raw = private_key.private_bytes_raw()
    tmp = path.with_name(path.name + f".tmp-{os.getpid()}")
    tmp.write_bytes(raw)
    if os.name == "posix":
        tmp.chmod(0o600)
    os.replace(tmp, path)
    if os.name == "posix":
        path.chmod(0o600)
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & ~0o600:
            path.chmod(0o600)
    return PolicySigner(private_key)


def _issued_at() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def build_document(*, version: int, org: str, device_id: str | None,
                   policy: dict[str, Any] | None, managed_by: str, locked: list[str],
                   signer: PolicySigner) -> dict[str, Any]:
    return {
        "policy_id": f"pol_{uuid.uuid4().hex}",
        "version": version,
        "tenant_slug": org,
        "device_id": device_id,
        "issued_at": _issued_at(),
        "key_id": signer.key_id,
        "managed_by": managed_by,
        "policy": policy,
        "locked": locked if policy is not None else [],
    }


def write_policy(store: ServerStore, signer: PolicySigner, *, device_id: str | None, org: str,
                 policy: dict[str, Any] | None, managed_by: str, locked: list[str] | None,
                 created_by: str | None = None) -> PolicyRow:
    """Validate (when ``policy`` is not ``None``), build and sign the
    envelope, and append a new row at the next version. Never updates an
    existing row.

    Assigning the version, building/signing the document, and inserting it
    all happen inside one call to :meth:`ServerStore.write_policy_locked` —
    under one held lock — so two concurrent writers (two admin PUTs racing,
    or a PUT racing an override-delete's re-issue) can never both compute the
    same "next" version; the second simply gets the version after.
    """
    normalized = validate_policy(policy) if policy is not None else None
    locked_keys = validate_locked(locked) if normalized is not None else []

    def _build(version: int) -> dict[str, Any]:
        return build_document(
            version=version, org=org, device_id=device_id, policy=normalized,
            managed_by=managed_by, locked=locked_keys, signer=signer,
        )

    return store.write_policy_locked(device_id=device_id, build_document=_build,
                                     sign=signer.sign, created_by=created_by)


def _reissue_default_above(store: ServerStore, signer: PolicySigner, *, org: str,
                           created_by: str | None) -> PolicyRow | None:
    default_row = store.latest_row(device_id=None)
    if default_row is None or default_row.document.get("policy") is None:
        return None
    doc = default_row.document
    return write_policy(
        store, signer, device_id=None, org=org, policy=doc["policy"],
        managed_by=doc.get("managed_by") or "", locked=doc.get("locked"),
        created_by=created_by,
    )


def release_device_override(store: ServerStore, signer: PolicySigner, *, device_id: str, org: str,
                            created_by: str | None = None) -> PolicyRow:
    """DELETE a device override without stranding the device: tombstone the
    override, then re-issue the live org default above it so the device's
    next poll gets something newer than what it holds. With no live default,
    the tombstone (signed ``policy: null``, already above anything the
    device held) is returned and the device leaves managed mode."""
    tombstone = write_policy(
        store, signer, device_id=device_id, org=org, policy=None, managed_by="",
        locked=None, created_by=created_by,
    )
    refreshed = _reissue_default_above(store, signer, org=org, created_by=created_by)
    return refreshed if refreshed is not None else tombstone


def pick_effective(override: PolicyRow | None, default: PolicyRow | None) -> PolicyRow | None:
    if override is not None and override.document.get("policy") is not None:
        return override
    if default is not None and default.document.get("policy") is not None:
        return default
    candidates = [row for row in (override, default) if row is not None]
    if not candidates:
        return None
    return max(candidates, key=lambda row: row.version)


def resolve_effective(store: ServerStore, *, device_id: str) -> PolicyRow | None:
    """Device override if live, else the org default if live, else whichever
    null signal is freshest — whole-document resolution, no merging."""
    return pick_effective(store.latest_row(device_id=device_id), store.latest_row(device_id=None))


def as_envelope(row: PolicyRow) -> dict[str, Any]:
    return row.envelope()


def public_key_from_hex_or_pem(hex_or_pem: str) -> Ed25519PublicKey:
    if "BEGIN" in hex_or_pem:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        key = load_pem_public_key(hex_or_pem.encode())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("not an Ed25519 public key")
        return key
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_or_pem))
