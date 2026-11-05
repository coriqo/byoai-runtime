"""Offline, independent verifier for a recorder ledger.

The verifier trusts nothing that the recorder wrote about itself. It re-derives
every ``entry_hash`` from the stored event data, walks the whole chain link by
link, re-checks every checkpoint signature against a supplied public key, and
reports missing sequence numbers and unpaired tool events.

It never opens a network connection and never writes to the ledger.
"""

from __future__ import annotations

import base64
import json
import sqlite3
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from byoai.recorder.canonical import CanonicalizationError, canonicalize, sha256_hex
from byoai.recorder.ledger import compute_entry_hash
from byoai.recorder.merkle import (
    InclusionProof,
    ProofStep,
    checkpoint_leaf_hash,
    verify_inclusion,
)
from byoai.recorder.schema import EVENT_SCHEMA_VERSION_V1, EventKind

GENESIS_PREV_HASH = "sha256:" + "00" * 32

# Columns that live on the ledger row itself rather than on the event.
_CHAIN_COLUMNS = frozenset({"prev_hash", "entry_hash", "event_digest"})

# Columns that exist only from schema v2 onward (trace
# attribution), added to agent_events via an additive ALTER TABLE migration
# (see ledger.py). A pre-migration (v1) row's stored entry_hash/event_digest
# was computed before these columns existed, so re-deriving its digest must
# exclude them entirely (not just pass NULL) — matches
# AgentEvent.to_dict()'s schema_version-conditional field set, which is the
# same rule applied on the write/ship path via schema.event_digest.
_V2_ONLY_COLUMNS = frozenset({"trace_id", "span_id", "parent_span_id", "continues_from"})


@dataclass
class VerifyReport:
    """Result of a full ledger verification pass."""

    ok: bool
    entries_checked: int
    broken_links: list[int]  # seqs where the re-derived chain did not hold
    bad_signatures: list[int]  # checkpoint seq_end values that failed
    gaps: list[tuple[int, int]]
    unpaired_tool_uses: list[str]  # tool_use_ids with no result — reported, NOT a finding
    orphan_tool_results: list[str]  # results with no tool_use — stronger finding

    # Descriptive context for the human report. Not part of the integrity
    # verdict; safe for consumers to ignore.
    device_ids: list[str] = field(default_factory=list)
    session_ids: list[str] = field(default_factory=list)
    seq_start: int | None = None
    seq_end: int | None = None
    ts_first: str | None = None
    ts_last: str | None = None
    checkpoints_checked: int = 0
    signatures_verified: bool = False
    notes: list[str] = field(default_factory=list)
    # One dict per KEY_ROTATED event found: old/new device_id, reason,
    # whether the cross-signature verified (None if no pubkey was supplied
    # for the old device, same "not checked" convention as checkpoints).
    key_rotations: list[dict[str, Any]] = field(default_factory=list)
    # seqs where an entry is attributed to a device whose key was already
    # rotated out as of that entry's effective_epoch — a genuine finding,
    # distinct from the device_id simply differing across a legitimate
    # rotation boundary.
    stale_key_usage: list[int] = field(default_factory=list)
    # Present only when verify_ledger was given receipts_path. Receipts ARE
    # folded into `ok`: a failing receipts section sets ok False. The detail
    # (findings, reasons, notes) is in here.
    receipts: dict[str, Any] | None = None
    # Ledger-path pinning hardening: set when public_key_b64 was supplied
    # but the ledger has zero checkpoint rows at all, so nothing could be
    # signature-checked. Folded into `ok`.
    no_signed_checkpoints: bool = False
    # Set when public_key_b64 was supplied but the checkpoints table could
    # not even be read (as opposed to an individual row's body being bad,
    # which is instead reported per-row via bad_signatures/notes). Folded
    # into `ok`.
    unreadable_checkpoints: bool = False
    # Inclusive (first_seq, last_seq) of entries after the last checkpoint's
    # seq_end when public_key_b64 was supplied — informational on the
    # ledger path (a live, still-recording ledger always has such a tail;
    # this is NOT folded into `ok`), but reported so a caller pinning a key
    # knows exactly how far signed coverage reaches.
    unsigned_tail: tuple[int, int] | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["gaps"] = [list(g) for g in self.gaps]
        data["unsigned_tail"] = list(self.unsigned_tail) if self.unsigned_tail else None
        return data


class VerifyError(RuntimeError):
    """The ledger file could not be read at all."""


def verify_checkpoint_epoch_inclusion(
    checkpoint: dict[str, Any], proof: InclusionProof, epoch_root: bytes
) -> bool:
    """The missing link in the verification path (seal-format §11.3): proves
    ``checkpoint`` (already verified against the device chain and its own
    signature by :func:`_verify_checkpoints` / the caller) was actually
    included in the tenant epoch tree that ``epoch_root`` is the root of.

    Re-derives the leaf hash from ``checkpoint`` itself rather than trusting
    ``proof.leaf_hash`` — a proof carrying a leaf hash that doesn't match the
    checkpoint it claims to cover is exactly the kind of substitution this
    check exists to catch. No network access; the caller supplies the
    checkpoint (from the local ledger), the proof, and the root (both
    presumably from an exported bundle, once one exists).
    """
    if checkpoint_leaf_hash(checkpoint) != proof.leaf_hash:
        return False
    if proof.root != epoch_root:
        return False
    return verify_inclusion(proof)


# --------------------------------------------------------------------------
# signature backend
# --------------------------------------------------------------------------


def _forged_rotations(key_rotations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rotations that are findings, not merely "unchecked".

    Two ways a rotation ends up here:

    - ``cross_signature_verified is False`` — the legacy, ``device_public_keys``
      -based check (used when no starting/pinned key was supplied to the
      chain walk) found a signature that does not verify.
    - ``valid is False`` — the live active-key walk (used when a starting key
      *was* supplied, see :func:`_check_rotation_live`) found the rotation
      fails one of its four required conditions: signature against the
      CURRENT active key, old_device_id/event.device_id matching the active
      id, or new_device_id matching derive_device_id(new_public_key). This
      is a strict superset of the signature-only check — a rotation can have
      a verifying signature and still be forged, if it was cross-signed by a
      RETIRED key posing as the active one.

    Excludes rotations where ``cross_signature_verified`` is ``None`` (not
    checked at all) and ``valid`` is absent — those are reported separately
    via notes, not treated as forged. Shared by :func:`_verify` and
    :func:`verify_bundle` so the two can never disagree on what counts as
    "forged".
    """
    return [
        r
        for r in key_rotations
        if r["cross_signature_verified"] is False or r.get("valid") is False
    ]


def _verify_signature(public_key_b64: str, data: bytes, sig: str) -> bool:
    """Ed25519 verification via the recorder's own key module.

    Imported lazily: ``keys.py`` needs ``cryptography``, which callers who
    verify without a public key (skipping signature checks entirely) should
    never be forced to install.
    """
    from byoai.recorder.keys import DeviceKey

    try:
        return bool(DeviceKey.verify(public_key_b64, data, sig))
    except Exception:
        return False


# --------------------------------------------------------------------------
# reading
# --------------------------------------------------------------------------


def _connect(path: str | Path) -> sqlite3.Connection:
    p = Path(path)
    if not p.exists():
        raise VerifyError(f"ledger not found: {p}")
    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _columns(conn: sqlite3.Connection, table: str) -> list[str]:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except sqlite3.DatabaseError as exc:  # pragma: no cover - corrupt file
        raise VerifyError(f"cannot read table {table}: {exc}") from exc
    return [r["name"] for r in rows]


def _row_to_event_dict(row: sqlite3.Row, event_columns: Iterable[str]) -> dict[str, Any]:
    """Rebuild the event mapping exactly as the recorder hashed it.

    A v1 row (``schema_version == "1"``) never had the v2-only trace fields
    at write time, so they are dropped here even though the migrated table
    now has those columns (NULL for that row) — otherwise re-deriving the
    digest for a pre-migration row would never match what was actually
    sealed. See ``_V2_ONLY_COLUMNS``.
    """
    is_v1 = row["schema_version"] == EVENT_SCHEMA_VERSION_V1
    event: dict[str, Any] = {}
    for name in event_columns:
        if is_v1 and name in _V2_ONLY_COLUMNS:
            continue
        value = row[name]
        if name == "payload":
            event[name] = json.loads(value) if isinstance(value, str) else (value or {})
        else:
            event[name] = value
    return event


def _event_digest(event: dict[str, Any]) -> str:
    return sha256_hex(canonicalize(event))


def _check_rotation(
    payload: dict[str, Any], device_public_keys: dict[str, str]
) -> dict[str, Any]:
    """Verify a KEY_ROTATED event's cross-signature, if a pubkey is available."""
    old_id = payload.get("old_device_id")
    new_id = payload.get("new_device_id")
    new_public_key = payload.get("new_public_key")
    cross_signature = payload.get("cross_signature")

    verified: bool | None = None
    old_pubkey = device_public_keys.get(str(old_id)) if old_id else None
    if old_pubkey is not None:
        signed_fields = {
            "old_device_id": old_id,
            "new_device_id": new_id,
            "new_public_key": new_public_key,
        }
        verified = bool(
            isinstance(cross_signature, str)
            and _verify_signature(old_pubkey, canonicalize(signed_fields), cross_signature)
        )

    # The rotation finding here: new_device_id must actually be the id the
    # new public key derives to, or the ledger's later device_id-based
    # bookkeeping (key timeline, stale-key checks) is trusting an
    # unsubstantiated claim. Checked independently of the cross-signature —
    # a device_id that doesn't match its own key is worth flagging even if
    # no old public key was supplied to check the cross-signature at all.
    device_id_matches_public_key: bool | None = None
    if isinstance(new_public_key, str) and isinstance(new_id, str):
        from byoai.recorder.keys import derive_device_id

        try:
            device_id_matches_public_key = derive_device_id(new_public_key) == new_id
        except Exception:
            device_id_matches_public_key = False

    return {
        "old_device_id": old_id,
        "new_device_id": new_id,
        "new_public_key": new_public_key,
        "reason": payload.get("reason"),
        "effective_epoch": payload.get("effective_epoch"),
        "cross_signature_verified": verified,
        "device_id_matches_public_key": device_id_matches_public_key,
    }


def _check_rotation_live(
    payload: dict[str, Any],
    active_key: str,
    active_id: str | None,
    event_device_id: Any,
) -> dict[str, Any]:
    """Validate a KEY_ROTATED entry against the key/id CURRENTLY active in
    the chain walk (the hardening for the "retired key re-rotation"
    finding).

    Unlike :func:`_check_rotation` — which looks the cross-signing key up in
    a caller-supplied ``device_public_keys`` dict, keyed by whatever
    ``old_device_id`` the payload itself claims — this checks the signature
    against ``active_key``, the key the walk has itself established as
    current as of this point in the chain. An attacker who still holds a
    RETIRED device key can produce a payload whose cross-signature verifies
    fine against *that* key and whose ``old_device_id`` label matches it too
    — but ``old_device_id`` will not match ``active_id`` (the walk moved
    past that key at the real rotation), so this is still correctly flagged
    as forged and does NOT advance the timeline.

    A rotation is ``valid`` only when ALL of the following hold:

    - its cross-signature verifies against ``active_key``;
    - ``payload["old_device_id"] == active_id``;
    - the KEY_ROTATED event's own ``device_id == active_id``;
    - ``new_device_id == derive_device_id(new_public_key)``.
    """
    old_id = payload.get("old_device_id")
    new_id = payload.get("new_device_id")
    new_public_key = payload.get("new_public_key")
    cross_signature = payload.get("cross_signature")

    signed_fields = {
        "old_device_id": old_id,
        "new_device_id": new_id,
        "new_public_key": new_public_key,
    }
    cross_signature_verified = bool(
        isinstance(cross_signature, str)
        and _verify_signature(active_key, canonicalize(signed_fields), cross_signature)
    )

    device_id_matches_public_key: bool | None = None
    if isinstance(new_public_key, str) and isinstance(new_id, str):
        from byoai.recorder.keys import derive_device_id

        try:
            device_id_matches_public_key = derive_device_id(new_public_key) == new_id
        except Exception:
            device_id_matches_public_key = False

    old_id_matches_active = active_id is not None and old_id == active_id
    event_device_id_matches_active = active_id is not None and event_device_id == active_id

    valid = bool(
        cross_signature_verified
        and old_id_matches_active
        and event_device_id_matches_active
        and device_id_matches_public_key
    )

    return {
        "old_device_id": old_id,
        "new_device_id": new_id,
        "new_public_key": new_public_key,
        "reason": payload.get("reason"),
        "effective_epoch": payload.get("effective_epoch"),
        "cross_signature_verified": cross_signature_verified,
        "device_id_matches_public_key": device_id_matches_public_key,
        "old_id_matches_active": old_id_matches_active,
        "event_device_id_matches_active": event_device_id_matches_active,
        "valid": valid,
    }


# --------------------------------------------------------------------------
# verification
# --------------------------------------------------------------------------


def verify_ledger(
    path: str | Path,
    *,
    public_key_b64: str | None = None,
    device_public_keys: dict[str, str] | None = None,
    receipts_path: str | Path | None = None,
    receipt_overdue_after_seconds: float = 3600.0,
    receipt_public_key_pem: str | None = None,
    allow_unchecked_receipts: bool = False,
    allow_pending_receipts: bool = False,
) -> VerifyReport:
    """Re-derive and check every hash, signature and sequence in the ledger.

    ``public_key_b64`` checks checkpoint signatures, as before.
    ``device_public_keys`` (device_id -> base64 Ed25519 public key) is used
    to verify ``KEY_ROTATED`` cross-signatures against the *old* device's
    key; a rotation whose old device_id has no entry there is noted as
    unchecked rather than failed, matching the existing checkpoint
    convention.
    """
    conn = _connect(path)
    try:
        report = _verify(conn, public_key_b64, device_public_keys or {})
    finally:
        conn.close()
    if receipts_path is not None:
        section = verify_receipts(
            receipts_path,
            overdue_after_seconds=receipt_overdue_after_seconds,
            public_key_pem=receipt_public_key_pem,
            allow_unchecked=allow_unchecked_receipts,
            allow_pending=allow_pending_receipts,
        )
        report.receipts = section
        if not section["ok"]:
            report.ok = False
    return report


def verify_receipts(
    store_path: str | Path,
    *,
    overdue_after_seconds: float = 3600.0,
    public_key_pem: str | None = None,
    allow_unchecked: bool = False,
    allow_pending: bool = False,
    now: Any = None,
) -> dict[str, Any]:
    """Check the receipt store against what was sent, and every stored bundle.

    Findings (each makes ``ok`` False):

    * ``unacknowledged``: a trace was sent more than ``overdue_after_seconds``
      ago and Coriqo never returned an ``event_hash`` for it. A server that
      swallowed the event produces exactly this.
    * ``receipt_overdue``: acknowledged, but no receipt after the same age.
      Still listed, but does not fail ``ok`` when ``allow_pending`` is set
      (tenants with slow or disabled checkpointing).
    * ``batch_rejected``: the server refused the batch carrying the trace
      (HTTP error or the POST raising). Not a swallowed event; fails ``ok``
      with its own reason until the trace is re-sent or the row is forgotten.
    * ``receipts_unavailable``: the receipts route kept answering 403/404.
    * ``content_mismatch``: the input/output hash Coriqo echoed differs from
      the one computed locally from what was sent (checked when acknowledged
      and again here, along with any hashes or event hash the bundle carries).
    * ``failed``: the bundle did not verify. ``malformed``: an unusable row.
    * ``store_error``: the store is corrupt or unreadable (never read as empty).
    * ``no_receipts_tracked``: nothing in the store, so nothing was checked.
    * ``unchecked``/``unpinned``: bundles that could not be checked (SDK
      missing) or were checked only against the bundle's own key. Both make
      ``ok`` False unless ``allow_unchecked`` is set, because a bundle checked
      against its own key proves consistency only.

    Bundles are checked with the SDK's offline verifier
    (``coriqo_agents.receipts``, extra ``coriqo-agents[receipts]``) using the
    pinned ``public_key_pem``. Never opens a network connection.

    Scope: content_mismatch shows the echoed record matches what was sent, not
    that the server's sealed event hash covers those fields. The store itself
    is unsigned, so deleted rows are not detectable.
    """
    from byoai.recorder.receipts import (
        CONTENT_SCOPE_NOTE,
        STORE_LIMITATION,
        UNAVAILABLE_AFTER,
        UNAVAILABLE_STATUSES,
        ReceiptStore,
        ReceiptStoreError,
        _norm_hash,
        content_mismatches,
        parse_ts,
        utc_now,
    )

    now = now or utc_now()
    out: dict[str, Any] = {
        "ok": False,
        "acknowledged": 0,
        "tracked": 0,
        "with_receipt": 0,
        "unacknowledged": [],
        "batch_rejected": [],
        "receipt_overdue": [],
        "receipts_unavailable": [],
        "content_mismatch": [],
        "failed": [],
        "malformed": [],
        "not_checked": [],
        "device_receipt_refused": [],
        "device_receipt_unsent": [],
        "device_receipt_withheld": [],
        "unpinned": False,
        "store_error": None,
        "reasons": [],
        "results": {},
        "notes": [STORE_LIMITATION, CONTENT_SCOPE_NOTE],
    }
    reasons: list[str] = out["reasons"]

    try:
        entries = ReceiptStore(store_path).entries()
    except ReceiptStoreError as exc:
        out["store_error"] = str(exc)
        reasons.append(f"receipt store error: {exc}")
        return out
    out["tracked"] = len(entries)
    if not entries:
        reasons.append(
            "no receipts tracked: the store has no rows, so nothing was checked "
            "(only traces sent through publish_session are tracked)"
        )
        out["no_receipts_tracked"] = True
        out["ok"] = allow_unchecked
        return out
    out["no_receipts_tracked"] = False

    try:
        from coriqo_agents.receipts import verify_receipt as _verify_receipt
    except ImportError:
        _verify_receipt = None
    out["unpinned"] = public_key_pem is None

    for i, row in enumerate(entries):
        if not isinstance(row, dict):
            out["malformed"].append({"row": i, "reason": "row is not an object"})
            continue
        key = row.get("key") or row.get("event_hash") or f"row {i}"
        try:
            age = (now - parse_ts(row["sent_at"])).total_seconds()
        except (KeyError, ValueError, TypeError, AttributeError) as exc:
            out["malformed"].append(
                {"key": key, "reason": f"missing or invalid sent_at: {exc!r}"}
            )
            continue
        overdue = age >= overdue_after_seconds
        device = row.get("device_receipt")
        if isinstance(device, dict) and device.get("finding") in (
            "device_receipt_refused", "device_receipt_unsent", "device_receipt_withheld",
        ):
            out[device["finding"]].append(
                {"key": key, "seal": device.get("seal"), "reason": device.get("reason")}
            )
        event_hash = row.get("event_hash")
        if not event_hash:
            if row.get("rejected"):
                rj = row["rejected"] if isinstance(row["rejected"], dict) else {}
                out["batch_rejected"].append({"key": key, "status": rj.get("status")})
            elif overdue:
                out["unacknowledged"].append(key)
            continue
        out["acknowledged"] += 1

        bad = list(row.get("content_mismatch") or [])
        echoed = {
            "input_hash": row.get("echoed_input_hash"),
            "output_hash": row.get("echoed_output_hash"),
        }
        for name in content_mismatches(
            row.get("expected_input_hash"), row.get("expected_output_hash"), echoed
        ):
            if name not in bad:
                bad.append(name)
        bundle = row.get("bundle")
        if isinstance(bundle, dict):
            for name in ("input_hash", "output_hash"):
                if name in bundle:
                    if _norm_hash(bundle[name]) != _norm_hash(row.get("expected_" + name)):
                        if name not in bad:
                            bad.append(name)
            if bundle.get("event_hash") not in (None, event_hash):
                bad.append("event_hash")
        if bad:
            out["content_mismatch"].append({"key": key, "fields": bad})

        fe = row.get("fetch_error") or {}
        if not bundle:
            if (
                fe.get("status") in UNAVAILABLE_STATUSES
                and fe.get("count", 0) >= UNAVAILABLE_AFTER
            ):
                out["receipts_unavailable"].append(
                    {"key": key, "status": fe.get("status"), "attempts": fe.get("count")}
                )
            elif overdue:
                out["receipt_overdue"].append(key)
            continue

        out["with_receipt"] += 1
        if _verify_receipt is None:
            out["not_checked"].append(key)
            continue
        # With no pinned key, still run the checks so a tampered bundle shows as
        # failed rather than hiding behind "unpinned".
        res = _verify_receipt(
            bundle, public_key_pem, allow_unpinned=public_key_pem is None
        )
        out["results"][key] = res
        if not res.get("ok"):
            out["failed"].append(key)

    for name, msg in (
        ("unacknowledged", "trace(s) sent but never acknowledged with an event_hash"),
        ("batch_rejected", "trace(s) in a batch the server rejected (not a swallowed event): "
                           "re-send them, or drop the rows with --forget-rejected"),
        ("receipt_overdue", "acknowledged event(s) with no receipt after the allowed age"),
        ("receipts_unavailable", "receipts route kept answering 403/404; receipts cannot be fetched"),
        ("content_mismatch", "echoed record differs from what was sent"),
        ("failed", "receipt bundle(s) failed verification"),
        ("malformed", "malformed store row(s)"),
        ("device_receipt_unsent", "device receipt(s) that could not be sent: "
                                  "call send_device_receipts again; a repeat is safe"),
    ):
        if out[name]:
            if name == "receipt_overdue" and allow_pending:
                out["notes"].append(
                    f"{len(out[name])} {msg} (waived by --allow-pending-receipts)"
                )
            else:
                reasons.append(f"{len(out[name])} {msg}")
    for item in out["device_receipt_refused"]:
        reasons.append(f"device receipt on {item['key']} refused: {item['reason']}")
    if out["device_receipt_withheld"]:
        out["notes"].append(
            f"{len(out['device_receipt_withheld'])} device receipt(s) kept on this device "
            "because the sealed row holds a message preview"
        )
    if not allow_unchecked:
        if out["not_checked"]:
            reasons.append(
                f"{len(out['not_checked'])} receipt bundle(s) not checked: install "
                "coriqo-agents[receipts], or pass --allow-unchecked-receipts"
            )
        if out["with_receipt"] and out["unpinned"]:
            reasons.append(
                "receipts were checked against the bundle's own key, not a pinned "
                "one: pass --receipt-pubkey, or --allow-unchecked-receipts"
            )
    out["ok"] = not reasons
    return out


def _pubkey_b64(public_key: str) -> str:
    """A device key as base64. Coriqo shows them as 64 hex characters, Shield as
    base64; both are accepted. Raises ValueError for anything else."""
    text = public_key.strip()
    try:
        raw = bytes.fromhex(text) if len(text) == 64 else base64.b64decode(text, validate=True)
    except ValueError as exc:
        raise ValueError("the public key is neither hex nor base64") from exc
    if len(raw) != 32:
        raise ValueError(f"an Ed25519 public key is 32 bytes, this one is {len(raw)}")
    return base64.b64encode(raw).decode("ascii")


def _receipt_inclusion(leaf: bytes | None, proof: Any, checkpoint: dict) -> str | None:
    """Why the entry is not in the signed tree, or None when it is."""
    if leaf is None:
        return "the payload could not be hashed, so its place in the tree cannot be checked"
    if not isinstance(proof, dict):
        return "the receipt has no inclusion proof"
    try:
        built = InclusionProof(
            leaf_index=0,
            leaf_hash=leaf,
            steps=tuple(
                ProofStep(sibling=bytes.fromhex(s["sibling"]), side=s["side"])
                for s in proof.get("steps") or []
            ),
            root=bytes.fromhex(proof["root_hex"]),
        )
    except (KeyError, TypeError, ValueError, AttributeError):
        return "the inclusion proof is not in the receipt format"
    if any(s.side not in ("left", "right") for s in built.steps):
        return "a proof step has no side"
    if not verify_inclusion(built):
        return "the proof does not lead to its root: the entry is not in the signed tree"
    if str(checkpoint.get("root_hex") or "").lower() != built.root.hex():
        return "the signed checkpoint is for a different tree than the proof"
    return None


def verify_device_receipt(doc: Any, public_key: str) -> dict[str, Any]:
    """The three checks on one Shield receipt (``byoai.receipt.v2``), offline.

    1. seal: ``sha256(0x00 || canonical(payload))`` starts with ``seal``;
    2. inclusion: that leaf, folded through the proof, is the checkpoint's root;
    3. signature: the checkpoint without ``sig`` is signed by ``public_key``,
       which the caller holds. The key inside the file is never trusted.

    All three always run and each reports on its own. ``doc`` may also be the
    row Coriqo stores, which holds the device's receipt unchanged under
    ``receipt``. Raises ValueError for an unusable ``public_key``.
    """
    from byoai.recorder.keys import DeviceKey

    pinned = _pubkey_b64(public_key)
    nested = doc.get("receipt") if isinstance(doc, dict) else None
    receipt = nested if isinstance(nested, dict) else doc
    if not isinstance(receipt, dict) or receipt.get("kind") != "byoai.receipt.v2":
        reason = "this file is not a byoai.receipt.v2 device receipt"
        return {"ok": False, "seal": None, "checks": {
            name: {"ok": False, "detail": reason} for name in ("seal", "inclusion", "signature")
        }}
    payload, seal = receipt.get("payload"), receipt.get("seal")
    merkle = receipt.get("merkle") if isinstance(receipt.get("merkle"), dict) else {}
    checkpoint = merkle.get("checkpoint") if isinstance(merkle.get("checkpoint"), dict) else {}

    leaf: bytes | None = None
    seal_problem = None
    try:
        leaf = checkpoint_leaf_hash(payload)
    except (CanonicalizationError, TypeError, ValueError):
        seal_problem = "the payload could not be hashed"
    if seal_problem is None:
        if not isinstance(seal, str) or len(seal) != 16:
            seal_problem = "the seal is not 16 hex characters"
        elif leaf.hex()[:16] != seal.lower():
            seal_problem = "the payload does not match its seal: it was changed after sealing"
    inclusion_problem = _receipt_inclusion(leaf, merkle.get("proof"), checkpoint)

    signature_problem = None
    body = {k: v for k, v in checkpoint.items() if k != "sig"}
    if not checkpoint.get("sig"):
        signature_problem = "the receipt has no signed checkpoint"
    else:
        try:
            signed = checkpoint_leaf_hash(body)
        except (CanonicalizationError, TypeError, ValueError):
            signed = b""
        verified = bool(signed) and DeviceKey.verify(pinned, signed, checkpoint["sig"])
    if checkpoint.get("sig") and not verified:
        signature_problem = "the checkpoint signature does not verify with this key"
        if "kind" not in checkpoint or "ts" not in checkpoint:
            signature_problem += (
                ". This receipt was exported by an older Shield that left signed fields "
                "out of the file; export it again from Shield to get one that verifies"
            )
        elif checkpoint.get("public_key_b64") != pinned:
            signature_problem += ", and the file names a different key"

    def _check(problem: str | None, passed: str) -> dict[str, Any]:
        return {"ok": problem is None, "detail": problem or passed}

    checks = {
        "seal": _check(seal_problem, "the payload hashes to its seal"),
        "inclusion": _check(inclusion_problem, "the entry is in the signed tree"),
        "signature": _check(signature_problem, "the checkpoint is signed by this key"),
    }
    return {"ok": all(c["ok"] for c in checks.values()), "seal": seal, "checks": checks}


@dataclass
class _ChainWalk:
    """Everything a walk over normalized chain entries accumulates, shared
    between the SQLite-backed ledger path and the JSON-bundle path so the two
    can never silently drift apart on what counts as a finding."""

    entries_checked: int
    broken_links: list[int]
    gaps: list[tuple[int, int]]
    device_ids: list[str]
    session_ids: list[str]
    ts_values: list[str]
    unpaired_tool_uses: list[str]
    orphan_tool_results: list[str]
    key_rotations: list[dict[str, Any]]
    stale_key_usage: list[int]
    derived: dict[int, str]
    notes: list[str]
    malformed: list[str]


def _walk_chain(
    entries: Iterable[dict[str, Any]],
    device_public_keys: dict[str, str],
    *,
    starting_public_key_b64: str | None = None,
) -> _ChainWalk:
    """Re-derive and check the hash chain over normalized entries.

    Each item in ``entries`` must have ``seq`` (int), ``prev_hash`` (str),
    ``entry_hash`` (str) and ``event`` (the event mapping, already parsed) —
    the same shape whether it came from an ``agent_events`` row or a bundle's
    ``entries`` array. This is the one chain-walking implementation; both
    :func:`verify_ledger` and :func:`verify_bundle` call it so a finding in
    one can never fail to appear in the other.

    ``starting_public_key_b64``, when given, is a key the CALLER trusts (a
    pinned key, or the key the caller connected with) — never anything read
    out of the untrusted chain data itself. When supplied, the walk builds
    the active device key/id live, inline, as it walks: each ``KEY_ROTATED``
    entry is checked against ``active_key``/``active_id`` as of that point
    (see :func:`_check_rotation_live`), and only a rotation that passes all
    four of its conditions advances them. This is what closes the "retired
    key re-rotation" gap: a rotation forged by a device holding a RETIRED
    key cannot take over the timeline, because its ``old_device_id`` will
    not match the walk's own ``active_id`` — no matter what
    ``device_public_keys`` says. Every non-rotation entry whose
    ``device_id`` no longer matches ``active_id`` at its seq is also a
    finding (folded into ``stale_key_usage``).

    ``device_public_keys`` remains supported for backward compatibility
    (and is exactly what's used when ``starting_public_key_b64`` is
    ``None`` — the original, note-based "can't verify rotations without a
    key" behaviour) but can never override the live timeline: if both are
    given and a rotation's ``new_device_id`` has an entry in
    ``device_public_keys`` that disagrees with its actual ``new_public_key``,
    that's surfaced as a note, not used for anything.
    """
    broken_links: list[int] = []
    gaps: list[tuple[int, int]] = []
    device_ids: list[str] = []
    session_ids: list[str] = []
    notes: list[str] = []

    tool_uses: dict[str, int] = {}
    tool_results: dict[str, int] = {}

    prev_seq: int | None = None
    prev_stored_hash = GENESIS_PREV_HASH
    derived: dict[int, str] = {}
    ts_values: list[str] = []

    key_rotations: list[dict[str, Any]] = []
    stale_key_usage: list[int] = []
    # device_id of a retired key -> the seq of the KEY_ROTATED event that
    # retired it. seq is assigned by the ledger at write time in strict
    # append order and is therefore trustworthy, unlike ts_device (a
    # device-controlled wall-clock string — see schema.now_ts_device()'s
    # docstring: "ordering comes from seq, never from this value"). Using
    # ts_device here would let a device holding a compromised pre-rotation
    # key keep forging entries under the old device_id by simply backdating
    # ts_device to before the rotation's effective_epoch.
    retired_devices: dict[str, int] = {}
    malformed: list[str] = []

    have_starting_key = starting_public_key_b64 is not None
    active_key: str | None = starting_public_key_b64
    active_id: str | None = None
    if have_starting_key:
        from byoai.recorder.keys import derive_device_id

        try:
            active_id = derive_device_id(active_key)
        except Exception:
            active_id = None
            notes.append(
                "starting_public_key_b64 could not be used to derive a device_id "
                "— rotation timeline tracking disabled for this run"
            )
            have_starting_key = False

    entries_checked = 0
    for entry in entries:
        entries_checked += 1
        # A hand-tampered or partially-written bundle can
        # carry an entry of the wrong shape entirely (not a dict, missing
        # "seq"/"event"/hash fields, a non-dict "event", etc). That must be
        # reported as a finding, never raise — so the whole per-entry body is
        # one try/except. A malformed entry is skipped: it does not
        # contribute to derived[], device/session lists, tool pairing or the
        # gap/link state, which is the same as if it were simply absent (and
        # its absence is separately visible as a gap or a broken link at the
        # next entry, if any).
        try:
            if not isinstance(entry, dict):
                raise TypeError("entry is not an object")
            raw_seq = entry["seq"]
            # seq is load-bearing for chain ordering, gap detection and
            # link/hash re-derivation, so it must be a genuine int — not a
            # bool (bool is an int subclass in Python: isinstance(True, int)
            # is True and int(True) == 1 would silently accept it), not a
            # numeric string, and not a float (even a whole one, since a
            # float seq was never actually written by the recorder).
            if isinstance(raw_seq, bool) or not isinstance(raw_seq, int):
                raise TypeError("seq is not a real int")
            seq = raw_seq
            event = entry["event"]
            stored_prev = entry["prev_hash"]
            stored_entry = entry["entry_hash"]
            if not isinstance(event, dict):
                raise TypeError("event is not an object")
            if not isinstance(stored_prev, str) or not isinstance(stored_entry, str):
                raise TypeError("prev_hash/entry_hash are not strings")

            # The chain is defined to start at seq 1, so a missing prefix is a
            # gap too, not just a hole between consecutive rows (matches
            # Ledger.missing_ranges()'s definition of a gap).
            if prev_seq is None and seq > 1:
                gaps.append((1, seq - 1))
            elif prev_seq is not None and seq != prev_seq + 1:
                gaps.append((prev_seq + 1, seq - 1))

            # Link check uses the *stored* previous hash so that a single
            # tampered row is reported once, at its own seq, instead of
            # cascading.
            derived_entry = compute_entry_hash(stored_prev, seq, _event_digest(event))
            derived[seq] = derived_entry

            if stored_prev != prev_stored_hash or derived_entry != stored_entry:
                broken_links.append(seq)

            prev_seq = seq
            prev_stored_hash = stored_entry

            dev = event.get("device_id")
            if dev and dev not in device_ids:
                device_ids.append(str(dev))
            ses = event.get("session_id")
            if ses and ses not in session_ids:
                session_ids.append(str(ses))
            ts = event.get("ts_device")
            if ts:
                ts_values.append(str(ts))

            kind = event.get("kind")
            kind = kind.value if isinstance(kind, EventKind) else kind
            tuid = event.get("tool_use_id")
            if tuid:
                if kind == EventKind.TOOL_USE.value and tuid not in tool_uses:
                    tool_uses[str(tuid)] = seq
                elif kind == EventKind.TOOL_RESULT.value and tuid not in tool_results:
                    tool_results[str(tuid)] = seq

            if have_starting_key:
                # The live-timeline path (a starting/pinned key was
                # supplied): any non-rotation entry not attributed to the
                # currently-active device is a finding, decided purely from
                # seq order (the walk's own active_id), never from the
                # payload's own claims.
                if kind != EventKind.KEY_ROTATED.value and dev and str(dev) != active_id:
                    stale_key_usage.append(seq)
            else:
                # Legacy path (no starting key): a device_id change
                # immediately after a KEY_ROTATED event is the *point* of
                # cross-signing continuity, not tampering — so this only
                # flags entries still attributed to a device whose key was
                # already retired. The KEY_ROTATED event itself is the last
                # thing signed by the OLD device_id (see rotation.py), so it
                # must not be flagged — only entries *after* it (seq
                # strictly greater than the rotation event's own seq) that
                # still carry the retired device_id are stale. This is
                # decided purely from seq, the trusted append order, never
                # from the device-controlled ts_device.
                if dev and dev in retired_devices and seq > retired_devices[dev]:
                    stale_key_usage.append(seq)

            if kind == EventKind.KEY_ROTATED.value:
                raw_payload = event.get("payload")
                # A key_rotated event's payload is a dict of claims
                # (old/new device_id, new_public_key, cross_signature, ...)
                # that _check_rotation/_check_rotation_live call .get() on.
                # A malformed payload (str, list, ...) must not crash the
                # walk — treat it as an empty/unsubstantiated claim, which
                # both rotation checkers already handle as "fails to verify".
                payload = raw_payload if isinstance(raw_payload, dict) else {}
                if not isinstance(raw_payload, dict) and raw_payload is not None:
                    malformed.append(
                        f"malformed_bundle: key_rotated payload at seq {seq} is not "
                        "an object, treated as empty"
                    )
                if have_starting_key:
                    rotation = _check_rotation_live(payload, active_key, active_id, dev)
                    rotation["seq"] = seq
                    key_rotations.append(rotation)
                    new_id = rotation.get("new_device_id")
                    new_key = rotation.get("new_public_key")
                    if rotation.get("valid"):
                        active_key = new_key
                        active_id = new_id
                    else:
                        notes.append(
                            f"key rotation at seq {seq} ({rotation.get('old_device_id')} "
                            f"-> {new_id}): REJECTED — does not match the key/id "
                            "actually active at this point in the chain (forged or "
                            "attempted re-rotation from a retired key); the active "
                            "key/id are unchanged"
                        )
                    pinned = device_public_keys.get(str(new_id)) if new_id else None
                    if (
                        pinned is not None
                        and isinstance(new_key, str)
                        and pinned != new_key
                    ):
                        notes.append(
                            f"device_public_keys entry for {new_id} disagrees with "
                            "the key timeline established by the chain walk — "
                            "device_public_keys is ignored for rotation validity"
                        )
                else:
                    rotation = _check_rotation(payload, device_public_keys)
                    rotation["seq"] = seq
                    key_rotations.append(rotation)
                    old_id = rotation.get("old_device_id")
                    if old_id:
                        retired_devices[str(old_id)] = seq
        except (KeyError, TypeError, ValueError) as exc:
            malformed.append(f"malformed_bundle: entry skipped, {exc}")
            continue

    unpaired_tool_uses = sorted(t for t in tool_uses if t not in tool_results)
    orphan_tool_results = sorted(
        t
        for t, result_seq in tool_results.items()
        if t not in tool_uses or tool_uses[t] > result_seq
    )

    for rotation in key_rotations:
        old_id = rotation.get("old_device_id")
        seq_note = f"key rotation {old_id} -> {rotation.get('new_device_id')}"
        if rotation["cross_signature_verified"] is None:
            notes.append(
                f"{seq_note}: cross-signature NOT checked — rerun with the old "
                "device's public key to verify continuity"
            )
        elif not rotation["cross_signature_verified"]:
            notes.append(f"{seq_note}: cross-signature does NOT verify")
        if rotation.get("device_id_matches_public_key") is False:
            notes.append(
                f"{seq_note}: new_device_id does not match "
                "derive_device_id(new_public_key) — the claimed id is not "
                "actually derived from the key it is paired with"
            )

    return _ChainWalk(
        entries_checked=entries_checked,
        broken_links=broken_links,
        gaps=gaps,
        device_ids=device_ids,
        session_ids=session_ids,
        ts_values=ts_values,
        unpaired_tool_uses=unpaired_tool_uses,
        orphan_tool_results=orphan_tool_results,
        key_rotations=key_rotations,
        stale_key_usage=stale_key_usage,
        derived=derived,
        notes=notes,
        malformed=malformed,
    )


def _verify(
    conn: sqlite3.Connection,
    public_key_b64: str | None,
    device_public_keys: dict[str, str],
) -> VerifyReport:
    all_columns = _columns(conn, "agent_events")
    if not all_columns:
        raise VerifyError("ledger has no agent_events table")
    event_columns = [c for c in all_columns if c not in _CHAIN_COLUMNS]

    rows = conn.execute("SELECT * FROM agent_events ORDER BY seq ASC").fetchall()
    entries: list[dict[str, Any]] = []
    row_malformed: list[str] = []
    for row in rows:
        # A corrupted row (e.g. a payload column that isn't valid JSON) must
        # not raise out of the whole verification pass — _row_to_event_dict
        # does a bare json.loads with no guard of its own, so wrap it here.
        # An entry that can't even be reconstructed is reported as malformed
        # and skipped, exactly like _walk_chain's own per-entry handling of
        # a malformed entry it receives.
        try:
            event = _row_to_event_dict(row, event_columns)
        except (ValueError, TypeError) as exc:
            seq = row["seq"] if "seq" in row.keys() else "?"
            row_malformed.append(f"malformed_bundle: ledger row at seq {seq} skipped, {exc}")
            continue
        entries.append(
            {
                "seq": row["seq"],
                "prev_hash": row["prev_hash"],
                "entry_hash": row["entry_hash"],
                "event": event,
            }
        )

    walk = _walk_chain(entries, device_public_keys, starting_public_key_b64=public_key_b64)
    walk.malformed = [*row_malformed, *walk.malformed]

    no_signed_checkpoints = False
    unreadable_checkpoints = False
    unsigned_tail: tuple[int, int] | None = None

    try:
        checkpoints, bad_row_seq_ends, bad_row_notes = _checkpoint_rows(conn)
    except (sqlite3.DatabaseError, ValueError) as exc:
        # The checkpoint TABLE itself could not even be read (as opposed to
        # an individual row's body being bad JSON, which _checkpoint_rows
        # already handles per-row). A caller who pinned a public key asked
        # for every checkpoint to be signature-checked — being unable to
        # read the table at all must not silently pass that request.
        checkpoints = []
        bad_row_seq_ends = []
        bad_row_notes = [f"checkpoint table unreadable: {exc}"]
        if public_key_b64 is not None:
            unreadable_checkpoints = True

    if not checkpoints and not bad_row_notes and public_key_b64 is not None:
        # A ledger with zero checkpoint rows at all — nothing is
        # signature-checked, and unlike the "no --pubkey supplied" case
        # (handled as a note inside _verify_checkpoints) this is a request
        # for verification that could not be honored, so it must fail ok.
        no_signed_checkpoints = True

    if checkpoints:
        bad_signatures, checkpoints_checked, cp_notes = _verify_checkpoints(
            checkpoints, walk.derived, public_key_b64, walk.key_rotations
        )
    elif bad_row_notes:
        # Every row present was unreadable — don't also emit
        # _verify_checkpoints' generic "no checkpoints present" note, which
        # would misleadingly suggest there were no rows at all.
        bad_signatures, checkpoints_checked, cp_notes = [], 0, []
    else:
        bad_signatures, checkpoints_checked, cp_notes = _verify_checkpoints(
            [], walk.derived, public_key_b64, walk.key_rotations
        )
    bad_signatures = [*bad_row_seq_ends, *bad_signatures]
    cp_notes = [*bad_row_notes, *cp_notes]

    if public_key_b64 is not None and checkpoints:
        # Entries after the last checkpoint's seq_end are never covered by
        # any signature — informational on the ledger path (a *live*
        # ledger always has such a tail, since the newest events haven't
        # been checkpointed yet), but worth surfacing so a caller pinning a
        # key knows exactly how far the signed coverage actually reaches.
        last_seq_end = max(_safe_seq_end(cp.get("seq_end", -1)) for cp in checkpoints)
        tail_seqs = sorted(s for s in walk.derived if s > last_seq_end)
        if tail_seqs:
            unsigned_tail = (tail_seqs[0], tail_seqs[-1])
            cp_notes.append(
                f"unsigned_tail: entries seq {tail_seqs[0]}-{tail_seqs[-1]} come "
                f"after the last checkpoint (seq_end={last_seq_end}) — covered "
                "only by the hash chain, not a signature"
            )

    notes = [*walk.notes, *cp_notes, *walk.malformed]

    forged_rotations = _forged_rotations(walk.key_rotations)

    ok = not (
        walk.broken_links
        or bad_signatures
        or walk.gaps
        or walk.orphan_tool_results
        or walk.stale_key_usage
        or forged_rotations
        or walk.malformed
        or no_signed_checkpoints
        or unreadable_checkpoints
    )

    return VerifyReport(
        ok=ok,
        entries_checked=walk.entries_checked,
        broken_links=walk.broken_links,
        bad_signatures=bad_signatures,
        gaps=walk.gaps,
        unpaired_tool_uses=walk.unpaired_tool_uses,
        orphan_tool_results=walk.orphan_tool_results,
        device_ids=walk.device_ids,
        session_ids=walk.session_ids,
        seq_start=int(entries[0]["seq"]) if entries else None,
        seq_end=int(entries[-1]["seq"]) if entries else None,
        ts_first=min(walk.ts_values) if walk.ts_values else None,
        ts_last=max(walk.ts_values) if walk.ts_values else None,
        checkpoints_checked=checkpoints_checked,
        signatures_verified=bool(public_key_b64) and checkpoints_checked > 0,
        notes=notes,
        key_rotations=walk.key_rotations,
        stale_key_usage=walk.stale_key_usage,
        no_signed_checkpoints=no_signed_checkpoints,
        unreadable_checkpoints=unreadable_checkpoints,
        unsigned_tail=unsigned_tail,
    )


def _checkpoint_rows(
    conn: sqlite3.Connection,
) -> tuple[list[dict[str, Any]], list[int], list[str]]:
    """Parse every row of the ``checkpoints`` table.

    Each row is parsed independently: a single corrupted row (bad JSON in
    ``body``, a non-object body, ...) must not disable checking of every
    OTHER checkpoint in the ledger — it is reported as its own failed
    checkpoint (in the returned seq_end list and notes) and skipped, while
    the rest are still returned for :func:`_verify_checkpoints` to check
    normally. This function itself never raises on row content.
    """
    columns = _columns(conn, "checkpoints")
    if not columns:
        return [], [], []
    rows = conn.execute("SELECT * FROM checkpoints").fetchall()
    out: list[dict[str, Any]] = []
    bad_seq_ends: list[int] = []
    bad_notes: list[str] = []
    for row in rows:
        row_seq_end = row["seq_end"] if "seq_end" in row.keys() else None
        try:
            # The only schema this codebase writes stores each checkpoint as
            # a JSON blob in a `body` column (see ledger.py's _SCHEMA). Fall
            # back to reconstructing one from raw columns only for a ledger
            # written by some other schema shape, not a case any writer here
            # produces.
            if "body" in columns and row["body"]:
                cp = json.loads(row["body"])
            else:
                cp = {k: row[k] for k in columns if k not in {"id", "rowid"}}
            if not isinstance(cp, dict):
                raise ValueError(f"checkpoint body is a {type(cp).__name__}, not an object")
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            bad_seq_ends.append(_safe_seq_end(row_seq_end))
            bad_notes.append(
                f"checkpoint row (seq_end={row_seq_end!r}) could not be parsed and is "
                f"treated as a failed checkpoint: {exc}"
            )
            continue
        out.append(cp)
    out.sort(key=lambda c: _safe_seq_end(c.get("seq_end", -1)))
    return out, bad_seq_ends, bad_notes


def _build_key_timeline(
    initial_key_b64: str, key_rotations: list[dict[str, Any]]
) -> tuple[list[tuple[int, str]], list[str]]:
    """Build the device key active at each point in the chain
    (``docs/seal-format.md`` §11.2).

    Level 2 used to check every checkpoint against one pinned key, which
    cannot pass after a rotation — the checkpoints before the rotation are
    signed with the old key, the ones after with the new one. This builds a
    timeline instead: start with ``initial_key_b64``, and at each
    ``key_rotated`` entry whose cross-signature VERIFIED, the active key
    becomes that rotation's ``new_public_key`` from its own ``seq`` onward
    (the rotation event itself, and everything up to and including it, is
    still signed by the OLD key — see ``docs/seal-format.md`` §7 and rotation.py, the
    rotation event is "the last event the old identity writes").

    A rotation whose cross-signature could NOT be verified (no old key
    supplied, or a forged cross-signature) does *not* extend the timeline:
    later checkpoints keep being checked against the last known-good key,
    matching the old single-key behaviour for everything after an
    unverifiable handover, plus a note explaining why.

    Returns ``(timeline, notes)``. ``timeline`` is a list of
    ``(seq_threshold, key_b64)`` pairs sorted ascending by ``seq_threshold``
    (the first entry is always ``(0, initial_key_b64)``, since every real
    seq is >= 1).
    """
    timeline: list[tuple[int, str]] = [(0, initial_key_b64)]
    notes: list[str] = []
    for r in key_rotations:
        seq = r.get("seq")
        new_key = r.get("new_public_key")
        if r.get("cross_signature_verified") is True and isinstance(new_key, str):
            timeline.append((int(seq), new_key))
        else:
            notes.append(
                f"key rotation at seq {seq} ({r.get('old_device_id')} -> "
                f"{r.get('new_device_id')}): cross-signature not verified — "
                "checkpoints after this point are still checked against the "
                "previously active key (supply the old device's public key "
                "to verify continuity across this rotation)"
            )
    return timeline, notes


def _key_active_at(timeline: list[tuple[int, str]], seq_end: int) -> str:
    """The key active for a checkpoint whose ``seq_end`` is given, per the
    timeline built by :func:`_build_key_timeline`."""
    active = timeline[0][1]
    for seq_threshold, key in timeline[1:]:
        if seq_end > seq_threshold:
            active = key
        else:
            break
    return active


def _verify_checkpoints(
    checkpoints: list[dict[str, Any]],
    derived: dict[int, str],
    public_key_b64: str | None,
    key_rotations: list[dict[str, Any]] | None = None,
) -> tuple[list[int], int, list[str]]:
    bad: list[int] = []
    notes: list[str] = []

    if not checkpoints:
        return [], 0, ["no checkpoints present in this ledger"]

    timeline: list[tuple[int, str]] | None = None
    if public_key_b64 is None:
        notes.append(
            f"{len(checkpoints)} checkpoint(s) present but NOT signature-checked "
            "— rerun with --pubkey to verify device signatures"
        )
    else:
        timeline, timeline_notes = _build_key_timeline(public_key_b64, key_rotations or [])
        notes.extend(timeline_notes)

    for cp in checkpoints:
        raw_seq_end = cp.get("seq_end", -1)
        # seq_end is used as a dict key against derived[] and to select the
        # active key from the rotation timeline, so it must be a genuine
        # int. int("abc")/int(None) raise, and this whole function must
        # never raise on untrusted checkpoint data — a checkpoint with an
        # unusable seq_end is reported as a failed checkpoint instead.
        if isinstance(raw_seq_end, bool) or not isinstance(raw_seq_end, int):
            bad.append(raw_seq_end if isinstance(raw_seq_end, int) else -1)
            notes.append(
                f"checkpoint has invalid seq_end ({raw_seq_end!r}): not a real int, "
                "treated as failed"
            )
            continue
        seq_end = raw_seq_end
        failed = False

        sig = cp.get("sig")
        if public_key_b64 is not None:
            active_key = _key_active_at(timeline, seq_end)  # type: ignore[arg-type]
            unsigned = {k: v for k, v in cp.items() if k != "sig"}
            try:
                canonical_unsigned = canonicalize(unsigned)
            except CanonicalizationError as exc:
                failed = True
                notes.append(
                    f"checkpoint ending at seq {seq_end}: cannot be canonicalized "
                    f"({exc}), treated as failed"
                )
            else:
                if not isinstance(sig, str) or not _verify_signature(
                    active_key, canonical_unsigned, sig
                ):
                    failed = True
                    notes.append(f"checkpoint ending at seq {seq_end}: signature does not verify")
        elif not isinstance(sig, str):
            failed = True
            notes.append(f"checkpoint ending at seq {seq_end}: missing signature")

        head = cp.get("chain_head")
        expected = derived.get(seq_end)
        if expected is None:
            failed = True
            notes.append(f"checkpoint ending at seq {seq_end}: no such entry in the ledger")
        elif head != expected:
            failed = True
            notes.append(
                f"checkpoint ending at seq {seq_end}: chain head does not match the "
                "hash re-derived from the stored entries"
            )

        if failed:
            bad.append(seq_end)

    return bad, len(checkpoints), notes


def _safe_seq_end(raw: Any) -> int:
    """Coerce a checkpoint's ``seq_end`` to int without ever raising.

    Rejects bool (an int subclass) the same way :func:`_walk_chain` rejects
    a bool ``seq`` — a load-bearing sequence number is never legitimately a
    boolean. Anything else that isn't already a real int falls back to -1,
    which never matches a real derived seq and so never spuriously "covers"
    entries it shouldn't.
    """
    if isinstance(raw, bool) or not isinstance(raw, int):
        return -1
    return raw


_EPOCH_SIGNED_FIELDS = ("epoch_index", "root", "epoch_start", "epoch_end", "tenant_id")


def _verify_epoch_signature(epoch: dict[str, Any]) -> bool | None:
    """Check an epoch root's tenant-KMS signature
    (``docs/seal-format.md`` §9.4).

    Returns ``None`` — not checked, not failed — when the bundle carries no
    ``tenant_sig``/``tenant_kms_public_key_b64`` for this epoch, matching the
    existing "not checked" convention used for checkpoints without a
    supplied public key. Uses the same Ed25519 primitive as everything else
    in this codebase; a tenant KMS that signs with something else needs its
    own verifier, not a change here.
    """
    sig = epoch.get("tenant_sig")
    public_key_b64 = epoch.get("tenant_kms_public_key_b64")
    if not isinstance(sig, str) or not isinstance(public_key_b64, str):
        return None
    signed_fields = {k: epoch.get(k) for k in _EPOCH_SIGNED_FIELDS}
    return _verify_signature(public_key_b64, canonicalize(signed_fields), sig)


def _verify_anchor(
    anchor_type: str,
    receipt: dict[str, Any],
    epoch: dict[str, Any],
    rekor_public_key_b64: str | None,
    tsa_trusted_roots_pem: list[str] | None = None,
) -> tuple[bool, list[str]]:
    """Dispatch to the right external anchor verifier
    (``docs/seal-format.md`` §10).

    Imported lazily for the same reason ``_verify_signature`` imports
    ``keys`` lazily: callers who never verify anchors shouldn't be forced to
    install ``rfc3161ng``.
    """
    from byoai.recorder import anchor as anchor_module

    if not isinstance(receipt, dict):
        return False, [f"cannot verify anchor: receipt is not an object ({type(receipt).__name__})"]

    try:
        epoch_root = bytes.fromhex(epoch["root"])
    except (KeyError, ValueError) as exc:
        return False, [f"cannot verify anchor: epoch root is missing/malformed ({exc})"]

    if anchor_type == "rfc3161_tsa":
        return anchor_module.verify_rfc3161_receipt(
            receipt, epoch_root, tsa_trusted_roots_pem=tsa_trusted_roots_pem
        )
    if anchor_type == "sigstore_rekor":
        inclusion = receipt.get("inclusion_proof") or {}
        flat_receipt = {
            **inclusion,
            "signed_entry_timestamp": receipt.get("signed_entry_timestamp"),
        }
        return anchor_module.verify_rekor_receipt(
            flat_receipt, epoch_root, rekor_public_key_b64=rekor_public_key_b64
        )
    return False, [f"unknown anchor type {anchor_type!r} — cannot verify"]


@dataclass
class BundleVerifyReport:
    """Result of verifying an examiner export bundle (``docs/seal-format.md``
    §13.2), covering §11 levels 1-4: chain, checkpoint signatures,
    checkpoint-to-epoch inclusion, tenant epoch-root signature, and (when
    ``check_anchors`` is set) the external anchor receipt. An anchor of type
    ``"none"`` is legitimately unanchored, not a failure — see
    :func:`verify_bundle`."""

    ok: bool
    entries_checked: int
    broken_links: list[int]
    bad_checkpoint_signatures: list[int]
    bad_inclusions: list[int]  # checkpoint seq_end values whose proof did not verify
    bad_epoch_signatures: list[int]  # epoch_index values whose tenant_sig did not verify
    gaps: list[tuple[int, int]]
    unpaired_tool_uses: list[str]
    orphan_tool_results: list[str]
    device_ids: list[str] = field(default_factory=list)
    session_ids: list[str] = field(default_factory=list)
    checkpoints_checked: int = 0
    inclusions_checked: int = 0
    epoch_signatures_checked: int = 0
    anchors_checked: int = 0
    bad_anchors: list[int] = field(default_factory=list)  # epoch_index values whose anchor failed
    key_rotations: list[dict[str, Any]] = field(default_factory=list)
    stale_key_usage: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    # Key pinning (seal-format §11.4): set when the caller supplied
    # pinned_device_public_key_b64 and the bundle's own device key differs.
    device_key_mismatch: bool = False
    # epoch_index values whose tenant_kms_public_key_b64 was not in the
    # caller-supplied pinned_tenant_public_keys_b64 set.
    tenant_key_mismatches: list[int] = field(default_factory=list)
    # Reasons a malformed bundle item (bad shape/type, not a signature or
    # hash failure) was skipped rather than raising.
    malformed_bundle: list[str] = field(default_factory=list)
    # Pinning hardening (seal-format §11.2): when pinned_device_public_key_b64 is supplied,
    # entries whose seq comes after the last checkpoint's seq_end are never
    # covered by any signed checkpoint at all. Each tuple is an inclusive
    # (first_seq, last_seq) range of such entries.
    unsigned_tail: list[tuple[int, int]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["gaps"] = [list(g) for g in self.gaps]
        data["unsigned_tail"] = [list(r) for r in self.unsigned_tail]
        return data


def verify_bundle(
    bundle: dict[str, Any],
    *,
    device_public_keys: dict[str, str] | None = None,
    check_anchors: bool = True,
    rekor_public_key_b64: str | None = None,
    pinned_device_public_key_b64: str | None = None,
    pinned_tenant_public_keys_b64: Iterable[str] | None = None,
    require_pinned_anchors: bool = False,
    tsa_trusted_roots_pem: list[str] | None = None,
) -> BundleVerifyReport:
    """Offline verification of an examiner export bundle
    (``docs/seal-format.md`` §13.2).

    Re-runs the same chain walk as :func:`verify_ledger`, over
    ``bundle["entries"]`` instead of a SQLite cursor, then re-checks every
    checkpoint's signature, its inclusion proof against ``bundle["epochs"]``,
    each epoch's tenant signature, and — when ``check_anchors`` is set and an
    epoch's ``anchor.type`` is not ``"none"`` — that epoch's external anchor
    receipt (RFC 3161 TSA or Sigstore Rekor, via ``anchor.py``). This covers
    every level of ``docs/seal-format.md`` §11. An epoch with
    ``anchor.type == "none"`` is legitimately unanchored, not a failure, and
    is noted as such rather than silently treated as passing.

    A bundle carries its own device key and tenant key(s) (§13.2): by
    default this only proves the bundle is internally consistent, not who
    wrote it. Passing ``pinned_device_public_key_b64`` and/or
    ``pinned_tenant_public_keys_b64`` (device_key_mismatch /
    tenant_key_mismatches findings on mismatch) closes that gap for a caller
    who obtained those keys some other way (seal-format §11.4).

    ``require_pinned_anchors=True`` turns an anchor that could only be
    checked against its own claims — a Rekor receipt with no
    ``rekor_public_key_b64``, or an RFC 3161 token whose chain wasn't checked
    against ``tsa_trusted_roots_pem`` — into a finding instead of a note.

    Malformed bundle shapes (missing ``epoch_index``, bad ``steps`` hex, a
    missing ``checkpoint``, wrong types, ...) are reported in
    ``malformed_bundle`` and never raise: this function's whole job
    is validating untrusted input.
    """
    if not isinstance(bundle, dict):
        # The bundle itself has the wrong shape entirely (e.g. a list or a
        # scalar) — there is nothing to walk at all. Report it as a totally
        # malformed bundle rather than raising on the first .get() call.
        return BundleVerifyReport(
            ok=False,
            entries_checked=0,
            broken_links=[],
            bad_checkpoint_signatures=[],
            bad_inclusions=[],
            bad_epoch_signatures=[],
            gaps=[],
            unpaired_tool_uses=[],
            orphan_tool_results=[],
            malformed_bundle=["malformed_bundle: bundle is not an object"],
        )
    device_obj = bundle.get("device")
    device_obj = device_obj if isinstance(device_obj, dict) else {}
    public_key_b64 = device_obj.get("public_key_b64")

    entries = bundle.get("entries", [])
    if not isinstance(entries, list):
        entries = []

    # The live rotation-timeline walk must never trust a key read out of the
    # bundle itself (device_obj["public_key_b64"] is exactly the untrusted
    # claim that pinning exists to avoid) — only a caller-supplied pinned key
    # counts as a "starting key" here. Without one, this keeps the original,
    # note-based "can't verify rotations" behaviour, just as other unpinned
    # calls do.
    walk = _walk_chain(
        entries,
        device_public_keys or {},
        starting_public_key_b64=pinned_device_public_key_b64,
    )

    malformed_bundle: list[str] = list(walk.malformed)

    device_key_mismatch = False
    if pinned_device_public_key_b64 is not None and public_key_b64 != pinned_device_public_key_b64:
        device_key_mismatch = True

    pinned_tenant_keys = (
        set(pinned_tenant_public_keys_b64) if pinned_tenant_public_keys_b64 is not None else None
    )

    raw_bundle_checkpoints = bundle.get("checkpoints", [])
    if not isinstance(raw_bundle_checkpoints, list):
        raw_bundle_checkpoints = []
        malformed_bundle.append("malformed_bundle: 'checkpoints' is not a list, treated as empty")

    bundle_checkpoints: list[dict[str, Any]] = []
    for bc in raw_bundle_checkpoints:
        if not isinstance(bc, dict) or not isinstance(bc.get("checkpoint"), dict):
            malformed_bundle.append(
                "malformed_bundle: a bundle checkpoint entry is missing a valid "
                "'checkpoint' object, skipped"
            )
            continue
        bundle_checkpoints.append(bc)

    unsigned_tail: list[tuple[int, int]] = []
    if pinned_device_public_key_b64 is not None:
        # Pinning hardening (seal-format §11.2): a caller who pins the device key is asking
        # for every entry to actually be covered by a signed checkpoint.
        # Zero checkpoints means nothing at all is signature-checked; any
        # entries after the last checkpoint's seq_end are a silent gap in
        # coverage a bundle could otherwise pad with unsigned tail entries.
        if not bundle_checkpoints:
            malformed_bundle.append(
                "pinned_device_public_key_b64 was supplied but this bundle has "
                "zero checkpoints — nothing is actually signature-checked"
            )
        else:
            last_seq_end = max(
                _safe_seq_end(bc["checkpoint"].get("seq_end", -1)) for bc in bundle_checkpoints
            )
            tail_seqs = sorted(s for s in walk.derived if s > last_seq_end)
            if tail_seqs:
                unsigned_tail = [(tail_seqs[0], tail_seqs[-1])]
                malformed_bundle.append(
                    f"pinned_device_public_key_b64 was supplied but entries seq "
                    f"{tail_seqs[0]}-{tail_seqs[-1]} come after the last "
                    f"checkpoint (seq_end={last_seq_end}) and are never covered "
                    "by a signed checkpoint (unsigned_tail)"
                )

    checkpoints = [bc["checkpoint"] for bc in bundle_checkpoints]
    bad_signatures, checkpoints_checked, cp_notes = _verify_checkpoints(
        checkpoints, walk.derived, public_key_b64, walk.key_rotations
    )

    raw_epochs = bundle.get("epochs", [])
    if not isinstance(raw_epochs, list):
        raw_epochs = []
        malformed_bundle.append("malformed_bundle: 'epochs' is not a list, treated as empty")

    epoch_roots: dict[int, bytes] = {}
    epoch_notes: list[str] = []
    for epoch in raw_epochs:
        try:
            if not isinstance(epoch, dict):
                raise TypeError("epoch entry is not an object")
            epoch_roots[epoch["epoch_index"]] = bytes.fromhex(epoch["root"])
        except (KeyError, TypeError, ValueError) as exc:
            # ``root`` is exactly what checkpoint inclusion proofs are
            # verified against and what an anchor receipt anchors — a bad
            # root is not merely "not checked", it's a malformed field that
            # matters, so it must fail `ok`, not just leave a note. This
            # holds regardless of the epoch's anchor.type (an unanchored
            # epoch with a corrupt root is still a corrupt epoch).
            malformed_bundle.append(
                f"malformed_bundle: epoch entry skipped ({exc})"
            )

    bad_inclusions: list[int] = []
    inclusions_checked = 0
    notes = [*walk.notes, *cp_notes, *epoch_notes]

    for bc in bundle_checkpoints:
        seq_end = -1
        try:
            seq_end = int(bc["checkpoint"].get("seq_end", -1))
            proof_json = bc.get("inclusion_proof")
            epoch_index = bc.get("epoch_index")

            if proof_json is None or epoch_index is None:
                notes.append(
                    f"checkpoint ending at seq {seq_end}: not yet anchored to an "
                    "epoch — inclusion not checked"
                )
                if pinned_tenant_keys is not None:
                    bad_inclusions.append(seq_end)
                    notes.append(
                        f"checkpoint ending at seq {seq_end}: "
                        "pinned_tenant_public_keys_b64 was supplied but this "
                        "checkpoint has no inclusion proof/epoch_index at all"
                    )
                continue

            root = epoch_roots.get(epoch_index)
            if root is None:
                bad_inclusions.append(seq_end)
                notes.append(
                    f"checkpoint ending at seq {seq_end}: references epoch "
                    f"{epoch_index}, which is not present in this bundle's epochs"
                )
                continue

            inclusions_checked += 1
            proof = InclusionProof(
                leaf_index=proof_json["leaf_index"],
                leaf_hash=checkpoint_leaf_hash(bc["checkpoint"]),
                steps=tuple(
                    ProofStep(sibling=bytes.fromhex(step["sibling"]), side=step["side"])
                    for step in proof_json["steps"]
                ),
                root=root,
            )
            if not verify_checkpoint_epoch_inclusion(bc["checkpoint"], proof, root):
                bad_inclusions.append(seq_end)
                notes.append(
                    f"checkpoint ending at seq {seq_end}: inclusion proof does not verify"
                )
        except (KeyError, TypeError, ValueError) as exc:
            malformed_bundle.append(
                f"malformed_bundle: bad checkpoint/inclusion-proof entry at seq "
                f"{seq_end}, skipped ({exc})"
            )
            if seq_end not in bad_inclusions:
                bad_inclusions.append(seq_end)

    bad_epoch_signatures: list[int] = []
    epoch_signatures_checked = 0
    bad_anchors: list[int] = []
    anchors_checked = 0
    tenant_key_mismatches: list[int] = []
    for epoch in raw_epochs:
        epoch_index = "?"
        try:
            epoch_index = epoch["epoch_index"]

            if pinned_tenant_keys is not None:
                tenant_key = epoch.get("tenant_kms_public_key_b64")
                if tenant_key not in pinned_tenant_keys:
                    tenant_key_mismatches.append(epoch_index)
                    notes.append(
                        f"epoch {epoch_index}: tenant_kms_public_key_b64 is not one "
                        "of the pinned tenant keys"
                    )

            verified = _verify_epoch_signature(epoch)
            if verified is None:
                notes.append(
                    f"epoch {epoch_index}: tenant signature NOT checked — bundle carries "
                    "no tenant_sig/tenant_kms_public_key_b64 for it"
                )
                if pinned_tenant_keys is not None:
                    bad_epoch_signatures.append(epoch_index)
                    notes.append(
                        f"epoch {epoch_index}: pinned_tenant_public_keys_b64 was "
                        "supplied but this epoch carries no tenant_sig at all"
                    )
            else:
                epoch_signatures_checked += 1
                if not verified:
                    bad_epoch_signatures.append(epoch_index)
                    notes.append(f"epoch {epoch_index}: tenant signature does NOT verify")

            raw_anchor = epoch.get("anchor")
            anchor = raw_anchor if isinstance(raw_anchor, dict) else {}
            if raw_anchor is not None and not isinstance(raw_anchor, dict):
                # A present-but-wrong-shaped anchor (e.g. a bare string) is
                # not the same claim as "no anchor at all" — silently
                # treating it as anchor.type == 'none' would let a corrupted
                # anchor field pass as legitimately unanchored. Malformed,
                # not a pass.
                malformed_bundle.append(
                    f"malformed_bundle: epoch {epoch_index} anchor is not an "
                    "object, treated as malformed"
                )
                bad_anchors.append(epoch_index)
                continue
            anchor_type = anchor.get("type", "none")
            if anchor_type == "none":
                notes.append(f"epoch {epoch_index}: no anchor (anchor.type == 'none')")
                if require_pinned_anchors:
                    bad_anchors.append(epoch_index)
                    notes.append(
                        f"epoch {epoch_index}: anchor.type == 'none' and "
                        "require_pinned_anchors=True"
                    )
                continue
            if not check_anchors:
                notes.append(
                    f"epoch {epoch_index}: anchor receipt ({anchor_type}) NOT verified — "
                    "check_anchors=False"
                )
                if require_pinned_anchors:
                    bad_anchors.append(epoch_index)
                    notes.append(
                        f"epoch {epoch_index}: check_anchors=False and "
                        "require_pinned_anchors=True"
                    )
                continue

            anchor_ok, anchor_notes = _verify_anchor(
                anchor_type,
                anchor.get("receipt") or {},
                epoch,
                rekor_public_key_b64,
                tsa_trusted_roots_pem,
            )
            anchors_checked += 1
            notes.extend(f"epoch {epoch_index}: anchor — {n}" for n in anchor_notes)

            # An anchor checked only against its own claims — no rekor key to
            # verify the SET, or no trusted root to check the RFC 3161 chain
            # against — normally just gets a note (seal-format §14 item 2: "an
            # unpinned anchor passes"). require_pinned_anchors turns that into a
            # finding instead, for a caller who wants the anchor to actually
            # prove something about an external log/authority they trust.
            unpinned_anchor = (
                anchor_type == "sigstore_rekor" and rekor_public_key_b64 is None
            ) or (anchor_type == "rfc3161_tsa" and not tsa_trusted_roots_pem)
            if not anchor_ok:
                bad_anchors.append(epoch_index)
            elif require_pinned_anchors and unpinned_anchor:
                bad_anchors.append(epoch_index)
                notes.append(
                    f"epoch {epoch_index}: anchor was not checked against a pinned "
                    "key/trusted root and require_pinned_anchors=True"
                )
        except (KeyError, TypeError, ValueError) as exc:
            malformed_bundle.append(
                f"malformed_bundle: bad epoch entry (epoch_index={epoch_index!r}), "
                f"skipped ({exc})"
            )

    forged_rotations = _forged_rotations(walk.key_rotations)

    ok = not (
        walk.broken_links
        or bad_signatures
        or bad_inclusions
        or bad_epoch_signatures
        or bad_anchors
        or walk.gaps
        or walk.orphan_tool_results
        or walk.stale_key_usage
        or forged_rotations
        or device_key_mismatch
        or tenant_key_mismatches
        or malformed_bundle
    )

    return BundleVerifyReport(
        ok=ok,
        entries_checked=walk.entries_checked,
        broken_links=walk.broken_links,
        bad_checkpoint_signatures=bad_signatures,
        bad_inclusions=bad_inclusions,
        bad_epoch_signatures=bad_epoch_signatures,
        anchors_checked=anchors_checked,
        bad_anchors=bad_anchors,
        gaps=walk.gaps,
        unpaired_tool_uses=walk.unpaired_tool_uses,
        orphan_tool_results=walk.orphan_tool_results,
        device_ids=walk.device_ids,
        session_ids=walk.session_ids,
        checkpoints_checked=checkpoints_checked,
        inclusions_checked=inclusions_checked,
        epoch_signatures_checked=epoch_signatures_checked,
        key_rotations=walk.key_rotations,
        stale_key_usage=walk.stale_key_usage,
        notes=notes,
        device_key_mismatch=device_key_mismatch,
        tenant_key_mismatches=tenant_key_mismatches,
        malformed_bundle=malformed_bundle,
        unsigned_tail=unsigned_tail,
    )
