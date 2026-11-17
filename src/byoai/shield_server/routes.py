"""HTTP routes: device routes (enrol, checkpoints, policy poll, public keys)
and the admin API (tokens, devices, policy authoring, drift) behind the
bearer admin token.

Wire shapes are pinned to match Coriqo's managed mode exactly — the released
``shield_publish.Publisher`` reads these responses and must work unchanged.
"""

from __future__ import annotations

import json
import time
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, status

from byoai.ingest import (
    CheckpointConflict,
    DeviceRevoked,
    Enrolment,
    EnrolmentRefused,
    IngestStore,
    MalformedEntry,
    SeqConflict,
    UnknownDeviceError,
)
from byoai.recorder.keys import derive_device_id
from byoai.shield_server import auth
from byoai.shield_server import policy as policy_mod
from byoai.shield_server.config import ShieldServerConfig
from byoai.shield_server.store import PolicyRow, ServerStore, hash_token

__all__ = ["build_admin_router", "build_device_router"]


# --------------------------------------------------------------------- device


def build_device_router(cfg: ShieldServerConfig, ingest: IngestStore, store: ServerStore,
                        signer: policy_mod.PolicySigner) -> APIRouter:
    router = APIRouter(tags=["device"])

    @router.post("/v1/enroll", status_code=201)
    async def enroll(body: dict = Body(...)) -> dict[str, Any]:
        public_key_b64 = body.get("public_key")
        token = body.get("token")
        if not isinstance(public_key_b64, str) or not public_key_b64.strip():
            raise HTTPException(status_code=400, detail="public_key is required")
        if not isinstance(token, str) or not token.strip():
            raise HTTPException(status_code=401, detail="Invalid or expired enrolment token.")
        try:
            device_id = derive_device_id(public_key_b64)
        except Exception:  # noqa: BLE001
            raise HTTPException(status_code=400, detail="public_key must be base64.") from None

        ok, reason, label = store.redeem_token(token, device_id=device_id)
        if not ok:
            # One message for every failure — unknown, expired, revoked,
            # already redeemed — so a caller cannot enumerate which guesses
            # were "close".
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Invalid or expired enrolment token.")
        try:
            ingest.record_enrolment(Enrolment(
                device_id=device_id, tenant_slug=cfg.org, public_key_b64=public_key_b64,
                enrolled_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            ))
        except EnrolmentRefused as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

        # Carry the enrolment token's label onto the device (first row for
        # this device_id, so this always takes — see
        # ServerStore.record_shield_state's INSERT branch), so the admin
        # device list shows what the token was minted for instead of the id.
        store.record_shield_state(device_id, None, label=label)

        return {
            "device_id": device_id,
            "coriqo_base_url": cfg.public_url.rstrip("/"),
            "tenant_slug": cfg.org,
            "label": label or device_id,
            "enrolled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "policy_key": {"key_id": signer.key_id, "public_key": signer.public_key_hex},
        }

    async def _authenticate(sr: auth.SignedRequest) -> tuple[str, dict]:
        """Shared device-signed-body auth for the two checkpoint/policy
        routes: look up the asserted device's pinned public key, verify the
        signature over the decompressed body (already read and
        size-capped by :func:`auth.read_signed_request`), and only then
        reject a revoked device.

        Order matters: an unknown device_id and a bad signature on a real
        (even revoked) device must be indistinguishable to the caller — same
        status, same detail — or a probe with garbage signatures could
        enumerate which device ids actually exist. "Revoked" is reported
        only once the signature has proven the caller genuinely holds that
        device's key; the released client relies on exactly that state to
        show "Coriqo refused this Mac".
        """
        device_id = sr.device_id
        row = ingest.enrolment_row(device_id)
        public_key_b64 = row["public_key_b64"] if row is not None else None
        sig_ok = public_key_b64 is not None and auth.verify_against_key(
            public_key_b64, sr.body, sr.signature)
        if row is None or not sig_ok:
            raise HTTPException(status_code=401, detail="Device signature did not verify.")
        if row["revoked_at"] is not None:
            raise HTTPException(status_code=401, detail="This device has been revoked.")
        try:
            body = json.loads(sr.body)
        except ValueError:
            raise HTTPException(status_code=400, detail="Body is not valid JSON.") from None
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="Body must be a JSON object.")
        return device_id, body

    @router.post("/v1/checkpoints/batch")
    async def checkpoints_batch(
        sr: auth.SignedRequest = Depends(auth.read_signed_request),
    ) -> dict[str, Any]:
        device_id, body = await _authenticate(sr)
        try:
            auth.check_sent_at(body.get("sent_at"))
        except auth.StaleRequest as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        checkpoints = body.get("checkpoints")
        if not isinstance(checkpoints, list):
            raise HTTPException(status_code=400, detail="checkpoints must be a list.")
        # The released shipper's checkpoint entries (see
        # shield_publish.Publisher._build_entry) name the chain root
        # "chain_hash"; IngestStore's own checkpoint schema (built for
        # Coriqo's ledger checkpoints) calls the same field "chain_head".
        # Translate at the boundary rather than rename either side.
        normalized = []
        for cp in checkpoints:
            if not isinstance(cp, dict):
                raise HTTPException(status_code=400,
                                    detail="each checkpoint must be an object.")
            normalized.append({**cp, "chain_head": cp.get("chain_hash", cp.get("chain_head"))})

        # Mirrors Coriqo's own posture exactly (see
        # runtime_router._checkpoints_batch, read-only reference): a batch
        # that can't be stored is refused outright — 400 for a malformed or
        # conflicting batch, 401 for a device that can no longer write at
        # all — never accepted with a per-item "malformed" placeholder. The
        # released Publisher only advances its outbox on a 2xx; collapsing a
        # real refusal into a fake 200 with accepted=0 would make it believe
        # this checkpoint was handled and move on, silently losing it.
        try:
            result = ingest.accept_checkpoints(device_id, normalized)
        except DeviceRevoked as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except UnknownDeviceError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except (MalformedEntry, SeqConflict, CheckpointConflict) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        store.record_shield_state(device_id, body.get("shield"))

        return {"accepted": result.accepted, "duplicates": result.duplicates,
               "rejected": [], "malformed": []}

    @router.post("/v1/shield/policy")
    async def shield_policy(
        sr: auth.SignedRequest = Depends(auth.read_signed_request),
    ) -> dict[str, Any]:
        device_id, body = await _authenticate(sr)
        try:
            auth.check_sent_at(body.get("sent_at"))
        except auth.StaleRequest as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        have_version = body.get("have_version")
        if have_version is not None and (not isinstance(have_version, int)
                                         or isinstance(have_version, bool)):
            raise HTTPException(status_code=400, detail="have_version must be an integer.")

        row = policy_mod.resolve_effective(store, device_id=device_id)
        if row is None:
            return {"changed": False, "version": None}
        version = row.document.get("version")
        if have_version is not None and have_version == version:
            return {"changed": False, "version": version}
        return {"changed": True, "envelope": policy_mod.as_envelope(row)}

    @router.get("/api/v1/checkpoints/public-keys")
    async def public_keys() -> dict[str, Any]:
        return {"keys": [{
            "key_id": signer.key_id,
            "public_key_pem": signer.public_key_pem(),
            "revoked": False,
            "active": True,
        }]}

    return router


# ---------------------------------------------------------------------- admin


def build_admin_router(cfg: ShieldServerConfig, ingest: IngestStore, store: ServerStore,
                       signer: policy_mod.PolicySigner) -> APIRouter:
    router = APIRouter(prefix="/api/v1/shield", tags=["admin"])

    def _require_admin(authorization: str | None = Header(None)) -> None:
        auth.check_admin_token(authorization, expected=cfg.admin_token)

    # -- tokens -------------------------------------------------------------

    def _token_wire(r) -> dict[str, Any]:
        """The console's token shape: a short, non-secret `token_id` (the
        hash's own first 12 hex chars — never the full hash, which stays
        internal to the store) and a plain boolean `revoked`."""
        return {
            "token_id": r.token_hash[:12],
            "label": r.label or "",
            "created_at": r.created_at,
            "expires_at": r.expires_at,
            "revoked": r.revoked_at is not None,
        }

    @router.post("/tokens", dependencies=[Depends(_require_admin)])
    async def mint_token(body: dict = Body(default={})) -> dict[str, Any]:
        label = body.get("label") if isinstance(body.get("label"), str) else None
        expires_at = body.get("expires_at") if isinstance(body.get("expires_at"), str) else None
        ttl = body.get("ttl_seconds")
        ttl_seconds = (float(ttl) if isinstance(ttl, (int, float)) and not isinstance(ttl, bool)
                      else None)
        token = store.mint_token(label=label, ttl_seconds=ttl_seconds, expires_at=expires_at)
        row = store.find_token_by_hash(hash_token(token))
        assert row is not None  # just minted, under the same store instance
        return {**_token_wire(row), "token": token}

    @router.get("/tokens", dependencies=[Depends(_require_admin)])
    async def list_tokens() -> dict[str, Any]:
        return {"tokens": [_token_wire(r) for r in store.list_tokens()]}

    @router.delete("/tokens/{token_id}", dependencies=[Depends(_require_admin)])
    async def revoke_token(token_id: str) -> dict[str, Any]:
        if not store.revoke_token_by_id(token_id):
            raise HTTPException(status_code=404, detail="No such active token.")
        return {"revoked": True}

    # -- devices --------------------------------------------------------------

    def _device_wire(r: dict[str, Any], *, states: dict, overrides: dict,
                     default_row: PolicyRow | None) -> dict[str, Any]:
        device_id = r["device_id"]
        state = states.get(device_id)
        assigned = policy_mod.pick_effective(overrides.get(device_id), default_row)
        assigned_version = assigned.document.get("version") if assigned else None
        reported_version = state.policy_version if state else None
        label = (state.label if state and state.label else None) or device_id
        return {
            "device_id": device_id,
            "label": label,
            "enrolled_at": r["enrolled_at"],
            "last_seen": state.last_seen_at if state else r["last_contact_at"],
            "protecting": state.protecting if state else None,
            "reasons": state.reasons if state else [],
            "mode": state.mode if state else None,
            "policy_version": reported_version,
            "assigned_version": assigned_version,
            "drift": (assigned_version is not None and assigned_version != reported_version),
            "revoked": r["revoked_at"] is not None,
        }

    @router.get("/devices", dependencies=[Depends(_require_admin)])
    async def devices() -> dict[str, Any]:
        rows = ingest.devices(cfg.org)
        states = store.all_device_shield_state()
        overrides = store.all_latest_device_overrides()
        default_row = store.latest_row(device_id=None)
        return {"devices": [_device_wire(r, states=states, overrides=overrides,
                                         default_row=default_row) for r in rows]}

    @router.delete("/devices/{device_id}", dependencies=[Depends(_require_admin)])
    async def revoke_device(device_id: str) -> dict[str, Any]:
        if not ingest.revoke_device(device_id):
            raise HTTPException(status_code=404, detail="Device not found.")
        return {"revoked": True}

    # -- policy -----------------------------------------------------------

    def _policy_body(body: dict) -> tuple[dict | None, str, list[str] | None]:
        policy = {k: body[k] for k in ("mode", "apps", "keep_text", "retention_days", "notice")
                 if k in body}
        managed_by = body.get("managed_by") or ""
        locked = body.get("locked")
        return policy, managed_by, locked

    @router.get("/policy", dependencies=[Depends(_require_admin)])
    async def get_default_policy() -> dict[str, Any] | None:
        row = store.latest_row(device_id=None)
        return policy_mod.as_envelope(row) if row else None

    @router.put("/policy", dependencies=[Depends(_require_admin)])
    async def put_default_policy(body: dict = Body(...)) -> dict[str, Any]:
        policy, managed_by, locked = _policy_body(body)
        try:
            row = policy_mod.write_policy(store, signer, device_id=None, org=cfg.org,
                                          policy=policy, managed_by=managed_by, locked=locked)
        except policy_mod.PolicyValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return policy_mod.as_envelope(row)

    @router.delete("/policy", dependencies=[Depends(_require_admin)])
    async def delete_default_policy() -> dict[str, Any]:
        row = policy_mod.write_policy(store, signer, device_id=None, org=cfg.org,
                                      policy=None, managed_by="", locked=None)
        return policy_mod.as_envelope(row)

    @router.get("/devices/{device_id}/policy", dependencies=[Depends(_require_admin)])
    async def get_device_policy(device_id: str) -> dict[str, Any] | None:
        row = store.latest_row(device_id=device_id)
        return policy_mod.as_envelope(row) if row else None

    def _require_known_device(device_id: str) -> None:
        rows = ingest.devices(cfg.org)
        if not any(r["device_id"] == device_id for r in rows):
            raise HTTPException(status_code=404, detail="Device not found.")

    @router.put("/devices/{device_id}/policy", dependencies=[Depends(_require_admin)])
    async def put_device_policy(device_id: str, body: dict = Body(...)) -> dict[str, Any]:
        _require_known_device(device_id)
        policy, managed_by, locked = _policy_body(body)
        try:
            row = policy_mod.write_policy(store, signer, device_id=device_id, org=cfg.org,
                                          policy=policy, managed_by=managed_by, locked=locked)
        except policy_mod.PolicyValidationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return policy_mod.as_envelope(row)

    @router.delete("/devices/{device_id}/policy", dependencies=[Depends(_require_admin)])
    async def delete_device_policy(device_id: str) -> dict[str, Any]:
        _require_known_device(device_id)
        row = policy_mod.release_device_override(store, signer, device_id=device_id, org=cfg.org)
        return policy_mod.as_envelope(row)

    @router.get("/policy/drift", dependencies=[Depends(_require_admin)])
    async def policy_drift() -> dict[str, Any]:
        rows = ingest.devices(cfg.org)
        states = store.all_device_shield_state()
        overrides = store.all_latest_device_overrides()
        default_row = store.latest_row(device_id=None)
        wired = [_device_wire(r, states=states, overrides=overrides, default_row=default_row)
                for r in rows if states.get(r["device_id"]) is not None]
        return {"devices": [d for d in wired if d["drift"]]}

    @router.get("/info", dependencies=[Depends(_require_admin)])
    async def info() -> dict[str, Any]:
        return {"public_url": cfg.public_url.rstrip("/"), "org": cfg.org, "key_id": signer.key_id}

    return router
