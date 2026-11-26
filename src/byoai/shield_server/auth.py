"""Device-signature and admin-bearer authentication for the Shield server.

Device auth matches ``byoai.recorder.shipper.post_signed_batch`` byte for
byte — the released client cannot change, so the server meets it exactly:
gzip'd body, ``x-coriqo-device`` / ``x-coriqo-signature`` headers,
``Ed25519(canonicalize(body-before-gzip))`` verified with
:meth:`byoai.recorder.keys.DeviceKey.verify` against the public key pinned at
enrolment. Coriqo verifies device posts with the same scheme.
"""

from __future__ import annotations

import hmac
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import Header, HTTPException, Request, status

from byoai.recorder.canonical import canonicalize
from byoai.recorder.keys import DeviceKey, derive_device_id

__all__ = [
    "MAX_DECOMPRESSED_BYTES",
    "SENT_AT_MAX_AGE",
    "SENT_AT_MAX_AHEAD",
    "SignedRequest",
    "StaleRequest",
    "check_admin_token",
    "check_sent_at",
    "decompress_signed_body",
    "device_id_matches_key",
    "read_signed_request",
    "verify_against_key",
]

#: A signed batch dated older than this is refused, so a captured request
#: cannot be replayed later to make a device look alive or protected.
SENT_AT_MAX_AGE = timedelta(minutes=10)
#: ...and one dated further ahead than this, which is a clock problem.
SENT_AT_MAX_AHEAD = timedelta(minutes=5)
STALE_REQUEST_DETAIL = "Request is stale or dated in the future; check this Mac's clock."

MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024  # 8 MiB — a generous checkpoint/policy poll body cap


class StaleRequest(ValueError):
    """``sent_at`` is outside the freshness window. The route answers 401."""


def check_sent_at(value: Any, *, now: datetime | None = None) -> None:
    """Mirrors Coriqo's ``ledger_service.check_sent_at``: absent is accepted
    (older clients send none), a non-string is a 400, out-of-window is a 401."""
    if value is None:
        return
    if not isinstance(value, str) or not value.strip():
        raise ValueError("`sent_at` must be an RFC 3339 UTC time")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        sent = datetime.fromisoformat(text)
    except ValueError:
        raise ValueError("`sent_at` must be an RFC 3339 UTC time") from None
    if sent.tzinfo is None:
        sent = sent.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    if sent < now - SENT_AT_MAX_AGE or sent > now + SENT_AT_MAX_AHEAD:
        raise StaleRequest(STALE_REQUEST_DETAIL)


def decompress_signed_body(raw: bytes, *, content_encoding: str | None) -> bytes:
    """The bytes a device signed. The released shipper signs canonical JSON
    BEFORE gzipping it, so verification runs against the decompressed bytes.
    Uncompressed bodies are accepted too (a proxy that transparently
    decompresses must not turn a valid request into a signature failure)."""
    if (content_encoding or "").lower().strip() != "gzip":
        return raw
    try:
        dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = dec.decompress(raw, MAX_DECOMPRESSED_BYTES + 1)
        if len(out) > MAX_DECOMPRESSED_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Compressed body expands past the {MAX_DECOMPRESSED_BYTES} byte limit.",
            )
        out += dec.flush()
    except (zlib.error, EOFError):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Body claims gzip encoding but is not valid gzip.") from None
    return out


@dataclass(frozen=True, slots=True)
class SignedRequest:
    device_id: str
    signature: str
    body: bytes  # decompressed, canonical JSON bytes — exactly what was signed


async def read_signed_request(
    request: Request,
    x_coriqo_device: str | None = Header(None, alias="X-Coriqo-Device"),
    x_coriqo_signature: str | None = Header(None, alias="X-Coriqo-Signature"),
    content_encoding: str | None = Header(None, alias="Content-Encoding"),
) -> SignedRequest:
    """FastAPI dependency: pull the asserted device id + signature headers
    and decompress the body. Does not verify the signature — that needs the
    device's pinned public key, which only the route (with the ingest store
    in hand) can look up; see :func:`verify_against_key`."""
    missing = [name for name, value in (("X-Coriqo-Device", x_coriqo_device),
                                        ("X-Coriqo-Signature", x_coriqo_signature)) if not value]
    if missing or not x_coriqo_device or not x_coriqo_signature:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Missing required header(s): {', '.join(missing)}.")
    raw = await request.body()
    signed = decompress_signed_body(raw, content_encoding=content_encoding)
    return SignedRequest(device_id=x_coriqo_device, signature=x_coriqo_signature, body=signed)


def verify_against_key(public_key_b64: str, signed_body: bytes, signature: str) -> bool:
    return DeviceKey.verify(public_key_b64, signed_body, signature)


def device_id_matches_key(device_id: str, public_key_b64: str) -> bool:
    """A defence-in-depth check: the asserted device_id must actually be
    derivable from the public key on file for it — mirrors
    ``IngestStore.record_enrolment``'s own guard at enrolment time."""
    try:
        return derive_device_id(public_key_b64) == device_id
    except Exception:  # noqa: BLE001
        return False


def check_admin_token(authorization: str | None, *, expected: str) -> None:
    """Constant-time bearer check for the admin API. 401 on anything but an
    exact ``Authorization: Bearer <token>`` match."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Missing bearer admin token.")
    presented = authorization[len("Bearer "):].strip()
    if not expected or not hmac.compare_digest(presented, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Invalid admin token.")


# Re-exported so callers don't need a second import for canonicalize.
__canonicalize__ = canonicalize
