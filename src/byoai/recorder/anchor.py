"""External anchor receipt verification (``docs/seal-format.md`` §10).

Level 4 is the last link in the seal model: a tenant epoch root (level 3,
see ``merkle.py``) gets submitted to something outside Coriqo's own control,
so a compromised Coriqo can't quietly rewrite history without also having to
forge an external timestamp. Two anchor types are supported, specified in
``docs/seal-format.md`` §10:

- ``rfc3161_tsa``: an RFC 3161 timestamp token from a Time Stamping
  Authority, verified via ``rfc3161ng`` against a TSA certificate supplied in
  the bundle. Only the message imprint and CMS signature are checked, and by
  default this module does NOT build a certificate chain to a trusted root
  (there is no root CA store anywhere in this codebase) — it only checks
  that each certificate in the supplied chain was directly issued by the
  next one, and reports whether the leaf cert is one that actually signed
  the token. "The chain is internally consistent" is not the same claim as
  "the TSA is trustworthy" — callers who need the latter must supply their
  own trusted roots via ``tsa_trusted_roots_pem`` (a list of PEM-encoded
  certificates), which makes ``verify_rfc3161_receipt`` additionally check
  that the supplied chain terminates at one of them. Even with
  ``tsa_trusted_roots_pem`` supplied, this module does not check the chain's
  ``pathLen``/``keyUsage`` constraints, nor the trusted root certificate's
  own validity period (see ``docs/seal-format.md`` §14). ``verify_bundle``'s
  ``require_pinned_anchors=True`` turns an RFC 3161 receipt whose chain was
  NOT checked against ``tsa_trusted_roots_pem`` into a finding instead of a
  note (same treatment as a Rekor receipt with no ``rekor_public_key_b64``,
  below) — a caller asking for pinned anchors is asking for every accepted
  anchor to actually be checked against a root or key it supplied, not just
  internally consistent.
- ``sigstore_rekor``: a Rekor transparency-log inclusion proof plus a signed
  entry timestamp (SET). Verifying the SET (and therefore that the receipt
  actually came from the log, not just that its Merkle path is internally
  consistent) requires the caller to supply the log's ``rekor_public_key_b64``
  — without it, `root_hash` and the audit path come entirely from the
  receipt itself, and any party can build a tree that "includes" the epoch
  root; the audit-path check alone proves nothing about a real log. The
  Merkle audit-path check implements RFC 6962
  section 2.1.1's ``PATH``/``MTH`` walk directly (not
  ``merkle.verify_inclusion``, which uses a different, simpler pairwise-node
  -promotion rule for odd leaf counts that is not guaranteed to produce the
  same audit paths Trillian/Rekor emit). It reuses ``merkle``'s domain-
  separated leaf/node hash primitives (``_leaf_hash``/``_node_hash``) so the
  two modules can never silently disagree on the RFC 6962 hash domain, even
  though the path-reconstruction algorithm around them differs. Despite the
  SET name (real Rekor signs its SET with ECDSA), this receipt's SET check
  verifies an Ed25519
  signature (``keys.DeviceKey.verify``, seal-format §6.2's encoding) over this
  receipt's own canonicalized fields — it does NOT claim
  byte-for-byte compatibility with a live Rekor server's actual SET encoding,
  since this codebase never talks to a real Rekor instance. A real adapter
  translating live Rekor API responses into this receipt shape would need to
  confirm the exact signed-payload format against Rekor's own source.

Both verifiers are offline: no network access, caller supplies every key and
certificate needed.
"""

from __future__ import annotations

from typing import Any

from byoai.recorder.canonical import canonicalize
from byoai.recorder.merkle import _leaf_hash
from byoai.recorder.merkle import _node_hash as _rfc6962_node_hash

__all__ = [
    "verify_rfc3161_receipt",
    "verify_rekor_receipt",
]


def _largest_power_of_two_less_than(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _max_audit_path_len(tree_size: int) -> int:
    """Upper bound on a valid RFC 6962 audit path length for ``tree_size``.

    A valid inclusion proof has at most ``ceil(log2(tree_size))`` elements.
    Used as a cheap defense-in-depth check before doing any hashing: a
    receipt whose ``hashes`` list is absurdly longer than this bound is
    rejected outright, regardless of how the reconstruction itself is
    implemented (recursive or iterative).
    """
    if tree_size <= 1:
        return 0
    return (tree_size - 1).bit_length()


def _root_from_audit_path(leaf_hash: bytes, index: int, size: int, path: list[bytes]) -> bytes:
    """RFC 6962 section 2.1.1 ``PATH``/``MTH`` recursion, inverted for verification.

    ``path`` is the audit path in leaf-to-root order (as ``PATH()`` itself
    produces it: each level's sibling hash is appended after the recursive
    call into the smaller subtree, so the last element belongs to the
    outermost split and the first is closest to the leaf).

    Implemented iteratively (not recursively) on purpose: a naive recursive
    version recurses once per element of ``path``, and a receipt with a
    long-enough ``hashes`` list can drive that past Python's recursion limit
    and raise an uncaught ``RecursionError`` instead of a clean verification
    failure. The iterative form has no such bound regardless of receipt
    size — the length is instead capped up front by callers via
    ``_max_audit_path_len``.
    """
    directions: list[tuple[str, bytes]] = []
    cur_index, cur_size, cur_path = index, size, path
    while cur_size > 1:
        if not cur_path:
            raise ValueError("audit path is shorter than the tree shape requires")
        k = _largest_power_of_two_less_than(cur_size)
        rest, top = cur_path[:-1], cur_path[-1]
        if cur_index < k:
            directions.append(("left", top))
            cur_size, cur_path = k, rest
        else:
            directions.append(("right", top))
            cur_index, cur_size, cur_path = cur_index - k, cur_size - k, rest
    if cur_path:
        raise ValueError("audit path has extra elements for a single-leaf subtree")

    result = leaf_hash
    for direction, top in reversed(directions):
        if direction == "left":
            result = _rfc6962_node_hash(result, top)
        else:
            result = _rfc6962_node_hash(top, result)
    return result


def verify_rekor_receipt(
    receipt: dict[str, Any],
    epoch_root: bytes,
    *,
    rekor_public_key_b64: str | None,
) -> tuple[bool, list[str]]:
    """Verify a Sigstore Rekor-style anchor receipt.

    Checks (1) the Merkle inclusion proof reconstructs the receipt's own
    ``root_hash`` from ``epoch_root`` as the leaf, via a correct RFC 6962
    audit-path recomputation, and (2) if ``rekor_public_key_b64`` is
    supplied, the signed entry timestamp over the receipt's own fields.
    Returns ``(ok, notes)`` — ``notes`` explains anything not checked, never
    silently passed.
    """
    notes: list[str] = []

    try:
        log_index = int(receipt["log_index"])
        tree_size = int(receipt["tree_size"])
        root_hash = bytes.fromhex(receipt["root_hash"])
        raw_hashes = receipt["hashes"]
    except (KeyError, TypeError, ValueError) as exc:
        return False, [f"rekor receipt malformed: {exc}"]

    if tree_size < 1:
        return False, [f"rekor receipt has non-positive tree_size {tree_size}"]
    if not 0 <= log_index < tree_size:
        return False, [f"log_index {log_index} out of range for tree_size {tree_size}"]

    max_path_len = _max_audit_path_len(tree_size)
    if len(raw_hashes) > max_path_len:
        return False, [
            f"rekor audit path has {len(raw_hashes)} elements, more than the "
            f"{max_path_len} a valid proof for tree_size {tree_size} can have"
        ]

    try:
        hashes = [bytes.fromhex(h) for h in raw_hashes]
    except (TypeError, ValueError) as exc:
        return False, [f"rekor receipt malformed: {exc}"]

    leaf_hash = _leaf_hash(epoch_root)
    try:
        recomputed_root = _root_from_audit_path(leaf_hash, log_index, tree_size, hashes)
    except (ValueError, RecursionError) as exc:
        return False, [f"rekor inclusion proof invalid: {exc}"]

    inclusion_ok = recomputed_root == root_hash
    if not inclusion_ok:
        notes.append("rekor inclusion proof does NOT reconstruct the claimed root_hash")

    set_ok = True
    signed_entry_timestamp = receipt.get("signed_entry_timestamp")
    if rekor_public_key_b64 is None:
        notes.append(
            "rekor signed entry timestamp NOT checked — no rekor_public_key_b64 supplied"
        )
    elif not isinstance(signed_entry_timestamp, str):
        set_ok = False
        notes.append(
            "rekor signed entry timestamp is missing or not a string — cannot verify "
            "against the supplied rekor_public_key_b64"
        )
    else:
        from byoai.recorder.keys import DeviceKey

        signed_fields = {
            "log_index": log_index,
            "tree_size": tree_size,
            "root_hash": receipt["root_hash"],
        }
        try:
            set_ok = bool(
                DeviceKey.verify(
                    rekor_public_key_b64, canonicalize(signed_fields), signed_entry_timestamp
                )
            )
        except Exception:
            set_ok = False
        if not set_ok:
            notes.append("rekor signed entry timestamp does NOT verify")

    return inclusion_ok and set_ok, notes


def verify_rfc3161_receipt(
    receipt: dict[str, Any],
    epoch_root: bytes,
    *,
    tsa_trusted_roots_pem: list[str] | None = None,
) -> tuple[bool, list[str]]:
    """Verify an RFC 3161 timestamp receipt anchors ``epoch_root``.

    Requires the ``rfc3161ng`` package (the ``recorder`` extra). Checks the
    message imprint matches ``epoch_root`` and the CMS signature verifies
    against the supplied leaf certificate. By default does NOT build a path
    to a trusted root — see module docstring. When ``tsa_trusted_roots_pem``
    is given (a list of PEM-encoded certificates), the top of the supplied
    chain must either equal one of those roots or be directly issued by one
    of them; otherwise this fails with a note, closing the "unpinned anchor"
    gap described in ``docs/seal-format.md`` §14 for callers who supply a trusted root.
    """
    try:
        import base64

        import rfc3161ng
    except ImportError:
        return False, ["rfc3161ng not installed — cannot verify RFC 3161 receipts"]

    notes: list[str] = []

    try:
        tsr_der = base64.b64decode(receipt["tsr_der_b64"])
        chain_der = [base64.b64decode(c) for c in receipt["tsa_certificate_chain_b64"]]
    except (KeyError, TypeError, ValueError) as exc:
        return False, [f"rfc3161 receipt malformed: {exc}"]
    if not chain_der:
        return False, ["rfc3161 receipt has an empty certificate chain"]

    from cryptography import x509

    certs = [x509.load_der_x509_certificate(der) for der in chain_der]

    chain_ok = True
    for issued, issuer in zip(certs, certs[1:], strict=False):
        try:
            issued.verify_directly_issued_by(issuer)
        except Exception:
            chain_ok = False
            break
    if len(certs) == 1:
        notes.append(
            "rfc3161 chain has only the leaf certificate — no issuer linkage checked"
        )
    elif not chain_ok:
        notes.append("rfc3161 certificate chain is NOT internally consistent")

    root_ok = True
    trusted_roots: list[Any] = []
    if tsa_trusted_roots_pem:
        try:
            trusted_roots = [
                x509.load_pem_x509_certificate(
                    pem.encode("ascii") if isinstance(pem, str) else pem
                )
                for pem in tsa_trusted_roots_pem
            ]
        except ValueError as exc:
            return False, [*notes, f"tsa_trusted_roots_pem malformed: {exc}"]

        from cryptography.hazmat.primitives.serialization import Encoding

        top = certs[-1]
        root_ok = False
        for root in trusted_roots:
            if top.public_bytes(Encoding.DER) == root.public_bytes(Encoding.DER):
                root_ok = True
                break
            try:
                top.verify_directly_issued_by(root)
                root_ok = True
                break
            except Exception:
                continue
        if not root_ok:
            notes.append(
                "rfc3161 certificate chain does NOT reach any of the supplied "
                "tsa_trusted_roots_pem"
            )
    else:
        notes.append(
            "rfc3161 verification does not build a path to a trusted root — "
            "no root CA store exists in this codebase"
        )

    response = None
    try:
        from pyasn1.codec.der import encoder as der_encoder

        response = rfc3161ng.decode_timestamp_response(tsr_der)
        status = int(response["status"]["status"])
        if status not in (0, 1):  # granted, grantedWithMods
            return False, [*notes, f"rfc3161 TSA did not grant the request (status={status})"]
        token_der = der_encoder.encode(response["timeStampToken"])
        signature_ok = bool(
            rfc3161ng.check_timestamp(
                token_der,
                certificate=chain_der[0],
                digest=epoch_root,
                hashname="sha256",
            )
        )
    except Exception as exc:
        signature_ok = False
        notes.append(f"rfc3161 timestamp signature does NOT verify: {exc}")

    strict_root_ok = True
    if tsa_trusted_roots_pem:
        if response is None:
            strict_root_ok = False
            notes.append(
                "rfc3161 could not decode the timestamp response to check trust "
                "requirements"
            )
        else:
            strict_root_ok, strict_notes = _check_tsa_trust_requirements(
                certs, trusted_roots, response=response, tsr_der=tsr_der
            )
            notes.extend(strict_notes)

    return signature_ok and chain_ok and root_ok and strict_root_ok, notes


def _check_tsa_trust_requirements(
    certs: list[Any],
    trusted_roots: list[Any],
    *,
    response: Any,
    tsr_der: bytes,
) -> tuple[bool, list[str]]:
    """Enforce the hardened TSA trust checks.

    When ``tsa_trusted_roots_pem`` is supplied, callers are asking for real
    trust validation, not just "the chain links together". This requires:

    - every issuing (non-leaf) certificate in the chain has the CA
      BasicConstraints (ca=True);
    - the leaf (TSA signing) certificate carries the id-kp-timeStamping
      ExtendedKeyUsage, and that extension is marked critical (RFC 3161
      §2.3 requires this);
    - every certificate's validity window covers the token's genTime.
    """
    import rfc3161ng
    from cryptography import x509

    notes: list[str] = []
    ok = True

    try:
        gen_time = rfc3161ng.get_timestamp(response["timeStampToken"], naive=False)
    except Exception as exc:
        return False, [f"rfc3161 could not extract genTime from timestamp token: {exc}"]
    if gen_time.tzinfo is None:
        from datetime import timezone

        gen_time = gen_time.replace(tzinfo=timezone.utc)

    leaf = certs[0]
    issuers = certs[1:]

    for cert in issuers:
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            is_ca = bool(bc.ca)
        except x509.ExtensionNotFound:
            is_ca = False
        if not is_ca:
            ok = False
            notes.append(
                f"rfc3161 issuing certificate {cert.subject.rfc4514_string()!r} is "
                "missing BasicConstraints ca=True"
            )

    try:
        eku_ext = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        eku = eku_ext.value
        eku_critical = eku_ext.critical
    except x509.ExtensionNotFound:
        eku = None
        eku_critical = False
    if eku is None or x509.oid.ExtendedKeyUsageOID.TIME_STAMPING not in eku:
        ok = False
        notes.append(
            "rfc3161 leaf certificate is missing the id-kp-timeStamping "
            "ExtendedKeyUsage"
        )
    elif not eku_critical:
        ok = False
        notes.append(
            "rfc3161 leaf certificate's ExtendedKeyUsage extension is not marked "
            "critical (RFC 3161 requires id-kp-timeStamping to be critical)"
        )

    for cert in certs:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        if not (not_before <= gen_time <= not_after):
            ok = False
            notes.append(
                f"rfc3161 certificate {cert.subject.rfc4514_string()!r} validity "
                f"window ({not_before}..{not_after}) does not cover the token's "
                f"genTime ({gen_time})"
            )

    return ok, notes
