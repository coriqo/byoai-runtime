"""CEI chain-head computation, ported from Coriqo's own algorithm.

Coriqo's server-side ingest code computes a CEI envelope's ``chain_head`` as:

    H_0 = GENESIS_PREV_HASH  ("0" * 64)
    H_n = sha256_hex(H_{n-1}.encode("utf-8") + canonical_bytes(event_n))

over events already in ascending ``seq`` order (Coriqo's ingest refuses to
sort for you — see ``attestation_ingest.compute_chain_head``'s docstring).
This is a straight port of that function, byte-for-byte, so byoai-runtime
can compute the same ``chain_head`` locally that Coriqo will compute
server-side for the same event list, and detect drift before shipping.

Canonicalization: Coriqo's ``canonical_bytes()`` is Python's ``json.dumps``
with ``sort_keys=True``, no insignificant whitespace, UTF-8. This repo's
``canonical.py`` implements RFC 8785 (JCS) instead, which differs from
Coriqo's scheme in number formatting and non-BMP key ordering in principle
— but AIR-4 already pinned byte-identical output between the two for the
payload-hash case (dict of JSON-safe primitives, ASCII/BMP keys, no floats
needing ECMAScript-specific formatting), which is the same shape of input a
CEI event is. We reuse ``canonicalize()`` here on that same basis rather
than duplicating a second canonicalizer; the parity fixture in
``tests/recorder/test_attestation.py`` is what actually proves it for the
chain-head computation specifically, not just asserted by this comment.

The hash itself must be raw lowercase hex, with NO ``"sha256:"`` prefix —
that prefix is this repo's own local-ledger convention
(``canonical.sha256_hex``), not Coriqo's. Reusing that helper here would
produce a value that no longer matches ``chain_head`` byte-for-byte, so this
module hashes directly with :mod:`hashlib` instead.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any

from .canonical import canonicalize
from .ledger import LedgerEntry
from .schema import EventKind

__all__ = [
    "CEI_ATTESTABLE_KINDS",
    "GENESIS_PREV_HASH",
    "build_envelope",
    "compute_chain_head",
]

# --------------------------------------------------------------------------
# Which local EventKinds are CEI-attestable.
#
# Attesting TOOL_USE + TOOL_RESULT might look like the natural first cut. That is
# NOT what this packet ships, and the deviation is deliberate, not an
# oversight: AIR-7b (the packet immediately before this one) already landed
# and threads `resource`/`on_behalf_of` onto exactly one event kind —
# MANDATE_VERDICT, inside `verdicts.py::ledger_payload()` — and nowhere else.
# TOOL_USE/TOOL_RESULT events carry neither field today (governed_tool.py's
# `_record()` for a raw tool call has no equivalent threading). An envelope
# builder that tried to attest TOOL_USE/TOOL_RESULT would ship
# `resource`/`on_behalf_of`-less events, defeating
# the entire point of the CEI v2 fields this program exists to populate.
#
# So the call made here: MANDATE_VERDICT is the (only) CEI-attestable kind
# for this first cut. It is already an attestable decision, it is the one kind that
# actually carries `resource`/`on_behalf_of` today, and every governed tool
# call already produces exactly one MANDATE_VERDICT event by construction
# (verdicts.py records allow/flag/block alike, not just denials) — so this
# does not lose tool-call coverage relative to attesting TOOL_USE directly,
# it reuses the row that already has the richer, mandate-checked shape.
# TOOL_USE/TOOL_RESULT attestation (and whether a pair collapses to one CEI
# event — moot here since neither kind is attested)
# is left for a follow-up packet.
CEI_ATTESTABLE_KINDS: dict[EventKind, str] = {
    EventKind.MANDATE_VERDICT: "MANDATE_VERDICT",
}

# Coriqo's GENESIS_PREV_HASH — the "previous hash" of the
# first event in a chain. Not to be confused with this repo's own
# GENESIS_PREV_HASH in ledger.py ("sha256:" + "00" * 32), which is a
# different, local-checkpoint-chain convention.
GENESIS_PREV_HASH = "0" * 64


def _sha256_hex_raw(data: bytes) -> str:
    """Raw lowercase hex digest, matching Coriqo's sha256_hex exactly (no
    ``"sha256:"`` prefix — see module docstring)."""
    return hashlib.sha256(data).hexdigest()


def compute_chain_head(events: list[dict[str, Any]]) -> str:
    """Port of Coriqo's ``attestation_ingest.compute_chain_head()``.

    ``H_0 = GENESIS_PREV_HASH``; ``H_n = sha256_hex(H_{n-1} + canonical_bytes(event_n))``.

    Events must already be in ascending ``seq`` order — this function does
    not sort, mirroring Coriqo's own refusal to sort for the emitter (a
    chain that only verifies after the *server* reorders it is not evidence
    of order, it is evidence of the server's own sort). An empty list
    returns ``GENESIS_PREV_HASH`` unchanged, same as Coriqo's ``EventChain``
    with no events.
    """
    prev = GENESIS_PREV_HASH
    for event in events:
        prev = _sha256_hex_raw(prev.encode("utf-8") + canonicalize(event))
    return prev


def build_envelope(
    entries: list[LedgerEntry],
    *,
    agent: Mapping[str, Any],
    device: Mapping[str, Any],
    window: Mapping[str, Any],
) -> dict[str, Any]:
    """Map a batch of local ledger entries onto a CEI v2 envelope.

    ``entries`` is expected to already be the same ``(seq_start, seq_end)``
    window a checkpoint covers (this does not invent its own
    windowing; the caller reads ``ledger.read_range(seq_start, seq_end)`` and
    hands the result straight in), in ascending local ``seq`` order, which is
    how :meth:`Ledger.read_range` already returns them.

    ``agent`` is the CEI envelope's ``subject`` (``agent_id``, optionally
    ``agent_version``); ``device`` is the ``emitter`` (``kind``, ``vendor``,
    optionally ``software_version``); ``window`` is ``{started_at, ended_at}``
    — the caller's job, not this function's, since only the caller knows
    whether that should be the checkpoint's own timestamps or something else.

    Only entries whose kind is in :data:`CEI_ATTESTABLE_KINDS` are attested;
    everything else in the window is dropped from the envelope and stays
    local-only, exactly as before this packet.

    ``seq`` is renumbered starting at 1 within the envelope — CEI's ``seq`` is
    a per-window sequence, not the local ledger's never-reset one —
    so an envelope's ``seq`` values say nothing about an event's position in
    the local chain, only its position in this one attestation.

    ``payload_hash`` is recomputed here with this module's raw-hex
    :func:`_sha256_hex_raw`, never copied from ``AgentEvent.payload_hash``:
    the local ledger's hash carries a ``"sha256:"`` prefix (see
    ``canonical.sha256_hex``) that is this repo's own convention, not
    Coriqo's — reusing it verbatim would produce a `payload_hash` Coriqo's
    own recompute (``sha256_hex(canonical_bytes(payload))``, no prefix) can
    never match, refusing the whole envelope on ingest.

    ``on_behalf_of`` is always present on every event, even as an empty list,
    which is what makes this envelope self-identify as v2 to Coriqo's
    ``envelope_schema_version()`` (v2 is detected by *presence* of the key,
    not by a value) — this runtime emits v2 always going
    forward, never v1. ``resource`` is included only when the local payload
    actually named one; it is optional on both sides.
    """
    events: list[dict[str, Any]] = []
    for seq, entry in enumerate(
        (e for e in entries if _kind_of(e) in CEI_ATTESTABLE_KINDS), start=1
    ):
        payload = entry.event.payload
        resource = payload.get("resource")
        on_behalf_of = payload.get("on_behalf_of") or []
        cei_event: dict[str, Any] = {
            "seq": seq,
            "event_type": CEI_ATTESTABLE_KINDS[_kind_of(entry)],
            "ts": entry.event.ts_device,
            "payload": payload,
            "payload_hash": _sha256_hex_raw(canonicalize(payload)),
            "on_behalf_of": list(on_behalf_of),
        }
        if resource is not None:
            cei_event["resource"] = resource
        events.append(cei_event)

    return {
        "emitter": dict(device),
        "subject": dict(agent),
        "window": dict(window),
        "events": events,
        "chain_head": compute_chain_head(events),
    }


def _kind_of(entry: LedgerEntry) -> EventKind:
    """``LedgerEntry.event.kind`` is stored/round-tripped as the enum's plain
    string value (see ``schema.py``/``ledger.py``'s ``_kind_value``), so this
    normalizes it back to :class:`EventKind` for the ``CEI_ATTESTABLE_KINDS``
    lookup rather than comparing raw strings at every call site."""
    return EventKind(entry.event.kind)
