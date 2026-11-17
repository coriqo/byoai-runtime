"""Batching shipper for the agent recorder — workstream G.

Reads confirmed-unsynced entries off the local :class:`~byoai.recorder.ledger.Ledger`,
batches them (100 events, 1 MB, or 5 seconds — whichever trips
first), gzips and signs the batch, and POSTs it to Coriqo's
``/v1/ingest/batch``. Delivery is at-least-once: the server dedupes on
``entry_hash``, so a batch that gets partially or fully resent after a crash
or a timeout is harmless.

The ledger is the source of truth — this module never blocks the
agent and never raises out of :meth:`Shipper.run_forever`; failures are
logged and retried with backoff.
"""

from __future__ import annotations

import asyncio
import gzip
import logging
import random
import threading
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from byoai._version import __version__
from byoai.recorder.attestation import CEI_ATTESTABLE_KINDS, build_envelope
from byoai.recorder.canonical import canonicalize
from byoai.recorder.coriqo_agents import CoriqoAgentsError
from byoai.recorder.coriqo_async import AsyncCoriqoAgentsClient
from byoai.recorder.identity import CoriqoIdentity
from byoai.recorder.keys import DeviceKey
from byoai.recorder.ledger import Ledger, LedgerEntry
from byoai.recorder.schema import EventKind

__all__ = [
    "runtime_info",
    "AttestationShipResult",
    "CheckpointShipResult",
    "ShipError",
    "ShipResult",
    "Shipper",
]

logger = logging.getLogger(__name__)

_INGEST_PATH = "/v1/ingest/batch"
_CHECKPOINT_INGEST_PATH = "/v1/checkpoints/batch"
_MAX_BACKOFF_SECONDS = 60.0
_INITIAL_BACKOFF_SECONDS = 1.0

#: CEI envelope emitter block (the envelope's `emitter` field) for every
#: attestation this runtime ships. Not per-agent — one runtime kind/vendor
#: for the whole process, matching what `attest_capability_snapshot`'s
#: `runtime_version` already reports elsewhere.
_EMITTER = {"kind": "proxy", "vendor": "byoai-runtime", "software_version": __version__}


#: Capability signal (C2), a top-level field of both batch bodies. A server
#: that sees ``heartbeat_chain_v1`` knows this runtime is writing ``heartbeat``
#: chain entries every ``heartbeat_interval_s`` seconds. It is sent only while
#: the heartbeat thread is alive (never when heartbeats are off or failed to
#: start) and omitted otherwise. It is self-asserted: the body signature proves
#: the device sent it, not that it is true, so a server should treat it as
#: sticky per device once seen and judge the heartbeat entries themselves.
#: Servers read the body by key and ignore fields they do not know, so the
#: released contract (``/v1/ingest/batch``, ``/v1/checkpoints/batch``,
#: ``rejected`` entries carrying ``seq_end``) is unchanged.
def runtime_info(heartbeat_interval_s: float) -> dict:
    interval = float(heartbeat_interval_s)
    return {
        "version": __version__,
        "capabilities": ["heartbeat_chain_v1"],
        "heartbeat_interval_s": int(interval) if interval.is_integer() else interval,
    }


@dataclass(frozen=True, slots=True)
class ShipResult:
    accepted: int
    duplicates: int
    gaps: list[list[int]]
    synced_up_to: int


@dataclass(frozen=True, slots=True)
class CheckpointShipResult:
    accepted: int
    duplicates: int
    synced_checkpoint_up_to: int


@dataclass(frozen=True, slots=True)
class AttestationShipResult:
    envelopes_shipped: int
    duplicates: int
    synced_attestation_up_to: int


class ShipError(RuntimeError):
    """Network failure or non-2xx after this attempt's retries (there are none
    inside :meth:`Shipper.ship_once` — the caller/run loop owns retry policy)."""

    def __init__(self, message: str, *, retry_after: float | None = None,
                 status_code: int | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after
        #: HTTP status of a rejected request; None for a network failure.
        self.status_code = status_code



def post_signed_batch(client: httpx.Client, base_url: str, key: DeviceKey,
                      path: str, body: dict) -> dict:
    """Canonicalize, sign with the device key, gzip, and POST ``body`` to
    ``base_url + path``; return the parsed JSON response.

    The one way a device talks to Coriqo's device-authenticated routes. Shared
    by the recorder's shipper and by Coriqo Shield's checkpoint publisher, so
    both sign, compress and treat failure identically. Raises
    :class:`ShipError` on network failure, a non-2xx status (carrying any
    ``Retry-After``) or a non-JSON response; never retries itself.
    """
    canonical_body = canonicalize(body)
    signature = key.sign(canonical_body)
    payload = gzip.compress(canonical_body)

    try:
        response = client.post(
            f"{base_url}{path}",
            content=payload,
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip",
                "x-coriqo-device": key.device_id,
                "x-coriqo-signature": signature,
            },
        )
    except httpx.HTTPError as exc:
        raise ShipError(f"request to {path} failed: {exc}") from exc

    if response.status_code // 100 != 2:
        retry_after = _parse_retry_after(response.headers.get("retry-after"))
        raise ShipError(
            f"request to {path} rejected: HTTP {response.status_code} {response.text}",
            retry_after=retry_after,
            status_code=response.status_code,
        )

    try:
        return response.json()
    except ValueError as exc:
        raise ShipError(
            f"response from {path} was not valid JSON: {response.text}"
        ) from exc



class Shipper:
    """Batches unsynced ledger entries and ships them to Coriqo.

    ``ship_once`` is the testable unit: read a batch, send it, advance the
    watermark. ``run_forever`` is the thin loop the proxy process owns as a
    background thread, wired to a :class:`threading.Event` for prompt
    shutdown.
    """

    def __init__(
        self,
        ledger: Ledger,
        key: DeviceKey,
        *,
        coriqo_base_url: str,
        max_batch_events: int = 100,
        max_batch_bytes: int = 1_000_000,
        max_batch_seconds: float = 5.0,
        http_client: httpx.Client | None = None,
        wait: Callable[[float], bool] | None = None,
        attestation_client: AsyncCoriqoAgentsClient | None = None,
        tenant_slug: str | None = None,
        runtime_info: Callable[[], dict | None] | None = None,
    ) -> None:
        #: Returns the ``runtime`` capability block to add to each batch, or
        #: ``None`` to send none. Unset sends none (an older runtime's shape).
        self._runtime_info = runtime_info
        self._ledger = ledger
        self._key = key
        self._base_url = coriqo_base_url.rstrip("/")
        # For the attestation client's identity only — entry/checkpoint
        # shipping's own signed batches (`_post_signed_batch`) carry no
        # tenant header today and are unaffected by this. `None` falls back
        # to `BYOAI_CORIQO_TENANT_SLUG` inside `AsyncCoriqoAgentsClient`
        # itself, same as every other device-signed call in this codebase.
        self._tenant_slug = tenant_slug
        self._max_batch_events = max_batch_events
        self._max_batch_bytes = max_batch_bytes
        self._max_batch_seconds = max_batch_seconds
        self._owns_client = http_client is None
        self._client = http_client if http_client is not None else httpx.Client()
        # Interruptible sleep: given a timeout, returns True if `stop` fired
        # during the wait (run_forever should exit then), False on timeout.
        # Defaults to a real threading.Event().wait bound at call time; tests
        # can inject a fake to assert exact backoff durations without a real
        # multi-second sleep.
        self._wait = wait
        # Attestation shipping (AIR-7d) talks to a different Coriqo API
        # family (the device-signed `{ENFORCEMENT_PREFIX}` enforcement
        # routes, via `AsyncCoriqoAgentsClient`) than entry/checkpoint
        # shipping does (the raw `x-coriqo-signature` ingest routes this
        # class signs by hand above) — same device key, different signing
        # convention and transport, so it gets its own client rather than
        # being bolted onto `self._client`. Built lazily from `self._key` so
        # a caller that never triggers attestation shipping (nothing
        # CEI-attestable has landed yet) never constructs it; tests inject
        # one directly to avoid a real event loop's connection setup.
        self._attestation_client = attestation_client
        self._owns_attestation_client = attestation_client is None

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
        if self._owns_attestation_client and self._attestation_client is not None:
            asyncio.run(self._attestation_client.close())

    def _add_runtime(self, body: dict) -> None:
        if self._runtime_info is None:
            return
        try:
            info = self._runtime_info()
        except Exception:  # noqa: BLE001 - a status read never blocks shipping
            info = None
        if info:
            body["runtime"] = info

    # -- single batch attempt ------------------------------------------------

    def ship_once(self) -> ShipResult | None:
        """One batch attempt. Returns ``None`` if there was nothing unsynced.

        Reads up to ``max_batch_events`` unsynced entries, then trims further
        to stay under ``max_batch_bytes`` (pre-gzip, of the canonical body).
        Signs ``canonicalize(body)`` with the device key and gzips those same
        canonical bytes as the request body, so the signature covers exactly
        what's on the wire. On ``202`` the watermark is advanced to the highest contiguous
        shipped seq that is not inside any gap the server reported — a
        gapped seq (and everything after it in this batch) is left unsynced
        so the next attempt retries it.

        Raises :class:`ShipError` on any network failure or non-2xx response;
        does not retry internally.
        """
        entries = self._ledger.read_unsynced(limit=self._max_batch_events)
        if not entries:
            return None

        batch = []
        total_bytes = 0
        for entry in entries:
            wire_entry = {
                "seq": entry.seq,
                "entry_hash": entry.entry_hash,
                "event": entry.event.to_dict(),
            }
            entry_bytes = len(canonicalize(wire_entry))
            if batch and total_bytes + entry_bytes > self._max_batch_bytes:
                break
            batch.append(wire_entry)
            total_bytes += entry_bytes

        body = {"device_id": self._key.device_id, "entries": batch}
        self._add_runtime(body)
        resp_body = self._post_signed_batch(_INGEST_PATH, body)

        accepted = int(resp_body.get("accepted", 0))
        duplicates = int(resp_body.get("duplicates", 0))
        gaps = [list(g) for g in resp_body.get("gaps", [])]

        shipped_seqs = [wire_entry["seq"] for wire_entry in batch]
        synced_up_to = self._advance_watermark(
            self._ledger.get_synced_up_to,
            self._ledger.set_synced_up_to,
            shipped_seqs,
            gaps,
        )

        return ShipResult(
            accepted=accepted,
            duplicates=duplicates,
            gaps=gaps,
            synced_up_to=synced_up_to,
        )

    def ship_checkpoints_once(self) -> CheckpointShipResult | None:
        """One checkpoint batch attempt. Returns ``None`` if nothing was pending.

        Checkpoints ship on their own watermark and their own endpoint,
        independent of entry shipping — a checkpoint only becomes useful to
        Coriqo (as a leaf in a tenant epoch tree, ``docs/seal-format.md`` §9) once it
        exists, regardless of whether the entries it summarizes have shipped
        yet. Delivery is at-least-once, same as entries: the server dedupes
        by ``(device_id, seq_end)``.

        Raises :class:`ShipError` on any network failure or non-2xx
        response; does not retry internally.
        """
        checkpoints = self._ledger.read_unsynced_checkpoints(limit=self._max_batch_events)
        if not checkpoints:
            return None

        body = {"device_id": self._key.device_id, "checkpoints": checkpoints}
        self._add_runtime(body)
        resp_body = self._post_signed_batch(_CHECKPOINT_INGEST_PATH, body)

        accepted = int(resp_body.get("accepted", 0))
        duplicates = int(resp_body.get("duplicates", 0))
        # Per-checkpoint outcomes the server explicitly rejected (e.g. a
        # malformed or badly-signed checkpoint) — distinct from ``accepted``
        # and ``duplicates``. Any seq_end reported here (and anything after
        # it in this batch) must never be marked synced, mirroring how
        # ``ship_once`` treats gapped seqs, or a rejected checkpoint would be
        # silently marked as synced forever and never retried, leaving a
        # permanent hole in the epoch tree.
        try:
            rejected_seq_ends = [int(r["seq_end"]) for r in resp_body.get("rejected", [])]
        except (KeyError, TypeError, ValueError) as exc:
            raise ShipError(
                f"response from {_CHECKPOINT_INGEST_PATH} had a malformed 'rejected' "
                f"entry: {resp_body.get('rejected')!r}"
            ) from exc
        rejected_ranges = [[seq_end, seq_end] for seq_end in rejected_seq_ends]

        shipped_seq_ends = [cp["seq_end"] for cp in checkpoints]
        synced_checkpoint_up_to = self._advance_watermark(
            self._ledger.get_synced_checkpoint_up_to,
            self._ledger.set_synced_checkpoint_up_to,
            shipped_seq_ends,
            rejected_ranges,
        )

        return CheckpointShipResult(
            accepted=accepted,
            duplicates=duplicates,
            synced_checkpoint_up_to=synced_checkpoint_up_to,
        )

    def ship_attestations_once(self) -> AttestationShipResult | None:
        """One attestation-shipping pass over checkpoints not yet CEI-sealed.

        Reuses the checkpoint windowing (no second, independently
        cadenced window): for each checkpoint after the attestation
        watermark (oldest first), reads its ``(seq_start, seq_end)`` range
        off the local ledger, groups the CEI-attestable entries in it
        (:data:`~byoai.recorder.attestation.CEI_ATTESTABLE_KINDS`) by the
        agent they belong to (``payload["agent_id"]`` — already stamped by
        ``verdicts.py::ledger_payload()``, AIR-7b), builds one CEI envelope
        per agent present via
        :func:`~byoai.recorder.attestation.build_envelope`, and ships each
        with :meth:`AsyncCoriqoAgentsClient.attest_execution`.
        A window with no attestable entries at all (or none carrying an
        ``agent_id``) still advances the watermark past it — there is
        nothing to attest there, not a failure to keep retrying.

        A checkpoint's envelopes are all-or-nothing: the watermark only
        advances past a checkpoint once every envelope built from it has
        been accepted or reported ``duplicate`` (the same posture checkpoint batch
        sync already has for a rejected checkpoint). A refused (4xx)
        envelope raises :class:`ShipError` and stops this pass at that
        checkpoint; nothing after it in this call is shipped, and the
        watermark is left exactly where it was for every checkpoint from
        that one on — the run loop backs off and the next pass retries the
        whole thing, never a lone envelope resent with a reshaped batch.

        Returns ``None`` if there was nothing pending.
        """
        checkpoints = self._ledger.read_checkpoints_pending_attestation(
            limit=self._max_batch_events
        )
        if not checkpoints:
            return None

        envelopes_shipped = 0
        duplicates = 0
        synced_attestation_up_to = self._ledger.get_synced_attestation_up_to()

        for checkpoint in checkpoints:
            seq_start = int(checkpoint["seq_start"])
            seq_end = int(checkpoint["seq_end"])
            entries = self._ledger.read_range(seq_start, seq_end)
            by_agent = self._group_attestable_by_agent(entries)

            window = {
                "started_at": entries[0].event.ts_device if entries else checkpoint["ts_device"],
                "ended_at": checkpoint["ts_device"],
            }
            for agent_id, agent_entries in by_agent.items():
                envelope = build_envelope(
                    agent_entries, agent={"agent_id": agent_id}, device=_EMITTER, window=window,
                )
                resp = self._attest(agent_id, envelope)
                if resp.get("status") == "duplicate":
                    duplicates += 1
                else:
                    envelopes_shipped += 1

            synced_attestation_up_to = seq_end
            self._ledger.set_synced_attestation_up_to(seq_end)

        return AttestationShipResult(
            envelopes_shipped=envelopes_shipped,
            duplicates=duplicates,
            synced_attestation_up_to=synced_attestation_up_to,
        )

    @staticmethod
    def _group_attestable_by_agent(
        entries: list[LedgerEntry],
    ) -> dict[str, list[LedgerEntry]]:
        by_agent: dict[str, list[LedgerEntry]] = {}
        for entry in entries:
            if EventKind(entry.event.kind) not in CEI_ATTESTABLE_KINDS:
                continue
            agent_id = entry.event.payload.get("agent_id")
            if not agent_id:
                # An attestable event with no agent_id can't be attested —
                # there is no subject to send it to Coriqo as. Not expected
                # in practice (verdicts.py always stamps one), but a corrupt
                # or hand-built entry must be skipped, not crash the pass.
                logger.warning(
                    "recorder shipper: attestable entry seq=%s has no agent_id, skipping",
                    entry.seq,
                )
                continue
            by_agent.setdefault(agent_id, []).append(entry)
        return by_agent

    def _attestation_identity(self) -> CoriqoIdentity:
        return CoriqoIdentity.from_device(
            base_url=self._base_url,
            device_id=self._key.device_id,
            signer=self._key,
            tenant_slug=self._tenant_slug,
        )

    async def _do_attest(self, coriqo_agent_id: str, envelope: dict) -> dict:
        """The actual coroutine ``_attest`` drives through ``asyncio.run``.

        A test-injected ``self._attestation_client`` is reused across calls
        (fine under a mock transport, which does no real connection pooling).
        Otherwise a fresh :class:`AsyncCoriqoAgentsClient` — and the
        ``httpx.AsyncClient`` it owns — is built and closed *within this one
        coroutine*, so it never outlives the event loop ``asyncio.run``
        creates for it. Caching one across separate ``asyncio.run`` calls
        instead would bind its connection pool to the first call's loop and
        then hand it to a second, already-closed loop on the next call —
        this repo's own reason a fresh request is rebuilt per retry attempt
        in ``coriqo_async.py``'s ``_send``, one level further down the same
        problem.
        """
        if self._attestation_client is not None:
            return await self._attestation_client.attest_execution(coriqo_agent_id, envelope)
        client = AsyncCoriqoAgentsClient(self._attestation_identity())
        try:
            return await client.attest_execution(coriqo_agent_id, envelope)
        finally:
            await client.close()

    def _attest(self, coriqo_agent_id: str, envelope: dict) -> dict:
        """POST one envelope via :meth:`AsyncCoriqoAgentsClient.attest_execution`.

        Bridges into the async client with :func:`asyncio.run` — this class
        runs single-threaded, sequentially, off its own background thread
        (never inside another event loop), so a fresh loop per call is safe
        here even though it would not be inside a running async application.
        Never retried, mirroring ``attest_execution``'s own posture: a
        refused envelope becomes a :class:`ShipError` the caller does not
        resend with a different batching.
        """
        try:
            return asyncio.run(self._do_attest(coriqo_agent_id, envelope))
        except CoriqoAgentsError as exc:
            raise ShipError(
                f"attestation for agent {coriqo_agent_id} refused: {exc}"
            ) from exc
        except httpx.HTTPError as exc:
            raise ShipError(
                f"attestation request for agent {coriqo_agent_id} failed: {exc}"
            ) from exc

    def _post_signed_batch(self, path: str, body: dict) -> dict:
        """See :func:`post_signed_batch`; bound to this shipper's device."""
        return post_signed_batch(self._client, self._base_url, self._key, path, body)

    def _advance_watermark(
        self,
        get_current: Callable[[], int],
        set_current: Callable[[int], None],
        shipped_seqs: list[int],
        gaps: list[list[int]],
    ) -> int:
        """Advance a synced-up-to watermark up to (but never past) the first
        gapped/rejected seq in this batch, if any.

        Generic over which watermark: ``ship_once`` passes the entry
        watermark accessors with the server's reported ``gaps`` ranges;
        ``ship_checkpoints_once`` passes the checkpoint watermark accessors
        with single-point ranges built from the server's ``rejected``
        seq_ends. Same discipline either way: a gapped/rejected seq (and
        everything after it in this batch) is left unsynced so the next
        attempt retries it.
        """
        current = get_current()
        if not shipped_seqs:
            return current

        first_gap_seq: int | None = None
        for start, _end in gaps:
            if start <= current:
                # Already synced past this gap in an earlier batch (or the
                # server is echoing a stale/unrelated historical gap) — it
                # has nothing to do with this batch and must not block it
                # from ever advancing again.
                continue
            if first_gap_seq is None or start < first_gap_seq:
                first_gap_seq = start

        target = max(shipped_seqs)
        if first_gap_seq is not None:
            # Never mark the gapped seq (or anything after it) as synced.
            safe_seqs = [s for s in shipped_seqs if s < first_gap_seq]
            if not safe_seqs:
                return current
            target = max(safe_seqs)

        if target <= current:
            return current

        set_current(target)
        return target

    # -- background loop ------------------------------------------------------

    def run_forever(self, *, stop: threading.Event) -> None:
        """Ship batches until ``stop`` is set.

        Sleeps up to ``max_batch_seconds`` between attempts (interruptible by
        ``stop``), calls :meth:`ship_once`, and on :class:`ShipError` applies
        exponential backoff with jitter (capped at 60s), honoring a
        ``Retry-After`` value if the failure carried one. Never raises out of
        the loop; exits promptly even mid-backoff-sleep.
        """
        wait_fn = self._wait if self._wait is not None else stop.wait
        backoff = _INITIAL_BACKOFF_SECONDS
        while not stop.is_set():
            try:
                self.ship_once()
                self.ship_checkpoints_once()
                self.ship_attestations_once()
                backoff = _INITIAL_BACKOFF_SECONDS
            except ShipError as exc:
                logger.warning("recorder shipper batch failed: %s", exc)
                if exc.retry_after is not None:
                    wait_seconds = exc.retry_after
                else:
                    wait_seconds = min(backoff, _MAX_BACKOFF_SECONDS)
                    wait_seconds = wait_seconds * (0.5 + random.random())
                    backoff = min(backoff * 2, _MAX_BACKOFF_SECONDS)
                if wait_fn(wait_seconds):
                    return
                continue
            except Exception:  # pragma: no cover - defensive, must never propagate
                logger.exception("recorder shipper hit an unexpected error")

            if wait_fn(self._max_batch_seconds):
                return


def _parse_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except ValueError:
        return None
