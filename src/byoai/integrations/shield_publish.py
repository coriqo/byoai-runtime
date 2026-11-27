"""Coriqo Shield → Coriqo: publish this Mac's signed seal, rarely and reliably.

What goes out is one small thing: the chain's current checkpoint (Merkle
root, entry count, Ed25519 signature by this Mac's key), wrapped in the shape
Coriqo's existing device checkpoint route already stores
(``POST /v1/checkpoints/batch``, the same route the agent recorder uses). No
messages, no rule matches, no ledger rows.

Design goals, in order:

* **No support after setup.** Setup is one enrolment token, pasted once.
  After that the Mac signs every request with its own key; there is no API
  key or password on disk to rotate or leak.
* **Cheap.** One small request every ``every_hours`` (6 by default), plus
  "Send now": the new seal if the chain grew, otherwise a heartbeat.
* **Alive, not just quiet.** With nothing new, Shield resends its last
  accepted seal byte for byte. Coriqo treats it as a duplicate (no new row, no
  second entry) but notes that the Mac was heard from, so an idle Mac is not
  mistaken for a dead one by Coriqo's quiet-device alert. The heartbeat
  interval is kept between 1 and 6 hours whatever ``every_hours`` says, to stay
  well inside Coriqo's quiet threshold (24 hours by default).
* **Never breaks capture.** Publishing runs on its own thread, catches
  everything, and never blocks, slows or stops checking.
* **Self-healing.** A failure backs off (1 min, doubling, capped at 6 h,
  honouring ``Retry-After``) and retries on its own. State is written
  atomically and survives restarts. Coriqo dedupes by checkpoint id, so a
  resend after a crash is harmless.
* **One human-actionable state.** If Coriqo refuses this Mac (401/403: the
  device was revoked or the tenant moved), the status says so and what to do.
  Everything else fixes itself. A 401 that names the clock is not a refusal:
  the Mac's date is wrong, the status says so, and sending resumes on its own
  once it is fixed.

Every request also carries, at the top level of the signed body, ``sent_at``
(when this request left, so Coriqo can refuse a replayed one) and ``shield``
(is Shield checking traffic right now, and if not, why). The checkpoint entry
inside stays byte for byte the same on a heartbeat. A new entry also names
``record_id`` (this Mac's local record; a new id means it was wiped) and
``prev_chain_hash`` (the chain hash of the last entry Coriqo accepted), so
Coriqo can tell a record that restarted or skipped from one that grew.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from byoai.integrations.shield_sync import aggregate_daily, build_event, sync_level
from byoai.recorder.canonical import canonicalize
from byoai.recorder.enroll import ENROLLMENT_FILENAME, EnrollmentError, enroll, load_enrollment_state
from byoai.recorder.keys import atomic_write_bytes
from byoai.recorder.shipper import ShipError, post_signed_batch

if TYPE_CHECKING:  # pragma: no cover
    from byoai.integrations.shield import SealChain

#: Used when no protection check was wired in: say "can't tell", never claim
#: protection nobody checked.
UNKNOWN_PROTECTION = {"protecting": False, "reasons": ["state_unknown"], "mode": None}
CLOCK_MESSAGE = ("This Mac's clock is wrong. Fix the date and time, and Shield "
                 "will send again on its own.")

CHECKPOINT_PATH = "/v1/checkpoints/batch"
SESSION_ID = "coriqo-shield"  # Coriqo tells a Shield Mac's seals apart by this
LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")
STATE_FILE = "coriqo_publish.json"
DEFAULT_EVERY_HOURS = 6
BACKOFF_FIRST_S = 60
BACKOFF_CAP_S = 6 * 3600
TICK_S = 60
TIMEOUT_S = 15
HEARTBEAT_MIN_S = 3600
HEARTBEAT_MAX_S = 6 * 3600

# -- activity sync (Shield Sync) ---------------------------------------------
#
# Only when the effective policy's ``sync`` is "daily" or "events" (see
# byoai.integrations.shield_sync for exactly what leaves). Sent after a
# checkpoint that covers every event in the batch, on its own backoff so a
# refusing events route can never slow the seal down.
EVENTS_PATH = "/v1/shield/events"
SYNC_BATCH = 200
SYNC_OUTBOX_CAP = 5000   # events kept while offline; older ones become a gap
SYNC_BATCHES_PER_TICK = 10  # batches sent in one window
SYNC_SEEN_CAP = 2000     # ids remembered so a sent event is never rebuilt
SYNC_EVERY_S = {"events": 60, "daily": 3600}

# -- managed policy ------------------------------------------------------------
#
# Signed exactly like the checkpoint post above (post_signed_batch): the same
# device key, the same canonicalize-then-sign scheme, the same "never block
# capture, keep the last good state on failure" posture. Polled every 10 min,
# at start (last_policy_poll_at == 0) and on "Send now" (poll_policy(force=True)
# from send()).
POLICY_PATH = "/v1/shield/policy"
PUBLIC_KEYS_PATH = "/api/v1/checkpoints/public-keys"
POLICY_POLL_S = 600


def _public_key_hex(entry: dict) -> str | None:
    """A public-keys list entry's key as lowercase hex of its raw 32 bytes —
    the only form :func:`byoai.integrations.shield.apply_managed_envelope`
    accepts. Coriqo's ``GET .../public-keys`` sends ``public_key_pem`` (an
    SPKI PEM); an already-hex ``public_key`` is accepted too, for callers
    (and tests) that already have the raw form. Malformed input is refused,
    not raised — the caller treats a ``None`` result as "no usable key"."""
    pem = entry.get("public_key_pem")
    if isinstance(pem, str) and pem.strip():
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            key = load_pem_public_key(pem.encode())
            if not isinstance(key, Ed25519PublicKey):
                return None
            return key.public_bytes_raw().hex()
        except Exception:  # noqa: BLE001
            return None
    raw = entry.get("public_key")
    if isinstance(raw, str) and raw.strip():
        raw = raw.strip()
        try:
            key = bytes.fromhex(raw)
        except ValueError:
            try:
                key = base64.b64decode(raw, validate=True)
            except ValueError:
                return None
        return key.hex() if len(key) == 32 else None
    return None


class WorkspacePinError(PermissionError):
    """The workspace is outside BYOAI_CORIQO_LINK_WORKSPACES (not an operating-system permission error)."""


@dataclass
class PublishState:
    last_root: str | None = None  # chain root covered by the last accepted send
    last_height: int = 0          # its entry count, for the status line
    last_seq: int = 0             # number of the last accepted send
    last_sent_at: float = 0.0     # epoch seconds; last accepted send or heartbeat
    #: The last entry Coriqo accepted, resent unchanged as the heartbeat.
    last_entry: dict | None = None
    #: The signed entry waiting for Coriqo's acknowledgement. Resent unchanged
    #: until acknowledged, so a crash between Coriqo storing it and us writing
    #: this file can only ever produce a duplicate, never two different heads
    #: under one number (which Coriqo would rightly treat as a conflict).
    outbox: dict | None = None
    failures: int = 0             # consecutive failed attempts
    next_attempt_at: float = 0.0  # epoch seconds; 0 = no backoff in force
    last_error: str | None = None
    needs_attention: bool = False  # Coriqo refused this Mac (401/403)
    # -- managed policy ------------------------------------------------------
    last_policy_poll_at: float = 0.0  # epoch seconds; 0 = never polled yet
    #: This device's pinned policy-signing key, once found: an already-known
    #: key_id (from enrolment) never triggers a lookup at all; an
    #: already-enrolled device fetches PUBLIC_KEYS_PATH once (policy_key_tried)
    #: and pins whichever entry matches the key_id the first envelope names.
    policy_key_id: str | None = None
    policy_public_key: str | None = None
    policy_key_tried: bool = False
    #: Set on a refused envelope (bad signature, wrong tenant/device, rollback,
    #: unknown key) or a poll that couldn't reach Coriqo; cleared on the next
    #: successful poll. Surfaced by GET /api/policy as managed.error.
    policy_last_error: str | None = None
    # -- activity sync ---------------------------------------------------------
    #: Built events waiting for Coriqo's 200, oldest first. Dropped only after
    #: the batch containing them is accepted (or refused as malformed).
    sync_outbox: list | None = None
    #: Ids already sent or dropped: never rebuilt from the feed.
    sync_seen: list | None = None
    #: When sharing last turned on (epoch seconds; 0 = not sharing). Nothing
    #: that happened before it is ever sent, including across the level being
    #: turned down and up again. Re-enrolment is a new identity: its state
    #: starts empty, and sharing begins afresh from its first tick.
    sync_since: float = 0.0
    #: Events dropped locally (offline past retention, or past the cap); sent
    #: with the next batch so the dashboard shows "no data", not a quiet period.
    sync_gap: dict | None = None
    #: The batch last sent and not yet acknowledged: {"batch_id", "ids",
    #: "gap", "level"}. A resend after a lost reply carries exactly these
    #: events, gap and id, whatever has been queued or dropped since, so
    #: Coriqo can recognise it (daily totals would otherwise count twice).
    sync_inflight: dict | None = None
    sync_batch_seq: int = 0  # makes every new batch_id unique, gap-only ones too
    sync_last_sent_at: float = 0.0
    sync_failures: int = 0
    sync_next_attempt_at: float = 0.0
    sync_last_error: str | None = None


class Publisher:
    """Owns the enrolment, the send decision and the retry state for one Mac.

    ``now`` and ``client_factory`` are injectable for tests; production uses
    wall-clock time and a fresh short-lived httpx client per attempt (so a
    wedged connection can never outlive one request).
    """

    def __init__(self, seals: SealChain, key_dir: Path, state_dir: Path, *,
                 every_hours: float = DEFAULT_EVERY_HOURS,
                 now: Callable[[], float] = time.time,
                 client_factory: Callable[[], httpx.Client] | None = None,
                 protection: Callable[[], dict] | None = None,
                 managed_policy_path: Path | None = None,
                 policy: Callable[[], dict] | None = None,
                 events: Callable[[], list] | None = None) -> None:
        self.seals = seals
        #: The effective policy (its ``sync`` level) and the feed's items.
        #: Either missing means activity sync is not wired: seal only.
        self._policy = policy
        self._events = events
        self._seen_cap = SYNC_SEEN_CAP  # grown to the feed's size by _collect
        self.key_dir = Path(key_dir)
        self.state_path = Path(state_dir) / STATE_FILE
        #: Where verified managed policy is stored; see
        #: byoai.integrations.shield.MANAGED_POLICY_PATH (the default, shared
        #: with the proxy and console) and its ``managed_policy_path`` override.
        self.managed_policy_path = managed_policy_path
        self.every_s = max(0.0, every_hours) * 3600
        self.heartbeat_s = min(HEARTBEAT_MAX_S, max(HEARTBEAT_MIN_S, self.every_s))
        self._now = now
        self._key_fetch_failed = False
        # trust_env=False: never route through a proxy. On a Mac running
        # Shield, the system proxy IS Shield's capture proxy; going through it
        # would fail its certificate check on every send.
        self._client_factory = client_factory or (
            lambda: httpx.Client(timeout=TIMEOUT_S, trust_env=False))
        #: Returns {"protecting", "reasons", "mode"}; see shield.protection_state.
        self._protection = protection or (lambda: dict(UNKNOWN_PROTECTION))
        self._lock = threading.RLock()  # sync_tick calls send() and poll_policy() while holding it
        self.state = self._load()

    # -- state ------------------------------------------------------------
    def _load(self) -> PublishState:
        try:
            data = json.loads(self.state_path.read_text())
            known = {k: v for k, v in data.items() if k in PublishState.__annotations__}
            return PublishState(**known)
        except (OSError, ValueError, TypeError):
            return PublishState()

    def _save(self) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_bytes(self.state_path, json.dumps(asdict(self.state)).encode(),
                           mode=0o600, prefix=".coriqo-publish-")

    # -- enrolment ----------------------------------------------------------
    def enrolment(self):
        try:
            return load_enrollment_state(self.key_dir)
        except EnrollmentError:
            return None

    def enrol(self, base_url: str, token: str, *, keep_existing: bool = False,
              allowed_tenants: list[str] | None = None) -> dict:
        """Exchange a one-time Coriqo enrolment token for this Mac's device
        identity. Uses the Mac's existing Shield key; nothing secret is kept
        afterwards. Re-enrolling replaces the old identity."""
        from urllib.parse import urlsplit
        base_url = base_url.strip().rstrip("/")
        parts = urlsplit(base_url)
        local = (parts.hostname or "") in ("localhost", "127.0.0.1", "::1")
        if parts.scheme != "https" and not (parts.scheme == "http" and local):
            # The token is a one-time credential: it only crosses a network
            # encrypted. Plain http is allowed for a Coriqo on this machine.
            raise ValueError("Enter the Coriqo address, starting with https://")
        if not token.strip():
            raise ValueError("Paste the enrolment token from Coriqo")
        refusal = ("That Coriqo workspace is not one this computer may join "
                   "(BYOAI_CORIQO_LINK_WORKSPACES). It has not been connected.")
        if allowed_tenants is not None:
            allowed_tenants = [t.strip().lower() for t in allowed_tenants]  # slugs are case-insensitive
            # The one-time token names its workspace (cik_live_<slug>.<secret>), so a
            # token for another workspace is refused before anything is sent to Coriqo.
            # An unreadable token is refused too: with a pin set, unknown is not allowed.
            head = token.strip().split(".", 1)[0]
            slug = head[len("cik_live_"):] if head.startswith("cik_live_") else None
            if slug is None or slug.lower() not in allowed_tenants:
                raise WorkspacePinError(refusal)
        with self._lock:
            if keep_existing:
                # Checked under the lock, with the write, so two requests cannot both pass it.
                # State that exists but cannot be read counts as enrolled: refusing is the safe side.
                try:
                    existing = load_enrollment_state(self.key_dir)
                except EnrollmentError:
                    existing = True
                if existing is not None:
                    raise EnrollmentError("already enrolled")
            enrol_path = Path(self.key_dir) / ENROLLMENT_FILENAME
            try:
                previous = enrol_path.read_bytes()
            except OSError:
                previous = None
            with self._client_factory() as client:
                enroll(coriqo_base_url=base_url, token=token.strip(),
                       key_dir=self.key_dir, force=True, http_client=client)
            if allowed_tenants is not None:
                try:
                    state = load_enrollment_state(self.key_dir)
                except EnrollmentError:
                    state = None  # unreadable counts as outside the pin
                if state is None or (state.tenant_slug or "").lower() not in allowed_tenants:
                    # The server named a workspace other than the token's: put back exactly
                    # what was enrolled before (or nothing), so the refusal changes nothing.
                    if previous is None:
                        enrol_path.unlink(missing_ok=True)
                    else:
                        atomic_write_bytes(enrol_path, previous, mode=0o600, prefix=".enrollment-")
                    raise WorkspacePinError(refusal)
            # A new identity starts clean (its own numbering, empty outbox):
            # the current seal goes out straight away.
            self.state = PublishState()
            self._save()
        return self.status()

    # -- decision ---------------------------------------------------------
    def has_new(self) -> bool:
        """Anything sealed since the last accepted send. Compared by root, not
        entry count: the seal chain keeps a bounded window, so its count stops
        growing while its root keeps changing."""
        return self.seals.height > 0 and self.seals.root_hex() != self.state.last_root

    def due(self) -> bool:
        s = self.state
        if self.enrolment() is None:
            return False
        now = self._now()
        if now < s.next_attempt_at:
            return False  # backing off
        if s.outbox is None and not self.has_new():
            # Nothing new: a heartbeat, once the interval has passed. Never a
            # new entry for an unchanged seal, so Coriqo holds no duplicates.
            return (self.seals.height > 0
                    and (s.last_sent_at == 0 or now - s.last_sent_at >= self.heartbeat_s))
        return s.last_sent_at == 0 or now - s.last_sent_at >= self.every_s

    def tick(self) -> bool:
        """Send if due. Never raises. Returns whether a send was attempted."""
        try:
            self.poll_policy()
        except Exception:  # noqa: BLE001 - never blocks capture or checkpoint sending
            pass
        attempted = False
        try:
            if self.due():
                attempted = True
                self.send()
        except Exception:  # noqa: BLE001 - the loop must never die
            attempted = True
        try:
            self.sync_tick()
        except Exception:  # noqa: BLE001 - activity sync never blocks the seal
            pass
        return attempted

    def publish_now(self) -> dict:
        """"Send now": force a policy poll (never blocking on its result) then
        send the checkpoint, same as :meth:`send` otherwise."""
        try:
            self.poll_policy(force=True)
        except Exception:  # noqa: BLE001
            pass
        return self.send()

    # -- activity sync ------------------------------------------------------
    def sync_tick(self) -> bool:
        """Collect new events and, when due, send them. Never raises. Returns
        whether a request went out."""
        if self._events is None or self._policy is None:
            return False
        if self.enrolment() is None:
            return False
        with self._lock:
            s = self.state
            policy = self._policy()
            level = sync_level(policy)
            s.sync_outbox = s.sync_outbox or []
            s.sync_seen = s.sync_seen or []
            if level == "seal":
                if s.sync_since or s.sync_outbox or s.sync_gap:
                    # Sharing was turned back down: forget what was waiting.
                    s.sync_since, s.sync_outbox, s.sync_gap = 0.0, [], None
                    s.sync_inflight = None
                    s.sync_failures, s.sync_next_attempt_at = 0, 0.0
                    s.sync_last_error, s.sync_last_sent_at = None, 0.0
                    self._save()
                return False
            if not s.sync_since:
                s.sync_since = self._now()
                self._save()
            if self._collect(policy):
                self._save()
            now = self._now()
            if not (s.sync_outbox or s.sync_gap) or now < s.sync_next_attempt_at:
                return False
            if s.sync_last_sent_at and now - s.sync_last_sent_at < SYNC_EVERY_S[level]:
                return False
            # Drain a backlog in one window (a busy `daily` device would
            # otherwise send 200 events an hour and outrun the outbox cap).
            sent = False
            for _ in range(SYNC_BATCHES_PER_TICK):
                if not self._send_events(level, now):
                    break
                sent = True
                s = self.state
                if s.sync_failures or not s.sync_outbox:
                    break
            return sent

    def _collect(self, policy: dict) -> bool:
        """Turn new feed items into outbox events. Returns whether anything
        changed."""
        s = self.state
        events = self._events
        if events is None:
            return False  # not wired: the caller checks this too
        # The caller sets both to lists before collecting; this says so to the type checker.
        s.sync_outbox = s.sync_outbox or []
        s.sync_seen = s.sync_seen or []
        since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(s.sync_since))
        try:
            items = list(events())
        except Exception:  # noqa: BLE001 - a feed being written to; try next tick
            return False
        self._seen_cap = max(SYNC_SEEN_CAP, 4 * len(items))
        seen = set(s.sync_seen)
        queued = {e["event_id"] for e in s.sync_outbox}
        device_id = self.seals._key.device_id
        changed = False
        old_ids: list[str] = []
        for item in reversed(items):  # the feed is newest first
            eid = item.get("id") if isinstance(item, dict) else None
            if not eid or eid in seen or eid in queued:
                continue
            ev = build_event(item, device_id=device_id)
            if ev is None:
                continue  # not sealed yet: picked up on a later tick
            if ev["occurred_at"] < since:
                old_ids.append(eid)  # from before sharing began: never sent
            else:
                s.sync_outbox.append(ev)
            changed = True
        if old_ids:
            self._mark_seen(old_ids)
        if s.sync_outbox:
            days = int(policy.get("retention_days") or 30)
            cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                   time.gmtime(self._now() - days * 86400))
            # The batch in flight is never trimmed: it may already be counted
            # by Coriqo, and its resend must stay byte-identical.
            frozen = set((s.sync_inflight or {}).get("ids") or [])
            keep = [e for e in s.sync_outbox
                    if e["occurred_at"] >= cutoff or e["event_id"] in frozen]
            excess = len(keep) - SYNC_OUTBOX_CAP
            if excess > 0:
                trimmed, rest = 0, []
                for e in keep:
                    if trimmed < excess and e["event_id"] not in frozen:
                        trimmed += 1
                        continue
                    rest.append(e)
                keep = rest
            kept_ids = {e["event_id"] for e in keep}
            dropped = [e for e in s.sync_outbox if e["event_id"] not in kept_ids]
            if dropped:
                self._drop_events(dropped)
                changed = True
        return changed

    def _send_events(self, level: str, now: float) -> bool:
        s = self.state
        enrolment = self.enrolment()
        if enrolment is None:
            return False
        # Every event's seal must already be under an accepted checkpoint, so
        # send that first (it is a no-op when the seal has not moved).
        if s.outbox is not None or self.has_new():
            if now < s.next_attempt_at:
                return False
            self.send()
            s = self.state  # send() replaces the state object
            if s.outbox is not None or self.has_new():
                return False
        # Resend exactly what is in flight; otherwise freeze the next batch
        # before sending it, so a lost reply can be retried byte for byte.
        flight = s.sync_inflight
        outbox = s.sync_outbox or []
        if (flight and flight["level"] == level and [
                e["event_id"] for e in outbox[:len(flight["ids"])]] == flight["ids"]):
            batch = outbox[:len(flight["ids"])]
        else:
            batch = outbox[:SYNC_BATCH]
            s.sync_batch_seq += 1
            ids = [e["event_id"] for e in batch]
            flight = {"ids": ids, "gap": dict(s.sync_gap) if s.sync_gap else None,
                      "level": level,
                      "batch_id": hashlib.sha256(
                          f"{s.sync_batch_seq}|{'|'.join(ids)}".encode()).hexdigest()[:32]}
            s.sync_inflight = flight
            self._save()
        batch_id = flight["batch_id"]
        body: dict = {
            "device_id": self.seals._key.device_id,
            "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "level": level,
            "policy_version": self._managed_policy_version(),
            "batch_id": batch_id,
        }
        if level == "events":
            body["events"] = batch
        else:
            body["daily"] = aggregate_daily(batch)
        if flight["gap"]:
            body["gap"] = flight["gap"]
        try:
            with self._client_factory() as client:
                post_signed_batch(client, enrolment.coriqo_base_url,
                                  self.seals._key, EVENTS_PATH, body)
        except ShipError as exc:
            self._sync_failed(now, exc)
            return True
        except Exception as exc:  # noqa: BLE001
            self._sync_failed(now, ShipError(str(exc)))
            return True
        self._mark_seen(e["event_id"] for e in batch)
        s.sync_outbox = outbox[len(batch):]
        # A gap that widened while this batch was in flight is still owed.
        if s.sync_gap == flight["gap"]:
            s.sync_gap = None
        s.sync_inflight = None
        s.sync_failures = 0
        s.sync_next_attempt_at = 0.0
        s.sync_last_error = None
        s.sync_last_sent_at = now
        self._save()
        return True

    def _mark_seen(self, ids) -> None:
        """Remember event ids so the feed never rebuilds them. The list is
        bounded, but always well above the feed's own size (an id can only be
        evicted once its item has left the feed)."""
        s = self.state
        s.sync_seen = (s.sync_seen or []) + list(ids)
        del s.sync_seen[:-self._seen_cap]

    def _drop_events(self, dropped: list) -> None:
        """Take events out of the outbox for good. They are marked seen (the
        feed must not rebuild them) and recorded as a gap (so the dashboard
        says "no data", not a quiet period)."""
        if not dropped:
            return
        s = self.state
        ids = {e["event_id"] for e in dropped}
        s.sync_outbox = [e for e in (s.sync_outbox or []) if e["event_id"] not in ids]
        self._mark_seen(e["event_id"] for e in dropped)
        lo = min(e["occurred_at"] for e in dropped)
        hi = max(e["occurred_at"] for e in dropped)
        if s.sync_gap:
            lo, hi = min(lo, s.sync_gap["from"]), max(hi, s.sync_gap["to"])
        s.sync_gap = {"from": lo, "to": hi}

    def _sync_failed(self, now: float, exc: ShipError) -> None:
        s = self.state
        if exc.status_code == 422:
            # Coriqo's closed schema refused the batch. Retrying the same bytes
            # can never work: drop it, and record its range in the gap so the
            # dashboard says "no data" rather than a quiet period.
            flight = s.sync_inflight
            n = len(flight["ids"]) if flight else SYNC_BATCH
            s.sync_inflight = None
            if n:
                self._drop_events((s.sync_outbox or [])[:n])
                s.sync_last_error = "Coriqo refused a batch of activity as malformed; it was dropped."
            else:
                # A gap-only batch refused: nothing to drop but the gap itself
                # (unless it has widened since: that part is still owed).
                if flight and s.sync_gap == flight["gap"]:
                    s.sync_gap = None
                s.sync_last_error = "Coriqo refused a gap marker as malformed; it was dropped."
        elif exc.status_code == 409:
            # The level this device sends at is not the one Coriqo has for it:
            # fetch the policy now rather than at the next poll. The frozen
            # batch is rebuilt at whatever level applies afterwards.
            s.sync_inflight = None
            try:
                self.poll_policy(force=True)
            except Exception:  # noqa: BLE001
                pass
            s.sync_last_error = "Coriqo expects a different sharing level; checking the policy."
        else:
            s.sync_last_error = "Couldn't send activity to Coriqo; Shield will try again on its own."
        s.sync_failures += 1
        delay = min(BACKOFF_CAP_S, BACKOFF_FIRST_S * 2 ** (s.sync_failures - 1))
        delay *= random.uniform(0.8, 1.2)
        if exc.retry_after:
            delay = max(delay, float(exc.retry_after))
        s.sync_next_attempt_at = now + delay
        self._save()

    # -- managed policy -----------------------------------------------------
    def _policy_key_path(self):
        from byoai.integrations.shield import MANAGED_POLICY_PATH
        return self.managed_policy_path or MANAGED_POLICY_PATH

    def _trusted_key(self, key_id: str, enrollment) -> str | None:
        """This device's pinned public key for ``key_id`` — always lowercase
        hex of the raw 32-byte Ed25519 public key, however it was pinned — or
        ``None`` if it isn't (or can't be found to be) trusted. Fetches
        Coriqo's public-keys list at most once per device lifetime
        (``policy_key_tried``); a key_id that still doesn't match after that
        fetch is refused as unknown, not retried on every poll."""
        if enrollment.policy_key and enrollment.policy_key.get("key_id") == key_id:
            return _public_key_hex(enrollment.policy_key)
        if self.state.policy_key_id == key_id and self.state.policy_public_key:
            return self.state.policy_public_key
        if self.state.policy_key_tried:
            return None
        self.state.policy_key_tried = True
        try:
            with self._client_factory() as client:
                resp = client.get(f"{enrollment.coriqo_base_url}{PUBLIC_KEYS_PATH}")
                resp.raise_for_status()
                data = resp.json()
        except Exception:  # noqa: BLE001 - no key found this time; try again next poll? no —
            # a fetch failure isn't "the key doesn't exist", so don't burn the
            # one-shot attempt on a transient network error.
            self.state.policy_key_tried = False
            self._key_fetch_failed = True
            self._save()
            return None
        keys = data.get("keys") if isinstance(data, dict) else data
        for k in keys or []:
            if not (isinstance(k, dict) and k.get("key_id") == key_id):
                continue
            if k.get("revoked"):
                break  # a revoked entry is not trusted, even if the id matches
            hexkey = _public_key_hex(k)
            if hexkey:
                self.state.policy_key_id = k["key_id"]
                self.state.policy_public_key = hexkey
            break
        self._save()
        if self.state.policy_key_id == key_id:
            return self.state.policy_public_key
        return None

    def policy_due(self) -> bool:
        s = self.state
        return s.last_policy_poll_at == 0 or self._now() - s.last_policy_poll_at >= POLICY_POLL_S

    def poll_policy(self, force: bool = False) -> None:
        """Poll Coriqo for a changed managed policy. Never raises, never
        blocks capture: a failure (network, bad signature, wrong tenant/
        device, rollback, unknown key) just keeps the last good policy and is
        recorded in ``policy_last_error`` for GET /api/policy to report."""
        if not force and not self.policy_due():
            return
        enrollment = self.enrolment()
        if enrollment is None:
            return
        with self._lock:
            self.state.last_policy_poll_at = self._now()
            from byoai.integrations.shield import load_managed_policy
            current = load_managed_policy(self._policy_key_path())
            have_version = None
            if current:
                v = (current["envelope"]["document"] or {}).get("version")
                if isinstance(v, int) and not isinstance(v, bool):
                    have_version = v
            body = {"sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._now())),
                    "have_version": have_version}
            try:
                with self._client_factory() as client:
                    resp = post_signed_batch(client, enrollment.coriqo_base_url,
                                             self.seals._key, POLICY_PATH, body)
            except Exception:  # noqa: BLE001 - network/ship failure: keep last good policy
                self.state.policy_last_error = "Couldn't reach Coriqo for policy; keeping the current one."
                self._save()
                return
            if not resp.get("changed"):
                self.state.policy_last_error = None
                self._save()
                return
            envelope = resp.get("envelope")
            key_id = ((envelope or {}).get("document") or {}).get("key_id")
            self._key_fetch_failed = False
            public_key = self._trusted_key(key_id, enrollment) if key_id else None
            if public_key is None and self._key_fetch_failed:
                # Not an unknown key: Coriqo's key list couldn't be fetched.
                # Say so, and try again in a minute rather than in ten.
                self.state.policy_last_error = "Couldn't reach Coriqo for its signing key; retrying shortly."
                self.state.last_policy_poll_at = self._now() - POLICY_POLL_S + 60
                self._save()
                return
            from byoai.integrations.shield import apply_managed_envelope
            result = apply_managed_envelope(
                envelope, tenant_slug=enrollment.tenant_slug,
                device_id=self.seals._key.device_id, public_key=public_key,
                path=self._policy_key_path())
            self.state.policy_last_error = result.get("error")
            self._save()

    def policy_status(self) -> dict:
        return {"error": self.state.policy_last_error}

    def _build_entry(self) -> dict:
        """A new outbox entry: the current seal, numbered and signed so
        Coriqo's checkpoint verification accepts it as this device's."""
        # Signed under the chain's own lock: root, count and signature describe
        # the same entries even if the watcher seals a new one this instant.
        cp = self.seals.sign_checkpoint()
        seq = self.state.last_seq + 1
        entry = {
            # One number per send, never reused: two different heads can never
            # share a range, which Coriqo would read as a conflicting record.
            "checkpoint_id": f"shield:{seq}:{cp['root_hex'][:32]}",
            "session_id": SESSION_ID,
            "kind": cp.get("kind", "byoai.shield.checkpoint.v1"),
            "seq_start": seq,
            "seq_end": seq,
            "chain_hash": cp["root_hex"],
            "entries": int(cp["height"]),
            "ts_device": cp["ts"],
            # The seal as the Mac signed it, kept whole for offline checks.
            "checkpoint": cp,
            # This Mac's local record, and the entry this one follows: a new
            # record_id or a prev_chain_hash Coriqo doesn't hold means the
            # record was wiped or skipped, not grown. None after enrolment.
            "record_id": self.seals.record_id,
            "prev_chain_hash": self.state.last_root,
        }
        # Coriqo verifies Ed25519 over canonical(entry minus "sig"), the same
        # rule the recorder's checkpoints follow.
        entry["sig"] = self.seals._key.sign(canonicalize(entry))
        return entry

    def send(self) -> dict:
        """Send now (used by tick and by "Send now"): the waiting outbox entry
        if there is one, else the current seal. Returns the status; failures
        are recorded and retried, never raised."""
        with self._lock:
            state_now = self._now()
            enrolment = self.enrolment()
            if enrolment is None:
                raise ValueError("This Mac isn't connected to Coriqo yet")
            if self.state.outbox is None and not self.has_new() and self.state.last_entry:
                # Heartbeat: the accepted entry again, byte for byte.
                entry = self.state.last_entry
            else:
                if self.state.outbox is None:
                    if self.seals.height == 0:
                        return self.status()
                    # New seal, or (state from before heartbeats, no
                    # last_entry kept) the unchanged one numbered once more.
                    self.state.outbox = self._build_entry()
                    self._save()  # before sending: see PublishState.outbox
                entry = self.state.outbox
            body = {"device_id": self.seals._key.device_id, "checkpoints": [entry],
                    # Fresh on every request (the entry may be a resend):
                    # signed with the body, so a replay reads as stale.
                    "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                             time.gmtime(state_now)),
                    "shield": self._shield_block()}
            try:
                with self._client_factory() as client:
                    resp = post_signed_batch(client, enrolment.coriqo_base_url,
                                             self.seals._key, CHECKPOINT_PATH, body)
            except ShipError as exc:
                self._failed(state_now, exc)
                return self.status()
            except Exception as exc:  # noqa: BLE001 - anything else is transient too
                self._failed(state_now, ShipError(str(exc)))
                return self.status()
            if resp.get("rejected"):
                # Coriqo's "send this again later": keep the outbox, back off.
                self._failed(state_now, ShipError("Coriqo asked for this seal again later"))
                return self.status()
            # Only the seal's own fields change: activity sync and managed-policy
            # state have their own lifecycles and must not be reset by a seal.
            self.state = replace(
                self.state,
                last_root=entry["chain_hash"], last_height=int(entry.get("entries") or 0),
                last_seq=int(entry["seq_end"]), last_sent_at=state_now, last_entry=entry,
                outbox=None, failures=0, next_attempt_at=0.0, needs_attention=False,
                last_error=("Coriqo stored this seal but couldn't verify it."
                            if resp.get("malformed") else None),
            )
            self._save()
            return self.status()

    def _shield_block(self) -> dict:
        """The protection state for this request. A failing check never stops
        a send: it reports that the state is unknown. ``policy_version`` is
        this device's currently applied managed-policy version (None if
        unmanaged), so Coriqo can tell a device's policy has drifted."""
        block: dict = dict(UNKNOWN_PROTECTION)
        try:
            p = self._protection()
            reasons = [str(r) for r in (p.get("reasons") or [])]
            mode = p.get("mode")
            block = {"protecting": bool(p.get("protecting")) and not reasons,
                     "reasons": reasons,
                     "mode": str(mode) if mode is not None else None}
        except Exception:  # noqa: BLE001
            pass
        block["policy_version"] = self._managed_policy_version()
        return block

    def _managed_policy_version(self) -> int | None:
        try:
            from byoai.integrations.shield import load_managed_policy
            managed = load_managed_policy(self._policy_key_path())
        except Exception:  # noqa: BLE001
            return None
        if not managed:
            return None
        doc = managed["envelope"]["document"] or {}
        v = doc.get("version")
        return v if isinstance(v, int) and not isinstance(v, bool) else None

    def _failed(self, now: float, exc: ShipError) -> None:
        s = self.state
        s.failures += 1
        delay = min(BACKOFF_CAP_S, BACKOFF_FIRST_S * 2 ** (s.failures - 1))
        delay *= random.uniform(0.8, 1.2)  # spread retries from many Macs
        if exc.retry_after:
            delay = max(delay, float(exc.retry_after))
        s.next_attempt_at = now + delay
        # Coriqo refuses a request dated too far from its own clock with a 401
        # that says so. That is this Mac's clock, not a revoked device: keep
        # retrying, and tell the person what to fix.
        clock = exc.status_code == 401 and "clock" in str(exc).lower()
        s.needs_attention = exc.status_code in (401, 403) and not clock
        if clock:
            s.last_error = CLOCK_MESSAGE
        elif s.needs_attention:
            s.last_error = ("Coriqo no longer accepts this Mac. Ask your Coriqo "
                            "admin for a new enrolment token and connect again.")
        else:
            s.last_error = "Couldn't reach Coriqo; Shield will try again on its own."
        self._save()

    # -- reporting ----------------------------------------------------------
    def status(self) -> dict:
        e = self.enrolment()
        s = self.state
        next_at = None
        if e is not None:
            if s.next_attempt_at > self._now():
                next_at = s.next_attempt_at
            elif s.last_sent_at:
                waiting = s.outbox is not None or self.has_new()
                next_at = s.last_sent_at + (self.every_s if waiting else self.heartbeat_s)
        return {
            "connected": e is not None,
            "base_url": e.coriqo_base_url if e else None,
            "tenant": e.tenant_slug if e else None,
            "device_id": e.device_id if e else None,
            "enrolled_at": e.enrolled_at if e else None,
            "last_sent_at": s.last_sent_at or None,
            "last_height": s.last_height,
            "has_new": s.outbox is not None or self.has_new(),
            "next_attempt_at": next_at,
            "every_hours": self.every_s / 3600,
            "last_error": s.last_error,
            "needs_attention": s.needs_attention,
            "sync": {"pending": len(s.sync_outbox or []),
                     "last_sent_at": s.sync_last_sent_at or None,
                     "last_error": s.sync_last_error},
        }

    # -- loop -----------------------------------------------------------------
    def start(self) -> threading.Thread:
        def run() -> None:
            while True:
                self.tick()
                time.sleep(TICK_S)
        t = threading.Thread(target=run, name="shield-publisher", daemon=True)
        t.start()
        return t
