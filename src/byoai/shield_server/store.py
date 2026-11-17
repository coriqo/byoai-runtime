"""The server's own SQLite tables: enrolment tokens, signed policies, and
per-device Shield state — everything :mod:`byoai.ingest.IngestStore` does not
already model.

Kept in a database separate from ``IngestStore`` (which owns enrolments,
entries and checkpoints) so this module's schema can evolve without touching
that one, the same separation Coriqo keeps between its ``agent_devices`` and
``shield_policies`` tables. Uses the stdlib ``sqlite3`` the way
``IngestStore`` does: WAL mode, one shared connection guarded by a
``threading.Lock`` (a write lock, not a read/write split — the whole point of
this store is a handful of admin calls per day, not a hot path).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = [
    "DeviceShieldState",
    "PolicyRow",
    "ServerStore",
    "TokenRow",
    "UnknownVersionRace",
    "hash_token",
]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS enrolment_tokens (
    token_hash   TEXT PRIMARY KEY,
    label        TEXT,
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    used_at      TEXT,
    used_by_device TEXT,
    revoked_at   TEXT
);

-- Append-only, exactly like Coriqo's shield_policies table: rows are never
-- updated, only inserted, and `version` is one monotonic counter for the
-- whole org (device_id NULL = tenant/org default, set = per-device
-- override). The unique index is the structural rollback guard the plan
-- asks for: two concurrent writers can't both land the same version, and
-- resolution always picks the highest version row for its key.
CREATE TABLE IF NOT EXISTS shield_policies (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id    TEXT,
    version      INTEGER NOT NULL,
    document_json TEXT NOT NULL,
    signature    TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    created_by   TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_shield_policies_version ON shield_policies(version);
CREATE INDEX IF NOT EXISTS idx_shield_policies_device ON shield_policies(device_id, version);

-- The last `shield` block a device reported (see shield_publish.Publisher's
-- checkpoint batch body) plus the policy version it says it applied — what
-- the admin device list and drift check read.
CREATE TABLE IF NOT EXISTS device_shield_state (
    device_id      TEXT PRIMARY KEY,
    protecting     INTEGER,
    reasons_json   TEXT NOT NULL DEFAULT '[]',
    mode           TEXT,
    policy_version INTEGER,
    last_seen_at   TEXT NOT NULL,
    label          TEXT
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def hash_token(token: str) -> str:
    """Tokens are held hash-only at rest — the plan's own requirement — so a
    stolen database backup cannot be used to enrol devices."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def generate_token() -> str:
    return "shieldtok_" + secrets.token_urlsafe(32)


@dataclass(frozen=True, slots=True)
class TokenRow:
    token_hash: str
    label: str | None
    created_at: str
    expires_at: str | None
    used_at: str | None
    used_by_device: str | None
    revoked_at: str | None

    @property
    def status(self) -> str:
        if self.revoked_at:
            return "revoked"
        if self.used_at:
            return "used"
        if self.expires_at and self.expires_at < _now():
            return "expired"
        return "active"


@dataclass(frozen=True, slots=True)
class PolicyRow:
    id: int
    device_id: str | None
    version: int
    document: dict[str, Any]
    signature: str
    created_at: str
    created_by: str | None

    def envelope(self) -> dict[str, Any]:
        return {"document": self.document, "signature": self.signature}


@dataclass(frozen=True, slots=True)
class DeviceShieldState:
    device_id: str
    protecting: bool | None
    reasons: list[str]
    mode: str | None
    policy_version: int | None
    last_seen_at: str
    label: str | None


class UnknownVersionRace(RuntimeError):
    """Two writers raced for the same version. See
    :meth:`ServerStore.write_policy_locked`, which already holds the
    process-wide write lock across the whole read-modify-write, so this
    should never actually fire outside a bug; it exists as the last line of
    defence the unique index promises."""


class ServerStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # One lock serialises every write (mint/revoke/redeem a token, write a
        # policy version) — the plan's "threading lock plus a unique(version)
        # index" belt-and-suspenders pair.
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> ServerStore:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- enrolment tokens -----------------------------------------------

    def mint_token(self, *, label: str | None = None, ttl_seconds: float | None = None,
                  expires_at: str | None = None) -> str:
        """Mint a single-use enrolment token, returned once (never again —
        only its hash is stored). ``expires_at`` (an RFC 3339 string, what
        the console sends) wins when given; ``ttl_seconds`` is kept for
        callers (the CLI) that would rather say "expire N seconds from now"."""
        token = generate_token()
        if expires_at is None and ttl_seconds is not None:
            expires_at = datetime.fromtimestamp(
                time.time() + ttl_seconds, tz=timezone.utc
            ).isoformat(timespec="microseconds").replace("+00:00", "Z")
        with self._lock:
            self._conn.execute(
                """INSERT INTO enrolment_tokens (token_hash, label, created_at, expires_at)
                   VALUES (?, ?, ?, ?)""",
                (hash_token(token), label, _now(), expires_at),
            )
        return token

    def list_tokens(self) -> list[TokenRow]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM enrolment_tokens ORDER BY created_at DESC"
            ).fetchall()
        return [
            TokenRow(
                token_hash=r["token_hash"], label=r["label"], created_at=r["created_at"],
                expires_at=r["expires_at"], used_at=r["used_at"],
                used_by_device=r["used_by_device"], revoked_at=r["revoked_at"],
            )
            for r in rows
        ]

    def revoke_token(self, token_hash: str) -> bool:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE enrolment_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
                (_now(), token_hash),
            )
            return cur.rowcount > 0

    def redeem_token(self, token: str, *, device_id: str) -> tuple[bool, str, str | None]:
        """Atomically mark ``token`` used, if it is valid. Returns
        ``(ok, reason, label)``; ``reason`` is one of "invalid", "used",
        "expired", "revoked" or "" (ok); ``label`` is the token's label (so
        the caller can carry it onto the freshly enrolled device), ``None``
        on any failure. Single-use is settled here, under the lock — never by
        a separate read then a separate write."""
        token_hash = hash_token(token)
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM enrolment_tokens WHERE token_hash = ?", (token_hash,)
            ).fetchone()
            if row is None:
                return False, "invalid", None
            if row["revoked_at"]:
                return False, "revoked", None
            if row["used_at"]:
                return False, "used", None
            if row["expires_at"] and row["expires_at"] < _now():
                return False, "expired", None
            cur = self._conn.execute(
                """UPDATE enrolment_tokens SET used_at = ?, used_by_device = ?
                   WHERE token_hash = ? AND used_at IS NULL AND revoked_at IS NULL""",
                (_now(), device_id, token_hash),
            )
            if cur.rowcount == 0:
                # Lost a race to another redeem of the same token between the
                # SELECT and here — impossible under our own lock, but the
                # WHERE guard is the real single-use enforcement.
                return False, "used", None
            return True, "", row["label"]

    def find_token_by_hash(self, token_hash: str) -> TokenRow | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM enrolment_tokens WHERE token_hash = ?", (token_hash,)
            ).fetchone()
        return self._row_to_token(row) if row else None

    def find_token_by_id(self, token_id: str) -> TokenRow | None:
        """``token_id`` is a hash prefix (see routes.py's ``_token_wire``).
        ``None`` if no token's hash starts with it, or (a real but
        astronomically unlikely event with a 12-hex-char prefix) more than
        one does — an ambiguous id must never be resolved to the wrong
        token."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM enrolment_tokens WHERE token_hash LIKE ? || '%'", (token_id,)
            ).fetchall()
        matches = [r for r in rows if r["token_hash"].startswith(token_id)]
        return self._row_to_token(matches[0]) if len(matches) == 1 else None

    def revoke_token_by_id(self, token_id: str) -> bool:
        row = self.find_token_by_id(token_id)
        return self.revoke_token(row.token_hash) if row else False

    @staticmethod
    def _row_to_token(row: sqlite3.Row) -> TokenRow:
        return TokenRow(
            token_hash=row["token_hash"], label=row["label"], created_at=row["created_at"],
            expires_at=row["expires_at"], used_at=row["used_at"],
            used_by_device=row["used_by_device"], revoked_at=row["revoked_at"],
        )

    # -- policy -----------------------------------------------------------

    def _next_version_locked(self) -> int:
        """Caller must already hold ``self._lock``. Not exposed on its own —
        a caller that reads this and inserts as two separate locked calls
        (which is exactly what this store used to offer as ``next_version()``
        + ``write_policy()``) reopens the race :meth:`write_policy_locked`
        exists to close: two concurrent writers can both read the same
        "next" version, and the loser hits the unique index as an uncaught
        ``UnknownVersionRace``/500 instead of simply, correctly, getting the
        version after."""
        row = self._conn.execute("SELECT MAX(version) AS v FROM shield_policies").fetchone()
        current = row["v"] if row and row["v"] is not None else 0
        return int(current) + 1

    def write_policy_locked(
        self, *, device_id: str | None,
        build_document: Callable[[int], dict[str, Any]],
        sign: Callable[[dict[str, Any]], str],
        created_by: str | None = None,
    ) -> PolicyRow:
        """Assign the next version and insert its row as ONE critical
        section: ``next_version`` (read), ``build_document``/``sign``
        (compute) and the insert (write) all happen while holding the same
        lock, so a second concurrent writer can only ever run before or after
        this one in full — never interleaved with it, which is what let two
        callers both read the same "next" version under the old
        ``next_version()`` then ``write_policy()`` two-step.
        """
        with self._lock:
            version = self._next_version_locked()
            document = build_document(version)
            if document.get("version") != version:
                raise ValueError("build_document must stamp the version it was handed")
            signature = sign(document)
            return self._insert_policy_locked(
                device_id=device_id, document=document, signature=signature, created_by=created_by)

    def _insert_policy_locked(self, *, device_id: str | None, document: dict[str, Any],
                              signature: str, created_by: str | None) -> PolicyRow:
        """Caller must already hold ``self._lock``."""
        version = document.get("version")
        if not isinstance(version, int) or isinstance(version, bool):
            raise ValueError("document.version must be an int")
        try:
            cur = self._conn.execute(
                """INSERT INTO shield_policies
                     (device_id, version, document_json, signature, created_at, created_by)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (device_id, version, json.dumps(document, sort_keys=True), signature,
                 _now(), created_by),
            )
        except sqlite3.IntegrityError as exc:
            raise UnknownVersionRace(str(exc)) from exc
        row_id = cur.lastrowid
        assert row_id is not None  # an INSERT always sets it
        return PolicyRow(id=row_id, device_id=device_id, version=version, document=document,
                         signature=signature, created_at=_now(), created_by=created_by)

    def latest_row(self, *, device_id: str | None) -> PolicyRow | None:
        with self._lock:
            if device_id is None:
                row = self._conn.execute(
                    "SELECT * FROM shield_policies WHERE device_id IS NULL"
                    " ORDER BY version DESC LIMIT 1"
                ).fetchone()
            else:
                row = self._conn.execute(
                    "SELECT * FROM shield_policies WHERE device_id = ? ORDER BY version DESC LIMIT 1",
                    (device_id,),
                ).fetchone()
        return self._row_to_policy(row) if row else None

    def all_latest_device_overrides(self) -> dict[str, PolicyRow]:
        """Highest-version row per non-null device_id — used for drift."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM shield_policies WHERE device_id IS NOT NULL ORDER BY version"
            ).fetchall()
        out: dict[str, PolicyRow] = {}
        for r in rows:
            out[r["device_id"]] = self._row_to_policy(r)  # ascending: last write wins
        return out

    @staticmethod
    def _row_to_policy(row: sqlite3.Row) -> PolicyRow:
        return PolicyRow(
            id=row["id"], device_id=row["device_id"], version=row["version"],
            document=json.loads(row["document_json"]), signature=row["signature"],
            created_at=row["created_at"], created_by=row["created_by"],
        )

    # -- device shield state ------------------------------------------------

    def record_shield_state(self, device_id: str, block: dict[str, Any] | None, *,
                            label: str | None = None) -> None:
        """Persist the last `shield` block a device reported (see
        ``shield_publish.Publisher._shield_block``). Never raises on a
        malformed block — an unusable one is simply not recorded, mirroring
        Coriqo's ``parse_shield_state``."""
        if not isinstance(block, dict) or not isinstance(block.get("protecting"), bool):
            with self._lock:
                self._conn.execute(
                    """INSERT INTO device_shield_state (device_id, last_seen_at, label)
                       VALUES (?, ?, ?)
                       ON CONFLICT(device_id) DO UPDATE SET
                         last_seen_at = excluded.last_seen_at,
                         label = COALESCE(excluded.label, device_shield_state.label)""",
                    (device_id, _now(), label),
                )
            return
        reasons = [str(r) for r in (block.get("reasons") or []) if isinstance(r, (str, int, float))]
        mode = block.get("mode")
        version = block.get("policy_version")
        version = version if isinstance(version, int) and not isinstance(version, bool) else None
        with self._lock:
            self._conn.execute(
                """INSERT INTO device_shield_state
                     (device_id, protecting, reasons_json, mode, policy_version, last_seen_at, label)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(device_id) DO UPDATE SET
                     protecting = excluded.protecting,
                     reasons_json = excluded.reasons_json,
                     mode = excluded.mode,
                     policy_version = excluded.policy_version,
                     last_seen_at = excluded.last_seen_at,
                     label = COALESCE(excluded.label, device_shield_state.label)""",
                (device_id, int(bool(block.get("protecting"))), json.dumps(reasons),
                 str(mode) if mode is not None else None, version, _now(), label),
            )

    def device_shield_state(self, device_id: str) -> DeviceShieldState | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM device_shield_state WHERE device_id = ?", (device_id,)
            ).fetchone()
        if row is None:
            return None
        return DeviceShieldState(
            device_id=row["device_id"],
            protecting=None if row["protecting"] is None else bool(row["protecting"]),
            reasons=json.loads(row["reasons_json"]), mode=row["mode"],
            policy_version=row["policy_version"], last_seen_at=row["last_seen_at"],
            label=row["label"],
        )

    def all_device_shield_state(self) -> dict[str, DeviceShieldState]:
        with self._lock:
            rows = self._conn.execute("SELECT * FROM device_shield_state").fetchall()
        out = {}
        for row in rows:
            out[row["device_id"]] = DeviceShieldState(
                device_id=row["device_id"],
                protecting=None if row["protecting"] is None else bool(row["protecting"]),
                reasons=json.loads(row["reasons_json"]), mode=row["mode"],
                policy_version=row["policy_version"], last_seen_at=row["last_seen_at"],
                label=row["label"],
            )
        return out
