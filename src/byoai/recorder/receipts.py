"""Local record of every trace sent to Coriqo, and the receipts fetched for them.

``publish_session`` writes one row per trace it sends, keyed by
``(session_id, step_index)``, BEFORE the request goes out. It then reconciles
each row against the response: a row whose trace came back with an
``event_hash`` is acknowledged; a row that did not (omitted from ``traces``,
empty or missing hash, or a ``recorded`` count larger than the traces listed)
stays unacknowledged. ``verify.verify_receipts`` reports an unacknowledged row
older than the configured age as ``unacknowledged``, so a server that swallows
an event is caught even though it never returned anything to store.

Each row also keeps the input/output hashes computed locally from what was
sent. The response echoes ``input_hash`` and ``output_hash``; a difference is a
``content_mismatch`` finding. That proves the echoed record matches what was
sent. It does NOT prove the server's sealed event hash covers those fields:
only the inclusion proof plus Coriqo's own event schema speak to that.

A background pass later asks Coriqo for the receipt of each acknowledged row
old enough to be covered by a checkpoint and stores the bundle beside it.

KNOWN LIMITATION: the store is an UNSIGNED JSON sidecar
(``<ledger>.receipts.json``). Anyone who can write that file can delete rows,
and a deleted row is not detectable from the file alone. The receipt bundles
themselves are checked cryptographically (against a pinned key); the list of
which traces SHOULD have receipts is not. Treat a clean report as "nothing in
this file is wrong", not as "nothing was omitted from this file".

Only traces sent through ``publish_session`` are tracked. The ``Shipper`` path
ships ledger entries to the ingest endpoint, whose response carries no
per-trace ``event_hash`` to reconcile against, so it cannot feed this store.

Concurrency: one process-wide lock per resolved store path, plus an OS file
lock (``fcntl.flock`` on POSIX, on a ``.lock`` sibling) around every
load-mutate-save, so threads and separate processes lose no rows. Writes go to
a uniquely named temp file, are fsynced, then ``os.replace``d. A corrupt or
unreadable store raises :class:`ReceiptStoreError`; it is never treated as
empty and never overwritten.

Nothing here may block or fail the request path: fetch errors are logged and
retried next pass.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import tempfile
import threading
from collections.abc import Callable, Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:  # POSIX only; elsewhere the in-process lock is the only guard.
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

log = logging.getLogger(__name__)

#: Default age before a receipt is requested. Checkpoints are cut on an
#: interval, so a fresh event is expected to be pending.
DEFAULT_MIN_AGE_SECONDS = 300.0

#: Max rows one fetch pass will contact Coriqo for.
DEFAULT_MAX_ROWS_PER_PASS = 50

#: A 403/404 from the receipts route this many times in a row on a row is
#: reported as ``receipts_unavailable`` instead of a silent retry.
UNAVAILABLE_AFTER = 3
UNAVAILABLE_STATUSES = (403, 404)

STORE_LIMITATION = (
    "The receipt store is an unsigned local file: rows deleted from it cannot "
    "be detected. Receipt bundles are verified cryptographically; the list of "
    "traces expected to have receipts is not."
)
CONTENT_SCOPE_NOTE = (
    "content_mismatch compares the input/output hashes Coriqo echoed with "
    "hashes computed locally from what was sent. It shows the echoed record "
    "matches what was sent; it does not show the sealed event hash covers "
    "those fields."
)


class ReceiptStoreError(RuntimeError):
    """The store file exists but cannot be read as a receipt store."""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def store_path_for(ledger_path: str | Path) -> Path:
    p = Path(ledger_path)
    return p.with_name(p.name + ".receipts.json")


def row_key(session_id: str, step_index: Any, trajectory_id: str | None = None) -> str:
    """Row key. With a ``trajectory_id`` it is ``<trajectory>/<session>#<step>``
    so publishing one session twice keeps both runs' rows. Rows written before
    that change are keyed ``<session>#<step>``; they are read as-is (their
    stored ``key`` is what verify and fetch use) and call sites without a
    trajectory id still address them."""
    if trajectory_id:
        return f"{trajectory_id}/{session_id}#{step_index}"
    return f"{session_id}#{step_index}"


def canonical_hash(obj: Any) -> str | None:
    """Bare-hex sha256 over canonical JSON, the way Coriqo hashes trace
    inputs/outputs (sorted keys, compact separators, ``ensure_ascii=False``,
    ``default=str``). ``None`` in, ``None`` out."""
    if obj is None:
        return None
    encoded = json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )
    return hashlib.sha256(encoded.encode()).hexdigest()


def _norm_hash(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text[len("sha256:"):] if text.startswith("sha256:") else text


def content_mismatches(
    expected_input: str | None,
    expected_output: str | None,
    got: dict[str, Any],
) -> list[str]:
    """Names of the fields where ``got`` disagrees with the locally computed
    hashes. A field ``got`` does not carry at all counts as a mismatch when we
    expected a value; an echoed value we did not expect is one too."""
    out = []
    for name, want in (("input_hash", expected_input), ("output_hash", expected_output)):
        if _norm_hash(got.get(name)) != _norm_hash(want):
            out.append(name)
    return out


_locks_guard = threading.Lock()
_path_locks: dict[str, threading.RLock] = {}


def _lock_for(path: Path) -> threading.RLock:
    key = str(path.resolve())
    with _locks_guard:
        lock = _path_locks.get(key)
        if lock is None:
            lock = _path_locks[key] = threading.RLock()
        return lock


class ReceiptStore:
    """JSON file of sent traces keyed by ``session_id#step_index``.

    Every instance for the same resolved path shares one lock, so a publisher
    and a fetcher constructed separately still serialise.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = _lock_for(self.path)

    @classmethod
    def for_ledger(cls, ledger: Any) -> ReceiptStore:
        return cls(store_path_for(ledger.path))

    # -- storage -----------------------------------------------------------

    def _load(self) -> dict[str, Any]:
        try:
            raw = self.path.read_text()
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise ReceiptStoreError(f"cannot read receipt store {self.path}: {exc}") from exc
        try:
            data = json.loads(raw)
        except ValueError as exc:
            raise ReceiptStoreError(f"receipt store {self.path} is corrupt: {exc}") from exc
        rows = data.get("entries") if isinstance(data, dict) else None
        if not isinstance(rows, dict):
            raise ReceiptStoreError(f"receipt store {self.path} has no 'entries' object")
        return rows

    def _save(self, rows: dict[str, Any]) -> None:
        parent = self.path.parent
        os.makedirs(parent, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=parent, prefix=self.path.name + ".", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as fh:
                json.dump({"version": 2, "entries": rows}, fh, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        with contextlib.suppress(OSError):  # best effort: persist the rename
            dfd = os.open(parent, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)

    @contextlib.contextmanager
    def _txn(self) -> Iterator[dict[str, Any]]:
        """Load, let the caller mutate, save. Held under both locks."""
        with self._lock:
            lock_fh = None
            if fcntl is not None:
                os.makedirs(self.path.parent, exist_ok=True)
                lock_fh = open(self.path.with_name(self.path.name + ".lock"), "a")
                fcntl.flock(lock_fh, fcntl.LOCK_EX)
            try:
                rows = self._load()
                yield rows
                self._save(rows)
            finally:
                if lock_fh is not None:
                    lock_fh.close()  # releases the flock

    def entries(self) -> list[Any]:
        """Every row. Raises :class:`ReceiptStoreError` on a corrupt store."""
        with self._lock:
            return list(self._load().values())

    # -- recording ---------------------------------------------------------

    def record_sent(
        self,
        session_id: str,
        step_index: Any,
        *,
        input_hash: str | None,
        output_hash: str | None,
        sent_at: str | None = None,
        trajectory_id: str | None = None,
    ) -> None:
        """Note that a trace is about to be sent. Idempotent: a re-send keeps the
        original ``sent_at`` so age is measured from the first attempt."""
        key = row_key(session_id, step_index, trajectory_id)
        with self._txn() as rows:
            if key in rows:
                rows[key].pop("rejected", None)  # a re-send waives an earlier rejection
                # On re-send with different payload, update the hashes so verify doesn't
                # report a stale mismatch. Store a note if they changed.
                old_input = rows[key].get("expected_input_hash")
                old_output = rows[key].get("expected_output_hash")
                if old_input != input_hash or old_output != output_hash:
                    rows[key]["expected_input_hash"] = input_hash
                    rows[key]["expected_output_hash"] = output_hash
                    rows[key]["payload_recomputed"] = True
                return
            rows[key] = {
                "key": key,
                "trajectory_id": trajectory_id,
                "session_id": session_id,
                "step_index": step_index,
                "sent_at": sent_at or utc_now().isoformat(),
                "expected_input_hash": input_hash,
                "expected_output_hash": output_hash,
                "event_hash": None,
            }

    def record_ack(
        self,
        session_id: str,
        step_index: Any,
        response_trace: dict[str, Any],
        trajectory_id: str | None = None,
    ) -> None:
        """Reconcile one sent row with the trace object the server returned."""
        key = row_key(session_id, step_index, trajectory_id)
        event_hash = response_trace.get("event_hash")
        with self._txn() as rows:
            row = rows.get(key)
            if row is None:
                return
            if not isinstance(event_hash, str) or not event_hash.strip():
                return  # still unacknowledged
            row["event_hash"] = event_hash
            row["echoed_input_hash"] = response_trace.get("input_hash")
            row["echoed_output_hash"] = response_trace.get("output_hash")
            bad = content_mismatches(
                row.get("expected_input_hash"), row.get("expected_output_hash"), response_trace
            )
            row["content_mismatch"] = bad
            if bad:
                log.warning(
                    "coriqo: trace %s echoed a different %s than was sent",
                    key, " and ".join(bad),
                )

    def mark_rejected(
        self,
        session_id: str,
        step_index: Any,
        status: int | None,
        trajectory_id: str | None = None,
    ) -> None:
        """The whole batch carrying this row was refused (HTTP error or the
        POST raising). Distinct from a swallowed event: the server answered
        with an error, so absence of an event_hash is expected."""
        key = row_key(session_id, step_index, trajectory_id)
        with self._txn() as rows:
            row = rows.get(key)
            if row is None or row.get("event_hash"):
                return
            row["rejected"] = {"status": status, "at": utc_now().isoformat()}

    def note_device_receipt(
        self,
        session_id: str,
        step_index: Any,
        finding: str,
        reason: str,
        *,
        status: int | None = None,
        seal: str | None = None,
        trajectory_id: str | None = None,
    ) -> None:
        """A step's device receipt did not reach Coriqo. ``finding`` is one of
        ``device_receipt_refused`` (422, the receipt failed Coriqo's checks),
        ``device_receipt_unsent`` (any other failure; sending it again is safe)
        or ``device_receipt_withheld`` (the sealed row holds message text)."""
        key = row_key(session_id, step_index, trajectory_id)
        with self._txn() as rows:
            row = rows.get(key)
            if row is not None:
                row["device_receipt"] = {
                    "finding": finding, "reason": reason, "status": status,
                    "seal": seal, "at": utc_now().isoformat(),
                }

    def clear_device_receipt(
        self, session_id: str, step_index: Any, trajectory_id: str | None = None
    ) -> None:
        """Coriqo holds this step's receipt now, so an earlier finding is over."""
        key = row_key(session_id, step_index, trajectory_id)
        with self._txn() as rows:
            row = rows.get(key)
            if row is not None:
                row.pop("device_receipt", None)

    def forget(self, key: str) -> bool:
        """Drop a row (used to waive a rejected batch). True if it existed."""
        with self._txn() as rows:
            return rows.pop(key, None) is not None

    def store_bundle(self, key: str, bundle: dict[str, Any]) -> None:
        with self._txn() as rows:
            row = rows.get(key)
            if row is None:
                return
            row["bundle"] = bundle
            row["fetched_at"] = utc_now().isoformat()
            row.pop("fetch_error", None)

    def clear_fetch_error(self, key: str) -> None:
        with self._txn() as rows:
            row = rows.get(key)
            if row is not None:
                row.pop("fetch_error", None)

    def note_fetch_error(self, key: str, status: int | None) -> None:
        with self._txn() as rows:
            row = rows.get(key)
            if row is None:
                return
            prev = row.get("fetch_error") or {}
            same = prev.get("status") == status
            row["fetch_error"] = {
                "status": status,
                "count": (prev.get("count", 0) + 1) if same else 1,
                "last_at": utc_now().isoformat(),
            }

    def awaiting(self, *, min_age_seconds: float, now: datetime | None = None) -> list[dict[str, Any]]:
        """Acknowledged rows with no bundle yet and old enough to ask for.
        Rows with an unparseable ``sent_at`` are skipped here; verify reports them."""
        now = now or utc_now()
        out = []
        for row in self.entries():
            if not isinstance(row, dict) or row.get("bundle") or not row.get("event_hash"):
                continue
            try:
                age = (now - parse_ts(row["sent_at"])).total_seconds()
            except (KeyError, ValueError, TypeError, AttributeError):
                continue
            if age >= min_age_seconds:
                out.append(row)
        return out


def fetch_receipts(
    client: Any,
    store: ReceiptStore,
    *,
    min_age_seconds: float = DEFAULT_MIN_AGE_SECONDS,
    now: datetime | None = None,
    max_rows: int = DEFAULT_MAX_ROWS_PER_PASS,
    should_stop: Callable[[], bool] | None = None,
) -> int:
    """One bounded pass. Never raises. Returns how many receipts landed.

    Contacts Coriqo for at most ``max_rows`` rows and checks ``should_stop``
    between rows. A 403/404 is recorded on the row (see ``UNAVAILABLE_AFTER``)
    so a route that is not deployed shows up in verify, not as silence.
    """
    landed = 0
    try:
        rows = store.awaiting(min_age_seconds=min_age_seconds, now=now)[:max_rows]
    except Exception as exc:  # noqa: BLE001 - background pass must not raise
        log.warning("coriqo: receipt store unusable, no fetch this pass: %s", exc)
        return 0
    for row in rows:
        if should_stop is not None and should_stop():
            break
        key, event_hash = row["key"], row["event_hash"]
        try:
            bundle = client.get_receipt(event_hash)
        except Exception as exc:  # noqa: BLE001
            status = getattr(exc, "status_code", None)
            if status in UNAVAILABLE_STATUSES:
                log.warning("coriqo: receipts route answered %s for %s", status, key)
            else:
                log.debug("coriqo: receipt fetch for %s failed, will retry: %s", key, exc)
            try:
                store.note_fetch_error(key, status)
            except Exception as exc2:  # noqa: BLE001
                log.warning("coriqo: could not record fetch error: %s", exc2)
            continue
        if bundle:
            try:
                store.store_bundle(key, bundle)
                landed += 1
            except Exception as exc:  # noqa: BLE001
                log.warning("coriqo: could not store receipt %s: %s", key, exc)
        elif row.get("fetch_error"):
            # The route answered (e.g. 202 pending): it is deployed, so a past
            # 403/404 streak no longer describes it.
            try:
                store.clear_fetch_error(key)
            except Exception as exc:  # noqa: BLE001
                log.warning("coriqo: could not clear fetch error: %s", exc)
    return landed


class ReceiptFetcher:
    """Daemon thread running :func:`fetch_receipts` every ``interval_seconds``.

    The first pass runs immediately. With ``owns_client=True`` the fetcher
    closes ``client`` itself: from :meth:`stop` only once the thread has
    actually exited, and from :meth:`start` if starting the thread fails.
    """

    def __init__(
        self,
        client: Any,
        store: ReceiptStore,
        *,
        interval_seconds: float = 60.0,
        min_age_seconds: float = DEFAULT_MIN_AGE_SECONDS,
        max_rows_per_pass: int = DEFAULT_MAX_ROWS_PER_PASS,
        owns_client: bool = False,
    ) -> None:
        self._client, self._store = client, store
        self._interval, self._min_age = interval_seconds, min_age_seconds
        self._max_rows = max_rows_per_pass
        self._owns_client = owns_client
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="coriqo-receipts", daemon=True)
        self._closed = False

    def _close_client(self) -> None:
        if self._owns_client and not self._closed:
            self._closed = True
            try:
                self._client.close()
            except Exception:  # noqa: BLE001
                log.debug("coriqo: closing receipt client failed", exc_info=True)

    def start(self) -> ReceiptFetcher:
        try:
            self._thread.start()
        except BaseException:
            self._close_client()
            raise
        return self

    def stop(self, timeout: float = 5.0) -> bool:
        """Stop the thread. Returns True if it exited; the client is closed only then."""
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout)
        if self._thread.is_alive():
            log.warning("coriqo: receipt fetcher still running after %ss; client left open", timeout)
            return False
        self._close_client()
        return True

    def _run(self) -> None:
        while not self._stop.is_set():
            fetch_receipts(
                self._client, self._store,
                min_age_seconds=self._min_age,
                max_rows=self._max_rows,
                should_stop=self._stop.is_set,
            )
            if self._stop.wait(self._interval):
                break
