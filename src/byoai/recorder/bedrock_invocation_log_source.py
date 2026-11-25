"""Read an Amazon Bedrock model-invocation log and seal what it holds (W10, Path 6).

The reader runs on the bank's side as its own enrolled device: it pages CloudWatch Logs
(``FilterLogEvents``) over a window, reads bodies over 100 KB from the large-data S3 location,
hands each record to :func:`byoai.recorder.bedrock_invocation_log.normalize` and seals the
events through a normal :class:`~byoai.recorder.integration.Recorder`, so the payload mode,
the hash chain, checkpoints and shipping are the same as for every other path.

One sweep:

1. Settings from Coriqo (``GET /api/v1/agent-runtime/capture-config``), else the last cached
   copy, else Coriqo's defaults compiled in here. ``paused`` reads nothing.
2. Window ``[watermark - overlap, now - settle)``; a new reader starts ``first_backfill_hours``
   back; anything older than ``max_catchup_hours`` is declared a gap and shown, never skipped
   silently.
3. Every record in the window, oldest first; ids are derived from the record, and ids already
   in the ledger are skipped before append, so re-reading a window seals nothing new.
4. The watermark moves only after every record was sealed or counted. A status block is posted
   to Coriqo after every sweep, including empty and failed ones
   (``POST /api/v1/agent-runtime/source-state``).

This is the only module on this path that imports ``boto3`` (the ``bedrock-agent`` extra).
State that is not evidence (watermark, the tool-call index used for linking, declared gaps, the
settings cache) lives in ``bedrock_log_state.db`` beside the ledger, so losing it never touches
the chain.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import json
import logging
import os
import random
import sqlite3
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from .bedrock_invocation_log import (
    PROVIDER,
    SCOPE_ALL_CALLS,
    SCOPE_TOOL_CALLS,
    IndexedCall,
    InvocationRecord,
    RecordRejected,
    normalize,
    parse_record,
)
from .canonical import canonicalize
from .ledger import LedgerWriteError

if TYPE_CHECKING:
    from .extract import PartialEvent
    from .integration import Recorder

log = logging.getLogger("byoai.recorder.bedrock_log")

CAPTURE_CONFIG_PATH = "/api/v1/agent-runtime/capture-config"
SOURCE_STATE_PATH = "/api/v1/agent-runtime/source-state"
STATE_DB_NAME = "bedrock_log_state.db"
LOCK_NAME = "bedrock-log-reader.lock"
KIND = "bedrock_invocation_log"

#: Coriqo's defaults for the tenant setting `bedrock_log_capture`, with the bounds Coriqo
#: enforces on write. Unset in Coriqo, or Coriqo unreachable with no cached copy: these apply.
CONFIG_DEFAULTS: dict[str, Any] = {
    "paused": False,
    "scope": SCOPE_TOOL_CALLS,
    "interval_minutes": 15,
    "overlap_minutes": 15,
    "settle_minutes": 5,
    "link_gap_minutes": 60,
    "first_backfill_hours": 24,
    "max_catchup_hours": 168,
}
CONFIG_BOUNDS: dict[str, tuple[int, int]] = {
    "interval_minutes": (1, 1440),
    "overlap_minutes": (0, 1440),
    "settle_minutes": (0, 120),
    "link_gap_minutes": (1, 10080),
    "first_backfill_hours": (0, 720),
    "max_catchup_hours": (1, 2160),
}

#: Host constants (W10 §4.2): a sweep stops reading at either cap and reports `truncated`.
MAX_RECORDS_PER_SWEEP = 50_000
MAX_MESSAGE_BYTES_PER_SWEEP = 500 * 1024 * 1024
DEFAULT_S3_MAX_BYTES = 10 * 1024 * 1024
THROTTLE_TRIES = 5
_THROTTLE_CODES = frozenset(
    {
        "ThrottlingException",
        "TooManyRequestsException",
        "RequestLimitExceeded",
        "LimitExceededException",
        "SlowDown",
    }
)
_DENIED_CODES = frozenset({"AccessDeniedException", "AccessDenied", "UnauthorizedOperation"})
_GZIP_MAGIC = b"\x1f\x8b"


# -- settings --------------------------------------------------------------------------


def effective_config(raw: Any) -> dict[str, Any]:
    """The settings to use: Coriqo's defaults, overlaid with every value from `raw` that is in
    bounds. A value out of bounds keeps the default, the same rule Coriqo applies on read."""
    config = dict(CONFIG_DEFAULTS)
    if not isinstance(raw, dict):
        return config
    if isinstance(raw.get("paused"), bool):
        config["paused"] = raw["paused"]
    if raw.get("scope") in (SCOPE_TOOL_CALLS, SCOPE_ALL_CALLS):
        config["scope"] = raw["scope"]
    for key, (low, high) in CONFIG_BOUNDS.items():
        value = raw.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high:
            config[key] = value
    return config


def config_sha256(config: dict[str, Any]) -> str:
    return hashlib.sha256(canonicalize(config)).hexdigest()


# -- state ---------------------------------------------------------------------------


class StateDB:
    """The reader's own state: watermark, tool-call index, declared gaps, settings cache.

    Also the :class:`~byoai.recorder.bedrock_invocation_log.LinkIndex` the normaliser links
    tool results through. SQLite in WAL mode, separate from the ledger.
    """

    def __init__(self, path: Path) -> None:
        self.created = not path.exists()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS watermark (
                source_arn TEXT PRIMARY KEY, through_ms INTEGER NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tool_use_index (
                tool_use_id TEXT PRIMARY KEY, account TEXT, region TEXT, principal TEXT,
                ts_ms INTEGER NOT NULL, request_id TEXT, session_id TEXT, trace_id TEXT,
                span_id TEXT, tool_name TEXT, result_seen INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS gaps (
                source_arn TEXT, from_ms INTEGER, to_ms INTEGER, declared_at TEXT);
            CREATE TABLE IF NOT EXISTS config_cache (
                id INTEGER PRIMARY KEY CHECK (id = 1), fetched_at TEXT, body_json TEXT,
                sha256 TEXT);
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # watermark
    def watermark(self, source: str) -> int | None:
        row = self._conn.execute(
            "SELECT through_ms FROM watermark WHERE source_arn = ?", (source,)
        ).fetchone()
        return row[0] if row else None

    def set_watermark(self, source: str, through_ms: int) -> None:
        self._conn.execute(
            "INSERT INTO watermark VALUES (?, ?, ?) ON CONFLICT(source_arn) DO UPDATE SET "
            "through_ms = excluded.through_ms, updated_at = excluded.updated_at",
            (source, through_ms, _iso(time.time() * 1000)),
        )
        self._conn.commit()

    # gaps
    def declare_gap(self, source: str, from_ms: int, to_ms: int) -> None:
        self._conn.execute(
            "INSERT INTO gaps VALUES (?, ?, ?, ?)",
            (source, from_ms, to_ms, _iso(time.time() * 1000)),
        )
        self._conn.commit()

    def gaps(self, source: str) -> list[tuple[int, int]]:
        rows = self._conn.execute(
            "SELECT from_ms, to_ms FROM gaps WHERE source_arn = ? ORDER BY from_ms DESC LIMIT 20",
            (source,),
        )
        return [(r[0], r[1]) for r in rows.fetchall()]

    # settings cache
    def cache_config(self, body: dict, sha: str) -> None:
        self._conn.execute(
            "INSERT INTO config_cache VALUES (1, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET "
            "fetched_at = excluded.fetched_at, body_json = excluded.body_json, "
            "sha256 = excluded.sha256",
            (_iso(time.time() * 1000), json.dumps(body), sha),
        )
        self._conn.commit()

    def cached_config(self) -> dict | None:
        row = self._conn.execute("SELECT body_json FROM config_cache WHERE id = 1").fetchone()
        return json.loads(row[0]) if row else None

    # LinkIndex
    def get(self, tool_use_id: str) -> IndexedCall | None:
        row = self._conn.execute(
            "SELECT tool_use_id, account, region, principal, ts_ms, request_id, session_id, "
            "trace_id, span_id, "
            "tool_name, result_seen FROM tool_use_index WHERE tool_use_id = ?",
            (tool_use_id,),
        ).fetchone()
        if row is None:
            return None
        return IndexedCall(*row[:10], result_seen=bool(row[10]))

    def put(self, call: IndexedCall) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO tool_use_index VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                call.tool_use_id,
                call.account,
                call.region,
                call.principal,
                call.ts_ms,
                call.request_id,
                call.session_id,
                call.trace_id,
                call.span_id,
                call.tool_name,
                int(call.result_seen),
            ),
        )

    def mark_result_seen(self, tool_use_id: str) -> None:
        self._conn.execute(
            "UPDATE tool_use_index SET result_seen = 1 WHERE tool_use_id = ?", (tool_use_id,)
        )

    def commit(self) -> None:
        self._conn.commit()

    def rollback(self) -> None:
        self._conn.rollback()

    @contextlib.contextmanager
    def record_scope(self) -> Iterator[None]:
        """Undo one record's index writes if reading it fails, inside the sweep's transaction."""
        if not self._conn.in_transaction:
            self._conn.execute("BEGIN")
        self._conn.execute("SAVEPOINT record")
        try:
            yield
        except BaseException:
            self._conn.execute("ROLLBACK TO record")
            self._conn.execute("RELEASE record")
            raise
        self._conn.execute("RELEASE record")

    def awaiting_result(self) -> int:
        return self._conn.execute(
            "SELECT COUNT(*) FROM tool_use_index WHERE result_seen = 0"
        ).fetchone()[0]

    def prune(self, older_than_ms: int) -> int:
        """Drop index rows past the link limit. Returns how many never saw a result."""
        unanswered = self._conn.execute(
            "SELECT COUNT(*) FROM tool_use_index WHERE ts_ms < ? AND result_seen = 0",
            (older_than_ms,),
        ).fetchone()[0]
        self._conn.execute("DELETE FROM tool_use_index WHERE ts_ms < ?", (older_than_ms,))
        self._conn.commit()
        return unanswered


def _iso(ms: float) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class ReaderBusy(RuntimeError):
    """Another reader holds this recorder directory."""


@contextlib.contextmanager
def reader_lock(directory: Path) -> Iterator[None]:
    """One reader per ledger: an exclusive lock on ``<dir>/bedrock-log-reader.lock``."""
    import fcntl

    handle = open(directory / LOCK_NAME, "a+")  # noqa: SIM115 - held for the process lifetime
    try:
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ReaderBusy(
                f"another Bedrock log reader is already running on {directory}. "
                "Run one reader per recorder directory, each enrolled as its own device."
            ) from None
        yield
    finally:
        handle.close()


# -- AWS ------------------------------------------------------------------------------


class SourceError(Exception):
    """The log group cannot be read. ``reason`` is the status reason Coriqo shows."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason


class S3ReadError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class LogEvent:
    message: str
    timestamp: int
    ingestion_time: int | None


class LogSource(Protocol):
    """What a sweep needs from AWS. :class:`AwsLogSource` is the real one; tests pass fakes."""

    def describe(self) -> dict[str, str]: ...
    def logging_configuration(self) -> dict[str, Any] | str: ...
    def events(self, start_ms: int, end_ms: int) -> Iterator[LogEvent]: ...
    def read_s3(self, path: str, max_bytes: int) -> bytes: ...


def _error_code(exc: Exception) -> str | None:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = (response.get("Error") or {}).get("Code")
        return code if isinstance(code, str) else None
    return None


def _read_failure_reason(exc: Exception) -> str:
    """The status reason for an AWS error while reading the log group's events."""
    code = _error_code(exc)
    if code in _DENIED_CODES:
        return "access_denied_logs"
    if code == "ResourceNotFoundException":
        return "log_group_not_found"
    return "aws_error"


class AwsLogSource:
    """CloudWatch Logs, S3 and Bedrock through boto3 clients (or fakes with the same methods).

    Every call has a timeout (botocore config) and throttling is retried with exponential
    backoff and jitter, at most :data:`THROTTLE_TRIES` times; then the sweep stops without
    moving the watermark. Never unmasks: a CloudWatch data protection policy is the bank's own
    control, and masked values are sealed as returned.
    """

    def __init__(
        self,
        *,
        log_group: str,
        region: str,
        logs: Any,
        s3: Any = None,
        bedrock: Any = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.log_group = log_group
        self.region = region
        self._logs = logs
        self._s3 = s3
        self._bedrock = bedrock
        self._sleep = sleep

    @classmethod
    def from_environment(
        cls,
        *,
        log_group: str,
        region: str,
        role_arn: str | None = None,
        external_id: str | None = None,
    ) -> AwsLogSource:
        import boto3
        from botocore.config import Config

        config = Config(
            connect_timeout=5, read_timeout=30, retries={"max_attempts": 2, "mode": "standard"}
        )
        session = boto3.Session(region_name=region)
        if role_arn:
            params: dict[str, Any] = {
                "RoleArn": role_arn,
                "RoleSessionName": "byoai-bedrock-log-reader",
            }
            if external_id:
                params["ExternalId"] = external_id
            creds = session.client("sts", config=config).assume_role(**params)["Credentials"]
            session = boto3.Session(
                region_name=region,
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
            )
        return cls(
            log_group=log_group,
            region=region,
            logs=session.client("logs", config=config),
            s3=session.client("s3", config=config),
            bedrock=session.client("bedrock", config=config),
        )

    def _call(self, fn: Callable[..., Any], **kwargs: Any) -> Any:
        delay = 1.0
        for attempt in range(THROTTLE_TRIES):
            try:
                return fn(**kwargs)
            except Exception as exc:  # noqa: BLE001 - botocore errors are classified by code
                if _error_code(exc) not in _THROTTLE_CODES:
                    raise
                if attempt == THROTTLE_TRIES - 1:
                    raise SourceError("throttled", str(exc)) from exc
                self._sleep(min(delay, 30.0) * (0.5 + random.random()))
                delay *= 2
        raise SourceError("throttled")  # pragma: no cover - loop always returns or raises

    def describe(self) -> dict[str, str]:
        is_arn = self.log_group.startswith("arn:")
        prefix = (
            self.log_group.rsplit(":log-group:", 1)[-1].split(":", 1)[0]
            if is_arn
            else self.log_group
        )
        try:
            page = self._call(self._logs.describe_log_groups, logGroupNamePrefix=prefix, limit=50)
        except SourceError:
            raise
        except Exception as exc:  # noqa: BLE001
            code = _error_code(exc)
            raise SourceError(
                "access_denied_logs" if code in _DENIED_CODES else "log_group_not_found", str(exc)
            ) from exc
        for group in page.get("logGroups") or []:
            if group.get("logGroupName") == prefix:
                arn = str(group.get("arn") or "").removesuffix(":*")
                return {
                    "arn": arn or prefix,
                    "account_id": arn.split(":")[4] if arn.count(":") >= 4 else "",
                }
        raise SourceError("log_group_not_found", prefix)

    def logging_configuration(self) -> dict[str, Any] | str:
        if self._bedrock is None:
            return "unknown"
        try:
            config = (
                self._call(self._bedrock.get_model_invocation_logging_configuration) or {}
            ).get("loggingConfig")
        except Exception:  # noqa: BLE001 - optional permission; the status says "unknown"
            return "unknown"
        if not isinstance(config, dict):
            return {
                "enabled": False,
                "cloudwatch": False,
                "text_delivery": False,
                "large_data_s3": False,
            }
        cloudwatch = config.get("cloudWatchConfig") or {}
        return {
            "enabled": True,
            "cloudwatch": bool(cloudwatch.get("logGroupName")),
            "text_delivery": bool(config.get("textDataDeliveryEnabled")),
            "large_data_s3": bool(
                (cloudwatch.get("largeDataDeliveryS3Config") or {}).get("bucketName")
            ),
        }

    def events(self, start_ms: int, end_ms: int) -> Iterator[LogEvent]:
        params: dict[str, Any] = {"startTime": start_ms, "endTime": end_ms}
        if self.log_group.startswith("arn:"):
            params["logGroupIdentifier"] = self.log_group
        else:
            params["logGroupName"] = self.log_group
        token: str | None = None
        while True:
            try:
                page = self._call(
                    self._logs.filter_log_events,
                    **params,
                    **({"nextToken": token} if token else {}),
                )
            except SourceError:
                raise
            except Exception as exc:  # noqa: BLE001 - botocore errors are classified by code
                raise SourceError(_read_failure_reason(exc), str(exc)) from exc
            for event in page.get("events") or []:
                message = event.get("message")
                if isinstance(message, str) and isinstance(event.get("timestamp"), int):
                    yield LogEvent(message, event["timestamp"], event.get("ingestionTime"))
            new_token = page.get("nextToken")
            if not new_token or new_token == token:
                return
            token = new_token

    def read_s3(self, path: str, max_bytes: int) -> bytes:
        if self._s3 is None:
            raise S3ReadError("no_client")
        bucket, _, key = path.removeprefix("s3://").partition("/")
        try:
            response = self._call(self._s3.get_object, Bucket=bucket, Key=key)
        except SourceError as exc:
            raise S3ReadError("throttled") from exc
        except Exception as exc:  # noqa: BLE001
            code = _error_code(exc)
            raise S3ReadError(
                "access_denied"
                if code in _DENIED_CODES
                else "not_found"
                if code in ("NoSuchKey", "404")
                else "error"
            ) from exc
        if int(response.get("ContentLength") or 0) > max_bytes:
            raise S3ReadError("over_cap")
        data = response["Body"].read(max_bytes + 1)
        if len(data) > max_bytes:
            raise S3ReadError("over_cap")
        return data


# -- the sweep -------------------------------------------------------------------------


@dataclass
class SweepCounters:
    values: dict[str, Any] = field(
        default_factory=lambda: {
            "records_read": 0,
            "calls_sealed": 0,
            "events_sealed": 0,
            "already_sealed": 0,
            "out_of_scope": 0,
            "unsupported_shape": {},
            "body_in_s3_unread": {},
            "body_missing_over_100kb": 0,
            "tool_calls_awaiting_result": 0,
            "tool_calls_no_result_in_log": 0,
            "results_without_call": 0,
            "links_refused": 0,
            "not_json": 0,
            "malformed": 0,
            "not_invocation_log": 0,
            "record_failed": 0,
        }
    )

    def add(self, name: str, n: int = 1) -> None:
        if name.startswith("unsupported_shape:"):
            bucket = self.values["unsupported_shape"]
            key = name.split(":", 1)[1]
            bucket[key] = bucket.get(key, 0) + n
        elif name in self.values and isinstance(self.values[name], int):
            self.values[name] += n
        else:
            self.values.setdefault("other", {})
            self.values["other"][name] = self.values["other"].get(name, 0) + n

    def s3_unread(self, reason: str) -> None:
        bucket = self.values["body_in_s3_unread"]
        bucket[reason] = bucket.get(reason, 0) + 1


ConfigFetcher = Callable[[], "tuple[dict, str] | None"]
StatusPoster = Callable[[dict], None]


class Sweeper:
    """One reader: a log source, a recorder (the ledger it seals into) and its state."""

    def __init__(
        self,
        *,
        recorder: Recorder,
        source: LogSource,
        state: StateDB,
        fetch_config: ConfigFetcher | None = None,
        post_status: StatusPoster | None = None,
        clock: Callable[[], float] = time.time,
        s3_max_bytes: int = DEFAULT_S3_MAX_BYTES,
        overrides: dict[str, Any] | None = None,
        runtime_version: str | None = None,
    ) -> None:
        self.recorder = recorder
        self.source = source
        self.state = state
        self._fetch_config = fetch_config
        self._post_status = post_status
        self._clock = clock
        self._s3_max_bytes = s3_max_bytes
        self._overrides = overrides or {}
        self._runtime_version = runtime_version
        self.last_status: dict[str, Any] | None = None
        self._state_recreated = False

    # settings
    def config(self) -> tuple[dict[str, Any], str]:
        """(effective settings, where they came from: coriqo | cache | defaults)."""
        fetched = None
        if self._fetch_config is not None:
            try:
                fetched = self._fetch_config()
            except Exception as exc:  # noqa: BLE001 - unreachable Coriqo falls back, and says so
                log.warning("bedrock log reader: could not fetch settings from Coriqo (%s)", exc)
        if fetched is not None:
            body, sha = fetched
            self.state.cache_config(body, sha)
            config, origin = effective_config(body), "coriqo"
        else:
            cached = self.state.cached_config()
            config, origin = (
                (effective_config(cached), "cache")
                if cached is not None
                else (dict(CONFIG_DEFAULTS), "defaults")
            )
        config.update(
            {
                k: v
                for k, v in effective_config({**config, **self._overrides}).items()
                if k in self._overrides
            }
        )
        return config, origin

    def sweep(self) -> dict[str, Any]:
        """One pass. Every failure ends in a posted status; nothing escapes to the loop."""
        now_ms = int(self._clock() * 1000)
        counters = SweepCounters()
        self._state_recreated = self.state.created and self._ledger_holds_reader_events()
        try:
            config, origin = self.config()
            status: dict[str, Any] = self._base_status(config, origin, counters)
        except Exception:  # noqa: BLE001 - reported in the status, the next sweep retries
            log.exception("bedrock log reader: the settings could not be read")
            status = self._base_status(dict(CONFIG_DEFAULTS), "defaults", counters)
            status.update(status="error", reason="reader_error")
            return self._finish(status)
        try:
            return self._sweep(now_ms, config, status, counters)
        except Exception as exc:  # noqa: BLE001 - reported in the status, the next sweep retries
            self.state.rollback()
            log.exception("bedrock log reader: the sweep failed")
            reason = "ledger_write_failed" if isinstance(exc, LedgerWriteError) else "reader_error"
            status.update(status="error", reason=reason)
            return self._finish(status)

    def _ledger_holds_reader_events(self) -> bool:
        """Whether this ledger already holds events this reader sealed. Other entries (the
        recorder's own heartbeats) do not count: a new state file next to them is a first run."""
        return any(
            entry.event.provider == PROVIDER for entry in self.recorder.ledger.iter_entries()
        )

    def _sweep(
        self, now_ms: int, config: dict[str, Any], status: dict[str, Any], counters: SweepCounters
    ) -> dict[str, Any]:
        if config["paused"]:
            status.update(status="paused", reason=None)
            return self._finish(status)
        try:
            described = self.source.describe()
        except SourceError as exc:
            status.update(status="error", reason=exc.reason)
            return self._finish(status)
        source_arn = described["arn"]
        status["account_id"] = described.get("account_id") or None
        logging_config = self.source.logging_configuration()
        status["logging_config"] = logging_config
        if isinstance(logging_config, dict) and not logging_config.get("enabled"):
            status["reason"] = "logging_off"
        elif isinstance(logging_config, dict) and not logging_config.get("text_delivery"):
            status["reason"] = "text_delivery_off"

        watermark = self.state.watermark(source_arn)
        end = now_ms - config["settle_minutes"] * 60_000
        start = (
            now_ms - config["first_backfill_hours"] * 3_600_000
            if watermark is None
            else watermark - config["overlap_minutes"] * 60_000
        )
        floor = now_ms - config["max_catchup_hours"] * 3_600_000
        if start < floor:
            self.state.declare_gap(source_arn, start, floor)
            start = floor
        status["window"] = [_iso(start), _iso(end)]
        status["gaps"] = [[_iso(a), _iso(b)] for a, b in self.state.gaps(source_arn)]

        try:
            through, partials = (
                self._read_and_normalize(start, end, config, counters, status)
                if start < end
                else (end, [])
            )
            self._seal(partials, counters)
        except SourceError as exc:
            self.state.rollback()
            status.update(status="error", reason=exc.reason)
            return self._finish(status)

        link_window_ms = (
            config["link_gap_minutes"] + config["overlap_minutes"] + config["settle_minutes"]
        ) * 60_000
        counters.values["tool_calls_no_result_in_log"] += self.state.prune(now_ms - link_window_ms)
        counters.values["tool_calls_awaiting_result"] = self.state.awaiting_result()
        self.state.set_watermark(source_arn, through)
        status["watermark"] = _iso(through)
        status["status"] = "ok"
        if status.get("max_ingest_lag_s", 0) * 1000 > config["overlap_minutes"] * 60_000 / 2:
            status["reason"] = status.get("reason") or "lag_near_overlap"
        return self._finish(status)

    def _read_and_normalize(
        self, start: int, end: int, config: dict, counters: SweepCounters, status: dict
    ) -> tuple[int, list[PartialEvent]]:
        records: list[InvocationRecord] = []
        read_bytes = 0
        max_lag = 0
        through = end
        for event in self.source.events(start, end - 1):
            counters.add("records_read")
            read_bytes += len(event.message)
            if event.ingestion_time is not None:
                max_lag = max(max_lag, event.ingestion_time - event.timestamp)
            try:
                records.append(parse_record(event.message, ingestion_ms=event.ingestion_time))
            except RecordRejected as exc:
                counters.add(exc.counter)
            if (
                counters.values["records_read"] >= MAX_RECORDS_PER_SWEEP
                or read_bytes >= MAX_MESSAGE_BYTES_PER_SWEEP
            ):
                # Process what was read; the next sweep continues from the last millisecond read.
                status["truncated"] = True
                through = event.timestamp
                break
        status["max_ingest_lag_s"] = max_lag // 1000
        records.sort(key=lambda r: (r.ts_ms, r.request_id))
        partials: list[PartialEvent] = []
        for record in records:
            try:
                with self.state.record_scope():
                    record = self._resolve_bodies(record, counters)
                    normalized = normalize(
                        record,
                        index=self.state,
                        scope=config["scope"],
                        link_gap_minutes=config["link_gap_minutes"],
                        log_group=getattr(self.source, "log_group", None),
                        reader_config_sha256=status["config_sha256"],
                    )
            except Exception:  # noqa: BLE001 - one bad record must not hold the watermark back
                log.warning(
                    "bedrock log reader: record %s could not be read", record.request_id,
                    exc_info=True,
                )
                counters.add("record_failed")
                continue
            for name, n in normalized.counters.items():
                counters.add(name, n)
            if normalized.partials:
                counters.add("calls_sealed")
            partials.extend(normalized.partials)
        return through, partials

    def _resolve_bodies(
        self, record: InvocationRecord, counters: SweepCounters
    ) -> InvocationRecord:
        from dataclasses import replace

        updates: dict[str, Any] = {}
        for side, path, tokens in (
            ("input_body", record.input_s3_path, record.input_tokens),
            ("output_body", record.output_s3_path, record.output_tokens),
        ):
            if getattr(record, side) is not None:
                continue
            if path:
                try:
                    data = self.source.read_s3(path, self._s3_max_bytes)
                    if data[:2] == _GZIP_MAGIC:
                        data = gzip.decompress(data)
                    updates[side] = json.loads(data)
                except S3ReadError as exc:
                    counters.s3_unread(exc.reason)
                except (ValueError, OSError, EOFError):
                    # EOFError: a truncated gzip object.
                    counters.s3_unread("not_json")
            elif tokens:
                counters.add("body_missing_over_100kb")
        return replace(record, **updates) if updates else record

    def _seal(self, partials: list[PartialEvent], counters: SweepCounters) -> None:
        ids = [p.event_id for p in partials if p.event_id]
        existing = self.recorder.ledger.existing_event_ids(ids)
        fresh = [p for p in partials if p.event_id not in existing]
        counters.values["already_sealed"] += len(partials) - len(fresh)
        self.recorder.record_many(fresh)
        counters.values["events_sealed"] += len(fresh)
        self.state.commit()

    def _base_status(self, config: dict, origin: str, counters: SweepCounters) -> dict[str, Any]:
        return {
            "kind": KIND,
            "status": "ok",
            "reason": "config_unreachable"
            if origin != "coriqo" and self._fetch_config is not None
            else None,
            "log_group": getattr(self.source, "log_group", None),
            "region": getattr(self.source, "region", None),
            "account_id": None,
            "logging_config": "unknown",
            "last_sweep_at": _iso(self._clock() * 1000),
            "window": None,
            "watermark": None,
            "counts": counters.values,
            "max_ingest_lag_s": 0,
            "truncated": False,
            "gaps": [],
            "payload_mode": self.recorder.payload_mode.value,
            "config_sha256": config_sha256(config),
            "config_source": origin,
            "overridden_on_host": sorted(self._overrides),
            "runtime_version": self._runtime_version,
        }

    def _finish(self, status: dict[str, Any]) -> dict[str, Any]:
        completed = status["status"] != "error"
        if completed and self._state_recreated:
            # A lost state file outranks a warning; an error is reported first and the loss
            # on the next sweep that completes.
            status["reason"] = "state_recreated"
        self.last_status = status
        posted = True
        if self._post_status is not None:
            try:
                self._post_status(status)
            except Exception as exc:  # noqa: BLE001 - the next sweep posts again
                posted = False
                log.warning("bedrock log reader: could not post the status to Coriqo (%s)", exc)
        if completed and posted:
            # Said once Coriqo has it: from now on this state file is no longer new.
            self.state.created = False
        return status


# -- Coriqo ----------------------------------------------------------------------------


def coriqo_config_fetcher(
    *, base_url: str, tenant_slug: str | None, signer: Any, client: Any = None
) -> ConfigFetcher:
    """GET the tenant's settings, device-signed per request. Returns (values, sha256)."""
    import httpx

    from .coriqo_async import device_headers, request_path

    http = client or httpx.Client(timeout=10.0)

    def fetch() -> tuple[dict, str] | None:
        request = http.build_request("GET", f"{base_url.rstrip('/')}{CAPTURE_CONFIG_PATH}")
        request.headers.update(
            device_headers(signer, method="GET", path=request_path(request.url), body=b"")
        )
        if tenant_slug:
            request.headers["X-Tenant-Slug"] = tenant_slug
        response = http.send(request)
        response.raise_for_status()
        body = response.json()
        values = body.get("bedrock_log") if isinstance(body, dict) else None
        if not isinstance(values, dict):
            raise ValueError("capture-config answered without a bedrock_log block")
        return values, str(body.get("sha256") or config_sha256(effective_config(values)))

    return fetch


def coriqo_status_poster(recorder: Recorder) -> StatusPoster | None:
    """POST the status block, signed like the ledger batches. None when not enrolled."""
    shipper = recorder.shipper
    if shipper is None:
        return None

    def post(status: dict) -> None:
        shipper.post_signed(
            SOURCE_STATE_PATH,
            {
                "device_id": recorder.key.device_id,
                "sent_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_state": status,
            },
        )

    return post


def s3_max_bytes_from_env() -> int:
    raw = os.getenv("BYOAI_BEDROCK_LOG_S3_MAX_BYTES")
    try:
        return int(raw) if raw else DEFAULT_S3_MAX_BYTES
    except ValueError:
        log.warning(
            "BYOAI_BEDROCK_LOG_S3_MAX_BYTES=%r is not a number; using %d", raw, DEFAULT_S3_MAX_BYTES
        )
        return DEFAULT_S3_MAX_BYTES
