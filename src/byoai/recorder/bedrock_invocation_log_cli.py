"""``byoai-bedrock-log-reader``: seal what an Amazon Bedrock model-invocation log holds (W10).

    byoai-bedrock-log-reader --check   # can it read the log group, and is logging on?
    byoai-bedrock-log-reader --once    # one sweep, ship everything sealed, exit
    byoai-bedrock-log-reader --loop    # sweep at the interval set in Coriqo, until stopped

The host decides what is bound to AWS identity and the local disk (log group, region, an
optional role in another account, the recorder directory, the payload mode); Coriqo's admin
decides the policy (pause, scope, interval, overlap, link limit, backfill), which the reader
fetches at the start of each sweep. The recorder directory must be this reader's own, enrolled
as its own device with ``byoai-recorder-enroll``.

Exit codes: 0 done (or paused), 1 the sweep or the check failed, 2 a setting is missing or
not valid, 3 another reader holds this recorder directory.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path
from typing import TYPE_CHECKING

from .bedrock_invocation_log_source import (
    STATE_DB_NAME,
    AwsLogSource,
    ConfigFetcher,
    ReaderBusy,
    SourceError,
    StateDB,
    Sweeper,
    coriqo_config_fetcher,
    coriqo_status_poster,
    reader_lock,
    s3_max_bytes_from_env,
)
from .redact import PayloadMode

if TYPE_CHECKING:
    from .integration import Recorder

log = logging.getLogger("byoai.recorder.bedrock_log")

#: How long ``--once`` waits for the shipper to send what the sweep sealed.
DRAIN_SECONDS = 60.0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="byoai-bedrock-log-reader",
        description=__doc__.split("\n\n")[0],
        epilog="Exit codes: 0 done (or paused), 1 the sweep or the check failed, "
        "2 a setting is missing or not valid, 3 another reader holds this recorder directory.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--once", action="store_true", help="One sweep, ship what it sealed, exit.")
    mode.add_argument(
        "--loop", action="store_true", help="Sweep at the interval set in Coriqo until stopped."
    )
    mode.add_argument(
        "--check", action="store_true", help="Check access and the logging configuration; exit."
    )
    parser.add_argument(
        "--log-group",
        default=os.getenv("BYOAI_BEDROCK_LOG_GROUP"),
        help="Log group name, or its ARN for a monitoring-account read (BYOAI_BEDROCK_LOG_GROUP).",
    )
    parser.add_argument(
        "--region",
        default=os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION"),
        help="Region of the log group (AWS_REGION).",
    )
    parser.add_argument(
        "--role-arn",
        default=os.getenv("BYOAI_BEDROCK_LOG_ROLE_ARN"),
        help="Role to assume for a log group in another account (BYOAI_BEDROCK_LOG_ROLE_ARN).",
    )
    parser.add_argument(
        "--external-id",
        default=os.getenv("BYOAI_BEDROCK_LOG_EXTERNAL_ID"),
        help="External id that role's trust policy requires (BYOAI_BEDROCK_LOG_EXTERNAL_ID).",
    )
    parser.add_argument(
        "--dir",
        default=os.getenv("BYOAI_RECORDER_DIR"),
        help="This reader's own recorder directory (BYOAI_RECORDER_DIR).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    if not args.log_group or not args.region:
        print(
            "Set the log group (--log-group or BYOAI_BEDROCK_LOG_GROUP) and the region "
            "(--region or AWS_REGION).",
            file=sys.stderr,
        )
        return 2
    mode = _payload_mode()
    if mode is None:
        return 2
    try:
        source = AwsLogSource.from_environment(
            log_group=args.log_group,
            region=args.region,
            role_arn=args.role_arn,
            external_id=args.external_id,
        )
    except ImportError:
        print("boto3 is missing: install byoai-runtime[bedrock-agent,recorder].", file=sys.stderr)
        return 2
    if args.check:
        return _check(source)
    try:
        return _run(args, source, mode)
    except ReaderBusy as exc:
        print(str(exc), file=sys.stderr)
        return 3


def _payload_mode() -> PayloadMode | None:
    """BYOAI_RECORDER_PAYLOAD_MODE (redacted when unset); None, with the reason, if invalid."""
    mode_raw = os.getenv("BYOAI_RECORDER_PAYLOAD_MODE", PayloadMode.REDACTED.value)
    try:
        return PayloadMode(mode_raw)
    except ValueError:
        print(
            f"BYOAI_RECORDER_PAYLOAD_MODE={mode_raw!r} is not a payload mode; use one of "
            f"{', '.join(m.value for m in PayloadMode)}.",
            file=sys.stderr,
        )
        return None


def _run(args: argparse.Namespace, source: AwsLogSource, mode: PayloadMode) -> int:
    """Sweep once or in a loop, holding this recorder directory for as long as it runs."""
    from .. import __version__
    from .integration import Recorder, default_recorder_dir

    directory = Path(args.dir) if args.dir else default_recorder_dir()
    directory.mkdir(parents=True, exist_ok=True)
    with reader_lock(directory):
        recorder = Recorder(dir=directory, payload_mode=mode)
        fetch_config = _config_fetcher(directory, recorder)
        state = StateDB(directory / STATE_DB_NAME)
        sweeper = Sweeper(
            recorder=recorder,
            source=source,
            state=state,
            fetch_config=fetch_config,
            post_status=coriqo_status_poster(recorder),
            s3_max_bytes=s3_max_bytes_from_env(),
            runtime_version=__version__,
        )
        try:
            return _once(sweeper, recorder) if args.once else _loop(sweeper)
        finally:
            state.close()
            recorder.close(final_ship=True)


def _config_fetcher(directory: Path, recorder: Recorder) -> ConfigFetcher | None:
    """Fetches Coriqo's capture settings for an enrolled directory; None (and a warning) if not."""
    from .enroll import load_enrollment_state

    enrollment = load_enrollment_state(directory)
    if enrollment is None:
        log.warning(
            "bedrock log reader: this directory is not enrolled; sealing locally with "
            "Coriqo's default settings, nothing is shipped (run byoai-recorder-enroll)"
        )
        return None
    return coriqo_config_fetcher(
        base_url=enrollment.coriqo_base_url,
        tenant_slug=enrollment.tenant_slug,
        signer=recorder.key,
    )


def _check(source: AwsLogSource) -> int:
    try:
        described = source.describe()
    except SourceError as exc:
        print(f"FAIL  log group {source.log_group}: {exc.reason}")
        return 1
    print(f"ok    log group {described['arn']}")
    config = source.logging_configuration()
    if config == "unknown":
        print("info  logging configuration: not readable with this role (optional permission)")
    elif not config.get("enabled"):
        print("FAIL  model invocation logging is off in this account and region")
        return 1
    else:
        text = "on" if config["text_delivery"] else "OFF"
        large = "on" if config["large_data_s3"] else "off (bodies over 100 KB are lost)"
        print(f"ok    logging on: text delivery {text}, large bodies to S3 {large}")
    return 0


def _once(sweeper: Sweeper, recorder) -> int:
    status = sweeper.sweep()
    print(json.dumps({k: status[k] for k in ("status", "reason", "window", "counts")}, default=str))
    if not recorder.drain(DRAIN_SECONDS):
        log.warning(
            "bedrock log reader: not everything sealed was shipped; the rest goes with the next run"
        )
    return 0 if status["status"] in ("ok", "paused") else 1


def _loop(sweeper: Sweeper) -> int:
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    while not stop.is_set():
        status = sweeper.sweep()
        interval = sweeper.config()[0]["interval_minutes"] * 60
        log.info(
            "bedrock log reader: %s (%s), next sweep in %d s",
            status["status"],
            status.get("reason"),
            interval,
        )
        stop.wait(interval)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
