"""``coriqo-verify`` — offline integrity check of a recorder ledger.

Usage::

    coriqo-verify <ledger.db> [--pubkey B64] [--json]
    coriqo-verify receipt <file> --pubkey KEY [--json]

Exit code 0 means the record verified clean. Exit code 1 means the record
cannot be relied upon and the reasons are printed. Exit code 2 means the input
could not be read.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from typing import Any

from byoai.recorder.verify import (
    VerifyError,
    VerifyReport,
    verify_bundle,
    verify_device_receipt,
    verify_ledger,
)

_EXIT_OK = 0
_EXIT_FAILED = 1
_EXIT_UNREADABLE = 2


def _subject(report: VerifyReport) -> str:
    if len(report.session_ids) == 1:
        subject = f"session `{report.session_ids[0]}`"
    elif report.session_ids:
        subject = f"{len(report.session_ids)} sessions"
    else:
        subject = "session (unknown)"
    if len(report.device_ids) == 1:
        return f"Device `{report.device_ids[0]}` — {subject}"
    if report.device_ids:
        return f"{len(report.device_ids)} devices — {subject}"
    return subject.capitalize()


def _fmt_seq(value: int | None) -> str:
    return "—" if value is None else f"{value:,}"


def _window(report: VerifyReport) -> str:
    if report.ts_first and report.ts_last:
        return f"{report.ts_first}–{report.ts_last} UTC"
    return "time window unknown"


def _key_id(pubkey_b64: str | None) -> str | None:
    if not pubkey_b64:
        return None
    try:
        from byoai.recorder.keys import derive_device_id

        return derive_device_id(pubkey_b64)
    except Exception:
        return None


def format_report(report: VerifyReport, pubkey_b64: str | None = None) -> str:
    lines: list[str] = []
    lines.append(_subject(report))
    lines.append(
        f"  seq {_fmt_seq(report.seq_start)}–{_fmt_seq(report.seq_end)} "
        f"({report.entries_checked:,} events, {_window(report)})"
    )
    lines.append(
        f"  {report.entries_checked:,} entry hashes re-derived from stored data; "
        f"{report.checkpoints_checked} checkpoint(s) examined"
        + ("" if report.signatures_verified else "; signatures not checked")
    )
    if report.heartbeats_checked:
        lines.append(
            f"  {report.heartbeats_checked} heartbeat(s) checked against the allowed spacing"
        )
    lines.append("")

    if report.ok and not report.unpaired_tool_uses:
        if report.signatures_verified:
            # A --pubkey was given and every checkpoint that exists verified
            # against it: say exactly what was and wasn't verified, rather
            # than a blanket "complete and unaltered" that would obscure an
            # unsigned tail (entries newer than the last checkpoint, which
            # a live, still-recording ledger always has).
            key_id = _key_id(pubkey_b64)
            verdict = (
                f"VERDICT: chain intact; {report.checkpoints_checked} "
                f"checkpoint(s) signed"
                + (f" by key `{key_id}`" if key_id else "")
                + "."
            )
            if report.unsigned_tail:
                first, last = report.unsigned_tail
                count = last - first + 1
                verdict += (
                    f" {count} entr{'y' if count == 1 else 'ies'} after the last "
                    f"checkpoint (seq {first}–{last}) are covered only by the "
                    "hash chain, not a signature."
                )
            lines.append(verdict)
        else:
            # Without a public key, a chain that is internally consistent
            # end-to-end is not distinguishable from one that was fully
            # rewritten and re-hashed by whoever controls the file — only a
            # verified checkpoint signature can rule that out. Say so
            # instead of claiming an integrity guarantee this pass can't
            # back up. This branch only runs when no --pubkey was supplied
            # at all: once one is given, a chain that's otherwise `ok` has
            # signatures_verified True (see verify_ledger — zero or
            # unreadable checkpoints fail `ok` instead of falling through
            # here), so "rerun with --pubkey" is never suggested to someone
            # who already passed one.
            lines.append(
                "VERDICT: record internally consistent, but NOT cryptographically "
                "verified — rerun with --pubkey to rule out a wholesale rewrite."
            )
        return "\n".join(lines)

    lines.append("FINDINGS")

    if report.no_signed_checkpoints:
        lines.append(
            "  - no signed checkpoints: with --pubkey given, nothing in this ledger "
            "is signed, so a wholesale rewrite cannot be ruled out."
        )
    if report.unreadable_checkpoints:
        lines.append(
            "  - the checkpoint table could not be read, so no signature could be checked."
        )

    for start, end in report.gaps:
        count = end - start + 1
        lines.append(
            f"  - record incomplete: seq {start:,}–{end:,} missing "
            f"({count:,} event{'s' if count != 1 else ''})."
        )

    for seq in report.broken_links:
        lines.append(
            f"  - entry seq {seq:,} does not match its own hash chain: the stored "
            "record was altered or replaced after it was written."
        )

    for seq_end in report.bad_signatures:
        lines.append(
            f"  - checkpoint covering up to seq {seq_end:,} failed verification: "
            "the device signature or the sealed chain head is not authentic."
        )

    lines.extend(_heartbeat_findings(report))

    for tool_use_id in report.orphan_tool_results:
        lines.append(
            f"  - tool result `{tool_use_id}` has no preceding tool_use: the client "
            "returned the outcome of an action the model never requested."
        )

    for tool_use_id in report.unpaired_tool_uses:
        lines.append(
            f"  - tool call `{tool_use_id}` has no recorded result: the agent "
            "requested an action whose outcome was never returned."
        )

    for note in report.notes:
        lines.append(f"  - note: {note}")

    lines.append("")
    if report.ok:
        lines.append("VERDICT: chain intact; incomplete tool pairings noted above for review.")
    else:
        lines.append("VERDICT: record CANNOT be relied upon — see findings above.")
    return "\n".join(lines)


def _silence_seconds(raw: str) -> float:
    """argparse type: a finite number of seconds > 0. ``nan``, ``inf``, zero and
    negatives are refused (exit 2), never read as "off"."""
    try:
        value = float(raw)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a number: {raw!r}") from None
    if not math.isfinite(value) or value <= 0:
        raise argparse.ArgumentTypeError(
            f"must be a finite number of seconds greater than 0, got {raw!r}"
        )
    return value


def _heartbeat_findings(report: Any) -> list[str]:
    """Plain-language lines for the heartbeat findings of a ledger or bundle
    report. They describe what the device's own record claims; none of them
    says what the host did, and none is proof the recorder was alive."""
    out: list[str] = []
    for gap in report.heartbeat_silences:
        kind, a, b, name = gap.get("kind", "spacing"), gap["from_seq"], gap["to_seq"], gap["name"]
        secs = gap.get("seconds")
        span = f" for {secs:,.0f}s" if secs is not None else ""
        accept = f" To accept it after review: --heartbeat-gap {name}."
        if kind == "disabled":
            out.append(
                f"  - heartbeats not covered: the recorder declared heartbeats off at "
                f"seq {a:,}; nothing vouches for the window to seq {b:,}{span}.{accept}"
            )
        elif kind == "tail":
            out.append(
                f"  - no heartbeat after seq {a:,}{span} before the end of the record "
                f"(seq {b:,}), over the allowed spacing.{accept}"
            )
        else:
            out.append(
                f"  - heartbeat gap: nothing between seq {a:,} and seq {b:,}{span}, over "
                "the allowed spacing. The record does not show the recorder writing in "
                "that window; it does not say why (a laptop or VM that slept, a stopped "
                f"process) or what the host did.{accept}"
            )
    for f in report.clock_findings:
        out.append(
            f"  - clock note (advisory unless --strict-clock): the heartbeat at seq "
            f"{f['seq']:,} is {f['reason']}. NTP steps, VM resume, a moved host and several "
            f"writer processes cause this in honest records. Accept with "
            f"--accept-clock-note {f['seq']}."
        )
    if report.no_heartbeats:
        out.append(
            "  - no heartbeats: this record spans longer than the allowed spacing and "
            "contains none (removed, never written, or an older recorder). Use "
            "--allow-no-heartbeats for a record from before heartbeats existed."
        )
    return out


def _add_gap_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--heartbeat-gap",
        dest="heartbeat_gaps",
        action="append",
        default=[],
        metavar="NAME",
        help="accept one window the check flags, by the name shown in the finding: "
        "FROM-TO (the two heartbeat seqs bounding a gap, e.g. a laptop or VM that "
        "slept), tail:SEQ (after the last heartbeat), off:SEQ (a 'heartbeats off' "
        "window, by its marker). Repeatable; needs --max-heartbeat-silence",
    )
    parser.add_argument(
        "--strict-clock",
        dest="strict_clock",
        action="store_true",
        help="make clock inconsistencies fail instead of only being noted. For a "
        "single-host, single-process deployment under review; NTP steps, VM "
        "resume, a moved host and several writer processes trip it in honest records",
    )
    parser.add_argument(
        "--accept-clock-note",
        dest="accept_clock_notes",
        action="append",
        type=int,
        default=[],
        metavar="SEQ",
        help="with --strict-clock, accept the clock note at this heartbeat seq "
        "(repeatable)",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="coriqo-verify",
        description="Offline integrity verification of a Coriqo agent ledger.",
    )
    parser.add_argument("ledger", help="path to the ledger SQLite file")
    parser.add_argument(
        "--pubkey",
        dest="pubkey",
        default=None,
        help=(
            "base64 Ed25519 device public key used to check checkpoint "
            "signatures AND to pin the start of the key-rotation timeline. "
            "This must be the key active at the FIRST entry (seq 1) — not "
            "necessarily the device's current key. Rotations after that "
            "point are validated by walking the chain live from this "
            "starting key (see --device-pubkey below); a caller who pins "
            "the CURRENT key instead of the starting one gets a clear "
            "finding explaining the mismatch, not a silent pass"
        ),
    )
    parser.add_argument(
        "--device-pubkey",
        dest="device_pubkeys",
        action="append",
        default=[],
        metavar="DEVICE_ID=B64",
        help=(
            "base64 Ed25519 public key for a specific device_id (repeatable). "
            "Informational only: it no longer decides whether a KEY_ROTATED "
            "cross-signature is valid — that is always determined by the "
            "live timeline walk from --pubkey. If an entry here disagrees "
            "with the key the live walk establishes for that device_id, a "
            "note is added, but nothing is overridden. Only meaningful when "
            "--pubkey is NOT given: without a starting key, rotations fall "
            "back to being checked against whatever key is supplied here "
            "for each rotation's old device_id, exactly as before"
        ),
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="emit the verification report as machine-readable JSON",
    )
    parser.add_argument(
        "--receipts",
        dest="receipts",
        default=None,
        metavar="PATH",
        help="receipt store written by publish_session; adds a receipts section to the check",
    )
    parser.add_argument(
        "--receipt-overdue-after",
        dest="receipt_overdue_after",
        type=float,
        default=3600.0,
        metavar="SECONDS",
        help="flag acknowledged events with no receipt after this many seconds (default 3600)",
    )
    parser.add_argument(
        "--receipt-pubkey",
        dest="receipt_pubkey",
        default=None,
        metavar="PEM_FILE",
        help="PEM public key file used to verify receipt signatures",
    )
    parser.add_argument(
        "--allow-unchecked-receipts",
        dest="allow_unchecked_receipts",
        action="store_true",
        help="do not fail when receipts are unchecked (SDK missing), unpinned "
        "(no --receipt-pubkey), or the store tracks nothing",
    )
    parser.add_argument(
        "--allow-pending-receipts",
        dest="allow_pending_receipts",
        action="store_true",
        help="do not fail when acknowledged events are merely still pending a "
        "receipt past the overdue age (slow or disabled checkpointing); they "
        "are still listed",
    )
    parser.add_argument(
        "--max-heartbeat-silence",
        dest="max_heartbeat_silence",
        type=_silence_seconds,
        default=None,
        metavar="SECONDS",
        help="turn on the heartbeat checks: fail when two consecutive heartbeat "
        "entries, or the last heartbeat and the end of the record, are further "
        "apart than this; when the recorder declared heartbeats off; when device "
        "time runs backwards or outside the signed checkpoints; or when a record "
        "that long has no heartbeats (see --allow-no-heartbeats). Off by default, "
        "so ledgers from before heartbeats verify as before. It bounds what the "
        "device's own clock claims; it is not proof of liveness",
    )
    parser.add_argument(
        "--allow-no-heartbeats",
        dest="allow_no_heartbeats",
        action="store_true",
        help="with --max-heartbeat-silence, accept a record with no heartbeat "
        "entries (a record from before heartbeats existed)",
    )
    _add_gap_flags(parser)
    parser.add_argument(
        "--forget-rejected",
        dest="forget_rejected",
        action="store_true",
        help="before verifying, drop receipt rows whose batch the server "
        "rejected (use after deciding not to re-send them)",
    )
    return parser


def _parse_device_pubkeys(raw: list[str]) -> dict[str, str]:
    device_public_keys: dict[str, str] = {}
    for item in raw:
        device_id, sep, pubkey = item.partition("=")
        if not sep:
            raise SystemExit(
                f"coriqo-verify: --device-pubkey must be DEVICE_ID=B64KEY, got {item!r}"
            )
        device_public_keys[device_id] = pubkey
    return device_public_keys


def _parse_heartbeat_gaps(raw: list[str]) -> list[str]:
    from byoai.recorder.verify import _parse_gap

    for item in raw:
        try:
            _parse_gap(item)
        except VerifyError as exc:
            raise SystemExit(f"coriqo-verify: --heartbeat-gap: {exc}") from None
    return list(raw)


def _receipt_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="coriqo-verify receipt",
        description="Check one device receipt offline: seal, inclusion, signature.",
    )
    parser.add_argument("file", help="path to the device receipt (JSON)")
    parser.add_argument(
        "--pubkey",
        required=True,
        help="the device's enrolled Ed25519 public key, hex or base64. Get it from "
        "your own record of the device, not from the receipt",
    )
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="emit the result as machine-readable JSON")
    args = parser.parse_args(argv)
    try:
        with open(args.file, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"coriqo-verify: cannot read {args.file}: {exc}", file=sys.stderr)
        return _EXIT_UNREADABLE
    try:
        result = verify_device_receipt(doc, args.pubkey)
    except ValueError as exc:
        print(f"coriqo-verify: --pubkey: {exc}", file=sys.stderr)
        return _EXIT_UNREADABLE
    if args.as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Device receipt {result['seal'] or '(no seal)'}")
        for name, check in result["checks"].items():
            print(f"  {'PASS' if check['ok'] else 'FAIL'}  {name}: {check['detail']}")
        print("")
        print("VERDICT: receipt verified." if result["ok"]
              else "VERDICT: receipt CANNOT be relied upon.")
    return _EXIT_OK if result["ok"] else _EXIT_FAILED


def _bundle_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="coriqo-verify bundle",
        description="Offline verification of an examiner export bundle (JSON, "
        "docs/seal-format.md 13.2).",
    )
    parser.add_argument("file", help="path to the bundle (JSON)")
    parser.add_argument("--pubkey", default=None,
                        help="base64 Ed25519 device public key to pin (the key active at seq 1)")
    parser.add_argument("--tenant-pubkey", dest="tenant_pubkeys", action="append", default=[],
                        metavar="B64", help="pinned tenant epoch key (repeatable)")
    parser.add_argument("--skip-anchors", action="store_true",
                        help="do not check external anchor receipts")
    parser.add_argument("--max-heartbeat-silence", dest="max_heartbeat_silence",
                        type=_silence_seconds, default=None, metavar="SECONDS",
                        help="turn on the heartbeat checks; see `coriqo-verify --help`")
    _add_gap_flags(parser)
    parser.add_argument("--allow-no-heartbeats", action="store_true",
                        help="accept a bundle with no heartbeat entries")
    parser.add_argument("--json", dest="as_json", action="store_true",
                        help="emit the report as machine-readable JSON")
    args = parser.parse_args(argv)
    try:
        with open(args.file, encoding="utf-8") as fh:
            bundle = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"coriqo-verify: cannot read {args.file}: {exc}", file=sys.stderr)
        return _EXIT_UNREADABLE
    try:
        report = verify_bundle(
            bundle,
            pinned_device_public_key_b64=args.pubkey,
            pinned_tenant_public_keys_b64=args.tenant_pubkeys or None,
            check_anchors=not args.skip_anchors,
            max_heartbeat_silence_seconds=args.max_heartbeat_silence,
            heartbeat_gaps_allowed=_parse_heartbeat_gaps(args.heartbeat_gaps),
            allow_no_heartbeats=args.allow_no_heartbeats,
            strict_clock=args.strict_clock,
            clock_notes_accepted=args.accept_clock_notes,
        )
    except VerifyError as exc:
        print(f"coriqo-verify: {exc}", file=sys.stderr)
        return _EXIT_UNREADABLE
    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"Bundle: {report.entries_checked:,} entries, "
              f"{report.checkpoints_checked} checkpoint(s), "
              f"{report.heartbeats_checked} heartbeat(s) checked")
        findings = _heartbeat_findings(report)
        for name in ("broken_links", "bad_checkpoint_signatures", "bad_inclusions",
                     "bad_epoch_signatures", "bad_anchors", "gaps", "orphan_tool_results",
                     "stale_key_usage", "tenant_key_mismatches", "malformed_bundle"):
            value = getattr(report, name)
            if value:
                findings.append(f"  - {name}: {value}")
        if report.device_key_mismatch:
            findings.append("  - device_key_mismatch: the bundle's key is not the pinned one")
        if findings:
            print("FINDINGS")
            print("\n".join(findings))
        for note in report.notes:
            print(f"  note: {note}")
        print("VERDICT: bundle verified." if report.ok
              else "VERDICT: bundle CANNOT be relied upon — see findings above.")
    return _EXIT_OK if report.ok else _EXIT_FAILED


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # A ledger file named "receipt" is still reachable as ./receipt.
    if argv and argv[0] == "receipt":
        return _receipt_main(argv[1:])
    if argv and argv[0] == "bundle":
        return _bundle_main(argv[1:])
    args = _build_parser().parse_args(argv)
    device_public_keys = _parse_device_pubkeys(args.device_pubkeys)
    receipt_pem = None
    if args.receipt_pubkey:
        try:
            with open(args.receipt_pubkey, encoding="utf-8") as fh:
                receipt_pem = fh.read()
        except OSError as exc:
            print(f"coriqo-verify: cannot read --receipt-pubkey: {exc}", file=sys.stderr)
            return _EXIT_UNREADABLE
    if args.forget_rejected:
        if not args.receipts:
            print("coriqo-verify: --forget-rejected needs --receipts", file=sys.stderr)
            return _EXIT_UNREADABLE
        from byoai.recorder.receipts import ReceiptStore, ReceiptStoreError

        try:
            st = ReceiptStore(args.receipts)
            for row in st.entries():
                if isinstance(row, dict) and row.get("rejected") and not row.get("event_hash"):
                    st.forget(row["key"])
        except ReceiptStoreError as exc:
            print(f"coriqo-verify: {exc}", file=sys.stderr)
            return _EXIT_UNREADABLE
    try:
        report = verify_ledger(
            args.ledger,
            public_key_b64=args.pubkey,
            device_public_keys=device_public_keys,
            receipts_path=args.receipts,
            receipt_overdue_after_seconds=args.receipt_overdue_after,
            receipt_public_key_pem=receipt_pem,
            allow_unchecked_receipts=args.allow_unchecked_receipts,
            allow_pending_receipts=args.allow_pending_receipts,
            max_heartbeat_silence_seconds=args.max_heartbeat_silence,
            heartbeat_gaps_allowed=_parse_heartbeat_gaps(args.heartbeat_gaps),
            allow_no_heartbeats=args.allow_no_heartbeats,
            strict_clock=args.strict_clock,
            clock_notes_accepted=args.accept_clock_notes,
        )
    except VerifyError as exc:
        print(f"coriqo-verify: {exc}", file=sys.stderr)
        return _EXIT_UNREADABLE

    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(format_report(report, pubkey_b64=args.pubkey))
        if report.receipts is not None:
            r = report.receipts
            print(
                f"RECEIPTS: {'OK' if r['ok'] else 'FAIL'}: {r['with_receipt']}/{r['acknowledged']} "
                f"acknowledged events have a receipt; {r['tracked']} traces tracked; "
                f"{len(r['unacknowledged'])} unacknowledged, {len(r['batch_rejected'])} rejected, "
                f"{len(r['receipt_overdue'])} overdue, "
                f"{len(r['content_mismatch'])} content mismatch, {len(r['failed'])} failed, "
                f"{len(r['not_checked'])} not checked."
            )
            for reason in r["reasons"]:
                print(f"  - {reason}")
            for note in r["notes"]:
                print(f"  note: {note}")
    return _EXIT_OK if report.ok else _EXIT_FAILED


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
