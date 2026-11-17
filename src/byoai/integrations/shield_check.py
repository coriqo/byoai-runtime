"""``byoai shield check-file``: does a produced file match a sealed record?

Answers "that isn't the file I sent" and "that file broke no rule" from the
record alone. It reads the local seal log, never the ledger's text, and prints
three verdicts:

* ``hash``             whether the file's SHA-256 equals the sealed one;
* ``rules reproduce``  whether running the rules on the file gives the rule
                       hits the record names (refused when the record was made
                       by a different version of the rules);
* ``seal verifies``    whether the record is intact in the sealed chain.

Exit status is 0 only when every check that applies passes.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from byoai.integrations.shield import (
    DATA_DIR,
    MAX_FILE_SCAN,
    RULES_VERSION,
    SealChain,
    ShieldConfig,
    _flags_from_row,
    inspect_file,
    mime_text_like,
)


def _find(chain: SealChain, row: str | None, sha256: str) -> dict | None:
    """The sealed entry for ``row`` (interaction id or seal), else the latest
    file entry carrying this SHA-256."""
    found = None
    for entry, problem in chain._scan_log():
        if problem:
            break  # nothing after a bad line can be trusted
        payload = (entry or {}).get("payload") or {}
        file = payload.get("file")
        if not isinstance(file, dict):
            continue
        if row:
            if row in (payload.get("interaction"), entry.get("seal")):
                found = entry
        elif file.get("sha256") == sha256:
            found = entry
    return found


def check_file(path: Path, *, row: str | None, ledger: Path, key_dir: Path,
               out=None, name: str | None = None) -> int:
    out = out or sys.stdout
    try:
        data = path.read_bytes()
    except OSError as exc:
        print(f"error: can't read {path}: {exc.strerror or exc}", file=sys.stderr)
        return 2
    sha = hashlib.sha256(data).hexdigest()
    seal_path = ledger.parent / "sealchain.json"
    if not seal_path.exists() and not seal_path.with_name("sealchain.log.jsonl").exists():
        print(f"error: no sealed record next to {ledger}", file=sys.stderr)
        return 2
    chain = SealChain(ShieldConfig(ledger=ledger, seal_path=seal_path, key_dir=key_dir,
                                   policy_path=ledger.parent / "policy.json"))
    entry = _find(chain, row, sha)
    damaged = not chain.verify_chain().get("tamper_evident")
    if entry is None and damaged:
        print("seal verifies: no (the sealed log is damaged or was edited; "
              "the record can't be relied on)", file=out)
        return 1
    if entry is None:
        print("hash: different" if row is None else f"error: no sealed file record {row}",
              file=out if row is None else sys.stderr)
        if row is None:
            print("no sealed file record has this SHA-256 (" + sha[:16] + "...)", file=out)
        return 1 if row is None else 2
    file = entry["payload"]["file"]
    payload = entry["payload"]
    ok = True
    match = file.get("sha256") == sha
    ok &= match
    print(f"hash: {'match' if match else 'different'}", file=out)

    version = file.get("rules_version")
    if not file.get("scanned") and mime_text_like(file.get("mime")) and len(data) <= MAX_FILE_SCAN:
        # The record says the rules did not read this, but its declared type is
        # one they read, at a size they read. Run them; a record that skipped a
        # readable file cannot claim its rule hits are reproduced.
        facts = inspect_file(None, file.get("mime"), data, None, {})
        print("rules reproduce: no (the record says not scanned, but this type is read "
              f"by the rules{'; they find ' + ', '.join(facts['flags']) if facts['flags'] else ''})",
              file=out)
        ok = False
    elif not file.get("scanned"):
        print("rules reproduce: n/a (this file type was not read by the rules)", file=out)
    elif version != RULES_VERSION:
        print(f"rules reproduce: cannot check (record used rules {version}, "
              f"this install has {RULES_VERSION})", file=out)
        ok = False
    else:
        # The record says the rules read this file. Whether it is text is decided
        # by its content (the same test a nameless upload gets), never by what
        # this copy is called on this disk; --name passes the original name.
        facts = inspect_file(name, file.get("mime"), data, None, {}, raw_upload=name is None)
        # Rule hits only: the record's flags come from the rules, not the policy.
        # The seal stores tiers as the feed shows them (secret is "high").
        again = [f"{t}:{r}" for t, r, _ in _flags_from_row({"flags": facts["flags"]})]
        same = facts["scanned"] and sorted(again) == sorted(payload.get("flags") or [])
        print(f"rules reproduce: {'yes' if same else 'no'}", file=out)
        ok &= bool(same)

    entry_ok = chain._leaf(payload).hex() == entry.get("leaf_hash")
    verdict = chain.verify_chain()
    sealed = bool(entry_ok and verdict.get("tamper_evident"))
    print(f"seal verifies: {'yes' if sealed else 'no'}", file=out)
    ok &= sealed
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="byoai shield check-file", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", type=Path, help="the file to check")
    ap.add_argument("--row", help="the record to check against (its id or seal); "
                    "default: the latest file record with this SHA-256")
    ap.add_argument("--name", help="the file's original name, if the copy has been renamed "
                    "(the rules read a file by its content when this is not given)")
    ap.add_argument("--ledger", type=Path, default=DATA_DIR / "captures.jsonl",
                    help="path to captures.jsonl (default: ~/.byoai/shield/captures.jsonl)")
    ap.add_argument("--key-dir", type=Path, default=None,
                    help="Shield's key folder (default: <ledger folder>/keys)")
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    key_dir = args.key_dir or (DATA_DIR / "keys" if args.ledger.parent == DATA_DIR
                               else args.ledger.parent / "keys")
    return check_file(args.path, row=args.row, ledger=args.ledger, key_dir=key_dir, name=args.name)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
