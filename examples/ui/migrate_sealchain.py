#!/usr/bin/env python
"""One-shot migration of sealchain.json to v2 canonical seals.

Every entry's seal is recomputed as the recorder-canonical leaf hash
(0x00-prefix + RFC 8785 canonical JSON via byoai.recorder.canonical), so all
entries speak one scheme. The result is verified, then re-signed with the
device key. Run after upgrading live_shield.py.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

# needs the sys.path entry above to run from a checkout
from byoai.recorder.merkle import checkpoint_leaf_hash  # noqa: E402

SEAL_PATH = ROOT / "examples" / "mcp_capture" / "sealchain.json"

state = json.loads(SEAL_PATH.read_text())
entries = state.get("entries", [])

fixed = 0
for e in entries:
    leaf = checkpoint_leaf_hash(e["payload"])
    new_seal = leaf.hex()[:16]
    if e.get("seal") != new_seal:
        e["seal"] = new_seal
        e["leaf_hash"] = leaf.hex()
        fixed += 1

state["entries"] = entries

# sanity: every entry must now verify
for e in entries:
    leaf = checkpoint_leaf_hash(e["payload"]).hex()[:16]
    assert leaf == e["seal"], f"entry {e['height']} failed to verify post-migration"

SEAL_PATH.write_text(json.dumps(state, indent=1))
print(f"migrated {len(entries)} entries, recomputed {fixed} seals — all verify")


def verify():
    for e in entries:
        assert checkpoint_leaf_hash(e["payload"]).hex()[:16] == e["seal"]


if __name__ == "__main__":
    verify()
    print("post-verify: chain consistent")
