"""coriqo-mcp device receipts: tool rows sealed by Shield, sent after the run.

Off unless ``--shield-dir`` is given. For each ``tools/call`` the gate decides,
this writes (1) for an allowed call, a ``tool_use`` ledger event that holds only
the tool name and the arguments' digest, so the step Coriqo gets has an
``args_hash``; and (2) for every call, allowed or not, a Shield ``tool.call``
row carrying that digest as ``payload_hash`` and the gate's decision as
``mandate_verdict``, sealed by a :class:`~byoai.integrations.shield.SealChain`
that signs with the recorder's own device key. Raw arguments are written
nowhere, whatever the payload mode.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from ..recorder.verdicts import tool_use_payload_hash

log = logging.getLogger("byoai.coriqo_mcp")

__all__ = ["ReceiptSink"]


class ReceiptSink:
    def __init__(self, verdicts: Any, *, shield_dir: Path | str, key_dir: Path | str) -> None:
        from .shield import Feed, ShieldConfig

        base = Path(shield_dir)
        base.mkdir(parents=True, exist_ok=True)
        cfg = ShieldConfig(
            ledger=base / "ledger.jsonl",
            seal_path=base / "seal.json",
            key_dir=Path(key_dir),
        )
        self._verdicts = verdicts
        self.feed = Feed(cfg)
        self.feed.scan_initial()
        self._lock = threading.Lock()
        #: Sessions that had at least one call, in order; published at close.
        self.sessions: dict[str, None] = {}

    def note(self, session_id: str, tool: str, arguments_sha256: str, verdict: Any) -> None:
        """Record one decided call. Never raises."""
        try:
            word = verdict.verdict
            digest = tool_use_payload_hash(tool, arguments_sha256)
            if getattr(verdict, "allowed", False):
                self._verdicts.record_tool_use(tool, arguments_sha256, session_id=session_id)
            call_id = uuid.uuid4().hex[:12]
            wall = time.strftime("%Y-%m-%d %H:%M:%S")
            common = {"wall_clock": wall, "call_id": call_id, "tool": tool,
                      "identity": {"client_name": "coriqo-mcp"}}
            rows = [{"kind": "tool.call", **common, "chars": 0,
                     "payload_hash": digest, "mandate_verdict": word}]
            if getattr(verdict, "allowed", False):
                rows.append({"kind": "tool.result", **common})
            else:
                rows.append({"kind": "tool.error", **common,
                             "error_type": f"mandate_{word}"})
            with self._lock:
                self.sessions[session_id] = None
                with self.feed.cfg.ledger.open("a", encoding="utf-8") as fh:
                    for row in rows:
                        fh.write(json.dumps(row, sort_keys=True) + "\n")
                self.feed.poll()
        except Exception:  # noqa: BLE001 - recording never breaks a call
            log.exception("coriqo-mcp: could not write a receipt row")
