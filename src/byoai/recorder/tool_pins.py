"""Tool pinning: compare an MCP tool's live hashes with the pinned ones.

A mandate may pin, per MCP server, the SHA-256 of each approved tool's
definition (name, description, input and output schema) and of its annotations
(title and hints). ``coriqo-mcp`` fetches the live tool list, hashes each tool
with :mod:`byoai.recorder.mandate_format` and asks :func:`evaluate_pin` what a
call to that tool should get.

This module does no I/O. The runtime holds only the pinned hashes, so it can
say that a hash changed, that a tool has no pin, or that a definition could not
be checked. It cannot say what changed, and it does not read the policy's
``class_actions``: any hash mismatch follows ``on_drift``, any unpinned tool
``on_unpinned``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .mandate import MandateSnapshot, _sanitize_keys
from .mandate_format import tool_annotations_sha256, tool_definition_sha256

__all__ = [
    "PinAction",
    "PinCheck",
    "PinStatus",
    "ToolHashes",
    "evaluate_pin",
    "hash_tool",
    "pin_actions",
    "pin_blocks",
    "safe_name",
]


class PinStatus:
    """The ``pin_status`` written on a verdict. Absent when the agent has no
    pins; ``NO_PINS`` is reserved for a caller that records it explicitly."""

    MATCH = "match"
    DRIFT = "drift"
    UNPINNED = "unpinned"
    NO_PINS = "no_pins"


class PinAction:
    ALLOW = "allow"
    FLAG = "flag"
    REFUSE = "refuse"


@dataclass(frozen=True, slots=True)
class ToolHashes:
    definition_sha256: str
    annotations_sha256: str | None


@dataclass(frozen=True, slots=True)
class PinCheck:
    """What a call to one tool gets from the pins."""

    status: str
    #: The definition hash seen live, or ``None`` when none was seen.
    definition_sha256: str | None
    action: str
    #: Operator-facing. Built from sanitized names only; never a tool
    #: description, and never sent to the model.
    detail: str | None = None
    #: The sanitised ``--server`` name, for the record; ``None`` when none was given.
    server: str | None = None


_NAME_RE = re.compile(r"[A-Za-z0-9_.\-]{1,64}")
_INVALID_NAME = "<invalid name>"


def safe_name(name: Any) -> str:
    """A tool or server name made safe to log and to put in a reason."""
    return _sanitize_keys([name], _NAME_RE, _INVALID_NAME)[0]


def hash_tool(tool: Any) -> ToolHashes | None:
    """Hashes of one ``tools/list`` entry, or ``None`` when it cannot be hashed
    (no name, a number JSON cannot represent exactly)."""
    if not isinstance(tool, dict):
        return None
    try:
        return ToolHashes(tool_definition_sha256(tool), tool_annotations_sha256(tool))
    except (ValueError, RecursionError, TypeError):
        return None


def pin_blocks(snapshot: MandateSnapshot) -> bool:
    """Whether a refusal may stop a call. ``observe`` and ``alert_only`` never
    block: they record and flag."""
    return not snapshot.observing and snapshot.on_violation != "alert_only"


def pin_actions(snapshot: MandateSnapshot) -> tuple[str, str]:
    """``(on_drift, on_unpinned)`` for this snapshot."""
    policy = snapshot.tool_pin_policy
    if policy is not None:
        return policy["on_drift"], policy["on_unpinned"]
    # A snapshot from a mandate file has no policy: refuse a changed tool where
    # the gate enforces, flag it where the gate only observes; an unpinned
    # tool is flagged.
    return (PinAction.FLAG if snapshot.observing else PinAction.REFUSE), PinAction.FLAG


def evaluate_pin(
    snapshot: MandateSnapshot,
    server: str | None,
    tool: str,
    live: ToolHashes | None,
    *,
    hashable: bool = True,
) -> PinCheck | None:
    """The pin verdict for ``tool``, or ``None`` when the agent has no pins.

    ``live`` is the hashes seen on the server, ``None`` when the tool was not
    seen and checked (not listed, fetch failed, hold timed out). ``hashable``
    is False for a listed tool whose definition could not be hashed.
    """
    pins = snapshot.tool_pins
    if pins is None:
        return None
    on_drift, on_unpinned = pin_actions(snapshot)
    name = safe_name(tool)
    if server is None:
        return PinCheck(
            PinStatus.UNPINNED, live.definition_sha256 if live else None, on_unpinned,
            f"tool {name} is unpinned: no --server name was given, so no pins apply",
        )
    where = safe_name(server)
    if not hashable:
        return PinCheck(
            PinStatus.DRIFT, None, on_drift,
            f"tool {name} on server {where} could not be hashed, so it cannot match its pin",
        )
    pin = (pins.get(server) or {}).get(tool)
    if live is None:
        if pin is not None:
            # Pinned, but its definition could not be read and checked (not
            # listed, fetch failed or timed out, list out of date): it follows
            # on_drift, never the unpinned policy, so it is not let through
            # unchecked.
            return PinCheck(
                PinStatus.DRIFT, None, on_drift,
                f"tool {name} on server {where} has a pin but could not be checked in time",
            )
        return PinCheck(
            PinStatus.UNPINNED, None, on_unpinned,
            f"tool {name} on server {where} was not seen and checked in time, so it counts as unpinned",
        )
    if pin is None:
        return PinCheck(
            PinStatus.UNPINNED, live.definition_sha256, on_unpinned,
            f"tool {name} on server {where} has no pin",
        )
    if live.definition_sha256 != pin["definition_sha256"]:
        return PinCheck(
            PinStatus.DRIFT, live.definition_sha256, on_drift,
            f"tool {name} on server {where}: definition changed since it was pinned",
        )
    if live.annotations_sha256 != pin.get("annotations_sha256"):
        return PinCheck(
            PinStatus.DRIFT, live.definition_sha256, on_drift,
            f"tool {name} on server {where}: annotations changed since it was pinned",
        )
    return PinCheck(PinStatus.MATCH, live.definition_sha256, PinAction.ALLOW)
