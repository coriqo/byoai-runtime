"""Run a mandate gate straight from a ``coriqo.mandate.yaml`` (v1).

The usual source of a :class:`~byoai.recorder.mandate.MandateSnapshot` is
Coriqo: the approved mandate, fetched and cached. This module is the other
source, for a runtime with no Coriqo account behind it, or one that keeps its
mandate in a repository: it reads the open mandate file and turns it into the
same snapshot payload, so the gate, the latch and the verdict record behave
exactly as they do for a fetched mandate.

The file is read with the reference reader, ``mandate_format.py``, copied
byte-for-byte from ``coriqo-seal-verifier`` (a test fails if the copy drifts).
Field mapping, from ``MANDATE_SPEC.md`` §7:

==========================  =====================================
File                        Snapshot
==========================  =====================================
``mode: shadow``            ``mandate_enforcement: observe``
``mode: enforce``           ``mandate_enforcement: enforce``
``on_stale_snapshot``       ``enforcement_posture``
``max_staleness_s``         ``max_staleness_s``
``tools.allowed``           ``allowed_tools`` (absent stays null)
``tools.prohibited``        ``prohibited_tools``
``max_steps_per_run``       ``max_run_steps``
``max_cost_usd``            ``max_run_cost_usd``
``delegation.*``            ``delegation_policy``, ``max_delegation_depth``
``environment``,            same names
``on_violation``,
``output_inspection``
==========================  =====================================

``mandate_version_id`` is ``sha256:`` and the file's document hash
(``MANDATE_SPEC.md`` §6), so every recorded verdict names the exact mandate it
was decided against, and a copy of the file reproduces the hash.

The file is re-read on the gate's refresh schedule. An unchanged file resets
the snapshot's age; a file that has become unreadable or invalid fails the
refresh, the last good copy keeps serving, and once it is older than
``max_staleness_s`` the file's own ``on_stale_snapshot`` decides.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from . import mandate_format
from .mandate import Enforcement, MandateError, MandateGate, MandateSource

__all__ = [
    "LoadedMandate",
    "file_mandate_gate",
    "file_mandate_source",
    "load_mandate_file",
    "snapshot_payload",
]

_MODE_TO_ENFORCEMENT = {
    "shadow": Enforcement.OBSERVE,
    "enforce": Enforcement.ENFORCE,
}


class LoadedMandate:
    """One valid mandate file, read and normalised."""

    __slots__ = ("document", "normalised", "sha256", "warnings", "path")

    def __init__(
        self,
        *,
        document: dict[str, Any],
        normalised: dict[str, Any],
        sha256: str,
        warnings: list[str],
        path: Path | None,
    ) -> None:
        self.document = document
        self.normalised = normalised
        self.sha256 = sha256
        self.warnings = warnings
        self.path = path

    @property
    def agent_name(self) -> str | None:
        return self.normalised["agent"].get("name")

    @property
    def agent_id(self) -> str | None:
        return self.normalised["agent"].get("id")

    @property
    def mode(self) -> str:
        return self.normalised["mode"]

    def payload(self) -> dict[str, Any]:
        return snapshot_payload(self.normalised, sha256=self.sha256)


def snapshot_payload(normalised: Mapping[str, Any], *, sha256: str) -> dict[str, Any]:
    """The snapshot payload for a normalised v1 document.

    Every key is set, because a file read on its own has no Coriqo-side value
    to fall back on: the reader's defaults (``MANDATE_SPEC.md`` §4) are the
    values.
    """
    tools = normalised.get("tools") or {}
    delegation = normalised.get("delegation") or {}
    cost = normalised.get("max_cost_usd")
    return {
        "mandate_version_id": f"sha256:{sha256}",
        "mandate_enforcement": _MODE_TO_ENFORCEMENT[normalised["mode"]],
        "enforcement_posture": normalised["on_stale_snapshot"],
        "max_staleness_s": normalised["max_staleness_s"],
        "allowed_tools": tools.get("allowed"),
        "prohibited_tools": list(tools.get("prohibited") or []),
        "max_run_steps": normalised.get("max_steps_per_run"),
        "max_run_cost_usd": None if cost is None else float(cost),
        "delegation_policy": delegation.get("policy"),
        "max_delegation_depth": delegation.get("max_depth"),
        "environment": normalised.get("environment"),
        "on_violation": normalised["on_violation"],
        "output_inspection": dict(normalised.get("output_inspection") or {}),
        "status": "active",
        "scope_source": "mandate_file",
    }


def load_mandate_text(text: str, *, path: Path | None = None) -> LoadedMandate:
    """Parse and check one document. Raises :class:`MandateError` listing
    every problem the reference reader found."""
    where = str(path) if path is not None else "the mandate file"
    try:
        document = mandate_format.parse_text(text)
    except mandate_format.MandateFileError as exc:
        raise MandateError(f"cannot read {where}: {exc}") from exc
    errors, warnings = mandate_format.check(document)
    if errors:
        raise MandateError(
            f"{where} is not a valid {mandate_format.SPEC_ID} mandate: " + "; ".join(errors)
        )
    return LoadedMandate(
        document=document,
        normalised=mandate_format.normalise(document),
        sha256=mandate_format.document_sha256(document),
        warnings=warnings,
        path=path,
    )


def load_mandate_file(path: str | Path) -> LoadedMandate:
    """Read and check ``path``. Raises :class:`MandateError` on any problem."""
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise MandateError(f"cannot read {path}: {exc}") from exc
    return load_mandate_text(text, path=path)


def file_mandate_source(path: str | Path) -> MandateSource:
    """A :data:`~byoai.recorder.mandate.MandateSource` that reads ``path``.

    The ETag is the document hash, so an unchanged file answers "unchanged"
    (the snapshot's age resets) and an edited one installs the new mandate.
    The read runs in a worker thread; the decide path never touches the file.
    """
    path = Path(path)

    async def fetch(etag: str | None) -> tuple[Mapping[str, Any] | None, str | None]:
        loaded = await asyncio.to_thread(load_mandate_file, path)
        if etag is not None and etag == loaded.sha256:
            return None, etag
        return loaded.payload(), loaded.sha256

    return fetch


def file_mandate_gate(
    path: str | Path,
    *,
    agent_id: str | None = None,
    **kwargs: Any,
) -> tuple[MandateGate, LoadedMandate]:
    """A gate over ``path``, with the file's first read already installed.

    Raises :class:`MandateError` if the file cannot be read or is invalid: a
    runtime started with a broken mandate file must refuse to start rather
    than run with no mandate. ``agent_id`` defaults to the file's
    ``agent.id``, then its ``agent.name``.
    """
    loaded = load_mandate_file(path)
    gate = MandateGate(
        file_mandate_source(path),
        agent_id=agent_id or loaded.agent_id or loaded.agent_name,
        **kwargs,
    )
    gate.apply_snapshot(loaded.payload(), etag=loaded.sha256)
    return gate, loaded
