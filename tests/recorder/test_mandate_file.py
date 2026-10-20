"""Running the gate from a coriqo.mandate.yaml, and the vendored reader."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from byoai.recorder import mandate_format
from byoai.recorder.mandate import Allow, Deny, Flag, MandateError, Posture, Reason
from byoai.recorder.mandate_file import (
    file_mandate_gate,
    file_mandate_source,
    load_mandate_file,
    load_mandate_text,
)

from .test_mandate import FakeClock

#: SHA-256 of seal-verifier/mandate_format.py in the coriqo repo at the
#: version copied here. The reader is copied byte-for-byte; to update it,
#: re-copy the file and change this constant in the same commit.
REFERENCE_READER_SHA256 = "5155c5ba571e279c751e9c5287fc982c1b968875959ca1ef448247201c7dab89"

VENDORED = Path(mandate_format.__file__)


def test_vendored_reader_is_the_pinned_reference_copy():
    digest = hashlib.sha256(VENDORED.read_bytes()).hexdigest()
    assert digest == REFERENCE_READER_SHA256, (
        "src/byoai/recorder/mandate_format.py no longer matches the reference "
        "reader it was copied from. Re-copy coriqo-seal-verifier/mandate_format.py "
        "byte-for-byte and update REFERENCE_READER_SHA256; never edit the copy."
    )


def test_vendored_reader_matches_a_local_reference_checkout():
    """When the reference is on disk (CORIQO_SEAL_VERIFIER_DIR, or a coriqo
    checkout next to this repo), the bytes must be identical, not just the
    pinned hash: this is what catches the reference moving on."""
    candidates = []
    if os.getenv("CORIQO_SEAL_VERIFIER_DIR"):
        candidates.append(Path(os.environ["CORIQO_SEAL_VERIFIER_DIR"]) / "mandate_format.py")
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidates.append(parent.parent / "coriqo" / "seal-verifier" / "mandate_format.py")
    reference = next((c for c in candidates if c.is_file()), None)
    if reference is None:
        pytest.skip("no reference checkout of coriqo-seal-verifier on this machine")
    assert VENDORED.read_bytes() == reference.read_bytes(), (
        f"{VENDORED} has drifted from {reference}; re-copy it and update "
        "REFERENCE_READER_SHA256"
    )


MINIMAL = """spec: coriqo.mandate/v1
agent:
  name: payments-assistant
"""


def test_minimal_file_uses_the_reader_defaults():
    loaded = load_mandate_text(MINIMAL)
    payload = loaded.payload()
    assert payload["mandate_enforcement"] == "observe"  # mode: shadow
    assert payload["enforcement_posture"] == "fail_open"
    assert payload["max_staleness_s"] == 300
    assert payload["allowed_tools"] is None  # no allow-list, not "nothing"
    assert payload["prohibited_tools"] == []
    assert payload["on_violation"] == "deny"
    assert payload["max_run_steps"] is None
    assert payload["max_run_cost_usd"] is None
    expected = mandate_format.document_sha256(loaded.document)
    assert payload["mandate_version_id"] == f"sha256:{expected}"
    assert loaded.agent_name == "payments-assistant"


def test_full_file_maps_every_field():
    text = """{
      "spec": "coriqo.mandate/v1",
      "agent": {"name": "pay", "id": "agt_1"},
      "environment": "production",
      "mode": "enforce",
      "on_stale_snapshot": "fail_closed",
      "max_staleness_s": 120,
      "tools": {"allowed": ["search", "pay"], "prohibited": ["delete"]},
      "max_steps_per_run": 40,
      "max_cost_usd": 2.5,
      "delegation": {"policy": "attenuated", "max_depth": 2},
      "output_inspection": {"secrets": "redact"},
      "on_violation": "deny_and_halt_run"
    }"""
    payload = load_mandate_text(text).payload()
    assert payload["mandate_enforcement"] == "enforce"
    assert payload["enforcement_posture"] == "fail_closed"
    assert payload["max_staleness_s"] == 120
    assert payload["allowed_tools"] == ["pay", "search"]
    assert payload["prohibited_tools"] == ["delete"]
    assert payload["max_run_steps"] == 40
    assert payload["max_run_cost_usd"] == 2.5
    assert payload["delegation_policy"] == "attenuated"
    assert payload["max_delegation_depth"] == 2
    assert payload["environment"] == "production"
    assert payload["on_violation"] == "deny_and_halt_run"
    assert payload["output_inspection"]["secrets"] == "redact"


def test_empty_allow_list_permits_nothing():
    text = MINIMAL + "mode: enforce\ntools:\n  allowed: []\n"
    gate, _ = file_mandate_gate_from_text(text)
    assert isinstance(gate.decide("search"), Deny)


def test_invalid_file_lists_the_field():
    with pytest.raises(MandateError) as info:
        load_mandate_text(MINIMAL + "mode: block-everything\n")
    assert "mode" in str(info.value)
    with pytest.raises(MandateError):
        load_mandate_text("spec: coriqo.mandate/v2\nagent: {name: x}\n")
    with pytest.raises(MandateError):
        load_mandate_text("")


def test_missing_file_is_a_mandate_error(tmp_path):
    with pytest.raises(MandateError):
        load_mandate_file(tmp_path / "nope.yaml")


def file_mandate_gate_from_text(text: str, tmp: Path | None = None, **kwargs):
    import tempfile

    directory = Path(tmp or tempfile.mkdtemp())
    path = directory / "coriqo.mandate.yaml"
    path.write_text(text, encoding="utf-8")
    return file_mandate_gate(path, clock=kwargs.pop("clock", FakeClock()), **kwargs)


def test_shadow_file_flags_and_enforce_file_denies(tmp_path):
    shadow, _ = file_mandate_gate_from_text(MINIMAL + "tools: {prohibited: [rm]}\n", tmp_path)
    verdict = shadow.decide("rm")
    assert type(verdict) is Flag and verdict.reason == Reason.OUT_OF_SCOPE_OBSERVED
    enforce, loaded = file_mandate_gate_from_text(
        MINIMAL + "mode: enforce\ntools: {prohibited: [rm]}\n", tmp_path
    )
    denied = enforce.decide("rm")
    assert isinstance(denied, Deny)
    assert denied.mandate_version_id == f"sha256:{loaded.sha256}"
    assert type(enforce.decide("search")) is Allow
    assert enforce.agent_id == "payments-assistant"


async def test_file_source_unchanged_edited_and_broken(tmp_path):
    path = tmp_path / "coriqo.mandate.yaml"
    path.write_text(MINIMAL, encoding="utf-8")
    source = file_mandate_source(path)
    payload, etag = await source(None)
    assert payload is not None and etag
    unchanged, same = await source(etag)
    assert unchanged is None and same == etag
    path.write_text(MINIMAL + "mode: enforce\n", encoding="utf-8")
    edited, new_etag = await source(etag)
    assert edited is not None and edited["mandate_enforcement"] == "enforce"
    assert new_etag != etag
    path.write_text("mode: [", encoding="utf-8")
    with pytest.raises(MandateError):
        await source(new_etag)


async def test_broken_file_keeps_the_last_good_copy_until_stale(tmp_path):
    clock = FakeClock()
    path = tmp_path / "coriqo.mandate.yaml"
    path.write_text(
        MINIMAL + "mode: enforce\non_stale_snapshot: fail_closed\nmax_staleness_s: 60\n",
        encoding="utf-8",
    )
    gate, _ = file_mandate_gate(path, clock=clock)
    path.write_text("not: [valid", encoding="utf-8")
    assert await gate.refresh_safely() is False
    assert type(gate.decide("search")) is Allow  # still the last good copy
    clock.advance(61)
    stale = gate.decide("search")
    assert isinstance(stale, Deny) and stale.reason == Reason.SNAPSHOT_STALE
    assert stale.posture == Posture.FAIL_CLOSED


def test_yaml_off_must_be_quoted():
    pytest.importorskip("yaml")
    with pytest.raises(MandateError) as info:
        load_mandate_text(MINIMAL + "output_inspection:\n  pii: off\n")
    assert "quotes" in str(info.value)
