"""The vendored mandate reader at format v1.4: golden tool-hash vectors, tool_pins."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from byoai.recorder import mandate_format as mf

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"
VECTORS_PATH = FIXTURES / "tool_hash_vectors.json"
VECTORS = json.loads(VECTORS_PATH.read_text(encoding="utf-8"))

#: The SHA-256 MANDATE_SPEC.md section 4.10.1 (coriqo seal-verifier) publishes for
#: testdata/tool_hash_vectors.json. Update it together with the vendored file.
PUBLISHED_VECTORS_SHA256 = "bb32d8a4147182f6d300652891de8bbe8a827292d2f54d56770612932daad0e4"


def _load(name: str):
    return mf.parse_text((FIXTURES / "mandate" / name).read_text(encoding="utf-8"))


def test_vendored_vectors_match_the_published_digest():
    assert hashlib.sha256(VECTORS_PATH.read_bytes()).hexdigest() == PUBLISHED_VECTORS_SHA256


def test_reader_is_at_v1_4():
    assert mf.SPEC_MINOR == 4


@pytest.mark.parametrize("v", VECTORS["jcs"], ids=lambda v: v["name"])
def test_jcs_matches_the_golden_vectors(v):
    assert mf.jcs(v["value"]) == v["canonical"]


@pytest.mark.parametrize("v", VECTORS["tools"], ids=lambda v: v["name"])
def test_tool_hashes_match_the_golden_vectors(v):
    assert mf.tool_definition_sha256(v["tool"]) == v["definition_sha256"]
    assert mf.tool_annotations_sha256(v["tool"]) == v["annotations_sha256"]


def test_a_v1_4_file_with_tool_pins_is_accepted():
    doc = _load("tool_pins_set.yaml")
    errors, warnings = mf.check(doc)
    assert errors == [] and warnings == []
    servers = mf.normalise(doc)["tool_pins"]["servers"]
    assert set(servers) == {"docs.example", "payments-mcp"}


def test_empty_tool_pins_leave_the_document_hash_unchanged():
    base = _load("minimal.yaml")
    h = mf.document_sha256(base)
    for pins in (None, {}, {"servers": None}, {"servers": {}}, {"servers": {"idle": {"tools": {}}}}):
        doc = {**base, "tool_pins": pins}
        assert mf.check(doc)[0] == [], pins
        assert mf.document_sha256(doc) == h, pins


def test_the_real_v1_3_reader_warns_and_drops_tool_pins():
    """tests/fixtures/mandate_format_v1_3.py is the reference reader as it was
    at v1.3 (coriqo seal-verifier/mandate_format.py, the commit before v1.4)."""
    spec = importlib.util.spec_from_file_location("mf_v1_3", FIXTURES / "mandate_format_v1_3.py")
    old = importlib.util.module_from_spec(spec)
    sys.modules["mf_v1_3"] = old
    spec.loader.exec_module(old)
    doc = _load("tool_pins_set.yaml")
    errors, warnings = old.check(doc)
    assert errors == []
    assert any("tool_pins" in w for w in warnings)
    assert "tool_pins" not in old.normalise(doc)
    assert old.document_sha256(doc) != mf.document_sha256(doc)
