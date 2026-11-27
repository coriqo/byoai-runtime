"""U0.2: the Shield signature file schema against the sample and negative fixtures."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "src" / "byoai" / "shield_signatures.schema.json"
FIXTURES = ROOT / "tests" / "fixtures" / "shield_signatures"

#: Contract rules a schema cannot express. Wave 1's loader must enforce these too.
CONTRACT_ONLY = {"duplicate_ids"}


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


def duplicate_ids(doc: dict) -> list[str]:
    return [i for i, n in Counter(s["id"] for s in doc["signatures"]).items() if n > 1]


@pytest.mark.parametrize("name", ["sample.json", "sample_bundle.json"])
def test_sample_files_validate(validator, name):
    doc = _load(FIXTURES / name)
    validator.validate(doc)
    assert not duplicate_ids(doc)


def test_sample_covers_every_signature_type(validator):
    types = {s["type"] for s in _load(FIXTURES / "sample.json")["signatures"]}
    enum = json.loads(SCHEMA_PATH.read_text())["properties"]["signatures"]["items"]["properties"]["type"]["enum"]
    assert types == set(enum)


@pytest.mark.parametrize("path", sorted((FIXTURES / "invalid").glob("*.json")), ids=lambda p: p.stem)
def test_invalid_fixtures_are_rejected(validator, path):
    doc = _load(path)
    if path.stem in CONTRACT_ONLY:
        validator.validate(doc)  # structurally fine
        assert duplicate_ids(doc), "contract-only fixture must break the contract"
    else:
        assert list(validator.iter_errors(doc)), f"{path.name} should not validate"


def test_sample_holds_no_secrets_or_values(validator):
    """Match conditions are names and patterns, never header or body values."""
    text = (FIXTURES / "sample.json").read_text().lower()
    for needle in ("bearer", "password", "api_key", "sk-"):
        assert needle not in text
