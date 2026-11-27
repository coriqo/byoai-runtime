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

#: Public suffixes the review must reject as wildcard parents (a tiny stand-in for the real list).
_SUFFIXES = {"co.uk", "com.au", "co.jp", "github.io"}


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


def test_timestamps_are_checked_for_format(validator):
    import rfc3339_validator  # noqa: F401  (dev dependency; a missing one must fail, not skip)
    doc = _load(FIXTURES / "sample.json")
    doc["generated_at"] = "2026-13-45T25:61:61Z"
    assert list(validator.iter_errors(doc))


def test_base_list_with_a_signature_slot_is_rejected(validator):
    doc = _load(FIXTURES / "invalid" / "base_with_signature.json")
    assert doc["kind"] == "base" and "signature" in doc
    assert list(validator.iter_errors(doc))


def test_stripped_bundle_is_structurally_a_base_list(validator):
    """The schema cannot tell: only the loader's location rule can (docs/shield-signatures.md,
    loader rule 3). A file at the bundle location is a bundle whatever its kind says."""
    doc = _load(FIXTURES / "contract_only" / "bundle_stripped_to_base.json")
    validator.validate(doc)
    assert doc["kind"] == "base" and "signature" not in doc


def test_wildcards_sit_above_a_registrable_domain():
    doc = _load(FIXTURES / "contract_only" / "public_suffix_and_punycode_hosts.json")
    hosts = [h for s in doc["signatures"] for h in s["match"].get("hosts", [])]
    bad = [h for h in hosts if (h.startswith("*.") and h[2:] in _SUFFIXES) or "xn--" in h]
    assert bad, "the fixture must hold what review has to reject"


def test_date_order_and_lifetime_are_contract_rules(validator):
    from datetime import datetime

    def ts(v):
        return datetime.fromisoformat(v.replace("Z", "+00:00"))

    doc = _load(FIXTURES / "contract_only" / "date_order_and_lifetime.json")
    validator.validate(doc)
    e = doc["signatures"][0]
    assert not (ts(e["first_seen"]) <= ts(e["last_verified"]) <= ts(e["expires_at"])), "order"
    assert (ts(e["expires_at"]) - ts(e["last_verified"])).days > 400, "lifetime"
