"""U1.2: the base AI-application catalog validates, cites sources, and ignores ordinary sites."""

from __future__ import annotations

import fnmatch
import json
from collections import Counter
from pathlib import Path

import pytest

jsonschema = pytest.importorskip("jsonschema")

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "src" / "byoai" / "shield_signatures.schema.json"
CATALOG_PATH = ROOT / "src" / "byoai" / "shield_catalog_apps.json"
FP_HOSTS_PATH = Path(__file__).with_name("false_positive_hosts.txt")

#: Vendors the base catalog must cover (the task's starting list).
REQUIRED_VENDORS = {
    "OpenAI",
    "Anthropic",
    "Google",
    "Microsoft",
    "Perplexity",
    "Mistral AI",
    "DeepSeek",
    "Hugging Face",
}


@pytest.fixture(scope="module")
def catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text())


@pytest.fixture(scope="module")
def validator():
    schema = json.loads(SCHEMA_PATH.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())


def _false_positive_hosts() -> list[str]:
    lines = FP_HOSTS_PATH.read_text().splitlines()
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def _host_matches(pattern: str, host: str) -> bool:
    """Exact host, or one leftmost wildcard label (`*.example.com`). No regex."""
    host = host.lower()
    if pattern.startswith("*."):
        base = pattern[2:]
        return host.endswith("." + base) and host != base
    return host == pattern


def _entry_matches_host(entry: dict, host: str) -> bool:
    return any(_host_matches(p, host) for p in entry["match"].get("hosts", []))


def _path_matches(pattern: str, path: str) -> bool:
    """`*` matches one segment. Query strings are never matched (docs/shield-signatures.md)."""
    path = path.split("?", 1)[0]
    if len(path) > 1:
        path = path.rstrip("/")
    pat_segs, path_segs = pattern.split("/"), path.split("/")
    if len(pat_segs) != len(path_segs):
        return False
    return all(fnmatch.fnmatchcase(seg, p) for p, seg in zip(pat_segs, path_segs, strict=True))


def _model_call_matches(entry: dict, host: str, path: str) -> bool:
    if entry["type"] != "model_endpoint" or not _entry_matches_host(entry, host):
        return False
    return any(_path_matches(p, path) for p in entry["match"]["paths"])


# --- structure -------------------------------------------------------------


def test_catalog_is_a_base_list(catalog):
    assert catalog["kind"] == "base"
    assert "signature" not in catalog, "a base list is unsigned"


def test_catalog_validates_against_schema(validator, catalog):
    validator.validate(catalog)


def test_no_duplicate_ids(catalog):
    ids = [s["id"] for s in catalog["signatures"]]
    assert not [i for i, n in Counter(ids).items() if n > 1]


def test_no_host_claimed_by_two_entries(catalog):
    seen: dict[str, str] = {}
    for entry in catalog["signatures"]:
        for host in entry["match"].get("hosts", []):
            assert host not in seen, f"{host} is in {seen[host]} and {entry['id']}"
            seen[host] = entry["id"]


def test_no_wildcard_host_overlaps_another_entry(catalog):
    """A wildcard host must not also match a host some other entry claims exactly."""
    hosts = [(e["id"], h) for e in catalog["signatures"] for h in e["match"].get("hosts", [])]
    for owner, pattern in hosts:
        if not pattern.startswith("*."):
            continue
        for other, host in hosts:
            if other != owner and not host.startswith("*.") and _host_matches(pattern, host):
                pytest.fail(f"{owner} wildcard {pattern} overlaps {other} host {host}")


def test_every_entry_has_source_and_last_verified(catalog):
    for entry in catalog["signatures"]:
        source = entry["source"]
        assert source.get("name"), entry["id"]
        assert source.get("url", "").startswith("https://"), entry["id"]
        assert entry.get("last_verified"), entry["id"]


def test_timestamps_are_ordered(catalog):
    for entry in catalog["signatures"]:
        assert entry["first_seen"] <= entry["last_verified"] < entry["expires_at"], entry["id"]


def test_catalog_covers_required_vendors(catalog):
    vendors = {entry["vendor"] for entry in catalog["signatures"]}
    assert REQUIRED_VENDORS <= vendors, REQUIRED_VENDORS - vendors


# --- matching ----------------------------------------------------------------


def test_each_entry_matches_its_own_host(catalog):
    """Positive control: every declared host is matched by its entry."""
    for entry in catalog["signatures"]:
        for host in entry["match"].get("hosts", []):
            assert _entry_matches_host(entry, host), f"{entry['id']} does not match {host}"


@pytest.mark.parametrize("host", _false_positive_hosts())
def test_ordinary_hosts_do_not_match(catalog, host):
    matched = [e["id"] for e in catalog["signatures"] if _entry_matches_host(e, host)]
    assert not matched, f"{host} wrongly matched {matched}"


@pytest.mark.parametrize(
    ("host", "path"),
    [
        ("api.openai.com", "/v1/chat/completions"),
        ("api.anthropic.com", "/v1/messages"),
        ("generativelanguage.googleapis.com", "/v1beta/models/gemini-2.5-flash:generateContent"),
        ("api.mistral.ai", "/v1/chat/completions"),
        ("api.deepseek.com", "/chat/completions"),
        ("router.huggingface.co", "/v1/chat/completions"),
        ("router.huggingface.co", "/v1/chat/completions/"),
        ("generativelanguage.googleapis.com", "/v1/models/gemini-2.5-flash:generateContent"),
        (
            "generativelanguage.googleapis.com",
            "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse",
        ),
    ],
)
def test_model_call_paths_match(catalog, host, path):
    assert any(_model_call_matches(e, host, path) for e in catalog["signatures"])


@pytest.mark.parametrize(
    ("host", "path"),
    [
        # Model listing and token counting are not generations.
        ("api.openai.com", "/v1/models"),
        ("api.anthropic.com", "/v1/messages/count_tokens"),
        # Other Google Cloud API on another host.
        ("aiplatform.googleapis.com", "/v1beta/models/gemini-2.5-flash:generateContent"),
        # Right path, wrong host.
        ("openai-gateway.example.net", "/v1/chat/completions"),
        # Provider-specific router route is not the generic route.
        ("router.huggingface.co", "/novita/v3/openai/chat/completions"),
    ],
)
def test_non_generation_calls_do_not_match(catalog, host, path):
    assert not any(_model_call_matches(e, host, path) for e in catalog["signatures"])
