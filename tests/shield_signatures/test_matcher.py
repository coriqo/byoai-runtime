"""U1.3: provider and model matching for OpenAI, Anthropic and Gemini wire shapes."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from byoai.shield_signatures import Catalog, ModelMatch, load_catalog, load_catalog_text

CATALOG = load_catalog()

OPENAI_REQ = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
OPENAI_RESP = {
    "id": "chatcmpl-abc",
    "object": "chat.completion",
    "model": "gpt-4o-mini-2024-07-18",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "hello"}}],
}
RESPONSES_REQ = {"model": "gpt-4.1", "input": "hi"}
ANTHROPIC_REQ = {
    "model": "claude-sonnet-4-5",
    "max_tokens": 64,
    "messages": [{"role": "user", "content": "hi"}],
}
ANTHROPIC_RESP = {
    "id": "msg_01",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-4-5-20250929",
    "content": [{"type": "text", "text": "hello"}],
}
GEMINI_REQ = {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}
GEMINI_RESP = {
    "candidates": [{"content": {"role": "model", "parts": [{"text": "hello"}]}}],
    "modelVersion": "gemini-2.0-flash",
}


def test_catalog_loads_clean():
    assert isinstance(CATALOG, Catalog)
    assert CATALOG.error is None
    assert len(CATALOG.entries) >= 3


@pytest.mark.parametrize(
    ("host", "path", "provider"),
    [
        ("api.openai.com", "/v1/chat/completions", "openai"),
        ("api.openai.com", "/v1/responses", "openai"),
        ("api.anthropic.com", "/v1/messages", "anthropic"),
        ("generativelanguage.googleapis.com", "/v1beta/models/gemini-2.0-flash:generateContent", "google"),
        (
            "generativelanguage.googleapis.com",
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent?alt=sse",
            "google",
        ),
        ("API.OpenAI.com:443", "/v1/chat/completions", "openai"),
    ],
)
def test_provider_from_host_and_path(host, path, provider):
    m = CATALOG.match(host, path)
    assert m.provider == provider
    assert m.model is None
    assert m.rule_id


@pytest.mark.parametrize(
    ("host", "path", "body", "model"),
    [
        ("api.openai.com", "/v1/chat/completions", OPENAI_REQ, "gpt-4o-mini"),
        ("api.openai.com", "/v1/chat/completions", OPENAI_RESP, "gpt-4o-mini-2024-07-18"),
        ("api.openai.com", "/v1/responses", RESPONSES_REQ, "gpt-4.1"),
        ("api.anthropic.com", "/v1/messages", ANTHROPIC_REQ, "claude-sonnet-4-5"),
        ("api.anthropic.com", "/v1/messages", ANTHROPIC_RESP, "claude-sonnet-4-5-20250929"),
        (
            "generativelanguage.googleapis.com",
            "/v1beta/models/gemini-2.0-flash:generateContent",
            GEMINI_RESP,
            "gemini-2.0-flash",
        ),
    ],
)
def test_model_only_when_in_payload(host, path, body, model):
    m = CATALOG.match(host, path, body)
    assert m.model == model
    assert m.model_source in {"request_field", "response_field"}


@pytest.mark.parametrize(
    ("host", "path"),
    [
        ("generativelanguage.googleapis.com", "/v1beta/models/gemini-2.0-flash:generateContent"),
        ("api.openai.com", "/v1/chat/completions"),
    ],
)
def test_model_absent_in_payload_is_never_invented(host, path):
    # Gemini's request has no model field; the model name in the URL is not read.
    body = GEMINI_REQ if "google" in host else {"messages": []}
    m = CATALOG.match(host, path, body)
    assert m.provider != "unknown"
    assert m.model is None
    assert m.model_source is None


@pytest.mark.parametrize(
    ("host", "path"),
    [
        ("myco.openai.azure.com", "/openai/deployments/prod-gpt/chat/completions"),
        ("gateway.internal.example.com", "/v1/chat/completions"),
        ("gateway.internal.example.com", "/v1/messages"),
        ("api.openai.com.evil.example", "/v1/chat/completions"),
        ("evilapi.openai.com", "/v1/chat/completions"),
        ("api.openai.com", "/v1/files"),
        ("api.openai.com", "/v1/chat/completions/../files"),
        ("", ""),
    ],
)
def test_private_deployment_or_gateway_is_unknown(host, path):
    m = CATALOG.match(host, path, OPENAI_REQ)
    assert m.provider == "unknown"
    assert m.deployment == "unknown"
    assert m.model is None
    assert m.rule_id is None


def test_matched_vendor_api_deployment():
    assert CATALOG.match("api.anthropic.com", "/v1/messages").deployment == "vendor_api"


@pytest.mark.parametrize(
    "body",
    [
        None,
        [],
        "model",
        42,
        {"model": None},
        {"model": ""},
        {"model": 7},
        {"model": ["gpt-4"]},
        {"model": {"name": "x"}},
        {"model": "x" * 500},
        {"model": "bad name with spaces\nand newline"},
        {"model": "gpt-4\u0000"},
        {"modelVersion": {"a": 1}},
    ],
)
def test_malformed_body_never_raises_and_gives_no_model(body):
    m = CATALOG.match("api.openai.com", "/v1/chat/completions", body)
    assert m.provider == "openai"
    assert m.model is None


@pytest.mark.parametrize("host", [None, 5, b"api.openai.com", ["api.openai.com"], "a\x00b"])
@pytest.mark.parametrize("path", [None, 5, b"/v1/messages", "\x00", "/" + "a" * 10000])
def test_malformed_host_or_path_never_raises(host, path):
    m = CATALOG.match(host, path, {"model": "gpt-4"})  # type: ignore[arg-type]
    assert m.provider == "unknown"
    assert m.model is None


def test_match_does_not_mutate_body():
    body = copy.deepcopy(OPENAI_REQ)
    CATALOG.match("api.openai.com", "/v1/chat/completions", body)
    assert body == OPENAI_REQ


def test_result_carries_no_payload_text():
    m = CATALOG.match("api.openai.com", "/v1/chat/completions", OPENAI_REQ)
    assert isinstance(m, ModelMatch)
    assert "hi" not in json.dumps(m.__dict__ if hasattr(m, "__dict__") else str(m))


def test_confidence_is_entry_confidence_not_higher():
    m = CATALOG.match("api.openai.com", "/v1/chat/completions")
    assert m.confidence in {"probable", "possible"}


# --- loader fail-closed -------------------------------------------------------------

BASE = json.loads(
    (Path(__file__).resolve().parents[2] / "src/byoai/shield_catalog_models.json").read_text()
)


def _text(doc) -> str:
    return json.dumps(doc)


def test_expired_entry_does_not_match_and_is_reported():
    cat = load_catalog_text(_text(BASE), now="2099-01-01T00:00:00Z")
    assert cat.match("api.openai.com", "/v1/chat/completions").provider == "unknown"
    assert cat.expired_ids


def test_unknown_field_rejects_whole_file():
    doc = copy.deepcopy(BASE)
    doc["signatures"][0]["surprise"] = 1
    cat = load_catalog_text(_text(doc))
    assert cat.error and not cat.entries
    assert cat.match("api.openai.com", "/v1/chat/completions").provider == "unknown"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(schema_version=2),
        lambda d: d.update(format="other"),
        lambda d: d.update(kind="bundle"),
        lambda d: d.update(signatures="nope"),
        lambda d: d["signatures"].append(copy.deepcopy(d["signatures"][0])),
        lambda d: d["signatures"][0].pop("expires_at"),
        lambda d: d["signatures"][0]["match"].pop("hosts"),
        lambda d: d["signatures"][0]["match"].update(hosts="api.openai.com"),
        lambda d: d["signatures"][0]["match"].update(hosts=["API.openai.com"]),
        lambda d: d["signatures"][0]["match"].update(paths=["v1/no-slash"]),
    ],
)
def test_invalid_file_fails_closed(mutate):
    doc = copy.deepcopy(BASE)
    mutate(doc)
    cat = load_catalog_text(_text(doc))
    assert cat.error and not cat.entries


@pytest.mark.parametrize("text", ["", "{", "[]", "null", "\x00", '{"a": NaN}', "1" * 100])
def test_garbage_file_never_raises(text):
    cat = load_catalog_text(text)
    assert cat.error and not cat.entries


def test_missing_file_fails_closed(tmp_path):
    cat = load_catalog(tmp_path / "nope.json")
    assert cat.error and not cat.entries


def test_catalog_validates_against_schema():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "src/byoai/shield_signatures.schema.json").read_text()
    )
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(BASE)


def _models_doc():
    return json.loads((Path(__file__).parents[2] / "src/byoai/shield_catalog_models.json").read_text())


def test_star_heavy_path_pattern_cannot_hang_the_matcher():
    import time

    doc = _models_doc()
    doc["signatures"][0]["match"]["paths"] = ["/" + "*" * 24]
    cat = load_catalog_text(json.dumps(doc))
    t = time.monotonic()
    assert cat.match("api.openai.com", "/" + "a" * 1000 + "/").provider == "unknown"
    assert time.monotonic() - t < 1


@pytest.mark.parametrize(
    "pattern,path,ok",
    [
        ("/v1/models/*:generateContent", "/v1/models/x:generateContent", True),
        ("/v1/models/*:generateContent", "/v1/models/:generateContent", False),
        ("/v1/models/*:generateContent", "/v1/models/a/b:generateContent", False),
        ("/a/*/*", "/a/x/y", True),
        ("/a/*/*", "/a/x", False),
        ("/a*b*c", "/aXbYc", True),
        ("/a*b*c", "/abc", False),
        ("/a**", "/abc", True),
        ("/a**", "/ab", False),
        ("/v1/messages", "/v1/messages", True),
        ("/v1/messages", "/v1/messages/", False),
    ],
)
def test_path_glob_semantics(pattern, path, ok):
    from byoai.shield_signatures import _path_ok

    assert _path_ok(pattern, path) is ok


def test_entry_expiring_after_load_stops_matching():
    doc = _models_doc()
    for s in doc["signatures"]:
        s["expires_at"] = "2026-11-28T00:00:00Z"
    cat = load_catalog_text(json.dumps(doc), now="2026-11-27T12:00:00Z")
    assert cat.match("api.openai.com", "/v1/chat/completions", now="2026-11-27T13:00:00Z").rule_id
    assert cat.match("api.openai.com", "/v1/chat/completions", now="2026-11-28T00:00:01Z").provider == "unknown"


@pytest.mark.parametrize("ts", ["2027-11-27T::::Z", "9999-99-99T99:99:99Z", "2027-13-01T00:00:00Z", "2027-01-01T25:00:00Z"])
def test_malformed_expires_at_rejects_file(ts):
    doc = _models_doc()
    doc["signatures"][0]["expires_at"] = ts
    assert load_catalog_text(json.dumps(doc)).error


@pytest.mark.parametrize("ts", ["2027-02-14T00:00Z", "2027-02-14T00:00:00.5Z", "2027-02-14T00:00:00.1234567Z"])
def test_previously_accepted_timestamp_forms_still_load(ts):
    doc = _models_doc()
    doc["signatures"][0]["expires_at"] = ts
    assert load_catalog_text(json.dumps(doc), now="2026-11-27T00:00:00Z").error is None


@pytest.mark.parametrize("now", ["2030-01-01", "x", "2030-01-01T00:00:00+00:00", 5, "2031-13-01T00:00:00Z"])
def test_invalid_now_falls_back_to_the_clock(now):
    doc = _models_doc()
    for s in doc["signatures"]:
        s["expires_at"] = "2030-01-01T00:00:00Z"
        s["last_verified"] = "2029-06-01T00:00:00Z"  # lifetime is capped at 400 days
    cat = load_catalog_text(json.dumps(doc), now="2026-11-27T00:00:00Z")
    assert cat.match("api.openai.com", "/v1/chat/completions", now=now).rule_id


def test_non_ascii_digit_timestamp_cannot_bypass_expiry():
    doc = _models_doc()
    doc["signatures"][0]["expires_at"] = "٢٠٢٠-01-01T00:00:00Z"  # Arabic-Indic 2020
    assert load_catalog_text(json.dumps(doc)).error


def test_valid_non_canonical_now_is_honoured_not_ignored():
    doc = _models_doc()
    for s in doc["signatures"]:
        s["expires_at"] = "2029-01-01T00:00:00Z"
        s["last_verified"] = "2028-06-01T00:00:00Z"
    cat = load_catalog_text(json.dumps(doc), now="2030-01-01T00:00Z")
    assert not cat.entries and cat.expired_ids
    live = load_catalog_text(json.dumps(doc), now="2026-11-27T00:00:00Z")
    assert live.match("api.openai.com", "/v1/chat/completions", now="2030-01-01T00:00:00.000Z").provider == "unknown"
