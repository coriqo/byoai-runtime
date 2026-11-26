"""Adversarial repros from review: bodies that hid secrets, engine drift, ReDoS."""
from __future__ import annotations

import json
import time

import pytest

from byoai.integrations.shield import (
    FLAG_RULES,
    PII_RULES,
    SECRET_RULES,
    default_policy,
    evaluate,
    flags_for,
    redact_json_body,
    redact_with_rules,
)

AWS = "AKIAIOSFODNN7EXAMPLE"
PGP = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----"

BODIES = {
    "system string": {"system": f"env: {AWS}", "messages": [{"role": "user", "content": "hi"}]},
    "system blocks": {"system": [{"type": "text", "text": AWS}], "messages": []},
    "tool_result string": {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t", "content": f"K={AWS}"}]}]},
    "tool_result nested": {"messages": [{"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t", "content": [{"type": "text", "text": AWS}]}]}]},
    "tool_use input": {"messages": [{"role": "assistant", "content": [
        {"type": "tool_use", "id": "t", "name": "bash", "input": {"cmd": f"export K={AWS}"}}]}]},
    "document text": {"messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": AWS}}]}]},
    "responses instructions": {"instructions": AWS, "input": "hi"},
    "gemini systemInstruction": {"systemInstruction": {"parts": [{"text": AWS}]},
                                 "contents": [{"role": "user", "parts": [{"text": "hi"}]}]},
}


@pytest.mark.parametrize("name", BODIES)
def test_a_secret_in_any_field_is_decided_on(name):
    from byoai.integrations.shield import all_message_text
    body = json.loads(json.dumps(BODIES[name]))
    assert evaluate(all_message_text(body), default_policy())[0] == "block"


@pytest.mark.parametrize("name", BODIES)
def test_a_secret_in_any_field_is_redacted_when_the_tier_redacts(name):
    policy = {**default_policy(), "actions": {"secret": "redact", "pii": "redact", "flag": "log"}}
    out, rules = redact_json_body(json.dumps(BODIES[name]), policy)
    assert AWS not in out and rules == ["aws_access_key"]


def test_ids_and_binary_payloads_are_left_alone():
    body = {"conversation_uuid": "555-123-4567-ab", "parent_message_id": "555-123-4567",
            "model": "a@b.co",
            "messages": [{"role": "user", "id": "415-555-0199", "content": [
                {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                             "data": "a@b.co"}},
                {"type": "text", "text": "a@b.co"}]}]}
    out, _ = redact_json_body(json.dumps(body))
    got = json.loads(out)
    assert got["conversation_uuid"] == "555-123-4567-ab" and got["model"] == "a@b.co"
    assert got["messages"][0]["id"] == "415-555-0199"
    assert got["messages"][0]["content"][0]["source"]["data"] == "a@b.co"
    assert got["messages"][0]["content"][1]["text"] == "[EMAIL_1]"


def test_pgp_private_key_block_is_caught():
    assert any(r == "private_key_block" for _, r, _ in flags_for(PGP))


def test_a_cjk_neighbour_does_not_hide_a_key():
    assert any(r == "aws_access_key" for _, r, _ in flags_for(f"密钥{AWS}"))
    assert any(r == "aws_access_key" for _, r, _ in flags_for(f"{AWS}密钥"))


def test_short_openai_keys_still_count():
    assert redact_with_rules("my key sk-abcdefghij123456")[0] == "my key [SECRET_1]"


def test_a_huge_body_is_scanned_at_both_ends_and_flagged():
    big = AWS + " " + "x " * 1_200_000 + "ghp_" + "A" * 36
    rules = {r for _, r, _ in flags_for(big)}
    assert {"aws_access_key", "github_token", "oversize"} <= rules
    assert evaluate(big, default_policy())[0] == "block"
    assert "oversize" not in {r for _, r, _ in flags_for("small")}


def _adversarial(n=100_000):
    return {
        "eyJ-": "eyJ-" * (n // 4), "eyJ run": "eyJ" + "a" * n, "a*": "a" * n,
        "password spaces": "password" + " " * n, "password:": "password:" * (n // 9),
        "sk- runs": "sk-" * (n // 3), "digits": "4" * n, "digits spaced": "4 " * (n // 2),
        "postgres://": "postgres://" + "a" * n, "postgres repeat": "postgres://" * (n // 11),
        "Bearer": "Bearer " * (n // 7), "IBAN-ish": "GB82 " + "ABCD " * (n // 5),
        "+digits": "+1" * (n // 2), "dots": "a." * (n // 2), "file dots": "a.b" * (n // 3),
        "at signs": "a@" * (n // 2), "user@dots": "a@" + "b." * (n // 2),
        "email tail": "a" * 60 + "@" + "b" * n, "dashes": "-" * n, "xox": "xox" * (n // 3),
        "BEGIN": "-----BEGIN " * (n // 11), "AIza": "AIza" * (n // 4),
        "headers": "-----BEGIN PRIVATE KEY-----" * (n // 27),
    }


def test_no_rule_is_slow_on_100kb_adversarial_input():
    slow = []
    for name, text in _adversarial().items():
        for _tier, rules in (("secret", SECRET_RULES), ("pii", PII_RULES), ("flag", FLAG_RULES)):
            for rule, pattern in rules:
                t0 = time.perf_counter()
                list(pattern.finditer(text))
                dt = time.perf_counter() - t0
                if dt > 0.5:
                    slow.append((name, rule, round(dt, 2)))
    assert not slow, slow


def test_the_whole_pipeline_is_fast_on_adversarial_input():
    for name, text in _adversarial().items():
        t0 = time.perf_counter()
        evaluate(text, default_policy())
        redact_with_rules(text)
        assert time.perf_counter() - t0 < 2.5, name


def test_a_private_key_is_redacted_whole_and_a_bare_header_still_blocks():
    key = ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAsecretbase64bodyZZZ\nabcDEF==\n"
           "-----END RSA PRIVATE KEY-----")
    policy = {**default_policy(), "actions": {"secret": "redact", "pii": "redact", "flag": "log"}}
    out, _ = redact_json_body(json.dumps({"prompt": f"here:\n{key}\nthanks"}), policy)
    assert "secretbase64body" not in out and "BEGIN" not in out
    assert json.loads(out)["prompt"] == "here:\n[SECRET_1]\nthanks"
    assert evaluate("-----BEGIN PRIVATE KEY----- MIIE", default_policy())[0] == "block"


def test_a_secret_in_the_middle_of_a_3mb_body_is_still_blocked_and_fast():
    big = "x " * 750_000 + " ghp_" + "B" * 36 + " " + "y " * 750_000
    assert len(big) > 3_000_000
    t0 = time.perf_counter()
    action, rules = evaluate(big, default_policy())
    assert action == "block" and "github_token" in rules and "oversize" in rules
    assert time.perf_counter() - t0 < 5


def test_names_types_roles_and_times_are_scanned_but_ids_are_not():
    from byoai.integrations.shield import all_message_text
    body = {"name": AWS, "role": "a@b.co", "created_at": "x", "request_id": "y",
            "model": "z", "messages": [{"id": "skipme", "content": "hi"}]}
    text = all_message_text(body)
    assert AWS in text and "a@b.co" in text and "created_at" not in text
    assert "skipme" not in text and "y" not in text.split("\n")[2:]


def test_warn_still_redacts_redact_tier_pii_in_the_proxy(tmp_path, monkeypatch):
    pytest.importorskip("mitmproxy")
    import byoai.integrations.shield as sh
    from byoai.integrations.shield_proxy import ShieldProxy

    from .test_shield_proxy import _Flow
    real = sh._fingerprint_key
    monkeypatch.setattr(sh, "_fingerprint_key", lambda p=None: real(tmp_path / "fp.key"))
    px = ShieldProxy(ledger=tmp_path / "l.jsonl", policy_path=tmp_path / "p.json")
    flow = _Flow("claude.ai", "/api/organizations/o/chat_conversations/c/completion",
                 json.dumps({"prompt": "mail a@x.co, the db password: hunter42x"}))
    px.request(flow)
    sent = json.loads(flow.request.get_text())["prompt"]
    assert sent == "mail [EMAIL_1], the db [SECRET_1]"
    row = json.loads((tmp_path / "l.jsonl").read_text().splitlines()[0])
    assert row["action"] == "warn"


def test_attachment_rows_only_for_post_and_put(tmp_path, monkeypatch):
    pytest.importorskip("mitmproxy")
    from byoai.integrations.shield_proxy import ShieldProxy

    from .test_shield_proxy import _Flow
    px = ShieldProxy(ledger=tmp_path / "l.jsonl", policy_path=tmp_path / "p.json")
    for method, expect in (("GET", 0), ("HEAD", 0), ("POST", 1), ("PUT", 2)):
        flow = _Flow("claude.ai", "/api/organizations/o/upload", "")
        flow.request.method = method
        flow.request.headers = {"content-type": "application/pdf"}
        flow.request.get_content = lambda strict=False: b"%PDF"
        px.request(flow)
        n = (len((tmp_path / "l.jsonl").read_text().splitlines())
             if (tmp_path / "l.jsonl").exists() else 0)
        assert n == expect, method
