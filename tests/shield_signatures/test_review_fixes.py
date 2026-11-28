"""Shield Wave 0/1 review findings: one test per finding (matcher and catalog loader)."""

from __future__ import annotations

import copy
import hashlib
import json
import signal
import time
from pathlib import Path

import pytest

from byoai import shield_signatures as ss
from byoai.shield_signatures import load_app_catalog, load_catalog, load_catalog_text

SRC = Path(ss.__file__).parent
MODELS = json.loads((SRC / "shield_catalog_models.json").read_text())
APPS = json.loads((SRC / "shield_catalog_apps.json").read_text())
META = json.loads((SRC / "shield_catalog_apps_meta.json").read_text())


def _doc(**over):
    sig = copy.deepcopy(MODELS["signatures"][0])
    sig.update(over)
    return {**{k: v for k, v in MODELS.items() if k != "signatures"}, "signatures": [sig]}


def _load(doc, now="2026-11-28T00:00:00Z"):
    return load_catalog_text(json.dumps(doc), now=now)


# 1. ReDoS ---------------------------------------------------------------------------


def test_f1_path_match_is_linear_and_stars_capped():
    deep = _doc(match={"hosts": ["api.openai.com"], "paths": ["/" + "*" * 24]})
    assert _load(deep).error  # too many stars is refused at load
    ok = _doc(match={"hosts": ["api.openai.com"], "paths": ["/*a*a*a*a"]})
    cat = _load(ok)
    assert cat.error is None

    def boom(*_):
        raise TimeoutError

    signal.signal(signal.SIGALRM, boom)
    signal.alarm(5)
    try:
        t = time.monotonic()
        # worst case for the old regex: many stars, long almost-matching input
        assert not ss._path_ok("/*a*a*a*a*a*a*a*a", "/" + "a" * 1500 + "b")
        assert time.monotonic() - t < 2
    finally:
        signal.alarm(0)
    assert ss._path_ok("/v1beta/models/*:generateContent", "/v1beta/models/x:generateContent")
    assert not ss._path_ok("/v1/*", "/v1/")  # a star is one or more characters
    assert not ss._path_ok("/v1/*", "/v1/a/b")


# 2. expiry ------------------------------------------------------------------------------


def test_f2_expiry_enforced_at_match_time():
    cat = _load(_doc(expires_at="2026-12-01T00:00:00Z"), now="2026-11-28T00:00:00Z")
    host, path = "api.openai.com", "/v1/chat/completions"
    assert cat.match(host, path, now="2026-11-30T00:00:00Z").provider == "openai"
    assert cat.match(host, path, now="2026-12-01T00:00:00Z").provider == "unknown"
    assert cat.match(host, path, now="2027-06-01T00:00:00Z").provider == "unknown"


@pytest.mark.parametrize(
    "bad",
    ["2027-11-27T::::Z", "9999-99-99T99:99:99Z", "2027-02-30T00:00:00Z", "2027-01-01T24:00:00Z"],
)
def test_f2_garbage_timestamps_rejected(bad):
    assert _load(_doc(expires_at=bad)).error
    assert _load(_doc(last_verified=bad)).error


def test_f2_lifetime_capped_and_ordered():
    # more than 400 days after last_verified
    assert _load(_doc(last_verified="2026-11-27T00:00:00Z", expires_at="2028-11-27T00:00:00Z")).error
    # first_seen after last_verified
    assert _load(_doc(first_seen="2026-11-28T00:00:00Z", last_verified="2026-11-27T00:00:00Z")).error


# 3. provenance --------------------------------------------------------------------------


def test_f3_licence_and_source_describe_real_origin():
    meta = META["entries"]
    for e in APPS["signatures"]:
        m = meta[e["id"]]
        if m["origin"] == "seed":
            continue
        assert e["source"]["licence"] != "LicenseRef-Vendor-Public-Info", e["id"]
        assert m["origin"] in e["source"]["name"], e["id"]
        if m["tier"] == "candidate":
            assert "unverified" in e["source"]["name"], e["id"]
    loaded = load_app_catalog()
    assert loaded.error is None
    by_id = {a.id: a for a in loaded.entries}
    assert by_id["app.008agent-ai"].origin == "tio"
    assert by_id["app.008agent-ai"].verified is False


# 4. tier binding ---------------------------------------------------------------------------


def _meta_with(mutate):
    meta = copy.deepcopy(META)
    mutate(meta)
    return json.dumps(meta)


def test_f4_loader_validates_tier_and_binds_meta_to_catalog(tmp_path):
    cat_text = (SRC / "shield_catalog_apps.json").read_text()
    assert META["catalog_sha256"] == hashlib.sha256(cat_text.encode()).hexdigest()
    ok = load_app_catalog()
    tiers = {a.tier for a in ok.entries}
    assert tiers == {"listed", "candidate"}

    def write(text):
        p = tmp_path / "m.json"
        p.write_text(text)
        return p

    # a tier flipped in the sidecar must disagree with the entry's origin
    def flip(m):
        m["entries"]["app.008agent-ai"]["tier"] = "listed"

    assert load_app_catalog(meta_path=write(_meta_with(flip))).error
    # dropped record
    assert load_app_catalog(meta_path=write(_meta_with(lambda m: m["entries"].pop("app.008agent-ai")))).error
    # unknown tier value
    def bad(m):
        m["entries"]["app.008agent-ai"]["tier"] = "approved"

    assert load_app_catalog(meta_path=write(_meta_with(bad))).error
    # catalog changed under the same sidecar
    alt = tmp_path / "apps.json"
    alt.write_text(cat_text.replace("ZipRecruiter AI", "ZipRecruiter AI2", 1))
    assert load_app_catalog(alt).error


# 5. cross-file duplicates ----------------------------------------------------------------------


def test_f5_no_duplicate_ids_or_hosts_across_base_files():
    def keyed(doc):
        ids = {s["id"] for s in doc["signatures"]}
        hosts = {(s["type"], h) for s in doc["signatures"] for h in s["match"].get("hosts", [])
                 if s["type"] == "model_endpoint"}
        return ids, hosts

    (i1, h1), (i2, h2) = keyed(MODELS), keyed(APPS)
    assert not i1 & i2
    assert not {h for _, h in h1} & {h for _, h in h2}


# 6. dual-use ---------------------------------------------------------------------------------


def test_f6_huggingface_is_ai_enabled_and_possible():
    e = next(s for s in APPS["signatures"] if s["id"] == "app.huggingface.hub")
    assert e["confidence"] == "possible"
    assert META["entries"]["app.huggingface.hub"]["nature"] == "ai-enabled"


# 8. matcher hardening ------------------------------------------------------------------------------

CAT = load_catalog()


@pytest.mark.parametrize("host", ["api.openai.com:abc", "api.openai.com:", "api.openai.com:0",
                                  "api.openai.com:99999", "api.openai.com:+443"])
def test_f8_bad_ports_rejected(host):
    assert CAT.match(host, "/v1/chat/completions").provider == "unknown"
    assert CAT.match("api.openai.com:443", "/v1/chat/completions").provider == "openai"


def test_f8_dotdot_in_path_rejected():
    assert CAT.match("generativelanguage.googleapis.com",
                     "/v1beta/models/..:generateContent").provider == "unknown"


@pytest.mark.parametrize("name", ["a/../../etc/passwd", "gpt-4/..", "a//b", "x/../y"])
def test_f8_traversal_model_names_ignored(name):
    m = CAT.match("api.openai.com", "/v1/chat/completions", {"model": name})
    assert m.provider == "openai" and m.model is None


# review round 2 ---------------------------------------------------------------------------


def _apps_with(tmp_path, mutate):
    doc = copy.deepcopy(APPS)
    mutate(doc)
    text = json.dumps(doc)
    meta = copy.deepcopy(META)
    meta["catalog_sha256"] = hashlib.sha256(text.encode()).hexdigest()
    (tmp_path / "a.json").write_text(text)
    (tmp_path / "m.json").write_text(json.dumps(meta))
    return load_app_catalog(tmp_path / "a.json", tmp_path / "m.json")


@pytest.mark.parametrize("hosts", ["chatgpt.com", ["*.chatgpt.com"], ["Not A Host"], [1], []])
def test_app_hosts_are_validated(tmp_path, hosts):
    def mut(d):
        next(s for s in d["signatures"] if s["type"] == "app_domain")["match"]["hosts"] = hosts

    assert _apps_with(tmp_path, mut).error


def test_unknown_entry_type_rejects_the_catalog(tmp_path):
    assert _load(_doc(type="mystery")).error
    assert _apps_with(tmp_path, lambda d: d["signatures"][0].update(type="mystery")).error


def test_empty_or_bad_now_uses_the_real_clock_not_the_past():
    cat = load_catalog()
    assert cat.match("api.openai.com", "/v1/chat/completions", now="").provider == "openai"
    assert load_catalog_text(json.dumps(MODELS), now="").error is None
    assert load_app_catalog(now="").error is None
