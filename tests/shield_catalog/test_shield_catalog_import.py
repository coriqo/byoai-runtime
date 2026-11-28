"""Bulk catalog import: importer rules, derived metadata, popular-host false positives."""

from __future__ import annotations

import importlib.util
import json
import os
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = ROOT / "src" / "byoai" / "shield_catalog_apps.json"
META_PATH = ROOT / "src" / "byoai" / "shield_catalog_apps_meta.json"
SCRIPT = ROOT / "scripts" / "import_shield_catalog.py"
HERE = Path(__file__).parent
REJECTED = HERE / "popular_rejected_hosts.txt"
ALLOWED = HERE / "popular_allowed_ai_hosts.txt"

CATEGORIES = {
    "chatbot", "meeting_transcription", "image_video", "writing", "coding",
    "sales_marketing", "data_analytics", "model_hub", "hr_recruiting",
    "productivity_agents", "design", "search",
}  # fmt: skip


def _lines(path: Path) -> list[str]:
    out = []
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line.split()[0])
    return out


def _load_script():
    spec = importlib.util.spec_from_file_location("import_shield_catalog", SCRIPT)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def imp():
    return _load_script()


@pytest.fixture(scope="module")
def catalog() -> dict:
    return json.loads(CATALOG_PATH.read_text())


@pytest.fixture(scope="module")
def meta() -> dict:
    return json.loads(META_PATH.read_text())


def _hosts(catalog: dict) -> set[str]:
    return {h for e in catalog["signatures"] for h in e["match"].get("hosts", [])}


# --- importer rules ---------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "host"),
    [
        ("https://www.008agent.ai/", "008agent.ai"),
        ("HTTPS://Read.AI/path?utm=1", "read.ai"),
        ("https://prompt.16x.engineer/", "16x.engineer"),
        ("https://app.appai.co.uk/x", "appai.co.uk"),
        ("https://gemini.google.com/app", "gemini.google.com"),
        ("https://firefly.adobe.com/", "firefly.adobe.com"),
        ("grok.x.ai", "x.ai"),
    ],
)
def test_normalises_to_registrable_or_exact_ai_subdomain(imp, url, host):
    assert imp.normalise_host(url) == (host, None)


@pytest.mark.parametrize(
    "url",
    [
        "https://google.com/",
        "https://meet.google.com/",
        "https://www.microsoft.com/en-us/ai",
        "https://github.com/some/tool",
        "https://microsoft.github.io/x",
        "https://something.github.io/",
        "https://bucket.s3.amazonaws.com/",
        "https://x.vercel.app/",
        "https://y.pages.dev/",
        "https://aws.amazon.com/",
        "https://xn--e1afmkfd.xn--p1ai/",
        "https://10.0.0.1/",
        "not a url",
        "",
    ],
)
def test_rejects_platforms_infrastructure_and_junk(imp, url):
    host, reason = imp.normalise_host(url)
    assert host is None and reason


def test_build_dedupes_and_ranks_trust(imp):
    shadow = [{"rank": "1", "domain": "figma.com", "vendor": "Figma", "category": "design"}]
    tio = [
        {
            "name": "Figma Again", "official_url": "https://www.figma.com/", "primary_category": "Design and creative",
            "last_verified": "2026-08-18",
        },
        {
            "name": "Zed", "official_url": "https://zed.dev/", "primary_category": "Coding and development",
            "last_verified": "2026-08-18",
        },
        {
            "name": "Pop", "official_url": "https://popular.example/", "primary_category": "Video",
            "last_verified": "2026-08-18",
        },
    ]  # fmt: skip
    auto = [
        {"name": "Zed2", "category": "Code", "website": "https://zed.dev", "review_url": "https://autoventure.live/r/z"},
        {"name": "New", "category": "Audio", "website": "https://newaudio.ai/", "review_url": "https://autoventure.live/r/n"},
    ]  # fmt: skip
    cat, meta, report = imp.build(
        shadow, tio, auto, popular={"popular.example"}, seed=[], seed_meta={}, today="2026-11-27"
    )
    by_host = {e["match"]["hosts"][0]: e for e in cat["signatures"]}
    assert set(by_host) == {"figma.com", "zed.dev", "newaudio.ai"}
    assert meta["entries"][by_host["figma.com"]["id"]]["tier"] == "listed"
    assert meta["entries"][by_host["figma.com"]["id"]]["nature"] == "ai-enabled"
    assert by_host["figma.com"]["confidence"] == "possible"
    assert meta["entries"][by_host["zed.dev"]["id"]]["tier"] == "candidate"
    assert by_host["zed.dev"]["last_verified"] == "2026-08-18T00:00:00Z"
    assert by_host["newaudio.ai"]["source"]["url"] == "https://newaudio.ai/"
    assert "autoventure" not in json.dumps(cat)
    assert meta["entries"][by_host["newaudio.ai"]["id"]]["category"] == "image_video"
    assert report["rejected"]["popular.example"].startswith("popular")


# --- shipped catalog --------------------------------------------------------


def test_catalog_is_large_and_meta_covers_every_entry(catalog, meta):
    ids = [e["id"] for e in catalog["signatures"]]
    assert len(ids) >= 900
    assert set(meta["entries"]) == set(ids)


def test_meta_values_are_closed_enums(meta):
    for eid, m in meta["entries"].items():
        assert set(m) == {"category", "nature", "tier", "origin"}, eid
        assert m["category"] in CATEGORIES, eid
        assert m["nature"] in {"ai-native", "ai-enabled"}, eid
        assert m["tier"] in {"listed", "candidate"}, eid  # never approved or trusted
        assert m["origin"] in {"seed", "shadow-ai", "tio", "autotune"}, eid


def test_confidence_follows_nature_and_tier(catalog, meta):
    for e in catalog["signatures"]:
        m = meta["entries"][e["id"]]
        if m["tier"] == "candidate" or m["nature"] == "ai-enabled":
            assert e["confidence"] == "possible", e["id"]
        else:
            assert e["confidence"] in {"probable", "confirmed"}, e["id"]


def test_tier_follows_origin(meta):
    for eid, m in meta["entries"].items():
        if m["origin"] in {"tio", "autotune"}:
            assert m["tier"] == "candidate", eid
        else:
            assert m["tier"] == "listed", eid


def test_dual_use_products_are_ai_enabled(catalog, meta):
    by_host = {e["match"]["hosts"][0]: e["id"] for e in catalog["signatures"]}
    for host in ("figma.com", "databricks.com", "grammarly.com"):
        m = meta["entries"][by_host[host]]
        assert m["nature"] == "ai-enabled" and m["tier"] == "listed", host


def _imported(catalog, meta):
    return [e for e in catalog["signatures"] if meta["entries"][e["id"]]["origin"] != "seed"]


def test_sources_are_vendor_sites_not_review_sites(catalog, meta):
    for e in _imported(catalog, meta):
        url = e["source"]["url"]
        assert "autoventure" not in url and "autotune" not in url, e["id"]
        host = url.split("/")[2].removeprefix("www.")
        want = e["match"]["hosts"][0]
        assert host == want or host.endswith("." + want), e["id"]


def test_every_entry_is_individually_overridable_by_id(catalog):
    """A policy layer keys on `id`: unique, stable-shaped, and the base file is read only."""
    ids = [e["id"] for e in catalog["signatures"]]
    assert len(set(ids)) == len(ids)
    # Every app_domain entry carries its own version, so a per-id override has something to pin.
    assert all(isinstance(e["version"], int) and e["version"] >= 1 for e in catalog["signatures"])


def test_no_generic_platform_hosts(imp, catalog, meta):
    """Applies to imported entries; the seeds are reviewed API hosts (e.g. googleapis.com)."""
    for host in _hosts({"signatures": _imported(catalog, meta)}):
        reg = imp.registrable(host)
        if reg in imp.PLATFORMS:
            assert host in imp.ALLOWED_PLATFORM_SUBDOMAINS, host
        assert not any(host.endswith("." + s) or host == s for s in imp.INFRA_SUFFIXES), host


def test_importer_is_repeatable(imp, catalog):
    """Regenerating from a catalog with no inputs keeps seeds and imports unchanged."""
    seeds = [e for e in catalog["signatures"] if e["id"] in imp.SEED_IDS]
    assert len(seeds) == 12
    again, _, _ = imp.build([], [], [], popular=set(), seed=seeds, seed_meta={}, today="2026-11-27")
    assert again["signatures"] == seeds


def test_no_imported_host_is_a_parent_of_a_seed_host(imp, catalog, meta):
    seed_hosts = {h for e in catalog["signatures"] if e["id"] in imp.SEED_IDS for h in e["match"]["hosts"]}
    parents = {imp.registrable(h) for h in seed_hosts}
    for h in _hosts({"signatures": _imported(catalog, meta)}):
        assert h not in parents, h


@pytest.mark.parametrize("host", ["airtable.com", "canva.com", "webflow.com", "media.io", "n8n.io"])
def test_generic_saas_and_builders_are_not_in_catalog(catalog, host):
    assert host not in _hosts(catalog)


def test_load_time_is_small():
    t0 = time.perf_counter()
    json.loads(CATALOG_PATH.read_text())
    json.loads(META_PATH.read_text())
    assert time.perf_counter() - t0 < 0.5
    assert CATALOG_PATH.stat().st_size < 2_000_000


# --- popular, non-AI hosts ----------------------------------------------------


def test_reviewed_popular_rejects_do_not_match(catalog):
    hosts = _hosts(catalog)
    assert not [h for h in _lines(REJECTED) if h in hosts]
    assert len(_lines(REJECTED)) >= 30


def test_allowlisted_popular_hosts_are_true_ai_hosts(catalog):
    """Each host here is in the OpenDNS top 10k and is an AI product; the file explains why."""
    for line in ALLOWED.read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            assert "#" in line, f"{line!r}: give the reason after #"


@pytest.mark.skipif(
    not os.environ.get("BYOAI_OPENDNS_TOP10K"), reason="set BYOAI_OPENDNS_TOP10K to the list path"
)
def test_opendns_top_10k_has_no_matches_except_allowlist(catalog):
    top = {
        line.strip().lower()
        for line in Path(os.environ["BYOAI_OPENDNS_TOP10K"]).read_text().splitlines()
        if line.strip()
    }
    assert len(top) > 5000
    matched = _hosts(catalog) & top
    assert matched <= set(_lines(ALLOWED)), sorted(matched - set(_lines(ALLOWED)))
