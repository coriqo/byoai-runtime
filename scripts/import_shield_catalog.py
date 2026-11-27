#!/usr/bin/env python3
"""Build the Shield base app catalog from ranked AI-app lists.

Repeatable: the output depends only on the input files, ``--today`` and the seed
entries already in ``src/byoai/shield_catalog_apps.json``. The raw lists are
inputs only; nothing but derived domain facts (host, vendor, category, dates, the
vendor's own URL) is written. Run with ``python -I`` when the inputs are untrusted:

    python -I scripts/import_shield_catalog.py \\
        --shadow shadow-ai-url.csv --tio ai-tools-tio-url.csv \\
        --autotune ai-tools-autotune.csv --popular opendns-top-domains-1ok-url.txt

Trust order, highest first: the seed entries, the shadow-ai list (tier ``listed``),
the tio list and the autotune review directory (tier ``candidate``). A lower list
only adds hosts no higher list has. Nothing is ever promoted automatically; an
admin approves, changes or disables an entry by ``id`` in the policy layer, which
never edits the base file. See docs/shield-signatures.md ("Base app catalog").

The signature schema is closed, so category, AI-native or AI-enabled, tier and
origin live in a sidecar, ``src/byoai/shield_catalog_apps_meta.json``, keyed by id.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "src" / "byoai" / "shield_catalog_apps.json"
META = ROOT / "src" / "byoai" / "shield_catalog_apps_meta.json"
REJECTED_OUT = ROOT / "tests" / "shield_catalog" / "popular_rejected_hosts.txt"
ALLOWED_AI = ROOT / "tests" / "shield_catalog" / "popular_allowed_ai_hosts.txt"

LICENCE = "LicenseRef-Vendor-Public-Info"
LISTED_DAYS, CANDIDATE_DAYS = 365, 180  # the format allows at most 400 after last_verified

SEED_IDS = frozenset(
    {
        "app.openai.chatgpt-web", "app.anthropic.claude-web", "app.google.gemini-web",
        "app.microsoft.copilot-web", "app.perplexity.web", "app.perplexity.api-host",
        "app.mistral.le-chat-web", "app.deepseek.chat-web", "app.huggingface.hub",
        "model.openai.chat-completions", "model.anthropic.messages",
        "model.google.gemini-generate-content", "model.mistral.chat-completions",
        "model.deepseek.chat-completions", "model.huggingface.router-chat-completions",
    }
)  # fmt: skip
_SEED_CATEGORY = {
    "app.perplexity.web": "search", "app.perplexity.api-host": "search",
    "app.huggingface.hub": "model_hub",
}  # fmt: skip

#: Big generic registrable domains. A host on one is rejected unless it is an exact
#: AI subdomain in ALLOWED_PLATFORM_SUBDOMAINS (so google.com never matches, but
#: gemini.google.com does).
PLATFORMS = frozenset(
    """google.com google.dev microsoft.com amazon.com adobe.com apple.com github.com gitlab.com
    meta.com facebook.com instagram.com x.com twitter.com linkedin.com youtube.com reddit.com
    medium.com substack.com wordpress.com wix.com squarespace.com shopify.com notion.so slack.com
    zoom.us salesforce.com intuit.com oracle.com ibm.com sap.com kuaishou.com jianying.com
    ebi.ac.uk bytedance.com baidu.com tencent.com alibaba.com aliexpress.com apache.org
    mozilla.org wikipedia.org tableau.com airtable.com canva.com zapier.com webflow.com bubble.io
    softr.io glideapps.com adalo.com coda.io linear.app temporal.io appwrite.io beehiiv.com
    apollo.io hunter.io n8n.io media.io""".split()
)
#: Hosting, CDN and tenant-subdomain suffixes: shared infrastructure, never a catalog host.
INFRA_SUFFIXES = frozenset(
    """github.io gitlab.io amazonaws.com cloudfront.net azurewebsites.net azurestaticapps.net
    cloudflare.com workers.dev pages.dev vercel.app netlify.app herokuapp.com web.app
    firebaseapp.com onrender.com streamlit.app hf.space gradio.live replit.app repl.co glitch.me
    fly.dev railway.app ngrok.io trycloudflare.com appspot.com run.app blogspot.com tumblr.com
    weebly.com godaddysites.com myshopify.com wixsite.com webflow.io dorik.io carrd.co
    bubbleapps.io softr.app lovable.app notion.site framer.website googleusercontent.com
    googleapis.com""".split()
)
ALLOWED_PLATFORM_SUBDOMAINS = frozenset(
    """gemini.google.com notebooklm.google.com ai.google.dev copilot.microsoft.com
    designer.microsoft.com amazonq.aws.amazon.com firefly.adobe.com podcast.adobe.com
    kling.kuaishou.com dreamina.jianying.com alphafold.ebi.ac.uk ai.meta.com""".split()
)
#: Hosts rejected by hand, with the reason (data errors in a source list).
REJECT_HOSTS = {
    "adobe.firefly.com": "probable typo for firefly.adobe.com; firefly.com is an unrelated domain",
}
#: Two-label public suffixes seen in the inputs (stdlib only; no suffix-list dependency).
SUFFIX2 = frozenset(
    """co.uk org.uk ac.uk com.au net.au org.au co.jp co.kr co.in co.nz co.za com.br com.cn com.hk
    com.mx com.sg com.tr com.tw com.ar co.il co.id com.my com.ph com.vn eu.org pp.ua org.cn net.cn com.ua co.ke com.ng com.pk com.sa com.eg""".split()
)
#: Shadow-ai products that are general SaaS with AI features, not AI-first.
AI_ENABLED_SHADOW = frozenset(
    """databricks.com grammarly.com figma.com descript.com gong.io 6sense.com clay.com
    sourcegraph.com kaggle.com rev.com grain.co replit.com braintrust.com mutiny.com people.ai
    chorus.ai seamless.ai warmly.ai scale.com""".split()
)
CATEGORY_MAP = {
    "Education and learning": "productivity_agents", "Automation and agents": "productivity_agents",
    "Customer support": "chatbot", "Research and knowledge": "search",
    "Business and finance": "data_analytics", "Health and lifestyle": "productivity_agents",
    "SEO and search": "sales_marketing", "Productivity and workflow": "productivity_agents",
    "Marketing and advertising": "sales_marketing", "Coding and development": "coding",
    "Data and analytics": "data_analytics", "Audio, music, and voice": "image_video",
    "Sales and CRM": "sales_marketing", "Presentations and documents": "writing",
    "Design and creative": "design", "Image generation and editing": "image_video",
    "Writing and content": "writing", "Video": "image_video",
    "Developer infrastructure and models": "model_hub", "Chatbots and assistants": "chatbot",
    # autotune
    "Automation": "productivity_agents", "Audio": "image_video", "Code": "coding",
    "Design": "design", "Productivity to Boost Workflow": "productivity_agents",
    "Chatbot": "chatbot", "Ecommerce": "sales_marketing", "Image Generators": "image_video",
    "Meeting": "meeting_transcription", "Research": "search", "Finance": "data_analytics",
    "Health": "productivity_agents", "Customer Service": "chatbot", "Data": "data_analytics",
    "Education": "productivity_agents", "Email": "sales_marketing", "Hiring": "hr_recruiting",
    "Marketing for Small Business": "sales_marketing", "Real Estate": "sales_marketing",
    "SEO": "sales_marketing", "Legal": "writing", "Social Media": "sales_marketing",
    "Translation": "writing", "Writing": "writing",
}  # fmt: skip
CATEGORIES = frozenset(
    """chatbot meeting_transcription image_video writing coding sales_marketing data_analytics
    model_hub hr_recruiting productivity_agents design search""".split()
)

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def registrable(host: str) -> str:
    """Registrable domain of ``host`` using the small suffix table above."""
    labels = host.split(".")
    n = 3 if len(labels) >= 3 and ".".join(labels[-2:]) in SUFFIX2 else 2
    return ".".join(labels[-n:])


def _on_infra(host: str) -> bool:
    return any(host == s or host.endswith("." + s) for s in INFRA_SUFFIXES)


def normalise_host(url: str) -> tuple[str | None, str | None]:
    """Return ``(host, None)`` for a catalog host, or ``(None, reason)``."""
    raw = (url or "").strip()
    if not raw:
        return None, "empty"
    parsed = urlparse(raw if "//" in raw else "//" + raw)
    try:
        host = (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return None, "unparseable"
    host = host.removeprefix("www.")
    if not host or not host.isascii():
        return None, "not an ascii host"
    try:
        ipaddress.ip_address(host)
        return None, "ip address"
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2 or not all(_LABEL.match(x) for x in labels):
        return None, "not a valid host"
    if any(x.startswith("xn--") for x in labels):
        return None, "punycode host needs manual review"
    if host in REJECT_HOSTS:
        return None, REJECT_HOSTS[host]
    if _on_infra(host):
        return None, "shared infrastructure host"
    reg = registrable(host)
    if reg in PLATFORMS:
        if host in ALLOWED_PLATFORM_SUBDOMAINS:
            return host, None
        return None, f"generic platform {reg}"
    return reg, None


def _slug_id(host: str) -> str:
    slug = "app." + re.sub(r"[^a-z0-9]+", "-", host).strip("-")
    if len(slug) > 81:
        slug = slug[:72] + "-" + hashlib.sha256(host.encode()).hexdigest()[:8]
    return slug


def _source_url(raw: str, host: str) -> str:
    parsed = urlparse(raw if "//" in raw else "//" + raw)
    h = (parsed.hostname or "").lower().removeprefix("www.")
    path = parsed.path or "/"
    if h and (h == host or h.endswith("." + host)) and not re.search(r"\s", path):
        url = f"https://{h}{path}"
        if len(url) <= 300:
            return url
    return f"https://{host}"


def _clean(text: str, limit: int) -> str:
    return re.sub(r"\s+", " ", text or "").strip()[:limit]


def _ts(day: str) -> str:
    return f"{day}T00:00:00Z"


def _entry(host, vendor, tech, source_url, nature, tier, first_seen, verified):
    days = LISTED_DAYS if tier == "listed" else CANDIDATE_DAYS
    expires = (dt.date.fromisoformat(verified) + dt.timedelta(days=days)).isoformat()
    if nature == "ai-enabled":
        note = (
            f"{host} is a general product with AI features. A visit alone does not show AI was "
            "used: look for an AI feature request before reporting AI use. A link to the site in "
            "a document or search result is not use."
        )
    else:
        note = (
            f"A link to {host} in a document, search result or help article is not use of the "
            "app. Count only a navigation to the app or a request it serves."
        )
    if tier == "candidate":
        note += " Imported from a third-party directory and not independently verified."
    confidence = "probable" if (tier == "listed" and nature == "ai-native") else "possible"
    return {
        "id": _slug_id(host),
        "type": "app_domain",
        "match": {"hosts": [host]},
        "vendor": vendor,
        "technology": tech,
        "confidence": confidence,
        "evidence_required": ["host_match"],
        "false_positive_notes": note,
        "source": {
            "name": _clean(f"{tech} (vendor site)", 120),
            "url": source_url,
            "licence": LICENCE,
        },
        "first_seen": _ts(first_seen),
        "last_verified": _ts(verified),
        "version": 1,
        "expires_at": _ts(expires),
    }


def build(shadow, tio, autotune, *, popular, seed, seed_meta, today, popular_allow=()):
    """Return ``(catalog, meta, report)``. Pure: no file access."""
    rejected: dict[str, str] = {}
    meta_entries: dict[str, dict] = {}
    entries: list[dict] = []
    taken: set[str] = set()
    seed_parents: set[str] = set()
    for e in seed:
        entries.append(e)
        taken.update(e["match"].get("hosts", []))
        seed_parents.update(registrable(h.removeprefix("*.")) for h in e["match"].get("hosts", []))
        if e["id"] in seed_meta:
            meta_entries[e["id"]] = seed_meta[e["id"]]
    # Verification dates come only from the tio list; the others carry none.
    tio_rows: dict[str, dict] = {}
    for r in tio:
        h, _ = normalise_host(r["official_url"])
        if h and h not in tio_rows:
            tio_rows[h] = r

    def add(host, origin, vendor, tech, raw_url, category, nature, tier, verified):
        entry = _entry(
            host, _clean(vendor, 80), _clean(tech, 120), _source_url(raw_url, host), nature, tier,
            min(today, verified), verified,
        )  # fmt: skip
        assert entry["id"] not in meta_entries, entry["id"]
        entries.append(entry)
        meta_entries[entry["id"]] = {
            "category": category, "nature": nature, "tier": tier, "origin": origin,
        }  # fmt: skip
        taken.add(host)

    def admit(raw, exempt_popular):
        host, why = normalise_host(raw)
        if host is None:
            shown = (urlparse(raw if "//" in raw else "//" + raw).hostname or raw).lower()
            rejected[shown.removeprefix("www.").strip() or "(empty)"] = why or "rejected"
            return None
        if host in taken:
            return None
        if host in seed_parents:
            rejected[host] = "parent domain of a seed host; the seed already covers the app"
            return None
        if not exempt_popular and host in popular and host not in popular_allow:
            rejected[host] = "popular non-AI host (in the popularity list)"
            return None
        return host

    for r in shadow:
        host = admit(r["domain"], True)
        if host is None:
            continue
        t = tio_rows.get(host)
        verified = t["last_verified"] if t and t.get("last_verified") else today
        nature = "ai-enabled" if host in AI_ENABLED_SHADOW else "ai-native"
        add(host, "shadow-ai", r["vendor"], t["name"] if t else f"{r['vendor']} ({host})",
            f"https://{host}", r["category"], nature, "listed", verified)  # fmt: skip
    for r in tio:
        host = admit(r["official_url"], False)
        if host is None:
            continue
        cat = CATEGORY_MAP.get(r["primary_category"], "productivity_agents")
        add(host, "tio", r["name"], r["name"], r["official_url"], cat, "ai-enabled",
            "candidate", r.get("last_verified") or today)  # fmt: skip
    for r in autotune:  # only hosts missing elsewhere; review_url is never read
        host = admit(r["website"], False)
        if host is None:
            continue
        cat = CATEGORY_MAP.get(r["category"], "productivity_agents")
        add(host, "autotune", r["name"], r["name"], r["website"], cat, "ai-enabled",
            "candidate", today)  # fmt: skip
    seeds = [e for e in entries if e["id"] in SEED_IDS]
    rest = sorted((e for e in entries if e["id"] not in SEED_IDS), key=lambda e: e["id"])
    catalog = {
        "schema_version": 1,
        "format": "coriqo.shield.signatures",
        "kind": "base",
        "file_version": 2,
        "generated_at": _ts(today),
        "publisher": "byoai-runtime",
        "signatures": seeds + rest,
    }
    meta = {
        "schema_version": 1,
        "format": "coriqo.shield.catalog-meta",
        "file_version": 2,
        "entries": dict(sorted(meta_entries.items())),
    }
    return catalog, meta, {"rejected": rejected}


def dump_catalog(catalog: dict) -> str:
    """One entry per line: small, diff-friendly, loads fast."""
    head = {k: v for k, v in catalog.items() if k != "signatures"}
    lines = [f"  {json.dumps(k)}: {json.dumps(v)}," for k, v in head.items()]
    body = ",\n".join("    " + json.dumps(e, ensure_ascii=False) for e in catalog["signatures"])
    return "{\n" + "\n".join(lines) + '\n  "signatures": [\n' + body + "\n  ]\n}\n"


def dump_meta(meta: dict) -> str:
    head = {k: v for k, v in meta.items() if k != "entries"}
    lines = [f"  {json.dumps(k)}: {json.dumps(v)}," for k, v in head.items()]
    body = ",\n".join(f"    {json.dumps(k)}: {json.dumps(v)}" for k, v in meta["entries"].items())
    return "{\n" + "\n".join(lines) + '\n  "entries": {\n' + body + "\n  }\n}\n"


def _csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _hostlist(path: Path) -> set[str]:
    return {
        x.strip().lower().rstrip(".").removeprefix("www.")
        for x in path.read_text().splitlines()
        if x.strip()
    }


def _allow(path: Path) -> set[str]:
    out = set()
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line.split()[0])
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--shadow", type=Path, required=True)
    ap.add_argument("--tio", type=Path, required=True)
    ap.add_argument("--autotune", type=Path, required=True)
    ap.add_argument("--popular", type=Path, required=True, help="popular domains, one per line")
    ap.add_argument("--today", default=dt.date.today().isoformat())
    args = ap.parse_args(argv)
    existing = json.loads(CATALOG.read_text())
    seed = [e for e in existing["signatures"] if e["id"] in SEED_IDS]
    seed_meta = {}
    for e in seed:
        cat = _SEED_CATEGORY.get(e["id"], "model_hub" if e["id"].startswith("model.") else "chatbot")
        seed_meta[e["id"]] = {
            "category": cat, "nature": "ai-native", "tier": "listed", "origin": "seed",
        }  # fmt: skip
    popular_allow = _allow(ALLOWED_AI) if ALLOWED_AI.exists() else set()
    catalog, meta, report = build(
        _csv(args.shadow), _csv(args.tio), _csv(args.autotune),
        popular=_hostlist(args.popular), seed=seed, seed_meta=seed_meta,
        today=args.today, popular_allow=popular_allow,
    )  # fmt: skip
    CATALOG.write_text(dump_catalog(catalog))
    META.write_text(dump_meta(meta))
    rej = sorted(
        h for h, why in report["rejected"].items() if why.startswith(("popular", "generic", "parent"))
    )
    REJECTED_OUT.write_text(
        "# Hosts the importer rejected as popular non-AI or generic-platform hosts.\n"
        "# Derived by scripts/import_shield_catalog.py. None may match a catalog entry.\n"
        + "".join(h + "\n" for h in rej)
    )
    print(f"{len(catalog['signatures'])} entries, {len(report['rejected'])} rejected", file=sys.stderr)
    for h, why in sorted(report["rejected"].items()):
        print(f"  rejected {h}: {why}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
