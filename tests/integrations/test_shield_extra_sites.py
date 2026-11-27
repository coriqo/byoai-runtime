"""Admin-added sites: the policy key, the one curated list, and that the
manifest, the validator, the generated script and the popup agree."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from byoai.integrations import shield
from byoai.integrations.shield import apply_policy_update, default_policy, merge_policy
from byoai.integrations.shield_extra_sites import (
    MAX_EXTRA_SITES,
    curated_hosts,
    validate_extra_sites,
)
from byoai.shield_server import policy as server_policy

ROOT = Path(__file__).resolve().parents[2]
EXT = ROOT / "src" / "byoai" / "browser_extension"
HOST = "chat.mistral.ai"


def _gen():
    spec = importlib.util.spec_from_file_location("gen_ext", ROOT / "scripts" / "gen_extension_rules.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_unset_behaves_as_today():
    assert default_policy()["extra_sites"] == []
    assert merge_policy({})["extra_sites"] == []
    # An update that never mentions the key changes nothing and needs no ack.
    out = apply_policy_update(default_policy(), {"notice": False})
    assert out["extra_sites"] == []
    # A server policy made without the key signs the same document as before.
    body = {"mode": "redact", "apps": {"claude": True}, "keep_text": False,
            "retention_days": 30, "notice": True}
    assert "extra_sites" not in server_policy.validate_policy(body)


def test_manifest_list_validator_script_and_generator_agree():
    manifest = json.loads((EXT / "manifest.json").read_text())
    hosts = curated_hosts()
    assert manifest["optional_host_permissions"] == [f"https://{h}/*" for h in hosts]
    assert "scripting" in manifest["permissions"]
    assert manifest["version"] == "0.10.9"
    # Chrome Web Store limit for the summary the store shows.
    assert len(manifest["description"]) <= 132, len(manifest["description"])
    # Only extension pages open PRIVACY.md, and they need no exposure to a website.
    assert "web_accessible_resources" not in manifest
    for pattern in manifest["optional_host_permissions"]:
        assert pattern.startswith("https://") and "*." not in pattern and pattern.count("*") == 1
    forbidden = {"https://*/*", "<all_urls>", "*://*/*"}
    every = set(manifest["permissions"]) | set(manifest["host_permissions"]) | set(
        manifest["optional_host_permissions"])
    for entry in manifest["content_scripts"]:
        every |= set(entry["matches"])
    assert not forbidden & every
    gen = _gen()
    assert (EXT / "shield-optional.js").read_text() == gen.render_optional()
    assert (EXT / "manifest.json").read_text() == gen.render_manifest()
    assert (EXT / "shield-sites.js").read_text() == gen.render_sites()
    for h in hosts:  # every curated host is accepted by the validator
        assert validate_extra_sites([{"host": h}])[0]["host"] == h


def test_add_needs_no_acknowledgement_and_is_normalised():
    out = apply_policy_update(default_policy(), {"extra_sites": [
        {"host": HOST, "app": "  Mistral   chat ", "compose": ["textarea"], "send": ["button"]}]})
    assert out["extra_sites"] == [{"host": HOST, "app": "Mistral chat",
                                   "compose": ["textarea"], "send": ["button"]}]


def test_removing_needs_acknowledgement():
    have = apply_policy_update(default_policy(), {"extra_sites": [{"host": HOST}]})
    with pytest.raises(ValueError, match="less_private"):
        apply_policy_update(have, {"extra_sites": []})
    out = apply_policy_update(have, {"extra_sites": [], "acknowledge": "less_private"})
    assert out["extra_sites"] == []


@pytest.mark.parametrize("bad", [
    "chat.mistral.ai",                                   # not a list
    [{"host": "https://chat.mistral.ai"}],               # scheme
    [{"host": "chat.mistral.ai/path"}],                  # path
    [{"host": "chat.mistral.ai?x=1"}],                   # query
    [{"host": "chat.mistral.ai:8443"}],                  # port
    [{"host": "*.mistral.ai"}],                          # wildcard
    [{"host": "*"}],
    [{"host": "evil.example.com"}],                      # not curated
    [{"host": "Chat.Mistral.ai"}],                       # case is not normalised away
    [{"host": HOST}, {"host": HOST}],                    # duplicate
    [{"host": HOST, "app": "x" * 41}],                   # name too long
    [{"host": HOST, "app": "<b>x</b>"}],                 # name with markup
    [{"host": HOST, "compose": ["a"] * 6}],              # too many selectors
    [{"host": HOST, "compose": ["a{}"]}],                # not a selector
    [{"host": HOST, "compose": ["a" * 201]}],            # selector too long
    [{"host": HOST, "extra": 1}],                        # unknown key
    [{"host": HOST}] * (MAX_EXTRA_SITES + 1),            # too many
])
def test_bad_writes_are_refused(bad):
    with pytest.raises(ValueError):
        apply_policy_update(default_policy(), {"extra_sites": bad})


def test_managed_policy_is_validated_and_locks_like_apps(tmp_path):
    with pytest.raises(ValueError):
        shield._validate_managed_policy({"extra_sites": [{"host": "evil.example.com"}]})
    shield._validate_managed_policy({"extra_sites": [{"host": HOST}]})
    assert "extra_sites" in shield.MANAGED_LOCKABLE_KEYS
    assert "extra_sites" in server_policy.LOCKABLE_KEYS
    with pytest.raises(server_policy.PolicyValidationError):
        server_policy.validate_policy({"mode": "redact", "apps": {"claude": True},
                                       "keep_text": False, "retention_days": 30,
                                       "notice": True, "extra_sites": [{"host": "x.com"}]})


def test_stored_junk_is_dropped_not_raised():
    p = merge_policy({"extra_sites": [{"host": "evil.example.com"}, {"host": HOST}, 5, {"host": HOST}]})
    assert [s["host"] for s in p["extra_sites"]] == [HOST]


def test_popup_and_worker_load_the_same_list_and_logic():
    popup = (EXT / "popup.html").read_text()
    for script in ("extra-sites.js", "shield-optional.js"):
        assert f'src="{script}"' in popup
    assert popup.index("extra-sites.js") < popup.index("popup.js")
    worker = (EXT / "background.js").read_text()
    assert "importScripts('extra-sites.js', 'shield-optional.js')" in worker
    # The page profile for each curated host exists, marked optional, so the
    # gate knows an admin switches it on.
    sites = (EXT / "shield-sites.js").read_text()
    for s in json.loads((EXT / "optional_sites.json").read_text())["sites"]:
        assert s["host"] in sites and s["app"] in sites


def test_sign_in_is_offered_but_never_started_by_the_extension_itself():
    """Signing in to Coriqo is optional: the popup and welcome page offer it, only on a click,
    and the privacy notice says so. Nothing may open it, or sign in, by itself."""
    import re
    for name in ("popup.js", "welcome.js"):
        js = (EXT / name).read_text()
        # the page is named exactly once, and only inside a click handler (never at load)
        at = [m.start() for m in re.finditer("login.html", js)]
        assert len(at) == 1, name
        assert "addEventListener('click'" in js[max(0, at[0] - 160):at[0]], name
        # these pages only read local state to show status; they never talk to Coriqo
        assert "coriqo_api_base" not in js, name
        # every request these pages make goes to the local Shield address, never to Coriqo
        for line in js.splitlines():
            if "fetch(" in line:
                assert "baseOf(" in line, f"{name}: {line.strip()}"
    # no page pulls in the sign-in script, and the service worker never opens, reads or calls it
    for page in ("popup.html", "welcome.html"):
        assert "login.js" not in (EXT / page).read_text()
    background = (EXT / "background.js").read_text()
    for word in ("login.html", "coriqo_session", "coriqo_api_base", "coriqo_link"):
        assert word not in background, word
    assert "login.html" not in (EXT / "manifest.json").read_text()
    # the privacy notice must not claim there is no sign-in while there is one
    notice = (EXT / "PRIVACY.md").read_text()
    assert "There is no account and no sign-in" not in notice
    assert "If you sign in to Coriqo" in notice and "optional" in notice
