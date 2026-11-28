"""Admin-added sites: the policy key, the one curated list, and that the
manifest, the validator, the generated script and the popup agree."""

from __future__ import annotations

import importlib.util
import json
import re
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
    assert "importScripts('extra-sites.js', 'shield-optional.js', 'shield-stats.js')" in worker
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
    # The service worker never reads the sign-in session. It opens the sign-in page in exactly
    # one place: finishing a join the person started, after Coriqo's page says it is done, only
    # when the admin allows linking and only when the message passed acceptJoinMessage. Checked
    # on the raw file, comments included: a check must be a live top-level line to count.
    code = (EXT / "background.js").read_text()
    assert "coriqo_session" not in code
    # Indirection the old whole-file ban also relied on not being used: no bracket access to the
    # extension APIs, and the hand-off named only where it is defined and called.
    assert not re.search(r"chrome\s*\[", code)
    assert code.count("handleJoinOnce") == 2
    start = code.index("async function handleJoinOnce(msg, sender, L) {")
    end = code.index("\n}\n", start) + 3
    join, rest = code[start:end], code[:start] + code[end:]
    # Nothing outside the join hand-off names the sign-in page (however it is spelled together),
    # reads the Coriqo link settings, or calls the hand-off.
    assert "login" not in rest.lower()
    for word in ("coriqo_link", "coriqo_api_base", "coriqo_pending_join"):
        assert word not in rest, word
    # The hand-off is reached only through handleJoinMessage, and that only from the
    # external-message listener (a message from a web page, never install or startup).
    assert re.findall(r"handleJoinOnce\(", rest) == ["handleJoinOnce("]
    assert "return await handleJoinOnce(msg, sender, globalThis.CoriqoLink)" in rest
    # The only page the worker opens outside the hand-off is the welcome page, by its literal name;
    # no other tab, window or extension URL is built anywhere else.
    assert len(re.findall(r"\.(?:tabs|windows)\.(?:create|update)\(", rest)) == 1
    assert rest.count("chrome.tabs.create({ url: chrome.runtime.getURL('welcome.html') })") == 1
    assert re.findall(r"getURL\([^)]*\)", rest) == ["getURL('')", "getURL('welcome.html')"]
    calls = [m.start() for m in re.finditer(r"handleJoinMessage\(", rest)]
    assert len(calls) == 2  # its definition and the one listener call
    listener = rest.index("chrome.runtime.onMessageExternal.addListener(")
    assert listener < calls[1] < rest.index("\n})", listener)
    # Inside it: the admin policy and the message verdict are real, live checks before the tab.
    assert join.count("login") == 1 and join.count("chrome.tabs.create") == 1
    # Each step is its own statement at the function's top level (two-space indent, whole line),
    # so wrapping a check in a dead branch or a condition moves it and fails here.
    def top(line: str) -> int:
        m = re.search(r"\n  " + re.escape(line) + r"[^\n]*\n", join)
        assert m, line
        # and not the body of a brace-less if/else/while/for on the line before
        before = join[:m.start()].rstrip().rsplit("\n", 1)[-1].strip()
        assert not re.search(r"(^|\W)(if|else|while|for)\b[^;{}]*$", before), line
        return m.start()
    policy = top("const policy = L.linkPolicy(managed)")
    gate1 = top("if (!policy.enabled) return false")
    verdict = top("const verdict = L.acceptJoinMessage({ msg, senderOrigin: sender.origin")
    gate2 = top("if (!verdict.ok) return false")
    opened = top("chrome.tabs.create({ url: chrome.runtime.getURL('login.html?auto=1') })")
    assert join.count("if (!verdict.ok)") == 1 and join.count("if (!policy.enabled)") == 1
    # Before the checks it only reads what it needs to make them: exactly these two reads, and it
    # makes no network request at all.
    reads = re.findall(r"chrome\.storage\.\w+\.get\([^)]*\)", join)
    assert reads == ["chrome.storage.local.get(['coriqo_pending_join', 'coriqo_api_base'])",
                     "chrome.storage.managed.get(['coriqo_link', 'coriqo_api_base'])"]
    for word in ("coriqo_link", "coriqo_api_base"):
        assert join.count(word) == (1 if word == "coriqo_link" else 3), word
    assert "fetch(" not in join and "XMLHttpRequest" not in join and "sendBeacon" not in join
    assert policy < gate1 < verdict < gate2 < opened
    assert "login.html" not in (EXT / "manifest.json").read_text()
    # the privacy notice must not claim there is no sign-in while there is one
    notice = (EXT / "PRIVACY.md").read_text()
    assert "There is no account and no sign-in" not in notice
    assert "If you sign in to Coriqo" in notice and "optional" in notice


def test_skip_never_calls_coriqo_or_stores_a_token():
    js = (EXT / "login.js").read_text()
    body = js[js.index("async function onSkip"):js.index("async function init")]
    for word in ("fetch(", "access_token", "SESSION_KEY", "LINK_KEY", "getApiBase", "launchWebAuthFlow"):
        assert word not in body, word
    assert "Escape" in js and 'id="skip"' in (EXT / "login.html").read_text()


def test_skip_is_ignored_while_a_sign_in_is_under_way_and_any_sign_in_clears_it():
    js = (EXT / "login.js").read_text()
    body = js[js.index("async function onSkip"):js.index("async function init")]
    assert "if (busy) return" in body
    for handler in ("onOAuth", "onConnect", "onSend", "onConsume"):
        # wrapped directly, or through a no-argument arrow that calls it
        assert re.search(rf"working\(({handler}|\(\) => {handler}\(\))\)", js), handler
    assert "remove(SKIP_KEY" in js[js.index("function setSession"):js.index("function clearSession")]
