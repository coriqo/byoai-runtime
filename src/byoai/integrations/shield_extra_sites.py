"""Admin-added AI sites: the validator for the ``extra_sites`` policy key.

An admin lists a site Shield should also check; the browser extension then
registers its scripts there at runtime. Only hosts in the curated list
(``browser_extension/optional_sites.json``, the same origins as the manifest's
``optional_host_permissions``) are accepted: the extension cannot run anywhere
the manifest did not name, so the list is the ceiling, and a host outside it
is refused here with a message saying so.

One shape, used by the device policy (``apply_policy_update``, managed policy
validation) and by the server's ``validate_policy``::

    [{"host": "chat.mistral.ai", "app": "Mistral chat",
      "compose": ["textarea"], "send": ["button[type=submit]"]}]
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

MAX_EXTRA_SITES = 20
MAX_SELECTORS = 5
MAX_SELECTOR_CHARS = 200
_ALLOWED_KEYS = {"host", "app", "compose", "send"}
_APP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 .-]{0,39}$")
_BAD_SELECTOR = re.compile(r"[\x00-\x1f\x7f{};<>\\]")

OPTIONAL_SITES_PATH = (Path(__file__).resolve().parent.parent
                       / "browser_extension" / "optional_sites.json")


def curated_sites() -> list[dict[str, Any]]:
    """The curated origins, read from the one list the manifest is built from."""
    return json.loads(OPTIONAL_SITES_PATH.read_text())["sites"]


def curated_hosts() -> list[str]:
    return [s["host"] for s in curated_sites()]


def _selectors(value: Any, key: str) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_SELECTORS:
        raise ValueError(f"extra_sites {key} must be a list of at most {MAX_SELECTORS} selectors")
    out = []
    for sel in value:
        if (not isinstance(sel, str) or not sel.strip() or len(sel) > MAX_SELECTOR_CHARS
                or _BAD_SELECTOR.search(sel)):
            raise ValueError(f"extra_sites {key} selectors must be plain CSS text of at most "
                             f"{MAX_SELECTOR_CHARS} characters")
        out.append(sel.strip())
    return out


def validate_extra_sites(raw: Any) -> list[dict[str, Any]]:
    """Normalised list, or ValueError naming the first bad field. Nothing is
    saved when it raises."""
    if not isinstance(raw, list):
        raise ValueError("extra_sites must be a list")
    if len(raw) > MAX_EXTRA_SITES:
        raise ValueError(f"extra_sites can list at most {MAX_EXTRA_SITES} sites")
    curated = {s["host"]: s for s in curated_sites()}
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict) or set(item) - _ALLOWED_KEYS:
            raise ValueError("each extra site is an object with host, app, compose and send only")
        host = item.get("host")
        if not isinstance(host, str) or not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", host):
            raise ValueError("extra_sites host must be a bare lower-case https host name: "
                             "no scheme, path, port, query or wildcard")
        if host not in curated:
            raise ValueError(f"{host} is not one of the sites this Shield build can add ("
                             + ", ".join(sorted(curated)) + "); adding another needs a new release")
        if host in seen:
            raise ValueError(f"extra_sites lists {host} twice")
        seen.add(host)
        app = item.get("app", host)
        app = " ".join(app.split()) if isinstance(app, str) else app
        if not isinstance(app, str) or not _APP_RE.match(app):
            raise ValueError("extra_sites app must be 1 to 40 characters: letters, digits, "
                             "spaces, dots and hyphens")
        entry: dict[str, Any] = {"host": host, "app": app}
        for key in ("compose", "send"):
            if key in item:
                entry[key] = _selectors(item[key], key)
        out.append(entry)
    return out


def clean_extra_sites(raw: Any) -> list[dict[str, Any]]:
    """Reading a stored value: whatever does not validate is dropped, never
    raised, so a bad file cannot take the policy down."""
    if not isinstance(raw, list):
        return []
    good = []
    for item in raw[:MAX_EXTRA_SITES]:
        try:
            good.extend(validate_extra_sites([item]))
        except ValueError:
            continue
    seen: set[str] = set()
    return [s for s in good if not (s["host"] in seen or seen.add(s["host"]))]


def removed_hosts(before: Any, after: list[dict[str, Any]]) -> set[str]:
    """Hosts in ``before`` that ``after`` no longer lists: removing one lowers
    protection, so the caller asks for an acknowledgement."""
    return {s["host"] for s in clean_extra_sites(before)} - {s["host"] for s in after}
