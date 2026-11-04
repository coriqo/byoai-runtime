"""BYOAI capture shield — behavioral capture, verdicts, and tamper-evident
sealing as a first-class integration.

Schema-contract is intentionally shared with the captures demo
(``captures.jsonl``): feed rows are ``kind``-tagged records produced by the
MCP connector gateway and the desktop capture proxy. This module keeps the
behavioral rules in one place so the console (``web/``) and the demo UI read
the same analyzer.

    python -m byoai.integrations.shield          # serves UI + API on :17831

Components:

* flag rules (PII / HIGH / AGENT) — same regex rules as the demo
* local PII redaction — matched spans are replaced with compartment labels;
  only their sha256 survives inside the seal
* sealed interactions — RFC 6962 Merkle tree + per-device Ed25519 signed
  checkpoints (same primitives as :mod:`byoai.recorder.merkle` /
  :mod:`byoai.recorder.keys`), receipts that verify offline in the browser

The UI is the ``/shield`` route of the console app in ``web/``. This server
serves its build (``byoai/console_static/``) and answers the API both at
``/api/*`` and at ``/shield-api/*``, the prefix the app calls through the Vite
dev proxy, so one build works in dev and standalone.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from byoai.recorder.keys import atomic_write_bytes, load_or_create_device_key
from byoai.recorder.merkle import MerkleTree, checkpoint_leaf_hash
from byoai.integrations.shield_sync import SYNC_LEVELS, level_words, sync_level

# Shield's own port. Not 8300 (Consul), 8800 (the MCP demo gateway), 8080
# (the proxy) or any other number a dev stack likes; the browser extension
# ships the same default (browser_extension/background.js). Override with
# BYOAI_SHIELD_PORT and enter the same port in the extension popup.
import os as _os
import sys as _sys


def _port_from_env(default: int = 17831) -> int:
    raw = _os.environ.get("BYOAI_SHIELD_PORT")
    if raw is None:
        return default
    try:
        port = int(raw)
        if 1 <= port <= 65535:
            return port
    except ValueError:
        pass
    # An exported-but-empty variable is common; it must not stop Shield from
    # starting at all, and the one line says what to fix.
    print(f"BYOAI_SHIELD_PORT={raw!r} is not a port number (1-65535); "
          f"using {default}.", file=_sys.stderr)
    return default


DEFAULT_PORT = _port_from_env()

# What /api/identity signs (prefix + caller's nonce); the extension checks the
# same bytes. Changing it breaks pairing with installed extensions.
IDENTITY_PREFIX = b"byoai-shield-identity:"

MAX_INTERACTIONS = 400
# Most entries an older seal file may claim to have trimmed before an upgrade.
MAX_CARRIED = 10_000_000


# ------------------------------------------------- private files, portable
#
# Shield's files hold a usage record, and the seal chain is the evidence. They
# are private to the user by default (0600 on POSIX; on Windows the user-profile
# ACL already limits them to the user, SYSTEM and administrators), written
# atomically so a crash or a reader never sees half a file, and locked with the
# platform's own primitive so this runs on Windows and Linux as well as macOS.

import contextlib as _contextlib


def atomic_write_private(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` via a same-directory temp file: fsync, then
    replace. Readers see the old file or the new one, never a torn one."""
    import tempfile
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")  # 0600
    try:
        with _os.fdopen(fd, "w") as fh:
            fh.write(text)
            fh.flush()
            _os.fsync(fh.fileno())
        _os.replace(tmp, path)
    except BaseException:
        with _contextlib.suppress(OSError):
            _os.unlink(tmp)
        raise


def harden_files(*paths: Path | None) -> None:
    """Tighten files Shield owns to owner-only. Best effort; POSIX only, since
    chmod means nothing on Windows."""
    if _os.name != "posix":
        return
    for path in paths:
        if path is not None and path.exists():
            with _contextlib.suppress(OSError):
                path.chmod(0o600)
    # Shield's own data folder is owner-only too. A folder the user chose (a
    # repo checkout, say) is left as they made it.
    with _contextlib.suppress(OSError):
        if DATA_DIR.is_dir():
            DATA_DIR.chmod(0o700)


@_contextlib.contextmanager
def file_lock(fh):
    """Exclusive lock on an open file, restored to its position on release."""
    if _os.name == "nt":
        import msvcrt
        pos = fh.tell()
        fh.seek(0)
        while True:
            try:
                msvcrt.locking(fh.fileno(), msvcrt.LK_LOCK, 1)  # retries ~10 s
                break
            except OSError:
                continue
        fh.seek(pos)
        try:
            yield
        finally:
            pos = fh.tell()
            fh.seek(0)
            with _contextlib.suppress(OSError):
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            fh.seek(pos)
    else:
        import fcntl
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)

# ---- rule table v2 -----------------------------------------------------
# One table for the desktop proxy and the browser extension: scripts/
# gen_extension_rules.py writes it into shield-rules.js. Patterns must stay
# valid JavaScript too (no inline flags except a leading (?i), no named groups).
#
# Tiers: ``secret`` (credentials, default action block), ``pii`` (personal
# details, default redact) and ``flag`` (signals only, default log: they are
# recorded but never stop a send).
def _rx(pattern: str, flags: int = 0) -> re.Pattern:
    """ASCII-only \\b, \\w and \\d, as in JavaScript, so a CJK character next
    to a key can't hide it from one engine and not the other."""
    return re.compile(pattern, flags | re.ASCII)


SECRET_RULES = [
    ("anthropic_key", _rx(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key",    _rx(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}")),
    ("aws_access_key", _rx(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token",  _rx(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}")),
    ("slack_token",   _rx(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google_api_key", _rx(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("stripe_key",    _rx(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}")),
    # Detection is the header alone. Redaction extends to a matching END line
    # within 8 KB, found in code (see _redact_private_keys), not in the regex:
    # a lazy "up to 8 KB then END" quantifier is quadratic on a stream of headers.
    ("private_key_block", _rx(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")),
    ("jwt",           _rx(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("conn_string",   _rx(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]*:[^\s@/]+@")),
    ("bearer",        _rx(r"\bBearer\s+[A-Za-z0-9._-]{20,}")),
    # "password: hunter42" with a value that has a digit in it. The bare word,
    # or "secret = os.environ[...]", is not a credential.
    ("credential_assign", _rx(
        r"(?i)\b(?:password|passwd|secret|api[_ ]?key)\s*[:=]\s*[\"']?(?=[^\s\"']{0,128}\d)[^\s\"'<>{}\[\]()]{6,}")),
]
PII_RULES = [
    ("emails",        _rx(r"(?<![a-z0-9._%+-])[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,255}\.[a-z]{2,}", re.I)),
    # 13-19 digits (spaces or dashes between) that pass Luhn; see VALIDATORS.
    ("cards",         _rx(r"\b[2-6](?:[ -]?[0-9]){12,18}\b")),
    ("wallets",       _rx(r"\b0x[a-fA-F0-9]{40}\b|\bbc1[a-z0-9]{25,}\b")),
    ("phone_numbers", _rx(r"\b(?:\+?1[-. ]?)?\(?\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b|(?<![\w+])\+[0-9]{8,15}\b")),
    ("ssn_like",      _rx(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("iban",          _rx(r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")),
]
FLAG_RULES = [
    ("executable_masquerade", _rx(r"(?<![\w.-])[\w.-]{1,128}\.(exe|scr|bat|cmd|dmg|msi|sh)\b", re.I)),
    ("tool_intent", _rx(r"\b(execute|execute_stream|tool_use|deploy|refund|wire ?transfer|send (the |my )?money|draft_email)\b", re.I)),
    ("password_said", _rx(r"\b(password|passphrase|credential)\b", re.I)),
]
REPLY_RULES = [
    ("reply_pii_echo", re.compile(r"(?<![a-z0-9._%+-])[a-z0-9._%+-]{1,64}@[a-z0-9.-]{1,255}\.[a-z]{2,}|\b4[0-9]{12}(?:[0-9]{3})?\b", re.I)),
    ("reply_leak", re.compile(r"(?i)(your api key|secret[^\n]{0,24}=|\bsk-[a-zA-Z0-9]{16,})")),
    ("reply_toxic", re.compile(r"(?i)\b(stupid|idiot|hate|hope you die)\b")),
]
RULE_TIER = {**{r: "secret" for r, _ in SECRET_RULES},
             **{r: "pii" for r, _ in PII_RULES},
             **{r: "flag" for r, _ in FLAG_RULES},
             "oversize": "flag",  # no pattern: the body was too big to scan whole
             "too_many_files": "flag",
             "unreadable": "flag"}  # no pattern: the page could not read the file  # no pattern: an upload with more parts than are listed


def _luhn(text: str) -> bool:
    digits = [int(c) for c in text if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _iban_ok(text: str) -> bool:
    s = text.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    n = int("".join(str(int(c, 36)) for c in s[4:] + s[:4]))
    return n % 97 == 1


#: A match only counts when its validator passes (same names in shield-rules.js).
VALIDATOR_NAMES = {"cards": "luhn", "iban": "iban"}
_VALIDATORS = {"luhn": _luhn, "iban": _iban_ok}


def _valid(rule: str, value: str) -> bool:
    name = VALIDATOR_NAMES.get(rule)
    return name is None or _VALIDATORS[name](value)


MAX_SCAN = 2_000_000
HALF_SCAN = 1_000_000


def _cap(text: str) -> tuple[str, bool]:
    """Above MAX_SCAN chars only the first and last HALF_SCAN are scanned."""
    if len(text) <= MAX_SCAN:
        return text, False
    return text[:HALF_SCAN] + "\n" + text[-HALF_SCAN:], True


def _matches(rule: str, pattern: re.Pattern, text: str):
    return [m for m in pattern.finditer(text) if _valid(rule, m.group(0))]


def _first_match(rule: str, pattern: re.Pattern, text: str):
    """The first match that counts, or None; stops there, so a body that is
    one match after another costs one match, not all of them."""
    for m in pattern.finditer(text):
        if _valid(rule, m.group(0)):
            return m
    return None


RULE_LABEL = {
    "emails": "email address", "cards": "card number", "wallets": "wallet address",
    "phone_numbers": "phone number", "ssn_like": "SSN-like number", "iban": "IBAN",
    "anthropic_key": "Anthropic API key", "openai_key": "OpenAI API key",
    "aws_access_key": "AWS access key", "github_token": "GitHub token",
    "slack_token": "Slack token", "google_api_key": "Google API key",
    "stripe_key": "Stripe key", "private_key_block": "private key",
    "jwt": "JWT", "conn_string": "database URL with a password",
    "bearer": "bearer token", "credential_assign": "credential text",
    "password_said": "credential mention", "oversize": "very large message", "too_many_files": "very many files",
    "unreadable": "file that could not be checked",
    "executable_masquerade": "dangerous file",
    "tool_intent": "agent action intent", "connector_tool_call": "agent tool call",
    "reply_pii_echo": "PII echoed in reply", "reply_leak": "secret echoed in reply",
    "reply_toxic": "harsh language in reply",
}
#: Placeholder word per rule: text is rewritten to [EMAIL_1], [SECRET_2], ...
PLACEHOLDER = {"emails": "EMAIL", "cards": "CARD", "wallets": "WALLET",
               "phone_numbers": "PHONE", "ssn_like": "SSN", "iban": "IBAN",
               **{r: "SECRET" for r, _ in SECRET_RULES}}
RULE_REDACT = PLACEHOLDER  # rules that can rewrite text (kept for older callers)
# The flag rules are signals, not secrets: rewriting the word "password" out of
# "how do I reset my password" would break the question and protect nothing.

# ---- actions -----------------------------------------------------------
ACTIONS = ("log", "redact", "warn", "block")  # weakest to strictest
DEFAULT_ACTIONS = {"secret": "block", "pii": "redact", "flag": "log"}
#: Per-rule action that replaces the tier default for that rule.
RULE_ACTIONS = {"credential_assign": "warn"}


def stricter(a: str, b: str) -> str:
    return a if ACTIONS.index(a) >= ACTIONS.index(b) else b


def clean_actions(raw: object) -> dict:
    """Tier -> action, each one of ACTIONS; missing or invalid falls back to
    the default for that tier."""
    raw = raw if isinstance(raw, dict) else {}
    return {t: (raw[t] if raw.get(t) in ACTIONS else d)
            for t, d in DEFAULT_ACTIONS.items()}


def action_for(rule: str, policy: dict | None) -> str:
    """What one rule hit does under ``policy``. ``observe`` mode logs all."""
    policy = policy or {}
    if policy.get("mode") == "observe":
        return "log"
    tier = RULE_TIER.get(rule, "flag")
    act = clean_actions(policy.get("actions"))[tier]
    override = RULE_ACTIONS.get(rule)
    if not override:
        return act
    # The rule's own action stands in for the tier default (credential_assign
    # warns even though secrets block). A policy that sets the tier stricter
    # than that default wins.
    if ACTIONS.index(act) > ACTIONS.index(DEFAULT_ACTIONS[tier]):
        return stricter(act, override)
    return override


def evaluate(text: str, policy: dict | None,
             flags: list | None = None) -> tuple[str, list[str]]:
    """(strictest action, rules that hit) for a message under ``policy``.
    ``flags`` is a precomputed ``flags_for(text)``, to avoid scanning twice."""
    rules = [r for _, r, _ in (flags if flags is not None else flags_for(text, replies=False))
             if r in RULE_TIER]
    action = "log"
    for r in rules:
        action = stricter(action, action_for(r, policy))
    return action, rules


APP_LABEL = {"claude": "Claude", "chatgpt": "ChatGPT", "gemini": "Gemini",
             "copilot": "Copilot",
             # Desktop-proxy apps that speak a public API (see the host table
             # in shield_proxy.py). All off until an admin turns them on.
             "github_copilot": "GitHub Copilot", "mistral": "Mistral",
             "deepseek": "DeepSeek", "groq": "Groq", "openrouter": "OpenRouter",
             "together": "Together", "gemini_api": "Gemini API"}
# Apps whose chat traffic the capture proxy can read and redact. Gemini's web
# client sends form-encoded batch RPC and Copilot talks over a websocket, so
# neither can be governed yet; their toggles stay off and say why.
COVERED_APPS = ("claude", "chatgpt", "github_copilot", "mistral", "deepseek",
                "groq", "openrouter", "together", "gemini_api")
# Apps whose traffic Shield can't read, but whose messages and files the
# extension's input gate checks as the user hands them to the page. They can
# be turned on; the network backstop and the desktop proxy still can't read them.
INPUT_ONLY_APPS = ("gemini", "copilot")

# ---- the rules object the extension carries, and its version ------------


def _js_rule(name: str, pattern: re.Pattern) -> list[str]:
    """[name, source, flags] for ``new RegExp(source, flags)``. JavaScript has
    no leading ``(?i)``, so that becomes the ``i`` flag."""
    source, flags = pattern.pattern, ""
    if source.startswith("(?i)"):
        source = source[4:]
        flags = "i"
    if pattern.flags & re.I:
        flags = "i"
    # Groups JavaScript also reads: (?:  (?=  (?!  (?<=  (?<!  -- anything else
    # after an unescaped "(?" (inline flags, named groups) must be rewritten.
    if re.search(r"(?<!\\)\(\?(?![:=!]|<[=!])", source):
        raise ValueError(f"rule {name!r} uses Python-only group syntax")
    return [name, source, flags]


def extension_rules() -> dict:
    """The rules object scripts/gen_extension_rules.py writes into
    shield-rules.js (without ``rules_version``, which is a hash of this)."""
    return {
        "secret": [_js_rule(n, p) for n, p in SECRET_RULES],
        "pii": [_js_rule(n, p) for n, p in PII_RULES],
        "flag": [_js_rule(n, p) for n, p in FLAG_RULES],
        # A match only counts if its named validator passes.
        "validators": VALIDATOR_NAMES,
        # Redacted as [EMAIL_1], [SECRET_2], ... (numbered per distinct value).
        "placeholder": PLACEHOLDER,
        "rule_actions": RULE_ACTIONS,
        "default_actions": DEFAULT_ACTIONS,
        "covered_apps": list(COVERED_APPS),
    }


def rules_version_of(rules: dict) -> str:
    """First 12 hex of SHA-256 over the canonical JSON of ``rules``."""
    from byoai.recorder.canonical import canonicalize
    return hashlib.sha256(canonicalize(rules)).hexdigest()[:12]


#: Names the version of the rules that checked a file. Each file row carries it
#: so an examiner can tell which rules to run; shield-rules.js carries the same.
RULES_VERSION = rules_version_of(extension_rules())

# ---- files ---------------------------------------------------------------
#: Per-app file policy, weakest to strictest. ``warn`` asks first in the
#: browser; the desktop proxy has no way to ask, so there it blocks.
FILE_ACTIONS = ("allow", "warn", "block")
TEXT_EXTENSIONS = frozenset(
    ".txt .csv .tsv .json .jsonl .md .log .env .ini .cfg .conf .yaml .yml .xml "
    ".sql .py .js .ts .go .java .rb .sh .pem .key".split())
MAX_FILE_SCAN = 5 * 1024 * 1024


def clean_files(raw: object) -> dict:
    """App -> file action; a missing or invalid entry is ``allow``."""
    raw = raw if isinstance(raw, dict) else {}
    return {a: (raw[a] if raw.get(a) in FILE_ACTIONS else "allow") for a in APP_LABEL}


def file_action(app: str | None, policy: dict | None) -> str:
    return clean_files((policy or {}).get("files")).get(app or "", "allow")


TEXT_MIMES = frozenset((
    "application/json", "application/x-sh", "application/xml",
    "application/x-yaml", "application/yaml"))


def mime_text_like(mime: str | None) -> bool:
    """A declared type that is text whatever the file is called: text/*, JSON,
    XML, YAML, shell, and certificate/key formats (x509, pem)."""
    m = (mime or "").split(";", 1)[0].strip().lower()
    return (m.startswith("text/") or m in TEXT_MIMES or m.endswith("+json")
            or m.endswith("+xml") or "yaml" in m or "x509" in m or "pem" in m)


def is_text_like(name: str | None, mime: str | None) -> bool:
    ext = _os.path.splitext(name or "")[1].lower()
    return ext in TEXT_EXTENSIONS or mime_text_like(mime)


def _utf16_guess(data: bytes) -> str | None:
    """utf-16-le / utf-16-be for text without a byte-order mark: more than 30%
    of the bytes at one parity are zero (ASCII in UTF-16 is every other byte)."""
    n = len(data)
    if n < 4:
        return None
    odd, even = data[1::2].count(0), data[0::2].count(0)
    if odd / (n / 2) > 0.3 and odd >= even:
        return "utf-16-le"
    if even / (n / 2) > 0.3:
        return "utf-16-be"
    return None


def _decode_text(data: bytes) -> str:
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return data.decode("utf-16", "replace")
    guess = _utf16_guess(data)
    if guess:
        return data.decode(guess, "replace")
    return data.decode("utf-8", "replace")


def _reads_as_text(data: bytes) -> bool:
    """Valid UTF-8, or UTF-16 (with a mark, or by the zero-byte pattern)."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or _utf16_guess(data):
        return True
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def inspect_file(name: str | None, mime: str | None, data: bytes, app: str | None,
                 policy: dict | None, *, key_path: Path | None = None,
                 raw_upload: bool = False) -> dict:
    """What a ledger row may hold about one uploaded file: type, size, SHA-256,
    a keyed hash of the name, whether the rules read it, which rules hit and the
    version of the rules. Never the name or any of the content.

    ``raw_upload``: the body came bare to a known upload endpoint (ChatGPT's
    storage PUT), so it has no name and a declared type that means nothing; it
    is read when it decodes as text.

    ``action`` is ``log``, ``warn`` or ``block``: the strictest of the per-app
    file policy and the rule actions (``redact`` counts as ``warn``, because
    files are never rewritten). ``mode: observe`` logs everything."""
    policy = policy or {}
    scanned = len(data) <= MAX_FILE_SCAN and (
        is_text_like(name, mime) or (raw_upload and not name and _reads_as_text(data)))
    flags: list[str] = []
    rule_action = "log"
    if scanned:
        text = _decode_text(data)
        found = flags_for(text, replies=False)
        rule_action, rules = evaluate(text, policy, flags=found)
        flags = list(dict.fromkeys(
            f"{t}:{r}" for t, r, _ in found if not r.startswith("reply_")))
        if rule_action == "redact":
            rule_action = "warn"
    base = {"allow": "log", "warn": "warn", "block": "block"}[file_action(app, policy)]
    action = stricter(rule_action, base)
    if policy.get("mode") == "observe":
        action = "log"
    return {
        "mime": (mime or "").split(";", 1)[0].strip().lower() or None,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "name_hash": (fingerprint(name, key_path or FINGERPRINT_KEY) if name else None),
        "scanned": scanned,
        "flags": flags,
        "rules_version": RULES_VERSION,
        "action": action,
    }


DATA_DIR = Path.home() / ".byoai" / "shield"
FINGERPRINT_KEY = DATA_DIR / "fingerprint.key"
#: The signed policy envelope last accepted from Coriqo managed mode (private,
#: atomic — see :func:`apply_managed_envelope`). Absent = never managed, or
#: unmanaged (a signed ``policy: null`` document, still kept here so a replayed
#: older envelope is refused as a rollback).
MANAGED_POLICY_PATH = DATA_DIR / "managed_policy.json"

# Ledger fields that carry message text. Privacy-first rows never write them;
# the scrub pass removes them from rows written before it.
TEXT_FIELDS = ("prompt", "preview", "input_preview", "delta_preview",
               "output_preview")
RETENTION_CHOICES = (7, 30, 90, 365)


@dataclass
class ShieldConfig:
    ledger: Path
    seal_path: Path
    key_dir: Path
    policy_path: Path | None = None
    #: Override for tests; production uses :data:`MANAGED_POLICY_PATH`.
    managed_policy_path: Path | None = None
    sig_every: int = 8
    max_interactions: int = 400


def flags_for(text: str, *, replies: bool = True) -> list[tuple[str, str, str]]:
    flags: list[tuple[str, str, str]] = []
    scanned, capped = _cap(text)
    for tier, rules in (("secret", SECRET_RULES), ("pii", PII_RULES),
                        ("flag", FLAG_RULES), ("reply", REPLY_RULES)):
        if tier == "reply" and not replies:
            continue
        # Secrets are scanned in full (their rules are linear and prefix-led);
        # only the softer tiers give up the middle of a huge body.
        subject = text if tier == "secret" else scanned
        for rule, pattern in rules:
            found = _first_match(rule, pattern, subject)
            if found:
                flags.append((reply_tier(rule) if tier == "reply" else tier,
                              rule, found.group(0)[:60]))
    if capped:
        flags.append(("flag", "oversize", ""))
    return flags


def reply_tier(rule: str) -> str:
    """A reply that echoes personal data or a secret is a privacy hit; harsh
    language is a conduct flag, not personal data."""
    return "conduct" if rule == "reply_toxic" else "pii"


def redact_with_rules(text: str, policy: dict | None = None,
                      state: dict | None = None) -> tuple[str, list[str]]:
    """Replace secrets and personal details with numbered placeholders
    (``[EMAIL_1]``, ``[SECRET_2]``), also naming which rules rewrote something.

    The same value gets the same number. Pass one ``state`` dict across the
    fields of a body to keep numbers consistent there; it lives only as long
    as the caller keeps it. With a ``policy``, rules whose action is ``log``
    are left alone."""
    state = state if state is not None else {}
    hit: list[str] = []
    for rule, p in (*SECRET_RULES, *PII_RULES):
        label = PLACEHOLDER.get(rule)
        if not label or (policy is not None and action_for(rule, policy) == "log"):
            continue
        changed = False

        def sub(m, rule=rule, label=label):
            nonlocal changed
            value = m.group(0)
            if not _valid(rule, value):
                return value
            changed = True
            seen = state.setdefault(label, {})
            return f"[{label}_{seen.setdefault(value, len(seen) + 1)}]"

        if rule == "private_key_block":
            text = _redact_private_keys(text, sub, p)
        else:
            text = p.sub(sub, text)
        if changed:
            hit.append(rule)
    return text, hit


_KEY_END = re.compile(r"-----END [A-Z ]{0,256}PRIVATE KEY(?: BLOCK)?-----", re.ASCII)
KEY_BODY_MAX = 8192


def _redact_private_keys(text: str, sub, header: re.Pattern) -> str:
    """Replace each private-key header, and the key body through its END line
    when that starts within KEY_BODY_MAX characters of the header, with one
    placeholder. Linear: the END search moves forward only (an END candidate
    that is not a valid END line is not one for any later header either)."""
    out: list[str] = []
    pos = 0
    end_at = -2  # start of the next valid END line at or after the last search point
    end_stop = -1
    for m in header.finditer(text):
        if m.start() < pos:
            continue
        stop = m.end()
        if end_at != -1 and end_at < stop:
            i = text.find("-----END ", stop)
            end_at = -1
            while i != -1:
                e = _KEY_END.match(text, i)
                if e:
                    end_at, end_stop = i, e.end()
                    break
                i = text.find("-----END ", i + 1)
        if end_at != -1 and end_at - stop <= KEY_BODY_MAX:
            stop = end_stop
        out.append(text[pos:m.start()])
        out.append(sub(_Span(text[m.start():stop])))
        pos = stop
    out.append(text[pos:])
    return "".join(out)


class _Span:
    """The bit of a ``re.Match`` the substituter reads."""
    def __init__(self, value: str) -> None:
        self._v = value

    def group(self, _n: int = 0) -> str:
        return self._v


def redact(text: str) -> str:
    return redact_with_rules(text)[0]


# ------------------------------------------------------------ privacy-first


def _fingerprint_key(path: Path = FINGERPRINT_KEY) -> bytes:
    """Per-device secret for message fingerprints, created on first use
    (mode 0600). Keyed so a fingerprint of a short message can't be reversed
    by hashing guesses."""
    import os
    import secrets
    try:
        return path.read_bytes()
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:  # lost a creation race to the other process
            return path.read_bytes()
        key = secrets.token_bytes(32)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        return key


def fingerprint(text: str, key_path: Path = FINGERPRINT_KEY) -> str:
    import hmac
    mac = hmac.new(_fingerprint_key(key_path), text.encode("utf-8"),
                   hashlib.sha256)
    return "hmac-sha256:" + mac.hexdigest()


def inspect_text(text: str, policy: dict, *, rules: str = "request",
                 key_path: Path = FINGERPRINT_KEY, flags: list | None = None) -> dict:
    """What a ledger row may hold about a message: rule hits, length and a
    keyed fingerprint. The redacted preview only when the admin opted in."""
    if rules == "reply":
        found = [(reply_tier(r), r) for r, p in REPLY_RULES if p.search(text)]
    else:
        found = [(t, r) for t, r, _ in (flags if flags is not None else flags_for(text, replies=False))
                 if not r.startswith("reply_")]
    out = {
        "flags": [f"{t}:{r}" for t, r in found],
        "chars": len(text),
        "text_hmac": fingerprint(text, key_path) if text else None,
    }
    if policy.get("keep_text"):
        out["preview"] = redact(text)[:200]
    return out


def _content_text(content) -> str:
    """Text of one message's content in any shape we read: a string, a list
    of text blocks (Anthropic / OpenAI), or ChatGPT web's ``{"parts": [...]}``."""
    if isinstance(content, str):
        return content
    if isinstance(content, dict) and isinstance(content.get("parts"), list):
        return "\n".join(x for x in content["parts"] if isinstance(x, str))
    if isinstance(content, list):
        return "\n".join(str(b.get("text", "")) for b in content
                         if isinstance(b, dict)
                         and b.get("type") in ("text", "input_text"))
    return ""


def _gemini_text(body: dict) -> str | None:
    """Text of the last ``contents[]`` turn of a Gemini generateContent body."""
    contents = body.get("contents")
    if isinstance(contents, list) and contents and isinstance(contents[-1], dict):
        parts = contents[-1].get("parts")
        if isinstance(parts, list):
            return "\n".join(x["text"] for x in parts
                             if isinstance(x, dict) and isinstance(x.get("text"), str))
    return None


def message_text(body: dict) -> str:
    """The human-typed part of a chat request body: claude.ai web ``prompt``,
    the last turn of a Messages / Chat Completions / ChatGPT web ``messages``
    list, a Responses API ``input``, or the last Gemini ``contents`` turn."""
    prompt = body.get("prompt")
    if isinstance(prompt, str):
        return prompt
    messages = body.get("messages")
    if isinstance(messages, list) and messages and isinstance(messages[-1], dict):
        return _content_text(messages[-1].get("content"))
    inp = body.get("input")
    if isinstance(inp, str):
        return inp
    if isinstance(inp, list) and inp and isinstance(inp[-1], dict):
        return _content_text(inp[-1].get("content"))
    return _gemini_text(body) or ""


# Keys whose string values are identifiers or labels, never message text:
# scanning or rewriting them would only create false hits.
_ID_KEYS = frozenset({"id", "uuid", "model", "signature", "media_type", "mimetype",
                      "mime_type"})
_ID_SUFFIXES = ("_id", "_uuid")


def _idish(key: object) -> bool:
    k = str(key).lower()
    return k in _ID_KEYS or k.endswith(_ID_SUFFIXES)


def _walk(node, fix):
    """Apply ``fix(str) -> str`` to every string leaf of a JSON value, in
    place, at any depth, except under id-like keys and base64 payloads. This
    covers system prompts, tool results, tool inputs and document text as well
    as the typed message, wherever a provider puts them."""
    if isinstance(node, str):
        return fix(node)
    if isinstance(node, list):
        for i, item in enumerate(node):
            node[i] = _walk(item, fix)
    elif isinstance(node, dict):
        binary = node.get("type") == "base64" or "mimeType" in node or "mime_type" in node
        for k, v in list(node.items()):
            if _idish(k) or (binary and str(k).lower() == "data"):
                continue
            node[k] = _walk(v, fix)
    return node


def _map_texts(body: dict, fix) -> None:
    _walk(body, fix)


def all_message_text(body: dict) -> str:
    """Every string in the body that could carry text, joined: what a block or
    redact decision must look at, so a secret in a system prompt, a tool
    result or earlier history can't ride along."""
    out: list[str] = []
    _walk(body, lambda s: (out.append(s), s)[1])
    return "\n".join(out)


def redact_json_body(raw: str, policy: dict | None = None) -> tuple[str, list[str]]:
    """Redact secrets and personal details inside the message fields of a JSON
    chat body.

    Only message text is rewritten: ``prompt``, ``input``, the content of each
    ``messages[]`` / ``input[]`` turn (strings, text blocks, ChatGPT web
    ``parts``) and Gemini ``contents[].parts[].text``. Running the rules over
    the raw wire body would also hit conversation ids, timestamps and model
    names that happen to look like phone numbers. A body that isn't JSON is
    returned unchanged with no rules. Placeholders are numbered across the
    whole body, and the mapping is dropped when this returns."""
    try:
        body = json.loads(raw)
    except (ValueError, TypeError):
        return raw, []
    if not isinstance(body, dict):
        return raw, []
    hit: set[str] = set()
    state: dict = {}

    def fix(s: str) -> str:
        out, rules = redact_with_rules(s, policy, state)
        hit.update(rules)
        return out

    _map_texts(body, fix)
    if not hit:
        return raw, []
    return json.dumps(body, ensure_ascii=False), sorted(hit)


def append_row(ledger: Path, rec: dict) -> None:
    """Append one ledger row under an exclusive lock, so a scrub rewriting the
    file can't drop a row the proxy writes at the same moment."""
    ledger.parent.mkdir(parents=True, exist_ok=True)
    fd = _os.open(ledger, _os.O_WRONLY | _os.O_APPEND | _os.O_CREAT, 0o600)
    with _os.fdopen(fd, "a") as fh:
        with file_lock(fh):
            fh.write(json.dumps(rec, default=str, sort_keys=True) + "\n")


class SealChainError(RuntimeError):
    pass


class SealChain:
    """RFC 6962-graded tamper evidence on recorder-core primitives.

    leaf = sha256(0x00 || canonical(payload)) per entry (via
    :data:`byoai.recorder.merkle.checkpoint_leaf_hash`), a binary MerkleTree
    over all leaves, and a checkpoint {root, height, device_id} Ed25519-signed
    with a locally-held DeviceKey (same trust root as recorder/receipts.py).

    Storage is an append-only log, one entry per line (``log_path``), plus a
    small state file (``cfg.seal_path``: latest checkpoint, incidents). An
    append is O(1), nothing is ever trimmed, and every entry back to the first
    is covered by the signed checkpoint. Only the newest ``WINDOW`` payloads
    are kept in memory; every leaf hash is, which is what the tree needs.
    Sealing is idempotent: a payload already in the chain is not added again,
    so replaying the ledger after a restart adds nothing.
    """

    WINDOW = 512

    def __init__(self, cfg: ShieldConfig) -> None:
        import threading
        self.cfg = cfg
        # The feed's watcher stamps entries while the Coriqo publisher and
        # receipt requests sign checkpoints, each on its own thread. One lock
        # keeps the entries, the checkpoint and the file in step.
        self._lock = threading.RLock()
        self._key = load_or_create_device_key(cfg.key_dir)
        self.entries: list[dict] = []        # newest WINDOW entries, with payloads
        self.checkpoint: dict | None = None
        self._leaves: list[bytes] = []       # every leaf, in order
        self._leaf_set: set[bytes] = set()
        self._tree: MerkleTree | None = None
        self._log_sig: tuple = (0, 0)
        self._carried = 0                    # entries the v1 format trimmed before upgrade
        self._batch = 0                      # >0 while a batch defers its checkpoint
        self._batch_dirty = False
        # Things an examiner must be able to see, kept in the state file (a
        # reset that left no trace would be the easiest way to hide edits).
        self.incidents: list[dict] = []
        #: Stable random id of this local record, made once with the seal file
        #: and kept across restarts and window trims. A new id means the record
        #: was wiped or recreated; Coriqo compares it between sends.
        self.record_id: str = ""
        self._load()

    @property
    def log_path(self) -> Path:
        return self.cfg.seal_path.with_name(self.cfg.seal_path.stem + ".log.jsonl")

    @property
    def height(self) -> int:
        return len(self._leaves)

    @property
    def total(self) -> int:
        """Sealed entries ever. Only goes up, so a chain that comes back
        shorter than a witness remembers (the extension keeps one) has been
        rolled back or wiped. Includes entries the old format had already
        trimmed before an upgrade, so the count does not drop when it happens."""
        return self._carried + len(self._leaves)

    # -- persistence ------------------------------------------------------
    def _note(self, what: str, detail: str) -> None:
        self.incidents.append({"at": time.strftime("%Y-%m-%d %H:%M:%S"),
                               "what": what, "detail": detail})

    def _quarantine(self, path: Path, tag: str) -> Path:
        moved = path.with_name(f"{path.name}.{tag}-{int(time.time())}")
        _os.replace(path, moved)
        return moved

    def _scan_log(self):
        """Yield ``(entry, problem)`` for each log line, in order. A problem
        ends the scan: nothing after a bad line can be trusted. A torn final
        line (a crash mid-write) is dropped without a problem."""
        try:
            raw = self.log_path.read_bytes()
        except FileNotFoundError:
            return
        lines = raw.split(b"\n")
        torn = lines.pop() if lines and lines[-1] else b""   # no trailing newline
        del torn
        for i, line in enumerate(lines):
            if not line:
                continue
            try:
                e = json.loads(line)
                ok = (e["height"] == i + 1
                      and self._leaf(e["payload"]).hex() == e["leaf_hash"]
                      and e["leaf_hash"][:16] == e["seal"])
            except Exception:  # noqa: BLE001
                ok = False
            if not ok:
                yield None, f"entry {i + 1} does not match its own hash"
                return
            yield e, None

    def _load(self) -> None:
        state: dict = {}
        if self.cfg.seal_path.exists():
            try:
                state = json.loads(self.cfg.seal_path.read_text())
            except Exception as exc:  # noqa: BLE001
                moved = self._quarantine(self.cfg.seal_path, "unreadable")
                self._note("chain_unreadable",
                           f"{type(exc).__name__}; the old file was kept as {moved.name}")
        self.incidents = list(state.get("incidents", [])) + self.incidents
        migrated = False
        carried = state.get("carried", 0)
        self._carried = (carried if isinstance(carried, int) and not isinstance(carried, bool)
                         and 0 < carried <= MAX_CARRIED else 0)
        if "entries" in state:                # format 1: one JSON file, last 512
            migrated = True
            kept = self._migrate_v1(state)
            state = {"incidents": self.incidents, "record_id": state.get("record_id"),
                     "checkpoint": state.get("checkpoint")}
            n = len(kept.get("entries") or [])
            total = kept.get("total", n)
            # The file is the user's to edit: only a plausible count is carried,
            # since an inflated one would make every honest count look rolled back.
            if isinstance(total, int) and not isinstance(total, bool) and n <= total <= n + MAX_CARRIED:
                self._carried = total - n
            else:
                self._carried = 0
                self._note("migrated", "the older seal file's entry count was not a usable "
                           "number, so the count restarts from the entries it held")
        self.checkpoint = state.get("checkpoint")
        stored_id = state.get("record_id")
        self.record_id = stored_id if isinstance(stored_id, str) and stored_id else uuid.uuid4().hex
        good: list[dict] = []
        for entry, problem in self._scan_log():
            if problem:
                moved = self._quarantine(self.log_path, "broken")
                self._note("chain_broken", f"{problem}; the log was kept as {moved.name} "
                           f"and its {len(good)} intact entries carried over")
                self._rewrite_log(good)
                break
            good.append(entry)
        else:
            self._trim_torn_tail()
        self._leaves = [bytes.fromhex(e["leaf_hash"]) for e in good]
        self._leaf_set = set(self._leaves)
        self.entries = good[-self.WINDOW:]
        self._tree = None
        self._log_sig = _stat_sig(self.log_path)
        cp_height = int((self.checkpoint or {}).get("height", 0) or 0)
        trimmed = self._carried and len(self._leaves) < cp_height <= self.total
        if migrated and self.checkpoint and trimmed and self._checkpoint_matches() is False:
            # The old format signed over entries it later trimmed away, so this
            # is the upgrade, not tampering. The old file is kept beside it.
            self._note("migrated",
                       "upgraded from the older seal format; its last signed checkpoint covered "
                       "entries that format had already trimmed, so it could not be carried "
                       "over (the old file was kept). A new one is signed with the next entry.")
            self.checkpoint = None
        elif self.checkpoint and self._checkpoint_matches() is False:
            self._note("checkpoint_mismatch",
                       "the signed checkpoint no longer matches the entries it covered "
                       "(entries were edited or removed while Shield was off)")
        self._persist()

    def _migrate_v1(self, state: dict) -> dict:
        # Keep the old file whole: earlier seal proofs and its signed
        # checkpoint stay checkable against it.
        backup = self.cfg.seal_path.with_name(f"{self.cfg.seal_path.name}.v1-{int(time.time())}")
        atomic_write_private(backup, self.cfg.seal_path.read_text())
        entries = state.get("entries") or []
        lines = []
        for i, e in enumerate(entries, 1):
            leaf = self._leaf(e["payload"])
            lines.append(json.dumps({"height": i, "payload": e["payload"],
                                     "seal": leaf.hex()[:16], "leaf_hash": leaf.hex()},
                                    sort_keys=True))
        if lines:
            atomic_write_private(self.log_path, "\n".join(lines) + "\n")
        return state

    def _rewrite_log(self, entries: list[dict]) -> None:
        atomic_write_private(self.log_path, "".join(
            json.dumps(e, sort_keys=True) + "\n" for e in entries))

    def _trim_torn_tail(self) -> None:
        try:
            raw = self.log_path.read_bytes()
        except FileNotFoundError:
            return
        if raw and not raw.endswith(b"\n"):
            keep = raw[: raw.rfind(b"\n") + 1]
            atomic_write_private(self.log_path, keep.decode("utf-8", "replace"))

    def _persist(self) -> None:
        atomic_write_private(self.cfg.seal_path, json.dumps({
            "format": 2, "record_id": self.record_id, "checkpoint": self.checkpoint,
            "total": self.total, "carried": self._carried, "incidents": self.incidents,
        }, indent=1))

    def _append_line(self, entry: dict) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        fd = _os.open(self.log_path, _os.O_WRONLY | _os.O_APPEND | _os.O_CREAT, 0o600)
        with _os.fdopen(fd, "a") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
            fh.flush()
            _os.fsync(fh.fileno())
        self._log_sig = _stat_sig(self.log_path)

    # -- chain ------------------------------------------------------------
    def _leaf(self, payload: dict) -> bytes:
        return checkpoint_leaf_hash(payload)

    def _rebuild_tree(self) -> None:
        self._tree = MerkleTree(self._leaves) if self._leaves else None

    def _leaf_index(self, seal: str) -> int:
        try:
            prefix = bytes.fromhex(seal)
        except ValueError:
            return -1
        for i, leaf in enumerate(self._leaves):
            if leaf.startswith(prefix):
                return i
        return -1

    def stamp(self, payload: dict) -> str:
        with self._lock:
            return self._stamp(payload)

    def _stamp(self, payload: dict) -> str:
        leaf = self._leaf(payload)
        if leaf in self._leaf_set:            # already sealed: replay adds nothing
            return leaf.hex()[:16]
        entry: dict = {"height": len(self._leaves) + 1, "payload": payload,
                       "seal": leaf.hex()[:16], "leaf_hash": leaf.hex()}
        self._append_line(entry)
        self._leaves.append(leaf)
        self._leaf_set.add(leaf)
        self.entries.append(entry)
        del self.entries[:-self.WINDOW]
        self._tree = None  # lazily rebuilt on demand
        if self._batch:
            self._batch_dirty = True          # signed once when the batch ends
        elif self.height % self.cfg.sig_every == 0:
            self.sign_checkpoint()
        else:
            self._persist()
        return entry["seal"]

    def batch(self):
        """Seal many entries under one signed checkpoint. Each entry is on disk
        as soon as it is stamped; only the signature (which hashes the whole
        tree) waits for the end, so a burst costs one signature, not one per
        row. A crash mid-burst leaves those entries without a signature until
        the next seal; the ledger replay is idempotent, so nothing is lost, and
        signing at load instead would vouch for entries someone appended by hand."""
        import contextlib

        @contextlib.contextmanager
        def _ctx():
            with self._lock:
                self._batch += 1
                try:
                    yield self
                finally:
                    self._batch -= 1
                    if not self._batch and self._batch_dirty:
                        self._batch_dirty = False
                        if self._leaves:
                            self._sign_checkpoint()
        return _ctx()

    def sign_checkpoint(self) -> dict:
        with self._lock:
            return self._sign_checkpoint()

    def _sign_checkpoint(self) -> dict:
        if self._tree is None:
            self._rebuild_tree()
        assert self._tree is not None, "empty seal chain — at least one entry required"
        cp = {
            "kind": "byoai.shield.checkpoint.v1",
            "root_hex": self._tree.root.hex(),
            "height": self.height,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "device_id": self._key.device_id,
            "public_key_b64": self._key.public_key_b64,
        }
        cp["sig"] = self._key.sign(checkpoint_leaf_hash(cp))
        self.checkpoint = cp
        self._persist()
        return cp

    def _checkpoint_matches(self) -> bool | None:
        """Does the signed checkpoint still describe the entries it covered?
        The seal is an unkeyed hash, so someone who edits an entry can
        recompute it; what they can't redo is the signature."""
        cp = self.checkpoint
        if not cp:
            return None
        n = int(cp.get("height", 0))
        if n > len(self._leaves):
            return False                       # entries were cut off the end
        if n == 0:
            return None
        return MerkleTree(self._leaves[:n]).root.hex() == cp.get("root_hex")

    def verify_chain(self) -> dict:
        with self._lock:
            return self._verify_chain()

    def _verify_chain(self) -> dict:
        self._rebuild_tree()
        # If the log changed by anything but our own appends, re-read it all.
        if _stat_sig(self.log_path) != self._log_sig:
            for _entry, problem in self._scan_log():
                if problem:
                    self._note("chain_broken", f"{problem} (found while running)")
                    self._persist()
                    break
            else:
                fresh = [e["leaf_hash"] for e, _ in self._scan_log()]
                if fresh != [leaf.hex() for leaf in self._leaves]:
                    self._note("chain_changed", "the log was changed while Shield was running")
                    self._persist()
            self._log_sig = _stat_sig(self.log_path)
        for e in self.entries:
            if self._leaf(e["payload"]).hex()[:16] != e["seal"]:
                return {"tamper_evident": False, "broken_at": e["height"],
                        "reason": "content hash mismatch"}
        cp = self.checkpoint
        sig_ok = self._sig_valid(cp) if cp else None
        matches = self._checkpoint_matches()
        return {
            "tamper_evident": (cp is None or bool(sig_ok)) and matches is not False
                              and not self.incidents,
            "checkpoint_matches_entries": matches,
            "incidents": self.incidents,
            "sealed_total": self.total,
            "entries": self.height,
            "merkle_root": self._tree.root.hex() if self._tree else None,
            "checkpoint": None if not cp else {
                "root": cp.get("root_hex"), "height": cp["height"],
                "device_id": cp.get("device_id"), "sig_valid": sig_ok,
            },
        }

    def _sig_valid(self, cp: dict) -> bool:
        return self._key.verify(cp["public_key_b64"],
                                   checkpoint_leaf_hash(
                                       {k: v for k, v in cp.items() if k != "sig"}),
                                   cp.get("sig", ""))

    def _find_entry(self, seal: str) -> dict | None:
        found = next((e for e in self.entries if e["seal"] == seal), None)
        if found is not None:
            return found
        for e, _problem in self._scan_log():   # older than the in-memory window
            if e and e["seal"] == seal:
                return e
        return None

    def count_with_text(self) -> int:
        """Entries whose payload carries a redacted preview (keep_text was on)."""
        return sum(1 for e, _ in self._scan_log()
                   if e and (e.get("payload") or {}).get("text_redacted"))

    def proof_for(self, seal: str) -> dict | None:
        idx = self._leaf_index(seal)
        if idx < 0:
            return None
        if self._tree is None:
            self._rebuild_tree()
        if self._tree is None:
            return None
        p = self._tree.proof(idx)
        return {
            "leaf_index": p.leaf_index,
            "leaf_hash": p.leaf_hash.hex(),
            "steps": [{"sibling": s.sibling.hex(), "side": s.side}
                      for s in p.steps],
            "root_hex": p.root.hex(),
        }

    def receipt(self, seal: str) -> dict | None:
        """Portable receipt — verifies fully offline given the checkpoint."""
        entry = self._find_entry(seal)
        if entry is None:
            return None
        cp = self.sign_checkpoint()  # fresh, so the root covers this entry
        return {
            "kind": "byoai.receipt.v2",
            "seal": entry["seal"], "height": entry["height"],
            "payload": entry["payload"],
            "merkle": {
                "proof": self.proof_for(seal),
                # Every field the device signed, exactly as signed (kind and
                # ts included), so the signature checks from the receipt alone.
                "checkpoint": dict(cp),
                "note": "Offline verify: sha256(0x00||canonical(payload)) == "
                        "seal; fold leaf + steps → root; unwrap Ed25519 sig over "
                        "the checkpoint (sig excluded) with public_key_b64.",
            },
            "self_check": {
                "entry_hash_ok": self._leaf(entry["payload"]).hex()[:16] == entry["seal"],
                "chain_intact": self.verify_chain()["tamper_evident"],
                "chain_height": self.height,
                "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
        }

    def root_hex(self) -> str | None:
        with self._lock:
            return self._root_hex()

    def _root_hex(self) -> str | None:
        self._rebuild_tree()
        return self._tree.root.hex() if self._tree else None


def receipt_kind(cfg: ShieldConfig) -> str:  # tiny helper for console wiring
    return "byoai.receipt.v2"


# Policy files written before privacy-first carry no version. The old UI saved
# its own default ("observe") into them, so a stored "observe" there is not a
# choice anyone made: those files are read as privacy-first.
POLICY_VERSION = 2


def default_policy() -> dict:
    """Privacy-first defaults: redact before sending, keep no message text,
    30 days of history, notice on."""
    return {
        "policy_version": POLICY_VERSION,
        "mode": "redact",
        "apps": {"claude": True, "chatgpt": False, "gemini": False,
                 "copilot": False, "github_copilot": False, "mistral": False,
                 "deepseek": False, "groq": False, "openrouter": False,
                 "together": False, "gemini_api": False},
        "keep_text": False,
        "retention_days": 30,
        "notice": True,
        # What each tier does on a hit: block | warn | redact | log. The mode
        # above is the master switch ("observe" logs everything).
        "actions": dict(DEFAULT_ACTIONS),
        # What happens to a file uploaded to each app: allow | warn | block.
        # Text-like files are also read by the rules; see inspect_file.
        "files": {a: "allow" for a in APP_LABEL},
        # What Coriqo may receive about activity: "seal" (integrity only),
        # "daily" totals, or per-message "events". Only a signed managed
        # policy moves it; see byoai.integrations.shield_sync.
        "sync": "seal",
    }


def merge_policy(disc: dict) -> dict:
    p = {**default_policy(), **disc}
    p["apps"] = {**default_policy()["apps"], **(disc.get("apps") or {})}
    p["actions"] = clean_actions(disc.get("actions"))
    p["files"] = clean_files(disc.get("files"))
    return p


def load_policy(cfg: ShieldConfig) -> dict:
    """The effective policy: the local file with any managed, locked keys
    overridden by the signed policy from Coriqo. Both the proxy's own checks
    and the console read this, not the local file directly, so managed mode
    can't be bypassed by only patching one caller."""
    local = read_policy(cfg.policy_path)
    # Only a signed managed policy moves how much activity leaves the device:
    # a value in the local file (hand-edited, or left over from a policy that
    # was later revoked) is ignored.
    local["sync"] = "seal"
    managed = load_managed_policy(cfg.managed_policy_path)
    if not managed:
        return local
    doc = managed["envelope"]["document"]
    policy = doc.get("policy")
    locked = doc.get("locked") or []
    if policy is None or not locked:
        return local  # unmanaged (policy: null), or nothing is actually locked
    out = dict(local)
    for key in locked:
        if key == "apps" and isinstance(policy.get("apps"), dict):
            out["apps"] = {**out.get("apps", {}), **policy["apps"]}
        elif key in policy:
            out[key] = policy[key]
    return out


# --------------------------------------------------------------- managed mode
#
# Signed managed policy: an MSP sets policy once in Coriqo and it lands on
# every device. Trust comes from an auditable, open agent — this module
# verifies the signed envelope and stores it;
# :mod:`byoai.integrations.shield_publish` polls for it and pins the
# signing key. Locked keys in the stored document take priority over the
# device's own settings (see :func:`load_policy`); everything else about the
# device — capture, redaction, sealing — is unaffected by whether a device is
# managed at all.

# The settings a managed policy is validated for (see _validate_managed_policy).
# It is a reference list, not a gate: load_policy applies every key a signed
# document names in ``locked``, and Coriqo's own list (shield_server.policy)
# offers mode, apps, keep_text, retention_days and notice. ``actions`` and
# ``files`` are not lockable yet.
MANAGED_LOCKABLE_KEYS = ("mode", "apps", "keep_text", "retention_days", "notice",
                         "sync")


def load_managed_policy(path: Path | None = None) -> dict | None:
    """The last accepted managed-policy envelope, or ``None`` if this device
    has never received one or the file is missing/corrupt. Corrupt is treated
    the same as absent: a device that can't read its own managed state falls
    back to its local policy rather than refusing to serve anything."""
    path = path or MANAGED_POLICY_PATH
    try:
        data = json.loads(path.read_text())
    except Exception:  # noqa: BLE001
        return None
    if isinstance(data, dict) and isinstance((data.get("envelope") or {}).get("document"), dict):
        return data
    return None


def managed_summary(managed: dict | None) -> dict | None:
    """The shape ``GET /api/policy`` reports as ``managed`` (minus ``error``,
    which the caller adds from the publisher's last poll). ``None`` when this
    device holds no managed state at all."""
    if not managed:
        return None
    doc = managed["envelope"]["document"]
    active = doc.get("policy") is not None
    return {
        "by": doc.get("managed_by") if active else None,
        "version": doc.get("version"),
        "locked": list(doc.get("locked") or []) if active else [],
        "fetched_at": managed.get("fetched_at"),
    }


def _validate_managed_policy(policy: dict) -> None:
    """Same validation :func:`apply_policy_update` runs on a local edit — a
    managed device must not be able to be handed a policy the UI itself would
    have refused to save."""
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    if "mode" in policy and policy["mode"] not in ("observe", "redact", "block"):
        raise ValueError("mode must be observe, redact or block")
    if "apps" in policy:
        apps = policy["apps"]
        if not isinstance(apps, dict) or not all(isinstance(v, bool) for v in apps.values()):
            raise ValueError("apps must map app names to true/false")
    if "retention_days" in policy and policy["retention_days"] not in RETENTION_CHOICES:
        raise ValueError("retention_days must be one of " + ", ".join(map(str, RETENTION_CHOICES)))
    for key in ("keep_text", "notice"):
        if key in policy and not isinstance(policy[key], bool):
            raise ValueError(f"{key} must be true or false")
    if "sync" in policy and policy["sync"] not in SYNC_LEVELS:
        raise ValueError("sync must be " + ", ".join(SYNC_LEVELS[:-1])
                         + " or " + SYNC_LEVELS[-1])


def apply_managed_envelope(envelope: dict, *, tenant_slug: str | None, device_id: str,
                           public_key: str | None, path: Path | None = None) -> dict:
    """Verify a signed policy envelope from Coriqo and, if valid, store it as
    this device's managed policy. Never raises — every refusal reason comes
    back as ``{"ok": False, "error": ...}``, and on refusal the previously
    stored policy (if any) is left exactly as it was: fail-safe, never
    fail-open.

    Checks, in order: well-formed envelope; the signature verifies over
    ``canonicalize(document)`` with ``public_key`` (a key this device has
    pinned — an envelope signed with any other ``key_id`` is refused before
    this function is even called, since the caller wouldn't have a
    ``public_key`` to hand it); ``tenant_slug`` matches this device's own
    tenant; ``device_id`` is null (tenant default) or this device's own;
    ``version`` is a newer integer than whatever is currently stored
    (rollback refused); and, if ``policy`` isn't null, that it passes the same
    validation a local Settings edit would.

    Coriqo signs with its own server key, not a device key: ``signature`` is
    lowercase hex of the raw 64-byte Ed25519 signature (no ``ed25519:``
    prefix, unlike :meth:`DeviceKey.sign`), and ``public_key`` (however it was
    pinned — see :mod:`byoai.integrations.shield_publish`) is always stored
    and passed in here as lowercase hex of the raw 32-byte public key.
    """
    path = path or MANAGED_POLICY_PATH
    if not isinstance(envelope, dict):
        return {"ok": False, "error": "malformed envelope"}
    doc = envelope.get("document")
    sig = envelope.get("signature")
    if not isinstance(doc, dict) or not isinstance(sig, str) or not sig:
        return {"ok": False, "error": "malformed envelope"}
    if not public_key:
        return {"ok": False, "error": "policy signed with an unknown key"}
    from byoai.recorder.canonical import canonicalize
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        raw_pub = bytes.fromhex(public_key)
        raw_sig = bytes.fromhex(sig)
        pub = Ed25519PublicKey.from_public_bytes(raw_pub)
        pub.verify(raw_sig, canonicalize(doc))
        sig_ok = True
    except (ValueError, TypeError, InvalidSignature):
        sig_ok = False
    except Exception:  # noqa: BLE001 - a malformed key/sig is a refusal, not a crash
        sig_ok = False
    if not sig_ok:
        return {"ok": False, "error": "bad signature"}
    if doc.get("tenant_slug") != tenant_slug:
        return {"ok": False, "error": "policy for a different tenant"}
    doc_device = doc.get("device_id")
    if doc_device is not None and doc_device != device_id:
        return {"ok": False, "error": "policy for a different device"}
    new_version = doc.get("version")
    if not isinstance(new_version, int) or isinstance(new_version, bool):
        return {"ok": False, "error": "malformed policy version"}
    current = load_managed_policy(path)
    current_version = -1
    if current:
        cur_v = (current["envelope"]["document"] or {}).get("version")
        if isinstance(cur_v, int) and not isinstance(cur_v, bool):
            current_version = cur_v
    if new_version <= current_version:
        return {"ok": False, "error": "rollback refused"}
    policy = doc.get("policy")
    if policy is not None:
        try:
            _validate_managed_policy(policy)
        except ValueError as exc:
            return {"ok": False, "error": str(exc)}
    atomic_write_private(path, json.dumps({
        "envelope": envelope,
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }, indent=1))
    return {"ok": True, "error": None}


def upgrade_policy(disc: dict) -> dict:
    """Bring a pre-privacy-first file up to the privacy-first defaults: redact
    (block stays block, it is stricter) and no stored text. App toggles and
    other choices are kept."""
    version = disc.get("policy_version")
    if isinstance(version, int) and version >= POLICY_VERSION:
        return disc  # current, or written by a newer Shield: leave it alone
    out = dict(disc)
    if out.get("mode") != "block":
        out["mode"] = "redact"
    out["keep_text"] = False
    out["policy_version"] = POLICY_VERSION
    return out


def read_policy(path: Path | None) -> dict:
    if path and path.exists():
        try:
            return merge_policy(upgrade_policy(json.loads(path.read_text())))
        except Exception:
            return default_policy()
    return default_policy()


def is_less_private(policy: dict) -> bool:
    """Record-only mode or stored previews: weaker than the default."""
    return policy.get("mode") == "observe" or bool(policy.get("keep_text"))


# The capture proxy writes this next to the ledger while it runs (pid and
# listen port) and removes it on a clean stop. Shield reads it to know whether
# anything is checking traffic right now.
PROXY_ALIVE_FILE = "shield_proxy.alive"


def proxy_alive_path(ledger: Path) -> Path:
    return Path(ledger).parent / PROXY_ALIVE_FILE


def _pid_running(pid: int) -> bool:
    import os
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by someone else
    except OSError:
        return False
    return True


def _port_open(port: int) -> bool:
    """Something is listening on 127.0.0.1:port."""
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def read_proxy_alive(ledger: Path) -> dict | None:
    """The running proxy's marker, or None when no proxy is running (no file,
    unreadable, its process is gone after a crash, or nothing listens on its
    port). The port check matters: after a crash macOS can hand the old pid to
    another process, and a pid check alone would then claim protection."""
    try:
        data = json.loads(proxy_alive_path(ledger).read_text())
        pid = int(data.get("pid"))
    except (OSError, ValueError, TypeError, AttributeError):
        return None
    if pid <= 0 or not _pid_running(pid):
        return None
    port = data.get("port")
    if isinstance(port, int) and not _port_open(port):
        return None
    return data


def macos_https_proxy() -> tuple[bool, int | None] | None:
    """(enabled, port) of this Mac's system HTTPS proxy from ``scutil
    --proxy``, or None when that can't be read (not a Mac, scutil missing)."""
    import subprocess
    import sys
    if sys.platform != "darwin":
        return None
    try:
        out = subprocess.run(["scutil", "--proxy"], capture_output=True,
                             text=True, timeout=3, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    fields = dict(m.groups() for m in re.finditer(r"(\w+)\s*:\s*(\S+)", out))
    port = fields.get("HTTPSPort")
    return (fields.get("HTTPSEnable") == "1",
            int(port) if port and port.isdigit() else None)


def protection_state(cfg: ShieldConfig, *, system_proxy=macos_https_proxy) -> dict:
    """Is Shield checking traffic right now? Read from what is running, not
    from what was configured.

    Protecting means all of: the capture proxy is running; this Mac's system
    HTTPS proxy points at it (when that can be read); the policy redacts or
    blocks (record-only watches but checks nothing); and at least one app it
    can read is switched on. The browser extension does not count: it records
    that a chat happened, it never reads or changes what is sent.

    ``reasons`` are short machine codes for Coriqo, empty when protecting."""
    policy = load_policy(cfg)
    reasons: list[str] = []
    alive = read_proxy_alive(cfg.ledger)
    if alive is None:
        reasons.append("capture_stopped")
    else:
        sysproxy = system_proxy()
        if sysproxy is not None:
            enabled, port = sysproxy
            want = alive.get("port")
            if not enabled or (want and port and int(want) != port):
                reasons.append("proxy_off")
    if policy.get("mode") == "observe":
        reasons.append("policy_monitor_only")
    if not any(policy["apps"].get(app) for app in COVERED_APPS):
        reasons.append("no_apps_enabled")
    return {"protecting": not reasons, "reasons": reasons,
            "mode": policy.get("mode")}


def apply_policy_update(policy: dict, payload: dict) -> dict:
    """Validated merge of a Settings write. Raises ValueError naming the first
    bad field; nothing is saved in that case.

    A change that makes Shield less private than it is now (record-only mode,
    or keeping previews) must carry ``"acknowledge": "less_private"``: the
    screen asks first, and a script can't weaken it by accident."""
    out = merge_policy(policy)
    if "mode" in payload:
        if payload["mode"] not in ("observe", "redact", "block"):
            raise ValueError("mode must be observe, redact or block")
        out["mode"] = payload["mode"]
    if "apps" in payload:
        if not isinstance(payload["apps"], dict) or not all(
                isinstance(v, bool) for v in payload["apps"].values()):
            raise ValueError("apps must map app names to true/false")
        for app, on in payload["apps"].items():
            if on and app not in COVERED_APPS and app not in INPUT_ONLY_APPS:
                raise ValueError(f"Shield can't read {APP_LABEL.get(app, app)} "
                                 "messages yet, so it can't be turned on")
        out["apps"] = {**out["apps"], **payload["apps"]}
    if "actions" in payload:
        acts = payload["actions"]
        if not isinstance(acts, dict) or not all(
                t in DEFAULT_ACTIONS and a in ACTIONS for t, a in acts.items()):
            raise ValueError("actions must map secret, pii or flag to "
                             + ", ".join(ACTIONS))
        out["actions"] = {**clean_actions(out.get("actions")), **acts}
    if "files" in payload:
        fl = payload["files"]
        if not isinstance(fl, dict) or not all(
                a in APP_LABEL and v in FILE_ACTIONS for a, v in fl.items()):
            raise ValueError("files must map app names to " + ", ".join(FILE_ACTIONS))
        out["files"] = {**clean_files(out.get("files")), **fl}
    for key in ("keep_text", "notice"):
        if key in payload:
            if not isinstance(payload[key], bool):
                raise ValueError(f"{key} must be true or false")
            out[key] = payload[key]
    if "retention_days" in payload:
        if payload["retention_days"] not in RETENTION_CHOICES:
            raise ValueError("retention_days must be one of "
                             + ", ".join(map(str, RETENTION_CHOICES)))
        out["retention_days"] = payload["retention_days"]
    weakened = ((out["mode"] == "observe" and policy.get("mode") != "observe")
                or (out["keep_text"] and not policy.get("keep_text"))
                or any(ACTIONS.index(a) < ACTIONS.index(
                    clean_actions(policy.get("actions"))[t])
                    for t, a in out["actions"].items())
                or any(FILE_ACTIONS.index(v) < FILE_ACTIONS.index(
                    clean_files(policy.get("files"))[a])
                    for a, v in out["files"].items()))
    if weakened and payload.get("acknowledge") != "less_private":
        raise ValueError("This makes Shield less private than it is now; "
                         "confirm it to save (acknowledge: less_private)")
    return out


def _row_date(row: dict) -> str:
    return (row.get("wall_clock") or "")[:10]


def _cutoff(days: int) -> str:
    return time.strftime("%Y-%m-%d", time.localtime(time.time() - days * 86400))


def _read_rows(ledger: Path) -> list[dict]:
    try:
        lines = ledger.read_text().splitlines()
    except OSError:
        return []
    rows = []
    for line in lines:
        try:
            rows.append(json.loads(line))
        except ValueError:
            continue
    return rows


def privacy_report(cfg: ShieldConfig, seals: "SealChain | None" = None) -> dict:
    """Facts for the "What Shield keeps" panel, read from disk, not assumed."""
    policy = load_policy(cfg)
    rows = _read_rows(cfg.ledger)
    cutoff = _cutoff(policy["retention_days"])
    dates = [d for d in (_row_date(r) for r in rows) if d]
    sealed_with_text = 0
    if seals is not None:
        sealed_with_text = seals.count_with_text()
    return {
        "ledger_rows": len(rows),
        "rows_with_text": sum(1 for r in rows
                              if any(r.get(f) for f in TEXT_FIELDS)),
        "oldest_row": min(dates) if dates else None,
        "rows_past_retention": sum(1 for d in dates if d < cutoff),
        "sealed_with_text": sealed_with_text,
        "keep_text": policy["keep_text"],
        "retention_days": policy["retention_days"],
        "mode": policy["mode"],
        "less_private": is_less_private(policy),
        # "Where your data lives": real paths, not a description of them.
        "ledger_path": str(cfg.ledger.resolve()),
        "seal_path": str(cfg.seal_path.resolve()),
        "device_id": seals._key.device_id if seals is not None else None,
    }


def scrub_ledger(cfg: ShieldConfig, key_path: Path = FINGERPRINT_KEY, *,
                 scrub_text: bool = True) -> dict:
    """Replace stored message text with fingerprint + length, and delete rows
    past retention (``scrub_text=False``: retention only, as at startup). Holds the ledger lock for the whole rewrite so the proxy
    can't append into a file that is about to be replaced."""
    import os
    policy = load_policy(cfg)
    cutoff = _cutoff(policy["retention_days"])
    scrubbed = deleted = 0
    if not cfg.ledger.exists():
        return {"scrubbed": 0, "deleted": 0, "ledger_rows": 0}
    with cfg.ledger.open("r+") as fh:
        with file_lock(fh):
            kept: list[str] = []
            for line in fh.read().splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if _row_date(row) and _row_date(row) < cutoff:
                    deleted += 1
                    continue
                text = next((row[f] for f in TEXT_FIELDS
                             if isinstance(row.get(f), str) and row[f]), None)
                if text is not None and scrub_text:
                    if not row.get("flags"):
                        row["flags"] = [f"{t}:{r}" for t, r, _ in flags_for(text)]
                    row["text_hmac"] = fingerprint(text, key_path)
                    for f in TEXT_FIELDS:
                        row.pop(f, None)
                    row["scrubbed"] = True
                    scrubbed += 1
                kept.append(json.dumps(row, default=str, sort_keys=True))
            # Rewrite in place, not via a temp file + rename: an appender
            # waiting on this lock holds the same inode and, being O_APPEND,
            # writes after our new end. A rename would leave it writing into
            # the unlinked old file.
            fh.seek(0)
            fh.write("\n".join(kept) + ("\n" if kept else ""))
            fh.truncate()
            fh.flush()
            os.fsync(fh.fileno())
    return {"scrubbed": scrubbed, "deleted": deleted, "ledger_rows": len(kept)}


def save_policy(cfg: ShieldConfig, p: dict) -> None:
    if cfg.policy_path:
        atomic_write_private(cfg.policy_path, json.dumps(p, indent=1))


# --------------------------------------------------------------------- feed


def _flags_from_row(r: dict) -> list[tuple[str, str, str]]:
    out = []
    for f in r.get("flags") or []:
        tier, _, rule = str(f).partition(":")
        # The console's tag colours know agent|high|pii|conduct; the rule
        # table's secret and flag tiers map onto high and agent.
        tier = {"secret": "high", "flag": "agent"}.get(tier, tier)
        if rule:
            out.append((tier if tier in ("high", "pii", "agent", "conduct")
                        else "pii", rule, ""))
    return out


def _chars(n) -> str:
    try:
        n = int(n or 0)
    except (TypeError, ValueError):
        n = 0
    return "1 character" if n == 1 else f"{n:,} characters"


def _as_list(v) -> list[str]:
    if isinstance(v, list):
        return [str(x) for x in v]
    if isinstance(v, str) and v:
        return v.split(",")
    return []


def _tier(item: dict) -> str:
    if item.get("status") == "blocked" or any(
            f["tier"] == "high" for f in item["flags"]):
        return "bad"
    if any(f["tier"] in ("pii", "conduct") for f in item["flags"]):
        return "warn"
    return "ok"


class Interaction(dict):
    """One user-visible activity event, already flag-evaluated."""


def _stat_sig(path) -> tuple:
    if path is None:
        return (0, 0)
    try:
        st = Path(path).stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return (0, 0)


class Feed:
    """Turns ledger rows into shield interactions and re-flags replies."""

    def __init__(self, cfg: ShieldConfig) -> None:
        self.cfg = cfg
        self.seals = SealChain(cfg)
        self.items: deque = deque(maxlen=cfg.max_interactions)
        self._offset = 0
        self._policy = load_policy(cfg)
        self._scanned = False
        self._poll_lock = threading.Lock()
        self._seen_rows: dict[str, int] = {}
        self._current_id = ""
        # Rule hits for a browser row from an extension before 0.6, which
        # shipped length only: recorded clean. Newer rows carry their own
        # rule names (`flags`), found in the page.
        self.BROWSER_FLAGS: list[tuple[str, str, str]] = []

    def scan_initial(self) -> int:
        self._scanned = True
        self._policy = load_policy(self.cfg)
        try:
            lines = self.cfg.ledger.read_text().splitlines()
        except OSError:
            return 0
        with self.seals.batch():
            for x in lines:
                try:
                    self._absorb(json.loads(x))
                except ValueError:
                    continue
        self._offset = len(lines)
        return len(self.items)

    def resync(self) -> None:
        """After a scrub rewrote the ledger, continue from its new end."""
        try:
            self._offset = len(self.cfg.ledger.read_text().splitlines())
        except OSError:
            self._offset = 0

    def poll(self) -> int:
        # A watcher thread can start before the first scan; reading from
        # offset 0 then would absorb (and seal) every row twice.
        with self._poll_lock:
            return self._poll_locked()

    def _poll_locked(self) -> int:
        if not self._scanned:
            return 0
        # Idle is the common case: two stat() calls, no read, no parse.
        sig = (_stat_sig(self.cfg.ledger), _stat_sig(self.cfg.policy_path))
        if sig == getattr(self, "_poll_sig", None):
            return 0
        self._policy = load_policy(self.cfg)
        try:
            lines = self.cfg.ledger.read_text().splitlines()
        except OSError:
            return 0    # not remembered as seen: the next poll reads it again
        self._poll_sig = sig
        if len(lines) < self._offset:  # rewritten under us (scrub/retention)
            self._offset = len(lines)
            return 0
        if len(lines) == self._offset:
            return 0
        new = [l for l in lines[self._offset:] if l.strip()]
        self._offset = len(lines)
        with self.seals.batch():
            for l in new:
                try:
                    self._absorb(json.loads(l))
                except Exception:
                    continue
        return len(new)

    def _row_id_for(self, r: dict) -> str:
        """The same ledger row gets the same interaction id on every restart,
        so sealing it again is a no-op. Text and scrub markers are left out of
        the key: a scrub rewrites them, and must not make the row look new."""
        skip = set(TEXT_FIELDS) | {"text_hmac", "scrubbed", "flags"}
        key = json.dumps({k: v for k, v in r.items() if k not in skip},
                         sort_keys=True, default=str)
        n = self._seen_rows[key] = self._seen_rows.get(key, 0) + 1
        return hashlib.sha256(f"{key}#{n}".encode()).hexdigest()[:10]

    def _absorb(self, r: dict) -> None:
        self._current_id = self._row_id_for(r)
        kind = r.get("kind", "")
        wall = r.get("wall_clock", "")
        ts = wall.split()[-1] if wall else ""
        date = wall[:10] or time.strftime("%Y-%m-%d")
        keep_text = bool(self._policy.get("keep_text"))
        if kind in ("desktop.chat.request", "desktop.verdict.denied"):
            app = r.get("app") or "claude"
            label = APP_LABEL.get(app, app)
            legacy = r.get("prompt") if isinstance(r.get("prompt"), str) else None
            if legacy is not None and not legacy:
                return  # pre-PF row with nothing typed (a retry, a ping)
            flags_box = (_flags_from_row(r) if legacy is None
                         else flags_for(legacy))
            # Pre-PF rows logged prompt_chars as the whole wire body and kept a
            # 200-char cut of the prompt, so neither is the message length.
            chars = r.get("chars") if legacy is None else None
            shown = r.get("preview") if keep_text else None
            if shown is None and keep_text and legacy:
                shown = redact(legacy)[:200]
            blocked = kind == "desktop.verdict.denied"
            verb = shown or (f"Message to {label} stopped on this Mac"
                             if blocked else
                             f"Message to {label} · {_chars(chars)}"
                             if chars is not None else
                             f"Message to {label} · sent before privacy settings")
            self._add(source="desktop", surface=f"{label} · desktop", ts=ts,
                      verb=verb, date=date, flags_box=flags_box,
                      status="blocked" if blocked else "answered",
                      verdict=r.get("verdict"), text_hmac=r.get("text_hmac"),
                      chars=chars, redactions=r.get("redactions"))
        elif kind == "desktop.chat.response":
            self._attach_reply(r)
        elif kind in BROWSER_KINDS:
            app = r.get("app") or "claude"
            label = APP_LABEL.get(app, app)
            if kind == "browser.chat.reply":
                self._attach_tools(r, label)
                return
            if kind == "browser.chat.attachment":
                self._absorb_file(r, "browser", date, ts)
                return
            if kind in ("browser.health.unmatched", "browser.health.core_missing"):
                return  # facts for the ledger and seal, not a message row
            wire = r.get("wire") if isinstance(r.get("wire"), str) else None
            ts_raw = r.get("sent_at") or ""
            # Extension rows carry their own ISO timestamp; fall back to now.
            try:
                when = ts_raw.replace("Z", "+00:00")
                import datetime as _dt
                parsed = _dt.datetime.fromisoformat(when)
                ts = parsed.strftime("%H:%M:%S.%f")
                ts = ts[:ts.index('.')] if '.' in ts else ts
                date = parsed.strftime("%Y-%m-%d")
                # sent_at is UTC; every other row's time is this Mac's local
                # time, and so is what the person reads. Only the shown time
                # changes: the seal keeps the UTC one above, since a changed
                # payload would seal every earlier browser row a second time.
                local = parsed.astimezone() if parsed.tzinfo else parsed
                shown_ts, shown_date = local.strftime("%H:%M:%S"), local.strftime("%Y-%m-%d")
            except ValueError:
                shown_ts, shown_date = ts, date
            status = ("answered" if r.get("ok") else "failed"
                      if kind == "browser.chat.status" and "ok" in r
                      else "answered")
            # Browser sends stop here only for a fetch that failed; statuses
            # attach to the latest browser request from the same app.
            if kind == "browser.chat.status":
                for it in self.items:             # newest first
                    if it["source"] == "browser" and it["surface"].startswith(label):
                        if status == "failed":
                            it["status"] = "failed"
                            it["tier"] = _tier(it)
                        break
                return
            first = self._is_first_browser_send(label)
            blocked = r.get("verdict") == "blocked"
            verb = (f"Message to {label} stopped in this browser" if blocked
                    else f"First message to {label} in this browser"
                    if first else f"Message to {label}")
            # Rows from extensions before 0.6 carry no rule names: nothing
            # was checked, which is not the same as nothing matching.
            flags_box = (_flags_from_row(r) if isinstance(r.get("flags"), list)
                         else self.BROWSER_FLAGS)
            self._add(source="browser", surface=f"{label} · browser", ts=ts,
                      verb=verb, date=date, flags_box=flags_box,
                      status="blocked" if blocked else status,
                      verdict=r.get("verdict"), text_hmac=r.get("text_hmac"),
                      chars=r.get("chars"), redactions=r.get("redactions"))
            self.items[0]["ts"], self.items[0]["date"] = shown_ts, shown_date
            self.items[0]["_send_id"] = r.get("send_id")
        elif kind == "desktop.chat.attachment":
            self._absorb_file(r, "desktop", date, ts)
        elif kind == "tool.call":
            ident = r.get("identity") or {}
            tool = r.get("tool") or "execute"
            legacy = r.get("input_preview")
            legacy = legacy if isinstance(legacy, str) else None
            flags_box = (_flags_from_row(r) if legacy is None
                         else flags_for(legacy))
            chars = r.get("chars") or r.get("input_chars") or 0
            shown = r.get("preview") if keep_text else None
            if shown is None and keep_text and legacy:
                shown = redact(legacy)
            self._add(source="mcp",
                      surface=ident.get("client_name") or "MCP client", ts=ts,
                      verb=shown or f"{tool} call · {_chars(chars)}",
                      date=date, status="running", tool=tool, identity=ident,
                      flags_box=flags_box, text_hmac=r.get("text_hmac"),
                      chars=chars)
            self.items[0]["call_id"] = r.get("call_id")
        elif kind in ("tool.result", "tool.error"):
            # Seal on completion, so the seal binds the outcome too (and a
            # finished row always carries a seal).
            self.close_seal(r.get("tool"), r.get("identity") or {},
                            r.get("usage") or {}, r.get("latency_ms"),
                            call_id=r.get("call_id"),
                            status="failed" if kind == "tool.error" else "answered")

    def _absorb_file(self, r: dict, source: str, date: str, ts: str) -> None:
        """A file that went (or was stopped) on its way to an AI app. Only rows
        that carry a SHA-256 are shown and sealed; older attachment rows stay
        ledger-only, as before."""
        sha = r.get("sha256")
        if not (isinstance(sha, str) and _SHA256.fullmatch(sha)):
            return
        app = r.get("app") or "claude"
        label = APP_LABEL.get(app, app)
        nbytes = r.get("bytes") if isinstance(r.get("bytes"), int) else None
        file = {k: r[k] for k in ("mime", "bytes", "sha256", "name_hash",
                                  "scanned", "rules_version") if r.get(k) is not None}
        verdict = r.get("verdict") if isinstance(r.get("verdict"), str) else None
        blocked = verdict == "blocked"
        self._add(source=source, surface=f"{label} \u00b7 {source}", ts=ts,
                  verb=(f"File to {label} stopped on this Mac" if blocked and source == "desktop"
                        else f"File to {label} stopped in this browser" if blocked
                        else f"File to {label}"
                        + (f" \u00b7 {nbytes:,} bytes" if nbytes is not None else "")),
                  date=date, flags_box=_flags_from_row(r),
                  status="blocked" if blocked else "answered", verdict=verdict,
                  file=file)

    def _is_first_browser_send(self, label: str) -> bool:
        return not any(
            it["source"] == "browser" and it["surface"].startswith(label)
            for it in self.items)

    def _add(self, *, source, surface, ts, verb, date, status="answered",
             tool=None, identity=None, flags_box, verdict=None, text_hmac=None,
             chars=None, redactions=None, file=None):
        item = {
            "id": self._current_id, "source": source, "surface": surface,
            "ts": ts, "date": date, "verb": redact(verb), "status": status,
            "tool": tool, "identity": identity or {},
            "flags": [{"tier": t, "rule": ru} for t, ru, _ in flags_box],
            "seal": "", "usage": {}, "latency_ms": None,
            "verdict": verdict, "chars": chars,
            "redactions": _as_list(redactions), "reply": None,
            "tools": [], "sources": None,
        }
        if file:
            item["file"] = file
        item["tier"] = _tier(item)
        # The seal binds what happened, not what was said: the message
        # fingerprint and length stand in for its text unless the admin
        # opted into previews (then the redacted preview is what's shown).
        item["_seal_payload"] = {
            "interaction": item["id"], "date": date, "ts": ts,
            "surface": surface, "status": status, "verdict": verdict,
            "flags": [f["tier"] + ":" + f["rule"] for f in item["flags"]],
            "text_hmac": text_hmac, "chars": chars,
            "identity": item["identity"], "usage": {},
        }
        if file:
            item["_seal_payload"]["file"] = file
        if self._policy.get("keep_text"):
            item["_seal_payload"]["text_redacted"] = item["verb"][:400]
        item["seal"] = (self.seals.stamp(item["_seal_payload"])
                        if item["status"] != "running" else "")
        # tool.call rows are resealed when their result lands (Feed.close_seal)
        item["_pending"] = item["status"] == "running"
        self.items.appendleft(item)

    def close_seal(self, tool: str | None, ident: dict, usage: dict,
                   latency_ms, *, call_id: str | None = None,
                   status: str = "answered") -> None:
        """Reseal the matching running tool interaction once its result lands,
        so the seal binds the full interaction outcome, not the request only.

        Matched by ``call_id`` when the gateway sent one. Rows without it fall
        back to the *oldest* running call for the same tool and user; items
        are newest-first, and picking the newest would hand call 1's result to
        call 2 whenever two calls overlap."""
        running = [it for it in self.items
                   if it["source"] == "mcp" and it.get("status") == "running"]
        if call_id:
            match = next((it for it in running if it.get("call_id") == call_id),
                         None)
        else:
            match = next((it for it in reversed(running)
                          if it["tool"] == tool
                          and (it["identity"] or {}).get("user_id")
                          == ident.get("user_id")), None)
        if match is None:
            return
        match["status"] = status
        match["response_stream"] = tool == "execute_stream"
        match["usage"] = usage or {}
        match["latency_ms"] = latency_ms
        match["tier"] = _tier(match)
        payload = {**match["_seal_payload"], "status": status,
                   "usage": match["usage"]}
        match["seal"] = self.seals.stamp(payload)
        match["_pending"] = False

    def _attach_tools(self, r: dict, label: str) -> None:
        """The tools an AI app ran for a browser reply land on the message it
        answers, and are sealed with it: a new seal over the message's payload
        plus the tool names and source count. The send id matches them, since
        a reply can finish after a newer send (another tab, a quick second
        message); without one, the latest message to that app is taken."""
        tools = [t for t in r.get("tools") or []
                 if isinstance(t, str) and _TOOL_NAME.fullmatch(t)]
        if not tools:
            return
        send_id = r.get("send_id")
        for it in self.items:                     # newest first
            if it["source"] != "browser" or not it["surface"].startswith(label):
                continue
            if send_id and it.get("_send_id") != send_id:
                continue
            it["tools"] = list(dict.fromkeys([*it["tools"], *tools]))
            if isinstance(r.get("sources"), int):
                it["sources"] = (it["sources"] or 0) + r["sources"]
            it["seal"] = self.seals.stamp({**it["_seal_payload"], "tools": it["tools"],
                                           "sources": it["sources"]})
            break

    def _attach_reply(self, r: dict) -> None:
        """Reply-side rule hits land on the latest desktop message from the
        same app; the reply's text is never shown or sealed."""
        app = r.get("app") or "claude"
        flags = _flags_from_row(r) if r.get("flags") is not None else [
            (reply_tier(ru), ru, "") for ru, p in REPLY_RULES
            if isinstance(r.get("preview"), str) and p.search(r["preview"])]
        for it in self.items:
            if it["source"] != "desktop" or it["reply"] is not None:
                continue
            if not it["surface"].startswith(APP_LABEL.get(app, app)):
                continue
            it["reply"] = f"Reply · {_chars(r.get('chars'))}" if r.get("chars") \
                else "Reply received"
            if flags:
                seen = {f["rule"] for f in it["flags"]}
                it["flags"] += [{"tier": t, "rule": ru} for t, ru, _ in flags
                                if ru not in seen]
                it["tier"] = _tier(it)
                it["seal"] = self.seals.stamp({
                    **it["_seal_payload"],
                    "flags": [f["tier"] + ":" + f["rule"] for f in it["flags"]],
                    "reply_hmac": r.get("text_hmac"),
                })
            break

    def counts(self) -> dict:
        counts = {"checked": len(self.items), "caught": 0, "high_risk": 0}
        for it in self.items:
            if it["tier"] == "warn":
                counts["caught"] += 1
            elif it["tier"] == "bad":
                counts["high_risk"] += 1
        return counts


# --------------------------------------------------------------------- server


# ------------------------------------------------------------ request guard
#
# The shield listens on localhost, but every web page the user opens can send
# requests to localhost too. Without these checks a page could POST
# {"mode": "observe", "acknowledge": "less_private"} and quietly weaken
# Shield, rewrite the Coriqo connection, or write fake rows into the sealed
# ledger through /api/browser. A page can't forge Origin or Host, and a
# cross-site JSON POST needs a CORS preflight this server never approves.

LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")
EXTENSION_SCHEMES = ("chrome-extension://", "moz-extension://")
BROWSER_KINDS = ("browser.chat.request", "browser.chat.status", "browser.chat.reply",
                 "browser.chat.attachment", "browser.health.unmatched",
                 "browser.health.core_missing")

# Hosts the browser extension watches. The relay covers the whole page even
# when the send itself bypassed fetch, so a bare host must classify like the
# tagged capture does.
_APP_TAG_FOR_HOST = {
    "claude.ai": "claude",
    "chatgpt.com": "chatgpt",
    "chat.openai.com": "chatgpt",
    "gemini.google.com": "gemini",
    "copilot.microsoft.com": "copilot",
}


def _host_name(value: str) -> str:
    value = (value or "").strip().lower()
    if value.startswith("["):
        return value[: value.find("]") + 1]
    return value.split(":", 1)[0]


def request_problem(method: str, path: str, headers) -> str | None:
    """Why a request must be refused, or None. ``headers`` is anything with
    ``.get`` (an HTTP message or a dict)."""
    import os
    from urllib.parse import urlsplit
    if _host_name(headers.get("Host", "")) not in LOCAL_HOSTS:
        return "Shield only answers requests addressed to localhost."
    if method != "POST":
        return None
    ctype = (headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
    if ctype != "application/json":
        return "Send JSON with Content-Type: application/json."
    origin = (headers.get("Origin") or "").strip()
    if path == "/api/browser":
        if not origin.startswith(EXTENSION_SCHEMES):
            return "Only the Shield browser extension can send browser rows."
        pinned = [x.strip() for x in os.environ.get(
            "BYOAI_SHIELD_EXTENSION_IDS", "").split(",") if x.strip()]
        if pinned and origin.split("://", 1)[1].rstrip("/") not in pinned:
            return "This browser extension isn't the one Shield was set up to trust."
        return None
    # Settings writes come from Shield's own page (or a local dev server
    # proxying to it), never from another site. "Localhost" alone is not the
    # rule: anything else on this Mac (a dev server, a daemon) is also a
    # localhost origin, and letting localhost:* write policy hands every
    # local process the keys. The Origin must name the same host:port this
    # request was addressed to — Shield's own page in production, the Vite
    # dev server proxying in dev.
    if origin:
        if urlsplit(origin).netloc.lower() != (headers.get("Host") or "").strip().lower():
            return "Settings can only be changed from Shield's own page."
    return None


# What a browser row may say about which rules fired: known rule names only,
# so the field can never carry text. Request rules, as the proxy records them.
_BROWSER_FLAGS = frozenset(
    [f"{tier}:{rule}" for tier, rules in (("secret", SECRET_RULES), ("pii", PII_RULES),
                                          ("flag", FLAG_RULES))
     for rule, _ in rules] + ["flag:oversize", "flag:unreadable", "flag:too_many_files"])
_BROWSER_VERDICT = re.compile(
    r"observe|redact|block|blocked|redacted\(\d{1,2}\)"
    r"|warned(?:\u2192|->)(?:sent|redacted|cancelled)")
# Names of tools an AI app ran for a reply ("web.run", "python"), as the
# extension reads them from the reply stream. A name, never text.
# What became of an uploaded file, as the extension records it.
_ATTACH_VERDICT = re.compile(
    r"allowed|blocked|cancelled|warned(?:\u2192|->)(?:uploaded|removed)")
# Which layer saw a send or a file: the extension's input gate (before the page
# gets it) or its network wrapper (the backstop).
_STAGES = frozenset({"input", "network"})
_GATE_REASONS = frozenset({"rewrite_failed", "send_retry_needed"})
_SHA256 = re.compile(r"[0-9a-f]{64}")
_NAME_HASH = re.compile(r"hmac-sha256:[0-9a-f]{64}")
_RULES_VERSION = re.compile(r"[0-9a-f]{12}")
_TOOL_NAME = re.compile(r"[A-Za-z0-9_.:-]{1,48}")
_MIME = re.compile(r"[A-Za-z0-9!#$&^_.+-]{1,60}/[A-Za-z0-9!#$&^_.+-]{1,80}")
_SEND_ID = re.compile(r"[A-Za-z0-9-]{8,64}")


def clean_browser_row(row: object) -> dict | None:
    """Keep only the fields a browser row is allowed to carry. Anything else,
    message text included, is dropped before it can reach the ledger."""
    if not isinstance(row, dict) or row.get("kind") not in BROWSER_KINDS:
        return None
    out: dict = {"kind": row["kind"],
                 "wall_clock": time.strftime("%Y-%m-%d %H:%M:%S")}
    app = row.get("app")
    # The relay publishes the host (`location.host`) because only it knows it
    # reliably; the fetch-patch path sends the app tag directly. Map known
    # hosts to apps so every path lands under the right surface.
    app = _APP_TAG_FOR_HOST.get(app) or app
    if app in APP_LABEL:
        out["app"] = app
    chars = row.get("chars")
    if isinstance(chars, int) and not isinstance(chars, bool) and 0 <= chars < 10_000_000:
        out["chars"] = chars
    for key, limit in (("wire", 60), ("sent_at", 40)):
        if isinstance(row.get(key), str):
            out[key] = row[key][:limit]
    # Dedupe key for the extension's retry batches. It's an opaque id —
    # random at the source, carries nothing about the user.
    if isinstance(row.get("row_id"), str) and 8 <= len(row["row_id"]) <= 64:
        out["row_id"] = row["row_id"]
    # Random per send, set in the page: ties a reply row to its request.
    if isinstance(row.get("send_id"), str) and _SEND_ID.fullmatch(row["send_id"]):
        out["send_id"] = row["send_id"]
    # Which layer saw it, and the id the input gate gave the send so its input
    # row and network row can be matched. Only request and attachment rows have them.
    if row["kind"] in ("browser.chat.request", "browser.chat.attachment"):
        stage = row.get("stage")
        if isinstance(stage, str) and stage in _STAGES:
            out["stage"] = stage
        if isinstance(row.get("gate_id"), str) and _SEND_ID.fullmatch(row["gate_id"]):
            out["gate_id"] = row["gate_id"]
        # Why a gate stopped a send that no rule named (the box couldn't be rewritten).
        reason = row.get("reason")
        if isinstance(reason, str) and reason in _GATE_REASONS:
            out["reason"] = reason
    # Set by the extension's page capture (content.js), which runs the same
    # rules before the message leaves the page. Anything not a known rule
    # name is dropped, not the row.
    if isinstance(row.get("flags"), list):
        out["flags"] = list(dict.fromkeys(
            f for f in row["flags"] if isinstance(f, str) and f in _BROWSER_FLAGS))
    if isinstance(row.get("redactions"), list):
        out["redactions"] = sorted({r for r in row["redactions"]
                                    if isinstance(r, str) and r in RULE_REDACT})
    verdict_re = (_ATTACH_VERDICT if row["kind"] == "browser.chat.attachment"
                  else _BROWSER_VERDICT)
    if isinstance(row.get("verdict"), str) and verdict_re.fullmatch(row["verdict"]):
        out["verdict"] = row["verdict"]
    if isinstance(row.get("tools"), list):
        out["tools"] = list(dict.fromkeys(
            t for t in row["tools"] if isinstance(t, str) and _TOOL_NAME.fullmatch(t)))[:12]
    sources = row.get("sources")
    if isinstance(sources, int) and not isinstance(sources, bool) and 0 <= sources <= 1000:
        out["sources"] = sources
    # browser.chat.attachment: that a file was attached, never what it holds.
    if isinstance(row.get("mime"), str) and _MIME.fullmatch(row["mime"]):
        out["mime"] = row["mime"].lower()
    nbytes = row.get("bytes")
    if isinstance(nbytes, int) and not isinstance(nbytes, bool) and 0 <= nbytes < 2**40:
        out["bytes"] = nbytes
    # File evidence: the hash and rule version the page computed, and a keyed
    # hash of the file name. A raw ``name`` is hashed here and then dropped;
    # it never reaches the ledger.
    if isinstance(row.get("sha256"), str) and _SHA256.fullmatch(row["sha256"]):
        out["sha256"] = row["sha256"]
    if isinstance(row.get("name"), str) and row["name"]:
        out["name_hash"] = fingerprint(row["name"][:512])
    elif isinstance(row.get("name_hash"), str) and _NAME_HASH.fullmatch(row["name_hash"]):
        out["name_hash"] = row["name_hash"]
    if isinstance(row.get("scanned"), bool):
        out["scanned"] = row["scanned"]
    # A page can't say "not read" about text: a text type of a size the rules
    # read is always recorded as scanned (and check-file then holds it to that).
    if (row["kind"] == "browser.chat.attachment"
            and mime_text_like(out.get("mime")) and out.get("bytes", MAX_FILE_SCAN + 1) <= MAX_FILE_SCAN):
        out["scanned"] = True
    if (isinstance(row.get("rules_version"), str)
            and _RULES_VERSION.fullmatch(row["rules_version"])):
        out["rules_version"] = row["rules_version"]
    # browser.health.unmatched: a path prefix, trimmed, no query and no body.
    if isinstance(row.get("path"), str):
        out["path"] = re.sub(r"[^A-Za-z0-9/_.:-]", "?", row["path"].split("?", 1)[0])[:60]
    if isinstance(row.get("ok"), bool):
        out["ok"] = row["ok"]
    if isinstance(row.get("status"), int) and not isinstance(row.get("status"), bool):
        out["status"] = row["status"]
    return out


def serve(cfg: ShieldConfig, host: str = "127.0.0.1", port: int = DEFAULT_PORT,
          feed: Feed | None = None) -> None:
    """Run the capture shield (API + static UI) until interrupted."""
    feed = feed or Feed(cfg)
    if cfg.policy_path and cfg.policy_path.exists():
        try:
            disc = json.loads(cfg.policy_path.read_text())
        except ValueError:
            disc = None
        if isinstance(disc, dict) and upgrade_policy(disc) is not disc:
            save_policy(cfg, merge_policy(upgrade_policy(disc)))
            print("policy: upgraded to privacy-first defaults (redact, no stored "
                  "text); app choices kept", flush=True)
    from byoai.integrations.shield_publish import Publisher
    publisher = Publisher(feed.seals, cfg.key_dir, cfg.key_dir.parent,
                          protection=lambda: protection_state(cfg),
                          managed_policy_path=cfg.managed_policy_path,
                          policy=lambda: load_policy(cfg),
                          events=lambda: feed.items)
    publisher.start()  # background; sends only when enrolled and due
    # The console SPA's fleet screens read /v1/console/fleet*; here the fleet
    # is this one Mac, and the answers come from the local chain (see
    # byoai.integrations.shield_console for what is knowable on this host).
    from byoai.integrations.shield_console import ShieldConsoleAPI
    console_api = ShieldConsoleAPI(cfg, feed, publisher)
    pruned = scrub_ledger(cfg, scrub_text=False)["deleted"]
    if pruned:
        print(f"retention: deleted {pruned} ledger rows past "
              f"{load_policy(cfg)['retention_days']} days", flush=True)
    feed.scan_initial()

    # Dedupe across the extension's batch retries; shared by all requests.
    browser_dedupe = {"ids": set(), "order": []}

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype="application/json",
                  cache="no-store"):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", cache)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _apps(self) -> dict:
            """Nontechnical-first app discovery: scan /Applications per
            request — cheap, no daemon, no root. Policy ON starts from the
            user's saved form; discovery never widens it silently."""
            import os
            try:
                apps = [q for q in os.listdir("/Applications") if q.endswith(".app")]
            except OSError:
                apps = []
            bundles = {
                "claude": ("Claude.app", "Claude Code.app"),
                "chatgpt": ("ChatGPT.app",),
                "gemini": ("Gemini.app", "Google Gemini.app"),
                "copilot": ("Microsoft Copilot.app", "Copilot.app"),
            }
            return {tag: any(b in apps for b in v) for tag, v in bundles.items()}

        def _coriqo(self) -> dict:
            """Connection and publishing status for Settings, plus the
            marketing link. Nothing secret is stored or returned: the Mac is
            identified by its own key after a one-time enrolment."""
            import os
            return {**publisher.status(),
                    "marketing_url": os.environ.get("BYOAI_CORIQO_MARKETING_URL")
                    or "https://coriqo.com"}

        def _api(self):
            from urllib.parse import urlparse, parse_qs
            path = self.path.split("?")[0]
            if path == "/api/feed":
                qs = parse_qs(urlparse(self.path).query)
                limit = min(int(qs.get("limit", ["60"])[0]), 200)
                offset = int(qs.get("offset", ["0"])[0])
                page = [{k: v for k, v in it.items() if not k.startswith("_")}
                        for it in list(feed.items)[offset:offset + limit]]
                return {"counts": feed.counts(),
                        "total": len(feed.items), "offset": offset,
                        "limit": limit, "has_more": offset + limit < len(feed.items),
                        "items": page}
            if path == "/api/verify":
                return feed.seals.verify_chain()
            if path == "/api/identity":
                # Proof that this is the Shield holding this device's key, not
                # another process that got to the port first. The caller picks
                # the nonce, so a recorded answer can't be replayed.
                nonce = parse_qs(urlparse(self.path).query).get("nonce", [""])[0]
                if not re.fullmatch(r"[0-9a-f]{16,64}", nonce):
                    return None
                key = feed.seals._key
                return {"device_id": key.device_id, "public_key": key.public_key_b64,
                        "sig": key.sign(IDENTITY_PREFIX + nonce.encode())}
            if path == "/api/policy":
                out = {**load_policy(cfg), "covered_apps": list(COVERED_APPS),
                       "input_only_apps": list(INPUT_ONLY_APPS)}
                summary = managed_summary(load_managed_policy(cfg.managed_policy_path))
                pol_error = publisher.policy_status().get("error")
                if summary or pol_error:
                    out["managed"] = {
                        **(summary or {"by": None, "version": None,
                                       "locked": [], "fetched_at": None}),
                        "error": pol_error,
                    }
                level = sync_level(out)
                by = (summary or {}).get("by")
                if by or level != "seal":
                    # Invariant 4: whoever receives activity is always named,
                    # in plain words, and can't be policy-hidden: a level above
                    # seal is disclosed even when no organisation is named.
                    by = by or "Your administrator"
                    out["sharing"] = {
                        "level": level, "by": by,
                        "since": (summary or {}).get("fetched_at"),
                        "words": level_words(level, by),
                    }
                return out
            if path == "/api/privacy":
                return privacy_report(cfg, feed.seals)
            return None

        def _fleet_api(self, path: str) -> None:
            """Read-only fleet console answers for this Mac's chain.

            GET-only and localhost-addressed like every other endpoint here:
            the Host check in request_problem has already run, and a write
            attempt simply has no route to hit."""
            from urllib.parse import parse_qs, urlparse
            code, body = console_api.handle(path, parse_qs(urlparse(self.path).query))
            self._send(code, body)

        def _unprefix(self) -> None:
            """The app calls ``/shield-api/*`` (Vite rewrites it in dev);
            standalone, this server takes the same prefix."""
            if self.path.startswith("/shield-api/"):
                self.path = "/api/" + self.path[len("/shield-api/"):]

        def _spa(self, path: str) -> None:
            """Serve the built console app: a real file under console_static,
            else index.html so client routes like /shield/timeline load."""
            import mimetypes

            from byoai.agent_context_cache import console
            if path == "/":
                self.send_response(302)
                self.send_header("Location", "/shield")
                self.end_headers()
                return
            if not console.assets_available():
                self._send(503, console.MISSING_BUILD_MESSAGE.encode(),
                           "text/plain; charset=utf-8")
                return
            # The build's asset URLs sit under the console base, /console/.
            rel = path[len("/console"):] if path.startswith("/console/") else path
            asset = console.resolve_asset(rel)
            if asset is not None:
                ctype = mimetypes.guess_type(asset.name)[0] or "application/octet-stream"
                self._send(200, asset.read_bytes(), ctype,
                           console.cache_headers(rel.lstrip("/"))["Cache-Control"])
                return
            # A missing file is a 404, never the app page: HTML served as a
            # stale script fails in the browser with no sign what went missing.
            last = path.rsplit("/", 1)[-1]
            if path.startswith("/console/assets/") or "." in last:
                self._send(404, b'{"error":"not found"}')
                return
            # Client routes: /shield itself, and old /console/<tenant>/shield
            # links, which the app redirects to /shield.
            if path.startswith(("/shield", "/console/")):
                self._send(200, console.INDEX_FILE.read_bytes(),
                           "text/html; charset=utf-8", "no-cache")
                return
            self._send(404, b'{"error":"not found"}')

        def _refused(self, method: str) -> bool:
            problem = request_problem(method, self.path.split("?")[0], self.headers)
            if problem is None:
                return False
            self._send(403 if "Content-Type" not in problem else 415,
                       json.dumps({"error": problem}).encode())
            return True

        def do_GET(self):  # noqa: N802
            self._unprefix()
            if self._refused("GET"):
                return
            path = self.path.split("?")[0]
            if path.startswith("/v1/console/"):
                self._fleet_api(path)
                return
            api = self._api()
            if path == "/api/apps":
                self._send(200, json.dumps(self._apps()).encode())
                return
            if path == "/api/coriqo":
                self._send(200, json.dumps(self._coriqo()).encode())
                return
            if path in ("/api/feed", "/api/verify", "/api/policy",
                        "/api/privacy") or (path == "/api/identity" and api):
                self._send(200, json.dumps(api).encode())
                return
            if path.startswith("/api/receipt/"):
                rc = feed.seals.receipt(path.rsplit("/", 1)[-1])
                self._send(200 if rc else 404,
                           (json.dumps(rc, indent=1, default=str) if rc
                            else b'{"error":"unknown seal"}'))
                return
            if path.startswith("/api/"):
                self._send(404, b'{"error":"not found"}')
                return
            self._spa(path)

        def do_POST(self):  # noqa: N802
            self._unprefix()
            if self._refused("POST"):
                return
            if self.path.split("?")[0] == "/api/browser":
                self._browser_ingest()
                return
            if self.path.split("?")[0] == "/api/coriqo/enrol":
                self._enrol()
                return
            if self.path.split("?")[0] == "/api/publish":
                self._publish_now()
                return
            if self.path.split("?")[0] == "/api/privacy/scrub":
                result = scrub_ledger(cfg)
                feed.resync()
                self._send(200, json.dumps(
                    {**result, **privacy_report(cfg, feed.seals)}).encode())
                return
            if self.path.split("?")[0] != "/api/policy":
                self._send(404, b'{"error":"not found"}')
                return
            n = int(self.headers.get("Content-Length", 0))
            policy = load_policy(cfg)
            try:
                payload = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                self._send(400, b'{"error":"invalid json"}')
                return
            if not isinstance(payload, dict):
                self._send(400, b'{"error":"expected a JSON object"}')
                return
            managed = load_managed_policy(cfg.managed_policy_path)
            if managed:
                mdoc = managed["envelope"]["document"]
                if mdoc.get("policy") is not None:
                    locked = set(mdoc.get("locked") or [])
                    touched = {k for k in payload if k != "acknowledge"}
                    if touched & locked:
                        by = mdoc.get("managed_by") or "your admin"
                        self._send(409, json.dumps({"error": f"Set by {by}"}).encode())
                        return
            try:
                policy = apply_policy_update(policy, payload)
            except ValueError as exc:
                self._send(400, json.dumps({"error": str(exc)}).encode())
                return
            save_policy(cfg, policy)
            self._send(200, json.dumps(
                {**policy, "covered_apps": list(COVERED_APPS),
                 "input_only_apps": list(INPUT_ONLY_APPS)}).encode())

        def _browser_ingest(self) -> None:
            """Rows from the browser extension: same ledger, same seal chain,
            same privacy-first stance as the desktop proxy. The extension was
            told the endpoint at install; an unconfigured one is not an error
            here — it is recorded, subject to the same policy as everything
            else."""
            n = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(self.rfile.read(n) or b"{}")
            except Exception:
                self._send(400, b'{"error":"invalid json"}')
                return
            rows = payload.get("rows") if isinstance(payload, dict) else None
            if not isinstance(rows, list) or not rows:
                self._send(400, b'{"error":"expected {rows: [...]}"}')
                return
            policy = load_policy(cfg)
            accepted = 0
            for row in rows[:200]:
                clean = clean_browser_row(row)
                if clean is None:
                    continue
                # The extension retries its batch after network trouble; a
                # row sealed twice reads as two chats. row_id (a uuid from
                # the extension) is the dedupe key, kept for the last 1000 —
                # far beyond any retry window the extension has.
                rid = clean.get("row_id")
                if rid:
                    if rid in browser_dedupe["ids"]:
                        continue
                    browser_dedupe["ids"].add(rid)
                    browser_dedupe["order"].append(rid)
                    if len(browser_dedupe["order"]) > 1000:
                        for old in browser_dedupe["order"][:-500]:
                            browser_dedupe["ids"].discard(old)
                        del browser_dedupe["order"][:-500]
                if not policy["apps"].get(clean.get("app") or "claude"):
                    continue
                append_row(cfg.ledger, clean)
                accepted += 1
            # Seal now, not on the watcher's next tick: the gap between "a row
            # is on disk" and "a row is sealed" is where an edit costs nothing.
            # poll() is locked, so this can't race the watcher into sealing a
            # row twice.
            if accepted:
                feed.poll()
            self._send(200, json.dumps(
                {"accepted": accepted, "sealed_total": feed.seals.total}).encode())

        def _enrol(self) -> None:
            """One-time setup: exchange a Coriqo enrolment token for this
            Mac's device identity. The token is used once and not kept."""
            from byoai.recorder.enroll import EnrollmentError
            n = int(self.headers.get("Content-Length", 0))
            try:
                payload = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                self._send(400, b'{"error":"invalid json"}')
                return
            try:
                status = publisher.enrol(str(payload.get("base_url") or ""),
                                         str(payload.get("token") or ""))
            except ValueError as exc:
                self._send(400, json.dumps({"error": str(exc)}).encode())
                return
            except EnrollmentError as exc:
                msg = str(exc)
                if "already enrolled" in msg or "HTTP 409" in msg:
                    hint = ("This Mac is already connected to Coriqo with its current key, "
                            "so it doesn't need a new token. The token hasn't been used.")
                elif "rejected" in msg:
                    hint = ("Coriqo didn't accept that token. It may be used, expired "
                            "or revoked; ask your Coriqo admin for a new one.")
                else:
                    hint = "Couldn't reach Coriqo at that address. Check it and try again."
                self._send(400, json.dumps({"error": hint}).encode())
                return
            self._send(200, json.dumps(status).encode())

        def _publish_now(self) -> None:
            """"Send now": publish the current seal immediately. Failures are
            recorded in the status (and retried on their own), not raised."""
            try:
                status = publisher.publish_now()
            except ValueError as exc:
                self._send(409, json.dumps({"error": str(exc)}).encode())
                return
            except Exception:  # noqa: BLE001 - always answer, never drop the request
                self._send(500, json.dumps({
                    "error": "Couldn't send right now. Shield will try again on its own."
                }).encode())
                return
            self._send(200, json.dumps(status).encode())

        def log_message(self, *a):  # per-request rlog silenced
            return

    harden_files(cfg.ledger, cfg.seal_path, cfg.policy_path)
    try:
        server = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        # Never slide to another port: the extension and bookmarks look for
        # Shield at one address, and a silent move would hide it from them.
        raise SystemExit(
            f"Shield cannot listen on {host}:{port} ({exc.strerror}). Something "
            f"else is using that port. Set BYOAI_SHIELD_PORT (or --port) to a "
            f"free one and enter the same address in the extension popup.") from exc
    print(f"Coriqo Shield → http://{host}:{port}/shield", flush=True)
    print(f"seal chain: {feed.seals.height} entries, root "
          f"{(feed.seals.root_hex() or '')[:10]}", flush=True)
    print(f"device: {feed.seals._key.device_id}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


def default_paths(ledger: str | Path) -> ShieldConfig:
    ledger = Path(ledger)
    return ShieldConfig(
        ledger=ledger,
        seal_path=ledger.parent / "sealchain.json",
        key_dir=DATA_DIR / "keys",
        policy_path=ledger.parent / "policy.json",
        sig_every=1, max_interactions=MAX_INTERACTIONS,
    )


def main() -> None:  # console-script entrypoint: byoai-shield
    import argparse

    ap = argparse.ArgumentParser(prog="byoai-shield", description=__doc__)
    ap.add_argument("ledger", nargs="?",
                    default=str(DATA_DIR / "captures.jsonl"),
                    help="path to captures.jsonl (default: ~/.byoai/shield/captures.jsonl)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--daemonize-watch", action="store_true", default=True)
    ap.add_argument("--install-login-item", action="store_true",
                    help="start Shield when you log in (macOS), then exit")
    ap.add_argument("--remove-login-item", action="store_true",
                    help="stop starting Shield at login (macOS), then exit")
    args = ap.parse_args()
    if _sys.stdout is None or _sys.stderr is None:
        # Started without a console (Windows pythonw, a service): print() would
        # raise on a missing stdout, so send output to the log instead.
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        log = open(DATA_DIR / "shield.log", "a", buffering=1)  # noqa: SIM115
        _sys.stdout = _sys.stdout or log
        _sys.stderr = _sys.stderr or log
    if args.install_login_item or args.remove_login_item:
        from byoai.integrations import shield_login
        raise SystemExit(shield_login.run(
            install=args.install_login_item, ledger=args.ledger, port=args.port))
    cfg = default_paths(args.ledger)
    feed = Feed(cfg)

    def _watcher():
        while True:
            try:
                feed.poll()
            except Exception:
                pass
            time.sleep(1.5)

    import threading
    threading.Thread(target=_watcher, daemon=True).start()
    serve(cfg, host=args.host, port=args.port, feed=feed)


if __name__ == "__main__":
    main()
