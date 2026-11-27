"""Coriqo Shield capture proxy — a mitmproxy addon, privacy-first.

It sits between an AI chat app and its API on this Mac and, per request,
looks at every string in the message body and applies the policy's per-tier
``actions`` (defaults: secret block, pii redact, flag log):

* ``block`` -- the send is refused locally with a 403 and never leaves;
* ``redact`` -- secrets and personal details are replaced with numbered
  placeholders ([EMAIL_1]) before the send goes out;
* ``warn`` -- a third-party app has no place for a "send anyway?" prompt, so
  this behaves as ``redact``, and the row says ``action="warn"`` so the Shield
  UI can tell the person;
* ``log`` -- recorded only.

The master ``mode`` still applies: ``observe`` turns every action into ``log``.

What it writes to the ledger is **what happened, not what was said**: the
app, the verdict, which rules fired, the message length and a keyed
fingerprint (:func:`byoai.integrations.shield.fingerprint`). A redacted
preview is written only when the admin turned on ``keep_text``. The same
applies to replies.

Rules, redaction and policy come from :mod:`byoai.integrations.shield`, so
the proxy and the shield UI can't disagree about what a rule is.

    mitmdump --listen-port 8080 -s examples/desktop_proxy_capture.py
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from pathlib import Path

from byoai.integrations.shield import (
    _MIME,
    COVERED_APPS,
    RULE_LABEL,
    RULE_TIER,
    action_for,
    all_message_text,
    append_row,
    evaluate,
    flags_for,
    inspect_file,
    inspect_text,
    message_text,
    proxy_alive_path,
    read_policy,
    redact_json_body,
)

# Host -> (app, wire format). A pattern is an exact host, or ``*.example.com``
# for any subdomain (matched on a dot boundary, so "evil-openai.com.attacker"
# is neither). ``verified`` is True where the format has been checked against
# real traffic; the newer entries are written from the provider's public API
# docs and their fixtures in tests/fixtures/proxy/ are not live captures.
# ``pinned`` marks a host whose TLS can't be inspected.
HOSTS: tuple[dict, ...] = (
    {"host": "claude.ai", "app": "claude", "format": "claude_web", "verified": True},
    {"host": "*.claude.ai", "app": "claude", "format": "claude_web", "verified": True},
    {"host": "anthropic.com", "app": "claude", "format": "anthropic", "verified": True},
    {"host": "*.anthropic.com", "app": "claude", "format": "anthropic", "verified": True},
    {"host": "chatgpt.com", "app": "chatgpt", "format": "chatgpt_web", "verified": True},
    {"host": "*.chatgpt.com", "app": "chatgpt", "format": "chatgpt_web", "verified": True},
    {"host": "chat.openai.com", "app": "chatgpt", "format": "chatgpt_web", "verified": True},
    {"host": "openai.com", "app": "chatgpt", "format": "openai", "verified": True},
    {"host": "*.openai.com", "app": "chatgpt", "format": "openai", "verified": True},
    # ChatGPT's file storage: the pre-signed PUT of the file itself (observed live).
    {"host": "*.oaiusercontent.com", "app": "chatgpt", "format": "upload", "verified": True},
    {"host": "gemini.google.com", "app": "gemini", "format": "batch_rpc", "verified": True},
    {"host": "copilot.microsoft.com", "app": "copilot", "format": "websocket", "verified": True},
    # verified: False - fixture from public API docs, not a live capture.
    {"host": "*.githubcopilot.com", "app": "github_copilot", "format": "openai", "verified": False},  # verified: False
    {"host": "api.mistral.ai", "app": "mistral", "format": "openai", "verified": False},  # verified: False
    {"host": "api.deepseek.com", "app": "deepseek", "format": "openai", "verified": False},  # verified: False
    {"host": "api.groq.com", "app": "groq", "format": "openai", "verified": False},  # verified: False
    {"host": "openrouter.ai", "app": "openrouter", "format": "openai", "verified": False},  # verified: False
    {"host": "api.together.xyz", "app": "together", "format": "openai", "verified": False},  # verified: False
    {"host": "generativelanguage.googleapis.com", "app": "gemini_api", "format": "gemini",
     "verified": False},  # verified: False
)
# Seen but never inspected: pinned certificates or binary protocols, or a
# proprietary format nobody has captured. One meta row per host, no bodies.
NOT_COVERED: tuple[dict, ...] = (
    {"host": "api2.cursor.sh", "reason": "pinned or binary protocol"},
    {"host": "*.cursor.sh", "reason": "pinned or binary protocol"},
    {"host": "*.codeium.com", "reason": "pinned or binary protocol"},
    {"host": "*.windsurf.com", "reason": "pinned or binary protocol"},
    {"host": "www.perplexity.ai", "reason": "proprietary format, not captured"},
)

# Paths that ARE the product: the user's chat going out, the model's reply
# coming back, and MCP tool traffic on the chat wire.
INTERESTING = (
    re.compile(r"/chat_conversations/.+/completion"),   # claude.ai chat send
    re.compile(r"/v1/messages"),                        # API / agent wire format
    re.compile(r"/api/organizations/[^/]+/mcp"),        # MCP aggregation endpoints
    re.compile(r"/backend-api/(f/)?conversation$"),     # chatgpt.com chat send
    re.compile(r"/chat/completions$"),                  # OpenAI-compatible chat
    re.compile(r"/v1/responses"),                       # OpenAI Responses
    re.compile(r":(?:stream)?[gG]enerateContent$"),     # Gemini
)
# A POST that looks like a chat send but matched nothing above: the app may
# have changed its wire format. Counted per host, see ShieldProxy._canary.
LOOKS_LIKE_SEND = re.compile(r"conversation|completion|chat|messages|generateContent")
CANARY_COUNT, CANARY_WINDOW = 3, 600
# Uploads: recorded as "a file was attached", never read.
UPLOAD_PATH = re.compile(r"/(?:files|upload|uploads|attachments)(?:$|[/?-])")
# A raw (non-form) upload body: only ChatGPT's pre-signed PUT of the file
# itself. Other file-ish paths carry JSON metadata, not a file.
MAX_FILE_PARTS = 32  # file parts listed one by one per request; the rest is one blob row
RAW_UPLOAD_HOST = "*.oaiusercontent.com"
RAW_UPLOAD_PATH = re.compile(r"^/files/[^/]+/raw/?$")
# Endpoints worth one body-free metadata row each.
MEANS = (
    re.compile(r"/system_prompts"),
    re.compile(r"/cowork_sysprompt_map"),
    re.compile(r"/desktop/features"),
    re.compile(r"/organizations/[^/]+/usage"),
)


def _host_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])  # ".example.com": a dot boundary
    return host == pattern


def _clean_host(host: str | None) -> str:
    return (host or "").strip().lower().rstrip(".")


def app_for_host(host: str | None) -> str | None:
    host = _clean_host(host)
    if not host:
        return None
    for entry in HOSTS:
        if _host_matches(entry["host"], host):
            return entry["app"]
    return None


def not_covered_reason(host: str | None) -> str | None:
    host = _clean_host(host)
    for entry in NOT_COVERED:
        if host and _host_matches(entry["host"], host):
            return entry["reason"]
    return None


def multipart_boundary(content_type: str) -> str | None:
    from email.message import Message
    msg = Message()
    msg["Content-Type"] = content_type
    b = msg.get_param("boundary")
    return b if isinstance(b, str) and b else None


def multipart_files(content_type: str, body: bytes):
    """(file name, declared type, exact bytes) of every file part in a
    multipart/form-data body, split on the boundary by hand so the bytes are
    the ones sent (a part's payload is everything between its blank line and
    the CRLF before the next boundary). Yields nothing when the body can't be
    read as a form."""
    from email.message import Message
    from email.parser import BytesHeaderParser
    msg = Message()
    msg["Content-Type"] = content_type
    boundary = msg.get_param("boundary")
    if not isinstance(boundary, str) or not boundary:
        return
    delim = b"--" + boundary.encode("latin-1", "replace")
    for chunk in body.split(delim)[1:]:
        if chunk.startswith(b"--"):
            break  # closing delimiter
        if chunk.startswith(b"\r\n"):
            chunk = chunk[2:]
        elif chunk.startswith(b"\n"):
            chunk = chunk[1:]
        if chunk.startswith((b"\r\n", b"\n")):
            continue  # a part with no headers is not a file
        # The blank line that ends the headers: CRLF, or a bare LF from a
        # sloppy client (some servers accept both).
        crlf, lf = chunk.find(b"\r\n\r\n"), chunk.find(b"\n\n")
        if crlf != -1 and (lf == -1 or crlf < lf):
            head, payload, nl = chunk[:crlf], chunk[crlf + 4:], b"\r\n"
        elif lf != -1:
            head, payload, nl = chunk[:lf], chunk[lf + 2:], b"\n"
        else:
            continue
        if payload.endswith(nl):
            payload = payload[:-len(nl)]
        hdrs = BytesHeaderParser().parsebytes(head + b"\r\n\r\n")
        fname = hdrs.get_filename()
        if fname is None:
            continue
        mime = str(hdrs.get("content-type", "") or "").split(";", 1)[0].strip().lower()
        yield (str(fname) or None, mime or "application/octet-stream", payload)


def _path(flow) -> str:
    parts = flow.request.path_components
    return "/" + "/".join(parts) if parts else (flow.request.path or "")


def _match(flow, patterns) -> bool:
    path = _path(flow)
    return any(p.search(path) for p in patterns)


def reply_text(raw: str) -> str:
    """The model's words out of a reply: joins SSE text chunks (Anthropic
    ``delta.text``, claude.ai ``completion``, OpenAI ``choices[].delta.content``
    and Responses ``response.output_text.delta``), or reads a plain JSON
    Messages / Chat Completions response. ChatGPT web streams whole-message
    snapshots; the last one wins."""
    parts: list[str] = []
    for line in raw.splitlines():
        if not line.startswith("data:"):
            continue
        try:
            ev = json.loads(line[5:].strip())
        except ValueError:
            continue
        if not isinstance(ev, dict):
            continue
        delta = ev.get("delta")
        choices = ev.get("choices")
        if isinstance(delta, dict) and isinstance(delta.get("text"), str):
            parts.append(delta["text"])
        elif isinstance(delta, str) and ev.get("type") == "response.output_text.delta":
            parts.append(delta)
        elif isinstance(ev.get("completion"), str):
            parts.append(ev["completion"])
        elif isinstance(choices, list) and choices and isinstance(choices[0], dict):
            piece = (choices[0].get("delta") or {}).get("content")
            if isinstance(piece, str):
                parts.append(piece)
        elif isinstance(ev.get("message"), dict):  # chatgpt.com snapshot
            snap = ev["message"].get("content")
            if isinstance(snap, dict) and isinstance(snap.get("parts"), list):
                parts = [x for x in snap["parts"] if isinstance(x, str)]
    if parts:
        return "".join(parts)
    try:
        body = json.loads(raw)
    except ValueError:
        return ""
    if isinstance(body, dict) and isinstance(body.get("content"), list):
        return "".join(str(b.get("text", "")) for b in body["content"]
                       if isinstance(b, dict))
    if isinstance(body, dict) and isinstance(body.get("choices"), list):
        return "".join(str((c.get("message") or {}).get("content") or "")
                       for c in body["choices"] if isinstance(c, dict))
    return ""


class ShieldProxy:
    """The addon. ``ledger`` and ``policy_path`` are where the shield UI reads
    and writes; policy is re-read at most every two seconds."""

    def __init__(self, ledger: Path, policy_path: Path) -> None:
        self.ledger = ledger
        self.policy_path = policy_path
        self._policy: dict | None = None
        self._policy_at = 0.0
        self._unmatched: dict[str, list[float]] = {}   # host -> send-looking POSTs
        self._inspected: dict[str, float] = {}         # host -> last inspected send
        self._noted: set[str] = set()                  # uncovered hosts already logged

    # -- plumbing ---------------------------------------------------------
    def policy(self) -> dict:
        if self._policy is None or time.time() - self._policy_at >= 2:
            self._policy = read_policy(self.policy_path)
            self._policy_at = time.time()
        return self._policy

    def _log(self, kind: str, **fields: object) -> None:
        rec = {"wall_clock": time.strftime("%Y-%m-%d %H:%M:%S"),
               "kind": "desktop." + kind, **fields}
        append_row(self.ledger, rec)
        # stderr gets the same row: it holds no message text either.
        print("[shield] " + json.dumps(rec, default=str)[:300],
              file=sys.stderr, flush=True)

    def _governed(self, flow) -> str | None:
        """The app tag when this flow is one Shield should look at, else None
        (not an AI host, or the admin turned that app off)."""
        host = flow.request.pretty_host or ""
        app = app_for_host(host)
        if app not in COVERED_APPS or not self.policy()["apps"].get(app, False):
            return None
        return app

    # -- liveness ---------------------------------------------------------
    def running(self) -> None:
        """mitmproxy is up: leave a marker (pid, listen port) next to the
        ledger, so Shield can tell Coriqo whether traffic is being checked."""
        import os

        from byoai.recorder.keys import atomic_write_bytes
        port = None
        try:
            from mitmproxy import (  # pyright: ignore[reportMissingImports]  # optional dependency, not installed in CI
                ctx,
            )
            port = int(ctx.options.listen_port or 8080)
        except Exception:  # noqa: BLE001 - outside mitmproxy, or no port option
            pass
        try:
            atomic_write_bytes(proxy_alive_path(self.ledger), json.dumps({
                "pid": os.getpid(), "port": port,
                "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }).encode(), mode=0o644, prefix=".shield-proxy-")
        except OSError:
            pass  # never stop the proxy over its own marker

    def done(self) -> None:
        """Clean stop: remove our marker (only ours, not a newer proxy's)."""
        import os
        path = proxy_alive_path(self.ledger)
        try:
            if json.loads(path.read_text()).get("pid") == os.getpid():
                path.unlink()
        except (OSError, ValueError, AttributeError):
            pass

    # -- health and attachments -------------------------------------------
    def _canary(self, flow, app: str, host: str) -> None:
        """Send-looking POSTs to a covered host that no rule recognised. Three
        in ten minutes with none inspected in that time means the wire format
        probably changed: say so instead of failing open in silence."""
        if getattr(flow.request, "method", "POST") != "POST":
            return
        path = _path(flow)
        if not LOOKS_LIKE_SEND.search(path):
            return
        now = time.time()
        hits = [t for t in self._unmatched.get(host, []) if now - t < CANARY_WINDOW]
        hits.append(now)
        self._unmatched[host] = hits
        if len(hits) >= CANARY_COUNT and now - self._inspected.get(host, 0) > CANARY_WINDOW:
            self._unmatched[host] = []
            self._log("health.unmatched", target=host, app=app, path=path[:60])

    def _attachment(self, flow, app: str, host: str) -> bool:
        """Hash and check every file this upload carries, and record one row
        per file: type, size, SHA-256, rule hits, never the name or content.
        Returns True when the upload was refused."""
        req = flow.request
        if str(getattr(req, "method", "POST")).upper() not in ("POST", "PUT"):
            return False
        headers = getattr(req, "headers", None) or {}
        ctype_full = str(headers.get("content-type", ""))
        ctype = ctype_full.split(";", 1)[0].strip().lower()
        is_form = ctype.startswith("multipart/")
        try:
            content = req.get_content(strict=False) if hasattr(req, "get_content") else b""
        except Exception:  # noqa: BLE001 - never break the app over a record
            content = b""
        content = content or b""
        if not is_form:
            # A raw body is an upload when it goes to ChatGPT's file storage
            # (any PUT or POST with a body there), or to an upload-looking path
            # with any content type or none. A JSON object or array on such a
            # path is metadata (ChatGPT's POST /backend-api/files), not a file.
            if not content:
                return False
            if not _host_matches(RAW_UPLOAD_HOST, _clean_host(host)):
                if not UPLOAD_PATH.search(_path(flow)):
                    return False
                if content.lstrip()[:1] in (b"{", b"["):
                    try:
                        if isinstance(json.loads(content), (dict, list)):
                            return False
                    except ValueError:
                        pass
        policy = self.policy()
        rows: list[dict] = []
        stop: list[str] = []
        state = {"n": 0}
        rest = {"sha": hashlib.sha256(), "bytes": 0, "flags": [], "scanned": True, "any": False}

        def check(name, mime, data, raw):
            facts = inspect_file(name, mime if _MIME.fullmatch(mime or "") else None,
                                 data, app, policy, raw_upload=raw)
            action = facts.pop("action")
            if action in ("warn", "block"):  # no place to ask here: warn stops it too
                stop.append(str(action))
                for f in facts["flags"]:
                    rule = f.partition(":")[2]
                    if action_for(rule, policy) in ("warn", "block", "redact"):
                        label = str(RULE_LABEL.get(rule, rule))
                        if label not in stop:
                            stop.append(label)
            state["n"] += 1
            if state["n"] <= MAX_FILE_PARTS:
                rows.append(facts)
            else:
                # Every part is read and counted against the policy; only the
                # rows are capped: the rest share one row (hash of all of
                # their bytes together, combined flags).
                rest["any"] = True
                rest["sha"].update(data)
                rest["bytes"] += len(data)
                rest["scanned"] &= facts["scanned"]
                rest["flags"] += [f for f in facts["flags"] if f not in rest["flags"]]

        if is_form:
            for n, m, d in multipart_files(ctype_full, content):
                check(n, m, d, False)
            if not state["n"]:
                if multipart_boundary(ctype_full):
                    return False  # a form with no file part is not an upload
                # Declared as a form but unreadable: the whole body is the
                # evidence, and it is not read by the rules.
                check(None, "application/octet-stream", content, False)
        else:
            check(None, ctype, content, True)
        if rest["any"]:
            facts = inspect_file(None, "application/octet-stream", b"", app, policy)
            facts.pop("action")
            facts.update(bytes=rest["bytes"], sha256=rest["sha"].hexdigest(), scanned=rest["scanned"],
                         flags=[*rest["flags"], "flag:too_many_files"])
            rows.append(facts)
        blocked = any(a in ("warn", "block") for a in stop)
        for facts in rows:
            self._log("chat.attachment", target=host, app=app,
                      verdict="blocked" if blocked else "allowed", **facts)
        if not blocked:
            return False
        labels = [x for x in stop if x not in ("warn", "block")]
        _refuse(flow, "Stopped on this Mac: file upload blocked"
                + (" (" + ", ".join(labels) + ")" if labels else ""))
        return True

    # -- mitmproxy hooks --------------------------------------------------
    def request(self, flow) -> None:
        app = self._governed(flow)
        if app is None:
            host = flow.request.pretty_host or ""
            reason = not_covered_reason(host)
            if reason and _clean_host(host) not in self._noted:
                self._noted.add(_clean_host(host))
                self._log("meta", target=host, app=None, not_covered=reason)
            return
        host = flow.request.pretty_host or ""
        if _match(flow, MEANS):
            self._log("meta", target=host, app=app, path=_path(flow)[:120])
            return
        if not _match(flow, INTERESTING):
            if self._attachment(flow, app, host):
                return
            self._canary(flow, app, host)
            return
        self._inspected[host] = time.time()
        policy = self.policy()
        mode = policy["mode"]
        raw = flow.request.get_text(strict=False) or ""
        try:
            body = json.loads(raw)
        except ValueError:
            body = {}
        text = message_text(body) if isinstance(body, dict) else ""
        # The decision looks at every turn the body carries (the same fields
        # redaction rewrites), so a secret in earlier history can't ride along.
        every = all_message_text(body) if isinstance(body, dict) else ""
        found = flags_for(every, replies=False)
        action, rules = evaluate(every, policy, flags=found)
        extra = [f"{RULE_TIER[r]}:{r}" for r in rules]

        def facts_for_row() -> dict:
            facts = inspect_text(text, policy, flags=found if text == every else None)
            facts["flags"] = list(dict.fromkeys([*facts["flags"], *extra]))
            return facts

        if action == "block":
            stopped = [RULE_LABEL.get(r, r) for r in rules
                       if action_for(r, policy) == "block"]
            self._log("verdict.denied", target=host, app=app, verdict="blocked",
                      **facts_for_row())
            _refuse(flow, "Stopped on this Mac: " + ", ".join(stopped))
            return

        redactions: list[str] = []
        if action in ("redact", "warn"):  # warn has no UI here: it redacts
            new_raw, redactions = redact_json_body(raw, policy)
            if redactions:
                flow.request.set_text(new_raw)
        # Rule hits come from the text as typed, so the record says what was
        # caught; the fingerprint is of that same text.
        verdict = f"redacted({len(redactions)})" if redactions else mode
        extra_fields = {"action": "warn"} if action == "warn" else {}
        self._log("chat.request", target=host, app=app, verdict=verdict,
                  redactions=redactions, **extra_fields, **facts_for_row())
        flow.metadata["shield_app"] = app

    def response(self, flow) -> None:
        app = flow.metadata.get("shield_app")
        if app is None or flow.response is None:
            return
        try:
            raw = flow.response.get_text(strict=False) or ""
        except ValueError:
            raw = ""
        text = reply_text(raw)
        facts = inspect_text(text, self.policy(), rules="reply")
        self._log("chat.response", target=flow.request.pretty_host or "",
                  app=app, status=flow.response.status_code, **facts)


def _refuse(flow, message: str) -> None:
    """Answer the app locally; the request never leaves the machine."""
    from mitmproxy import (  # pyright: ignore[reportMissingImports]  # optional dependency, not installed in CI
        http,
    )

    flow.response = http.Response.make(
        403,
        json.dumps({"error": {"type": "coriqo_shield_blocked",
                              "message": message}}).encode(),
        {"Content-Type": "application/json", "x-coriqo-shield": "blocked"},
    )
