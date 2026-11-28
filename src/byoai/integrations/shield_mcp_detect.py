"""Detect MCP JSON-RPC (over HTTP) in already-captured bodies (Shield unit U2.2).

Pure: no network, no ledger writes, no input mutation, never raises. The proxy
calls :func:`detect_mcp` with a captured body and gets envelope-ready rows
(docs/shield-event-envelope.md), shaped like the adapter's derived rows.

Rules held here:

* A ``tools/call`` request is a **request** (``observed_requested``), never an
  execution. Arguments are never copied; only the tool name and call id.
* An encrypted, compressed, oversized or unsupported stream is
  ``unobservable_payload``: seen, not inspected.
* A ``tools/call`` result matched by id is reported in ``Detection.correlated``
  only. The envelope has no desktop-proxy result row (``desktop.*`` kinds may not
  carry ``ai.tool.result``), so no envelope row is invented for it.
"""

from __future__ import annotations

import json
import re
from collections.abc import MutableMapping
from dataclasses import dataclass, field
from typing import Any

MAX_BODY_BYTES = 1_048_576
MAX_BATCH = 100
MAX_PENDING = 1024

_TOOL = re.compile(r"^[A-Za-z0-9_.:-]{1,48}$")
_CALL = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_HOST = re.compile(r"^[a-z0-9._:-]{1,253}$")
_JSON_TYPES = ("application/json", "application/json-rpc")
_SSE = "text/event-stream"
_Pending = MutableMapping[tuple[str, str], tuple[str, "str | None"]]


@dataclass
class Detection:
    rows: list[dict[str, Any]] = field(default_factory=list)
    methods: list[str] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    correlated: list[dict[str, Any]] = field(default_factory=list)


def _base(kind: str, event_type: str, evidence: str, host: str | None) -> dict[str, Any]:
    row: dict[str, Any] = {"kind": kind, "envelope_version": 1, "ai_event_type": event_type,
                           "evidence_level": evidence, "collector": "desktop_proxy",
                           "policy_action": "none", "outcome": "not_applicable"}
    if host:
        row["target"] = host
    return row


def _unobservable(host: str | None, why: str) -> dict[str, Any]:
    row = _base("desktop.meta", "ai.app.discovered", "unobservable_payload", host)
    row["not_covered"] = why
    return row


def _id_key(raw: Any) -> tuple[str, str] | None:
    if isinstance(raw, bool) or not isinstance(raw, (int, str)):
        return None
    return (type(raw).__name__, str(raw))


def _call_id(key: tuple[str, str] | None) -> str | None:
    return key[1] if key and _CALL.fullmatch(key[1]) else None


def _sse_payloads(text: str) -> list[str]:
    out: list[str] = []
    for block in re.split(r"\n\n+", text.replace("\r\n", "\n").replace("\r", "\n")):
        data = [ln[5:].removeprefix(" ") for ln in block.split("\n") if ln.startswith("data:")]
        if data:
            out.append("\n".join(data))
    return out


def _messages(text: str, ctype: str) -> tuple[list[Any], bool]:
    """Parsed messages (capped) and whether the body was malformed.

    Malformed means chunks existed but none parsed; a stray non-JSON SSE event
    (e.g. a ping) next to valid ones is ignored.
    """
    chunks = _sse_payloads(text) if ctype == _SSE else [text]
    msgs: list[Any] = []
    bad = parsed = False
    for chunk in chunks:
        try:
            doc = json.loads(chunk)
        except ValueError:
            bad = True
            continue
        parsed = True
        msgs.extend(doc if isinstance(doc, list) else [doc])
        if len(msgs) >= MAX_BATCH:
            break
    return msgs[:MAX_BATCH], bad and not parsed


def detect_mcp(body: bytes | str | None, direction: str, content_type: str | None = None, *,
               host: str | None = None, encrypted: bool = False,
               content_encoding: str | None = None,
               pending: _Pending | None = None) -> Detection:
    """Recognise MCP ``tools/list`` and ``tools/call`` in one captured body.

    ``direction`` is ``"request"`` or ``"response"``. ``pending`` is an optional
    caller-owned dict that correlates a request id with its result across calls
    (bounded to ``MAX_PENDING``, oldest dropped).
    """
    try:
        return _detect(body, direction, content_type, host, encrypted, content_encoding, pending)
    except Exception:  # noqa: BLE001 - a detector must never break the proxy
        return Detection()


def _detect(body: Any, direction: str, content_type: str | None, host: str | None,
            encrypted: bool, content_encoding: str | None, pending: _Pending | None) -> Detection:
    det = Detection()
    target = host.strip().lower() if isinstance(host, str) else None
    if target is not None and not _HOST.fullmatch(target):
        target = None
    if not isinstance(body, (bytes, bytearray, str)) or not body:
        return det
    ctype = (content_type or "").split(";", 1)[0].strip().lower()
    enc = (content_encoding or "").strip().lower()
    if encrypted:
        det.rows.append(_unobservable(target, "encrypted stream"))
        return det
    if enc not in ("", "identity"):
        det.rows.append(_unobservable(target, "encoded body"))
        return det
    if ctype and ctype != _SSE and ctype not in _JSON_TYPES and not ctype.endswith("+json"):
        det.rows.append(_unobservable(target, "unsupported content type"))
        return det
    if len(body) > MAX_BODY_BYTES:
        det.rows.append(_unobservable(target, "body too large"))
        return det
    try:
        text = body.decode("utf-8") if not isinstance(body, str) else body
    except UnicodeDecodeError:
        det.rows.append(_unobservable(target, "undecodable body"))
        return det
    if not ctype and text.lstrip().startswith(("data:", "event:")):
        ctype = _SSE
    msgs, bad = _messages(text, ctype)
    for msg in msgs:
        if len(det.rows) >= MAX_BATCH:
            break
        if isinstance(msg, dict) and msg.get("jsonrpc") == "2.0":
            _one(msg, direction, target, pending, det)
    if bad and len(det.rows) < MAX_BATCH:
        det.rows.append(_unobservable(target, "malformed body"))
    return det


def _remember(pending: _Pending | None, key: tuple[str, str] | None,
              value: tuple[str, str | None]) -> None:
    if pending is None or key is None:
        return
    pending.pop(key, None)  # a re-issued id becomes the newest entry
    pending[key] = value
    while len(pending) > MAX_PENDING:
        del pending[next(iter(pending))]


def _one(msg: dict[str, Any], direction: str, target: str | None,
         pending: _Pending | None, det: Detection) -> None:
    method = msg.get("method")
    key = _id_key(msg.get("id"))
    # Client-to-server messages carry a method; only server replies (no method)
    # may correlate. Anything else is a server-initiated request or a client
    # reply to one, and must not touch ``pending``.
    if direction != ("request" if method is not None else "response"):
        return
    if method == "tools/call":
        params = msg.get("params")
        if not isinstance(params, dict):
            return
        raw = params.get("name")
        name = raw if isinstance(raw, str) and _TOOL.fullmatch(raw) else None
        det.methods.append(method)
        tool: dict[str, str] = {"status": "requested"}
        if name:
            tool["name"] = name
        cid = _call_id(key)
        if cid:
            tool["call_id"] = cid
        if target:
            tool["destination"] = target
        row = _base("desktop.chat.response", "ai.tool_call.requested", "observed_requested",
                    target)
        row["tool"] = tool
        det.rows.append(row)
        _remember(pending, key, (method, name))
    elif method == "tools/list":
        det.methods.append(method)
        _remember(pending, key, (method, None))
        det.rows.append(_base("desktop.meta", "ai.app.visited", "observed", target))
    elif method is None and key is not None and pending is not None and key in pending:
        if "result" not in msg and "error" not in msg:
            return
        req_method, name = pending.pop(key)
        result = msg.get("result")
        if req_method == "tools/list":
            det.methods.append(req_method)
            tools = result.get("tools") if isinstance(result, dict) else None
            for t in (tools if isinstance(tools, list) else [])[:MAX_BATCH]:
                n = t.get("name") if isinstance(t, dict) else None
                if isinstance(n, str) and _TOOL.fullmatch(n):
                    det.tool_names.append(n)
        else:
            errored = "error" in msg or (isinstance(result, dict) and result.get("isError") is True)
            det.correlated.append({"call_id": _call_id(key), "method": req_method,
                                   "tool": name, "is_error": bool(errored)})
