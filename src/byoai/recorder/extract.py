"""SSE extraction for the agent recorder.

Pure, I/O-free translation of an Anthropic ``/v1/messages`` exchange into
:class:`PartialEvent` records. The streaming path is a *tee*: bytes are handed
to :meth:`StreamExtractor.feed` after they have already been forwarded
downstream, so nothing here can add latency to or reorder the token stream.

Design notes that are load-bearing:

* SSE frames are parsed incrementally. A chunk boundary may fall anywhere —
  mid-line, between ``\\r`` and ``\\n``, mid-UTF-8-sequence — and the parser
  must produce identical output regardless of how the byte stream was split.
* ``input_json_delta`` fragments are accumulated per ``content_block`` index
  for the lifetime of the response, and the ``tool_use`` event is emitted on
  ``content_block_stop``, never earlier.
* A truncated stream is not silently discarded: :meth:`StreamExtractor.close`
  emits a ``stream_aborted`` marker for every block that never stopped. An
  unpaired/incomplete tool call is a finding for the examiner.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from time import monotonic_ns
from typing import Any

from .schema import EVENT_SCHEMA_VERSION, EventKind, now_ts_device

PROVIDER = "anthropic"

KIND_STREAM_ABORTED: str = EventKind.STREAM_ABORTED.value
KIND_PARSE_FAILURE: str = EventKind.PARSE_FAILURE.value

# Cap on raw text kept for a data line we could not parse. Bounded so a
# pathological upstream cannot make an event unboundedly large.
_MAX_RAW_KEEP = 4096


def _kind(kind: EventKind | str) -> str:
    return kind.value if isinstance(kind, EventKind) else str(kind)


@dataclass(frozen=True, slots=True)
class PartialEvent:
    """Everything an ``AgentEvent`` needs except ``seq``/``device_id``/``event_id``.

    ``payload_hash`` is deliberately absent: hashing is workstream A's
    canonicalization, and the recorder computes it when it promotes a
    ``PartialEvent`` into an ``AgentEvent``.
    """

    session_id: str
    kind: str
    ts_device: str
    ts_monotonic_ns: int
    tool_use_id: str | None
    tool_name: str | None
    payload: dict[str, Any]
    model: str | None
    provider: str = PROVIDER
    schema_version: str = EVENT_SCHEMA_VERSION
    # Trace attribution. trace_id/span_id are set by whoever
    # calls extract_request_events/extract_response_events/StreamExtractor
    # (the proxy request handler, per capture call) — "" here only shows up
    # if a caller genuinely didn't supply one, which integration.py's
    # promotion path is not expected to do.
    trace_id: str = ""
    span_id: str = ""
    parent_span_id: str | None = None
    continues_from: str | None = None
    # A caller-chosen id, for a source that must seal the same record to the same event every
    # time it reads it (the Bedrock invocation log reader, W10). None: the recorder mints a
    # random one, as for every live capture.
    event_id: str | None = None


def _make_event(
    *,
    session_id: str,
    kind: EventKind | str,
    payload: dict[str, Any],
    model: str | None,
    tool_use_id: str | None = None,
    tool_name: str | None = None,
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str | None = None,
    continues_from: str | None = None,
) -> PartialEvent:
    return PartialEvent(
        session_id=session_id,
        kind=_kind(kind),
        ts_device=now_ts_device(),
        ts_monotonic_ns=monotonic_ns(),
        tool_use_id=tool_use_id,
        tool_name=tool_name,
        payload=payload,
        model=model,
        trace_id=trace_id,
        span_id=span_id,
        parent_span_id=parent_span_id,
        continues_from=continues_from,
    )


@dataclass(slots=True)
class _Block:
    """Accumulator for one ``content_block`` index."""

    index: int
    type: str
    id: str | None = None
    name: str | None = None
    json_parts: list[str] = field(default_factory=list)
    text_parts: list[str] = field(default_factory=list)

    def partial_json(self) -> str:
        return "".join(self.json_parts)

    def text(self) -> str:
        return "".join(self.text_parts)


class StreamExtractor:
    """Tee an Anthropic SSE response. Bytes in, events out.

    Never buffers or delays the passthrough stream — callers forward the chunk
    first and hand a reference to this object second.
    """

    def __init__(
        self,
        *,
        session_id: str,
        model: str | None,
        trace_id: str = "",
        span_id: str = "",
        parent_span_id: str | None = None,
        continues_from: str | None = None,
    ) -> None:
        self.session_id = session_id
        self.model = model
        self.trace_id = trace_id
        self.span_id = span_id
        self.parent_span_id = parent_span_id
        self.continues_from = continues_from
        self._buf = bytearray()
        self._data_lines: list[str] = []
        self._event_name: str | None = None
        self._blocks: dict[int, _Block] = {}
        self._message_started = False
        self._message_stopped = False
        self._stop_reason: str | None = None
        self._usage: dict[str, Any] = {}
        self._closed = False

    def _make(self, **kwargs: Any) -> PartialEvent:
        """``_make_event`` pre-bound to this stream's trace context."""
        return _make_event(
            trace_id=self.trace_id,
            span_id=self.span_id,
            parent_span_id=self.parent_span_id,
            continues_from=self.continues_from,
            **kwargs,
        )

    # -- public API ---------------------------------------------------------

    def feed(self, chunk: bytes) -> list[PartialEvent]:
        """Parse whatever complete SSE lines ``chunk`` completes.

        Safe against arbitrary chunk boundaries: incomplete lines (and
        incomplete UTF-8 sequences within them) stay in the buffer until the
        bytes that finish them arrive.
        """
        if self._closed or not chunk:
            return []
        self._buf.extend(chunk)
        events: list[PartialEvent] = []
        while True:
            nl = self._buf.find(b"\n")
            if nl == -1:
                break
            raw = bytes(self._buf[:nl])
            del self._buf[: nl + 1]
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            events.extend(self._handle_line(raw.decode("utf-8", errors="replace")))
        return events

    def close(self) -> list[PartialEvent]:
        """Stream truncated or client disconnected.

        Emits a ``stream_aborted`` marker for every content block that never
        received ``content_block_stop``, carrying whatever partial JSON or text
        accumulated. Idempotent: a second call returns nothing.
        """
        if self._closed:
            return []
        self._closed = True
        events: list[PartialEvent] = []

        # A trailing line with no newline terminator is still a real line.
        if self._buf:
            raw = bytes(self._buf)
            self._buf.clear()
            if raw.endswith(b"\r"):
                raw = raw[:-1]
            events.extend(self._handle_line(raw.decode("utf-8", errors="replace")))
        # An unterminated final frame still holds data lines worth dispatching.
        if self._data_lines:
            events.extend(self._dispatch())

        if self._blocks:
            for index in sorted(self._blocks):
                block = self._blocks[index]
                events.append(self._aborted_event(block))
            self._blocks.clear()
        elif self._message_started and not self._message_stopped:
            events.append(
                self._make(
                    session_id=self.session_id,
                    kind=KIND_STREAM_ABORTED,
                    payload={
                        "complete": False,
                        "reason": "stream_truncated",
                        "index": None,
                        "stop_reason": self._stop_reason,
                        "usage": dict(self._usage) or None,
                    },
                    model=self.model,
                )
            )
        return events

    # -- SSE line handling --------------------------------------------------

    def _handle_line(self, line: str) -> list[PartialEvent]:
        if line == "":
            return self._dispatch()
        if line.startswith(":"):
            # Comment / heartbeat (e.g. ``: ping``). Not part of any frame.
            return []
        if ":" in line:
            field_name, _, value = line.partition(":")
            if value.startswith(" "):
                value = value[1:]
        else:
            field_name, value = line, ""
        if field_name == "data":
            self._data_lines.append(value)
        elif field_name == "event":
            self._event_name = value
        # ``id``/``retry``/unknown fields carry nothing we record.
        return []

    def _dispatch(self) -> list[PartialEvent]:
        if not self._data_lines:
            self._event_name = None
            return []
        data = "\n".join(self._data_lines)
        event_name = self._event_name
        self._data_lines = []
        self._event_name = None
        if data.strip() == "[DONE]":
            return []
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            return [
                self._make(
                    session_id=self.session_id,
                    kind=KIND_PARSE_FAILURE,
                    payload={
                        "reason": "sse_data_not_json",
                        "event": event_name,
                        "raw": data[:_MAX_RAW_KEEP],
                        "error": str(exc),
                    },
                    model=self.model,
                )
            ]
        if not isinstance(payload, dict):
            return [
                self._make(
                    session_id=self.session_id,
                    kind=KIND_PARSE_FAILURE,
                    payload={
                        "reason": "sse_data_not_object",
                        "event": event_name,
                        "raw": data[:_MAX_RAW_KEEP],
                    },
                    model=self.model,
                )
            ]
        # ``type`` in the data object is authoritative; the ``event:`` line is
        # a duplicate of it and may legally arrive before or after ``data:``.
        return self._handle_event(payload.get("type") or event_name or "", payload)

    # -- Anthropic stream semantics ----------------------------------------

    def _handle_event(self, etype: str, data: dict[str, Any]) -> list[PartialEvent]:
        if etype == "message_start":
            self._message_started = True
            message = data.get("message") or {}
            model = message.get("model")
            if isinstance(model, str) and model:
                self.model = model
            usage = message.get("usage")
            if isinstance(usage, dict):
                self._usage.update(usage)
            return []

        if etype == "content_block_start":
            index = _as_index(data.get("index"))
            if index is None:
                return []
            block = data.get("content_block") or {}
            acc = _Block(
                index=index,
                type=str(block.get("type") or "unknown"),
                id=block.get("id"),
                name=block.get("name"),
            )
            # A tool_use block may (rarely) arrive with a complete input.
            initial = block.get("input")
            if isinstance(initial, dict) and initial:
                acc.json_parts.append(json.dumps(initial))
            text = block.get("text")
            if isinstance(text, str) and text:
                acc.text_parts.append(text)
            self._blocks[index] = acc
            return []

        if etype == "content_block_delta":
            index = _as_index(data.get("index"))
            if index is None:
                return []
            block = self._blocks.get(index)
            if block is None:
                # Delta for a block we never saw start: keep it rather than
                # drop it, so the gap is visible downstream.
                block = _Block(index=index, type="unknown")
                self._blocks[index] = block
            delta = data.get("delta") or {}
            dtype = delta.get("type")
            if dtype == "input_json_delta":
                part = delta.get("partial_json")
                if isinstance(part, str):
                    block.json_parts.append(part)
            elif dtype == "text_delta":
                part = delta.get("text")
                if isinstance(part, str):
                    block.text_parts.append(part)
            # thinking/signature deltas are not recorded content.
            return []

        if etype == "content_block_stop":
            index = _as_index(data.get("index"))
            if index is None:
                return []
            block = self._blocks.pop(index, None)
            if block is None:
                return []
            return self._complete_block(block)

        if etype == "message_delta":
            delta = data.get("delta") or {}
            stop_reason = delta.get("stop_reason")
            if isinstance(stop_reason, str):
                self._stop_reason = stop_reason
            usage = data.get("usage")
            if isinstance(usage, dict):
                self._usage.update(usage)
            return []

        if etype == "message_stop":
            self._message_stopped = True
            return []

        if etype == "error":
            error = data.get("error") or {}
            return [
                self._make(
                    session_id=self.session_id,
                    kind=EventKind.API_ERROR,
                    payload={
                        "error_type": error.get("type"),
                        "message": error.get("message"),
                        "raw": error,
                    },
                    model=self.model,
                )
            ]

        # ping and any future event type: nothing to record.
        return []

    def _complete_block(self, block: _Block) -> list[PartialEvent]:
        if block.type == "tool_use":
            return [self._tool_use_event(block)]
        if block.type == "unknown":
            # We never saw a content_block_start for this index (dropped or
            # reordered SSE frame), so we don't know whether it was really
            # text or tool_use. If it accumulated JSON fragments (the
            # tool_use shape), the text-based path below would silently
            # discard it — text_parts is empty for a tool-input block. Surface
            # it as a parse_failure instead: the input is a finding for the
            # examiner, never a silent drop.
            if block.json_parts:
                return [self._unknown_block_event(block)]
            text = block.text()
            if not text:
                return []
            return [
                self._make(
                    session_id=self.session_id,
                    kind=EventKind.MESSAGE,
                    payload={"index": block.index, "text": text, "complete": True},
                    model=self.model,
                )
            ]
        if block.type == "text":
            text = block.text()
            if not text:
                return []
            return [
                self._make(
                    session_id=self.session_id,
                    kind=EventKind.MESSAGE,
                    payload={"index": block.index, "text": text, "complete": True},
                    model=self.model,
                )
            ]
        return []

    def _unknown_block_event(self, block: _Block) -> PartialEvent:
        """A block that accumulated content but whose ``content_block_start``
        was never observed (missing or reordered SSE frame). Its real type —
        text vs tool_use — cannot be determined, so this is recorded as a
        parse failure carrying the raw accumulated JSON rather than silently
        dropped or misfiled as an empty text block."""
        raw = block.partial_json()
        return self._make(
            session_id=self.session_id,
            kind=EventKind.PARSE_FAILURE,
            payload={
                "index": block.index,
                "block_type": block.type,
                "complete": False,
                "reason": "content_block_start_missing",
                "input_raw": raw[:_MAX_RAW_KEEP],
            },
            model=self.model,
            tool_use_id=block.id,
            tool_name=block.name,
        )

    def _tool_use_event(self, block: _Block) -> PartialEvent:
        raw = block.partial_json()
        payload: dict[str, Any] = {
            "index": block.index,
            "id": block.id,
            "name": block.name,
            "complete": True,
        }
        parsed, error = _parse_tool_input(raw)
        if error is None:
            payload["input"] = parsed
        else:
            # Never drop the event: record the raw accumulation and mark it.
            payload["input"] = None
            payload["input_raw"] = raw[:_MAX_RAW_KEEP]
            payload["malformed_input"] = True
            payload["parse_error"] = error
        return self._make(
            session_id=self.session_id,
            kind=EventKind.TOOL_USE,
            payload=payload,
            model=self.model,
            tool_use_id=block.id,
            tool_name=block.name,
        )

    def _aborted_event(self, block: _Block) -> PartialEvent:
        payload: dict[str, Any] = {
            "index": block.index,
            "block_type": block.type,
            "complete": False,
            "reason": "stream_truncated",
            "id": block.id,
            "name": block.name,
        }
        if block.type == "tool_use" or block.json_parts:
            payload["partial_json"] = block.partial_json()[:_MAX_RAW_KEEP]
        if block.text_parts:
            payload["partial_text"] = block.text()[:_MAX_RAW_KEEP]
        return self._make(
            session_id=self.session_id,
            kind=KIND_STREAM_ABORTED,
            payload=payload,
            model=self.model,
            tool_use_id=block.id,
            tool_name=block.name,
        )


def _as_index(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _parse_tool_input(raw: str) -> tuple[dict[str, Any] | None, str | None]:
    """Parse accumulated ``partial_json``. Empty input means ``{}`` (no args)."""
    if raw.strip() == "":
        return {}, None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, str(exc)
    if not isinstance(parsed, dict):
        return None, f"tool input is {type(parsed).__name__}, expected object"
    return parsed, None


# -- non-streaming paths ----------------------------------------------------


def extract_request_events(
    body: dict,
    *,
    session_id: str,
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str | None = None,
    continues_from: str | None = None,
) -> list[PartialEvent]:
    """Pull ``tool_result`` blocks out of the LAST user message.

    Anthropic allows ``content`` to be a bare string or a list of blocks, at
    both the message level and inside a ``tool_result`` block; both shapes are
    preserved as-is in the payload.
    """
    if not isinstance(body, dict):
        return []
    messages = body.get("messages")
    if not isinstance(messages, list):
        return []
    last_user = None
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            last_user = message
            break
    if last_user is None:
        return []
    content = last_user.get("content")
    if not isinstance(content, list):
        # A string-content user message carries no tool results.
        return []

    model = body.get("model") if isinstance(body.get("model"), str) else None
    events: list[PartialEvent] = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "tool_result":
            continue
        tool_use_id = block.get("tool_use_id")
        events.append(
            _make_event(
                session_id=session_id,
                kind=EventKind.TOOL_RESULT,
                payload={
                    "tool_use_id": tool_use_id,
                    "content": block.get("content"),
                    "is_error": bool(block.get("is_error", False)),
                },
                model=model,
                tool_use_id=tool_use_id if isinstance(tool_use_id, str) else None,
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_span_id,
                continues_from=continues_from,
            )
        )
    return events


def extract_response_events(
    body: dict,
    *,
    session_id: str,
    trace_id: str = "",
    span_id: str = "",
    parent_span_id: str | None = None,
    continues_from: str | None = None,
) -> list[PartialEvent]:
    """Non-streaming JSON response body -> ``tool_use`` / ``message`` events."""
    if not isinstance(body, dict):
        return []
    model = body.get("model") if isinstance(body.get("model"), str) else None

    if body.get("type") == "error":
        error = body.get("error") or {}
        return [
            _make_event(
                session_id=session_id,
                kind=EventKind.API_ERROR,
                payload={
                    "error_type": error.get("type") if isinstance(error, dict) else None,
                    "message": error.get("message") if isinstance(error, dict) else None,
                    "raw": error,
                },
                model=model,
                trace_id=trace_id,
                span_id=span_id,
                parent_span_id=parent_span_id,
                continues_from=continues_from,
            )
        ]

    content = body.get("content")
    if not isinstance(content, list):
        return []
    events: list[PartialEvent] = []
    for index, block in enumerate(content):
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "tool_use":
            tool_use_id = block.get("id")
            payload_input = block.get("input")
            events.append(
                _make_event(
                    session_id=session_id,
                    kind=EventKind.TOOL_USE,
                    payload={
                        "index": index,
                        "id": tool_use_id,
                        "name": block.get("name"),
                        "input": payload_input if isinstance(payload_input, dict) else {},
                        "complete": True,
                    },
                    model=model,
                    tool_use_id=tool_use_id if isinstance(tool_use_id, str) else None,
                    tool_name=block.get("name") if isinstance(block.get("name"), str) else None,
                    trace_id=trace_id,
                    span_id=span_id,
                    parent_span_id=parent_span_id,
                    continues_from=continues_from,
                )
            )
        elif btype == "text":
            text = block.get("text")
            if isinstance(text, str) and text:
                events.append(
                    _make_event(
                        session_id=session_id,
                        kind=EventKind.MESSAGE,
                        payload={"index": index, "text": text, "complete": True},
                        model=model,
                        trace_id=trace_id,
                        span_id=span_id,
                        parent_span_id=parent_span_id,
                        continues_from=continues_from,
                    )
                )
    return events
