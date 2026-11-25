"""Amazon Bedrock model-invocation log records -> recorder events (W10, Path 6).

Pure: no AWS SDK, no I/O, no clock. :mod:`byoai.recorder.bedrock_invocation_log_source` reads
the log and calls :func:`normalize` once per record, in timestamp order.

A ``ModelInvocationLog`` record is one model call as AWS logged it: the request body, the
response body, who called, when. Converse bodies are rewritten into the Anthropic Messages shape
and handed to the same extractors every other path uses, so a tool call reads the same in the
ledger whichever way it was captured. What is sealed:

- ``tool_use`` and ``message`` from the response, ``tool_result`` from the request's LAST user
  message (the history in earlier messages was sealed from the call that produced it);
- one ``session_start`` per run, naming the tools offered and a digest of their configuration;
- ``guardrail_intervention`` (policy names only) and ``api_error`` when the record says so.

Prompts and system text are never sealed. Every event carries ``provider`` =
``bedrock_invocation_log``, so it never reads as captured on the host.

Ids are derived from the record (:func:`deterministic_id`), so reading the same record twice, on
any machine, gives the same events. A tool result joins the run of the call it answers only
when the call came from the same account, region and caller, within the link limit; otherwise
it starts its own run, marked ``linked: false``, and the verifier reports it as an orphan.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Protocol

from .bedrock_agent import guardrail_categories
from .canonical import canonicalize
from .extract import PartialEvent, StreamExtractor, extract_request_events, extract_response_events
from .schema import EventKind, format_ts_device

__all__ = [
    "PROVIDER",
    "SCOPE_ALL_CALLS",
    "SCOPE_TOOL_CALLS",
    "IndexedCall",
    "InvocationRecord",
    "LinkIndex",
    "MemoryLinkIndex",
    "Normalized",
    "RecordRejected",
    "classify_shape",
    "deterministic_id",
    "normalize",
    "parse_record",
    "principal_arn",
]

PROVIDER = "bedrock_invocation_log"
SCHEMA_TYPE = "ModelInvocationLog"
SCOPE_TOOL_CALLS = "tool_calls"
SCOPE_ALL_CALLS = "all_calls"

SHAPE_CONVERSE = "converse"
SHAPE_ANTHROPIC = "anthropic_messages"
SHAPE_CONVERSE_STREAM = "converse_stream_events"
SHAPE_ANTHROPIC_STREAM = "anthropic_stream_events"

#: Bedrock's own tool-name pattern. `tools_offered` keeps only names that match it, which is
#: what lets that field pass through REDACTED mode (redact.py, W10 §7.2).
TOOL_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")
#: Caller-supplied requestMetadata is copied bounded, never trusted (same bounds as Coriqo's
#: discovery adapter for this log).
MAX_TAGS = 10
MAX_TAG_VALUE = 64

_CONVERSE_STREAM_KEYS = frozenset(
    {
        "messageStart",
        "contentBlockStart",
        "contentBlockDelta",
        "contentBlockStop",
        "messageStop",
        "metadata",
    }
)
_ANTHROPIC_STREAM_TYPES = frozenset(
    {
        "message_start",
        "content_block_start",
        "content_block_delta",
        "content_block_stop",
        "message_delta",
        "message_stop",
        "ping",
        "error",
    }
)
_ERROR_STOP_REASONS = frozenset({"malformed_tool_use", "malformed_model_output"})
_GEO_PREFIXES = ("us.", "eu.", "apac.", "us-gov.", "global.", "ca.", "jp.", "au.")


class RecordRejected(Exception):
    """A log line that is not a usable invocation record. ``counter`` names the status counter."""

    def __init__(self, counter: str) -> None:
        super().__init__(counter)
        self.counter = counter


def principal_arn(arn: str | None) -> str | None:
    """The caller: an assumed-role ARN without its session name. Ported from Coriqo's discovery
    adapter for this log (api/domains/discovery/log_adapters/aws_bedrock_invocation.py), so both
    features name a caller the same way. Other ARN shapes are returned unchanged."""
    if not arn or ":" not in arn:
        return arn
    head, resource = arn.rsplit(":", 1)
    if resource.startswith("assumed-role/"):
        parts = resource.split("/")
        if len(parts) > 2:
            return f"{head}:{'/'.join(parts[:2])}"
    return arn


def deterministic_id(account: str, region: str, *parts: Any) -> str:
    """Hex sha256 of the canonical JSON of the id's parts, namespaced to this source."""
    return hashlib.sha256(
        canonicalize(["bedrock_invocation_log", "v1", account, region, *parts])
    ).hexdigest()


@dataclass(frozen=True)
class InvocationRecord:
    """One parsed log record. Bodies are None until read (inline, or from S3 by the source)."""

    raw_message: str
    request_id: str
    timestamp: datetime
    account_id: str
    region: str
    operation: str
    model_id: str | None
    principal: str | None
    request_metadata: dict[str, str]
    schema_version: str | None
    input_body: Any = None
    output_body: Any = None
    input_s3_path: str | None = None
    output_s3_path: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    error_code: str | None = None
    ingestion_ms: int | None = None

    @property
    def ts_ms(self) -> int:
        return int(self.timestamp.timestamp() * 1000)

    @property
    def ts_ns(self) -> int:
        return int(self.timestamp.timestamp()) * 1_000_000_000 + self.timestamp.microsecond * 1000


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _tags(meta: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if not isinstance(meta, dict):
        return out
    for key, value in meta.items():
        if len(out) >= MAX_TAGS:
            break
        if isinstance(value, bool) or not isinstance(value, str | int | float):
            continue
        out[str(key)[:MAX_TAG_VALUE]] = str(value)[:MAX_TAG_VALUE]
    return out


def parse_record(message: str, *, ingestion_ms: int | None = None) -> InvocationRecord:
    """One CloudWatch message -> record. Raises :class:`RecordRejected` with the counter name."""
    try:
        data = json.loads(message)
    except (TypeError, ValueError):
        raise RecordRejected("not_json") from None
    if not isinstance(data, dict) or data.get("schemaType") != SCHEMA_TYPE:
        raise RecordRejected("not_invocation_log")
    request_id = data.get("requestId")
    timestamp = _parse_timestamp(data.get("timestamp"))
    if not isinstance(request_id, str) or not request_id or timestamp is None:
        raise RecordRejected("malformed")
    side_in = data.get("input") if isinstance(data.get("input"), dict) else {}
    side_out = data.get("output") if isinstance(data.get("output"), dict) else {}
    identity = data.get("identity") if isinstance(data.get("identity"), dict) else {}
    return InvocationRecord(
        raw_message=message,
        request_id=request_id,
        timestamp=timestamp.astimezone(timezone.utc),
        account_id=str(data.get("accountId") or ""),
        region=str(data.get("region") or ""),
        operation=str(data.get("operation") or ""),
        model_id=data.get("modelId") if isinstance(data.get("modelId"), str) else None,
        principal=principal_arn(
            identity.get("arn") if isinstance(identity.get("arn"), str) else None
        ),
        request_metadata=_tags(data.get("requestMetadata")),
        schema_version=data.get("schemaVersion")
        if isinstance(data.get("schemaVersion"), str)
        else None,
        input_body=side_in.get("inputBodyJson"),
        output_body=side_out.get("outputBodyJson"),
        input_s3_path=side_in.get("inputBodyS3Path")
        if isinstance(side_in.get("inputBodyS3Path"), str)
        else None,
        output_s3_path=side_out.get("outputBodyS3Path")
        if isinstance(side_out.get("outputBodyS3Path"), str)
        else None,
        input_tokens=_int(side_in.get("inputTokenCount")),
        output_tokens=_int(side_out.get("outputTokenCount")),
        error_code=data.get("errorCode") if isinstance(data.get("errorCode"), str) else None,
        ingestion_ms=ingestion_ms,
    )


def _model_family(model_id: str | None) -> str:
    name = (model_id or "unknown").split(":", 1)[0]
    for prefix in _GEO_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name.split("-", 1)[0]


def _is_converse_block_list(content: Any) -> bool:
    return isinstance(content, list) and all(
        isinstance(b, dict) and "type" not in b for b in content
    )


def classify_shape(record: InvocationRecord) -> str | None:
    """The body shape this record can be read as, or None when unsupported (Titan, Llama or Nova
    native bodies, embeddings, images). Decided from the bodies, not from the model id alone."""
    inp, out = record.input_body, record.output_body
    if isinstance(out, list):
        items = [i for i in out if isinstance(i, dict)]
        if items and any(_CONVERSE_STREAM_KEYS & i.keys() for i in items):
            return SHAPE_CONVERSE_STREAM
        if items and all("chunk" in i or i.get("type") in _ANTHROPIC_STREAM_TYPES for i in items):
            return SHAPE_ANTHROPIC_STREAM
        return None
    if isinstance(inp, dict) and "anthropic_version" in inp:
        return SHAPE_ANTHROPIC
    if isinstance(out, dict) and out.get("type") == "message":
        return SHAPE_ANTHROPIC
    if isinstance(out, dict) and isinstance(out.get("output"), dict) and "message" in out["output"]:
        return SHAPE_CONVERSE
    if isinstance(inp, dict) and isinstance(inp.get("messages"), list):
        contents = [m.get("content") for m in inp["messages"] if isinstance(m, dict)]
        if contents and all(_is_converse_block_list(c) for c in contents):
            return SHAPE_CONVERSE
        if contents and any(
            isinstance(c, list) and any(isinstance(b, dict) and "type" in b for b in c)
            for c in contents
        ):
            return SHAPE_ANTHROPIC
    return None


def unsupported_label(record: InvocationRecord) -> str:
    return f"{record.operation or 'unknown'}:{_model_family(record.model_id)}"


# -- linking -------------------------------------------------------------------


@dataclass
class IndexedCall:
    """A tool call the reader has sealed, kept so a later record's result can join its run."""

    tool_use_id: str
    account: str
    region: str
    principal: str | None
    ts_ms: int
    request_id: str
    session_id: str
    trace_id: str
    span_id: str
    tool_name: str | None
    result_seen: bool = False


class LinkIndex(Protocol):
    def get(self, tool_use_id: str) -> IndexedCall | None: ...
    def put(self, call: IndexedCall) -> None: ...
    def mark_result_seen(self, tool_use_id: str) -> None: ...


class MemoryLinkIndex:
    """An in-memory :class:`LinkIndex` (tests; the source keeps its own in SQLite)."""

    def __init__(self) -> None:
        self.calls: dict[str, IndexedCall] = {}

    def get(self, tool_use_id: str) -> IndexedCall | None:
        return self.calls.get(tool_use_id)

    def put(self, call: IndexedCall) -> None:
        self.calls.setdefault(call.tool_use_id, call)

    def mark_result_seen(self, tool_use_id: str) -> None:
        if tool_use_id in self.calls:
            self.calls[tool_use_id].result_seen = True


# -- translation ---------------------------------------------------------------


def _last_user_message(messages: Any) -> dict | None:
    if not isinstance(messages, list):
        return None
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            return message
    return None


def _converse_request(inp: Any) -> dict:
    """Converse request -> an Anthropic-shaped body holding only the last user message's tool
    results. `content` is kept verbatim: the digest commits to what the log said."""
    last = _last_user_message(inp.get("messages") if isinstance(inp, dict) else None)
    blocks: list[dict] = []
    for block in (last or {}).get("content") or []:
        result = block.get("toolResult") if isinstance(block, dict) else None
        if isinstance(result, dict):
            blocks.append(
                {
                    "type": "tool_result",
                    "tool_use_id": result.get("toolUseId"),
                    "content": result.get("content"),
                    "is_error": result.get("status") == "error",
                }
            )
    return {"messages": [{"role": "user", "content": blocks}]} if blocks else {"messages": []}


@dataclass
class _Response:
    body: dict
    stop_reason: str | None
    server_tool_ids: set[str] = field(default_factory=set)
    dropped_blocks: int = 0
    trace: Any = None


def _converse_response(out: Any) -> _Response:
    if not isinstance(out, dict):
        return _Response({"content": []}, None)
    message = (
        (out.get("output") or {}).get("message") if isinstance(out.get("output"), dict) else None
    )
    content: list[dict] = []
    server: set[str] = set()
    dropped = 0
    for block in (message or {}).get("content") or []:
        if not isinstance(block, dict):
            continue
        if "text" in block:
            content.append({"type": "text", "text": block.get("text")})
        elif isinstance(block.get("toolUse"), dict):
            use = block["toolUse"]
            content.append(
                {
                    "type": "tool_use",
                    "id": use.get("toolUseId"),
                    "name": use.get("name"),
                    "input": use.get("input"),
                }
            )
            if use.get("type") == "server_tool_use" and isinstance(use.get("toolUseId"), str):
                server.add(use["toolUseId"])
        else:
            # reasoningContent, images, documents and the rest are not sealed (as Path 3 does
            # not seal the model's scratchpad); the count says they were there.
            content.append({"type": "dropped"})
            dropped += 1
    stop = out.get("stopReason") if isinstance(out.get("stopReason"), str) else None
    return _Response({"content": content}, stop, server, dropped, out.get("trace"))


def _anthropic_response(out: Any) -> _Response:
    if not isinstance(out, dict):
        return _Response({"content": []}, None)
    stop = out.get("stop_reason") if isinstance(out.get("stop_reason"), str) else None
    return _Response(out, stop)


def _sse(event: dict) -> bytes:
    return f"event: {event.get('type', '')}\ndata: {json.dumps(event)}\n\n".encode()


def _converse_stream_as_sse(events: list) -> Iterable[bytes]:
    """Converse stream events -> Anthropic SSE frames, so the one StreamExtractor does the
    accumulation, tool-input parsing and abort handling for both shapes."""
    opened: set[int] = set()
    for item in events:
        if not isinstance(item, dict):
            continue
        if "messageStart" in item:
            yield _sse({"type": "message_start", "message": {"role": "assistant", "content": []}})
        elif "contentBlockStart" in item:
            start = item["contentBlockStart"] or {}
            index = start.get("contentBlockIndex", 0)
            use = (start.get("start") or {}).get("toolUse") or {}
            opened.add(index)
            yield _sse(
                {
                    "type": "content_block_start",
                    "index": index,
                    "content_block": {
                        "type": "tool_use",
                        "id": use.get("toolUseId"),
                        "name": use.get("name"),
                        "input": {},
                    },
                }
            )
        elif "contentBlockDelta" in item:
            delta_block = item["contentBlockDelta"] or {}
            index = delta_block.get("contentBlockIndex", 0)
            delta = delta_block.get("delta") or {}
            if "text" in delta:
                if index not in opened:
                    opened.add(index)
                    yield _sse(
                        {
                            "type": "content_block_start",
                            "index": index,
                            "content_block": {"type": "text", "text": ""},
                        }
                    )
                yield _sse(
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {"type": "text_delta", "text": delta.get("text") or ""},
                    }
                )
            elif isinstance(delta.get("toolUse"), dict):
                yield _sse(
                    {
                        "type": "content_block_delta",
                        "index": index,
                        "delta": {
                            "type": "input_json_delta",
                            "partial_json": delta["toolUse"].get("input") or "",
                        },
                    }
                )
        elif "contentBlockStop" in item:
            index = (item["contentBlockStop"] or {}).get("contentBlockIndex", 0)
            opened.discard(index)
            yield _sse({"type": "content_block_stop", "index": index})
        elif "messageStop" in item:
            stop = (item["messageStop"] or {}).get("stopReason")
            yield _sse({"type": "message_delta", "delta": {"stop_reason": stop}})
            yield _sse({"type": "message_stop"})


def _id_slot(kind: str, tool_use_id: Any, position: Any) -> str:
    """The slot an event id is derived from. A block's own id keeps the slot stable across
    re-reads; a block without one falls back to its position, so two such blocks in one
    record do not collide on the same event id."""
    if isinstance(tool_use_id, str) and tool_use_id:
        return f"{kind}:{tool_use_id}"
    return f"{kind}:#{position}"


def _anthropic_stream_as_sse(
    events: list, on_undecodable: Callable[[], None] = lambda: None
) -> Iterable[bytes]:
    for item in events:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("chunk"), dict) and "bytes" in item["chunk"]:
            try:
                item = json.loads(base64.b64decode(item["chunk"]["bytes"]))
            except (ValueError, TypeError):
                # A chunk that does not decode may have held a tool use: count it so the
                # status says a part of this stream was not read.
                on_undecodable()
                continue
            if not isinstance(item, dict):
                continue
        yield _sse(item)


def _stream_stop_reason(events: list) -> str | None:
    for item in events:
        if isinstance(item, dict):
            stop = (
                (item.get("messageStop") or {}).get("stopReason")
                if isinstance(item.get("messageStop"), dict)
                else None
            )
            if isinstance(stop, str):
                return stop
            if item.get("type") == "message_delta":
                stop = (item.get("delta") or {}).get("stop_reason")
                if isinstance(stop, str):
                    return stop
    return None


# -- normalise one record ---------------------------------------------------------------


@dataclass
class Normalized:
    """What one record produced: events to seal, in order, and counters for the status."""

    partials: list[PartialEvent] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)
    in_scope: bool = True

    def count(self, name: str, n: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + n


def _cited_tool_use_ids(request: dict) -> list[str]:
    """Tool-use ids the request's last user message answers, in message order."""
    last = _last_user_message(request.get("messages"))
    return [
        b["tool_use_id"]
        for b in (last or {}).get("content") or []
        if isinstance(b, dict)
        and b.get("type") == "tool_result"
        and isinstance(b.get("tool_use_id"), str)
    ]


def _tool_config(inp: Any, shape: str) -> tuple[Any, list[str], str | None, int]:
    """(config to digest, tool names offered, tool choice, names dropped for the pattern)."""
    if not isinstance(inp, dict):
        return None, [], None, 0
    if shape in (SHAPE_CONVERSE, SHAPE_CONVERSE_STREAM):
        config = inp.get("toolConfig") if isinstance(inp.get("toolConfig"), dict) else None
        tools = (config or {}).get("tools") or []
        names = [
            ((t or {}).get("toolSpec") or {}).get("name") for t in tools if isinstance(t, dict)
        ]
        choice = (config or {}).get("toolChoice")
        choice_name = next(iter(choice), None) if isinstance(choice, dict) and choice else None
    else:
        config = inp.get("tools") if isinstance(inp.get("tools"), list) else None
        names = [t.get("name") for t in (config or []) if isinstance(t, dict)]
        choice = inp.get("tool_choice")
        choice_name = choice.get("type") if isinstance(choice, dict) else None
    kept = [n for n in names if isinstance(n, str) and TOOL_NAME_RE.match(n)]
    return config, kept, choice_name, len(names) - len(kept)


def _flatten_assessments(value: Any) -> list:
    """Converse nests guardrail assessments by guardrail id (and a list per id on output)."""
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        out: list = []
        for v in value.values():
            out.extend(v if isinstance(v, list) else [v])
        return out
    return []


def _acted(assessments: list) -> bool:
    """Whether any policy item in these assessments blocked or masked something."""
    for assessment in assessments:
        for policy in assessment.values() if isinstance(assessment, dict) else ():
            for items in policy.values() if isinstance(policy, dict) else ():
                for item in items if isinstance(items, list) else ():
                    if isinstance(item, dict) and item.get("action") in ("BLOCKED", "ANONYMIZED"):
                        return True
    return False


def _guardrail(trace: Any, stop_reason: str | None) -> dict | None:
    guardrail = trace.get("guardrail") if isinstance(trace, dict) else None
    inputs = _flatten_assessments((guardrail or {}).get("inputAssessment"))
    outputs = _flatten_assessments((guardrail or {}).get("outputAssessments"))
    if not (stop_reason == "guardrail_intervened" or _acted(inputs + outputs)):
        return None
    stage = (
        "input"
        if inputs and not outputs
        else "output"
        if outputs and not inputs
        else ("input_output" if inputs else None)
    )
    return {
        "action": "INTERVENED",
        "stage": stage,
        "categories": guardrail_categories(inputs + outputs),
        "input_assessments": len(inputs),
        "output_assessments": len(outputs),
    }


def normalize(
    record: InvocationRecord,
    *,
    index: LinkIndex,
    scope: str = SCOPE_TOOL_CALLS,
    link_gap_minutes: int = 60,
    log_group: str | None = None,
    reader_config_sha256: str | None = None,
) -> Normalized:
    """The events one record seals, linked into the run its tool results answer.

    The record's bodies must already be resolved (inline or read from S3). An unsupported shape
    or an out-of-scope call produces no events, only a counter.
    """
    result = Normalized()
    shape = classify_shape(record)
    # Bedrock logs a call it refused (throttled, invalid, not found) with its errorCode and no
    # bodies at all. There is no shape to read, but the failed call is still evidence, in either
    # scope, because nothing in the record says whether it would have used a tool.
    bodiless_error = (
        shape is None
        and record.error_code is not None
        and record.input_body is None
        and record.output_body is None
    )
    if shape is None and not bodiless_error:
        result.in_scope = False
        result.count(f"unsupported_shape:{unsupported_label(record)}")
        return result

    inp = record.input_body
    if shape in (SHAPE_CONVERSE, SHAPE_CONVERSE_STREAM):
        request = _converse_request(inp)
    else:
        request = inp if isinstance(inp, dict) else {"messages": []}
    streamed = shape in (SHAPE_CONVERSE_STREAM, SHAPE_ANTHROPIC_STREAM)
    if shape == SHAPE_CONVERSE:
        response = _converse_response(record.output_body)
    elif shape == SHAPE_ANTHROPIC:
        response = _anthropic_response(record.output_body)
    else:
        response = _Response({"content": []}, _stream_stop_reason(record.output_body or []))

    config, tools_offered, tool_choice, names_dropped = _tool_config(inp, shape)
    tool_config_sha256 = hashlib.sha256(canonicalize(config)).hexdigest() if config else None
    cited = _cited_tool_use_ids(request)
    response_calls = [
        b
        for b in response.body.get("content") or []
        if isinstance(b, dict) and b.get("type") == "tool_use"
    ]
    stream_has_tools = streamed and any(
        isinstance(i, dict)
        and (
            ((i.get("contentBlockStart") or {}).get("start") or {}).get("toolUse")
            or (i.get("content_block") or {}).get("type") == "tool_use"
        )
        for i in record.output_body or []
    )
    if scope == SCOPE_TOOL_CALLS and not (
        config or cited or response_calls or stream_has_tools or bodiless_error
    ):
        result.in_scope = False
        result.count("out_of_scope")
        return result

    # Which run this record belongs to.
    gap_ms = link_gap_minutes * 60_000
    linked_call: IndexedCall | None = None
    refusals: dict[str, str] = {}
    calls_for: dict[str, IndexedCall] = {}
    for tool_use_id in cited:
        candidate = index.get(tool_use_id)
        if candidate is None:
            result.count("results_without_call")
            continue
        if (candidate.account, candidate.region, candidate.principal) != (
            record.account_id,
            record.region,
            record.principal,
        ):
            refusals[tool_use_id] = "caller"
        elif not 0 <= record.ts_ms - candidate.ts_ms <= gap_ms:
            refusals[tool_use_id] = "time"
        else:
            calls_for[tool_use_id] = candidate
            if linked_call is None:
                linked_call = candidate
            elif candidate.session_id != linked_call.session_id:
                result.count("link_conflicts")
            continue
        result.count("links_refused")

    account, region, rid = record.account_id, record.region, record.request_id
    if linked_call is not None:
        session_id, trace_id, span_id = (
            linked_call.session_id,
            linked_call.trace_id,
            linked_call.span_id,
        )
    else:
        session_id = f"bil_{rid}"[:128]
        trace_id = "tr_" + deterministic_id(account, region, "trace", rid)[:32]
        span_id = "sp_" + deterministic_id(account, region, "span", rid)[:32]

    log_record_sha256 = hashlib.sha256(record.raw_message.encode("utf-8")).hexdigest()
    ts_device = format_ts_device(record.timestamp)

    def seal(partial: PartialEvent, slot: str, order: int, extra: dict[str, Any]) -> PartialEvent:
        payload = {
            **partial.payload,
            **extra,
            "request_id": rid,
            "log_record_sha256": log_record_sha256,
        }
        return replace(
            partial,
            provider=PROVIDER,
            model=record.model_id,
            session_id=session_id,
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=None,
            continues_from=None,
            ts_device=ts_device,
            ts_monotonic_ns=record.ts_ns + max(order, 0),
            payload=payload,
            event_id="evt_" + deterministic_id(account, region, rid, slot)[:32],
        )

    base = PartialEvent(
        session_id=session_id,
        kind="",
        ts_device=ts_device,
        ts_monotonic_ns=record.ts_ns,
        tool_use_id=None,
        tool_name=None,
        payload={},
        model=record.model_id,
    )

    if linked_call is None:
        start_payload: dict[str, Any] = {
            "source": PROVIDER,
            "operation": record.operation,
            "account_id": account,
            "region": region,
            "principal_arn": record.principal,
            "model_id": record.model_id,
            "log_group": log_group,
            "tools_offered": tools_offered,
            "tool_choice": tool_choice,
            "tool_config_sha256": tool_config_sha256,
            "request_metadata": record.request_metadata,
            "log_schema_version": record.schema_version,
            "reader_config_sha256": reader_config_sha256,
            "linked": False,
        }
        if refusals:
            start_payload["link_refused"] = sorted(set(refusals.values()))[0]
        result.partials.append(
            seal(
                replace(base, kind=EventKind.SESSION_START.value), "session_start", 0, start_payload
            )
        )
        if names_dropped:
            result.count("tools_offered_dropped", names_dropped)

    for position, partial in enumerate(extract_request_events(request, session_id=session_id)):
        call = calls_for.get(partial.tool_use_id or "")
        extra: dict[str, Any] = {"linked": call is not None}
        if partial.tool_use_id in refusals:
            extra["link_refused"] = refusals[partial.tool_use_id]
        slot = _id_slot("tool_result", partial.tool_use_id, position)
        sealed = seal(partial, slot, position, extra)
        if call is not None:
            sealed = replace(sealed, tool_name=call.tool_name)
            index.mark_result_seen(call.tool_use_id)
        result.partials.append(sealed)

    stop_reason = response.stop_reason
    if streamed:
        extractor = StreamExtractor(session_id=session_id, model=record.model_id)
        frames = (
            _converse_stream_as_sse(record.output_body)
            if shape == SHAPE_CONVERSE_STREAM
            else _anthropic_stream_as_sse(
                record.output_body, lambda: result.count("stream_chunks_undecodable")
            )
        )
        response_partials = [
            p for frame in frames for p in extractor.feed(frame)
        ] + extractor.close()
    else:
        response_partials = extract_response_events(response.body, session_id=session_id)
    if response.dropped_blocks:
        result.count("blocks_not_sealed", response.dropped_blocks)

    for partial in response_partials:
        index_in_body = (
            partial.payload.get("index") if isinstance(partial.payload.get("index"), int) else 0
        )
        extra = {"stop_reason": stop_reason}
        if partial.kind == EventKind.TOOL_USE.value:
            slot = _id_slot("tool_use", partial.tool_use_id, index_in_body)
            extra["tool_config_sha256"] = tool_config_sha256
            if partial.tool_use_id in response.server_tool_ids:
                extra["executed_by"] = "bedrock"
            if partial.tool_use_id:
                index.put(
                    IndexedCall(
                        tool_use_id=partial.tool_use_id,
                        account=account,
                        region=region,
                        principal=record.principal,
                        ts_ms=record.ts_ms,
                        request_id=rid,
                        session_id=session_id,
                        trace_id=trace_id,
                        span_id=span_id,
                        tool_name=partial.tool_name,
                    )
                )
        elif partial.kind == EventKind.MESSAGE.value:
            slot = f"message:{index_in_body}"
        elif partial.kind == EventKind.API_ERROR.value:
            slot = "api_error"
        else:
            slot = f"{partial.kind}:{index_in_body if index_in_body is not None else 'end'}"
        result.partials.append(seal(partial, slot, 100 + (index_in_body or 0), extra))

    guardrail = _guardrail(response.trace, stop_reason)
    if guardrail is not None:
        result.partials.append(
            seal(
                replace(base, kind=EventKind.GUARDRAIL_INTERVENTION.value),
                "guardrail",
                900,
                guardrail,
            )
        )
    if record.error_code or stop_reason in _ERROR_STOP_REASONS:
        error = (
            {"error_type": "bedrock_invocation_error", "error_code": record.error_code}
            if record.error_code
            else {"error_type": "bedrock_stop_reason", "stop_reason": stop_reason}
        )
        if not any(p.kind == EventKind.API_ERROR.value for p in result.partials):
            result.partials.append(
                seal(replace(base, kind=EventKind.API_ERROR.value), "api_error", 950, error)
            )
        result.count(f"stop_reason:{stop_reason}" if not record.error_code else "error_records")
    return result
