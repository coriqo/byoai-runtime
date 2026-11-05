"""Publishing recorded runs to Coriqo's agent governance API.

The local ledger proves a run happened as recorded. Coriqo is where that
becomes governance: an agent registry, the mandate each agent is allowed to
act under, and a hash-chained trail of what every agent actually did. This
module is the bridge, for any agent anywhere — register once, then publish each
run as a trajectory plus one decision trace per sealed step.

Distinct from :mod:`byoai.recorder.shipper`, which is worth being clear about
since both talk to something called Coriqo:

* ``shipper.py`` syncs the raw device ledger itself (``/v1/ingest/batch``),
  signed and batched, as a verbatim copy of the hash chain. No Coriqo serves
  those endpoints yet.
* this module publishes *governed decisions* to Coriqo's shipped agent API
  (``/api/v1/agents/…``), which exists today. It sends digests and step
  metadata, never raw payloads.

Two properties make what lands in Coriqo evidence rather than telemetry:

* **Ledger-first.** :func:`read_tool_steps` reads sealed rows back out of the
  ledger, so nothing reaches Coriqo that wasn't recorded first.
* **Shared digests.** Each step's ``args_hash``/``result_hash`` are the
  ledger's own ``payload_hash`` values, which commit to the raw, unredacted
  payload whatever ``BYOAI_RECORDER_PAYLOAD_MODE`` is set to, and each trace
  cites its ledger row's ``entry_hash`` as an external grounding anchor. So both
  stores commit to the same bytes: a hash from a Coriqo trace resolves to the
  sealed row it came from, and ``coriqo-verify`` still checks the ledger
  offline. Neither store has to be trusted on its own.

Unlike the shipper, nothing here runs automatically. Session boundaries and
agent identity are application concepts the recorder can't infer — it never
sees where a "run" ends, and under the default redacted payload mode it can't
even read which agent a session belonged to. So the caller drives this
explicitly, and functions here raise on failure rather than swallowing, leaving
the log-and-continue decision to the application that knows whether Coriqo
being down should matter.

Typical wiring::

    creds = CoriqoCredentials.from_env()
    if creds is not None:
        with CoriqoAgentsClient(creds) as client:
            agent_ids = ensure_registered(client, {
                "my-app:my-agent": AgentRegistration(
                    name="My Agent",
                    allowed_tools=("search_docs", "summarize"),
                ),
            })
            # ... after a run completes ...
            publish_session(
                client,
                coriqo_agent_id=agent_ids["my-app:my-agent"],
                ledger=recorder.ledger,
                session_id=run_id,
                payload_mode=recorder.payload_mode,  # thread the recorder's
                                                      # own mode through so
                                                      # final_output follows it
            )
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

import httpx

from byoai.errors import ByoAIError

from .ledger import Ledger
from .receipts import ReceiptStore, canonical_hash
from .redact import PayloadMode, TextRedactor, redact_free_text
from .schema import EventKind

__all__ = [
    "GROUNDING_SYSTEM",
    "GUARDRAIL_CONTROL_SYSTEM",
    "MAX_EXTERNAL_CONTROLS",
    "MAX_TRACE_BATCH",
    "AgentRegistration",
    "AgentSuspendedError",
    "CoriqoAgentsClient",
    "CoriqoAgentsError",
    "CoriqoCredentials",
    "ExternalControlStep",
    "PublishResult",
    "ToolStep",
    "ensure_registered",
    "parse_response",
    "publish_session",
    "send_device_receipts",
    "read_external_controls",
    "read_tool_steps",
    "trace_body",
]

log = logging.getLogger(__name__)

#: Sealed-row fields that hold message text. A receipt carries its payload whole
#: (the seal covers it), so a row with one of these cannot leave the device.
_MESSAGE_TEXT_FIELDS = ("text_redacted", "prompt", "preview", "input_preview",
                        "delta_preview", "output_preview")

_DEFAULT_TIMEOUT = 10.0
_LIST_PAGE_SIZE = 200  # Coriqo caps `limit` at 200 on GET /api/v1/agents.

#: Coriqo's cap on ``/traces/batch``. Longer runs are split across batches.
MAX_TRACE_BATCH = 200
#: Matches Coriqo's own cap on POST .../external-controls. Interventions are
#: rare next to tool calls, so a smaller batch is not a constraint in practice.
MAX_EXTERNAL_CONTROLS = 100
#: Matches Coriqo's cap on POST .../device-receipts.
MAX_DEVICE_RECEIPTS = 200

#: The ``system`` value on the external grounding anchors this module writes, so
#: an auditor reading a Coriqo trace knows which store the cited hash lives in.
GROUNDING_SYSTEM = "byoai-recorder"


class CoriqoAgentsError(ByoAIError, RuntimeError):
    """Any non-2xx from Coriqo, or a response that isn't usable JSON.

    Derives from :class:`~byoai.errors.ByoAIError` like every other runtime
    error, and still from ``RuntimeError`` so code written against the
    original hierarchy keeps catching it.

    ``status_code`` and ``detail`` let a caller branch on a specific failure
    (409 = the agent has no mandate version yet, 403 = the service account is
    missing a role, 422 = a field Coriqo's strict schemas rejected) without
    matching on message text.
    """

    def __init__(self, status_code: int | None, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"Coriqo API error {status_code}: {detail}")


class AgentSuspendedError(CoriqoAgentsError):
    """423: governance has suspended this agent, so Coriqo refuses to record
    anything further for it.

    Worth catching separately, and worth being honest about what it is: a
    governance-level stop, not a live circuit breaker. It prevents new traces
    from being recorded; it cannot stop an agent that has already acted. A
    caller that wants a real kill switch has to enforce it in its own loop.
    """


@dataclass(frozen=True, slots=True)
class CoriqoCredentials:
    """How a machine identity authenticates to Coriqo.

    Coriqo service accounts use two headers rather than a JWT and cannot log in
    to its web UI. The account needs ``governance:approve`` to register agents
    and ``model:write`` to record traces. A deployment that only publishes to
    already-registered agents can hold ``model:write`` alone and skip
    :func:`ensure_registered`, passing known agent ids to
    :func:`publish_session` directly.
    """

    base_url: str
    api_key: str
    tenant_slug: str

    @classmethod
    def from_env(cls) -> CoriqoCredentials | None:
        """Reads ``BYOAI_CORIQO_URL``/``_API_KEY``/``_TENANT_SLUG``.

        Returns ``None`` when the URL is unset, which is how a caller keeps
        Coriqo publishing opt-in. A URL set without the other two is treated as
        a misconfiguration and warned about rather than silently ignored, since
        the likely cause is a typo'd variable name.
        """
        base_url = os.environ.get("BYOAI_CORIQO_URL")
        if not base_url:
            return None
        api_key = os.environ.get("BYOAI_CORIQO_API_KEY")
        tenant_slug = os.environ.get("BYOAI_CORIQO_TENANT_SLUG")
        if not api_key or not tenant_slug:
            log.warning(
                "BYOAI_CORIQO_URL is set but BYOAI_CORIQO_API_KEY/"
                "BYOAI_CORIQO_TENANT_SLUG are not — Coriqo publishing disabled"
            )
            return None
        return cls(base_url=base_url.rstrip("/"), api_key=api_key, tenant_slug=tenant_slug)


@dataclass(frozen=True, slots=True)
class AgentRegistration:
    """What Coriqo needs to put an agent in its registry.

    ``allowed_tools`` is the agent's mandate surface and is enforced on every
    trace: Coriqo flags a recorded call outside it and opens a mandate Finding.
    It has to be the agent's real declared tool set, or ordinary runs will be
    flagged as out-of-mandate. Set ``mandate_enforcement="observe"`` to have
    violations sealed and reported without flagging the trace — useful while
    learning an agent's real tool surface, readable afterwards via Coriqo's
    ``/mandate/observed-tools``.

    ``external_id`` is what makes registration idempotent: re-registering with
    the same one returns the existing agent instead of creating a second copy.
    :func:`ensure_registered` fills it in from the caller's own key when it
    isn't set, so it is rarely worth passing by hand.
    """

    name: str
    mandate: str | None = None
    system: str | None = None
    risk_tier: str | None = None
    allowed_tools: tuple[str, ...] = ()
    owner_id: str | None = None
    external_id: str | None = None
    mandate_enforcement: str | None = None
    use_case: str | None = None

    def to_body(self) -> dict[str, Any]:
        """Coriqo's request schemas are strict (``extra="forbid"``), so this
        sends only fields it declares — never a spare key that would 422."""
        body: dict[str, Any] = {
            "name": self.name,
            "mandate": self.mandate,
            "system": self.system,
            "risk_tier": self.risk_tier,
            "allowed_tools": list(self.allowed_tools),
            "owner_id": self.owner_id,
        }
        if self.external_id is not None:
            body["external_id"] = self.external_id
        if self.mandate_enforcement is not None:
            body["mandate_enforcement"] = self.mandate_enforcement
        if self.use_case is not None:
            body["use_case"] = self.use_case
        return body


@dataclass(frozen=True, slots=True)
class ToolStep:
    """One sealed ``tool_use``/``tool_result`` pair, ready to publish.

    ``args_hash``/``result_hash`` are the ledger's ``payload_hash`` values
    verbatim, and ``entry_hash`` is the ledger row's own chain link. Those
    shared digests are what tie a Coriqo trace back to the sealed row behind
    it. ``result_hash`` is ``None`` for a tool call the ledger has no result
    for, which the offline verifier reports as an unpaired tool_use.
    """

    index: int
    tool_name: str
    args_hash: str
    result_hash: str | None
    entry_hash: str
    occurred_at: str
    latency_ms: int | None


@dataclass(frozen=True, slots=True)
class PublishResult:
    trajectory_id: str
    total_steps: int
    recorded: int
    flagged: int
    status: str
    #: Third-party control events published alongside the steps. Counted
    #: separately from `flagged` on purpose: one is the agent breaching its
    #: mandate, the other is somebody else's control firing, and a caller that
    #: added them together would be reporting a number that means neither.
    external_controls: int = 0
    #: Device receipts Coriqo verified and stored for this run. What did not
    #: land is a finding in the receipt store, not a failed publish.
    device_receipts: int = 0
    #: Steps with no sealed device row to send. Zero when no chain was given.
    device_receipts_missing: int = 0


@dataclass(frozen=True)
class ExternalControlStep:
    """One sealed control event from a system other than the agent's own.

    Today that means a Bedrock guardrail (see
    :mod:`byoai.recorder.bedrock_agent`). It is deliberately NOT a
    :class:`ToolStep`: a tool step is something the agent did, and Coriqo
    checks those against the mandate. A control firing is something done TO the
    agent, under a policy Coriqo has never seen — publishing it as a tool call
    would flag the agent for a control that worked.
    """

    control_system: str
    control_ref: str | None
    action: str
    stage: str | None
    categories: list[dict[str, Any]] | None
    entry_hash: str
    occurred_at: str


#: Guardrail vocabulary -> the action words Coriqo's API accepts. Mapped here
#: rather than passed through, so a vendor renaming its verbs is one line.
_GUARDRAIL_ACTIONS = {"INTERVENED": "intervened", "NONE": "allowed"}

#: Which control system a ``guardrail_intervention`` event came from. Only
#: Bedrock writes this kind today; when a second one does, the event payload
#: will have to name its own system and this constant becomes a fallback.
GUARDRAIL_CONTROL_SYSTEM = "aws.bedrock.guardrail"


def read_external_controls(ledger: Ledger, session_id: str) -> list[ExternalControlStep]:
    """One session's sealed third-party control events, in ledger order.

    Reads the ``categories`` the capture seam already normalized rather than
    re-deriving them from the raw assessments. Two reasons, and the second is
    the one that bites: those raw assessments are redacted in the shipped
    payload under the default ``REDACTED`` mode, so deriving from them here
    published policy names as ``[REDACTED:hash:…]`` — evidence a reviewer
    cannot read, protecting nothing, since the matched text was never in that
    field. ``categories`` survives redaction precisely because
    ``bedrock_agent.guardrail_categories`` guarantees it holds names only.
    """
    steps: list[ExternalControlStep] = []
    for entry in ledger.read_session(session_id):
        event = entry.event
        if event.kind != EventKind.GUARDRAIL_INTERVENTION.value:
            continue
        payload = event.payload or {}
        raw_action = str(payload.get("action") or "INTERVENED").upper()
        categories = payload.get("categories")
        stage = payload.get("stage")
        steps.append(
            ExternalControlStep(
                control_system=GUARDRAIL_CONTROL_SYSTEM,
                control_ref=payload.get("bedrock_trace_id"),
                action=_GUARDRAIL_ACTIONS.get(raw_action, "intervened"),
                stage=stage if stage in ("input", "output") else None,
                categories=categories if isinstance(categories, list) and categories else None,
                entry_hash=entry.entry_hash,
                occurred_at=event.ts_device,
            )
        )
    return steps


# -- reading a run back out of the ledger -----------------------------------


def read_tool_steps(ledger: Ledger, session_id: str) -> list[ToolStep]:
    """Pairs one session's sealed tool calls, in ledger order.

    Pairing is by ``tool_use_id``, since ``tool_name`` is only set on the
    ``tool_use`` side. Latency comes from the monotonic capture clock rather
    than ``ts_device``, which is an untrusted host wall clock that may have
    jumped mid-run.
    """
    entries = ledger.read_session(session_id)
    # Only events that actually carry an id can be paired. extract.py stores
    # tool_use_id=None when a transcript's id field wasn't a string, and
    # without this guard every such event would collide on the None key: the
    # results dict would keep only the last one, and an unrelated malformed
    # tool_use would then be published carrying that result's hash and latency
    # as its own evidence. verify.py's pairing walk guards the same way.
    results = {
        e.event.tool_use_id: e.event
        for e in entries
        if e.event.kind == EventKind.TOOL_RESULT.value and e.event.tool_use_id
    }

    steps: list[ToolStep] = []
    for entry in entries:
        event = entry.event
        if event.kind != EventKind.TOOL_USE.value:
            continue
        result = results.get(event.tool_use_id) if event.tool_use_id else None
        latency_ms = None
        if result is not None:
            elapsed_ns = result.ts_monotonic_ns - event.ts_monotonic_ns
            # A negative delta means the two rows came from different processes
            # and so different monotonic epochs. Report nothing rather than a
            # nonsense duration.
            if elapsed_ns >= 0:
                latency_ms = elapsed_ns // 1_000_000
        steps.append(
            ToolStep(
                index=len(steps),
                tool_name=event.tool_name or "unknown",
                args_hash=event.payload_hash,
                result_hash=result.payload_hash if result is not None else None,
                entry_hash=entry.entry_hash,
                occurred_at=event.ts_device,
                latency_ms=latency_ms,
            )
        )
    return steps


def _as_utc_isoformat(ts_device: str) -> str | None:
    """Ledger timestamps are RFC3339 UTC with microsecond precision.

    Coriqo reads a naive timestamp as already-UTC, so an unparseable value is
    dropped rather than risk sealing a decision hours off.
    """
    try:
        parsed = datetime.strptime(ts_device, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc).isoformat()


def parse_response(response: httpx.Response, *, path: str = "") -> tuple[Any, int]:
    """Turn one Coriqo response into ``(parsed_body, status_code)``, or raise.

    The single definition of this API's error contract, shared with the async
    client in :mod:`byoai.recorder.coriqo_async` so the two cannot drift into
    disagreeing about what a 423 means. ``path`` is accepted for callers that
    want it in a message and is otherwise unused.
    """
    if response.status_code >= 400:
        detail = response.text
        if response.headers.get("content-type", "").startswith("application/json"):
            try:
                detail = response.json().get("detail", response.text)
            except ValueError:
                pass
        if response.status_code == 423:
            raise AgentSuspendedError(response.status_code, detail)
        raise CoriqoAgentsError(response.status_code, detail)

    if not response.content:
        return None, response.status_code
    try:
        return response.json(), response.status_code
    except ValueError as exc:
        # A 2xx carrying a non-JSON body isn't a Coriqo response at all —
        # usually a proxy or maintenance page. Surface it as the same error
        # type every other failure uses so one `except` covers it.
        raise CoriqoAgentsError(response.status_code, f"non-JSON response body: {exc}") from exc


# -- the client ------------------------------------------------------------


class CoriqoAgentsClient:
    """Thin, synchronous client for Coriqo's agent governance API.

    One client per process rather than a shared global: it holds an
    ``httpx.Client`` and offers no more thread safety than that already does.
    Every method raises :class:`CoriqoAgentsError` on a non-2xx response and
    does not retry.
    """

    def __init__(
        self,
        credentials: CoriqoCredentials,
        *,
        http_client: httpx.Client | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        device_signer: Any | None = None,
    ) -> None:
        """Pass ``device_signer`` (a device key: ``device_id``, ``public_key_b64``,
        ``sign``) and receipt fetches are device-signed instead of sent with the
        API key. Pass ``http_client`` to supply your own transport, retry policy, or
        a test double. A caller-supplied client is never closed by
        :meth:`close`, since closing something shared out from under its owner
        would break its next use elsewhere."""
        self._device_signer = device_signer
        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.Client(
                base_url=credentials.base_url,
                headers={
                    "X-API-Key": credentials.api_key,
                    "X-Tenant-Slug": credentials.tenant_slug,
                    "content-type": "application/json",
                },
                timeout=timeout,
            )
            self._owns_client = True

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> CoriqoAgentsClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _send(self, method: str, path: str, **kwargs: Any) -> tuple[Any, int]:
        """Performs the request and returns ``(parsed_body, status_code)``.

        Separate from :meth:`_request` because registration needs the status
        code itself: Coriqo distinguishes "created" from "already existed" by
        201 vs 200, not by anything in the body.
        """
        try:
            response = self._client.request(method, path, **kwargs)
        except httpx.HTTPError as exc:
            raise CoriqoAgentsError(None, f"request to {path} failed: {exc}") from exc
        return parse_response(response, path=path)

    def _send_device_signed(self, method: str, path: str) -> tuple[Any, int]:
        """A body-less request carrying the device-signature headers.

        Coriqo refuses a request that carries both an API key and a device
        signature, so the API key header is removed from this one request. The
        signature is made over the final URL (path and query) and is fresh per
        call, because Coriqo accepts a timestamp only ~2 minutes old.
        """
        from .coriqo_async import device_headers, request_path

        request = self._client.build_request(method, path)
        request.headers.pop("X-API-Key", None)
        request.headers.update(
            device_headers(
                self._device_signer,
                method=method,
                path=request_path(request.url),
                body=b"",
            )
        )
        try:
            response = self._client.send(request)
        except httpx.HTTPError as exc:
            raise CoriqoAgentsError(None, f"request to {path} failed: {exc}") from exc
        return parse_response(response, path=path)

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        body, _status = self._send(method, path, **kwargs)
        return body

    # -- agents ------------------------------------------------------------

    def list_agents(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        """Every agent in the tenant, paging until the reported total is reached.

        Coriqo caps ``limit`` at 200 per request, so a single call cannot see a
        tenant with more agents than that. Paging matters because a caller using
        this to decide whether an agent already exists would otherwise register
        a duplicate for every agent past the first page. ``limit`` caps the
        total returned; omit it for all of them.
        """
        collected: list[dict[str, Any]] = []
        offset = 0
        while True:
            page_size = _LIST_PAGE_SIZE
            if limit is not None:
                page_size = min(page_size, limit - len(collected))
                if page_size <= 0:
                    return collected
            page = self._request(
                "GET", "/api/v1/agents", params={"limit": page_size, "offset": offset}
            )
            if not isinstance(page, dict):
                return collected
            items = page.get("items") or []
            collected.extend(items)
            total = page.get("total")
            offset += len(items)
            # Stop on an empty page even if `total` disagrees, so a miscounted
            # total can't spin this loop forever.
            if not items or (isinstance(total, int) and offset >= total):
                return collected

    def register_agent(self, registration: AgentRegistration) -> tuple[dict[str, Any], bool]:
        """Registers an agent, returning ``(record, created)``.

        With an ``external_id`` this is idempotent: Coriqo answers ``201`` the
        first time and ``200`` with the existing agent afterwards, so
        ``created`` distinguishes the two. Note that a repeat call does **not**
        apply changes to ``mandate``/``allowed_tools`` — amend those through
        Coriqo's mandate endpoint, so the change is versioned rather than
        silently rewriting what earlier decisions were judged against.

        Without an ``external_id`` every call creates a new agent.

        Registering always lands the agent at ``in_review``: Coriqo never
        pre-approves. That is what makes self-registration safe — it files a
        governance to-do rather than granting the agent any standing.
        """
        body, status = self._send("POST", "/api/v1/agents", json=registration.to_body())
        if not isinstance(body, dict):
            raise CoriqoAgentsError(status, "registration response was not an object")
        return body, status == 201

    def get_agent(self, coriqo_agent_id: str) -> dict[str, Any]:
        return self._request("GET", f"/api/v1/agents/{coriqo_agent_id}")

    # -- runs --------------------------------------------------------------

    def open_trajectory(
        self,
        coriqo_agent_id: str,
        *,
        goal: str | None = None,
        use_case: str | None = None,
        parent_trajectory_id: str | None = None,
        started_at: str | None = None,
    ) -> dict[str, Any]:
        """Opens a run.

        ``started_at`` (ISO-8601 UTC) is when the run actually began, for a run
        published after the fact; omitted, Coriqo stamps the time it received
        the call.

        ``parent_trajectory_id`` nests this run under another, which Coriqo
        uses to roll a flagged step up through every ancestor. The parent must
        belong to the **same** agent and still be open — Coriqo refuses
        cross-agent nesting, so a sub-agent that is its own registered agent
        cannot be nested this way and is better represented as a tool call on
        its parent's trace.
        """
        body: dict[str, Any] = {"goal": goal}
        if use_case is not None:
            body["use_case"] = use_case
        if parent_trajectory_id is not None:
            body["parent_trajectory_id"] = parent_trajectory_id
        if started_at is not None:
            body["started_at"] = started_at
        return self._request("POST", f"/api/v1/agents/{coriqo_agent_id}/trajectories", json=body)

    def complete_trajectory(
        self,
        coriqo_agent_id: str,
        trajectory_id: str,
        *,
        status: str = "completed",
        ended_at: str | None = None,
    ) -> dict[str, Any]:
        """Closes a run. Coriqo answers 409 if it still has open sub-runs, so
        nested children have to be completed first. ``ended_at`` is optional,
        as ``started_at`` is on :meth:`open_trajectory`."""
        body: dict[str, Any] = {"status": status}
        if ended_at is not None:
            body["ended_at"] = ended_at
        return self._request(
            "POST",
            f"/api/v1/agents/{coriqo_agent_id}/trajectories/{trajectory_id}/complete",
            json=body,
        )

    def list_trajectories(
        self, coriqo_agent_id: str, *, status: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        """This agent's runs, depth-first with each run followed by its
        children, each carrying ``depth``/``step_count``/``child_count``."""
        params: dict[str, Any] = {"limit": limit}
        if status is not None:
            params["status"] = status
        return self._request("GET", f"/api/v1/agents/{coriqo_agent_id}/trajectories", params=params)

    def record_trace(
        self,
        coriqo_agent_id: str,
        *,
        inputs: Any | None = None,
        output: str | None = None,
        tool_calls: list[dict[str, Any]] | None = None,
        grounding_refs: list[Any] | None = None,
        trajectory_id: str | None = None,
        step_index: int | None = None,
        latency_ms: int | None = None,
        cost_usd: float | None = None,
        token_count: int | None = None,
        occurred_at: str | None = None,
    ) -> dict[str, Any]:
        """Records one decision. See :meth:`record_traces` for the batch form.

        ``inputs`` is hashed server-side and never stored, but it *is*
        transmitted — so send metadata or a digest, not raw payloads you can't
        have Coriqo see even in transit. Prefer pre-computed
        ``args_hash``/``result_hash`` in ``tool_calls`` (which is what
        :func:`publish_session` does) so raw arguments never leave the process
        at all.

        ``grounding_refs`` entries are either ids Coriqo can resolve itself, or
        anchors into another store, written as
        ``{"type": "external", "id": …, "system": …}``. External anchors are
        held outside the integrity calculation — neither verified nor counted
        against the score — which is what makes it safe to cite a hash from a
        store Coriqo has no copy of.
        """
        return self._request(
            "POST",
            f"/api/v1/agents/{coriqo_agent_id}/traces",
            json=trace_body(
                inputs=inputs,
                output=output,
                tool_calls=tool_calls,
                grounding_refs=grounding_refs,
                trajectory_id=trajectory_id,
                step_index=step_index,
                latency_ms=latency_ms,
                cost_usd=cost_usd,
                token_count=token_count,
                occurred_at=occurred_at,
            ),
        )

    def get_receipt(self, event_hash: str) -> dict[str, Any] | None:
        """The evidence receipt for ``event_hash``, or ``None`` while it is pending (202).

        Raises :class:`CoriqoAgentsError` on 404 (unknown hash or another
        actor's event), 403 or 409. Does not poll; the caller retries.
        """
        path = f"/api/v1/receipts/{event_hash}"
        if self._device_signer is not None:
            body, status = self._send_device_signed("GET", path)
        else:
            body, status = self._send("GET", path)
        if status == 202 or not isinstance(body, dict) or body.get("status") == "pending":
            return None
        return body

    def record_traces(
        self, coriqo_agent_id: str, traces: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        """Records up to :data:`MAX_TRACE_BATCH` decisions in one request.

        All-or-nothing: Coriqo rejects the whole batch if any single trace is
        invalid, and records none of them. Mandate checks still run per trace,
        so the returned ``traces`` array carries each one's own
        ``status``/``flag_reason`` and ``recorded``/``flagged`` are counts.
        """
        if not traces:
            raise ValueError("traces must not be empty")
        if len(traces) > MAX_TRACE_BATCH:
            raise ValueError(f"a batch holds at most {MAX_TRACE_BATCH} traces, got {len(traces)}")
        return self._request(
            "POST",
            f"/api/v1/agents/{coriqo_agent_id}/traces/batch",
            json={"traces": [dict(t) for t in traces]},
        )

    def record_external_controls(
        self,
        coriqo_agent_id: str,
        trajectory_id: str,
        controls: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Records enforcement decisions taken on a run by controls outside
        Coriqo — a Bedrock guardrail intervening, say.

        Idempotent per ``evidence_ref`` on Coriqo's side, so a retried flush
        does not double-count an intervention; the response separates
        ``recorded`` from ``skipped`` so a caller can tell the two apart.
        """
        if not controls:
            raise ValueError("controls must not be empty")
        if len(controls) > MAX_EXTERNAL_CONTROLS:
            raise ValueError(
                f"a batch holds at most {MAX_EXTERNAL_CONTROLS} control events, got {len(controls)}"
            )
        return self._request(
            "POST",
            f"/api/v1/agents/{coriqo_agent_id}/external-controls",
            json={
                "trajectory_id": trajectory_id,
                "controls": [dict(c) for c in controls],
            },
        )

    def record_device_receipts(
        self,
        coriqo_agent_id: str,
        trajectory_id: str,
        receipts: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Attaches sealed device rows to a run. Coriqo checks each on arrival
        and refuses the whole request with 422 if any fails. Sending a receipt
        it already holds is safe: it is counted as a duplicate."""
        if not receipts:
            raise ValueError("receipts must not be empty")
        if len(receipts) > MAX_DEVICE_RECEIPTS:
            raise ValueError(
                f"a request holds at most {MAX_DEVICE_RECEIPTS} receipts, got {len(receipts)}"
            )
        return self._request(
            "POST",
            f"/api/v1/agents/{coriqo_agent_id}/trajectories/{trajectory_id}/device-receipts",
            json={"receipts": [dict(r) for r in receipts]},
        )

    def authorize(
        self,
        coriqo_agent_id: str,
        *,
        tool: str,
        trajectory_id: str | None = None,
        step_index: int | None = None,
    ) -> dict[str, Any]:
        """Pre-act mandate check, returning a sealed ``allow``/``deny``
        verdict. Advisory: Coriqo records the verdict, it does not enforce it —
        honoring a deny is the caller's responsibility."""
        return self._request(
            "POST",
            f"/api/v1/agents/{coriqo_agent_id}/authorize",
            json={"tool": tool, "trajectory_id": trajectory_id, "step_index": step_index},
        )


def _as_count(value: Any) -> int:
    """A response count, or 0 if it isn't a usable number.

    These are reporting figures, not control flow — a malformed one shouldn't
    be able to take down a publish that otherwise succeeded. Numeric strings
    are still accepted, since a JSON encoder that quotes its numbers is
    reporting a real count and zeroing it would undercount silently. ``bool``
    is excluded deliberately: it is an ``int`` subclass, so ``True`` would
    otherwise land here as the count ``1``.
    """
    if isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        log.warning("coriqo: ignoring unusable count in batch response: %r", value)
        return 0


def _close_quietly(
    client: CoriqoAgentsClient, coriqo_agent_id: str, trajectory_id: str, session_id: str
) -> None:
    """Best-effort completion of a trajectory whose steps failed to publish.

    Deliberately swallows its own errors: it runs while a real failure is
    already propagating, and masking that failure with a cleanup error would
    hide the thing the caller actually needs to see.
    """
    try:
        client.complete_trajectory(coriqo_agent_id, trajectory_id, status="flagged")
    except CoriqoAgentsError as exc:
        log.warning(
            "coriqo: could not close trajectory %s after session %s failed to "
            "publish, it will stay open: %s",
            trajectory_id,
            session_id,
            exc.detail,
        )


def _required(body: Any, key: str, path: str) -> Any:
    """Reads a required field off a 2xx body, or raises.

    A 2xx whose body is missing the field it promised (a proxy rewriting
    responses, an API version that renamed it) is a Coriqo-side problem, not a
    bug in the caller — so it surfaces as the error type callers already handle
    instead of a bare ``KeyError`` escaping this module and breaking a run that
    was told a Coriqo outage would never do that.
    """
    if not isinstance(body, dict) or body.get(key) is None:
        raise CoriqoAgentsError(None, f"response from {path} had no {key}")
    return body[key]


def trace_body(
    *,
    inputs: Any | None,
    output: str | None,
    tool_calls: list[dict[str, Any]] | None,
    grounding_refs: list[Any] | None,
    trajectory_id: str | None,
    step_index: int | None,
    latency_ms: int | None,
    cost_usd: float | None,
    token_count: int | None,
    occurred_at: str | None,
) -> dict[str, Any]:
    """The wire body for one decision trace.

    Shared with the async client so both spell Coriqo's strict schema the same
    way; ``occurred_at`` is omitted rather than sent as null so Coriqo stamps
    its own receipt time when the caller has none.
    """
    body: dict[str, Any] = {
        "inputs": inputs,
        "output": output,
        "tool_calls": tool_calls,
        "grounding_refs": grounding_refs,
        "trajectory_id": trajectory_id,
        "step_index": step_index,
        "latency_ms": latency_ms,
        "cost_usd": cost_usd,
        "token_count": token_count,
    }
    if occurred_at is not None:
        body["occurred_at"] = occurred_at
    return body


# -- orchestration ---------------------------------------------------------


def ensure_registered(
    client: CoriqoAgentsClient,
    registrations: Mapping[str, AgentRegistration],
    *,
    external_id_prefix: str = "",
) -> dict[str, str]:
    """Resolves every local agent key to a Coriqo agent id, registering as needed.

    Safe to call on every startup, and safe to call concurrently from several
    processes. Idempotency is Coriqo's: each agent is registered with an
    ``external_id`` (the registration's own, or the mapping key prefixed by
    ``external_id_prefix``), and re-registering the same one returns the
    existing agent rather than creating a second copy. That means there is no
    local cache to keep in sync, no listing to page through, and no matching on
    display names — the server is the single source of truth.

    Pick an ``external_id_prefix`` that names your application (``"my-app:"``)
    if the mapping keys are generic enough to collide with another publisher
    sharing the tenant.

    Raises :class:`CoriqoAgentsError` if Coriqo refuses a registration — most
    often 403 for a service account without ``governance:approve``. A
    deployment that shouldn't create agents at all can skip this entirely and
    pass known agent ids straight to :func:`publish_session`.
    """
    resolved: dict[str, str] = {}
    for key, registration in registrations.items():
        if registration.external_id is None:
            registration = replace(registration, external_id=f"{external_id_prefix}{key}")
        record, created = client.register_agent(registration)
        agent_id = record.get("agent_id")
        if not agent_id:
            raise CoriqoAgentsError(None, f"registration of {key!r} returned no agent_id")
        resolved[key] = agent_id
        if created:
            log.info(
                "coriqo: registered %r as agent %s (%s)",
                key,
                agent_id,
                record.get("validation_status", "in_review"),
            )
        else:
            log.debug("coriqo: %r already registered as agent %s", key, agent_id)
    return resolved


def publish_session(
    client: CoriqoAgentsClient,
    *,
    coriqo_agent_id: str,
    ledger: Ledger,
    session_id: str,
    goal: str | None = None,
    use_case: str | None = None,
    final_output: str | None = None,
    payload_mode: PayloadMode = PayloadMode.REDACTED,
    redactor: TextRedactor = redact_free_text,
    inputs_extra: Mapping[str, Any] | None = None,
    parent_trajectory_id: str | None = None,
    ground_in_ledger: bool = True,
    started_at: str | None = None,
    ended_at: str | None = None,
    receipt_store: ReceiptStore | None = None,
    seal_chain: Any | None = None,
) -> PublishResult | None:
    """Publishes one recorded session as a trajectory plus a trace per step.

    Returns ``None`` when the session sealed no tool calls, so there is
    nothing to publish. ``final_output`` is attached to the last step, which is
    where a run's decision text belongs; earlier steps carry their results by
    hash only.

    ``final_output`` is free text — usually the model's own words — and is the
    one field this function ships as readable prose rather than a digest, so
    it is the one place ``payload_mode`` still has to be applied by hand: pass
    the same mode the local :class:`~byoai.recorder.integration.Recorder` is
    using (``recorder.payload_mode``) so a decision's readable text is bound
    by the same policy as the tool payloads that produced it, instead of
    always shipping raw regardless of what the device is configured to
    redact. ``full`` ships it unchanged, ``redacted`` (the default, matching
    the recorder's own default) runs ``final_output`` through ``redactor``,
    and ``hash-only`` drops it entirely, consistent with that mode shipping no
    payload bytes anywhere else.

    ``redactor`` defaults to :func:`~byoai.recorder.redact.redact_free_text`
    — fast, dependency-free, and limited to fixed-shape secrets/PII (email,
    SSN, credit card, API/AWS key); see that function's docstring for what it
    does and does not catch. Pass a different :data:`~byoai.recorder.redact.TextRedactor`
    (e.g. one backed by a local NER model, a DLP SDK, or a hand-rolled name
    list) for detection beyond that — this package doesn't bundle one, since
    a model adds real weight to a path meant to add near-zero latency per
    governed call, and no fixed choice fits every integrator's
    latency/accuracy tradeoff. ``redactor`` is only ever called under
    ``payload_mode=PayloadMode.REDACTED``; it has no effect under ``full`` or
    ``hash-only``.

    Steps go up in batches of :data:`MAX_TRACE_BATCH`, so an ordinary run costs
    one request. Each batch is atomic on Coriqo's side: one invalid trace
    rejects that whole batch, which is why a rejection raises rather than
    reporting a partial success. If a batch does fail, the trajectory is closed
    as ``flagged`` on the way out rather than left open — an abandoned open run
    would sit in Coriqo as permanently in-progress and would block its parent
    from ever completing.

    ``started_at``/``ended_at`` (ISO-8601 UTC) carry the run's real start and
    end for a session published after the fact; each step already carries its
    own ``occurred_at`` from the ledger.

    With ``ground_in_ledger`` (the default) every trace cites its ledger row's
    ``entry_hash`` as an external grounding anchor, so a Coriqo trace names the
    exact sealed row behind it. Coriqo holds external anchors outside its
    integrity scoring, so this adds provenance without distorting the score.

    ``parent_trajectory_id`` nests this run under another of the **same**
    agent's runs; Coriqo refuses cross-agent nesting. A nested run has to be
    completed before its parent can be.

    A trajectory containing a flagged step is completed as ``flagged`` rather
    than ``completed`` — a run that went outside its mandate should not close
    looking clean.

    Every trace sent gets a row in ``receipt_store`` (default: the sidecar next
    to the ledger) before the request, keyed by session and step. The response
    then fills in each acknowledged ``event_hash``; a step with none stays
    unacknowledged and is reported by :mod:`byoai.recorder.receipts` once it is
    old enough. A store failure never fails the publish.

    With ``seal_chain`` (Shield's ``SealChain``), the sealed device row behind
    each step goes up after the traces and before the close: see
    :func:`send_device_receipts`. A row holding message text is never sent. A
    failure here leaves a finding in ``receipt_store`` and the run published.

    Raises :class:`CoriqoAgentsError` on any rejection, and
    :class:`AgentSuspendedError` if governance has stopped this agent.
    """
    steps = read_tool_steps(ledger, session_id)
    if not steps:
        return None

    if final_output is not None:
        if payload_mode is PayloadMode.HASH_ONLY:
            final_output = None
        elif payload_mode is PayloadMode.REDACTED:
            final_output = redactor(final_output)
        # PayloadMode.FULL ships final_output unchanged.

    trajectory = client.open_trajectory(
        coriqo_agent_id,
        goal=goal,
        use_case=use_case,
        parent_trajectory_id=parent_trajectory_id,
        started_at=started_at,
    )
    trajectory_id = _required(
        trajectory, "trajectory_id", f"/api/v1/agents/{coriqo_agent_id}/trajectories"
    )

    last_index = steps[-1].index
    bodies = []
    for step in steps:
        inputs: dict[str, Any] = {
            "session_id": session_id,
            "step": step.index,
            "tool": step.tool_name,
        }
        if inputs_extra:
            inputs.update(inputs_extra)
        grounding_refs = (
            [{"type": "external", "id": step.entry_hash, "system": GROUNDING_SYSTEM}]
            if ground_in_ledger
            else None
        )
        bodies.append(
            trace_body(
                inputs=inputs,
                output=final_output if step.index == last_index else None,
                tool_calls=[
                    {
                        "step": step.index,
                        "tool": step.tool_name,
                        "args_hash": step.args_hash,
                        "result_hash": step.result_hash,
                    }
                ],
                grounding_refs=grounding_refs,
                trajectory_id=trajectory_id,
                step_index=step.index,
                latency_ms=step.latency_ms,
                cost_usd=None,
                token_count=None,
                occurred_at=_as_utc_isoformat(step.occurred_at),
            )
        )

    if receipt_store is None:
        receipt_store = ReceiptStore.for_ledger(ledger)
    # One row per trace we are about to send, written BEFORE the request, so a
    # server that swallows an event (or a request that dies mid-flight) leaves
    # an unacknowledged row behind instead of nothing.
    for body in bodies:
        try:
            receipt_store.record_sent(
                session_id,
                body["step_index"],
                input_hash=canonical_hash(body.get("inputs")),
                output_hash=canonical_hash(body.get("output")),
                trajectory_id=trajectory_id,
            )
        except Exception as exc:  # noqa: BLE001 - never fail a publish
            log.warning("coriqo: could not store receipt row: %s", exc)
    recorded = 0
    flagged = 0
    try:
        for start in range(0, len(bodies), MAX_TRACE_BATCH):
            batch = bodies[start : start + MAX_TRACE_BATCH]
            try:
                response = client.record_traces(coriqo_agent_id, batch)
            except Exception as exc:
                # Batch refused outright: this and every unsent later batch
                # are 'rejected', not 'swallowed'.
                for body in bodies[start:]:
                    try:
                        receipt_store.mark_rejected(
                            session_id, body["step_index"],
                            getattr(exc, "status_code", None),
                            trajectory_id=trajectory_id,
                        )
                    except Exception as exc2:  # noqa: BLE001
                        log.warning("coriqo: could not store receipt row: %s", exc2)
                raise
            # A 2xx whose counts aren't numbers is a Coriqo-side problem, but a
            # bare ValueError here would escape the except below and strand the
            # trajectory open — the exact outcome that handler exists to
            # prevent. Treat an unusable count as zero and carry on.
            recorded += _as_count(response.get("recorded"))
            flagged += _as_count(response.get("flagged"))
            listed = [t for t in (response.get("traces") or []) if isinstance(t, dict)]
            by_step = {t.get("step_index"): t for t in listed}
            for body in batch:
                trace = by_step.get(body["step_index"])
                if trace is None:
                    continue  # stays unacknowledged; verify reports it
                try:
                    receipt_store.record_ack(
                        session_id, body["step_index"], trace, trajectory_id=trajectory_id
                    )
                except Exception as exc:  # noqa: BLE001 - never fail a publish
                    log.warning("coriqo: could not store receipt row: %s", exc)
            for trace in listed:
                if trace.get("status") == "flagged":
                    log.warning(
                        "coriqo: flagged step %s of session %s: %s",
                        trace.get("step_index"),
                        session_id,
                        trace.get("flag_reason"),
                    )
    except CoriqoAgentsError:
        # The trajectory is already open at this point. Leaving it that way
        # would strand the run as permanently in-progress in Coriqo — and
        # since a parent can't be completed while a child is open, it would
        # block that parent too. Callers of this function typically log and
        # carry on, so nothing else would ever come back to close it. Mark it
        # flagged (the closest Coriqo has to "this didn't finish cleanly")
        # before re-raising the real failure.
        _close_quietly(client, coriqo_agent_id, trajectory_id, session_id)
        raise

    # After the steps and before the close: the run has to exist and still be
    # open, and a failure here must not strand it (see _publish_external_controls).
    external_controls = _publish_external_controls(
        client,
        coriqo_agent_id=coriqo_agent_id,
        trajectory_id=trajectory_id,
        ledger=ledger,
        session_id=session_id,
        ground_in_ledger=ground_in_ledger,
    )

    device_receipts, device_receipts_missing = 0, 0
    if seal_chain is not None:
        device_receipts, device_receipts_missing = _publish_device_receipts(
            client,
            coriqo_agent_id=coriqo_agent_id,
            trajectory_id=trajectory_id,
            session_id=session_id,
            steps=steps,
            seal_chain=seal_chain,
            receipt_store=receipt_store,
        )

    # Note what does NOT go into this: external_controls. A run's status is
    # about the agent's own conduct against its mandate, and a third party's
    # control firing is a different fact — often the opposite one, since a
    # control that fired is a control that worked. Coriqo refuses to move the
    # status for these too; agreeing here keeps one answer, not two.
    status = "flagged" if flagged else "completed"
    client.complete_trajectory(coriqo_agent_id, trajectory_id, status=status, ended_at=ended_at)

    log.info(
        "coriqo: published session %s to agent %s (trajectory %s, %s/%s steps, "
        "%s flagged, status=%s)",
        session_id,
        coriqo_agent_id,
        trajectory_id,
        recorded,
        len(steps),
        flagged,
        status,
    )
    return PublishResult(
        trajectory_id=trajectory_id,
        total_steps=len(steps),
        recorded=recorded,
        flagged=flagged,
        status=status,
        external_controls=external_controls,
        device_receipts=device_receipts,
        device_receipts_missing=device_receipts_missing,
    )


def _publish_external_controls(
    client: CoriqoAgentsClient,
    *,
    coriqo_agent_id: str,
    trajectory_id: str,
    ledger: Ledger,
    session_id: str,
    ground_in_ledger: bool,
) -> int:
    """Ship this session's third-party control events. Never raises.

    Swallowing the error is the opposite of what the trace path does, and it
    is deliberate. A rejected trace means the run's own record is incomplete,
    so the run is closed flagged and the caller told. A rejected control event
    means one piece of *corroborating* evidence did not land — the run itself
    is fully recorded and verifiable without it, and failing the publish here
    would turn a complete run into a stranded one over a Coriqo that is merely
    older than this client (the endpoint does not exist before migration 0314,
    and a 404 must not take a working integration down with it).

    The ledger keeps the authoritative copy either way, so nothing is lost that
    ``coriqo-verify`` cannot still show.
    """
    controls = read_external_controls(ledger, session_id)
    if not controls:
        return 0

    bodies = [
        {
            "control_system": control.control_system,
            "control_ref": control.control_ref,
            "action": control.action,
            "stage": control.stage,
            "categories": control.categories,
            # The sealed ledger row this was read out of: Coriqo's idempotency
            # key, and the anchor that resolves the row back to its bytes.
            "evidence_ref": control.entry_hash if ground_in_ledger else None,
            "evidence_system": GROUNDING_SYSTEM if ground_in_ledger else None,
            "occurred_at": _as_utc_isoformat(control.occurred_at),
        }
        for control in controls
    ]

    published = 0
    for start in range(0, len(bodies), MAX_EXTERNAL_CONTROLS):
        batch = bodies[start : start + MAX_EXTERNAL_CONTROLS]
        try:
            response = client.record_external_controls(coriqo_agent_id, trajectory_id, batch)
        except CoriqoAgentsError as exc:
            log.warning(
                "coriqo: could not publish %s control event(s) for session %s (%s); "
                "the sealed ledger keeps them",
                len(batch),
                session_id,
                exc.detail,
            )
            continue
        published += _as_count(response.get("recorded"))
    return published


def _note_device_receipt(store: ReceiptStore, session_id: str, trajectory_id: str,
                         step_index: Any, finding: str, reason: str, *,
                         status: int | None = None, seal: str | None = None) -> None:
    """Log it and keep it in the store, so it is seen even if the store fails."""
    log.warning(
        "coriqo: %s for step %s of session %s (seal %s): %s",
        finding, step_index, session_id, seal, reason,
    )
    try:
        store.note_device_receipt(
            session_id, step_index, finding, reason,
            status=status, seal=seal, trajectory_id=trajectory_id,
        )
    except Exception as exc:  # noqa: BLE001 - never fail a publish
        log.warning("coriqo: could not store receipt row: %s", exc)


def send_device_receipts(
    client: CoriqoAgentsClient,
    *,
    coriqo_agent_id: str,
    trajectory_id: str,
    session_id: str,
    items: Sequence[Mapping[str, Any]],
    receipt_store: ReceiptStore,
) -> int:
    """POSTs ``{"receipt": ..., "step_index": n}`` items and returns how many
    Coriqo stored. Never raises.

    The run is complete without these, so a failure must not lose it. A 422 is
    ``device_receipt_refused``: Coriqo refuses a whole request for one bad
    receipt, so a refused request is split and resent one by one, and the
    finding lands on the receipt it names. Any other failure is
    ``device_receipt_unsent``. Calling this again with the same items is the
    retry: a receipt Coriqo holds counts as a duplicate, and success clears the
    step's finding.
    """
    stored = 0
    for start in range(0, len(items), MAX_DEVICE_RECEIPTS):
        batch = list(items[start : start + MAX_DEVICE_RECEIPTS])
        try:
            response = client.record_device_receipts(coriqo_agent_id, trajectory_id, batch)
        except CoriqoAgentsError as exc:
            if exc.status_code == 422 and len(batch) > 1:
                for item in batch:
                    stored += send_device_receipts(
                        client,
                        coriqo_agent_id=coriqo_agent_id,
                        trajectory_id=trajectory_id,
                        session_id=session_id,
                        items=[item],
                        receipt_store=receipt_store,
                    )
                continue
            refused = exc.status_code == 422
            finding = "device_receipt_refused" if refused else "device_receipt_unsent"
            for item in batch:
                _note_device_receipt(
                    receipt_store, session_id, trajectory_id, item["step_index"],
                    finding, str(exc.detail), status=exc.status_code,
                    seal=item["receipt"].get("seal"),
                )
            continue
        if isinstance(response, dict):
            stored += _as_count(response.get("stored"))
        for item in batch:
            try:
                receipt_store.clear_device_receipt(
                    session_id, item["step_index"], trajectory_id=trajectory_id
                )
            except Exception as exc:  # noqa: BLE001 - never fail a publish
                log.warning("coriqo: could not store receipt row: %s", exc)
    return stored


def _publish_device_receipts(
    client: CoriqoAgentsClient,
    *,
    coriqo_agent_id: str,
    trajectory_id: str,
    session_id: str,
    steps: Sequence[ToolStep],
    seal_chain: Any,
    receipt_store: ReceiptStore,
) -> tuple[int, int]:
    """Finds each step's sealed row by its ledger digest and sends it. Returns
    ``(stored, steps with no sealed row)``. Never raises."""
    try:
        found = seal_chain.receipts_for_payload_hashes({s.args_hash for s in steps})
    except Exception as exc:  # noqa: BLE001 - the run is already published
        for step in steps:
            _note_device_receipt(
                receipt_store, session_id, trajectory_id, step.index,
                "device_receipt_unsent", f"could not read the seal chain: {exc}",
            )
        return 0, 0
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    missing = 0
    for step in steps:
        receipt = found.get(step.args_hash)
        if receipt is None:
            missing += 1
        elif step.args_hash in seen:
            continue  # identical arguments on a later step: one sealed row
        elif any(receipt.get("payload", {}).get(f) for f in _MESSAGE_TEXT_FIELDS):
            seen.add(step.args_hash)
            _note_device_receipt(
                receipt_store, session_id, trajectory_id, step.index,
                "device_receipt_withheld",
                "the sealed row holds a message preview (Shield's keep_text is on), "
                "and message text does not leave this device",
                seal=receipt.get("seal"),
            )
        else:
            seen.add(step.args_hash)
            items.append({"receipt": receipt, "step_index": step.index})
    if missing:
        log.warning(
            "coriqo: %s of %s steps of session %s have no sealed device row",
            missing, len(steps), session_id,
        )
    if not items:
        return 0, missing
    stored = send_device_receipts(
        client,
        coriqo_agent_id=coriqo_agent_id,
        trajectory_id=trajectory_id,
        session_id=session_id,
        items=items,
        receipt_store=receipt_store,
    )
    return stored, missing
