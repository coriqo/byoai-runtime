"""Async, retrying client for Coriqo's agent API and its enforcement path.

:mod:`byoai.recorder.coriqo_agents` publishes finished runs from a script, so a
blocking ``httpx.Client`` that never retries is the right shape there: the
caller is already between turns, and a duplicate publish would corrupt the
record it exists to keep.

Mandate enforcement is a different shape. The runtime refreshes a cached policy
snapshot on a background interval while the agent is mid-turn, so a blocking
call there stalls the event loop for a whole round trip, and a single transient
blip would be read as "the policy could not be refreshed". This module is the
variant for that path:

* **async** — ``httpx.AsyncClient``, same construction options as the sync
  client (a caller-supplied client is never closed by :meth:`close`);
* **retrying, but only reads.** :class:`RetryPolicy` retries idempotent
  requests with exponential backoff and jitter, honours a server-sent
  ``Retry-After``, and leaves writes alone. A retried publish can duplicate a
  decision, and an accurate record is the whole product;
* **device-signed** where it has to be. Enforcement endpoints under
  ``/api/v1/agent-runtime/`` authenticate with the device key resolved by
  :mod:`byoai.recorder.identity`, never the static service-account key — the
  credential that fetches an agent's permitted scope must not be one the agent
  itself can use to widen that scope.

The error contract is the sync client's, unchanged: every failure is a
:class:`~byoai.recorder.coriqo_agents.CoriqoAgentsError` carrying
``status_code``/``detail``, with 423 raised as
:class:`~byoai.recorder.coriqo_agents.AgentSuspendedError`.

The signature format
--------------------
Coriqo verifies an Ed25519 signature over canonical JSON of::

    {"body_sha256": <hex sha256 of the exact request body bytes>,
     "method":      <uppercase HTTP method>,
     "path":        <path, plus "?"+query when a query string is present>,
     "public_key":  <the signer's own public key, lowercase hex>,
     "timestamp":   <the X-Coriqo-Timestamp value, verbatim>}

Everything that selects what a request does is covered, so a captured
signature cannot be replayed against a different method, path, query or body,
and the signer's own key sits inside the signed bytes so it cannot be replayed
under a different claimed identity. Coriqo accepts a timestamp up to 120s old
and 30s in the future, so every attempt — including a retry — is signed afresh
rather than resent with the timestamp of the attempt before it.

Note the encodings: the recorder's own wire format is base64
(``public_key_b64``, ``ed25519:<base64>`` signatures) and this API's headers
are hex. :func:`signing_payload` and :func:`device_headers` are the one place
that conversion happens.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import gzip
import hashlib
import json
import logging
import math
import os
import random
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from byoai.errors import ByoAIError, ProviderError

from .canonical import canonicalize
from .capability_digest import DIGEST_SPEC, compute_capability_digest
from .coriqo_agents import (
    MAX_TRACE_BATCH,
    AgentRegistration,
    CoriqoAgentsError,
    CoriqoCredentials,
    parse_response,
    trace_body,
)
from .identity import CoriqoIdentity, IdentitySource, Signer

__all__ = [
    "ENFORCEMENT_PREFIX",
    "MAX_VERDICT_BATCH",
    "VERDICT_RETRY_STATUSES",
    "AsyncCoriqoAgentsClient",
    "RetryPolicy",
    "SignatureError",
    "device_headers",
    "new_batch_key",
    "request_path",
    "signing_payload",
    "signing_timestamp",
]

log = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 10.0
_LIST_PAGE_SIZE = 200  # Coriqo caps `limit` at 200 on GET /api/v1/agents.

#: Path prefix Coriqo serves with device-signed auth. Requests below it are
#: signed and must NOT carry ``X-API-Key`` — Coriqo answers 403 to a service
#: account key here on purpose, so sending both is worse than sending neither.
ENFORCEMENT_PREFIX = "/api/v1/agent-runtime"

#: The signature prefix :meth:`byoai.recorder.keys.DeviceKey.sign` emits.
_SIG_PREFIX = "ed25519:"

#: Statuses worth a second attempt on an idempotent request: a rate limit and
#: the three gateway-ish failures that mean "nothing durable happened here".
#: 500 is deliberately absent — it can mean the write landed and the response
#: didn't.
DEFAULT_RETRY_STATUSES = frozenset({429, 502, 503, 504})

#: Verdicts Coriqo accepts in one batch; over-cap is a 422.
MAX_VERDICT_BATCH = 200

#: Extra retry status for verdict batches only. A 409 there means two
#: copies of the same batch_key raced a unique index and this one lost —
#: the server is asking for the retry, not reporting a conflict to give up
#: on.
VERDICT_RETRY_STATUSES = frozenset({409})

#: Verdict words Coriqo requires a reason for.
_REASON_REQUIRED = frozenset({"flagged", "blocked"})


class SignatureError(ByoAIError):
    """A request could not be signed for Coriqo.

    Distinct from :class:`~byoai.errors.EnforcementIdentityUnavailableError`,
    which means there is no device identity at all: this means there is one and
    its key material or signature came back in a shape the wire format cannot
    carry.
    """


# -- signing ---------------------------------------------------------------


def _b64_to_hex(value: str, *, what: str) -> str:
    try:
        return base64.b64decode(value, validate=True).hex()
    except (binascii.Error, ValueError) as exc:
        raise SignatureError(f"{what} is not valid base64: {exc}") from exc


def signing_payload(
    *, method: str, path: str, body: bytes, timestamp: str, public_key_hex: str
) -> bytes:
    """The exact bytes a device signs for one enforcement request.

    ``path`` must already include the query string when there is one — see
    :func:`request_path`.

    Canonicalization is :mod:`byoai.recorder.canonical` (RFC 8785), rather than
    a second serializer written for this one tuple. Coriqo canonicalizes with
    sorted keys and compact separators, which agrees with JCS byte for byte on
    a flat object of ASCII strings, and every field here is one: two hex
    digests, an uppercase method, a URL path and an RFC 3339 timestamp.
    """
    return canonicalize(
        {
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "method": method.upper(),
            "path": path,
            "public_key": public_key_hex.lower(),
            "timestamp": timestamp,
        }
    )


def request_path(url: httpx.URL) -> str:
    """Path as it is signed: query string included when present, because it
    selects what the request does."""
    query = url.query.decode("ascii")
    return url.path + (f"?{query}" if query else "")


def signing_timestamp(now: datetime | None = None) -> str:
    """RFC 3339 UTC, whole seconds. Coriqo compares this against its own clock
    with a 120s past / 30s future window."""
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def device_headers(
    signer: Signer,
    *,
    method: str,
    path: str,
    body: bytes,
    timestamp: str | None = None,
) -> dict[str, str]:
    """The four (plus one) headers a device-signed request carries.

    ``X-Coriqo-Device`` is sent as a diagnostic hint only. Coriqo resolves
    identity from the key that verified the signature, which is the honest
    answer after ``byoai-recorder-rotate-key`` has replaced the live key
    without rewriting ``enrollment.json``.
    """
    stamp = timestamp or signing_timestamp()
    public_key_hex = _b64_to_hex(signer.public_key_b64, what="device public key")
    signature = signer.sign(
        signing_payload(
            method=method,
            path=path,
            body=body,
            timestamp=stamp,
            public_key_hex=public_key_hex,
        )
    )
    if not signature.startswith(_SIG_PREFIX):
        raise SignatureError(
            f"signer returned {signature[:16]!r}…, expected an {_SIG_PREFIX!r} signature"
        )
    return {
        "X-Coriqo-Public-Key": public_key_hex,
        "X-Coriqo-Signature": _b64_to_hex(
            signature[len(_SIG_PREFIX) :], what="signature"
        ),
        "X-Coriqo-Timestamp": stamp,
        "X-Coriqo-Device": signer.device_id,
    }


# -- retry -----------------------------------------------------------------


def new_batch_key() -> str:
    """A fresh device-chosen idempotency key for one verdict batch."""
    return "vb_" + uuid.uuid4().hex


def _wire_batch_verdict(verdict: Mapping[str, Any]) -> dict[str, Any]:
    """One verdict as Coriqo's batch endpoint accepts it.

    ``snapshot_age_s`` is a float locally (a monotonic difference), and Coriqo
    takes whole seconds: a fractional value is a 422 for the whole batch, and
    a 422 batch is parked, not resent. So every batch carrying a real age was
    refused until this rounded it. Rounded up, so the age sent is never
    younger than the snapshot was, which is what Coriqo's staleness check
    compares. Done here, on the way out, so verdicts already waiting in an
    outbox ship too, and the local ledger keeps the exact value.
    """
    out = dict(verdict)
    age = out.get("snapshot_age_s")
    if isinstance(age, float) and math.isfinite(age):
        out["snapshot_age_s"] = max(0, math.ceil(age))
    return out


def _parse_retry_after(value: str | None) -> float | None:
    """Seconds from a ``Retry-After`` header. Only the delta-seconds form —
    an HTTP-date is ignored rather than guessed at against a device clock that
    may itself be the reason the request was refused."""
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    return seconds if seconds >= 0 else None


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded retry with exponential backoff and jitter, for reads.

    ``attempts`` counts total tries, not extra ones: ``attempts=1`` disables
    retry entirely. Backoff for attempt *n* is ``min(base * 2**n, max_delay)``
    scaled by a random factor in ``[1 - jitter, 1)``, so a fleet that all lost
    the same Coriqo does not come back in lockstep.

    ``retry_writes`` is off by default and stays that way for anything that
    records a decision. Turning it on makes exactly one write retryable —
    :meth:`AsyncCoriqoAgentsClient.register_agent` when the registration
    carries an ``external_id``, which Coriqo treats as an idempotency key and
    answers with the existing agent rather than a second copy. The cost of
    turning it on is that ``created`` can come back ``False`` for an agent this
    process did create, if the first attempt landed and its response was lost.
    """

    attempts: int = 3
    base_delay: float = 0.2
    max_delay: float = 5.0
    jitter: float = 0.5
    max_retry_after: float = 30.0
    retry_statuses: frozenset[int] = field(default=DEFAULT_RETRY_STATUSES)
    retry_writes: bool = False

    def __post_init__(self) -> None:
        if self.attempts < 1:
            raise ValueError("attempts must be at least 1")
        if not 0.0 <= self.jitter <= 1.0:
            raise ValueError("jitter must be between 0 and 1")

    def delay_for(
        self, attempt: int, *, retry_after: float | None = None, rand: float | None = None
    ) -> float:
        """Seconds to wait before attempt ``attempt + 1`` (0-based).

        A server-sent ``retry_after`` wins over the computed backoff and is not
        jittered — the server named a time, and spreading it would be second-
        guessing it — but it is still capped by ``max_retry_after`` so a
        mistaken header cannot park a refresh loop for an hour.
        """
        if retry_after is not None:
            return max(0.0, min(retry_after, self.max_retry_after))
        capped = min(self.base_delay * (2**attempt), self.max_delay)
        factor = rand if rand is not None else random.random()
        return capped * (1.0 - self.jitter + self.jitter * factor)


# -- the client ------------------------------------------------------------


class AsyncCoriqoAgentsClient:
    """Async client for Coriqo's agent API, plus its device-signed
    enforcement endpoints.

    Takes a :class:`~byoai.recorder.identity.CoriqoIdentity` (or, for symmetry
    with the sync client, plain :class:`CoriqoCredentials`). A device identity
    can do everything; a static-key identity can publish, and raises
    :class:`~byoai.errors.EnforcementIdentityUnavailableError` the moment it is
    asked for an enforcement call — refused at the client rather than as a 403
    from a server that does not accept the key at all.

    One client per event loop, as with any ``httpx.AsyncClient``.
    """

    def __init__(
        self,
        identity: CoriqoIdentity | CoriqoCredentials,
        *,
        tenant_slug: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        retry: RetryPolicy | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        """``http_client`` supplies your own transport or a test double, and
        is never closed by :meth:`close` — closing something shared out from
        under its owner breaks its next use. ``sleep`` exists so tests can
        observe the backoff without spending it.

        ``tenant_slug`` overrides the tenant the identity already carries;
        without it, the tenant comes from the identity (``enrollment.json``
        for a device, ``BYOAI_CORIQO_TENANT_SLUG`` for a static key) and
        finally from ``BYOAI_CORIQO_TENANT_SLUG`` — see
        :func:`_default_tenant_slug`."""
        if isinstance(identity, CoriqoCredentials):
            identity = CoriqoIdentity.from_credentials(identity)
        self._identity = identity
        self._retry = retry or RetryPolicy()
        self._sleep = sleep
        self._tenant_slug = tenant_slug or _default_tenant_slug(identity)

        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                base_url=identity.base_url, timeout=timeout
            )
            self._owns_client = True

    @property
    def identity(self) -> CoriqoIdentity:
        return self._identity

    @property
    def retry_policy(self) -> RetryPolicy:
        return self._retry

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> AsyncCoriqoAgentsClient:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()

    # -- request plumbing --------------------------------------------------

    def _base_headers(self, *, signed: bool) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        if self._tenant_slug:
            headers["X-Tenant-Slug"] = self._tenant_slug
        elif signed:
            raise CoriqoAgentsError(
                None,
                "a device-signed request needs a tenant: re-enroll this device so "
                "enrollment.json records one, pass tenant_slug=…, or set "
                "BYOAI_CORIQO_TENANT_SLUG",
            )
        if not signed and self._identity.source == IdentitySource.API_KEY:
            credentials = self._identity.credentials
            if credentials is not None:
                headers["X-API-Key"] = credentials.api_key
        return headers

    def _build(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None,
        params: Mapping[str, Any] | None,
        signed: bool,
        extra_headers: Mapping[str, str] | None = None,
    ) -> httpx.Request:
        """One attempt's request, signed at build time.

        The body is serialized here rather than handed to httpx as ``json=``
        because the signature commits to the exact bytes on the wire: any
        re-encoding between signing and sending would invalidate it.
        """
        content = b"" if json_body is None else json.dumps(json_body).encode("utf-8")
        headers = self._base_headers(signed=signed)
        if extra_headers:
            headers.update(extra_headers)
        request = self._client.build_request(
            method,
            path,
            params=params,
            content=content or None,
            headers=headers,
        )
        if signed:
            signer = self._identity.require_enforcement()
            # A caller-supplied client may carry a service-account key in its
            # default headers. Coriqo refuses any enforcement request that
            # presents one, so drop it here rather than let a correctly signed
            # request come back 403.
            request.headers.pop("X-API-Key", None)
            request.headers.update(
                device_headers(
                    signer,
                    method=method,
                    path=request_path(request.url),
                    body=content,
                )
            )
        return request

    async def _send(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        params: Mapping[str, Any] | None = None,
        signed: bool = False,
        idempotent: bool = False,
        extra_headers: Mapping[str, str] | None = None,
        collect_headers: dict[str, str] | None = None,
        extra_retry_statuses: frozenset[int] | None = None,
    ) -> tuple[Any, int]:
        """Perform the request, returning ``(parsed_body, status_code)``.

        Registration needs the status code itself — Coriqo distinguishes
        "created" from "already existed" by 201 vs 200, not by the body.

        Retry happens only when ``idempotent`` is true. Each attempt is rebuilt
        from scratch so a signed retry carries a fresh timestamp rather than
        the stale one Coriqo would refuse.

        ``collect_headers``, when given, is filled with the headers of the
        attempt that answered. Conditional requests need one of them (``ETag``)
        and the parsed body alone cannot carry it.
        """
        attempts = self._retry.attempts if idempotent else 1
        retry_statuses = self._retry.retry_statuses
        if extra_retry_statuses:
            retry_statuses = retry_statuses | extra_retry_statuses
        last_error: Exception | None = None

        for attempt in range(attempts):
            retry_after: float | None = None
            try:
                response = await self._client.send(
                    self._build(
                        method,
                        path,
                        json_body=json_body,
                        params=params,
                        signed=signed,
                        extra_headers=extra_headers,
                    )
                )
            except ProviderError as exc:
                # A transport or hook that already speaks the runtime's own
                # error vocabulary (RateLimitError and friends) has said
                # whether this is worth another go; don't second-guess it.
                if not exc.retryable:
                    raise
                last_error, retry_after = exc, exc.retry_after
            except httpx.HTTPError as exc:
                # Connect/read failures: nothing was necessarily durable, and
                # this only runs for requests the caller marked idempotent.
                # httpx's connect errors often have an empty message; the class
                # name ("ConnectError") is then the only thing that says why.
                why = f"{type(exc).__name__}: {exc}" if str(exc) else type(exc).__name__
                last_error = CoriqoAgentsError(None, f"request to {path} failed: {why}")
            else:
                if response.status_code not in retry_statuses:
                    if collect_headers is not None:
                        collect_headers.update(response.headers)
                    return parse_response(response, path=path)
                retry_after = _parse_retry_after(response.headers.get("retry-after"))
                last_error = _error_for(response, path=path)

            if attempt == attempts - 1:
                break
            delay = self._retry.delay_for(attempt, retry_after=retry_after)
            log.debug(
                "coriqo: retrying %s %s in %.2fs (attempt %d/%d): %s",
                method,
                path,
                delay,
                attempt + 1,
                attempts,
                last_error,
            )
            await self._sleep(delay)

        if last_error is None:  # pragma: no cover - the loop always sets one
            last_error = CoriqoAgentsError(None, f"request to {path} made no attempt")
        raise last_error

    async def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        body, _status = await self._send(method, path, **kwargs)
        return body

    # -- agents (service-account auth) -------------------------------------

    async def list_agents(self, *, limit: int | None = None) -> list[dict[str, Any]]:
        """Every agent in the tenant, paging until the reported total is reached.

        Coriqo caps ``limit`` at 200 per request, so one call cannot see a
        larger tenant; without paging, a caller using this to decide whether an
        agent exists would register a duplicate for every agent past the first
        page.
        """
        collected: list[dict[str, Any]] = []
        offset = 0
        while True:
            page_size = _LIST_PAGE_SIZE
            if limit is not None:
                page_size = min(page_size, limit - len(collected))
                if page_size <= 0:
                    return collected
            page = await self._request(
                "GET",
                "/api/v1/agents",
                params={"limit": page_size, "offset": offset},
                idempotent=True,
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

    async def get_agent(self, coriqo_agent_id: str) -> dict[str, Any]:
        return await self._request(
            "GET", f"/api/v1/agents/{coriqo_agent_id}", idempotent=True
        )

    async def register_agent(
        self, registration: AgentRegistration
    ) -> tuple[dict[str, Any], bool]:
        """Register an agent, returning ``(record, created)``.

        Retried only under ``RetryPolicy(retry_writes=True)`` *and* only with an
        ``external_id``, which is Coriqo's idempotency key: a repeat lands on
        the existing agent rather than creating a second one. Without one,
        every call creates a new agent, so a retry would leave a duplicate
        behind — see :class:`RetryPolicy`.
        """
        idempotent = self._retry.retry_writes and registration.external_id is not None
        body, status = await self._send(
            "POST",
            "/api/v1/agents",
            json_body=registration.to_body(),
            idempotent=idempotent,
        )
        if not isinstance(body, dict):
            raise CoriqoAgentsError(status, "registration response was not an object")
        return body, status == 201

    # -- runs (service-account auth) ---------------------------------------

    async def open_trajectory(
        self,
        coriqo_agent_id: str,
        *,
        goal: str | None = None,
        use_case: str | None = None,
        parent_trajectory_id: str | None = None,
    ) -> dict[str, Any]:
        """Open a run. Never retried: each call creates a trajectory."""
        body: dict[str, Any] = {"goal": goal}
        if use_case is not None:
            body["use_case"] = use_case
        if parent_trajectory_id is not None:
            body["parent_trajectory_id"] = parent_trajectory_id
        return await self._request(
            "POST", f"/api/v1/agents/{coriqo_agent_id}/trajectories", json_body=body
        )

    async def complete_trajectory(
        self, coriqo_agent_id: str, trajectory_id: str, *, status: str = "completed"
    ) -> dict[str, Any]:
        """Close a run. Coriqo answers 409 while it still has open sub-runs."""
        return await self._request(
            "POST",
            f"/api/v1/agents/{coriqo_agent_id}/trajectories/{trajectory_id}/complete",
            json_body={"status": status},
        )

    async def list_trajectories(
        self, coriqo_agent_id: str, *, status: str | None = None, limit: int = 200
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"limit": limit}
        if status is not None:
            params["status"] = status
        return await self._request(
            "GET",
            f"/api/v1/agents/{coriqo_agent_id}/trajectories",
            params=params,
            idempotent=True,
        )

    async def record_trace(
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
        """Record one decision. Never retried — a resent trace is a second
        decision in the record, and there is no idempotency key to collapse it
        back onto the first."""
        return await self._request(
            "POST",
            f"/api/v1/agents/{coriqo_agent_id}/traces",
            json_body=trace_body(
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

    async def record_traces(
        self, coriqo_agent_id: str, traces: Sequence[Mapping[str, Any]]
    ) -> dict[str, Any]:
        """Record up to :data:`MAX_TRACE_BATCH` decisions in one request.
        All-or-nothing on Coriqo's side, and never retried here."""
        if not traces:
            raise ValueError("traces must not be empty")
        if len(traces) > MAX_TRACE_BATCH:
            raise ValueError(
                f"a batch holds at most {MAX_TRACE_BATCH} traces, got {len(traces)}"
            )
        return await self._request(
            "POST",
            f"/api/v1/agents/{coriqo_agent_id}/traces/batch",
            json_body={"traces": [dict(t) for t in traces]},
        )

    async def authorize(
        self,
        coriqo_agent_id: str,
        *,
        tool: str,
        trajectory_id: str | None = None,
        step_index: int | None = None,
    ) -> dict[str, Any]:
        """Pre-act mandate check returning a sealed ``allow``/``deny`` verdict.
        Advisory — Coriqo records the verdict, honoring it is the caller's job.
        Sealed, so never retried."""
        return await self._request(
            "POST",
            f"/api/v1/agents/{coriqo_agent_id}/authorize",
            json_body={
                "tool": tool,
                "trajectory_id": trajectory_id,
                "step_index": step_index,
            },
        )

    # -- enforcement (device-signed) ---------------------------------------

    async def fetch_mandate(self, coriqo_agent_id: str) -> dict[str, Any]:
        """The scope this runtime enforces, for the cached policy snapshot.

        The one call worth retrying hard: it is a read, it is what a refresh
        loop repeats on an interval, and treating one blip as a refresh failure
        would age out a snapshot that is still perfectly good. Coriqo binds the
        agent to this device on first contact and refuses an agent another host
        already holds, which is a one-time effect and identical on every later
        call.
        """
        return await self._request(
            "GET",
            f"{ENFORCEMENT_PREFIX}/agents/{coriqo_agent_id}/mandate",
            signed=True,
            idempotent=True,
        )

    async def fetch_mandate_conditional(
        self, coriqo_agent_id: str, *, etag: str | None = None
    ) -> tuple[dict[str, Any] | None, str | None]:
        """:meth:`fetch_mandate`, as a conditional request.

        Returns ``(snapshot, etag)``. A ``304`` — Coriqo's answer when the
        mandate has not changed since ``etag`` — comes back as
        ``(None, etag)``: *still fresh, keep what you have*, not an empty
        snapshot. A refresh loop that read it as either an error or an empty
        mandate would age out or empty a scope that never changed.
        """
        headers: dict[str, str] = {}
        body, status = await self._send(
            "GET",
            f"{ENFORCEMENT_PREFIX}/agents/{coriqo_agent_id}/mandate",
            signed=True,
            idempotent=True,
            extra_headers={"If-None-Match": etag} if etag else None,
            collect_headers=headers,
        )
        new_etag = headers.get("etag") or etag
        if status == 304:
            return None, new_etag
        if not isinstance(body, dict):
            raise CoriqoAgentsError(status, "mandate response was not an object")
        return body, new_etag

    async def record_verdict(
        self,
        coriqo_agent_id: str,
        *,
        tool: str,
        verdict: str,
        reason: str | None = None,
        trajectory_id: str | None = None,
        step_index: int | None = None,
    ) -> dict[str, Any]:
        """Append what the runtime did about one tool call — permitted or
        blocked — sealed onto the agent's mandate chain.

        Never retried: it appends to a chain, so a resent verdict is a second
        blocked call that never happened.
        """
        return await self._request(
            "POST",
            f"{ENFORCEMENT_PREFIX}/agents/{coriqo_agent_id}/verdicts",
            json_body={
                "tool": tool,
                "verdict": verdict,
                "reason": reason,
                "trajectory_id": trajectory_id,
                "step_index": step_index,
            },
            signed=True,
        )

    async def ack_suspend(
        self,
        coriqo_agent_id: str,
        *,
        mandate_version_id: str,
        observed_at: str | None = None,
    ) -> dict[str, Any]:
        """AD-9: report that this host saw the agent's CURRENT suspend and
        stopped acting on it. Best-effort by design — callers (mandate.py's
        MandateGate) fire this from a background task and swallow any error,
        since posting the ack must never block the decide() path or the
        refresh loop. A failed ack just means Coriqo's UI shows this host as
        still-pending until a later attempt succeeds or a human checks the
        host directly; it never changes what the host itself does, which
        already denied the moment it saw `status == "suspended"`.
        """
        return await self._request(
            "POST",
            f"{ENFORCEMENT_PREFIX}/agents/{coriqo_agent_id}/suspend-ack",
            json_body={
                "mandate_version_id": mandate_version_id,
                "observed_at": observed_at,
            },
            signed=True,
        )

    async def request_tool_approval(
        self,
        coriqo_agent_id: str,
        *,
        request_id: str,
        tool: str,
        trajectory_id: str | None,
        step_index: int | None,
        mandate_version_id: str,
    ) -> dict[str, Any]:
        """AD-10: report a tool call the local gate classified as
        approval-required and did not execute. Idempotent on `request_id` —
        Coriqo returns the existing row on a retry rather than minting a new
        pending request. Best-effort by design, same posture as ack_suspend:
        callers (mandate.py's MandateGate.report_approval_request) fire this
        from a background task and swallow any error, since posting the
        report must never block decide() or the refresh loop. A failed
        report just means the request doesn't appear in Coriqo's queue yet;
        the local denial already applies regardless.
        """
        return await self._request(
            "POST",
            f"{ENFORCEMENT_PREFIX}/agents/{coriqo_agent_id}/approval-requests",
            json_body={
                "request_id": request_id,
                "tool": tool,
                "trajectory_id": trajectory_id,
                "step_index": step_index,
                "mandate_version_id": mandate_version_id,
            },
            signed=True,
        )

    async def record_verdict_batch(
        self,
        coriqo_agent_id: str,
        *,
        verdicts: Sequence[Mapping[str, Any]],
        batch_key: str | None = None,
    ) -> dict[str, Any]:
        """Ship a batch of local mandate verdicts, sealed as one governance event.

        The one write in this client that is retryable, and the reason is
        specific rather than a change of heart about writes. ``batch_key`` is
        chosen by the device and unique per device server-side: a repeat replays
        the stored result with ``duplicate: true`` and seals nothing, and two
        concurrent copies race a unique index where the loser gets a 409 that
        says *retry*. So a resend cannot produce a second governance record,
        which was the whole objection to retrying a write. Everything else here
        stays non-retryable.

        A 409 therefore joins the retry set for this call only. A 422 does not:
        an over-cap batch, a ``flagged``/``blocked`` verdict with no reason, or
        a verdict naming a mandate version that belongs to a different agent are
        all statements about the batch, and resending it changes nothing.

        The cap is enforced here rather than discovered as a 422, and a missing
        reason on a non-``allowed`` verdict likewise — both are things the
        caller can still fix at this point.

        Returns Coriqo's response, which carries ``anchor_mandate_version_id``
        and ``stale_mandate_version_count``: a host whose snapshot has drifted
        learns it from the reply rather than by reading the chain later.
        """
        if not verdicts:
            raise ValueError("verdicts must not be empty")
        if len(verdicts) > MAX_VERDICT_BATCH:
            raise ValueError(
                f"a batch holds at most {MAX_VERDICT_BATCH} verdicts, "
                f"got {len(verdicts)}"
            )
        for verdict in verdicts:
            if verdict.get("verdict") in _REASON_REQUIRED and not verdict.get("reason"):
                raise ValueError(
                    f"a {verdict.get('verdict')!r} verdict needs a reason; "
                    f"{verdict.get('tool')!r} has none"
                )
        return await self._request(
            "POST",
            f"{ENFORCEMENT_PREFIX}/agents/{coriqo_agent_id}/verdicts/batch",
            json_body={
                "batch_key": batch_key or new_batch_key(),
                "verdicts": [_wire_batch_verdict(v) for v in verdicts],
            },
            signed=True,
            idempotent=True,
            extra_retry_statuses=VERDICT_RETRY_STATUSES,
        )

    async def record_signed_trace(
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
        """:meth:`record_trace` attested by the device key instead of a
        service-account key. Same sealing path on Coriqo's side; what differs
        is who the sealed event names as actor. Never retried."""
        return await self._request(
            "POST",
            f"{ENFORCEMENT_PREFIX}/agents/{coriqo_agent_id}/traces",
            json_body=trace_body(
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
            signed=True,
        )

    async def attest_capability_snapshot(
        self,
        coriqo_agent_id: str,
        *,
        tools: Sequence[Mapping[str, Any]],
        system_prompt: str | None = None,
        model_id: str | None = None,
        runtime_version: str | None = None,
        store_system_prompt: bool = False,
    ) -> dict[str, Any]:
        """W-7: attest the actual tool/prompt/model surface this runtime
        loaded for ``coriqo_agent_id``, so Coriqo can detect capability drift
        against the mandate it approved — a tool silently added at the
        runtime layer, not through the governed change path, is exactly the
        kind of drift a mandate re-approval workflow can't see if nothing
        ever reports what actually loaded.

        The digest is computed locally with
        :func:`byoai.recorder.capability_digest.compute_capability_digest`
        (a port of Coriqo's ``cap-digest-v1``, unverified for byte-for-byte
        cross-repo parity — see that module's docstring) and sent alongside
        the raw inputs Coriqo needs to recompute and verify it; Coriqo 422s on
        a mismatch, so a bug in the local port surfaces as a hard failure here
        rather than a silently-wrong record.

        ``store_system_prompt`` defaults to ``False`` — the raw
        ``system_prompt`` field is omitted from the request whenever it is
        false, and only ``system_prompt_sha256`` (always sent) reaches
        Coriqo. This is the safe default in the absence of a visible
        Coriqo-side opt-in flag on the mandate snapshot; see the module
        that calls this (``mandate.py``) for where that follow-up belongs.

        Device-signed, like the rest of this client's enforcement calls.
        Never retried: a resent attestation is a second capability record,
        and Coriqo's endpoint has no idempotency key for it.
        """
        digest, prompt_hash = compute_capability_digest(
            tools=tools, system_prompt=system_prompt, model_id=model_id,
        )
        body: dict[str, Any] = {
            "tools": [dict(tool) for tool in tools],
            "system_prompt": system_prompt if store_system_prompt else None,
            "system_prompt_sha256": prompt_hash,
            "model_id": model_id,
            "runtime_version": runtime_version,
            "digest": digest,
            "digest_spec": DIGEST_SPEC,
        }
        return await self._request(
            "POST",
            f"{ENFORCEMENT_PREFIX}/agents/{coriqo_agent_id}/capability-snapshot",
            json_body=body,
            signed=True,
        )

    async def attest_execution(
        self,
        coriqo_agent_id: str,
        envelope: Mapping[str, Any],
    ) -> dict[str, Any]:
        """AIR-7d: ship one CEI v2 attestation envelope
        (:func:`byoai.recorder.attestation.build_envelope`) for
        ``coriqo_agent_id``.

        POSTs ``envelope`` verbatim to Coriqo's live contract
        (``POST {ENFORCEMENT_PREFIX}/attestations``; unlike its sibling
        enforcement calls there is no
        ``/agents/{id}/`` path segment for this endpoint, because the
        envelope already names its subject agent in ``envelope["subject"]``).
        ``coriqo_agent_id`` is taken as its own argument, rather than read
        back out of the envelope, purely so a caller building the envelope
        and a caller shipping it can't silently drift on which agent this
        is for — this raises ``ValueError`` if the two disagree instead of
        sending a mismatched envelope Coriqo would have to notice for us.

        **Signing scheme correction (AIR-7e).** This method was first
        written to sign this route with ``device_headers()``, the same tuple-based
        enforcement scheme ``attest_capability_snapshot``/``record_verdict``
        use. That is wrong for the route Coriqo actually ships:
        ``POST {ENFORCEMENT_PREFIX}/attestations`` depends on
        Coriqo's ledger-device signature check,
        the SECOND, raw signature scheme this codebase's own
        ``Shipper._post_signed_batch`` already speaks for
        ``/ingest/batch``/``/checkpoints/batch`` —
        ``Ed25519(canonicalize(body))`` over four headers
        (``content-type``, ``content-encoding: gzip``, ``x-coriqo-device``,
        ``x-coriqo-signature``), no timestamp, no public-key header. Signing
        this call with ``device_headers()`` instead produces a well-formed
        but wrong signature that Coriqo 401s with "Device signature did not
        verify" — caught only by AIR-7e's real round trip against a live
        server, never by a mock transport that only replays what a client
        already believes the contract is. An attestation route reasonably
        shares the no-timestamp ledger scheme rather than
        the replay-windowed enforcement one: ingest here is idempotent by
        construction (dedup on ``chain_head``), so a replayed attestation
        tells Coriqo nothing it was not already told — the same reasoning
        that scheme was built for. Coriqo's route is the fixed point — this
        client conforms to it, not the other way round.

        Modeled directly on :meth:`attest_capability_snapshot`: device-signed,
        never retried. Coriqo's idempotency key for this endpoint is the
        envelope's own ``chain_head`` — a resend of the exact same
        envelope comes back ``duplicate`` and reseals nothing, while a client
        retry that silently reshaped the batch first would produce a
        different ``chain_head`` under the same window, i.e. a second,
        divergent attestation. So, like ``attest_capability_snapshot``, this
        client never retries the call itself; the caller (``shipper.py``)
        treats a ``duplicate`` response the same as a fresh accept when
        advancing its own attestation sync watermark, and treats a refused
        (4xx) envelope as a hard failure it does not resend.
        """
        subject_agent_id = envelope.get("subject", {}).get("agent_id")
        if subject_agent_id is not None and subject_agent_id != coriqo_agent_id:
            raise ValueError(
                f"envelope subject.agent_id ({subject_agent_id!r}) does not match "
                f"coriqo_agent_id ({coriqo_agent_id!r})"
            )
        signer = self._identity.require_enforcement()
        canonical_body = canonicalize(dict(envelope))
        signature = signer.sign(canonical_body)
        payload = gzip.compress(canonical_body)
        headers = {
            "content-type": "application/json",
            "content-encoding": "gzip",
            "x-coriqo-device": signer.device_id,
            "x-coriqo-signature": signature,
        }
        if self._tenant_slug:
            headers["X-Tenant-Slug"] = self._tenant_slug
        request = self._client.build_request(
            "POST", f"{ENFORCEMENT_PREFIX}/attestations", content=payload, headers=headers,
        )
        # Same rule `_build` enforces for the tuple-scheme signed calls: a
        # caller-supplied client's default headers must never carry a
        # service-account key onto a device-signed request — this route
        # would refuse it just the same as the enforcement ones do.
        request.headers.pop("X-API-Key", None)
        response = await self._client.send(request)
        body, _status = parse_response(response, path=f"{ENFORCEMENT_PREFIX}/attestations")
        return body


def _default_tenant_slug(identity: CoriqoIdentity) -> str | None:
    """Tenant for the ``X-Tenant-Slug`` header, when the caller named none.

    Both kinds of identity carry their own tenant: a static-key one from
    ``BYOAI_CORIQO_TENANT_SLUG`` via :class:`CoriqoCredentials`, an enrolled
    device from ``enrollment.json``. The env var stays as the fallback for the
    one case that has neither — a device enrolled before the tenant was
    persisted, which is every device already in the field. Falling back keeps
    those hosts enforcing until they are re-enrolled; ``identity.py`` warns
    once that they should be.
    """
    if identity.tenant_slug:
        return identity.tenant_slug
    if identity.credentials is not None:
        # A CoriqoIdentity built by hand rather than through
        # from_credentials() has credentials but no mirrored tenant_slug;
        # reading it here keeps that construction working as it did before.
        return identity.credentials.tenant_slug
    return os.environ.get("BYOAI_CORIQO_TENANT_SLUG") or None


def _error_for(response: httpx.Response, *, path: str) -> CoriqoAgentsError:
    """The error a retryable status would raise if it were the last attempt.

    Built through :func:`parse_response` so a retried-then-exhausted failure is
    indistinguishable from a first-attempt one — same type, same ``detail``.
    """
    try:
        parse_response(response, path=path)
    except CoriqoAgentsError as exc:
        return exc
    return CoriqoAgentsError(response.status_code, response.text)
