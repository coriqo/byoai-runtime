"""Wires the showcase's agents and runs into Coriqo.

All the reusable machinery lives in :mod:`byoai.recorder.coriqo_agents` —
credentials, the client, registration idempotency, reading sealed steps back
out of the ledger, publishing a session. What's left here is the part that is
genuinely specific to this demo: turning an ``AgentDef`` into an
:class:`AgentRegistration`, and deciding that a Coriqo failure must never take
down a run.

That second part is a policy choice, not a technical one. The core API raises
so a caller can decide; this app log-and-continues, because the ledger already
holds the authoritative record and a demo should keep working with Coriqo
switched off, mirroring how ``recorder/integration.py`` treats an unenrolled
device.
"""

from __future__ import annotations

import logging
import os
import threading

from byoai.recorder.coriqo_agents import (
    AgentRegistration,
    CoriqoAgentsClient,
    CoriqoAgentsError,
    CoriqoCredentials,
    ensure_registered,
    publish_session,
)
from byoai.recorder.integration import get_recorder

from .agents.registry import get_agent, list_agents
from .agents.types import AgentDef

log = logging.getLogger("agent_showcase.coriqo_sync")

# Banking and healthcare agents both act on regulated decisions, so neither
# domain gets to look low-risk in Coriqo's registry.
_RISK_TIER_BY_DOMAIN = {"banking": "high", "healthcare": "high"}
_DEFAULT_RISK_TIER = "medium"

# Namespaces the external_id Coriqo dedupes registrations on, so this demo's
# "b1-fraud-triage" can't collide with another publisher's agent of the same
# key in a shared tenant.
_EXTERNAL_ID_PREFIX = "byoai-agent-showcase:"

# Publishing runs on worker threads, so the shared client is built under a lock.
_CLIENT: CoriqoAgentsClient | None = None
_CLIENT_LOCK = threading.Lock()


def enabled() -> bool:
    return CoriqoCredentials.from_env() is not None


def _auto_register_enabled() -> bool:
    return os.environ.get("BYOAI_CORIQO_AUTO_REGISTER", "1") == "1"


def _registration(agent: AgentDef) -> AgentRegistration:
    """``allowed_tools`` is the agent's real declared surface, which matters:
    Coriqo flags any recorded call outside it and opens a mandate Finding, so a
    padded or trimmed list here would flag every ordinary run. Sub-agent
    trigger tools are declared tools too, so ``declared_tool_names`` is already
    the complete set — which leaves the b5-misfire-demo agent's out-of-scope
    call as a genuine finding, exactly what it exists to demonstrate.
    """
    return AgentRegistration(
        name=agent.name,
        mandate=agent.description,
        system=agent.system or f"byoai-agent-showcase/{agent.domain}",
        risk_tier=_RISK_TIER_BY_DOMAIN.get(agent.domain, _DEFAULT_RISK_TIER),
        allowed_tools=tuple(sorted(agent.declared_tool_names)),
        use_case=agent.use_case,
    )


def ensure_agents_registered(agents: list[AgentDef] | None = None) -> dict[str, str]:
    """Registers every showcase agent that isn't mapped yet; returns the map.

    Only the top-level catalog is registered. A sub-agent's work reaches Coriqo
    as its parent's tool call instead, because Coriqo has no parent link
    between trajectories — publishing sub-runs independently would produce runs
    nobody could tie back to the run that spawned them.
    """
    credentials = CoriqoCredentials.from_env()
    if credentials is None:
        return {}

    if not _auto_register_enabled():
        log.info("coriqo_sync: auto-register off, publishing nothing this session")
        return {}

    registrations = {agent.id: _registration(agent) for agent in (agents or list_agents())}
    try:
        with CoriqoAgentsClient(credentials) as client:
            try:
                return ensure_registered(
                    client, registrations, external_id_prefix=_EXTERNAL_ID_PREFIX
                )
            except CoriqoAgentsError as exc:
                if exc.status_code != 403:
                    raise
                # A publishing key normally can't register (that takes
                # governance:approve), but can still publish against agents a
                # governance user already registered under the same external_id.
                return _resolve_existing(client, registrations, refused=exc.detail)
    except CoriqoAgentsError as exc:
        log.warning("coriqo_sync: could not register agents (%s), sync inactive", exc.detail)
        return {}


def _resolve_existing(
    client: CoriqoAgentsClient, registrations: dict, *, refused: str
) -> dict[str, str]:
    by_external_id = {
        item.get("external_id"): item.get("agent_id") for item in client.list_agents()
    }
    resolved = {
        key: str(by_external_id[f"{_EXTERNAL_ID_PREFIX}{key}"])
        for key in registrations
        if by_external_id.get(f"{_EXTERNAL_ID_PREFIX}{key}")
    }
    missing = sorted(set(registrations) - set(resolved))
    if missing:
        log.warning(
            "coriqo_sync: registration refused (%s); not registered yet, so not published: %s",
            refused,
            ", ".join(missing),
        )
    return resolved


def publish_run(
    run_id: str,
    showcase_agent_id: str,
    *,
    agent_map: dict[str, str],
    final_text: str | None = None,
    goal: str | None = None,
) -> None:
    """Publishes one completed run. Never raises. ``goal`` defaults to the
    agent's default scenario, for a run that was not bound to a case."""
    credentials = CoriqoCredentials.from_env()
    if credentials is None:
        return

    coriqo_agent_id = agent_map.get(showcase_agent_id)
    if not coriqo_agent_id:
        log.info(
            "coriqo_sync: %s is not registered with Coriqo, skipping run %s",
            showcase_agent_id,
            run_id,
        )
        return

    recorder = get_recorder()
    if recorder is None:
        log.info("coriqo_sync: recorder disabled, nothing sealed to publish for %s", run_id)
        return

    agent = get_agent(showcase_agent_id)
    if goal is None:
        goal = agent.scenario_message if agent is not None else f"showcase run {run_id}"

    try:
        publish_session(
            _shared_client(credentials),
            coriqo_agent_id=coriqo_agent_id,
            ledger=recorder.ledger,
            session_id=run_id,
            goal=goal,
            final_output=final_text,
            payload_mode=recorder.payload_mode,
            inputs_extra={"showcase_agent": showcase_agent_id},
        )
    except CoriqoAgentsError as exc:
        log.warning("coriqo_sync: publishing run %s failed: %s", run_id, exc.detail)


def _shared_client(credentials: CoriqoCredentials) -> CoriqoAgentsClient:
    """One client for the process, built on first publish.

    Runs finish continuously (and the autopilot keeps them coming), so building
    a client per run would pay a fresh TCP/TLS handshake each time instead of
    reusing a pooled connection — the same reason the context cache moved off a
    per-request client. Publishing happens on worker threads, so creation is
    guarded; the underlying ``httpx.Client`` is itself safe to share across
    them.
    """
    global _CLIENT
    with _CLIENT_LOCK:
        if _CLIENT is None:
            _CLIENT = CoriqoAgentsClient(credentials)
        return _CLIENT


def close() -> None:
    """Releases the shared client. Call on application shutdown."""
    global _CLIENT
    with _CLIENT_LOCK:
        if _CLIENT is not None:
            _CLIENT.close()
            _CLIENT = None
