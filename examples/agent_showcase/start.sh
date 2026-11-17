#!/usr/bin/env bash
# Installs byoai-runtime (editable, with the fastapi + recorder extras) and
# launches the Agent Showcase demo. Run from anywhere; paths are resolved
# relative to this script.
#
#   ./start.sh
#
# Env vars (all optional, see README.md for the full list):
#   ANTHROPIC_API_KEY, OPENAI_API_KEY   live model calls (falls back to
#                                       cached transcripts if unset)
#   BYOAI_RECORDER_ENABLED=1           seal every run to the Coriqo ledger
#                                       (on by default here — set to 0 to
#                                       disable and confirm /verify reports
#                                       the recorder as disabled)
#   BYOAI_RECORDER_DIR                 ledger dir, defaults to ~/.byoai/recorder
#   BYOAI_DEMO_LIVE_CALL_STATE         file tracking each agent's last live
#                                       call, defaults to
#                                       ~/.byoai/agent_showcase_live_calls.json
#                                       (persists the 24h live-call TTL across
#                                       restarts)
#   DEMO_TAMPER=1                      enable the /api/demo/tamper endpoint
#   BYOAI_DEMO_AUTOPILOT=1             background traffic every 90-240s
#   BYOAI_DEMO_STEP_DELAY_MS           pace fallback-transcript replay so the
#                                       UI's heartbeat/active-card/workflow
#                                       indicators are visible (400ms here;
#                                       fallback replay has no real network
#                                       latency of its own, so without this
#                                       every step fires in milliseconds)
#   PORT                               port to serve the demo on, defaults to
#                                       8001 (not 8000 — a local Coriqo's API
#                                       already binds that)
#   BYOAI_CORIQO_URL                   publish every run to this Coriqo as
#                                       governed agent evidence, e.g.
#                                       http://localhost:8000. Unset = off
#   BYOAI_CORIQO_API_KEY               Coriqo service account key (cq_sa_...)
#   BYOAI_CORIQO_TENANT_SLUG           Coriqo tenant slug, e.g. acme_bank
#   BYOAI_CORIQO_AUTO_REGISTER         1 (default) self-registers each agent
#                                       with Coriqo on startup, which is
#                                       idempotent; 0 publishes nothing
#   HTTPX_LOG_LEVEL=DEBUG               log raw outbound httpx/httpcore wire
#                                       traffic (request lines, connection
#                                       pool events) to the console — use
#                                       this to confirm live calls are
#                                       actually leaving the process, e.g.
#                                       to api.anthropic.com or a local
#                                       Coriqo ingest endpoint
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

for ENV_FILE in "$REPO_ROOT/.env" "$SCRIPT_DIR/.env"; do
  if [ -f "$ENV_FILE" ]; then
    echo "==> Loading $ENV_FILE"
    set -a
    # shellcheck disable=SC1091
    source "$ENV_FILE"
    set +a
  fi
done

cd "$REPO_ROOT"

# boto3 is only pulled in when B6 is actually pointed at AWS. It is a large
# dependency and every other agent in this gallery runs without it, so a demo
# box that will never call Bedrock should not pay for it.
EXTRAS="fastapi,recorder"
if [ -n "${BYOAI_BEDROCK_AGENT_ID:-}" ]; then
  EXTRAS="$EXTRAS,bedrock-agent"
fi

echo "==> Installing byoai-runtime (editable) with $EXTRAS extras"
pip install -e ".[$EXTRAS]"

export BYOAI_RECORDER_ENABLED="${BYOAI_RECORDER_ENABLED:-1}"
export BYOAI_RECORDER_DIR="${BYOAI_RECORDER_DIR:-$HOME/.byoai/recorder}"
export BYOAI_DEMO_STEP_DELAY_MS="${BYOAI_DEMO_STEP_DELAY_MS:-400}"
PORT="${PORT:-8001}"

echo "==> Recorder: BYOAI_RECORDER_ENABLED=$BYOAI_RECORDER_ENABLED  BYOAI_RECORDER_DIR=$BYOAI_RECORDER_DIR"
if [ "$BYOAI_RECORDER_ENABLED" = "1" ]; then
  echo "    Runs will be sealed to the ledger above. Check with:"
  echo "      curl -s localhost:$PORT/api/runs/<run_id>/verify | python -m json.tool"
else
  echo "    Recorder disabled — runs will NOT be sealed; /verify will report it as disabled."
fi

if [ -n "${BYOAI_BEDROCK_AGENT_ID:-}" ] && [ -n "${BYOAI_BEDROCK_AGENT_ALIAS_ID:-}" ]; then
  echo "==> B6 will call a real Bedrock agent: $BYOAI_BEDROCK_AGENT_ID / $BYOAI_BEDROCK_AGENT_ALIAS_ID"
  echo "    Region: ${BYOAI_BEDROCK_REGION:-${AWS_REGION:-<from your AWS config>}}"
  echo "    Credentials come from the usual boto3 chain (env vars, AWS_PROFILE, SSO, instance role)."
  echo "    The role needs bedrock:InvokeAgent on that agent alias — see the README."
elif [ -n "${BYOAI_BEDROCK_AGENT_ID:-}" ] || [ -n "${BYOAI_BEDROCK_AGENT_ALIAS_ID:-}" ]; then
  # Half-set is the common first-run mistake, and it fails silently into a
  # replay that looks like a working live run.
  echo "==> B6: BYOAI_BEDROCK_AGENT_ID and BYOAI_BEDROCK_AGENT_ALIAS_ID must BOTH be set."
  echo "    Only one is set, so B6 will replay its recorded trace instead."
else
  echo "==> B6 will replay its recorded Bedrock trace (set BYOAI_BEDROCK_AGENT_ID +"
  echo "    BYOAI_BEDROCK_AGENT_ALIAS_ID to call a real agent in your own account)"
fi

if [ -n "${BYOAI_CORIQO_URL:-}" ]; then
  echo "==> Coriqo sync: $BYOAI_CORIQO_URL (tenant ${BYOAI_CORIQO_TENANT_SLUG:-<unset>})"
  echo "    Agents self-register on startup and land 'in review'. Check with:"
  echo "      curl -s localhost:$PORT/api/coriqo/status | python -m json.tool"
else
  echo "==> Coriqo sync off (set BYOAI_CORIQO_URL to publish runs as governed evidence)"
fi

echo "==> Starting uvicorn on http://localhost:$PORT"
exec uvicorn examples.agent_showcase.app:app --reload --port "$PORT"
