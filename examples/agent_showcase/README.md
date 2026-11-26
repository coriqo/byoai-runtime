# ByoAI Demo Agent Showcase

Client-facing demo: enterprise agents captured live by byoai-runtime, sealed
by the Coriqo agent recorder, verifiable after the fact.

**Status: M5 — feature-complete, plus B6.** All milestones (M1-M5) landed: 10
agents (8 real, 1 deliberate misfire demo, 1 managed AWS Bedrock Agent), sub-agent spans, the UI, verify,
sealed replay, the tamper demo, and a Coriqo shipping smoke test.

**Status detail — M2, all 8 agents.** All four banking agents (B1 Fraud Triage, B2
KYC Onboarding, B3 Dispute Resolution, B4 Loan Prequalification) and all four
healthcare agents (H1 Prior Authorization, H2 Clinical Documentation, H3
Patient Intake, H4 Claims Denial Appeal) run end-to-end and are sealed by the
recorder, with a verify endpoint. B2, B4, and H1 each delegate one step to a
sub-agent (Sanctions Screener, Document Extractor, Criteria Matcher
respectively); the recorder attributes each sub-agent's events to a distinct
span sharing the parent run's `trace_id`, with `parent_span_id` set to the
parent's `span_id`.

H1-H4 (`provider="openai"`) make real OpenAI chat-completions calls via
`OpenAICompatProvider` when `OPENAI_API_KEY` is set. The recorder's extractor
only understands Anthropic-shaped request/response bodies, so the OpenAI live
path normalizes each turn into that shape (text/tool_use content blocks)
before sealing it — the actual wire call is genuine OpenAI; only what's fed
to the recorder is re-shaped so one extractor covers both providers.

**M3 — UI.** A static single-page UI (`ui/`, served at `/`) lists the agent
gallery, runs an agent, streams its timeline live over SSE, renders the span
tree (root + sub-agent spans), and calls `/verify` on demand.

**B6 — a managed AWS Bedrock Agent.** Every other agent here is ours: our
loop, our tool dispatch, our process. B6 is not. AWS builds the prompts, picks
the tools, calls the Lambdas and decides when to stop, so there is nothing to
intercept and nothing to decorate. The evidence comes out of the agent's own
`InvokeAgent` trace instead, normalized by `byoai.recorder.bedrock_agent` into
the same sealed events every other agent produces.

Set `BYOAI_BEDROCK_AGENT_ID` and `BYOAI_BEDROCK_AGENT_ALIAS_ID` and it invokes
a real agent in your account. Unset — the default — it replays
`fallbacks/b6_bedrock_sanctions_review.json`, which holds real response-stream
events rather than the step transcripts the other agents fall back to, so the
no-credentials path runs the same normalizer the live path runs. Nothing about
the demo is stubbed; only the input is recorded.

The recorded run screens a held payment, hits a 0.71 partial OFSI match, reads
its own knowledge base, asks a collaborator agent about the settlement window,
and refuses to release the payment. Two things happen alongside that, and the
pairing is the point:

- **A Bedrock guardrail intervenes**, and the ledger records that AWS's own
  control fired — a `guardrail_intervention` event, distinct from anything we
  decided.
- **A `returnControl` call asks the caller to run
  `PaymentActions::initiate_wire_transfer`** — outside the agent's declared
  action groups, for the payment it just said to hold. The guardrail did not
  stop it, because a guardrail scores content, not authority. The recorder
  seals it like any other call and the app flags it against
  `declared_tool_names`.

That second one has the least coverage anywhere else: a `returnControl` action
runs in the caller's own process, so it appears in no AWS log at all. Without
this seam the request would exist nowhere. `coriqo-verify` reports it as an
unpaired `tool_use`, which is correct — nothing executed it.

Point the showcase at a Coriqo (below) and the whole thing lands there with no
Bedrock-specific wiring: B6 registers with its `actionGroup::function` names as
`allowed_tools`, the run publishes as a flagged trajectory with four decision
traces, and Coriqo raises its own **major open finding** for the wire transfer.
### Pointing B6 at your own Bedrock agent

Nothing below is needed to run the demo — B6 replays a recorded trace by
default. This is for running it against an agent in your own AWS account.

**1. Install the extra.** `boto3` is not a base dependency; every other agent
here runs without it.

```bash
pip install "byoai-runtime[fastapi,recorder,bedrock-agent]"
```

`start.sh` adds `bedrock-agent` on its own when `BYOAI_BEDROCK_AGENT_ID` is
set, so exporting the vars before running it is enough.

**2. Give the caller credentials.** There is no credential handling in this
code — `boto3.client()` is called with nothing but a region, so the standard
chain applies unchanged: `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`,
`AWS_PROFILE` against `~/.aws/credentials`, `aws sso login`, or an instance
/task role if you run the demo on EC2 or ECS. Whatever `aws sts
get-caller-identity` works with here will work.

**3. Allow the one call.** `InvokeAgent` against the alias, and nothing else:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "bedrock:InvokeAgent",
    "Resource": "arn:aws:bedrock:<region>:<account>:agent-alias/<AGENT_ID>/<ALIAS_ID>"
  }]
}
```

The agent's own execution role is what needs `bedrock:InvokeModel`, Lambda
invoke, and knowledge-base access — that role is yours already and this demo
does not touch it. If you also want the after-the-fact CloudWatch path
(`iter_cloudwatch_invocations`), add `logs:FilterLogEvents` on the log group.

**4. Export the ids and run.**

```bash
export BYOAI_BEDROCK_AGENT_ID=ABCDE12345      # the agent, not its ARN
export BYOAI_BEDROCK_AGENT_ALIAS_ID=FGHIJ67890 # a PUBLISHED alias, not DRAFT/TSTALIASID
export BYOAI_BEDROCK_REGION=eu-west-2          # optional; falls back to your AWS config
./start.sh
```

Both ids are required. With only one set, `/api/agents` reports B6 as not
live and the run replays — deliberately, since a half-configured agent cannot
be invoked and reporting it as live would promise a run that fails.

**5. Check it actually went to AWS.** `/api/agents` shows `"live": true` once
both vars are set, but that only means the demo will *try*. The run itself is
the proof: a live run's timeline has no `api_error`, and its steps carry your
own action groups rather than `SanctionsActions::screen_party`.

```bash
curl -s localhost:8001/api/agents | python -m json.tool | grep -A2 bedrock
```

If the call fails, the run falls back to the recorded trace **and says why** —
an `api_error` event carrying the AWS error, sealed into the ledger like any
other. The three that come up first:

| What you see | What it usually is |
|---|---|
| `AccessDeniedException` | the policy above is missing, or names the agent rather than the agent *alias* |
| `ResourceNotFoundException` | wrong region, or the alias id is `TSTALIASID`/a draft that was never published |
| `boto3 is required for Bedrock agent ingest` | the `bedrock-agent` extra isn't installed |

**6. Tracing is not optional.** `stream_invocation` sets `enableTrace=True`
and does not take an override. Without it AWS returns the answer and no
orchestration steps, which would seal an empty run — evidence that reads like
a quiet agent rather than like a missing flag.

**What this costs.** One `InvokeAgent` per run, billed to you at your agent's
usual rate, plus whatever its action groups and knowledge bases cost. The
24-hour live-call TTL applies to B6 like every other agent, so mashing the Run
button replays the cached trace instead of spending again; `?force_live=true`
bypasses it.

The guardrail intervention travels too, to its own endpoint, and shows up on
the agent's Runs tab under *Controls outside Coriqo* — attributed to AWS,
sealed, and deliberately kept out of the flagged count. That separation is
worth pointing at in a demo: the wire transfer is the agent breaching its
mandate, the guardrail is somebody else's control firing, and a screen that
merged them would tell a bank neither.

**Misfire demo (B5).** `b5-misfire-demo` has the exact same declared tool
schema as B1 Fraud Triage, but its fallback transcript calls
`initiate_wire_transfer` — a tool that was never offered to the model,
simulating a mis-fired or prompt-injected action. The recorder seals that
event exactly like any other (capture doesn't care about scope); the demo
app then flags it after the fact by diffing the tool call against the
agent's declared schema (`AgentDef.is_out_of_scope`, `runner.py`
`_tool_use_data`, exposed as `policy_violations`/`flagged` on
`/api/runs/{run_id}`) and highlights it in the UI. `/verify` still reports a
clean chain — the point isn't that the ledger breaks, it's that the audit
trail makes the off-scope action undeniable and inspectable.

**M4 — replay, tamper demo.** `GET /api/runs/{run_id}/replay` reconstructs a
run purely from the sealed ledger (queries `agent_events` by `session_id`,
no `_RUNS` in-memory state involved) — proves the ledger alone is sufficient
to audit a run, e.g. after a process restart. `POST
/api/demo/tamper/{run_id}` (gated behind `DEMO_TAMPER=1`; 403 otherwise)
flips a sealed row's payload in place without recomputing its hash, so a
follow-up `/verify` visibly flips from green to red for that run — the UI's
verify panel has a "Tamper demo" button that does exactly this live.

**M5 — Coriqo shipping smoke test, polish.**
`tests/test_coriqo_shipping.py` runs a real agent through the app (sealing
real events into the real local ledger), then hands that ledger + device key
to byoai-runtime's public `Shipper` class against a local double standing in
for Coriqo's `/v1/ingest/batch` (`httpx.MockTransport` — no live Coriqo
credentials needed to prove the wiring). Confirms the batch is signed
(`ed25519:`-prefixed device signature), gzip-encoded, accepted, and the
ledger's sync watermark advances — and that a second ship attempt finds
nothing left to send. Acceptance criteria all verified: 8 agents
complete end-to-end with correct span parenting, event counts match the
ledger, verify flips red on tamper and names the exact seq, replay survives
`_RUNS` being wiped, fallback engages on API outage, and cold start is well
under a second (`uvicorn ... ` to first successful request).

All data is synthetic — no real customers, patients, or institutions.

## Quick start

```bash
./start.sh
```

Installs `byoai-runtime` editable (`fastapi` + `recorder` extras) from the
repo root and launches uvicorn with the recorder on by default
(`BYOAI_RECORDER_ENABLED=1`), so every run is sealed to the ledger. Check
with `curl -s localhost:8001/api/runs/<run_id>/verify | python -m json.tool`.
Set `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` first for live model calls; without
them agents fall back to cached transcripts. See `start.sh` for the rest of
the env vars it reads.

## Setup (manual)

```bash
pip install 'byoai-runtime[fastapi,recorder]' uvicorn
export ANTHROPIC_API_KEY=sk-ant-...        # optional — powers B1-B4 live;
                                            # falls back to a cached transcript
                                            # if unset/unavailable
export OPENAI_API_KEY=sk-...               # optional — same, for H1-H4
export BYOAI_RECORDER_ENABLED=1
export BYOAI_RECORDER_DIR=~/.byoai/demo    # optional, defaults to ~/.byoai/recorder
export BYOAI_DEMO_AUTOPILOT=1              # optional — pings a random agent
                                            # every 1.5-4min to keep the demo alive
```

## Run

```bash
uvicorn examples.agent_showcase.app:app --reload --port 8001
```

Port 8001 rather than uvicorn's default 8000, which a local Coriqo's API
already binds — the two are meant to run side by side (see
[Publishing runs to Coriqo](#publishing-runs-to-coriqo)).

## Try it

Open http://localhost:8001/ for the UI, or drive the API directly:

```bash
curl -s localhost:8001/api/agents | python -m json.tool

run_id=$(curl -s -X POST localhost:8001/api/agents/b2-kyc-onboarding/run | python -c 'import json,sys;print(json.load(sys.stdin)["run_id"])')

curl -s localhost:8001/api/runs/$run_id | python -m json.tool

curl -s localhost:8001/api/runs/$run_id/verify | python -m json.tool
```

## Env vars

`start.sh` auto-loads and exports every variable from a `.env` file in the
repo root or this directory, if either exists, before setting any of the
defaults below — a convenient place to keep the vars in this table without
retyping `export` each time you run it.

| Var | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Live model calls for B1-B4. If unset or the call fails, the agent replays its recorded fallback transcript (`fallbacks/`) instead — the run still completes and the recorder still seals real events. |
| `OPENAI_API_KEY` | Live model calls for H1-H4, same fallback behavior as above. |
| `BYOAI_RECORDER_ENABLED` | `1` to capture/seal every run to the local ledger. Without it, agents still run but nothing is sealed and `/verify` reports the recorder as disabled. |
| `BYOAI_RECORDER_DIR` | Ledger/device-key directory. Defaults to `~/.byoai/recorder`. |
| `BYOAI_DEMO_AUTOPILOT` | `1` to start a background loop that runs a random agent every 90-240s, mimicking real bank/healthcare traffic. Off by default so importing the app (tests, one-off runs) never spends API credits on its own. |
| `DEMO_TAMPER` | `1` to enable `/api/demo/tamper/{run_id}`, which flips a byte in a sealed row to demonstrate `/verify` catching it. |
| `BYOAI_DEMO_STEP_DELAY_MS` | Milliseconds to pause between fallback-transcript replay steps. Fallback replay has no real network latency, so without this every step fires in milliseconds — too fast for the UI's heartbeat/active-card/workflow indicators to be seen. `start.sh` sets this to `400` by default; `0` (the library default) disables pacing, which is what the test suite runs with. |
| `BYOAI_DEMO_LIVE_CALL_STATE` | File tracking each agent's last live-call time, so the 24h live-call TTL (below) survives a server restart. Defaults to `~/.byoai/agent_showcase_live_calls.json`. |
| `BYOAI_BEDROCK_AGENT_ID` | Invoke a real AWS Bedrock agent for B6 instead of replaying its recorded trace. Requires the alias below; standard AWS credentials apply. Needs `pip install 'byoai-runtime[bedrock-agent]'`. |
| `BYOAI_BEDROCK_AGENT_ALIAS_ID` | The agent alias to invoke. Both this and the id must be set — `/api/agents` reports B6 as not live otherwise, rather than promising a run that will fail. |
| `BYOAI_BEDROCK_REGION` | Region for the Bedrock call. Falls back to the usual boto3 resolution (`AWS_REGION`, profile, instance metadata). |
| `PORT` | Port to serve on. Defaults to `8001`, since a local Coriqo API takes 8000. |
| `BYOAI_CORIQO_URL` | Publish every run to this Coriqo as governed agent evidence, e.g. `http://localhost:8000`. Unset (the default) turns sync off entirely. |
| `BYOAI_CORIQO_API_KEY` | Coriqo service account key (`cq_sa_...`). Required with the URL. |
| `BYOAI_CORIQO_TENANT_SLUG` | Coriqo tenant slug, e.g. `acme_bank`. Required with the URL. |
| `BYOAI_CORIQO_AUTO_REGISTER` | `1` (default) self-registers each agent with Coriqo on startup, which is idempotent — Coriqo dedupes on the agent's `external_id`, so restarts reuse the same agents. `0` publishes nothing. |

`/api/agents` reports each agent's current `"live"` status — `true` if its provider's API key is set, `false` if it's running off the cached transcript.

### Live-call TTL and misfire injection

`POST /api/agents/{agent_id}/run` takes two optional query params:

- `force_live=true` — bypass the 1-day live-call TTL (below) and always attempt a live call for this run.
- `inject_misfire=true` — skip the live call entirely and force the fallback path, simulating a provider misfire (timeout, bad response) on demand. The run's events include a `"misfire"` event and `run_complete.data.mode` is `"misfire"`.

Once an agent has been called live, repeat runs of that same agent within **24 hours** replay its cached fallback transcript instead of spending API credits again (`runner.LIVE_CALL_TTL_SECONDS`). This is persisted to `BYOAI_DEMO_LIVE_CALL_STATE` (above), so it survives a server restart. `run_complete.data.mode` reports which path a run took: `"live"`, `"replay"` (live call failed), `"cached"` (TTL cooldown), or `"misfire"` (injected).

```bash
curl -s -X POST "localhost:8001/api/agents/b1-fraud-triage/run?inject_misfire=true" | python -m json.tool
```

## Publishing runs to Coriqo

The local ledger proves a run happened as recorded. Coriqo is where that
becomes governance: an agent registry, the mandate each agent is allowed to act
under, and a hash-chained trail of what every agent actually did. Point the
showcase at a Coriqo and each agent registers itself once, then every run is
published as a trajectory plus one decision trace per sealed step.

The machinery is part of the runtime, not this example:
`byoai.recorder.coriqo_agents` holds the client, registration, and publishing
(documented in
[CONFIGURATION.md](../../CONFIGURATION.md#publishing-runs-to-coriqos-agent-api-byoairecordercoriqo_agents)),
so any agent can use it. `coriqo_sync.py` here is only the adapter: it maps an
`AgentDef` onto a registration and log-and-continues on failure.

```bash
export BYOAI_CORIQO_URL=http://localhost:8000
export BYOAI_CORIQO_API_KEY=cq_sa_...        # POST /api/v1/service-accounts
export BYOAI_CORIQO_TENANT_SLUG=acme_bank
./start.sh

curl -s localhost:8001/api/coriqo/status | python -m json.tool
```

The service account needs `governance:approve` (to register agents) and
`model:write` (to record traces). Registered agents land at `in_review` —
Coriqo never pre-approves, so self-registration files a governance to-do
rather than granting an agent any standing.

Two things make this evidence rather than telemetry:

- Steps are read back out of the sealed ledger, not the app's in-memory run
  state. If it wasn't sealed, it isn't published.
- Each step's `args_hash`/`result_hash` are the ledger's own `payload_hash`
  values, which commit to the raw payload whatever
  `BYOAI_RECORDER_PAYLOAD_MODE` is set to. So both stores commit to the same
  bytes: a hash from a Coriqo trace resolves to the sealed row it came from,
  and `coriqo-verify` still checks the ledger offline. Neither store has to be
  trusted alone. No raw tool payloads are sent.
- The one exception is the run's final decision text (a step's `output`),
  which ships as readable prose on purpose — that's the point of a decision
  trace. Under the default `redacted` mode it's still passed through a
  `TextRedactor` first — `redact_free_text` by default, masking known
  secret/PII shapes (email, SSN, credit card, API key) wherever they appear
  in the sentence; anything without a fixed shape (a name, an address) is not
  caught by the default, since there's no pattern to match it against.
  `publish_session`'s `redactor` parameter accepts a different one (e.g.
  something NER-backed) for callers who need name-level redaction and are
  willing to own that dependency/latency tradeoff themselves — this demo
  doesn't wire one in, so it stays on the default. `hash-only` drops the
  field entirely instead; `full` ships it untouched.

Coriqo checks every recorded call against the agent's `allowed_tools`. Running
the `b5-misfire-demo` agent shows both halves agreeing — its out-of-scope
`initiate_wire_transfer` call trips the showcase's own guardrail and comes back
from Coriqo as a `flagged` trace with a mandate Finding attached:

```bash
curl -s -X POST "localhost:8001/api/agents/b5-misfire-demo/run?inject_misfire=true"
```

Sub-agent runs stay sealed in the ledger but are not published as separate
Coriqo agents. Coriqo can nest one run under another, but only within the same
agent — and each showcase sub-agent is its own `AgentDef` with its own mandate
and tools, so nesting is refused for exactly the case we have. A sub-agent's
work reaches Coriqo as its parent's tool call instead, carrying the same hashes.
The full contract — batching, mandate enforcement, grounding anchors, nesting —
is in
[CONFIGURATION.md](../../CONFIGURATION.md#publishing-runs-to-coriqos-agent-api-byoairecordercoriqo_agents).

Coriqo being down costs visibility, not evidence — publishing failures are
logged and the run completes normally.

## Tests

```bash
pytest examples/agent_showcase/tests
```
