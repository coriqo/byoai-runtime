# Shield event envelope v1

The envelope is a small set of **additive** fields that say what a Shield row
means: what kind of AI event it records, how strongly the collector knows it,
who saw it, what policy decided and what happened. It is the interface the
adapter, scanner, collectors and the Coriqo side all code to.

- Schema: [`src/byoai/shield_envelope.schema.json`](https://github.com/coriqo/byoai-runtime/blob/main/src/byoai/shield_envelope.schema.json) (JSON Schema 2020-12)
- Fixtures: `tests/fixtures/shield_envelope/` (`valid/` one row per existing kind, `invalid/` negative cases)
- Test: `tests/integrations/test_shield_envelope_schema.py`

This is a format document. Nothing here changes hashing, canonical JSON,
signed bytes or the recorder `EventKind` list.

## What the code looks like today (sources read for this spec)

| Source | What it fixes |
|---|---|
| `src/byoai/integrations/shield.py`: `BROWSER_KINDS`, `clean_browser_row` | Browser rows are rebuilt from an allowlist of fields. Anything else, message text included, is dropped before the ledger. The allowlist must grow by the envelope names for browser rows to carry them (adapter, unit U1.1). |
| `src/byoai/integrations/shield_proxy.py`: `_log` | Desktop rows are `{"wall_clock", "kind": "desktop." + kind, **fields}`, appended as written. Kinds: `chat.request`, `chat.response`, `chat.attachment`, `verdict.denied`, `meta`, `health.unmatched`. |
| `src/byoai/integrations/coriqo_mcp_receipts.py`: `ReceiptSink.note` | Writes `tool.call` (with `payload_hash` and `mandate_verdict`), then `tool.result` for an allowed call or `tool.error` for a denied one. Both are written **at decision time**; the sink does not see the tool run. |
| `src/byoai/recorder/schema.py`: `EventKind` | Recorder kinds `tool_use`, `tool_result`, `mandate_verdict` and others. Frozen. |
| `docs/seal-format.md` section 4 | Event fields and kinds are hashed. `payload_hash` is `H(C(raw payload))`. Section 4.2 lists `EventKind`. |

## Rules that never bend

1. **Additive.** No existing field is renamed, removed or re-typed. A row with no envelope stays valid and is read as unclassified.
2. **No `ai.*` in `EventKind`.** `ai_event_type` values live in row payloads and derived views only. `docs/seal-format.md` 4.2 is untouched.
3. **No byte changes.** No new hashing, no canonical JSON change, no signed-byte change. Envelope fields do not enter any digest that exists today (see "Recorder events" below, which is the one place this needs care).
4. **The row's field set is closed.** The schema allows only the envelope names and the pre-existing row fields in `$defs/legacy_fields`, per row kind, with `unevaluatedProperties: false`; every string is bounded by a pattern or length and the nested objects (`model`, `tool`, `agent`, `detection`) are closed. A name outside the list (`text`, `prompt`, `file_name`, `Text`, anything) is rejected, and a free-text value cannot fit the patterns. This is a **format** check on a row that is offered to it. The runtime text guard is still the allowlists in code (`clean_browser_row`, the proxy's `_log` callers); the schema does not replace them.
5. **Never invent a model name.** `model.name` exists only when the source carried one, and `model.source` says where. Otherwise `model.identification` is `unknown` and there is no name.
6. **Execution is never assumed.** `tool.status = executed` and `ai_event_type = ai.tool.executed` imply each other, and both require `tool.execution_source` and the `governed_tool` collector. `evidence_level: verified` needs that same pair. `tool.status = requested` needs `observed_requested`. A row with a `tools` list is a request row (`ai.tool_call.requested`, `observed_requested`). A model's request, a gate's decision and a tool result row are not execution.
7. **A request is a request.** Every `ai.tool_call.requested` carries `evidence_level: observed_requested`.

## Fields

All five core fields are required on an envelope row. The rest appear only when known.

| Field | Values | Meaning |
|---|---|---|
| `envelope_version` | `1` | Format version. |
| `ai_event_type` | `ai.model.requested`, `ai.model.response`, `ai.tool_call.requested`, `ai.tool.result`, `ai.tool.executed`, `ai.data.attachment`, `ai.policy.enforced`, `ai.policy.evaluated`, `ai.app.discovered`, `ai.app.visited`, `ai.collector.health`, `ai.mcp.configured`, `ai.runtime.detected` | What the row records. |
| `evidence_level` | `observed`, `observed_requested`, `inferred`, `verified`, `unobservable_payload`, `unattested` | How the collector knows it (below). |
| `collector` | `browser_extension`, `desktop_proxy`, `mcp_interposer`, `recorder`, `governed_tool`, `scanner` | Who produced the observation. Today's ledger rows carry no such column; this is the provenance. |
| `policy_action` | `none`, `observe`, `allow`, `flag`, `warn`, `redact`, `block`, `pending_approval` | What policy **decided**. |
| `outcome` | `not_applicable`, `unknown`, `sent`, `sent_redacted`, `blocked`, `cancelled`, `answered`, `failed`, `uploaded`, `removed`, `allowed`, `denied` | What **happened**. |
| `app` | `^[a-z0-9_]{1,40}$` | App tag (`claude`, `chatgpt`, ...). Same values as `APP_LABEL`. Omitted when unknown: a real `desktop.meta` `not_covered` row has `app: null`, and the adapter leaves the key out rather than copy the null. |
| `model` | `{identification: observed\|inferred\|unknown, name?, provider?, source?}` | See below. |
| `tool` | `{name?, destination?, status: requested\|result\|executed, execution_source?, call_id?}` | See below. |
| `agent` | `{identification, id?, name?, protocol?}` | An agent or agent protocol seen. Correlated agents are computed in Coriqo, never by collectors. |
| `detection` | `{rule_id, rule_version, confidence: confirmed\|probable\|possible}` | The signature or rule that matched. |

### Evidence levels

| Level | Use |
|---|---|
| `observed` | The collector saw the thing itself (a send, a reply, a file attached, a gate decision). |
| `observed_requested` | The collector saw a **request** (a tool name in a reply stream, a `tool_use`). Not that it ran. |
| `inferred` | Derived from something weaker, such as a host name implying a provider, or a text regex. |
| `verified` | Cross-checked by a second source or by the seam that did the work (for example `@governed_tool`). |
| `unobservable_payload` | The traffic was seen but cannot be read (pinned certificate, encrypted stream). Honest "seen, not inspected". |
| `unattested` | Reported by a scanner that is not a registered, sealed device collector. Never sealed as device evidence. |

### `policy_action` and `outcome` are separate on purpose

`verdict` stays frozen as it is. It mixes what policy did with what happened
(`redacted(1)`, `warned->sent`, a mode name). The envelope splits them:

| Existing | `policy_action` | `outcome` |
|---|---|---|
| browser `verdict: redacted(n)` | `redact` | `sent_redacted` |
| browser `verdict: blocked` | `block` | `blocked` |
| browser `verdict: observe` | `observe` | `sent` |
| browser `verdict: warned->sent` | `warn` | `sent` |
| browser `verdict: warned->cancelled` | `warn` | `cancelled` |
| desktop `action: "warn"` | `warn` | `sent_redacted` if `redactions` is non-empty, else `sent` |
| attachment `allowed` / `blocked` | `allow` / `block` | `uploaded` / `blocked` |
| desktop request `verdict: blocked` | `block` | `blocked` |
| `tool.result` with a `mandate_verdict` | as `mandate_verdict` below | as `mandate_verdict` below |
| `mandate_verdict: allowed` / `flagged` / `blocked` / `pending_approval` | `allow` / `flag` / `block` / `pending_approval` | `allowed` / `allowed` / `denied` / `unknown` |

A desktop `warn` has no user prompt (it behaves as redact, see the `shield_proxy.py` docstring), so `policy_action: warn` does **not** mean the user was asked. Only `outcome` says what reached the app.

### `model`

| `identification` | `name` | `source` |
|---|---|---|
| `unknown` | absent | absent |
| `observed` | required | `request_field`, `response_field` or `event_field` (the name was in the payload or in `AgentEvent.model`) |
| `inferred` | absent (`provider` required) | absent. A host says who the provider is, never which model |

Browser chat rows normally cannot carry a model: use `{"identification": "unknown"}`. A desktop row for a provider API (for example Mistral) may carry the model only when the request body had a `model` field and the adapter read it.

`agent` follows the same rule: with `identification: unknown` there is no `id` and no `name`, and `agent.name` is a label with no spaces, never free text. `detection.confidence` is never `confirmed` when the collector is `scanner` or the evidence is `unattested` or `inferred`.

### `tool`

`status` is `requested` (a request was seen), `result` (a result or error row exists) or `executed` (the call is known to have run). `destination` is a host or server name, never a URL with a path or query. `execution_source` is only allowed with `executed`, and its values are `governed_tool` and `instrumented_telemetry`.

## Mapping: existing row kind to envelope

`kind` is exactly the existing kind string. The schema enforces this table: a row of a given kind may only use the listed `ai_event_type`, `collector` and `evidence_level`.

| Existing row | `ai_event_type` | `collector` | `evidence_level` |
|---|---|---|---|
| `browser.chat.request` | `ai.model.requested` | `browser_extension` | `observed` |
| `browser.chat.reply` | `ai.model.response` | `browser_extension` | `observed` |
| `browser.chat.reply` (one derived row per entry of `tools[]`) | `ai.tool_call.requested` | `browser_extension` | `observed_requested` |
| `browser.chat.status` | `ai.model.response` | `browser_extension` | `observed` |
| `browser.chat.attachment` | `ai.data.attachment` | `browser_extension` | `observed` |
| `browser.health.unmatched`, `browser.health.core_missing` | `ai.collector.health` | `browser_extension` | `observed` |
| `desktop.chat.request` | `ai.model.requested` | `desktop_proxy` | `observed` |
| `desktop.chat.response` | `ai.model.response` | `desktop_proxy` | `observed` |
| `desktop.chat.response` (derived, per tool) | `ai.tool_call.requested` | `desktop_proxy` | `observed_requested` |
| `desktop.chat.attachment` | `ai.data.attachment` | `desktop_proxy` | `observed` |
| `desktop.verdict.denied` | `ai.policy.enforced` | `desktop_proxy` | `observed` |
| `desktop.meta` with `not_covered` | `ai.app.discovered` | `desktop_proxy` | `unobservable_payload` |
| `desktop.meta` without `not_covered` (a `MEANS` path) | `ai.app.visited` | `desktop_proxy` | `observed` |
| `desktop.health.unmatched` | `ai.collector.health` | `desktop_proxy` | `observed` |
| `tool.call` | `ai.tool_call.requested` | `mcp_interposer` | `observed_requested` |
| `tool.result`, `tool.error` | `ai.tool.result` | `mcp_interposer` | `observed` |
| recorder `tool_use` | `ai.tool_call.requested` | `recorder` | `observed_requested` |
| recorder `tool_result` | `ai.tool.result` | `recorder` | `observed` |
| recorder `tool_result` from `@governed_tool` | `ai.tool.executed` | `governed_tool` | `verified` |
| recorder `mandate_verdict` | `ai.policy.evaluated` | `recorder` | `observed` |

Derived events:

- `ai.app.visited` for a request row is emitted at most once per app per day by the adapter, as a separate envelope row. It is not stamped on the request row itself, which keeps one `ai_event_type` per row.
- A reply row with `tools[]` produces its own `ai.model.response` envelope plus one derived `ai.tool_call.requested` envelope per tool, each with `tool.name` and `tool.status: requested`.
- Scanner output (`ai.app.discovered`, `ai.mcp.configured`, `ai.runtime.detected`) uses `collector: scanner` and `evidence_level: unattested`, and a `kind` starting `scanner.`. It lives in the scanner's own file, never in the signed ledger.
- `ai.agent.detected` and `ai.workflow.*` are computed in Coriqo from rows. Collectors never emit them, so the schema has no such value.

### Gaps and judgment calls in the mapping

These are places the spec's table was silent or the code disagrees with it. Wave 1 and 2 units code to the choices made here.

1. **`browser.chat.status` is in `BROWSER_KINDS` but not in the spec's table.** It carries `ok` and `status` for a send. Mapped to `ai.model.response` with `outcome: answered` or `failed`.
2. **`desktop.meta` without `not_covered`** (a path matching `MEANS`, a means-of-chat host with no payload read) is also not in the table. Mapped to `ai.app.visited`.
3. **`tool.result` is not execution.** `ReceiptSink.note` writes `tool.result` for an allowed call immediately, without seeing the tool run. So the row means "the gate allowed it", `tool.status` is `result`, and `ai.tool.executed` is not used for it. The spec's note ("execution is observed here only if the interposer ran the call") is not satisfied by the current code. Wave 2 unit U2.3 is where an interposer-observed execution would be added.
4. **Desktop `warn` is not a prompt.** See above.
5. **Desktop rows may carry `preview`.** `inspect_text` adds a redacted 200-character `preview` when the admin enables `keep_text`. That is message-derived text in an existing field and is outside this envelope. The envelope forbids new text fields; it does not remove `preview`.

## Recorder events: derived, not stamped

`tool_use` and `mandate_verdict` events have payloads whose digest is joined on
elsewhere. For `tool_use`, `ReceiptSink` passes
`recorder.verdicts.tool_use_payload_hash(tool, arguments_sha256)`, the hash of
`{tool, arguments_sha256}`, and Coriqo matches the `tool.call` row on it. Adding
envelope fields to that payload would change `payload_hash` for new events and
break the join. So:

- Envelope fields are **not written into recorder event payloads.**
- For recorder events the envelope is a derived view the adapter builds from `AgentEvent.kind`, `tool_name`, `tool_use_id`, `model`, `provider` and the verdict, at read or ship time.
- The schema validates that derived view. Its `kind` is the `EventKind` value, which recorder payloads do not carry.

Any later decision to stamp recorder payloads is a format question for the
owner, not an adapter detail.

## What later units must change

None of this touches hashing, canonical JSON or signed bytes.

- `clean_browser_row` rebuilds every browser row from an allowlist, so today it drops **every** new envelope field (`envelope_version`, `ai_event_type`, ... `model`, `tool`). The browser allowlist must grow by exactly the names and shapes in this schema.
- `ReceiptSink.note` builds fixed dicts for `tool.call`, `tool.result` and `tool.error`; it must add the envelope fields itself.
- `desktop._log(**fields)` has no allowlist: it appends whatever its caller passes. It needs one that matches `$defs/legacy_fields` plus the envelope names. Until it has, the schema rejects such a row but nothing in the proxy does.

## Validating

```bash
python -m pytest tests/integrations/test_shield_envelope_schema.py
```

An adapter that produces envelopes should validate its output against the
schema in its own tests, and must drop any field it cannot source (rule 5 and
rule 6) rather than guess.

## Adapter hardening

`adapt_row` checks every pass-through field against the shape in `legacy_fields`. A row
with a present but malformed field (`flags: ["free text"]`, `chars: "lots"`, a `verdict`
that is not one of the listed words) is dropped (`[]`), never copied into an envelope.
A field the row's family does not allow (`tools` on a request row) is not copied. A
`not_covered` of `false` means covered; a non-string truthy value drops the row.
`adapt_agent_event` never raises, and reports `ai.tool.executed` / `verified` only for
a `governed` result of a named tool whose payload is not an error.
