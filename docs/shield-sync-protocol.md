# Shield Sync protocol

What a Shield device may tell Coriqo about its activity, and exactly how.
Shield's promise is "what happened, never what was said": nothing below carries
message text, a preview, a matched snippet, or a fingerprint of the text.

The whole thing is enforced in code on both ends. The device builds each event
field by field from an allowlist
(`src/byoai/integrations/shield_sync.py`), and Coriqo validates with a closed
schema and rejects a batch that carries any other field.

## Levels

Set by the signed managed policy (`"sync"`), never by the local policy file.
The device sends at most the level it was given, and the person is always told
who receives what (`GET /api/policy` → `sharing`).

| Level | What leaves the device |
|---|---|
| `seal` (default) | Only the signed checkpoint (`POST /v1/checkpoints/batch`). No activity. |
| `daily` | Per day, per app: message count, caught count per rule, redacted and blocked counts. Aggregated on the device, so per-message rows are never sent. |
| `events` | One row per message or tool call, fields below. |

Turning sharing on does not send the past: only activity after the level
changed is sent. Turning it down drops anything still waiting to be sent.

## Request

`POST {coriqo}/v1/shield/events`, signed exactly like the checkpoint post: the
body is canonicalised, signed with the device's Ed25519 key, gzipped, and sent
with `x-coriqo-device` and `x-coriqo-signature`.

```json
{
  "device_id": "dev_…",
  "sent_at": "2026-09-26T10:03:00Z",
  "level": "events",
  "policy_version": 7,
  "batch_id": "9f2c…",
  "events": [ … ],
  "gap": {"from": "…", "to": "…"}
}
```

- `level` must equal the level Coriqo has assigned to the device. If not:
  `409 {"error": "level_mismatch", "assigned": "daily"}` and the device
  re-fetches its policy.
- `events` (level `events`) or `daily` (level `daily`), never both. Up to 200
  events per batch.
- `batch_id` identifies a batch. A batch that was sent but not acknowledged is
  resent exactly as it was (the same events, the same `batch_id`), whatever has
  been queued since, so a lost reply can never double-count. Coriqo de-duplicates events by `(device_id, event_id)` and daily
  batches by `batch_id`.
- `gap` appears once, on the first batch after events were dropped locally (a batch with no events is sent if nothing else is waiting)
  (offline longer than the retention window, or past the local cap), so a
  dashboard can show "no data" instead of a quiet period.
- A batch is sent only after a checkpoint that covers every event's `seal` has
  been accepted.
- `422 {"error": "schema", "field": "…"}`: the whole batch is rejected. The
  device drops it rather than retrying the same bytes.

### Event

```json
{
  "event_id": "b3f1c0ffee",
  "occurred_at": "2026-09-26T10:02:11Z",
  "device_id": "dev_…",
  "person_id": null,
  "source": "browser | desktop | mcp | agent",
  "app": "claude | chatgpt | gemini | copilot | <mcp client name>",
  "kind": "message | tool_call",
  "chars": 184,
  "verdict": "allowed | redacted | blocked | observed",
  "flags": [{"tier": "pii", "rule": "emails"}],
  "redactions": 1,
  "tool": "search_files",
  "seal": "a1b2c3d4e5f60718"
}
```

- `flags` are rule ids from Shield's fixed rule set; the text a rule matched
  is never included.
- `app` (for MCP clients) and `tool` are names a vendor chose, truncated to 40
  characters and limited to `[A-Za-z0-9 ._-]`; anything else is dropped.
- `chars` is the message length. `redactions` is a count, not what was
  redacted.
- `seal` links the event to the signed chain, so any event can be exported with
  a receipt and checked offline.
  The receipt (`byoai.receipt.v2`) carries the signed checkpoint exactly as
  the device signed it: `kind`, `root_hex`, `height`, `ts`, `device_id`,
  `public_key_b64` and `sig`. The signature is Ed25519 over
  `sha256(0x00 || JCS(checkpoint without sig))`, so dropping or changing any
  field, `kind` and `ts` included, fails the check.
- `person_id` is `null` from the device; Coriqo binds it from the device's
  person, set by the organisation.

### Daily row

```json
{"date": "2026-09-26", "app": "claude", "messages": 41,
 "flags": {"pii:emails": 2}, "redacted": 2, "blocked": 0}
```

`date` is the device's local calendar day.

## Backoff

Activity sync has its own retry state, separate from the checkpoint's: a
failing events route never slows or blocks the seal. A backlog is sent in up to ten batches per window. Failures back off from one
minute, doubling, capped at six hours, honouring `Retry-After`. Events are kept
in a persisted outbox and dropped only after a `200`.
