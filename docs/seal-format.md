# Recorder seal format

This page specifies the tamper-evident records written by the agent recorder
(`byoai.recorder`): the hash-chained event ledger, device-signed checkpoints,
tenant epoch Merkle trees, external anchor receipts, and the export bundle
that carries all of them. It is written so that someone can build a verifier
in another language without reading our code. Every rule below is taken from
the current source, and the module or function it comes from is named inline.

Where this page and the code disagree, the code is what produced the records
you hold, so treat the disagreement as a documentation bug and report it.

Test vectors are in [section 16](#16-test-vectors). They are produced by
[`docs/seal-format-vectors.py`](https://github.com/coriqo/byoai-runtime/blob/main/docs/seal-format-vectors.py),
which drives the real library with fixed keys and clocks.

**Out of scope.** Coriqo Shield's local seal chain (`sealchain.log.jsonl`,
written by `byoai.integrations.shield`) is a separate format and is not
described here. Neither are the Coriqo receipt bundles checked by
`verify_receipts` (their format belongs to the `coriqo-agents` SDK) or the CEI
attestation envelopes built by `recorder/attestation.py`.

## 1. Overview and trust model

The record is built in four levels. The level numbers match the ones used in
the module docstrings.

| Level | What it is | Who produces it | Module |
|---|---|---|---|
| 1 | Per-device hash chain of events | the device | `ledger.py` |
| 2 | Checkpoint: the chain head at some `seq`, signed with the device's Ed25519 key | the device | `checkpoint.py` |
| 3 | Epoch tree: a Merkle tree over many checkpoints, with a root signed by a tenant key | the server (Coriqo) | `merkle.py` |
| 4 | Anchor: the epoch root timestamped by an RFC 3161 TSA or logged in a Rekor-style transparency log | an outside party | `anchor.py` |

Level 1 needs no key. Changing any hashed field of a stored event changes
the entry hash a verifier derives for it, which then no longer matches the
stored one.
Level 1 alone cannot stop someone with write access from rewriting the whole
chain from the tampered row onward, so it only proves the chain is internally
consistent. Level 2 pins a chain head to the device key, so a rewrite also
requires that key. Level 3 pins the checkpoint into a tree the server
committed to. Level 4 pins the tree root to a time and a log the server does
not control.

What a verifier has to trust, and what it does not:

- **Trusted input the verifier must obtain itself:** the device public key
  (or keys, across rotations), the tenant epoch-signing key, the Rekor log
  key, and the TSA root certificate. None of these can be proven by the
  record itself. See [10.3](#103-root-of-trust-duties).
- **Trusted by construction:** `seq`, because the ledger assigns it in strict
  append order and it is inside the event digest (`ledger.Ledger._append_locked`).
- **Never trusted:** `ts_device` and every other timestamp written by the
  device. It comes from the host wall clock and can be set by the caller
  (`schema.set_device_clock`). It is hashed, so it cannot be changed after
  the fact, but it says nothing reliable about when an event happened. The
  same applies to `effective_epoch` in a key rotation, and to `ts_device` in a
  checkpoint.
- **Not proven:** that the recorded events describe what really happened. The
  seal shows the record has not been changed since it was written.

## 2. Notation

- `SHA256(x)`: SHA-256 of the byte string `x`, 32 bytes.
- `hex(x)`: lowercase hexadecimal, no prefix.
- `H(x)`: the text `"sha256:" + hex(SHA256(x))`. This is the form every hash
  in the ledger uses (`canonical.sha256_hex`). Merkle and anchor hashes are
  the exception: they are bare `hex()` or raw bytes, as stated where they
  appear.
- `C(obj)`: the canonical JSON bytes of `obj` (section 3).
- `||`: byte concatenation.
- Base64 means standard base64 (RFC 4648 section 4, `+/`, with `=` padding).
  Decoders in this codebase use strict mode (`validate=True`).

## 3. Canonical encoding

Every hash and signature is computed over `C(obj)`, which is RFC 8785 (JSON
Canonicalization Scheme) as implemented in `canonical.canonicalize`:

1. Output is UTF-8. No whitespace between tokens. Separators are `,` and `:`.
2. Object members are sorted by key, comparing keys as sequences of UTF-16
   code units (`canonical._utf16_sort_key`). This differs from code-point
   order for keys containing characters above U+FFFF: such a character is a
   surrogate pair starting at 0xD800, so it sorts before a BMP character such
   as U+FB01. Vector 0 shows this.
3. Strings: `"` and `\` are escaped as `\"` and `\\`. U+0008, U+0009,
   U+000A, U+000C and U+000D become `\b`, `\t`, `\n`, `\f`, `\r`. Any other
   code point below U+0020 becomes `\u00XX` with lowercase hex. Everything
   else, including U+007F, U+2028 and all non-ASCII text, is written as
   literal UTF-8. A lone surrogate is an error.
4. Numbers:
   - An integer is written in plain decimal at full precision, even beyond
     2^53 (`canonical.serialize_number`). This is a superset of RFC 8785,
     which assumes IEEE-754 doubles.
   - A float is written with ECMAScript `Number.prototype.toString` rules:
     `1.0` becomes `1`, `-0.0` becomes `0`, `1e21` becomes `1e+21`, `1e-7`
     becomes `1e-7`, `0.1` stays `0.1`.
   - NaN and the infinities are errors.
5. `true`, `false` and `null` are written as such. Arrays keep their order.
6. Object keys must be strings.

A verifier should canonicalize from the parsed value, not reuse bytes from a
file.

**Integer precision.** `ts_monotonic_ns` is a nanosecond counter from
`time.monotonic_ns()` and can exceed 2^53 on a host with long uptime, and
payloads may contain large integers. A verifier whose JSON parser turns
integers into doubles (JavaScript's `JSON.parse`, for example) will produce
different bytes. Parse integers into an arbitrary-precision type.

## 4. Events

### 4.1 Fields

An event is `schema.AgentEvent`. Its hashed form is `AgentEvent.to_dict()`:
every field below, with the rules for schema version `"1"` in
[section 12](#12-versioning).

| Field | Type | Hashed | Notes |
|---|---|---|---|
| `schema_version` | string | yes | `"2"` for everything written now, `"1"` for legacy rows |
| `event_id` | string | yes | `"evt_" + 32 hex chars` (`schema.new_event_id`) |
| `device_id` | string | yes | device that captured the event (section 6.1) |
| `session_id` | string | yes | one agent invocation. Sentinels: `"_key_rotation"` for KEY_ROTATED, `"_record_failure"` for RECORD_FAILURE |
| `seq` | integer | yes | position in the device chain, starting at 1, assigned by the ledger |
| `kind` | string | yes | one of the values in 4.2 |
| `ts_device` | string | yes, untrusted | `YYYY-MM-DDTHH:MM:SS.ffffffZ`, UTC, always 6 fractional digits (`schema.format_ts_device`) |
| `ts_monotonic_ns` | integer | yes, untrusted | host monotonic counter |
| `tool_use_id` | string or null | yes | pairs `tool_use` with `tool_result` |
| `tool_name` | string or null | yes | |
| `payload` | object | yes | what was shipped, after the payload mode was applied (4.3) |
| `payload_hash` | string | yes | `H(C(raw payload))`, computed before redaction (4.3) |
| `model` | string or null | yes | |
| `provider` | string | yes | `"recorder"` for recorder bookkeeping events |
| `trace_id` | string | v2 only | `"tr_" + 32 hex` normally; may be `""` when the caller has no trace |
| `span_id` | string | v2 only | `"sp_" + 32 hex` normally; may be `""` |
| `parent_span_id` | string or null | v2 only | null for a top-level agent |
| `continues_from` | string or null | v2 only | null unless the session resumes another |

In a v2 event all four trace fields are always present in the hashed object,
with `null` where there is no value. `AgentEvent.from_dict` rejects missing
and unknown fields.

No field of an event is signed individually. An event is protected by the
chain (level 1) and by the next checkpoint that covers it (level 2).

### 4.2 Kinds

From `schema.EventKind`: `tool_use`, `tool_result`, `message`, `api_error`,
`record_failure`, `session_start`, `stream_aborted`, `parse_failure`,
`key_rotated`, `mandate_verdict`, `guardrail_intervention`,
`worker_stop_ack`, `heartbeat`.

The verifier gives meaning to four of them: `tool_use` and `tool_result`
(pairing, 11.1 step 5), `key_rotated` (section 7) and `heartbeat` (4.4, an
opt-in spacing check, 11.6). The rest are hashed like any other event.

`record_failure` is written by `Ledger._drain_failures` after writes were
dropped in non-strict mode. Its payload is
`{"reason": "ledger_write_failed", "dropped_count": n, "dropped": [...]}`,
one item per dropped event (`event_id`, `kind`, `session_id`,
`tool_use_id`, `error`, `ts_device`). The dropped events themselves are gone.
The marker is how their loss is recorded.

### 4.3 Payload and `payload_hash`

`payload_hash` is always `H(C(raw_payload))` over the payload as captured
(`integration.RecorderIntegration._promote`). The `payload` field then holds
the result of `redact.apply_payload_mode`:

| Mode | Stored `payload` |
|---|---|
| `full` | the raw payload |
| `hash-only` | `{}` |
| `redacted` (default) | a copy with secrets masked and most values replaced by salted digests |

So `payload_hash == H(C(payload))` holds only in `full` mode, and the verifier
does not check it in any mode. In `hash-only` and `redacted` mode,
`payload_hash` commits to content the verifier never sees. Whoever holds the
raw payload can later prove it matches.

The ledger row also keeps the mode it was written in, in a `payload_mode`
column (`full`, `redacted`, `hash-only`, or `runtime` for payloads the
runtime writes itself: mandate verdicts, worker stop acks, key rotations and
the failure marker, heartbeats). It describes how the row was recorded, not the event:
it is not part of `event_digest` or `entry_hash`, and a verifier leaves it out
of the event it re-hashes. Rows written before the column existed hold NULL.

### 4.4 Heartbeat

`heartbeat` is a liveness entry the recorder process writes on a timer
(`recorder/heartbeat.py`). It is an ordinary chain entry: it takes the next
`seq`, links to the previous entry by section 5, and is covered by the
device-signed checkpoints (section 8) the same as a tool event. Nothing in the
hash, link or signature rules changed for it.

Payload:

| Field | Type | Meaning |
|---|---|---|
| `last_seq` | integer | The highest `seq` in the chain at the instant of the write; 0 on an empty chain. A heartbeat normally has `seq == last_seq + 1`. |
| `device_time` | string | RFC 3339 UTC, microsecond precision. The device's own clock, the same trust as `ts_device`. |
| `interval_s` | number | The interval the process was configured with. An integer when whole. `0` means heartbeats were off from this entry on. |
| `boot_id` | string, optional | A per-boot identifier, on new entries only: the first 16 hex characters of `sha256(device_id \|\| raw)`, where `raw` is the Linux `boot_id` or the macOS `kern.boottime`, and the field is left out where the platform gives none cheaply. It is hashed so the shared, signed ledger does not carry the exact boot time or uptime; a verifier only compares two of them for equality within one record, to compare the monotonic counter only inside one boot. Entries without it (written before it existed) are unchanged and compared as before. |

The envelope uses `session_id = "byoai-heartbeat"`, `provider =
"byoai-recorder"`, `tool_use_id = null`, `tool_name = null`, `model = null`.
The payload is stored in full in every payload mode (section 4.3), so
`payload_hash == H(C(payload))` holds and can be checked.

Ordering and cadence:

- One is written when the process starts, unless the newest `heartbeat` in the
  ledger is younger than `interval_s`. Then none is written and the next falls
  due when that one reaches `interval_s`. Restarts seconds apart do not add
  entries.
- After that, one per `interval_s` (default 900, `BYOAI_RECORDER_HEARTBEAT_SECONDS`).
  A process that stalls or sleeps writes one when it wakes, not one per missed
  interval.
- None is written while the process is not running. That absence is what the
  check in 11.6 looks for.
- With `BYOAI_RECORDER_HEARTBEAT_SECONDS=0` the recorder writes one heartbeat at
  start with `interval_s: 0`, once, and none after. That entry says "heartbeats
  off from here" in the chain itself, so a record with the feature turned off
  cannot be mistaken for one that lost its heartbeats.
- `last_seq` is read inside the write, after any queued `record_failure` marker
  and any stale-head resync, so it is always the stored entry's `seq - 1`.
- A heartbeat is covered by the next checkpoint (section 8). On an idle process
  that is about one checkpoint per two heartbeats, and a clean shutdown flushes
  the rest. A heartbeat written just before a crash can sit in the unsigned tail
  (11.2) until the next run.

What a verifier may conclude. A `heartbeat` at `seq` n shows that, at the
`device_time` the device claims, the recorder process wrote an entry and the
chain had been written up to `last_seq`. Because it sits in the chain it cannot
be inserted, removed or reordered afterwards without breaking a link, and once a
checkpoint covers it the device key vouches for it.

What it does not show.

- It is not proof of liveness, and it says nothing about actions taken outside
  the recorder: a host can run an agent that bypasses the recorder while the
  recorder heartbeats.
- A gap means the record does not show the recorder writing in that window. It
  does not say why (stopped, blocked, crashed) and does not say the host was idle.
- Every time in it is the device's clock. A host that controls its own clock can
  make spacing look right. 11.6 adds advisory cross-checks (the monotonic
  counter each entry carries, the signed checkpoints, the tenant epoch time), but
  only an external time anchor (a verified RFC 3161 or Rekor anchor, or the time
  Coriqo received the entry) bounds device time from outside.

The older "resend heartbeat" of `shield_publish.py` is separate. It resends the
last accepted seal as a transport keep-alive and adds no chain entry. It is
unchanged.

Capability signal. While the heartbeat thread is running, both upload bodies
(13.1) carry a top-level
`"runtime": {"version": ..., "capabilities": ["heartbeat_chain_v1"], "heartbeat_interval_s": N}`.
It is left out when heartbeats are off or the thread did not start, and by older
runtimes. It is self-asserted: the body signature proves the device sent it, not
that it is true. A server should treat it as sticky per device once seen (so a
runtime cannot hide by dropping it) and judge the heartbeat entries themselves.
Servers read the body by key, so the released contract is unchanged: the same
two routes, the same signature over `C(body)`, and a `rejected` entry still
carries a parseable `seq_end`.

Forked workers. The thread does not survive `fork()`. The recorder holds the
ledger lock across the fork (waiting at most 1 s, then forking without it and
logging one warning), so no thread is inside SQLite when the child is cloned. The
child opens its own SQLite connection and restarts the thread on its first use of
the ledger, not at fork time, so a child that only execs (`subprocess` with
`preexec_fn`) opens nothing and starts nothing. A connection must not be shared
across fork. Each
forked worker writes its own heartbeats into the shared ledger: N workers write N
times the entries, and under `gunicorn --preload` the master heartbeats too, so
N + 1 writers. The shipper thread is not restarted.

Several writers on one file. Each append reads the real head inside the write
lock, and a checkpoint signs the real head and the time read together under that
lock. Before a process adopts rows another writer added, it re-derives each one
(`entry_hash` from the stored fields, `prev_hash` linking to the row before,
contiguous `seq`). It resyncs forward only. If the file's head is behind what the
process already wrote, or the row at its last known seq no longer has the hash it
remembers (the file was truncated, replaced or rewritten), it does not adopt the
head: it logs an error naming the file and both heads, queues a `record_failure`
(`ledger_head_changed`), refuses to append, and signs no checkpoint. If new rows
do not re-derive, it logs an error and queues a `record_failure`
(`ledger_rows_unverified`), refuses to append onto them, and a checkpoint stops at
the process's own last verified head. The marker is written when the chain can be
continued again.

Trust. Every process that writes one ledger file is trusted. Entry hashes are
unkeyed, so a writer with file access can forge rows that are consistent with each
other. A checkpoint signature vouches for the file's content at that moment, not
for who wrote each row. A keyed per-row MAC is a possible future hardening and is
not part of this format.

Volume. At the default 900 s: 96 heartbeats a day, 35,040 a year per device,
and (measured over a simulated idle day in `tests/recorder/test_heartbeat.py`)
about 48 checkpoints a day, roughly 17,500 a year.

## 5. Chain

### 5.1 Event digest and entry hash

```
event_digest = H(C(event_dict))                                  # schema.event_digest
entry_hash   = H(C({"prev_hash": prev_hash,
                    "seq": seq,
                    "event_digest": event_digest}))              # ledger.compute_entry_hash
```

`event_dict` includes `seq`, so the event digest also commits to the event's
position. The same `seq` appears again in the link object.

### 5.2 Linking

- The chain starts at `seq = 1`.
- `prev_hash` of `seq = 1` is the genesis value
  `"sha256:0000000000000000000000000000000000000000000000000000000000000000"`
  (`ledger.GENESIS_PREV_HASH`).
- `prev_hash` of `seq = n` is `entry_hash` of `seq = n - 1`.
- The chain head is the `entry_hash` of the highest `seq`, or genesis for an
  empty ledger.

There is one chain per device. It continues across restarts from the last
stored `entry_hash` (`Ledger._resume`) and across key rotations (section 7).

### 5.3 Storage (SQLite)

The ledger is one SQLite file (`ledger._SCHEMA`). Table `agent_events` holds
one row per event: every event field as a column (payload as the canonical
JSON text `C(payload)`), plus `event_digest`, `prev_hash` and `entry_hash`.
Table `checkpoints` holds one row per checkpoint, keyed by `seq_end`, with
the whole checkpoint as canonical JSON in the `body` column. A second
checkpoint with the same `seq_end` replaces the first (`INSERT OR REPLACE`).
Table `sync_state` holds shipping watermarks and is not part of the seal.

The stored `event_digest` column is never trusted: `verify.py` recomputes it
from the other columns.

## 6. Keys and signatures

### 6.1 Device key and device id

Each device has one Ed25519 key pair (RFC 8032), generated locally
(`keys.load_or_create_device_key`). The private key is stored as the raw 32
bytes with mode 0600. The public key is written as base64 of the raw 32
bytes.

```
device_id = "dev_" + base32(SHA256(raw_public_key))[0:26]
```

Base32 is RFC 4648 uppercase with padding removed (`keys.derive_device_id`).
So a device id is a public function of its public key, and a verifier holding
a public key can compute the id it belongs to.

### 6.2 Signature encoding

Every signature in this format, including those the verifier treats as
coming from a tenant key or a transparency log, uses `keys.DeviceKey`:

```
sig_string = "ed25519:" + base64(ed25519_sign(private_key, message_bytes))
```

`DeviceKey.verify` returns false (never raises) if the prefix is missing,
the base64 is invalid, the key is not 32 bytes, or the signature fails.
There is no key id inside a signature. The key is chosen by context: the
device key for checkpoints, the old device key for a rotation, the key in
the epoch for an epoch signature.

### 6.3 What is signed

| Object | Signed bytes | Key | Code |
|---|---|---|---|
| Checkpoint | `C(checkpoint without "sig")` | device key | `checkpoint.checkpoint_signing_bytes` |
| Key rotation | `C({"old_device_id", "new_device_id", "new_public_key"})` | old device key | `rotation.rotate_key` |
| Epoch root | `C({"epoch_index", "root", "epoch_start", "epoch_end", "tenant_id"})` | tenant key | `verify._verify_epoch_signature` |
| Rekor-style SET | `C({"log_index", "tree_size", "root_hash"})` | log key | `anchor.verify_rekor_receipt` |
| Upload batch (wire only) | `C(body)` | device key | `shipper.post_signed_batch` |

Events are not signed one by one.

## 7. Key rotation and revocation

`rotation.rotate_key` replaces the device key and records the handover as a
`key_rotated` event in the same chain:

- `device_id` = the **old** device id. The rotation event is the last event
  the old identity writes.
- `session_id` = `"_key_rotation"`, `provider` = `"recorder"`, `tool_use_id`
  and `tool_name` null, fresh `trace_id` and `span_id`.
- `payload`:

  | Field | Meaning |
  |---|---|
  | `old_device_id` | id of the key being retired |
  | `new_device_id` | id of the new key |
  | `new_public_key` | base64 raw public key of the new key |
  | `cross_signature` | old key's signature over `C({old_device_id, new_device_id, new_public_key})` |
  | `reason` | `"rotation"`, `"revocation"` or `"compromise"` |
  | `effective_epoch` | a `ts_device` string. Untrusted, and not used by the verifier |

The rules the verifier applies (`verify._walk_chain`) are based on `seq`, not
on time, and split into two modes depending on whether the caller supplied a
**starting key** — a key the caller itself trusts (`public_key_b64` for
`verify_ledger`, `pinned_device_public_key_b64` for `verify_bundle`; never a
key read out of the untrusted chain/bundle data itself):

**With a starting key** (the hardened path — `verify._check_rotation_live`):
the walk maintains `active_key`/`active_id` live, inline, as it walks,
starting from the caller's key. This is what closes a critical gap: without
it, a `key_rotated` event's cross-signature was checked by looking up
`old_device_id` (a label the payload itself claims) in a caller-supplied
`device_public_keys` map — so a device that still held a **retired** key
could forge a second rotation, cross-sign it correctly with that retired
key, label it with its own (retired) id, and take over the timeline, because
nothing checked that the retired key was still the one actually active.

1. A `key_rotated` event at seq `r` is **valid** only if ALL of the
   following hold, checked against the walk's own current `active_key`/
   `active_id` (not the payload's claims): its `cross_signature` verifies
   against `active_key`; `payload.old_device_id == active_id`; the event's
   own `device_id == active_id`; and `new_device_id ==
   derive_device_id(new_public_key)`.
2. A valid rotation advances `active_key`/`active_id` to
   `new_public_key`/`new_device_id` from seq `r` onward. Any other rotation
   — forged, mislabeled, signed by a retired key, or otherwise failing one
   of the four conditions — is reported as forged (via `key_rotations[i]
   ["valid"] is False`, which also makes it appear in the forged-rotations
   set that fails verification) and does **not** change the active key/id.
3. Every non-rotation event whose `device_id` no longer matches `active_id`
   at its seq — because it's still using a key that was legitimately
   rotated away, or one that was never active in the first place — is
   reported in `stale_key_usage`, which fails verification.
4. `device_public_keys` remains accepted for backward compatibility but can
   never override the live timeline; if it disagrees with what the timeline
   itself established for a given `new_device_id`, that's a note, not
   something acted on.

**Without a starting key** (the original, note-based behaviour — no
rotations can actually be verified, so none of this is enforced):

1. When a `key_rotated` event at seq `r` is seen, `old_device_id` is retired
   as of `r`, and (2) any later event (seq > `r`) whose `device_id` is that
   retired id is reported in `stale_key_usage`.
2. The cross-signature is checked only if the caller supplies a public key
   for `old_device_id` via `device_public_keys` (CLI `--device-pubkey`). If
   it is supplied and the signature fails, the rotation is counted as forged
   and verification fails. If no key is supplied, the rotation is reported
   as unchecked in `notes` and does not fail. Because the lookup is keyed by
   the payload's own claimed `old_device_id`, this mode cannot detect a
   retired-key re-rotation — that's exactly why the starting-key path above
   exists, and why supplying a starting key is what a caller who needs that
   protection must do.
3. `new_device_id` must equal `derive_device_id(new_public_key)` (6.1),
   checked independently of the cross-signature. A mismatch is a note, not a
   finding on its own in this mode.

In both modes, events before `r` under the old id stay valid, whatever
`reason` says. `revocation` and `compromise` are recorded but not treated
differently from `rotation`: nothing written before the rotation event is
invalidated. `ts_device` and `effective_epoch` play no part in either mode —
using them would let someone holding a retired key backdate new events to
before the rotation.

**Out-of-process rotation and stale in-memory keys.** `rotate_key` writes the
`key_rotated` event and rewrites the on-disk key material, but it does not
reach into any *other* process's already-open `Ledger`/`Recorder` object. If
a sibling process (or the CLI, run out-of-process) rotates the key while a
long-running recorder keeps its old `Ledger` open, that recorder keeps
signing and appending under its old key/device_id — `_append_locked` has no
way to know its in-memory identity is now retired. Every entry it writes
after that point fails verification as stale-key usage (§7 point 3 above),
exactly as if it were a forged/compromised writer, because from the
verifier's point of view that's indistinguishable from one. **The recorder
process must be restarted after any out-of-process key rotation.** There is
no hot-reload of keys by design — silently swapping the active key under a
running writer without re-deriving everything downstream of it (session
state, in-flight signatures) is a bigger footgun than requiring a restart.

## 8. Checkpoints (level 2)

A checkpoint is a JSON object (`checkpoint.Checkpointer._emit`):

| Field | Type | Meaning |
|---|---|---|
| `device_id` | string | id of the signing key at emit time |
| `seq_start` | integer | first seq noted since the previous checkpoint |
| `seq_end` | integer | last seq noted |
| `chain_head` | string | the ledger head when the checkpoint was emitted, expected to equal `entry_hash` at `seq_end` |
| `ts_device` | string | untrusted wall-clock time, same format as events |
| `sig` | string | signature over `C(checkpoint without "sig")` |

A checkpoint is emitted after every 256 noted events or once 60 seconds have
passed since the first un-checkpointed event, whichever comes first
(`DEFAULT_EVERY_EVENTS`, `DEFAULT_EVERY_SECONDS`). The time trigger is only
evaluated when a new event is noted or `tick()` is called. `flush()` on
shutdown emits a final checkpoint if anything is pending, and never an empty
one.

A checkpoint signs only its chain head. Because the head commits to every
earlier entry, one valid checkpoint at `seq_end = n` covers entries 1..n.
`seq_start` is informational, and the verifier does not check it.

## 9. Epoch trees (level 3)

### 9.1 Leaves

Each leaf is one full checkpoint, `sig` included:

```
leaf_hash(checkpoint) = SHA256(0x00 || C(checkpoint))       # merkle.checkpoint_leaf_hash
```

The leaf input is the canonical JSON bytes, not a hash of them.

### 9.2 Tree

```
node_hash(l, r) = SHA256(0x01 || l || r)
```

`merkle.MerkleTree` builds the tree level by level: pair adjacent nodes left
to right, and when a level has an odd count, move the last node up to the
next level unchanged (it is not paired with itself). This gives the same
root as the RFC 6962 section 2.1 Merkle Tree Hash, which splits at the
largest power of two below `n`. An empty tree is an error. A one-leaf tree's
root is the leaf hash.

Leaf order is set by whoever builds the tree (`build_epoch_tree` takes
checkpoints "in receipt order"). The proof format below carries positions
explicitly, so a verifier does not need to know the order.

The root is carried as `hex(root)` in the epoch object.

### 9.3 Inclusion proof

```json
{"leaf_index": 7, "steps": [{"sibling": "<hex>", "side": "left"}, ...]}
```

Steps go from the leaf towards the root. A promoted node contributes no step
at that level, so proof length depends on the leaf's position. To verify
(`merkle.verify_inclusion`):

```
h = leaf_hash(checkpoint)                 # recomputed, never taken from the proof
for step in steps:
    if step.side == "right": h = node_hash(h, step.sibling)
    else:                    h = node_hash(step.sibling, h)
accept iff h == epoch_root
```

Any `side` other than `"right"` is treated as `"left"`. `leaf_index` is not
used when verifying.

### 9.4 Epoch object and tenant signature

```json
{
  "epoch_index": 0,
  "root": "<hex>",
  "epoch_start": "<ts>",
  "epoch_end": "<ts>",
  "tenant_id": "<string>",
  "tenant_kms_public_key_b64": "<base64>",
  "tenant_sig": "ed25519:<base64>",
  "anchor": {"type": "none" | "rfc3161_tsa" | "sigstore_rekor", "receipt": null | {...}}
}
```

`tenant_sig` is checked against `C({epoch_index, root, epoch_start,
epoch_end, tenant_id})`, with a missing field serialized as `null`. It is
an Ed25519 signature in the section 6.2 encoding.

## 10. Anchors (level 4)

An anchor ties an epoch root to something outside the server. Both kinds are
verified offline (`anchor.py`).

### 10.1 RFC 3161 timestamp (`rfc3161_tsa`)

Receipt:

```json
{"tsr_der_b64": "<base64 DER TimeStampResp>",
 "tsa_certificate_chain_b64": ["<base64 DER leaf cert>", "<issuer>", ...]}
```

What is timestamped: the TSA request's message imprint is the **raw 32-byte
epoch root** with hash algorithm SHA-256. The root is not hashed again. A
producer asks the TSA to timestamp a SHA-256 digest whose value is the epoch
root.

Verification (`anchor.verify_rfc3161_receipt`):

1. Base64-decode the response and the certificate list. The list must not be
   empty. Certificate 0 is the TSA signing certificate.
2. For each adjacent pair, check certificate `i` is directly issued by
   certificate `i + 1` (signature and issuer name). A failure makes the anchor
   fail.
3. Decode the `TimeStampResp`. `status` must be 0 (granted) or 1
   (grantedWithMods).
4. Check the `TimeStampToken` (via `rfc3161ng.check_timestamp`): the message
   imprint's algorithm is SHA-256 and its value equals the epoch root; the
   signed content type is `id-ct-TSTInfo`; if signed attributes are present,
   their `messageDigest` equals the digest of the encapsulated content and
   the signature covers the DER `SET OF` those attributes; the signature
   verifies under certificate 0's public key with RSA PKCS#1 v1.5.
5. Pass if steps 2 and 4 pass — and, when `tsa_trusted_roots_pem` is
   supplied (a list of PEM-encoded trusted root certificates), step 6 below.

6. **With `tsa_trusted_roots_pem`** (`anchor._check_tsa_trust_requirements`):
   the chain must actually reach a trusted root, not merely be internally
   consistent — chain-linking alone (step 2) means any self-signed "TSA"
   certificate passes. This requires ALL of:
   - the top of the supplied chain equals, or is directly issued by, one of
     the supplied roots;
   - every issuing (non-leaf) certificate in the chain carries
     `BasicConstraints` with `ca=True` — an ordinary end-entity certificate
     must not be usable as an issuer;
   - the leaf (TSA signing) certificate carries the `id-kp-timeStamping`
     `ExtendedKeyUsage`, and that extension is marked **critical** (RFC 3161
     §2.3 requires this — a non-critical EKU is rejected too, not just a
     missing one);
   - every certificate in the chain has a validity window (`not_before`..
     `not_after`) that covers the token's own `genTime` (extracted via
     `rfc3161ng.get_timestamp`), not just the current wall-clock time.

   Without `tsa_trusted_roots_pem`, none of step 6 runs — the anchor passes
   on steps 2 and 4 alone, same as before, with a note that no trusted-root
   check was made.

Not checked: that certificate 0 is actually named in the token's signer
info, and the nonce.

### 10.2 Rekor-style transparency log (`sigstore_rekor`)

Receipt, as stored in a bundle:

```json
{"log_id": "<informational, not read>",
 "inclusion_proof": {"log_index": 3, "tree_size": 7,
                     "root_hash": "<hex>", "hashes": ["<hex>", ...]},
 "signed_entry_timestamp": "ed25519:<base64>"}
```

`verify._verify_anchor` flattens `inclusion_proof` and
`signed_entry_timestamp` into one object and passes it to
`anchor.verify_rekor_receipt`:

1. `log_index` and `tree_size` must be integers, `root_hash` and each of
   `hashes` valid hex. `tree_size >= 1` and `0 <= log_index < tree_size`.
2. `len(hashes)` must be at most `bit_length(tree_size - 1)` (0 for a
   one-leaf tree).
3. The leaf is `SHA256(0x00 || epoch_root)`, with the raw 32-byte root as
   leaf data.
4. Recompute the root from the audit path by the RFC 6962 section 2.1.1
   `PATH` rule. `hashes` is in leaf-to-root order, so the last element
   belongs to the top split. With `k` the largest power of two less than
   the current size: if the index is below `k`, the last remaining hash is a
   right sibling and the walk descends into the left `k` leaves; otherwise
   it is a left sibling, the index drops by `k`, and the walk descends into
   the right part. The path must be used up exactly when the subtree size
   reaches 1. Then fold back up with `node_hash`.
5. The recomputed root must equal `root_hash`.
6. If the caller supplied a log public key: the receipt's
   `signed_entry_timestamp` must be a string, and must verify as Ed25519
   (section 6.2) over `C({"log_index": int, "tree_size": int, "root_hash":
   <the hex string as given>})`. A missing or non-string SET is a failure
   here, same as one that fails to verify — supplying a log key means the
   caller is asking for the SET to actually be checked, so there being none
   to check must not silently pass. If no log public key was supplied at
   all, the SET is noted as not checked and the anchor passes on step 5
   alone.

This is the bundle format's own receipt shape. It is **not** the byte format
a live Rekor server returns: real Rekor signs SETs with ECDSA over a
different payload, and its leaves are entry hashes, not epoch roots. A
producer that anchors to real Rekor must translate, and `anchor.py` does not
claim compatibility.

The level 3 tree (section 9.3) and this log proof use different proof
encodings: explicit sides versus index-derived RFC 6962 paths. Both use the
same `0x00`/`0x01` hashing.

### 10.3 Root-of-trust duties

`anchor.py` has no certificate store and no pinned keys. The following are
the verifier's job:

- **TSA:** check that the chain ends at a TSA root you trust. By default
  `anchor.py` checks only that the supplied chain is internally consistent;
  anyone can make a self-signed "TSA" certificate that passes every check
  in 10.1. Passing `tsa_trusted_roots_pem` (a list of PEM certificates) to
  `verify_rfc3161_receipt`/`verify_bundle` makes it additionally check that
  the chain terminates at one of them — but even then, `pathLen`/`keyUsage`
  constraints and the trusted root's own validity period are not checked
  (§14).
- **Rekor:** supply the log's public key via `rekor_public_key_b64`.
  Without it, `root_hash` comes from the receipt itself, and any party can
  build a tree that contains the epoch root. Step 5 then proves nothing
  about a real log.
- **`require_pinned_anchors=True`** (`verify_bundle`): turns an anchor that
  could only be checked against its own claims — a Rekor receipt with no
  `rekor_public_key_b64`, or an RFC 3161 token whose chain wasn't checked
  against `tsa_trusted_roots_pem` — into a finding instead of a note (11.4).
  It also turns an unanchored epoch (`anchor.type == "none"`) and an
  anchored epoch the caller opted out of checking (`check_anchors=False`)
  into findings, since asking for pinned anchors while accepting "nothing
  to check" or "not checking it" defeats the point.
- **Tenant key:** `tenant_kms_public_key_b64` comes from the bundle. Compare
  it with a key you got from the tenant some other way.
- **Device key:** in a bundle, `device.public_key_b64` comes from the bundle.
  With a ledger file, the key is whatever the caller passes as `--pubkey`.
  Compare it against a key obtained out of band, for example the one
  registered at enrollment. The key gives its own device id (6.1).

A bundle that carries its own keys proves it is internally consistent, not
who wrote it.

## 11. Verification

`verify.py` has two entry points. `verify_ledger(path, ...)` reads a SQLite
ledger and runs levels 1 and 2 (this is the `coriqo-verify` CLI).
`verify_bundle(bundle, ...)` reads an export bundle (section 13) and runs all
four levels. Both use the same chain walk (`verify._walk_chain`) and the same
checkpoint check (`verify._verify_checkpoints`).

Each check ends in one of three states:

- **pass**
- **finding**: listed in the report and sets `ok` to false
- **note**: listed in `notes`, does not change `ok`. Used for anything that
  was not checked, for example a missing key.

### 11.1 Level 1: chain

Input: entries in order. `verify_ledger` reads rows `ORDER BY seq`.
`verify_bundle` uses the order of `bundle["entries"]` as given and does not
sort.

To rebuild each event dict from a ledger row, take every column of
`agent_events` except `prev_hash`, `entry_hash` and `event_digest`, parse
`payload` from JSON, and for a row with `schema_version == "1"` drop
`trace_id`, `span_id`, `parent_span_id` and `continues_from`
(`verify._row_to_event_dict`). In a bundle the event dict is used as given. A
row whose `payload` is not valid JSON is a finding, not a raise — the row is
skipped and reported the same way a malformed bundle entry is.

`seq` must be a genuine `int`. Since `bool` is an `int` subclass in Python,
`True`/`False` are rejected rather than silently treated as `1`/`0`; a
string or float standing in for a sequence number is rejected the same way.
An entry that fails this check is skipped and reported, exactly like any
other malformed entry (step 4 below), not raised.

Let `expected_prev = GENESIS`, `prev_seq = none`. For each entry:

1. **Gaps.** If this is the first entry and `seq > 1`, record gap
   `(1, seq - 1)`. Otherwise, if `seq != prev_seq + 1`, record gap
   `(prev_seq + 1, seq - 1)`. Every gap is a finding.
2. **Link.** `derived = H(C({"prev_hash": stored_prev_hash, "seq": seq,
   "event_digest": H(C(event_dict))}))`. The entry is a broken link
   (finding) if `stored_prev_hash != expected_prev` or
   `derived != stored_entry_hash`. Remember `derived` for this `seq`.
3. Set `expected_prev = stored_entry_hash` and `prev_seq = seq`. Using the
   stored value, not the derived one, means one altered row is reported once,
   at its own seq, instead of at every row after it.
4. **Stale/wrong key, and rotation.** Whether this step can actually verify
   anything depends on whether a **starting key** was supplied
   (`public_key_b64` for `verify_ledger`, `pinned_device_public_key_b64` for
   `verify_bundle` — never a key read out of the entries/bundle themselves):

   - **With a starting key:** the walk maintains `active_key`/`active_id`
     live, starting from that key. A `key_rotated` event is valid only if
     its cross-signature verifies against the CURRENT `active_key`,
     `payload.old_device_id == active_id`, `event.device_id == active_id`,
     and `new_device_id == derive_device_id(new_public_key)` — all four,
     checked against the walk's own state, never against a label the
     payload merely claims. A valid rotation advances `active_key`/
     `active_id` from that `seq` onward; any other rotation is a finding
     (forged) and does not change them. Every non-rotation event whose
     `device_id != active_id` at its seq is also a finding
     (`stale_key_usage`) — this is what catches a device still signing
     with a key that was legitimately rotated away, or a key that was
     never active to begin with (this is what defends against the
     retired-key re-rotation attack: a device holding a key that was
     legitimately rotated away cannot take over the timeline by forging a
     further rotation, since its claimed `old_device_id` will not match
     `active_id`).
   - **Without a starting key** (original behaviour): a lookup-table
     `retired = {}` is used instead. A `key_rotated` event's cross-signature
     is checked, if the caller separately supplied `device_public_keys`, by
     looking up the key for the payload's own claimed `old_device_id` — a
     failed check is a finding, an unchecked one is a note — and
     `retired[old_device_id] = seq` is recorded regardless. A later
     non-rotation event whose `device_id` is in `retired` and whose `seq`
     is past the retiring event's own `seq` is `stale_key_usage` (finding).
     This mode cannot detect a rotation forged by a retired key;
     supplying a starting key is what closes that gap.

   In both modes, `new_device_id == derive_device_id(new_public_key)` is
   also checked independently — with a starting key this is one of the
   four conditions checked above, so a mismatch there is already a
   **finding** (the rotation is rejected as forged); without a starting key,
   a mismatch is a note only.
5. **Tool pairing.** If `tool_use_id` is set, remember the seq of the first
   `tool_use` and the first `tool_result` with that id.

After the walk:

6. `unpaired_tool_uses`: ids with a `tool_use` but no `tool_result`. Reported,
   **not** a finding (the call may still be running, or the process may have
   stopped).
7. `orphan_tool_results`: ids with a `tool_result` and either no `tool_use`
   or a `tool_use` at a later seq. Finding.

The walk does not check `payload_hash` (4.3).

### 11.2 Level 2: checkpoints

Input: all checkpoints, the `derived` map from 11.1,
and an optional device public key. For `verify_ledger` the key is the
`public_key_b64` argument (`--pubkey`). For `verify_bundle` it is
`bundle["device"]["public_key_b64"]`.

1. No checkpoints: note, nothing else to do.
2. No key: note that signatures were not checked.
3. **Key timeline** (`verify._build_key_timeline`). With a key, a checkpoint
   is no longer checked against one single pinned key for the whole run.
   Instead the verifier builds a timeline from the same chain walk that
   already ran in 11.1: it starts with the given key, and at each
   `key_rotated` entry whose cross-signature VERIFIED (11.1 step 4), the
   active key becomes that event's `new_public_key` from its own `seq`
   onward. A rotation whose cross-signature was NOT verified (no old key
   supplied, or forged) does not extend the timeline — checkpoints after it
   keep being checked against whatever key was last known good, plus a note
   explaining why. Each `key_rotated` event also gets one more check
   independent of the cross-signature: `new_device_id` must equal
   `derive_device_id(new_public_key)` (6.1); a mismatch is a note, not a
   finding on its own. This checkpoint-signature timeline is built the same
   way regardless of whether `public_key_b64`/`pinned_device_public_key_b64`
   is also used as the *live* rotation-validity starting key described in
   11.1 step 4 — the two use the same key but are otherwise separate
   mechanisms (one gates checkpoint signatures, the other gates which
   rotations are accepted into the device-id timeline at all).
4. For each checkpoint:
   - With a key: verify `sig` over `C(checkpoint without "sig")`, using the
     key active (per the timeline) at that checkpoint's own `seq_end`. A
     missing or invalid signature is a finding.
   - Without a key: a missing (non-string) `sig` is a finding.
   - If there is no `derived` value for `seq_end`, finding.
   - If `chain_head != derived[seq_end]`, finding.

`device_id`, `seq_start` and `ts_device` are not checked.

**Pinning hardening (`verify_bundle` only).** A caller who supplies
`pinned_device_public_key_b64` is asking for every entry to actually be
covered by a signed checkpoint, not merely for the ones that exist to check
out:

- Zero checkpoints in the bundle: finding (nothing is signature-checked at
  all).
- Entries whose `seq` comes after the last checkpoint's `seq_end`: finding,
  reported in `unsigned_tail` as an inclusive `(first_seq, last_seq)` range —
  a bundle could otherwise pad itself with unsigned "tail" entries after the
  last real checkpoint and have them pass silently.

**Pinning hardening (`verify_ledger` only).** A caller who supplies
`public_key_b64` (`--pubkey`) similarly gets the checkpoint table itself
covered, not just whatever checkpoints happen to parse:

- Zero checkpoint rows in the ledger: finding (`no_signed_checkpoints`).
- The `checkpoints` table itself cannot be read at all (as opposed to one
  row's body being bad JSON, handled per-row below): finding
  (`unreadable_checkpoints`).
- Each checkpoint row is parsed independently — a corrupted row (bad JSON
  body, a non-object body, an unusable `seq_end`) is its own failed
  checkpoint (added to `bad_signatures`) and does not stop the rest of the
  table from being checked.
- Entries whose `seq` comes after the last checkpoint's `seq_end`: reported
  in `unsigned_tail` as an inclusive `(first_seq, last_seq)` range, but this
  is **informational only** on the ledger path (unlike the bundle path
  above, it does not affect `ok`) — a live, still-recording ledger always
  has such a tail, since the newest events haven't been checkpointed yet.
  The `coriqo-verify` CLI still prints it, so a caller pinning a key knows
  exactly how far signed coverage reaches.

### 11.3 Level 3: epoch inclusion and tenant signature (bundle only)

1. Read every epoch's `root` from hex into a map by `epoch_index`. A malformed
   epoch (not an object, missing/non-int `epoch_index`, `root` not valid hex,
   ...) is skipped and reported in `malformed_bundle` — a **finding**, not a
   note: a corrupt root is exactly what checkpoint inclusion proofs are
   verified against and what an anchor receipt anchors, regardless of that
   epoch's `anchor.type`.
2. For each bundle checkpoint:
   - If `inclusion_proof` or `epoch_index` is null: note ("not yet anchored").
     If the caller supplied `pinned_tenant_public_keys_b64`, this is instead
     a finding — pinning a tenant key is asking for inclusion to actually be
     provable, and a checkpoint with no proof at all can't be.
   - If `epoch_index` is not in the map: finding.
   - Otherwise recompute `leaf_hash` from the checkpoint and fold the proof
     (9.3). If the result is not the epoch root: finding.
3. For each epoch: if `tenant_sig` or `tenant_kms_public_key_b64` is missing,
   note (or, if `pinned_tenant_public_keys_b64` was supplied, finding — same
   reasoning as the inclusion-proof case above). Otherwise verify it (9.4).
   Failure is a finding.

### 11.4 Level 4: anchors (bundle only)

`require_pinned_anchors=True` turns two cases that would otherwise only be
notes into findings: an epoch whose `anchor.type == "none"` (nothing to
anchor to at all), and any anchored epoch when the caller passed
`check_anchors=False` (the caller explicitly opted out of checking, but is
also asking every anchor to be provably pinned — those two options
together mean "there had better be a pinned anchor, and I'm not even going
to check it" is not a state this run should silently accept).

For each epoch, read `anchor.type` (default `"none"`):

1. `"none"`: legitimately unanchored. A note says so (`"no anchor
   (anchor.type == 'none')"`); it is a finding only when
   `require_pinned_anchors=True` (item 5 below) — otherwise never a finding.
2. `check_anchors=False`: note, not verified — unless `require_pinned_anchors=True`
   (item 5 below), in which case it is a finding.
3. `"rfc3161_tsa"`: 10.1, with the caller's `tsa_trusted_roots_pem` if
   given. `"sigstore_rekor"`: 10.2, with the caller's
   `rekor_public_key_b64`. Failure is a finding. The verifier's notes are
   copied into the report.
4. Any other type: finding.
5. **Key/root pinning** (`require_pinned_anchors=True`). By
   default an anchor checked only against its own claims — a Rekor receipt
   with no `rekor_public_key_b64`, or an RFC 3161 token whose chain wasn't
   checked against `tsa_trusted_roots_pem` — still counts as passing (this
   is §14 item 2, kept for callers who don't have an external key
   to pin). `require_pinned_anchors=True` turns that specific case into a
   finding instead, on top of whatever 10.1/10.2 already found.

**Bundle key pinning** (§10.3). `verify_bundle` also accepts
`pinned_device_public_key_b64` and `pinned_tenant_public_keys_b64` (an
iterable of base64 keys). When given: the bundle's own
`device.public_key_b64` must equal the pinned device key, or
`device_key_mismatch` is set (finding). Each epoch's
`tenant_kms_public_key_b64` must be one of the pinned tenant keys, or its
`epoch_index` is added to `tenant_key_mismatches` (finding). Without these
arguments, verification still only proves the bundle is internally
consistent, not who wrote it (§10.3).

**Malformed bundles.** A bundle entry, checkpoint or epoch of the wrong
shape — missing `epoch_index`, bad `steps` hex, a missing `checkpoint`
object, wrong types, an unparseable `seq` — is reported in
`malformed_bundle` (finding) and the item is skipped, never raised — this
verifier must not raise on any field of untrusted input it reads, not just
the ones already wrapped in `try`/`except`.

### 11.5 Verdict

`verify_ledger` sets `ok` to true only if there are no broken links, bad
checkpoints (`bad_signatures`, which also covers unparseable checkpoint
rows), gaps, orphan tool results, stale-key entries, forged rotations,
malformed ledger rows (`notes`, prefixed `malformed_bundle:` for
consistency with the bundle path), or — when `public_key_b64` was supplied
— `no_signed_checkpoints`/`unreadable_checkpoints`. `unsigned_tail` is
informational on the ledger path and does not affect `ok` (11.2). If a
receipt store was passed, its own verdict must also be true.

`verify_bundle` adds bad inclusions, bad epoch signatures, bad anchors,
`malformed_bundle` (covers malformed entries, checkpoints, epochs, and the
bundle itself), `device_key_mismatch`, `tenant_key_mismatches`, and — when
`pinned_device_public_key_b64` was supplied — the "zero checkpoints" and
`unsigned_tail` findings from 11.2 to that list. When a heartbeat silence
policy was supplied (11.6), `heartbeat_silences` is added to both.

`coriqo-verify` exits 0 when `ok`, 1 when not, and 2 when the ledger or a
key file cannot be read. `--json` prints the full report.

### 11.6 Heartbeat checks (opt-in)

Off by default, so a ledger or bundle written before heartbeats verifies as
before. A caller turns them on with a policy value: `--max-heartbeat-silence
SECONDS` on `coriqo-verify`, or `max_heartbeat_silence_seconds` on `verify_ledger`
and `verify_bundle`. A value that is not a finite number above 0 (`nan`, `inf`,
0, negative) is refused: `VerifyError`, exit 2. It is never read as "off".

Which command checks which format: `coriqo-verify LEDGER.db [flags]` checks a
ledger (`verify_ledger`). `coriqo-verify bundle FILE.json [flags]` checks an
export bundle (`verify_bundle`) and takes the same heartbeat flags.

With the check on, each of these fails `ok`:

1. Spacing. Two consecutive heartbeats further apart than the policy
   (`heartbeat_silences`, `kind: "spacing"`, each `{from_seq, to_seq, seconds}`).
2. Tail. The last heartbeat to the newest time in the record (the latest
   checkpoint `ts_device` or entry `ts_device`) is longer than the policy
   (`kind: "tail"`, named `tail:SEQ`). Silence after
   the last entry of the record, up to now, is not judged: the offline verifier
   has no reference time.
3. Heartbeats off. A heartbeat with `interval_s: 0` starts a window the recorder
   declared uncovered, until the next heartbeat or the end of the record
   (`kind: "disabled"`, named `off:SEQ`).
4. No heartbeats. A record that spans longer than the policy and contains none
   (`no_heartbeats`). `--allow-no-heartbeats` / `allow_no_heartbeats=True`
   accepts it, for a record from before heartbeats existed.
5. An invalid `interval_s` (not a number >= 0), or a heartbeat with no parseable
   time (`malformed_bundle`).
6. With the check on, a bundle with no entries or no checkpoints. Stripping
   checkpoints must not turn a failing record into a pass.

Clock notes are advisory. These are reported as labelled "clock notes" in the
output and in `clock_findings` (JSON), and do not change `ok`:

- device time going backwards between heartbeats;
- device time advancing less than the monotonic counter (`ts_monotonic_ns`)
  between two heartbeats of the same boot (a clock set back, for example across
  an outage). A host that slept shows the opposite and is not noted;
- a heartbeat dated before the signed checkpoint that precedes it (by checkpoint
  row order), or after the one that covers it;
- in a bundle, a heartbeat dated after the `epoch_end` of any tenant epoch whose
  checkpoint covers it.

They are advisory because honest records trip them: an NTP step, a VM resume, a
ledger moved to another host, several writer processes on one ledger. Use
`--strict-clock` (`strict_clock=True`) to make them fail, in a single-host,
single-process deployment under review. In strict mode a note you reviewed is
accepted by its heartbeat seq: `--accept-clock-note SEQ` (repeatable;
`clock_notes_accepted=[...]`). A clock note can always be accepted.

Sleep. A laptop that sleeps or a VM that is suspended produces a spacing gap: the
process was alive but not running, so it wrote nothing. The check reports it as
any other gap. If you know that is the cause, accept it by name (below).

A policy value below the smallest `interval_s` the device declared is noted
("the policy is stricter than the interval the device declared"); it is not a
failure, but a healthy recorder can fail such a policy.

The caller accepts a window they have reviewed, such as a planned shutdown or a
sleep, by the name shown in the finding. A gap between two heartbeats is
`FROM-TO` (`--heartbeat-gap 12-13`, or `(12, 13)` in the API). The tail after the
last heartbeat is `tail:SEQ`, SEQ being that heartbeat. A window the recorder
declared off is `off:SEQ`, SEQ being the marker, so the acceptance does not change
as the record grows. An accepted window is listed in `notes`. A name covers only
that window.

Limits. This check bounds what the device claims. A host that controls its own
clock, and the monotonic counter source, can defeat it. Only an external time
anchor bounds it from outside: a verified RFC 3161 or Rekor anchor (11.4), or the
time Coriqo received the entry. Read the result together with pinned keys and the
signed checkpoints that cover the heartbeats (11.2). A pass means nothing in the
record contradicts the spacing policy. It is not proof the recorder was running.

A green result without keys means "internally consistent". Read `notes` to
see what was not checked.

## 12. Versioning

Schema versions are in `schema.EVENT_SCHEMA_VERSION` (`"2"`) and
`EVENT_SCHEMA_VERSION_V1` (`"1"`).

- **v1** events have no trace fields. Their hashed dict has 14 keys.
- **v2** adds `trace_id`, `span_id`, `parent_span_id`, `continues_from`. All
  four are always in the hashed dict, `null` where empty. 18 keys.

Migration is additive and nothing is rehashed. Opening an old ledger adds the
four columns with `ALTER TABLE` (`Ledger.__init__`). Existing rows keep
`schema_version = "1"` and get NULL in the new columns. Because the digest of
a v1 row was computed without those keys, `AgentEvent.to_dict` and
`verify._row_to_event_dict` drop them for any row whose `schema_version` is
`"1"`: they are left out, not included as null. New rows are always v2. A
chain can therefore mix v1 and v2 rows, and a verifier chooses the key set
per row from that row's `schema_version`.

Checkpoints, epochs and anchor receipts have no version field. The export
bundle has `bundle_version: "1.0"`, which the verifier does not read.

## 13. Wire and bundle shapes

### 13.1 Upload to the server

The shipper (`shipper.py`) sends signed, gzipped batches:

- `POST /v1/ingest/batch` with body
  `{"device_id": ..., "entries": [{"seq", "entry_hash", "event"}, ...]}`.
  `event` is `AgentEvent.to_dict()`. `prev_hash` is not sent: the receiver
  gets it from the previous entry's `entry_hash`.
  An entry whose row has a `payload_mode` (§4.3) also carries it as
  `entries[].payload_mode`, beside `event` and never inside it; a row without
  one ships without the key. When a payload mode is configured, the top-level
  `runtime` block also carries `"name": "byoai-runtime"`, `"version"` and
  `"payload_mode"`, naming the shipper and the mode it is configured with,
  beside the capability signal of 4.4 when heartbeats run. The block is left
  out when there is neither. Both are covered by the batch signature and by no
  digest.
- A Coriqo workspace may refuse a batch whose payloads were sent above its
  payload mode: HTTP 409 with `detail.code == "payload_mode_refused"`,
  `detail.modes`, `detail.payload_mode`, `detail.message` and a `Retry-After`
  header. Nothing in the batch is stored; the shipper keeps the entries
  unsynced, retries after backoff and logs the refusal at most once an hour.
- `POST /v1/checkpoints/batch` with body
  `{"device_id": ..., "checkpoints": [<checkpoint>, ...]}`.
- Request body: `gzip(C(body))`. Headers: `content-encoding: gzip`,
  `x-coriqo-device: <device_id>`, `x-coriqo-signature: <sig over C(body)>`.
  The signature covers the uncompressed canonical bytes.

Delivery is at least once. The receiver dedupes on `entry_hash`.

Decision traces sent with `CoriqoAgentsClient.record_trace` or
`record_traces` carry the mode their text was prepared in as an
`X-Coriqo-Payload-Mode` header (`full`, `redacted` or `hash-only`); no
header is sent when the caller passes no mode.

Enrollment (`enroll.py`) posts `{"public_key": <base64>, "token": ...}` to
`/v1/enroll`. That is where a server gets the device key it later pins.

### 13.2 Export bundle

`verify_bundle` reads one JSON object. Producing bundles is a server job, and
no producer ships in this package. Fields the verifier reads:

```jsonc
{
  "bundle_version": "1.0",                  // not read
  "device": {"device_id": "...", "public_key_b64": "..."},
  "entries": [
    {"seq": 1, "prev_hash": "sha256:...", "entry_hash": "sha256:...",
     "event_digest": "sha256:...",           // not read; recomputed
     "event": { /* AgentEvent.to_dict() */ }}
  ],
  "checkpoints": [
    {"checkpoint": { /* section 8 */ },
     "epoch_index": 0,                        // or null
     "inclusion_proof": {"leaf_index": 0, "steps": [...]}}   // or null
  ],
  "epochs": [ /* section 9.4 */ ]
}
```

Key rotation cross-signatures are checked with a separate, caller-supplied
argument, never from a key read out of the bundle itself (§10.3). The
preferred one is `pinned_device_public_key_b64` — the key active at the
bundle's first entry (seq 1), not necessarily the device's current key —
which drives the same live rotation-timeline walk described in §11.1 step
4. `device_public_keys` (a `{device_id: key}` map) is the fallback used
only when no `pinned_device_public_key_b64` is supplied; once one is
supplied, `device_public_keys` no longer decides rotation validity and can
only produce an informational note if it disagrees with the timeline
already established.

## 14. Known limitations

These describe how the current code behaves. A verifier written from this page
should reproduce them, or report them as a deliberate difference.

Fixed since the previous revision of this page (kept here as history, not as
a current gap): checking every checkpoint against a single pinned key across
a rotation is now §11.2's key timeline; bundle keys being impossible to pin
is now `pinned_device_public_key_b64`/`pinned_tenant_public_keys_b64`
(§10.3/§11.4); malformed bundle fields raising instead of producing a
finding is now `malformed_bundle` (§11.4); an unpinned anchor always passing
with no way to make that strict is now optional via
`require_pinned_anchors=True` (kept as item 2 below for a caller who doesn't
opt into it, which is still the default). Also fixed: a `key_rotated` event
forged by a device still holding a **retired** key could previously take
over the device-id timeline outright when a starting key was supplied — the
cross-signature was checked by looking the signing key up under whatever
`old_device_id` the payload itself claimed, never confirmed against what was
actually active — this is now §7/§11.1 step 4's live `active_key`/
`active_id` walk, and a device-id mismatch anywhere in that walk is a
finding (`stale_key_usage`), not merely a note; pinning
(`pinned_device_public_key_b64`/`pinned_tenant_public_keys_b64`) no longer
just *changes what key is compared* — with no signed checkpoint/inclusion
proof/tenant signature at all, or entries past the last signed checkpoint, it
is now a finding rather than silently unchecked (§11.2/§11.3); a Rekor SET
that was missing or non-string used to pass anyway whenever a
`rekor_public_key_b64` was supplied — it is now a finding, not a silent pass
(§10.2); an RFC 3161 chain checked against `tsa_trusted_roots_pem` used to
stop at "links together and reaches a listed root" — it now also requires
each issuing cert's BasicConstraints `ca=True`, the leaf's
ExtendedKeyUsage id-kp-timeStamping to be present and critical, and every
cert's validity window to cover the token's `genTime` (§10.1); and a
`COMMIT` failure inside `Ledger._append_locked` used to leave the SQLite
connection wedged inside an open transaction forever — it is now rolled
back, so the very next append can still succeed (§7 out-of-process note
below, unrelated mechanism but the same "must not wedge the ledger" theme).

Also fixed, a further round of malformed-input hardening: a `key_rotated`
event's `payload` being a non-object used to raise `AttributeError` out of
the rotation checkers — it is now treated as an empty (unsubstantiated)
claim plus a `malformed_bundle` finding; an epoch's `anchor` being a
non-object used to be silently coerced to `{"type": "none"}`, passing as
legitimately unanchored — it is now a `malformed_bundle` finding; an epoch's
`root` being invalid hex used to only produce a note that was never folded
into `malformed_bundle`, so a bad root passed whenever the epoch's own
anchor was `"none"` — it is now always a finding; a checkpoint's `seq_end`
being a non-int (a numeric string, or `None`) used to raise `ValueError`/
`TypeError` out of `_verify_checkpoints` — it is now a failed checkpoint; a
`sigstore_rekor` anchor's `receipt` being a non-object used to raise
`AttributeError` out of `verify_rekor_receipt` — it is now a failed anchor;
and the bundle argument to `verify_bundle` itself being the wrong shape
entirely (e.g. a list) used to raise on the first `.get()` call — it now
returns a report with `ok=False` and a `malformed_bundle` finding, same as
any other malformed input.

1. **Bundles must start at seq 1.** The chain walk expects the first entry's
   `prev_hash` to be genesis and treats a first `seq` above 1 as a gap, so an
   export of a middle range always fails. Accepting a stated starting
   `prev_hash` without a note would let a bundle producer silently splice in
   a fabricated earlier history — strictly worse than failing loudly on a
   partial range — so this is left as a real limitation rather than patched
   around.
2. **An unpinned anchor passes by default.** A Rekor receipt checked without
   a log key, or an RFC 3161 token whose chain does not reach a trusted
   root, still counts as a passing anchor unless the caller passes
   `require_pinned_anchors=True` (§11.4), in which case it is a finding
   instead. Either way the gap is reported in a note.
3. **The Rekor receipt is this format's own**, with an Ed25519 SET (10.2).
4. **RFC 3161 tokens must be RSA-signed.** The check uses PKCS#1 v1.5, so a
   TSA that signs with ECDSA fails verification.
5. **Even with `tsa_trusted_roots_pem`, the TSA chain check is not a full PKIX
   validation.** It confirms each certificate was directly issued by the
   next one and that the chain terminates at a supplied root, but does not
   check `pathLen`/`keyUsage` constraints along the chain, and does not
   check that the trusted root certificate itself is within its own
   validity period (§10.3).
6. **`payload_hash` is not verified** (4.3).
7. **Revocation does not reach back.** `compromise` and `revocation` retire
   the old id from the rotation's seq onward, like `rotation` does. Entries
   before that seq stay valid, including any a thief wrote with a stolen key
   before the rotation.
8. **Events are unsigned between checkpoints.** Events after the last
   checkpoint are protected only by the chain until the next checkpoint.
9. **Deletion from the end.** Removing the newest entries leaves a shorter
   chain that still verifies, unless a checkpoint, epoch or anchor
   references a later `seq_end`. The checkpoint row can be deleted along
   with the entries, so only a copy held elsewhere (shipped to a server, or
   included in an epoch) shows the truncation.

## 15. Relation to the Coriqo attestation format

Coriqo's `seal-verifier` publishes its own specification (Coriqo Attestation
Format v1.0, `seal-verifier/SPEC.md`, Apache-2.0). It covers Coriqo's
server-side governance chain, not device records. The two formats are
independent, and a record in one cannot be checked with the other's
verifier. They compare as follows:

| | This format (device recorder) | Coriqo attestation format v1.0 |
|---|---|---|
| Canonical JSON | RFC 8785: UTF-16 key order, ECMAScript number formatting | `json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False)`: code-point key order, integers only |
| Hash text | `"sha256:" + hex` | bare hex |
| Genesis | `"sha256:" + 64 zeros` | 64 zeros |
| First `seq` | 1 | 0 |
| Chain link | event digest, then `entry_hash` over `{prev_hash, seq, event_digest}` | one `event_hash` over the event fields including `prev_hash` |
| Merkle leaves | whole signed device checkpoints (canonical JSON) | raw 32-byte event hashes |
| Tree shape | RFC 6962 (odd node promoted) | `tree_version` 1 (duplicate last node) or 2 (RFC 6962) |
| Proof encoding | explicit sibling and side | RFC 6962 path from the leaf index |
| Signed object | checkpoint `{device_id, seq_start, seq_end, chain_head, ts_device}` | `sth_body` |
| Signature | Ed25519 only, `"ed25519:"` prefix | Ed25519, or ES256 when `sth_body.algorithm` says so |
| TSA imprint | the raw epoch root | `SHA256(C(sth_body))` |
| Anchors in the verdict | a failed anchor fails `verify_bundle` | informational, never changes PASS/FAIL |
| Revocation | `key_rotated` event in the chain, applied by `seq` | revoked flag or signed revocation record in the keyring. A signature under a revoked key fails |

The two canonical forms produce the same bytes for objects whose numbers are
all integers and whose keys contain no characters above U+FFFF. They differ
for floats and for such keys. A device checkpoint uploaded to
`/v1/checkpoints/batch` becomes a leaf of a tenant epoch tree (level 3 here).
The Coriqo specification does not describe that tree.

## 16. Test vectors

Produced by `python docs/seal-format-vectors.py` (install with
`pip install -e ".[recorder]"`). The output is deterministic: the keys come
from `SHA256` of fixed labels, the ids and clocks are fixed, and Ed25519
signatures are deterministic. The keys are for testing only.

The output below is verbatim. In vector 0, the character after `\n` in the
`é` value is a literal U+2028, which may display as a space or line break.

```text
========================================================================
Vector 0: canonical JSON
========================================================================
input (Python repr):
  {'z': 1.0, 'a': [1e+21, 0.1, -0.0, 1e-07], 'é': 'café\n ', '😀': 'astral key', 'ﬁ': 'BMP key above the surrogate range', 'n': None, 't': True}
canonical bytes (UTF-8, shown as text):
  {"a":[1e+21,0.1,0,1e-7],"n":null,"t":true,"z":1,"é":"café\n ","😀":"astral key","ﬁ":"BMP key above the surrogate range"}
canonical bytes (hex):
  7b2261223a5b31652b32312c302e312c302c31652d375d2c226e223a6e756c6c2c2274223a747275652c227a223a312c22c3a9223a22636166c3a95c6ee280a8222c22f09f9880223a2261737472616c206b6579222c22efac81223a22424d50206b65792061626f76652074686520737572726f676174652072616e6765227d
sha256:
  sha256:7b031c82f0bbf2a841d7ec4ddba31212d05dee11a5dde635038e59e261cc301b

========================================================================
Vector 1: device key, three events, hash chain
========================================================================
device private seed (hex, TEST ONLY):
  1a520e24db897329b32ff276f259bab667bafd23a8427c54ae6a5cef8f717e8b
device public_key_b64:
  mxEBY+42DpKkf9Ho/FtI96t9NvF/+8BlHSAFGps5oj8=
device_id:
  dev_XJ3WSKC2GEJ743SW4BQ2BVZ3S2

--- entry seq=1 ---
event canonical bytes:
  {"continues_from":null,"device_id":"dev_XJ3WSKC2GEJ743SW4BQ2BVZ3S2","event_id":"evt_00000000000000000000000000000001","kind":"message","model":"claude-test","parent_span_id":null,"payload":{"role":"user","text":"list files in /tmp"},"payload_hash":"sha256:3f90a8ad478642763e0cd25b310581708642d3bad1990ac47ec3439f2c5ca322","provider":"anthropic","schema_version":"2","seq":1,"session_id":"sess_vectors","span_id":"sp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tool_name":null,"tool_use_id":null,"trace_id":"tr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ts_device":"2026-07-25T12:00:01.000000Z","ts_monotonic_ns":1000000}
payload_hash = sha256(canonical(payload)):
  sha256:3f90a8ad478642763e0cd25b310581708642d3bad1990ac47ec3439f2c5ca322
event_digest = sha256(event canonical bytes):
  sha256:26ec4224901d408f7c982ed20bab795caf5e45a6e05af07275a93ade740fe49d
prev_hash:
  sha256:0000000000000000000000000000000000000000000000000000000000000000
link canonical bytes:
  {"event_digest":"sha256:26ec4224901d408f7c982ed20bab795caf5e45a6e05af07275a93ade740fe49d","prev_hash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","seq":1}
entry_hash = sha256(link canonical bytes):
  sha256:ad32f4b93b6ac843a019ad4c6f57e2ca58ff104b67c63a708d74817feb13b09e

--- entry seq=2 ---
event canonical bytes:
  {"continues_from":null,"device_id":"dev_XJ3WSKC2GEJ743SW4BQ2BVZ3S2","event_id":"evt_00000000000000000000000000000002","kind":"tool_use","model":"claude-test","parent_span_id":null,"payload":{"input":{"path":"/tmp"}},"payload_hash":"sha256:e8f4d84e09487c5ab6c56e5dd6b3dc541f8e6ba789677b5758cb4f7377d1175c","provider":"anthropic","schema_version":"2","seq":2,"session_id":"sess_vectors","span_id":"sp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tool_name":"list_dir","tool_use_id":"toolu_01","trace_id":"tr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ts_device":"2026-07-25T12:00:02.000000Z","ts_monotonic_ns":2000000}
payload_hash = sha256(canonical(payload)):
  sha256:e8f4d84e09487c5ab6c56e5dd6b3dc541f8e6ba789677b5758cb4f7377d1175c
event_digest = sha256(event canonical bytes):
  sha256:ee99dcd18180babd9744ab5c752fd550a4c953440ec48b3a6094802390b21326
prev_hash:
  sha256:ad32f4b93b6ac843a019ad4c6f57e2ca58ff104b67c63a708d74817feb13b09e
link canonical bytes:
  {"event_digest":"sha256:ee99dcd18180babd9744ab5c752fd550a4c953440ec48b3a6094802390b21326","prev_hash":"sha256:ad32f4b93b6ac843a019ad4c6f57e2ca58ff104b67c63a708d74817feb13b09e","seq":2}
entry_hash = sha256(link canonical bytes):
  sha256:23e0c488bdf2623b8d715d8f69311d773688dd4dfdfe2eaefeb38f34aac61830

--- entry seq=3 ---
event canonical bytes:
  {"continues_from":null,"device_id":"dev_XJ3WSKC2GEJ743SW4BQ2BVZ3S2","event_id":"evt_00000000000000000000000000000003","kind":"tool_result","model":"claude-test","parent_span_id":null,"payload":{"bytes":12,"content":"a.txt\nb.txt","is_error":false,"ratio":0.5},"payload_hash":"sha256:b8db3498ddb0995785de5ac02c84a725de3fdc909606c075531ffa693a0d290a","provider":"anthropic","schema_version":"2","seq":3,"session_id":"sess_vectors","span_id":"sp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","tool_name":"list_dir","tool_use_id":"toolu_01","trace_id":"tr_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","ts_device":"2026-07-25T12:00:03.000000Z","ts_monotonic_ns":3000000}
payload_hash = sha256(canonical(payload)):
  sha256:b8db3498ddb0995785de5ac02c84a725de3fdc909606c075531ffa693a0d290a
event_digest = sha256(event canonical bytes):
  sha256:96bf53e546ccadaf19c5401f7bfe9bc46f96fe6eba848abcbe3996d280d72bf0
prev_hash:
  sha256:23e0c488bdf2623b8d715d8f69311d773688dd4dfdfe2eaefeb38f34aac61830
link canonical bytes:
  {"event_digest":"sha256:96bf53e546ccadaf19c5401f7bfe9bc46f96fe6eba848abcbe3996d280d72bf0","prev_hash":"sha256:23e0c488bdf2623b8d715d8f69311d773688dd4dfdfe2eaefeb38f34aac61830","seq":3}
entry_hash = sha256(link canonical bytes):
  sha256:c645927570e822445c671cda675490fc0ec05e6eb28125ae52ac35973e5c9411

========================================================================
Vector 2: checkpoints, epoch Merkle tree (3 leaves), inclusion proofs
========================================================================

--- checkpoint seq_end=1 ---
signing bytes = canonical(checkpoint minus sig):
  {"chain_head":"sha256:ad32f4b93b6ac843a019ad4c6f57e2ca58ff104b67c63a708d74817feb13b09e","device_id":"dev_XJ3WSKC2GEJ743SW4BQ2BVZ3S2","seq_end":1,"seq_start":1,"ts_device":"2026-07-25T17:20:01.000000Z"}
sig:
  ed25519:QE/MyqUJhzPlfg41+SEL4KlIfmvG8mwJbIaTLUr875He1n9Xznpqp+Bcgh0OH1iAoj64gtcHCAbQtLlkv7ssAQ==
full checkpoint canonical bytes (Merkle leaf input):
  {"chain_head":"sha256:ad32f4b93b6ac843a019ad4c6f57e2ca58ff104b67c63a708d74817feb13b09e","device_id":"dev_XJ3WSKC2GEJ743SW4BQ2BVZ3S2","seq_end":1,"seq_start":1,"sig":"ed25519:QE/MyqUJhzPlfg41+SEL4KlIfmvG8mwJbIaTLUr875He1n9Xznpqp+Bcgh0OH1iAoj64gtcHCAbQtLlkv7ssAQ==","ts_device":"2026-07-25T17:20:01.000000Z"}
leaf hash = sha256(0x00 || leaf input) (hex):
  c467c6f752b950be7f1777f24c037d31b0f7ff01f7e6f7f48a88bd04077b8a11

--- checkpoint seq_end=2 ---
signing bytes = canonical(checkpoint minus sig):
  {"chain_head":"sha256:23e0c488bdf2623b8d715d8f69311d773688dd4dfdfe2eaefeb38f34aac61830","device_id":"dev_XJ3WSKC2GEJ743SW4BQ2BVZ3S2","seq_end":2,"seq_start":2,"ts_device":"2026-07-25T17:20:02.000000Z"}
sig:
  ed25519:OIPVfYNPjiKwPkOMEnB7Ln3djY5nhGhmR3p5Q/1/AMwAe7PCXt4mLN56vdKCubemoQAKvw3Qvmwufiuy12zXDw==
full checkpoint canonical bytes (Merkle leaf input):
  {"chain_head":"sha256:23e0c488bdf2623b8d715d8f69311d773688dd4dfdfe2eaefeb38f34aac61830","device_id":"dev_XJ3WSKC2GEJ743SW4BQ2BVZ3S2","seq_end":2,"seq_start":2,"sig":"ed25519:OIPVfYNPjiKwPkOMEnB7Ln3djY5nhGhmR3p5Q/1/AMwAe7PCXt4mLN56vdKCubemoQAKvw3Qvmwufiuy12zXDw==","ts_device":"2026-07-25T17:20:02.000000Z"}
leaf hash = sha256(0x00 || leaf input) (hex):
  59119f3514c75ad2424cc7f4aceb84dc4d3ed58f2e30e748d0bfa6aa44700af3

--- checkpoint seq_end=3 ---
signing bytes = canonical(checkpoint minus sig):
  {"chain_head":"sha256:c645927570e822445c671cda675490fc0ec05e6eb28125ae52ac35973e5c9411","device_id":"dev_XJ3WSKC2GEJ743SW4BQ2BVZ3S2","seq_end":3,"seq_start":3,"ts_device":"2026-07-25T17:20:03.000000Z"}
sig:
  ed25519:c9jmLF0xAgQ9zTrWwWXEOzh3m8uHEEx3b8/X4ZzpM/Hh9WSFJyYBF3SiQWlBAaqFfnmhA8RtK7hZPcOo8mmIBQ==
full checkpoint canonical bytes (Merkle leaf input):
  {"chain_head":"sha256:c645927570e822445c671cda675490fc0ec05e6eb28125ae52ac35973e5c9411","device_id":"dev_XJ3WSKC2GEJ743SW4BQ2BVZ3S2","seq_end":3,"seq_start":3,"sig":"ed25519:c9jmLF0xAgQ9zTrWwWXEOzh3m8uHEEx3b8/X4ZzpM/Hh9WSFJyYBF3SiQWlBAaqFfnmhA8RtK7hZPcOo8mmIBQ==","ts_device":"2026-07-25T17:20:03.000000Z"}
leaf hash = sha256(0x00 || leaf input) (hex):
  f0a42ff6691fe31d529da4b34531ef30bf3a09dd7da3dba1d8ea52e9e23c013f

node(0,1) = sha256(0x01 || leaf0 || leaf1) (hex):
  c0fe6e98f8e1dec66d242ddfd8fafc5ed96efe04e103b7cc586c51c56c3c0774
level 1 (leaf 2 promoted unchanged):
  ['c0fe6e98f8e1dec66d242ddfd8fafc5ed96efe04e103b7cc586c51c56c3c0774', 'f0a42ff6691fe31d529da4b34531ef30bf3a09dd7da3dba1d8ea52e9e23c013f']
epoch root (hex):
  23c75bb4da3b8a208ef6af0a905b15e7c09b57c0f38348d935ecf992b816a7c3
inclusion proof leaf_index=0:
  [{'sibling': '59119f3514c75ad2424cc7f4aceb84dc4d3ed58f2e30e748d0bfa6aa44700af3', 'side': 'right'}, {'sibling': 'f0a42ff6691fe31d529da4b34531ef30bf3a09dd7da3dba1d8ea52e9e23c013f', 'side': 'right'}]
inclusion proof leaf_index=1:
  [{'sibling': 'c467c6f752b950be7f1777f24c037d31b0f7ff01f7e6f7f48a88bd04077b8a11', 'side': 'left'}, {'sibling': 'f0a42ff6691fe31d529da4b34531ef30bf3a09dd7da3dba1d8ea52e9e23c013f', 'side': 'right'}]
inclusion proof leaf_index=2:
  [{'sibling': 'c0fe6e98f8e1dec66d242ddfd8fafc5ed96efe04e103b7cc586c51c56c3c0774', 'side': 'left'}]

========================================================================
Vector 3: verify_ledger and verify_bundle over the above
========================================================================
verify_ledger ok:
  True
verify_ledger checkpoints_checked:
  3
verify_ledger unpaired / orphan:
  ([], [])
tenant public_key_b64:
  oCg4VLd3nHDsmOf4QLbnBxAcqs9AvHi5TYN5wog7/P8=
epoch signing bytes:
  {"epoch_end":"2026-07-25T12:10:00.000000Z","epoch_index":0,"epoch_start":"2026-07-25T12:00:00.000000Z","root":"23c75bb4da3b8a208ef6af0a905b15e7c09b57c0f38348d935ecf992b816a7c3","tenant_id":"ten_vectors"}
tenant_sig:
  ed25519:RnKheDfQZsOQEZLCvuDUn+xeChcJRXQr0DwJK9AZ53ESzLKJvck1NCXvxP97dDEt7ivhOBv3H8JqoAgqvIwpCA==
verify_bundle ok:
  True
verify_bundle inclusions_checked / epoch_signatures_checked:
  (3, 1)
bundle sha256 (canonical, for comparing your own copy):
  sha256:696084b53ee42d01cb6bfab42827917568c80372e8449c573addbdf70d0db157
after tampering entry seq=2: ok:
  False
after tampering entry seq=2: broken_links:
  [2]
after tampering entry seq=2: bad_checkpoint_signatures:
  [2]

========================================================================
Vector 4: KEY_ROTATED cross-signature
========================================================================
new public_key_b64:
  8QMvHb7FeDe0eFn4tlbYL7LjLGUgFfl+fFkXIMp/+Mc=
new device_id:
  dev_QKFRWZURLZG7U64ZFYA7HAZR7F
cross-signature signing bytes:
  {"new_device_id":"dev_QKFRWZURLZG7U64ZFYA7HAZR7F","new_public_key":"8QMvHb7FeDe0eFn4tlbYL7LjLGUgFfl+fFkXIMp/+Mc=","old_device_id":"dev_XJ3WSKC2GEJ743SW4BQ2BVZ3S2"}
cross_signature (signed by OLD key):
  ed25519:ab2R5CbRbqiUnYB3AMro+Yo+dYsm1I2KUEpPp4baChY102DlJCHVpi0b1rbtXCjeeR4mRxjPEvsmTVcAr885BQ==

========================================================================
Vector 5: Rekor-style receipt over the epoch root (RFC 6962 audit path)
========================================================================
log public_key_b64:
  PZiK7ICqPMfKpIWmRv/nGnc/kMeXdLBtEPcFQVm7D9c=
receipt (flat form verify_rekor_receipt takes):
  {'log_index': 2, 'tree_size': 5, 'root_hash': '76ff9ad2b58a1d488d241123578e5a93fcb8ba4e0067fb774f201f0be412bd93', 'hashes': ['f37cd65fec3c37e67a78de8345cb73ea6f043508f514787c4faf47c72e8f97cb', 'b5bf98edc08e43f96935972d18d0d4263ef7cfdd9b4936e8bfd9bd373439069a', '9754f5c34e0fc2b4bded6ef6e8f87a90a0700441a71db68336eb0fc5a18d73e9'], 'signed_entry_timestamp': 'ed25519:KF4TinVVKqTdnNTWGuUTeotUraNyok2cGfEvwbFKvDnuKRVeiqoOSSRM/Y/M/xm1RN60Lp46r68MChMqoIiSCg=='}
SET signing bytes:
  {"log_index":2,"root_hash":"76ff9ad2b58a1d488d241123578e5a93fcb8ba4e0067fb774f201f0be412bd93","tree_size":5}
verify_rekor_receipt:
  (True, [])
```

What to check with them:

- **Vector 0**: the key order `é`, `😀`, `ﬁ` holds only under UTF-16
  ordering; code-point ordering puts `ﬁ` before `😀`. Also check the float
  forms `1e+21`, `0`, `1e-7` and `1` (from `1.0`).
- **Vector 1**: rebuild each `event_digest` and `entry_hash` from the printed
  canonical bytes, and derive `device_id` from the public key.
- **Vector 2**: three leaves is the smallest case where promoting the odd
  node and duplicating it give different roots. Leaf 2's proof has one step
  because it was promoted at level 0.
- **Vector 3**: changing one payload byte at seq 2 produces a broken link at
  seq 2 only (not 3), and the checkpoint whose `chain_head` is seq 2's entry
  hash fails.
- **Vector 4**: verify the cross-signature with the old public key from
  vector 1.
- **Vector 5**: a five-leaf log with the epoch root at index 2, which
  exercises both branches of the RFC 6962 path walk.
