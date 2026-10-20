# Configuration Reference

Every knob in ByoAI Runtime, by component. Two ways to configure anything:

1. **Declarative dicts** — `Runtime(llm={...}, cache={...}, ...)`. Easiest to
   load from env/JSON/YAML; goes through `byoai/config.py`'s `build_*`
   functions, which `**kwargs`-forward straight into the class below.
2. **Direct objects** — construct the adapter yourself (`OpenAICompatProvider(...)`,
   `RedisCache(...)`, ...) and pass the instance in
   (`Runtime(providers=[...], cache=my_cache, ...)`). Same parameters either way.

Unless noted, every parameter has a default that preserves prior behavior —
nothing here is required to keep working code working.

---

## Runtime

`byoai.Runtime(...)`

| Param | Default | Notes |
| --- | --- | --- |
| `llm` | `None` | Dict: `{"provider": ..., "model": ..., "fallback": {...}}`. See [Providers](#providers). |
| `providers` | `None` | Pre-built `LLMProvider` list instead of/in addition to `llm=`. |
| `cache` | `None` | Dict or `CacheStore` instance. See [Cache](#cache-exact-match). |
| `vector_store` | `None` | Dict or `VectorStore` instance. See [Vector stores](#vector-stores). Building it alone doesn't add retrieval to the default pipeline — see [RAG retrieval in the pipeline](guides/vector-stores.md#rag-retrieval-in-the-pipeline) for wiring in `VectorRetrieve`. |
| `semantic_cache` | `None` | Dict or `SemanticCacheStore` instance. See [Semantic cache](#semantic-intent-cache). Requires `embedder=`. |
| `embedder` | `None` | Dict or async `(str) -> list[float]` callable. Powers `semantic_cache` and `vector_store` retrieval. |
| `retry_policy` | `None` | A `RetryPolicy` shared by the whole provider fallback chain. See [RetryPolicy](#retrypolicy--providerrouter). |
| `selection` | `"ordered"` | Which provider goes first each call — `"ordered"` \| `"round_robin"` \| a callable `(providers) -> providers`. See [RetryPolicy / ProviderRouter](#retrypolicy--providerrouter). |
| `system_prompt` | `None` | Prepended as a system message on every request (via `ContextResolver`). |
| `telemetry` | `None` | Dict (`{"provider": "opentelemetry", "endpoint": ...}`), a pre-built `TracerProvider`, or `None`. See [Telemetry](#telemetry-opentelemetry). |

Exact-match cache write-back TTL is *not* a `Runtime` knob — it's controlled entirely by the
cache itself: `cache={"default_ttl": 3600}` (or the equivalent constructor arg on a pre-built
`CacheStore` instance). Earlier versions had a separate `Runtime(cache_ttl=...)` param that
always overrode `default_ttl` regardless of what the cache was configured with; it's been
removed so there's exactly one place TTL is set. See [Cache](#cache-exact-match).

`Runtime.execute()` / `Runtime.stream()` per-call kwargs: `pipeline`,
`session_id`, `user_id`, `model` (override), `system_prompt` (override —
`None` falls back to the constructor default, `""` clears it for this call),
`filters` (AST dialect for retrieval), plus any `**provider_options`
(`temperature`, `top_p`, ...) — forwarded to the provider and included in the
exact-match cache fingerprint.

`provider_metadata` is a separate kwarg, forwarded into the provider's own
request payload as Anthropic's top-level `metadata` field (`{"user_id": ...}`
for audit correlation on Anthropic's side). Don't confuse it with
`metadata=`, which is app-level (`ExecutionResult.metadata`) and never
reaches the provider. It's Anthropic-shaped, so every non-Anthropic adapter
(`GeminiProvider`, `OpenAICompatProvider` — neither has a `metadata` concept
of its own) drops it rather than forwarding it: a fallback from Anthropic to
one of these degrades (loses the audit tag) instead of failing outright. Only
the other Anthropic-family adapters (Bedrock/Vertex) forward it as-is. It's
also excluded from the exact-match cache fingerprint (unlike the rest of
`provider_options`) since it never changes what answer comes back — tagging
otherwise-identical calls with a different `user_id` doesn't defeat caching.

---

## Console (web UI)

The console lives in `web/` and is built with Vite. It is a read-only UI over
the recorder's shipped evidence; it never writes to a ledger.

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `BYOAI_CONSOLE` | proxy (shell) | `1` | Set to `0` to stop the proxy serving `/console/` at all (a headless deployment that wants only the API). |
| `BYOAI_PROXY_URL` | dev server (shell) | `http://127.0.0.1:8787` | Origin the Vite dev server proxies `/v1` to. Set this when the context-cache proxy runs on another host or port. |
| `VITE_API_BASE` | build/runtime | `/v1/console` | Base path the console calls. Change only if the console API is mounted somewhere other than the proxy's `/v1/console`. |
| `VITE_BYOAI_TENANT` | build time | `default` | Tenant the SPA lands on when a URL names none and it is running without a server redirect (the Vite dev server). Both `byoai-shield-server` and the proxy redirect `/console/` to their own org (`BYOAI_SHIELD_SERVER_ORG`, `BYOAI_CONSOLE_ORG`) before the SPA loads, so a served console never depends on this value. |
| `BYOAI_CONSOLE_ORG` | proxy (shell) | the store's existing tenant, else `default` | The one org slug `/v1/console/*` serves. Any other `tenant` in the query string gets a 404, not that org's data. The public console is single-org (a many-org view is Coriqo's paid MSP console): an install that already has a tenant in its ingest store keeps working unchanged, since nothing on this side creates a second one. Set this only if you need the served slug to be something other than what is already there. |

### Installing Shield

`pip install --pre "byoai-runtime[shield]"` installs what `byoai-shield` needs on top of the base package
(`cryptography`, used to sign the seal chain). Without it the command prints that line and exits, instead of a
traceback. The `all` extra includes it.

### Shield extra origins (extension + dev server)

| Variable | Where | Default | Meaning |
|---|---|---|---|
| `BYOAI_SHIELD_PORT` | shield (shell) | `17831` | Port Shield listens on when `--port` is not given. Chosen to stay clear of common dev ports (Consul 8300, the MCP demo 8800, proxies 8080). If you change it, enter the new address in the extension popup. A value that is not a port number (empty, text, outside 1–65535) is ignored with a one-line message on stderr and the default is used. |
| `byoai-shield --install-login-item` | shield (CLI flag) | *(off)* | Starts Shield at login as you (never root), at low priority, restarting only after a failure with a 30 s back-off. macOS: launchd agent `~/Library/LaunchAgents/com.coriqo.shield.plist`. Linux: systemd user unit `~/.config/systemd/user/coriqo-shield.service`. Windows: Task Scheduler task "Coriqo Shield" (at logon, no elevation). Uses the ledger path and `--port` you pass, made absolute; with no ledger it uses `~/.byoai/shield/captures.jsonl`. `--remove-login-item` undoes it. Windows and Linux paths are generated and unit-tested but have not been run on those systems yet. |
| `BYOAI_SHIELD_EXTENSION_IDS` | shield (shell) | *(unset = any extension)* | Comma-separated list of extension IDs `POST /api/browser` accepts. With it set, every other `chrome-extension://` origin is refused — the popup shows the id to pin (Trust only this extension → Copy id). |
| `CHROMIUM_PATH`, `BYOAI_EXT_TEST_DOWNLOAD`, `BYOAI_PYTHON` | extension tests (`web`, shell) | *(unset)* | The two real-browser tests in `web/tests/extension/` need a Chromium that still honours `--load-extension` (branded Chrome 137+ does not). Point `CHROMIUM_PATH` at one, or set `BYOAI_EXT_TEST_DOWNLOAD=1` to fetch one into `~/.cache/byoai-ext-test`; with neither, the two tests are skipped with a reason, not failed. `BYOAI_PYTHON` names the interpreter with byoai installed (default: `.venv`, then `python3`). |
| `SHIELD_URL` | dev server (shell) | `http://127.0.0.1:17831` | Where the Vite dev proxy finds the shield; also the Origin the proxy claims on its forwarded writes, so Shield's same-origin policy rule holds in dev without extra config. |

The shield hardens every write: `POST /api/browser` requires a
`chrome-extension://` origin (optionally pinned as above; the extension
stamps a `row_id` the server dedupes on, so batch retries can't double-seal),
and `POST /api/policy` requires the request's Origin to name the very
`host:port` the request was addressed to — Shield's own page — so no other
local process can weaken the policy. `POST /api/policy` also refuses (409) a
change to a setting a managed policy has locked, naming who manages it — see
"Managed mode" below.

### The fleet console on one Mac

`byoai-shield` also serves the console's fleet screens (
`http://127.0.0.1:17831/console/<tenant>/fleet`) by answering the same
read-only API the fleet server does (`web/src/api/schemas.ts`), with the
fleet here being exactly one enrolled device: this Mac. Nothing is
configured; the same localhost-Host guard applies, and `tenant` is echoed.

| Endpoint | What this host can honestly answer |
|---|---|
| `GET /v1/console/fleet` | Coverage and liveness from the seal log; **integrity from a fresh walk on every read** — entries re-hashed, checkpoint signature re-checked (the optional `local` block carries the root, so the Integrity panel shows the earned verdict with its evidence); backlog/unsynced only while connected to a fleet server, null otherwise; denial from local verdicts over the loaded ledger window. |
| `GET /v1/console/fleet/devices` | One device row: this Mac's `device_id` and host, agents observed in the ledger (`desktop:claude`, `browser:chatgpt`, `mcp:<client>`), and `null` — never `0` — where only the receiving server knows (batches arrived, ship lag, cadence). |
| `GET /v1/console/fleet/findings` | The seal chain's recorded incidents, mapped onto the console's finding kinds (`chain_broken` → `broken_links`, `checkpoint_mismatch` → `bad_signatures`). An empty list means this read walked everything and it held. |
| `GET /v1/console/verdicts` | The fleet verdict stream (§6.5): every sealed interaction read by outcome — `blocked` → denied, a rule hit that passed → flagged, everything else → allowed — newest first, each with its device·seq address. `enforcement` comes from the live (managed-locked) policy mode, and `observe_flagged` is the "N would have been stopped" count under observe and null under enforcement; `latches` lists surfaces with a repeat denial after the first. Covers what the feed holds in memory (newest 400); older verdicts stay sealed in the ledger, and the page says so rather than letting "showing N" imply full history. |
| `GET /v1/console/fleet/coverage` | The silence report for one device. `unverified_ranges` is empty because the walk is the read; the blind-spot text names the limit: no other machine you run is in any of these numbers. |
| `GET /v1/console/ledger` | The sealed record itself, cursor-paginated (`limit`, `before`). `head()` and `missing_ranges()` are computed over the log by the read that answers the request — a contiguous 1–n ledger is a result here, not a stored claim, and the off-scope gap banner can only stay quiet because the walk that just ran proved there is nothing to show. `sessions` and `trajectories` are `null`: session/trajectory indexes are what a fleet server computes across devices; one Mac answers with its own chain rather than pretending an empty list is an answer it could give. |
| `GET /v1/console/entries/<device_id>/<seq>` | The only endpoint returning payload bodies — a sealed entry addressed by device AND seq (a seq is an address only beside its device): the stored payload verbatim (no message text is ever sealed; the fingerprint is keyed to the device), its Merkle fold path, and whether the signed checkpoint covers the height. The wrong device answers "this host holds no ledger for that device"; a seq beyond the head answers "a sealed entry is never absent" — different facts, shown as such. |
| `GET /v1/console/enrollment` | Who this Mac answers to: device identity + public key + chain state, the connection (org tenant, base_url, enrolled/last-send/next-attempt times normalised from the publisher's own state, unsent entries only while connected, the refused-device flag), the effective sharing disclosure (invariant 4 — named in plain words whenever activity may leave, computed from the level the managed merge actually produced: a hand-edited local `sync` is already collapsed back to `seal` and cannot open a hole here), the managed summary, and a disk-read "what this device keeps" block (ledger rows, rows still carrying text, real file paths) that proves the privacy-first claim by counting rather than asserting. |

Implemented in `src/byoai/integrations/shield_console.py` beside the rules
it follows; `byoai.console.router` is the fleet-server side of the same
contract.

### Shield policy `actions` and desktop app toggles

`GET|POST /api/policy` on `byoai-shield` (and a managed policy from a server) carry an `actions` map. The global `mode` stays the master switch: `observe` logs every hit, and `redact` and `block` both use the table.

| Key | Values | Default | What it does |
|---|---|---|---|
| `actions.secret` | `block` `warn` `redact` `log` | `block` | API keys and tokens, private keys, JWTs, database URLs with passwords, Luhn-valid card numbers. Was replaced before; a detected secret now stops the send (`403`) in the default mode. |
| `actions.pii` | same | `redact` | Emails, phone numbers, SSNs, IBANs, wallet addresses, replaced by numbered placeholders (`[EMAIL_1]`). |
| `actions.flag` | same | `log` | Conduct and intent rules. `executable_masquerade`, `tool_intent` and `password_said` are log-only. |

The strictest action of all hits wins (`block > warn > redact > log`). `credential_assign` always warns unless its tier is set stricter. An unknown value falls back to the tier default; a write with a bad key or value is refused. A write that lowers a tier (or sets `observe`, or `keep_text`) must carry `"acknowledge": "less_private"`.

`warn` shows a bar in the browser extension (*Send redacted*, *Send anyway*, *Cancel*; 60 s without an answer cancels). From extension 0.10.0 the same policy is applied by an input gate that checks the message (Enter, the send button, a form submit) and files (a picked file, a drop, a paste) as the user hands them to the page, on claude.ai, chatgpt.com, gemini.google.com and copilot.microsoft.com, with the network wrapper as the backstop. The gate needs no setting. Where each app's message box, send button and file input are is data in `src/byoai/browser_extension/sites.json` (the gate falls back to any focused `textarea` or `contenteditable` and any `send` button); after editing it run `python scripts/gen_extension_rules.py`, which also rewrites `shield-sites.js`, and a test fails if that file is stale. Browser rows for sends and files carry `stage` (`input` or `network`) and, when the gate decided the send, the same `gate_id` on both. The desktop proxy has no UI inside another app, so `warn` behaves as `redact` there.

New desktop-proxy app toggles, all **off** by default and turned on in Shield's Settings or `apps` in the policy: `github_copilot`, `mistral`, `deepseek`, `groq`, `openrouter`, `together`, `gemini_api`. Their request fixtures come from public API documentation and are untested against live traffic. Hosts match exactly or on a dot boundary. Cursor, Windsurf and Perplexity are not covered.

Health rows (no text, no body): `browser.health.unmatched` and `desktop.health.unmatched` (host or app and a path prefix of at most 60 characters, after three unrecognised send-looking POSTs in ten minutes with none inspected).

#### Shield file evidence: `files` policy, attachment rows and `byoai shield check-file`

`files` maps an app name to `allow`, `warn` or `block` (default `allow` for every app; unknown apps and values are refused on write and read as `allow` from disk). It applies to every file uploaded to that app. A write that lowers an app (`block` to `warn` or `allow`, `warn` to `allow`) must carry `"acknowledge": "less_private"`. It is served in `GET /api/policy` and is not one of the managed lockable keys yet. `mode: observe` records files and stops none.

Text-like files (extensions `.txt .csv .tsv .json .jsonl .md .log .env .ini .cfg .conf .yaml .yml .xml .sql .py .js .ts .go .java .rb .sh .pem .key`, or a `text/*` type) up to 5 MB are decoded as UTF-8 (lossy; UTF-16 with a byte-order mark is decoded as UTF-16) and run through the same rules and `actions` as a message. The file's action is the strictest of its `files` setting and the rule actions, with `redact` counted as `warn` because files are never rewritten. Anything else is not read (`scanned: false`) and only `files` applies. A text file renamed to `.bin` is therefore not read. Two more cases count as text: a declared type of JSON, XML, YAML, shell or a certificate/key format (`application/json`, `+json`, `*yaml*`, `*x509*`, `*pem*`, `application/x-sh`) whatever the file is called; and a bare, nameless upload to a known storage endpoint (ChatGPT's pre-signed PUT) of up to 5 MB that decodes as UTF-8 or UTF-16. UTF-16 without a byte-order mark is recognised when over 30% of the bytes at one parity are zero. A browser row that says `scanned: false` for a text type of a size the rules read is recorded as scanned, and `byoai shield check-file` reports `rules reproduce: no` for such a record. When a record says the rules read the file, `check-file` decides whether it is text by its content (valid UTF-8 or UTF-16 up to 5 MB), not by what the copy is called; `--name <original name>` passes the original name instead.

Desktop proxy: a POST or PUT with a `multipart/form-data` body that has at least one file part (every file part is hashed on its exact bytes; a form with no file part is not an upload) or a body sent to an upload path (`/files`, `/upload`, `/uploads`, `/attachments`, any content type or none, unless it parses as a JSON object or array, which is metadata) is inspected; any PUT or POST with a body to `*.oaiusercontent.com` counts; ChatGPT's pre-signed PUT of the file itself (`*.oaiusercontent.com`, `/files/<id>/raw`) counts too, and a JSON body on `/backend-api/files` (metadata) does not. `warn` and `block` both refuse it with the usual `403` (`coriqo_shield_blocked`); the proxy has no place to ask. The host list gains `*.oaiusercontent.com` (app `chatgpt`, uploads only). Multipart parts may end their lines with CRLF or a bare LF. Every file part is read and counted against the policy, but only 32 get a row each; the rest share one row (hash of their bytes together, combined flags, `flag:too_many_files`).

Browser extension (0.9.0): an upload is a `FormData` with a file entry on any path, or a file body on claude.ai `.../wiggle/upload-file` or a PUT to `*.oaiusercontent.com/files/<id>/raw` (sent by ChatGPT over `XMLHttpRequest`, which the extension wraps for uploads only). The file is hashed (SHA-256) and, if text-like and up to 5 MB, scanned in the page with the same rules and `actions`. `block` stops it with the usual `403` (an XHR ends with `error` and `loadend`); `warn` shows a bar with *Remove file* (the upload fails like a network error), *Upload anyway* and *Cancel*, and 60 s without an answer cancels. From 0.9.1, when a file is stopped, removed or cancelled the page also shows a short notice that it wasn't uploaded, because the chat app may still show it as attached. `mode: observe` only records. In the browser a string, `URLSearchParams` or `Document` body on those endpoints is read as bytes; a stream (which cannot be read without using it up) is recorded as not scanned and follows the file policy; a `fetch(Request)` is read from a clone; a `FormData` is copied before it is checked and the copy is sent. A synchronous XHR upload and `navigator.sendBeacon` cannot wait for a hash: a synchronous XHR follows only the file policy (`block` and `warn` throw `NetworkError`, and the row says not scanned), and `sendBeacon` returns `false` under `block`, otherwise it is checked and sent when the check ends. A refused XHR upload ends with readyState 4, status 0 and `readystatechange`, `error`, `loadend`. The browser row also carries the raw `name`, which Shield hashes and drops; see the extension's PRIVACY.md.

`desktop.chat.attachment` and `browser.chat.attachment` rows carry:

| Field | Meaning |
|---|---|
| `app`, `mime`, `bytes` | app, declared type, size in bytes |
| `sha256` | lowercase hex SHA-256 of the file's bytes; equals `shasum -a 256 file` |
| `name_hash` | keyed HMAC of the file name (`hmac-sha256:...`, the same keyed fingerprint as message text). The name itself is never stored. |
| `scanned` | `true` if the rules read the file |
| `flags` | `tier:rule` for each rule that matched (`secret:aws_access_key`), never the matched text |
| `rules_version` | first 12 hex of SHA-256 over the canonical JSON of the rules object in `shield-rules.js`; the file carries it as `rules_version` and Python exposes `byoai.integrations.shield.RULES_VERSION` |
| `verdict` | `allowed`, `blocked`, and for the browser `warned→uploaded`, `warned→removed`, `cancelled` |

Rows with a `sha256` appear in the feed and are sealed with a `file` object (`mime`, `bytes`, `sha256`, `name_hash`, `scanned`, `rules_version`) in the sealed payload. The browser ingest endpoint accepts a raw `name` and stores only its `name_hash`. `sha256` and `name_hash` stay on the device: the sync event schema is an allowlist and carries neither at any level (`seal`, `daily`, `events`).

`byoai shield check-file <path> [--row ID] [--ledger PATH] [--key-dir DIR]` checks a produced file against the sealed record (`--row` is an interaction id or seal; without it, the latest sealed file record with the same SHA-256). It prints `hash: match|different`, `rules reproduce: yes|no` (or `n/a` for a file that was not scanned, or `cannot check` when the record's `rules_version` differs from this install), and `seal verifies: yes|no`. Exit status is `0` only when every applicable check passes, `2` for a bad path or unknown row. The command needs the `shield` extra.

What is scanned: every string in the request body except id-like keys (`id`, `*_id`, `uuid`, `model`, `signature`, media types) and base64 payloads, so system prompts, tool results, tool inputs and document text count as much as the typed message. Secret rules always scan the whole body; personal-detail and flag rules scan the first and last 1,000,000 characters of a body over 2,000,000 and add `flag:oversize`. A private key block is replaced whole when its END line follows within 8 KB; otherwise the send is still stopped on the header. In the extension, policy and warn answers travel over a private channel set up before the page's own scripts run, so the page can't lower the policy or answer the warn bar itself; with no live channel a held send is redacted, never sent as typed.

### Shield guard for your own chat app (`byoai-cache`)

| Variable | Default | What it does |
|---|---|---|
| `BYOAI_SHIELD_GUARD` | `off` | `off`, `observe` (check and record, forward as sent) or `enforce` (block or redact). Applies to `/v1/messages`, `/v1/chat/completions` and `/v1/responses`. |
| `BYOAI_SHIELD_POLICY` | Shield defaults | Path to a Shield policy file (same format as `byoai-shield`: `mode`, `actions`). A missing file means the privacy-first defaults. |
| `BYOAI_SHIELD_ON_WARN` | `block` | `block` or `redact`. A `warn` hit (for example `credential_assign`) has nobody to ask on a server; `redact` rewrites it when a placeholder exists, otherwise it still blocks. |
| `BYOAI_SHIELD_OPENAI_UPSTREAM` | `https://api.openai.com` | Where guarded OpenAI-shaped requests go. With the guard `off` those paths keep the old passthrough. |
| `BYOAI_SHIELD_APP` | none | A Shield app name (for example `claude`). When set, the policy's per-app `files` setting applies to files. Middleware: `app_name=`. |
| `BYOAI_SHIELD_KEY_PATH` | Shield's own key | Fingerprint key file for `text_hmac`. |

With the guard on, every body-carrying request is checked, not only chat paths: `gzip`/`deflate` bodies are decoded, other `Content-Encoding`s and undecodable bodies get the `403` (`unreadable`), and a non-JSON body (multipart, binary) is scanned as text for secrets only: clean passes byte-for-byte, a secret blocks, personal details are never rewritten. `observe` and `off` forward the original bytes and headers; only `enforce` changes a body (a redacted or repeated-key JSON body is sent decoded, without `Content-Encoding`). The policy file is re-read only when it changes, and checks run in a worker thread. A blocked decision carries no body; the middleware keeps only its last 100 decisions (rules, labels, length, fingerprint).

A blocked request gets `403` with `type: coriqo_shield_blocked`, `rules` and `labels` (Anthropic: `{"type":"error","error":{...}}`; OpenAI: `{"error":{"message","type","code":"shield_blocked",...}}`). The secret tier blocks by default, so a policy with `mode: observe` never stops anything. Recorder rows are kind `shield_guard`: `guard_mode`, `provider`, `path`, `action`, `forwarded`, `redacted`, `rules`, `chars`, `text_hmac`, `rules_version`. The Python middleware is `byoai.shield_guard.fastapi.ShieldGuardMiddleware(app, *, paths=, policy=, mode=, on_warn=, max_body=, key_path=, app_name=)`; a body over `max_body` (8 MB) is refused.

### Shield managed mode

Once enrolled with Coriqo, Shield can be put into managed mode: a Coriqo
tenant sets policy centrally and it lands on every enrolled device, without
touching each Mac. This is state, not an env var — nothing here needs to be
set by hand.

| Where | What |
|---|---|
| `~/.byoai/shield/managed_policy.json` | The last accepted signed policy envelope from Coriqo (private, atomic write). Absent = never managed. A signed `policy: null` document unmanages the device but is kept here so a replayed older envelope is still refused as a rollback. |
| `enrollment.json` (`policy_key`) | The Ed25519 key Coriqo signs policy envelopes with, pinned once at enrolment (`{key_id, public_key}`). Absent (state written before managed mode, or the server didn't send one) falls back to fetching `GET /api/v1/checkpoints/public-keys` once and pinning the entry matching the first envelope's `key_id`. |
| `sync` (policy key) | What Coriqo may receive about activity: `seal` (default: the seal only, no activity), `daily` (per-day totals per app) or `events` (one row per message: app, time, length, verdict, rule ids). Never message text, a preview, a matched snippet or a text fingerprint, at any level. Lockable like the other keys; only a signed managed policy moves it, and a local Settings edit cannot. Above `seal`, Shield sends activity to `POST /v1/shield/events` after the checkpoint that covers it, on its own retry state (never slows the seal), and only what happens after sharing was turned on; the wire format is in [docs/shield-sync-protocol.md](docs/shield-sync-protocol.md). `GET /api/coriqo` reports `sync: {pending, last_sent_at, last_error}`. |
| `GET /api/policy` → `sharing` | `{level, by, since, words}` whenever a managed policy names an organisation or `sync` is above `seal`. `words` is the plain-language description the Settings banner shows; it cannot be hidden by policy. |
| `GET /api/policy` → `managed` | `{by, version, locked, fetched_at, error}` when this device has ever been managed; omitted otherwise. `error` is the last poll/verify failure (network, bad signature, wrong tenant/device, rollback, unknown key) — the previous good policy is kept, never cleared, on any of these. |

Polling (`POST /v1/shield/policy`, signed the same way as the checkpoint
post) runs every 10 minutes, at Shield's start, and once more whenever "Send
now" is used — on the same background thread as checkpoint publishing, never
blocking capture.

Commands, run from `web/`:

| Command | Does |
|---|---|
| `npm run dev` | Dev server on `http://localhost:5174/console/` (Shield at `/shield`), with the MSW mock API enabled. |
| `npm run build` | Type-checks and builds to `src/byoai/console_static/`, served by the proxy under the `/console/` base path and shipped inside the wheel. |
| `npm run typecheck` | TypeScript only. |
| `npm test` | Vitest — includes tests asserting the API contract in `web/src/api/schemas.ts` is enforced rather than coerced. |

**Serving it in production.** The context-cache proxy serves the built console
at `http://localhost:8787/console/`, including client-side routes on a hard
refresh, behind the same `BYOAI_PROXY_TOKEN` gate as the API. A `pip install`
gets the assets prebuilt in the wheel; a **source checkout does not — run
`npm --prefix web run build` first**, or `/console/` returns `503` naming that
command instead of a blank page.

**Mock data.** With no ingest backend yet, `npm run dev` serves a deterministic
40-device fixture fleet through MSW. Responses are validated against the same
zod schemas that will validate real ones, so a contract drift surfaces as a
visible error rather than a silently empty screen.


## Ingest read model

`byoai.ingest.IngestStore(path)` — a SQLite store of evidence shipped by
recorder devices. No environment variables; the database path is the only
configuration.

| Call | Does |
|---|---|
| `record_enrolment(Enrolment)` | Binds a device to a tenant. The **only** place tenancy is set — batches carry no tenant identifier, so it is never read off a request. Refuses a `device_id` not derived from its public key, and refuses re-enrolling a device into a different tenant. |
| `accept_batch(device_id, entries)` | Persists an authenticated batch. Dedupes per device (redelivery is at-least-once by design), refuses unknown or revoked devices, and rejects malformed wire data with `MalformedEntry` rather than coercing it. |
| `accept_checkpoints(device_id, checkpoints)` | Same guards. A checkpoint records contact but is deliberately **not** counted as evidence of liveness. |
| `devices(tenant_slug)` | One row per enrolled device with its observed state. |
| `coverage(tenant_slug)` | The silence report: `never_seen`, `contact_without_evidence`, `reporting`, `devices_without_checkpoint`, `seq_gaps`, and a `blind_spot` naming the limit of the claim. |

Typed refusals — `UnknownDeviceError`, `DeviceRevoked`, `EnrolmentRefused`,
`MalformedEntry`, `SeqConflict`, `CheckpointConflict`, `EntryHashCollision` —
are importable from `byoai.ingest` itself, so a caller can map each to its own
response rather than treating every failure alike.

**Not a trust boundary on its own.** The store assumes the caller authenticated
the device and verified the batch signature. It also takes a tenant slug on
trust, so enrolment authorization must be enforced above it.

## Self-hosted Shield server — `byoai-shield-server`

A free, self-hosted, single-org control plane speaking the exact same wire
protocol Coriqo's managed mode does, so
`byoai.integrations.shield_publish.Publisher` enrols and polls it with no
code changes. `byoai.shield_server.create_app(config)` builds the FastAPI
app; the console script wraps it. Install with
`pip install --pre 'byoai-runtime[shield-server]'`.

| Var | Default | Meaning |
|---|---|---|
| `BYOAI_SHIELD_SERVER_DATA` | `~/.byoai/shield-server/` | Data directory: two SQLite databases, the Ed25519 signing key, and the admin token (0700 dir, 0600 files). |
| `BYOAI_SHIELD_SERVER_HOST` | `127.0.0.1` | Bind address. |
| `BYOAI_SHIELD_SERVER_PORT` | `17840` | Bind port. Deliberately not 17831 (`byoai-shield`'s own local port). |
| `BYOAI_SHIELD_SERVER_PUBLIC_URL` | `http://127.0.0.1:17840` | Returned to devices at enrolment as `coriqo_base_url`. Put a reverse proxy in front and set this to its `https://` address before any device outside this host enrols — the enrolment token and every signed request cross the network in the clear otherwise. |
| `BYOAI_SHIELD_SERVER_ORG` | `default` | The single tenant slug this server serves. Enrolment always binds to it (a second org can't be created through this server), and `/v1/console/*` answers 404 for any other `tenant` in the query string — a many-org fleet view is Coriqo's paid MSP console, not this free server's job. |
| `BYOAI_SHIELD_SERVER_ADMIN_TOKEN` | generated on first run, saved 0600, printed once | Bearer token for the admin API (`/api/v1/shield/*`, `/v1/console/*`) and the console. Setting this env var yourself skips generation and file storage. |

CLI (`byoai-shield-server <command>`):

| Command | Does |
|---|---|
| `serve` | Runs the server (uvicorn) on `BYOAI_SHIELD_SERVER_HOST`/`_PORT`. Prints the admin token once, on the run that generates it. |
| `mint-token [--label L] [--ttl-seconds N]` | Mints a single-use enrolment token, printed once (only its hash is stored). |
| `admin-token` | Prints the current admin bearer token (generating one first if none exists yet). |

Device routes (unauthenticated by design, or device-signed — see
`byoai.recorder.shipper.post_signed_batch` for the signing scheme):
`POST /v1/enroll`, `POST /v1/checkpoints/batch`, `POST /v1/shield/policy`,
`GET /api/v1/checkpoints/public-keys`.

Admin routes (`Authorization: Bearer <admin token>`, constant-time compare):
`POST|GET|DELETE /api/v1/shield/tokens[/{token_id}]` (a short, non-secret
12-hex-char id — never the full token hash),
`GET /api/v1/shield/devices`, `DELETE /api/v1/shield/devices/{id}`,
`GET|PUT|DELETE /api/v1/shield/policy`,
`GET|PUT|DELETE /api/v1/shield/devices/{id}/policy`,
`GET /api/v1/shield/policy/drift` (devices whose reported policy version
doesn't match what they're assigned, wrapped as `{devices: [...]}`),
`GET /api/v1/shield/info` (`{public_url, org, key_id}`, what the Enrol page
shows), and the read-only fleet console API (`/v1/console/*`) mounted behind
the same token. The built console is served at `/console/` (see "Console
(web UI)" above for the build step) with a Shield section at
`/console/<org>/shield-server/{devices,policy,enrol}`.

`GET`/`PUT`/`DELETE /policy` and `/devices/{id}/policy` return the signed
envelope as stored, `{document, signature}` (or `null` if nothing has ever
been set for that key) — not a flattened view. `PUT` takes the policy fields
flat at the top level plus `managed_by` and `locked`:
`{mode, apps, keep_text, retention_days, notice, managed_by, locked}`.

Security floor: binds `127.0.0.1` by default, caps request bodies at 16 MiB,
and never receives message text — only checkpoints and the `shield` state
block, the same boundary Coriqo's managed mode keeps.

## Providers

One shared HTTP plumbing layer (`byoai/providers/base.py`):

- `DEFAULT_RETRYABLE_STATUS = {408, 409, 500, 502, 503, 504}` — the default
  retry-eligible status set; every adapter accepts `retryable_status=` to
  override it per-instance.
- `build_openai_client(...)` — shared client/header/api-key construction for
  the OpenAI-compatible family (chat + embeddings).
- `raise_for_status(...)` — shared 429→`RateLimitError` / other→`ProviderError`
  classification.

### `OpenAICompatProvider` — OpenAI, Azure, Ollama, vLLM, OpenRouter, LiteLLM, any `/chat/completions`-shaped endpoint

| Param | Default | Notes |
| --- | --- | --- |
| `model` | required | |
| `api_key` | `None` → `$OPENAI_API_KEY` | |
| `base_url` | `https://api.openai.com/v1` | Point at any compatible deployment. |
| `name` | `"openai"` | Shows up in events/errors/telemetry as `gen_ai.system`. |
| `timeout` | `60.0` | Single httpx timeout (connect+read+write+pool). For split timeouts, build your own `httpx.AsyncClient` and pass `client=`. |
| `default_headers` | `None` | Merged into every request (auth proxies, org routing). |
| `client` | `None` | Pre-built `httpx.AsyncClient` — bypasses `api_key`/`base_url`/`timeout`/`default_headers` entirely; you own its lifecycle (`Runtime.close()` only closes clients the provider built itself). |
| `chat_path` | `"/chat/completions"` | For gateways that mount the route elsewhere. |
| `retryable_status` | `None` → `DEFAULT_RETRYABLE_STATUS` | Per-instance override. |

Declarative: `llm={"provider": "openai"|"ollama"|"openrouter"|"openai_compatible"|"vllm"|"litellm", ...}`.
`ollama`/`openrouter` set sensible `base_url`/`api_key` defaults (still overridable);
`openai_compatible`/`vllm`/`litellm` require `base_url` explicitly.
`azure_openai` is handled specially in `config.py` (`endpoint`, `deployment`,
`api_version`, default `"2024-06-01"`, all overridable).

### `AnthropicProvider`

| Param | Default | Notes |
| --- | --- | --- |
| `model` | required | |
| `api_key` | `None` → `$ANTHROPIC_API_KEY` | |
| `base_url` | `https://api.anthropic.com` | |
| `name` | `"anthropic"` | |
| `timeout` | `60.0` | |
| `max_tokens` | `4096` | Default per-request cap; overridable per-call via `max_tokens=` in `execute()`. |
| `client` | `None` | Same semantics as above. |
| `api_version` | `"2023-06-01"` | The `anthropic-version` header — override when Anthropic ships a new API surface you want. |
| `default_headers` | `None` | e.g. `{"anthropic-beta": "prompt-caching-2024-07-31"}`. |
| `retryable_status` | `None` → `DEFAULT_RETRYABLE_STATUS | {529}` | 529 = Anthropic's "overloaded". |
| `messages_path` | `"/v1/messages"` | |
| `cache_system` | `False` | When `True`, a plain-string system prompt is wrapped in a `cache_control: {"type": "ephemeral"}` block so repeated calls with the same prompt hit Anthropic's server-side prompt cache. Has no effect if you already built your own system content blocks by hand (see [Provider routing & fallback](guides/providers.md#anthropic-tool-use-and-content-blocks)). |

Declarative: `llm={"provider": "anthropic", ...}`.

### `AnthropicBedrockProvider` / `AnthropicVertexProvider`

Unlike every other adapter, these depend on the `anthropic` SDK (`bedrock`/`vertex` extras) —
Bedrock's AWS SigV4 signing and Vertex's GCP OAuth service-account auth aren't reasonable to
hand-roll with raw `httpx`. Message translation and error classification (`raise_for_status()`
against the SDK's own `httpx.Response`) stay identical to every other provider.

| Param | Default | Notes |
| --- | --- | --- |
| `model` | required | |
| `name` | `"bedrock"` / `"vertex"` | |
| `max_tokens` | `4096` | |
| `client` | `None` | Pre-built `AsyncAnthropicBedrock`/`AsyncAnthropicVertex` — bypasses every other constructor param below. |
| `retryable_status` | `None` → `DEFAULT_RETRYABLE_STATUS | {529}` | |
| `cache_system` | `False` | Same as `AnthropicProvider.cache_system` above. |
| **Bedrock only** | | |
| `aws_region` | `None` → `$AWS_REGION` or `$AWS_DEFAULT_REGION` | Required (directly or via env). |
| `aws_access_key`, `aws_secret_key`, `aws_session_token`, `aws_profile` | `None` | Falls back to the standard AWS credential chain (env vars, `~/.aws`, instance/task role) when all unset. |
| **Vertex only** | | |
| `project_id` | `None` → `$ANTHROPIC_VERTEX_PROJECT_ID` or `$GOOGLE_CLOUD_PROJECT` | Required (directly or via env). |
| `region` | `None` → `$ANTHROPIC_VERTEX_REGION` or `$CLOUD_ML_REGION` | Required (directly or via env). |
| `access_token`, `credentials` | `None` | Falls back to Application Default Credentials when unset. |

Declarative: `llm={"provider": "bedrock", "model": "...", "aws_region": "..."}` /
`llm={"provider": "vertex", "model": "...", "project_id": "...", "region": "..."}`.

### `GeminiProvider`

| Param | Default | Notes |
| --- | --- | --- |
| `model` | required | |
| `api_key` | `None` → `$GEMINI_API_KEY` or `$GOOGLE_API_KEY` | |
| `base_url` | `https://generativelanguage.googleapis.com/v1beta` | |
| `name` | `"gemini"` | |
| `timeout` | `60.0` | |
| `client` | `None` | |
| `default_headers` | `None` | |
| `retryable_status` | `None` → `DEFAULT_RETRYABLE_STATUS` | |

Declarative: `llm={"provider": "gemini", ...}`.

### `OpenAICompatEmbedder` — powers `semantic_cache`/`vector_store` retrieval

| Param | Default | Notes |
| --- | --- | --- |
| `model` | required | |
| `api_key`, `base_url`, `name`, `default_headers`, `client` | same as chat adapter | `base_url` default is OpenAI's; point elsewhere for Ollama/vLLM embeddings. |
| `timeout` | `30.0` | |
| `embeddings_path` | `"/embeddings"` | |
| `retryable_status` | `None` → `DEFAULT_RETRYABLE_STATUS` | |
| `max_batch_size` | `None` (no chunking) | Transparently splits `embed_batch()` calls larger than this into multiple requests — set to your provider's cap (e.g. OpenAI: 2048) for bulk ingestion jobs. |

Declarative: `embedder={"provider": "openai"|"ollama"|"openai_compatible"|"vllm"|"litellm", ...}`.

`embed_batch()` reorders the response by each item's own `"index"` field rather than trusting
response order, so a backend that returns vectors out of request order can't silently mismatch a
vector to the wrong input text; falls back to response position when `"index"` is absent.

### `RetryPolicy` / `ProviderRouter`

```python
@dataclass
class RetryPolicy:
    max_retries: int = 2
    base_delay: float = 0.5
    max_delay: float = 10.0
    jitter: float = 0.25
```

One `RetryPolicy` applies to every provider in a fallback chain (retries
happen per-provider before moving to the next). Status-code retry
classification is per-adapter (`retryable_status=`, above), not on
`RetryPolicy` — that's a deliberate separation: backoff shape is
provider-agnostic, retry *eligibility* is provider-specific (Anthropic's 529
isn't the same concept as an OpenAI-compatible gateway's custom codes).

`llm={"provider": ..., "fallback": {"provider": ..., "fallback": {...}}}`
chains up to 10 tiers deep — a fixed safety rail (not a config knob) against
infinite/mistaken fallback loops; construct `providers=[...]` directly with
`ProviderRouter` if you genuinely need more.

`selection=` (also `ProviderRouter(selection=...)`) picks the order providers
are tried each call — a fallback walks whatever `selection` returned in full
on failure, so the two presets below (pure reordering) never skip a
provider; a custom callable that also filters (e.g. dropping providers it
considers unhealthy) does exclude them for that call, by its own choice:

| Value | Behavior |
| --- | --- |
| `"ordered"` (default) | Always try `providers` in the order given — identical to the router's original fixed-primary/fallback behavior. |
| `"round_robin"` | Rotates the starting provider each call, so load spreads across providers instead of always preferring the first. |
| `(providers) -> providers` | A bare callable — returns the providers to try, in order, for this call (e.g. weighted selection); may also filter, at the cost of the "nothing skipped" guarantee above. |

---

## Cache (exact-match)

### `MemoryCache`

| Param | Default | Notes |
| --- | --- | --- |
| `namespace` | `"byoai:"` | Key prefix. |
| `default_ttl` | `3600` | Seconds; explicit `ttl=` per-call overrides. `None` disables expiry, `<=0` disables caching entirely (nothing is stored) — the only place TTL is set (there is no separate `Runtime`-level TTL knob). |
| `session_reader` | `None` | `{"pattern": "app:{user_id}:history"}` — read-only key-pattern mapping onto existing app state. |
| `session_data` | `None` | Dev/test stand-in for the "existing app state" `session_reader` reads. |
| `max_size` | `None` (unbounded) | Caps entry count; oldest (by last write) evicted first. |
| `url` | — | Not a `MemoryCache` param — passing it (e.g. left over from switching `provider` from `"redis"` to `"memory"`) raises `ConfigurationError` instead of being silently ignored. |

### `RedisCache` / Redis-backed everything

`make_redis_client(url, mode, sentinels, service_name, **client_kwargs)` is
the shared factory behind `RedisCache`, `RedisSemanticCache`, and
`RedisStreamQueue` — all three accept the same connection-level params:

| Param | Default | Notes |
| --- | --- | --- |
| `url` | `redis://localhost:6379` | |
| `mode` | `"standalone"` | `"standalone"` \| `"cluster"` \| `"sentinel"`. |
| `sentinels` | `None` | Required for `mode="sentinel"`: `[(host, port), ...]`. Passing it with any other `mode` raises `ConfigurationError` instead of silently connecting without it. |
| `service_name` | `None` | Required for `mode="sentinel"`. Same fail-fast as `sentinels` above. |
| `client` | `None` | Pre-built client — bypasses `url`/`mode`/`sentinels`/`service_name`/`**client_kwargs`. |
| `**client_kwargs` | — | Forwarded to redis-py: `socket_timeout`, `socket_connect_timeout`, `retry_on_timeout`, `health_check_interval`, `ssl`, `ssl_ca_certs`, etc. |

`RedisCache`-specific: `namespace="byoai:"`, `session_reader`, `default_ttl`
(same semantics as `MemoryCache`).

Declarative: `cache={"provider": "redis"|"valkey", ...}` (Valkey is
protocol-compatible — same adapter, same knobs).

---

## Semantic (intent) cache

### `MemorySemanticCache`

| Param | Default | Notes |
| --- | --- | --- |
| `capacity` | `10_000` | Ring buffer size; oldest entries evicted on overflow. |
| `ttl` | `3600` | Seconds; `None` = no expiry, `<=0` = don't store. |
| `metric` | `"cosine"` | `"cosine"` \| `"dot"` \| `"euclidean"` \| a callable `(matrix, vector) -> scores`. `"cosine"` normalizes vectors at insert/query time; the others use raw vectors. The `threshold` guidance below (0.85-0.95+) assumes `"cosine"`. |

### `RedisSemanticCache` — shared across workers, survives restarts

All `RedisCache` connection params (`url`/`mode`/`sentinels`/`service_name`/
`client`/`**client_kwargs`), plus:

| Param | Default | Notes |
| --- | --- | --- |
| `stream` | `"byoai:semcache"` | The backing Redis Stream key. |
| `capacity` | `10_000` | Both the local numpy mirror's size and the stream's `XTRIM MAXLEN` bound. |
| `ttl` | `3600` | Same semantics as `MemorySemanticCache`. |
| `metric` | `"cosine"` | Same as `MemorySemanticCache.metric` — forwarded to its local mirror, which does the actual scoring. |
| `approximate_trim` | `True` | `False` = exact `XTRIM MAXLEN` (costlier) instead of `~` approximate trimming. |

`SemanticCacheLookup` stage (what `Runtime` wires up):

| Param | Default | Notes |
| --- | --- | --- |
| `threshold` | `0.92` (`stages.DEFAULT_SEMANTIC_THRESHOLD`) | Similarity floor (assumes the default `"cosine"` metric; other metrics need a different scale — see `metric` above). Also settable via `semantic_cache={"threshold": ...}`. 0.95+ conservative, <0.85 risks off-topic hits. |

Declarative: `semantic_cache={"provider": "memory"|"redis"|"valkey", "threshold": 0.92, ...}`.

---

## Vector stores

### `PgVectorStore`

| Param | Default | Notes |
| --- | --- | --- |
| `dsn` | `None` | Required unless `pool=` given. |
| `table` | required | Existing table name (validated as a safe SQL identifier). |
| `schema_map` | `DEFAULT_SCHEMA_MAP` | `{"id": ..., "embedding": ..., "content": ..., "metadata": ...}` — zero-migration column mapping. |
| `metric` | `"cosine"` | `"cosine"` (`<=>`) \| `"l2"` (`<->`) \| `"inner_product"` (`<#>`) — must match the table's actual index operator class (`vector_cosine_ops`/`vector_l2_ops`/`vector_ip_ops`) or pgvector silently falls back to a sequential scan. `Document.score` is always "higher = more similar" regardless. |
| `pool` | `None` | Pre-built `asyncpg.Pool` — bypasses `dsn`/pool sizing/`**pool_kwargs`. |
| `min_pool_size` / `max_pool_size` | `1` / `5` | |
| `command_timeout` | `None` | Per-query timeout in seconds. |
| `**pool_kwargs` | — | Forwarded to `asyncpg.create_pool`: `server_settings={"statement_timeout": "..."}`, `ssl=...`, `max_inactive_connection_lifetime=...`, etc. |

### `QdrantVectorStore`

| Param | Default | Notes |
| --- | --- | --- |
| `url` | `http://localhost:6333` | |
| `collection` | required | |
| `api_key` | `None` | |
| `schema_map` | `{}` | `{"content": field_name, "metadata": field_name_or_None}`; `metadata: None` = whole payload. |
| `timeout` | `30.0` | |
| `client` | `None` | |
| `with_vectors` | `False` | Return embeddings on `Document.embedding`. |
| `score_threshold` | `None` | Server-side similarity floor, applied before `top_k`. |
| `search_params` | `None` | Raw Qdrant search params, e.g. `{"hnsw_ef": 128, "exact": False}` (recall/latency tradeoff). |

### `PineconeVectorStore`

| Param | Default | Notes |
| --- | --- | --- |
| `host` | required unless `client=` given | Index data-plane host from the Pinecone console. |
| `api_key` | `None` → `$PINECONE_API_KEY`, required unless `client=` given | |
| `namespace` | `""` | |
| `schema_map` | `{}` | `{"content": metadata_field_name}` (Pinecone stores text in metadata). |
| `timeout` | `30.0` | |
| `client` | `None` | |
| `include_values` | `False` | Return embeddings on `Document.embedding`. |
| `sparse_vector` | `None` | Fixed `{"indices": [...], "values": [...]}` for hybrid dense+sparse search. |

Declarative: `vector_store={"provider": "pgvector"|"postgres"|"postgresql"|"qdrant"|"pinecone", ...}`.

All three vector stores share the cross-provider AST filter dialect
(`byoai.vector.filters`) — `filters={"field": {"$eq": ...}}` compiles to each
backend's native query form; see `filters.py` for the full operator set.

---

## Pipeline stages

Constructor knobs on the built-in stages (`byoai/stages.py`), reachable by
building your own `Pipeline` — the declarative `Runtime(...)` path uses their
defaults except where noted.

`Pipeline.remove(stage_type)`/`.replace(stage_type, replacement)` match every stage of that type —
`add()` wraps every bare function in the same `FunctionStage` type, so with two or more function
stages, matching by type alone hits all of them at once. Pass `name=` (a bare function's stage
name defaults to `fn.__name__`) to target one specifically: `pipeline.remove(FunctionStage,
name="my_stage")`. `stage_type` and `name` can be given together, or `name` alone.

### `ContextResolver`

`system_prompt`, `cache`, `session_params` (callable resolving read-session
params from a `RequestContext`, overriding the default `user_id`/`session_id`
lookup), `max_history_messages=20` (`<=0` disables history injection).

### `CacheLookup` (exact-match)

`bus`, `extra_fingerprint` — an optional `(RequestContext) -> Any` hook adding
extra dimensions to the cache key (e.g. a tenant id from `ctx.state`) without
subclassing. The fingerprint always includes normalized messages, model,
pipeline name, `provider_options`, and `filters` — two requests differing
only in `temperature` or retrieval `filters` never collide on the same entry.

### `SemanticCacheLookup`

`threshold` (see above), `bus`. Embedder/store failures degrade to a cache
miss (never fail the request) — see the `cache.miss` event's `error` field.

### `VectorRetrieve`

`top_k=5`, `filters`, `bus`, and the RAG prompt wrapper:

- `format_document`: `(Document) -> str`, default `f"[{d.id}] {d.content}"`.
- `context_header`: default `"Relevant context retrieved for this request:"`.
- `insert_at`: `(RequestContext) -> int`, default just-before-the-last-message.

### `ProviderCall`

`**default_options` — provider options merged under any per-call
`provider_options` (per-call wins).

---

## Workers / queues

### `MemoryJobQueue`

`maxsize=0` (unbounded, `asyncio.Queue` semantics) — set to backpressure
`publish()` when a slow worker fleet can't keep up.

### `RedisStreamQueue`

All `RedisCache` connection params, plus:

| Param | Default | Notes |
| --- | --- | --- |
| `stream` | `"byoai:jobs"` | |
| `group` | `"byoai-workers"` | Consumer group name. |
| `consumer` | `None` → `worker-<random>` | Consumer identity within the group. |
| `result_prefix` | `"byoai:result:"` | |
| `result_ttl` | `3600` | |
| `prefetch` | `16` | Entries fetched per `XREADGROUP` round-trip. |
| `maxlen` | `None` (unbounded) | Caps the jobs stream so an idle/crashed worker fleet doesn't let it grow forever. |
| `approximate_trim` | `True` | Same tradeoff as the semantic cache's stream trim. |
| `start_id` | `"0"` | Consumer group's initial read position. `"0"` replays the whole existing stream (default, for a fresh deployment); `"$"` starts from only new entries (attaching a new worker fleet to a pre-existing, already-large stream without replaying the backlog). |

### `RuntimeWorker`

| Param | Default | Notes |
| --- | --- | --- |
| `concurrency` | `10` | |
| `shutdown_timeout` | `None` (wait forever) | Caps how long `stop()`/graceful shutdown waits for in-flight jobs to finish draining; a stuck job otherwise blocks shutdown forever. Timed-out tasks keep running in the background, just aren't awaited further. |

---

## Telemetry (OpenTelemetry)

`instrument(runtime, *, tracer_provider=None)` — attach tracing to an
existing `Runtime`; or declaratively via `Runtime(telemetry=...)`.

### `configure_otlp(...)` — builds a `TracerProvider` exporting to your collector

| Param | Default | Notes |
| --- | --- | --- |
| `endpoint` | required | |
| `service_name` | `"byoai-runtime"` | |
| `headers` | `None` | e.g. auth headers your collector requires. |
| `protocol` | `"grpc"` | `"grpc"` (port 4317) or `"http"`/`"http/protobuf"` (port 4318) — many collectors behind corporate ingress only allow HTTP. |
| `timeout` | `None` → SDK default | Exporter request timeout, seconds. |
| `compression` | `None` | `"gzip"` or `None`. |
| `resource_attributes` | `None` | Merged with `service.name`, e.g. `{"service.version": "1.2.0", "deployment.environment": "prod"}`. |
| `max_queue_size` / `schedule_delay_millis` / `max_export_batch_size` / `export_timeout_millis` | `None` → SDK defaults | `BatchSpanProcessor` tuning. Note: `max_export_batch_size` must be `<= max_queue_size`. |

Declarative: `Runtime(telemetry={"provider": "opentelemetry", "endpoint": "...", **any configure_otlp kwarg})`.
Pass a pre-built `TracerProvider` directly as `telemetry=` to skip
`configure_otlp` entirely (e.g. reusing a provider your app already
configured) — in that case `Runtime.close()` does **not** shut it down; you
own its lifecycle. A provider `Runtime` builds for you *is* shut down (final
span batch flushed) on `close()`.

---

## Transports

### FastAPI — `byoai.integrations.fastapi`

- `attach(app, runtime)` — binds `runtime.close()` to the app's shutdown hook.
- `stream_response(runtime, input, *, media_type="text/event-stream", headers=None, **execute_kwargs)` —
  `headers=None` defaults to `{"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}`
  (proxy-buffering-safe); pass `{}` to omit them, or your own dict to replace them.
- `serve_websocket(runtime, websocket)` — no extra config; drop it into your own route.

### Robyn — `byoai.integrations.robyn`

- `attach(app, runtime, *, prefix="/byoai", stream_media_type="text/event-stream", stream_headers=None)` —
  same `stream_headers=None` default-buffering-safe-headers behavior as FastAPI's `stream_response`.
- `create_app(runtime, *, prefix="/byoai", healthz_path="/healthz", **attach_kwargs)` —
  `healthz_path=None` skips registering the health route (e.g. your host app already has one).

### MCP — `byoai.integrations.mcp`

- `create_server(runtime, *, name="byoai-runtime", tool_name="execute", description=None, stream_tool_name="execute_stream", stream_description=None, **server_kwargs)` —
  registers two tools by default: `execute` (one request, one response) and
  `execute_stream` (streams token deltas as MCP progress notifications for
  clients that render them live, while still returning the same full result
  dict at the end — non-streaming-aware clients work unchanged). Pass
  `stream_tool_name=None` to register only `execute`. `**server_kwargs`
  forwarded to the MCP SDK server constructor (`instructions`, `version`,
  `debug`, `auth`, ...). Progress notifications require a live client
  session; calling `execute_stream` without one (e.g. a local `call_tool()`)
  skips reporting and still returns the correct full result.
- `attach(app, runtime, *, path="/mcp", name="byoai-runtime", **create_kwargs)` —
  mounts streamable-HTTP MCP into an existing Starlette/FastAPI app.
- `create_app(runtime, *, name="byoai-runtime", **create_kwargs)` — standalone ASGI app.
- Also works over **stdio** (`server.run_stdio_async()`) — the classic MCP
  transport for local clients like Claude Desktop; same two tools, same dialect.

All three transports (FastAPI, Robyn, MCP tool calls, queue workers) share one
payload/result/frame dialect (`byoai/transport.py`) — nothing transport-specific
to configure beyond framing.

---

## Agent Context Cache — `byoai-agent-context-cache`

A standalone FastAPI proxy (`byoai.agent_context_cache`) you run in front of
the Anthropic API. It sits between a client (e.g. Claude Code) and
`api.anthropic.com`, injecting prompt-cache breakpoints, truncating oversized
tool output, and collapsing repeated large tool results within a request to cut
token spend.

Dedup deliberately never rewrites a plain `text` block in a user turn: that
block is the instruction, not a file snapshot. It also keeps no state between
requests, so resending an identical body produces an identical upstream
request. See the `SessionDedup` docstring in `byoai/stages.py` for why both
constraints exist.
It is a separate process from `Runtime`, started via its own console script,
not something you configure through `build_*` dicts.

The proxy needs FastAPI, uvicorn, and redis, so it ships behind its own extra —
a base install has none of them and `byoai-cache` will fail to import:

```bash
pip install --pre "byoai-runtime[agent-context-cache]"
```

Start it with `byoai-cache` (the long `byoai-agent-context-cache` name is an
alias for the same command):

```bash
byoai-cache                # foreground
byoai-cache start          # background (detached; survives closing the terminal)
byoai-cache console        # background, and prints http://localhost:8787/console/
byoai-cache status         # running (pid …) → http://localhost:8787
byoai-cache stop
```

`start` writes its pid and logs under `~/.byoai/` (`proxy.pid`, `proxy.log`).
`--host` / `--port` override the `BYOAI_HOST` / `BYOAI_PORT` env vars below.

Then point any Anthropic API client at it, e.g. for Claude Code:

```bash
export ANTHROPIC_BASE_URL=http://localhost:8787
```

| Env var | Default | Purpose |
| --- | --- | --- |
| `BYOAI_HOST` | `0.0.0.0` | Bind address |
| `BYOAI_PORT` | `8787` | Bind port |
| `BYOAI_PROXY_TOKEN` | _(empty — no gate)_ | Shared secret required on every request when set, so the proxy can be exposed via a public tunnel (ngrok/Cloudflare) without being an open relay. Supply it as an `x-byoai-proxy-token` header or a leading URL path segment (`ANTHROPIC_BASE_URL=https://host/<token>`). `/health` is exempt. |
| `REDIS_URL` | `redis://localhost:6379/0` | Session hash state; falls back to an in-process store if unreachable (lost on restart, not shared across processes). Not consulted by dedup, which is request-scoped |
| `BYOAI_SQLITE_PATH` | `~/.byoai/byoai_runtime.db` | Durable log of usage + benchmark events (`db.py`); absolute default so data survives launching from any directory |
| `BYOAI_SESSION_TTL_SECONDS` | `28800` (8h) | How long a session's hash set lives in Redis |
| `BYOAI_RETENTION_DAYS` | `90` | How long rows are kept in the durable SQLite log. Pruned once on each proxy start, or on demand with `byoai-cache prune`. Set to `0` to keep everything forever |
| `BYOAI_BENCHMARK_SAMPLE_RATE` | `0.1` | Fraction of requests sampled for before/after token-count comparison |
| `BYOAI_READ_TIMEOUT_SECONDS` | `600` | Upstream request read timeout |
| `BYOAI_OPENAI_COMPAT_MODELS` | *(empty)* | Comma-separated model names to route to an OpenAI-compatible backend instead of Anthropic |
| `BYOAI_OPENAI_COMPAT_BASE_URL` / `BYOAI_OPENAI_COMPAT_API_KEY` | *(empty)* | Target for the above |

Session identity (`derive_session_id` in `main.py`) prefers an explicit
`X-Byoai-Session-Id` / `X-Session-Id` header; without one it derives an id
scoped to the caller's API key plus the request's system prompt + first
message. Dedup no longer keys off this id at all (it is request-scoped), so
session identity now only affects stats and cache accounting.

### Agent recorder — tamper-evident capture (`byoai.recorder`)

Opt-in, off by default. When enabled, `byoai-cache` extracts every
`tool_use`/`tool_result` pair the agent exchanges with the model and appends
it to a local hash-chained SQLite ledger, signed in checkpoints with a
device-held Ed25519 key. It never blocks or delays the token stream — the
extractor tees already-forwarded bytes — and by default a recording failure
is logged, not fatal to the request (see `BYOAI_RECORDER_STRICT` below).

Requires the `cryptography` package (and, for verifying RFC 3161 anchor
receipts, `rfc3161ng`), behind its own extra:

```bash
pip install --pre "byoai-runtime[recorder]"
export BYOAI_RECORDER_ENABLED=1
```

| Env var | Default | Purpose |
| --- | --- | --- |
| `BYOAI_RECORDER_ENABLED` | `0` | Set to `1` to turn the recorder on. Everything below is a no-op while it's off |
| `BYOAI_RECORDER_DIR` | `~/.byoai/recorder` | Where the device key and ledger (`ledger.db`) live |
| `BYOAI_RECORDER_STRICT` | `0` | `1` = a ledger write failure returns `503` to the client instead of being logged and skipped — for deployments where an unrecorded action is unacceptable |
| `BYOAI_RECORDER_PAYLOAD_MODE` | `redacted` | What payload bytes actually reach the ledger. `hash-only` ships no payload bytes at all (only the tamper-evident `payload_hash`); `redacted` masks detected secrets/PII and salted-hashes everything else before it's written; `full` ships payloads unchanged. `payload_hash` always commits to the raw, unredacted payload regardless of mode |

#### Trace attribution (sub-agents, resumed sessions)

Every recorded event carries a `trace_id` (root of one logical run) and
`span_id` (this agent invocation), so a ledger holds enough lineage to
reconstruct sub-agent trees and resumed-session links without changing the
chain's flat, append-only topology. Callers can supply this attribution via
headers on the request; if omitted, the recorder generates a fresh root
trace/span itself:

| Header | Default if absent | Purpose |
| --- | --- | --- |
| `X-BYOAI-Trace-Id` | a freshly generated trace id (this request becomes the root of a new trace) | Groups every span belonging to one logical run |
| `X-BYOAI-Parent-Span-Id` | `null` | Marks this request's span as spawned by another agent's span (e.g. a sub-agent invocation), within the same `trace_id` |
| `X-BYOAI-Continues-From` | `null` | Links a resumed session's (new) `trace_id` back to the prior trace it continues — plumbed through as given, never inferred automatically |

`span_id` is always generated fresh per request; it isn't settable via
header. These fields are part of the hashed event body like any other field,
so tampering with them post-hoc breaks the ledger's hash chain the same way
tampering with a payload would.

Verify a ledger offline, independent of the running proxy:

```bash
coriqo-verify ~/.byoai/recorder/ledger.db
```

Reports broken hash links, seq gaps, invalid checkpoint signatures, and
tool-call pairing findings (a `tool_use` with no matching `tool_result`, or a
`tool_result` with none — see the recorder's `verify.py` docstring for what
each finding means). Exit code `0` on a clean ledger, `1` on any integrity
failure, `2` if the file can't be read at all.

#### Managed agents you cannot intercept (`byoai.recorder.bedrock_agent`)

The two enforcement seams below (`@governed_tool`, the proxy gate) and the
capture path above all assume something of ours sits in the path. An AWS
Bedrock Agent breaks that assumption: the caller invokes the agent and AWS
runs the whole orchestration loop — prompt construction, model turns,
action-group Lambdas, knowledge-base retrieval — inside the service. No model
request leaves the account for a proxy to tee.

What AWS returns instead is a trace. Invoke with `enableTrace=True` and the
response stream carries a `TracePart` for every step, and that is the
evidence. `byoai.recorder.bedrock_agent` rewrites those parts into the same
Anthropic-shaped bodies `extract.py` already reads, so one extractor and one
digest rule cover this too:

| Bedrock orchestration part | Sealed as |
|---|---|
| `rationale` | `message` — the agent's stated reasoning |
| `invocationInput` | `tool_use` — action group, KB lookup, code interpreter, or collaborator handoff |
| `observation.*Output` | `tool_result`, paired to its call by `traceId` |
| `observation.finalResponse` | `message` — the decision text |
| `returnControl` | `tool_use` — a call the *caller* executes |
| `guardrailTrace` with `action: INTERVENED` | `guardrail_intervention` |
| `failureTrace` | `api_error` |

Sealed tool names are `actionGroup::function` (or `actionGroup::VERB /path`
for an OpenAPI action group), which is what Coriqo matches against an agent's
`allowed_tools`. A Bedrock guardrail firing gets its own event kind because it
is a third party's decision, carrying none of the reason codes a
`mandate_verdict` has. Collaborator steps land on their own span under the
root, the same shape sub-agents use.

`modelInvocationInput` is not sealed as an event — it is the constructed
prompt, not an action, and the proxy seam does not seal prompts either.
`modelInvocationOutput`'s raw scratchpad is off unless you pass
`include_raw_model_output=True`.

```python
from byoai.recorder.bedrock_agent_source import record_invocation
from byoai.recorder.integration import get_recorder

run = record_invocation(
    get_recorder(),
    agent_id="AGENT123456",
    agent_alias_id="ALIAS7890",
    prompt="Payment pay_5512 is held for sanctions review. Can it be released?",
)
print(run.final_text, run.guardrail_interventions)
```

`normalize_run(chunks)` is pure — no AWS SDK, no ledger — so recorded JSON
produces exactly what a live stream would. `seal_run(recorder, run)` writes
it. `boto3` is confined to `bedrock_agent_source.py` and lives behind an
extra:

```bash
pip install --pre "byoai-runtime[bedrock-agent,recorder]"
```

`iter_cloudwatch_invocations(...)` replays Bedrock's model-invocation logs
after the fact for agents already running, and is the weaker source of the
two. The log group is written by AWS and read by us: the customer's logging
configuration decides what is in it, large payloads are dropped to S3, and
anyone with CloudWatch write access could have edited a record before we
sealed it. The ledger will faithfully attest to what the log said, which is
not the same claim as attesting to what the agent did — say that out loud
rather than letting a green verify imply more.

The seam's own limit is worth stating too. It sees exactly what the trace
says, and an agent invoked without `enableTrace` leaves nothing here. Unlike
the proxy, which cannot be switched off from inside the agent, that flag
belongs to the caller — and an empty ledger for an untraced agent looks
identical to an agent that never ran.

##### What a Bedrock run looks like in Coriqo

Publishing needs nothing Bedrock-specific: `publish_session` reads the sealed
tool steps and Coriqo's agent API does the rest. Verified against a local
Coriqo (`acme_bank`, service account with `governance:approve` + `model:write`)
with the showcase's B6:

- The agent registers itself once, with `allowed_tools` set to the
  `actionGroup::function` names — the same spelling the recorder seals, which
  is what makes the mandate check work without a translation table.
- The run becomes one trajectory (`status: flagged`, 4 steps, 1 flagged) and
  one decision trace per sealed tool call, each citing its ledger row's
  `entry_hash` as an external grounding anchor.
- The `returnControl` wire transfer publishes with `result_hash: null` rather
  than being dropped for want of a result, so Coriqo sees the call that
  nothing executed.
- Coriqo raises the mandate breach itself: a **major, open finding** reading
  "acted outside its mandate. Used tool(s) outside the agent's mandate:
  PaymentActions::initiate_wire_transfer", raised by "Coriqo · agent
  oversight". The agent's Runs tab lists each Bedrock tool as in- or
  not-in-mandate.
- The run's decision text lands on the last step as readable prose, subject to
  `payload_mode` like any other.

**`guardrail_intervention` events publish too**, to their own endpoint —
`POST /api/v1/agents/{id}/external-controls`, added by Coriqo's migration
0314. Not as a trace: Coriqo mandate-checks a trace's tool calls, so a
guardrail filed there would flag the agent for a control that worked. They
land in their own table, sealed onto the mandate chain, and they **never move
a run's status** — "flagged" means the agent breached the mandate Coriqo
governs, and merging a third party's control firing into that counter would
make a bank's breach rate climb every time one of its controls did its job.
Coriqo shows them on the agent's Runs tab under *Controls outside Coriqo*.

Only policy NAMES travel. `bedrock_agent.guardrail_categories` builds the
published `categories` from a match's `name`/`type` and deliberately drops an
item carrying only a `match` — the matched span of text, which for a PII
entity is the email address itself. That structural guarantee is why
`redact.py` lets `categories` through under `REDACTED` mode while the raw
assessments stay digested; without it, a compliance screen showed
`[REDACTED:hash:027cb…]` where a reviewer needed "LegalAdvice", which
protected nothing because the matched text was never in that field.

A Coriqo too old to know the endpoint returns 404, which is logged and
ignored rather than failing the publish — the run's own record is complete
without it, and the sealed ledger keeps the authoritative copy either way.

#### Syncing to Coriqo (opt-in, requires enrollment)

> **Client-only for now.** No released Coriqo serves the `/v1/enroll` and
> `/v1/ingest/batch` endpoints described below, so `byoai-recorder-enroll`
> currently has nothing to enroll against. Everything on the byoai side is
> implemented and tested against the mock server in `tests/recorder/`, and the
> wire format below is the frozen contract a server has to satisfy — but until
> one exists, the recorder is local-only in practice. The rest of this section
> documents the client's behavior, not a working round trip.

The ledger is fully useful offline (`coriqo-verify` needs no network), but a
device can also ship it to a Coriqo instance for centralized storage. This is
a two-step, opt-in flow on top of everything above:

```bash
byoai-recorder-enroll --coriqo-url https://coriqo.example.com \
    --token cik_live_... --key-dir ~/.byoai/recorder \
    --tenant-slug acme_bank
```

This generates (or reuses) the device's Ed25519 keypair locally and sends
only the **public** key plus the single-use enrollment token to Coriqo —
the private key never leaves the machine. Coriqo replies with a `device_id`,
persisted alongside the key as `~/.byoai/recorder/enrollment.json`.

`--tenant-slug` records which Coriqo tenant the device belongs to, so
enforcement requests can set `X-Tenant-Slug` from enrollment state instead of
needing the legacy `BYOAI_CORIQO_TENANT_SLUG` in the agent's environment. A
`tenant_slug` in the enrollment response takes precedence — the server issued
the token and knows which tenant it was issued for — so the flag is what fills
the field in until a server returns one. It is optional: leave it off and the
device still enrolls, it just can't name its own tenant.

Once enrolled, the next time the recorder starts (`BYOAI_RECORDER_ENABLED=1`)
it launches a background shipper thread automatically — no separate command
needed. It batches unsynced ledger entries (100 events, 1&nbsp;MB, or 5s,
whichever comes first), gzips and signs each batch, and `POST`s it to
`{coriqo_base_url}/v1/ingest/batch`. Delivery is at-least-once with
server-side dedup, so a retried or resent batch after a crash or timeout is
harmless; a sync watermark stored in the ledger itself only advances past
entries Coriqo has confirmed, so a restart never silently drops unsynced
rows. Network failures never block the proxy — the shipper retries with
exponential backoff (honoring `Retry-After`) and simply queues locally in
the meantime.

Without enrollment, the recorder stays local-only: it writes the ledger and
makes no network calls.

#### Publishing runs to Coriqo's agent API (`byoai.recorder.coriqo_agents`)

A separate integration from the ledger sync above, and the one that works
against Coriqo today. Where the shipper would copy the raw hash chain, this
publishes *governed decisions* to Coriqo's agent API: each agent is registered
once, and each run becomes a trajectory plus one decision trace per sealed
step. Coriqo then holds the agent registry, the mandate each agent may act
under, and its own hash-chained trail of what the agent did.

Nothing here runs automatically. Session boundaries and agent identity are
application concepts the recorder can't infer — it never sees where a run ends,
and under the default `redacted` payload mode it can't even read which agent a
session belonged to. So the caller drives it:

```python
from byoai.recorder.coriqo_agents import (
    AgentRegistration, CoriqoAgentsClient, CoriqoCredentials,
    ensure_registered, publish_session,
)
from byoai.recorder.integration import get_recorder

credentials = CoriqoCredentials.from_env()   # None when BYOAI_CORIQO_URL is unset
if credentials is not None:
    with CoriqoAgentsClient(credentials) as client:
        agent_ids = ensure_registered(client, {
            "my-agent": AgentRegistration(
                name="My Agent",
                mandate="What this agent is allowed to do",
                allowed_tools=("search_docs", "summarize"),
            ),
        })
        # ...once a run identified by `session_id` has finished...
        recorder = get_recorder()
        publish_session(
            client,
            coriqo_agent_id=agent_ids["my-agent"],
            ledger=recorder.ledger,
            session_id=session_id,
            final_output=final_text,
            payload_mode=recorder.payload_mode,  # keep final_output under the
                                                  # same policy as everything
                                                  # else the recorder ships
        )
```

| Env var | Default | Purpose |
| --- | --- | --- |
| `BYOAI_CORIQO_URL` | unset | Coriqo base URL, e.g. `http://localhost:8000`. Unset means `CoriqoCredentials.from_env()` returns `None` and nothing is published |
| `BYOAI_CORIQO_API_KEY` | unset | Coriqo service account key (`cq_sa_…`). Required alongside the URL |
| `BYOAI_CORIQO_TENANT_SLUG` | unset | Coriqo tenant slug, e.g. `acme_bank`. Required alongside the URL |
| `BYOAI_CORIQO_MARKETING_URL` | `https://coriqo.com` | Coriqo Shield only: the link its Settings page shows for what longer plans offer (`GET /api/coriqo` → `marketing_url`) |
| `BYOAI_SHIELD_EXTENSION_IDS` | unset | Coriqo Shield only: comma-separated browser-extension ids allowed to send rows to `POST /api/browser`. Unset: any browser extension may (web pages never can) |

The service account authenticates with two headers rather than a JWT, and needs
`governance:approve` to register agents plus `model:write` to record traces. A
deployment that shouldn't create agents can hold `model:write` alone, skip
`ensure_registered`, and pass known agent ids to `publish_session` directly.
Registering always lands an agent at `in_review` — Coriqo never pre-approves —
so self-registration files a governance to-do rather than granting the agent any
standing.

`ensure_registered` is safe to call on every startup and from several processes
at once. Idempotency is Coriqo's, not ours: each agent is registered under an
`external_id` (your mapping key, optionally prefixed via
`external_id_prefix="my-app:"`), and re-registering the same one returns the
existing agent instead of a second copy. So there is no local cache to keep in
sync and no matching on display names. Note that a repeat call does **not** push
changed `mandate`/`allowed_tools` — amend those through Coriqo's mandate
endpoint, so the change is versioned rather than silently rewriting what earlier
decisions were judged against.

`publish_session` sends digests and step metadata, never raw tool payloads.
Each step's `args_hash`/`result_hash` are the ledger's own `payload_hash`
values, which commit to the raw payload whatever `BYOAI_RECORDER_PAYLOAD_MODE`
is set to, and each trace cites its ledger row's `entry_hash` as an external
grounding anchor (`{"type": "external", "id": …, "system": "byoai-recorder"}`),
which Coriqo holds outside its integrity scoring. Both stores therefore commit
to the same bytes: a hash off a Coriqo trace resolves to the sealed row behind
it, and `coriqo-verify` still checks the ledger offline, so neither store has
to be trusted on its own. Pass `ground_in_ledger=False` to leave the anchors
off.

`publish_session` also ships any third-party control events the session
sealed — a Bedrock guardrail intervening — to Coriqo's
`POST /api/v1/agents/{id}/external-controls`, added by its migration 0314.
`PublishResult.external_controls` counts them, deliberately apart from
`flagged`: one is the agent breaching its mandate, the other is somebody
else's control firing, and a caller that added the two would report a number
meaning neither. They never move a run's status, on either side. Read them
without publishing with `read_external_controls(ledger, session_id)`, which
returns `ExternalControlStep` records; `MAX_EXTERNAL_CONTROLS` is the batch
cap, and `CoriqoAgentsClient.record_external_controls` is the raw call. A
Coriqo too old to know the endpoint answers 404, which is logged and ignored
rather than failing the publish — the run's own record is complete without
it, and the ledger keeps the authoritative copy either way. See *Managed
agents you cannot intercept* above for how the events are captured.

The one field that isn't digest-only is `final_output` — a run's decision
text, attached to the last step, ships as readable prose on purpose. Its
handling follows `publish_session`'s own `payload_mode` argument (default
`redacted`, independent of the recorder instance's `payload_mode` unless you
pass it explicitly — see the example above): `redacted` runs the text through
a `redactor` (a `redact.TextRedactor`, i.e. `Callable[[str], str]`), `hash-only`
drops the field entirely, and `full` ships it unchanged.

`redactor` defaults to `redact.redact_free_text`, which masks known
secret/PII substrings (email, SSN, credit card, API/AWS key) wherever they
appear in the text, but has no way to catch free-form PII with no fixed
shape — a name, a street address. That's a deliberate boundary, not a bug:
name-level detection needs something closer to NER, which trades away the
near-zero latency this recording path is built around and has no one-size
answer for every integrator's accuracy/latency budget, so the package ships
a seam instead of a model. Pass your own `redactor` — spaCy, a DLP SDK, a
hand-rolled list, whatever fits your own tradeoff — to `publish_session` for
name-level redaction:

```python
def my_redactor(text: str) -> str:
    text = redact_free_text(text)   # keep the fixed-shape coverage
    return my_ner_model.scrub(text)  # then layer on name/address detection

publish_session(..., redactor=my_redactor)
```

`redactor` is only ever called under `payload_mode=PayloadMode.REDACTED`; it
has no effect under `full` or `hash-only`. Treat the default as narrowing
what can leak, not as a guarantee the text is clean.

Steps go up through Coriqo's batch endpoint, so an ordinary run costs one
request; runs longer than `MAX_TRACE_BATCH` (200) steps are split. A batch is
atomic on Coriqo's side — one invalid trace rejects all of them — so a rejection
raises rather than reporting partial success.

`allowed_tools` is enforced on every trace: a recorded call outside it comes back
`flagged` with a mandate Finding attached, so the list has to be the agent's real
declared tool surface. Register with `mandate_enforcement="observe"` to have
violations sealed and reported without flagging the trace, then read what the
agent actually reached for via Coriqo's `/mandate/observed-tools`.

`publish_session` also takes `parent_trajectory_id` to nest a run under another
of the **same** agent's runs, which rolls a flagged step up through every
ancestor. Coriqo refuses cross-agent nesting, so a sub-agent registered as its
own agent is better represented as a tool call on its parent's trace.

Functions here raise `CoriqoAgentsError` (and `AgentSuspendedError` on a 423)
rather than swallowing failures, leaving it to the application to decide whether
Coriqo being unreachable should matter. See
`examples/agent_showcase/coriqo_sync.py` for a caller that log-and-continues.

#### Which credential Coriqo sees (`byoai.recorder.identity`)

An agent host can hold two Coriqo credentials, and they are not
interchangeable. `resolve_identity()` is the single place that picks one:

```python
from byoai.recorder.identity import resolve_identity

identity = resolve_identity()          # or resolve_identity(key_dir=...)
```

It tries, in order:

1. **Device enrollment state** — `enrollment.json` plus the Ed25519 key under
   the recorder's directory (`BYOAI_RECORDER_DIR`, default
   `~/.byoai/recorder`), written by `byoai-recorder-enroll`. Enforcement-capable:
   `identity.enforcement_capable` is `True` and `identity.sign(data)` returns
   `ed25519:<base64>`, verifiable with `DeviceKey.verify`.
2. **`CoriqoCredentials.from_env()`** — the static `BYOAI_CORIQO_API_KEY` pair.
   Publish-only. Resolving one logs a warning naming the enrollment command,
   once per process rather than once per call.
3. **`None`** — no Coriqo identity configured. A supported state; callers no-op.

No new env vars: the device path reads the recorder's existing
`BYOAI_RECORDER_DIR`, the static path the existing `BYOAI_CORIQO_*` trio.

`identity.tenant_slug` is the tenant this identity acts in, for Coriqo's
`X-Tenant-Slug` header — from `enrollment.json` for a device, from
`BYOAI_CORIQO_TENANT_SLUG` for a static key. It is `None` on a device enrolled
before the tenant was persisted; that state loads normally and keeps signing,
and `resolve_identity()` logs one warning per process naming the re-enrollment
command (`... --tenant-slug <slug> --force`).

The split matters because of what a credential is used *for*. A static key is a
long-lived bearer secret living in the agent's own environment, and the one
that registers agents carries `governance:approve` — so anything that decides
what an agent is allowed to do must not authenticate with it. Callers on that
path ask for a signer rather than testing a boolean:

```python
signer = identity.require_enforcement()   # EnforcementIdentityUnavailableError on a static key
```

`EnforcementIdentityUnavailableError` derives from `CoriqoIdentityError`, which
derives from `ByoAIError`, and its message names the `byoai-recorder-enroll`
command to run. `CoriqoIdentityError` is also raised when `enrollment.json`
exists but is unreadable, or when an enrolled directory has lost its private
key — neither silently falls back to the static key, since that substitution is
exactly what this resolver exists to prevent.

The private key never leaves `byoai.recorder.keys`. `CoriqoIdentity` holds a
`Signer` (public key, `device_id`, `sign`), never key bytes, so tests can inject
a fake signer and the on-disk permission checks stay in one module. Loading goes
through `keys.load_device_key()`, which loads or returns `None` and never
creates — an enrolled device whose key file has gone missing gets an error
rather than a fresh keypair bound to nothing.

`identity.device_id` is the id of the key that signs. It can differ from
`identity.enrolled_device_id` after `byoai-recorder-rotate-key`, which replaces
the live key without rewriting `enrollment.json`; the rotation is followable
through the ledger's `KEY_ROTATED` event, and reporting the enrolled id
alongside a signature from the rotated key would describe two different keys.

#### Async publishing and enforcement (`byoai.recorder.coriqo_async`)

`CoriqoAgentsClient` is synchronous and never retries, which is right for
publishing a finished run from a script. Mandate enforcement is a different
shape: the runtime refreshes a cached policy snapshot on a background interval
while the agent is mid-turn, so a blocking call stalls the event loop for a
whole round trip and one transient blip reads as a failed refresh.
`AsyncCoriqoAgentsClient` is the variant for that path. The sync client is
unchanged and stays the recommended one for batch publishing.

```python
from byoai.recorder.coriqo_async import AsyncCoriqoAgentsClient, RetryPolicy
from byoai.recorder.identity import resolve_identity

identity = resolve_identity()
async with AsyncCoriqoAgentsClient(identity, retry=RetryPolicy(attempts=3)) as client:
    mandate = await client.fetch_mandate(coriqo_agent_id)     # device-signed, retried
    await client.record_verdict(coriqo_agent_id, tool="rm", verdict="blocked")
```

It takes a `CoriqoIdentity` (or plain `CoriqoCredentials`, for symmetry with
the sync client) and mirrors its construction options — `http_client`,
`timeout` — including that a caller-supplied client is never closed by
`close()`. No new env vars. The tenant for `X-Tenant-Slug` is resolved in this
order: an explicit `tenant_slug=…`, then the identity's own tenant
(`enrollment.json` for a device, `BYOAI_CORIQO_TENANT_SLUG` via
`CoriqoCredentials` for a static key), then `BYOAI_CORIQO_TENANT_SLUG` directly.
A signed call with none of those is refused before it reaches the network. The
last step exists for devices enrolled before the tenant was persisted — an
enrolled device that also passes `--tenant-slug` needs nothing else in its
environment to enforce.

**What gets retried.** Reads only, by default:

| Retried | Not retried |
| --- | --- |
| `fetch_mandate`, `get_agent`, `list_agents`, `list_trajectories`, `record_verdict_batch` | `record_trace`, `record_traces`, `record_signed_trace`, `record_verdict`, `open_trajectory`, `complete_trajectory`, `authorize`, `register_agent` |

A resent trace or single verdict is a second decision in the record, and Coriqo
has no idempotency key to collapse it back onto the first — so those are sent
once and the failure is the caller's to handle.

`record_verdict_batch` is the exception that needs no opt-in, because the
objection does not apply to it. Its `batch_key` is device-chosen and unique per
device server-side: a repeat replays the stored result with `duplicate: true`
and seals nothing, and two concurrent copies race a unique index where the loser
gets a `409` asking it to retry. So `409` joins the retry set for that call only,
and a resend cannot produce a second governance record. `422` stays out of it —
an over-cap batch, a reasonless `blocked`, or a verdict naming another agent's
mandate version are statements about the batch, not about the network. The other
exception is opt-in:
`RetryPolicy(retry_writes=True)` makes `register_agent` retryable *only* when
the registration carries an `external_id`, which is Coriqo's own idempotency
key (a repeat returns the existing agent instead of creating a second copy).
The cost is that `created` can come back `False` for an agent this process did
create, when the first attempt landed and its response was lost.

`RetryPolicy` retries 429/502/503/504 — 500 is deliberately absent, since it
can mean the write landed and the response didn't. Backoff for attempt *n* is
`min(base_delay * 2**n, max_delay)` scaled by a random factor in
`[1 - jitter, 1)`, so a fleet that all lost the same Coriqo doesn't come back
in lockstep. A `Retry-After` header (or the `retry_after` on a `RateLimitError`
raised by a transport hook) wins over the computed backoff and is not jittered,
capped by `max_retry_after` so a mistaken header can't park a refresh loop.

| Field | Default | Meaning |
| --- | --- | --- |
| `attempts` | `3` | total tries, not extra ones — `1` disables retry |
| `base_delay` | `0.2` | first backoff, in seconds, before jitter |
| `max_delay` | `5.0` | ceiling on the exponential growth |
| `jitter` | `0.5` | fraction of each delay that is randomized |
| `max_retry_after` | `30.0` | ceiling on a server-sent `Retry-After` |
| `retry_statuses` | `{429, 502, 503, 504}` | statuses worth another attempt |
| `retry_writes` | `False` | see above — affects `register_agent` only |

**Enforcement endpoints are device-signed.** Calls under
`/api/v1/agent-runtime` (`fetch_mandate`, `record_verdict`,
`record_verdict_batch`, `record_signed_trace`) authenticate with the enrolled device key and never send
`X-API-Key` — Coriqo rejects a service-account key on that path on purpose,
because the credential that fetches an agent's permitted scope must not be one
the agent can use to widen it. A static-key identity raises
`EnforcementIdentityUnavailableError` at the client rather than collecting a
403. Each request carries `X-Coriqo-Public-Key`, `X-Coriqo-Timestamp` and
`X-Coriqo-Signature`, an Ed25519 signature over canonical JSON of
`{body_sha256, method, path, public_key, timestamp}` — `path` includes the
query string, and the signer's own key is inside the signed bytes, so a
captured signature can't be replayed against a different request or under a
different identity. Coriqo accepts a timestamp up to 120s old and 30s in the
future, so every attempt is signed afresh rather than resent with the previous
attempt's timestamp.

Errors are the sync client's, unchanged: `CoriqoAgentsError` with
`status_code`/`detail` (409 no mandate version, 403 missing role, 422 schema
rejection) and `AgentSuspendedError` on 423. `CoriqoAgentsError` now also
derives from `ByoAIError` alongside `RuntimeError`, so one `except ByoAIError`
covers the whole runtime; existing `except RuntimeError` code is unaffected.

#### Enforcing the mandate locally (`byoai.recorder.mandate`)

`MandateGate` answers one question — *may this agent call this tool?* — from a
**local cached snapshot**, never a synchronous call to Coriqo. Putting a
governance service on an agent's hot path makes the agent's availability a
function of that service's, which is not something a bank will ship. The gate
refreshes on a background interval and decides in memory.

```python
from byoai.recorder.mandate import Allow, Deny, RequireApproval, mandate_gate

gate = mandate_gate(coriqo_agent_id)        # identity resolved from this host
async with gate:                            # first fetch, then a refresh loop
    verdict = gate.decide("send_payment")   # no network I/O, safe off-thread
    if isinstance(verdict, Deny):
        ...                                 # terminal: do not run the tool
```

`decide()` returns one of three verdicts. `Flag` is a subclass of `Allow` — a
flagged call still runs, it is the record that differs — so
`isinstance(verdict, Allow)` (or `verdict.allowed`) is the test for *may this
proceed*. Every verdict carries `reason`, `mandate_version_id`,
`snapshot_age_s`, `tool`, `posture` and an operator-facing `detail`.

**Two server fields, two questions.** `mandate_enforcement`
(`enforce`/`observe`) is the tenant's rollout dial: does a scope breach count
as a violation. `enforcement_posture` (`fail_open`/`fail_closed`) is about this
runtime: what happens when the gate cannot evaluate. They are separate, so an
observing agent can still run under a fail-closed posture.

| Situation | `fail_open` | `fail_closed` |
| --- | --- | --- |
| snapshot fresh, tool in scope | allow | allow |
| fresh, out of scope, `enforce` | **deny** | **deny** |
| fresh, out of scope, `observe` | allow + flag | allow + flag |
| snapshot stale past `max_staleness_s` | allow + flag | **deny** |
| agent suspended | **deny** | **deny** |
| no snapshot ever fetched | allow + flag | **deny** |
| tool in `approval_required_tools`, no decision yet | **require approval** | **require approval** |

Suspension denies under both postures — it is a decision Coriqo made and this
runtime read, not a failure to evaluate. And what trips the fail-closed branch
is *staleness*, not reachability: a failed refresh keeps the cached snapshot,
so one blip cannot become an outage, and the snapshot stops counting only when
it is older than the budget the tenant set.

**`allowed_tools: null` is not `allowed_tools: []`.** `null` means
unrestricted; `[]` means nothing is permitted. Both are valid on the wire and
they are opposite instructions, so the snapshot keeps them apart (`None` vs
`()`) and never uses a falsy test to tell them apart.

**A third tier: approval-required tools.** A tool named in the mandate's
`approval_required_tools` is neither allowed nor denied outright — a call to
it gets `RequireApproval` (a fourth verdict, not a subclass of `Allow` or
`Deny`) instead. This is denied FOR NOW, locally, with no network wait —
`decide()` keeps its "no I/O, ever" guarantee. It denies under BOTH postures
and regardless of `mandate_enforcement`, the same way suspension does: it is
a control a tenant named explicitly (payments, regulatory filings), not
something an `observe`-mode rollout should silently wave through.

```python
verdict = gate.decide("send_payment")
if isinstance(verdict, RequireApproval):
    gate.report_approval_request(verdict)   # tells Coriqo about it — best-effort,
    ...                                      # schedules a background task, never blocks
```

`report_approval_request()` is a separate, explicit call — `decide()` itself
never reports anything, staying pure. Call it once per verdict; it dedupes on
`verdict.request_id` for the gate's lifetime, so a tight retry loop doesn't
spam Coriqo, and a failed report (no running event loop, mid-flight network
error) is NOT counted as reported, so a genuine retry of the same call tries
again.

`request_id` is computed deterministically from `(tool, trajectory_id,
step_index, arguments)` — a retried identical call reports/resolves to the
same pending request rather than minting a new one every attempt. Include
`trajectory_id`/`step_index` (or distinguishing `arguments`) on
`ProposedAction` for any approval-gated tool; without at least one of them,
two genuinely different calls to the same tool are indistinguishable and
would collide onto one request.

Once a human decides in Coriqo, the outcome is NOT pushed live — it arrives
in `resolved_approvals` on the gate's next scheduled snapshot fetch, same as
every other mandate change. The identical call (same `request_id`) then
gets `Allow` or `Deny` instead of `RequireApproval` on its next `decide()`.

**Enforced budgets: cost, call-rate, and step ceilings.** Three more mandate
fields — `max_run_cost_usd`, `max_calls_per_minute`, `max_run_steps` — are
checked entirely locally, no I/O, right alongside suspension: a breach
returns `Deny` with reason `budget_cost_exceeded` / `budget_call_rate_exceeded`
/ `budget_step_limit_exceeded`. Unlike approval-required tools, there is no
separate report call — a budget-breach `Deny` is an ordinary verdict, sealed
through whatever verdict-reporting call you already make.

```python
verdict = gate.decide(ProposedAction(tool="send_payment", trajectory_id="run-1"))
...                                          # execute the call if allowed
gate.record_actual_cost("run-1", 0.014)      # tell the gate what it actually cost
```

`max_calls_per_minute` is a sliding 60s window over every `decide()` call
that reaches this check (i.e. not suspended). `max_run_steps` counts
DISTINCT `step_index` values per `trajectory_id` — retrying the same step
doesn't count twice, but a call with no `trajectory_id`/`step_index` can't be
step-limited at all (nothing to key the ceiling on). `max_run_cost_usd` is
checked against a running total per `trajectory_id` — `decide()` runs
BEFORE a call, so it can't know that call's own cost, only what earlier
calls in the same trajectory already spent; call `record_actual_cost()`
once the real cost is known (e.g. from the model API's own usage response)
so the NEXT `decide()` in that trajectory sees it. All three ceilings deny
under both postures, same as suspension and approval-required tools — a
declared limit is not something a rollout mode should silently waive.

**A denial is not a tool error.** If a denial reaches the model as an ordinary
failure — worse, one naming the tool and the scope — the model will rephrase,
try an adjacent tool, and route around the control. So `Deny.model_message` is
a single fixed sentence, identical for every reason, and everything an operator
needs stays in `detail` and the logs.

**Refresh.** `start()` fetches once and then refreshes every
`max_staleness_s / 2` (floor: 1s), a per-agent value that comes from the
snapshot itself, so the interval follows the agent's own budget. Coriqo answers
`304` when the mandate has not changed; that is read as *still fresh, keep what
you have* — the age resets and the cached scope stands.

Without any Coriqo identity on the host, `mandate_gate()` returns a working
no-op: everything is allowed, one line is logged, so the enforcement code path
can be adopted before enrolment. A *static API key* identity is refused with
`EnforcementIdentityUnavailableError` instead — an absence is fine, a
credential that could widen the agent's own mandate is not.

| Env var | Default | Purpose |
| --- | --- | --- |
| `BYOAI_MANDATE_POSTURE` | `fail_open` | `fail_open` or `fail_closed`, used only until the first snapshot names the tenant's own posture |
| `BYOAI_MANDATE_MAX_STALENESS_S` | `300` | staleness budget used until a snapshot names its own `max_staleness_s` |
| `BYOAI_MANDATE_ENVIRONMENT` | *(unset)* | where this runtime runs, e.g. `production`. When set, a snapshot whose `environment` names somewhere else is treated as no mandate and the posture decides (reason `environment_mismatch`). Unset: not compared. `MandateGate(environment=...)` overrides it |

The first two are bootstrap values for the window before the first snapshot
lands; after that Coriqo's values win.

**Fields from a mandate file (TI-20).** A snapshot carries `prohibited_tools`,
`on_violation`, `environment` and `output_inspection` only when the agent's
approved mandate came from a `coriqo.mandate.yaml` that set them. Absent, each
reproduces the behaviour from before it existed. `prohibited_tools` are outside
the mandate even with no allow-list, and win over `approval_required_tools`.
`on_violation` under `enforce`: `deny` (default), `deny_and_halt_run` (the
first scope denial halts the run), `alert_only` (allowed, recorded as
`flagged` with reason `out_of_scope`); unknown values read as `deny`.
`output_inspection` is kept and not acted on yet.

**Running from a mandate file** (`byoai.recorder.mandate_file`).
`file_mandate_gate(path)` builds a gate from a `coriqo.mandate.yaml` with no
Coriqo account: `mode: shadow`/`enforce` map to `observe`/`enforce`,
`on_stale_snapshot` to the posture, and `mandate_version_id` is
`sha256:<document hash>`. The file is read by the reference reader, vendored
byte-for-byte as `byoai/recorder/mandate_format.py` (YAML needs PyYAML; JSON
needs nothing), and re-read on the refresh schedule; an unreadable or invalid
file keeps the last good copy until it is stale. `MandateGate(default_posture=…,
default_max_staleness_s=…)` overrides them in code.

#### `@governed_tool` — enforcing at the call site (`byoai.recorder.governed_tool`)

`MandateGate` decides; `@governed_tool` is where the decision stops something.
Put it on your own tool functions and a `Deny` means the function is never
entered — not entered and its result discarded, and not handed to the model as
an error it can work around.

```python
from byoai.recorder.governed_tool import governed_tool, set_default_gate
from byoai.recorder.mandate import mandate_gate

gate = mandate_gate(coriqo_agent_id)

@governed_tool
def search(query: str, limit: int = 10) -> list[str]:
    """Search the corpus."""
    return corpus.query(query, limit=limit)

@governed_tool(name="payments.send")       # the name Coriqo approved
async def send_payment(iban: str, amount: str) -> str:
    return await bank.transfer(iban, amount)

async def main():
    async with gate:                        # first fetch, then the refresh loop
        set_default_gate(gate)
        search("rates")                     # in scope: runs normally
        await send_payment("DE…", "10.00")  # out of scope: raises, never runs
```

One decorator covers sync and async tools — the tool name, the gate lookup and
the denial contract are identical either way, and `inspect.iscoroutinefunction`
already knows which you wrote. It is `functools.wraps`-based and sets
`__signature__`, so a framework that builds its tool schema by introspection
sees the real function: same `__name__`, `__doc__`, signature and annotations.
The tool name defaults to `fn.__name__`; pass `name=` when the Python function
and the tool Coriqo approved are not called the same thing, which is common
once a framework namespaces them. The call's arguments are bound onto the
`ProposedAction` for the record; `capture_arguments=False` turns that off for a
tool whose arguments are large or sensitive.

**A denial raises `MandateDeniedError`** (from `byoai.errors`, so it derives
from `ByoAIError` like everything else the runtime raises). It is terminal and
non-retryable *by construction*, not by convention:

| | |
| --- | --- |
| `str(exc)` | the fixed `MODEL_MESSAGE`, and nothing else — `str(exc)` is what frameworks feed back into the model's context |
| `exc.verdict` | the whole `Deny`: `reason`, `mandate_version_id`, `snapshot_age_s`, `tool`, `posture`, `detail` |
| `exc.operator_detail` | those fields as one log line. Never put it in front of the model |
| `exc.retryable` | `False`, and there is no `retry_after` — nothing about it reads as transient |

The decorator also logs the operator detail at `WARNING` on the raising path,
so a blocked call is in the record whether or not the caller catches it.
Retrying is pointless in any case: the same action against the same snapshot
denies again. A `Flag` is *not* a denial — an off-mandate call under
`mandate_enforcement: observe` runs exactly as it would have, which is the
whole point of `observe`.

**Getting a gate to the decorator.** Tools are defined at import time; gates
are built at startup. Resolution is layered, most specific first:

1. `@governed_tool(gate=…)` — a `MandateGate`, or a zero-argument callable
   returning one, for that tool only. The callable is evaluated per call, so a
   tool decorated at import time can still see a gate built later.
2. Whatever `set_default_gate(gate)` or `with use_gate(gate):` bound.

The default lives in a `ContextVar`, not a module global, so two agents in one
process do not share a mandate and `use_gate` restores the previous binding on
exit. `set_default_gate` returns the token if you want to unwind it yourself;
`default_gate()` reads the current one.

With no gate bound at all — or a gate from `mandate_gate()` on a host with no
Coriqo identity — the decorator runs the function and logs one line. Adopting
it is never the thing that breaks a build.

#### Enforcing at the proxy (`byoai.recorder.proxy_gate`)

`@governed_tool` needs you to decorate your own tool functions, and that is a
source change to code you may not own — a vendored agent, a framework's
built-in tools, a binary someone else ships. The proxy already sits at
`ANTHROPIC_BASE_URL` and already parses `tool_use` blocks out of model
responses, so it can refuse one without touching the agent at all.

Same gate, same latch, same verdict recorder. There is no second policy path:
two implementations of one enforcement rule drift, and then one of them is
wrong.

```bash
BYOAI_PROXY_ENFORCEMENT=1
BYOAI_MANDATE_AGENT_ID=agt_7f3c      # or a comma-separated list
```

On a denial the `tool_use` block is **withheld** — it never reaches the agent,
so there is nothing for the agent's dispatcher to execute — and a synthesized
`tool_result` block goes out in its place carrying the same fixed
`MODEL_MESSAGE` a decorator denial carries, `is_error: true`, and nothing else.
No tool name, no reason, no mandate version, no suggested alternative. At this
seam that text lands directly in the model's next context window, so a denial
that explained itself would be a working hint sheet for routing around the
control.

If every `tool_use` in a response was denied, `stop_reason` is rewritten from
`tool_use` to `end_turn`. A message that says it is waiting on a tool but
contains no tool call is a shape no agent loop expects, and the common
`while stop_reason == "tool_use"` spins on it with nothing to dispatch.

**Streaming.** Nothing is buffered except the frames of a `tool_use` block that
has not finished yet, plus at most one partially-received SSE frame. Text
frames — the tokens a human is watching appear — go out in the same pass they
arrived. The decision lands on `content_block_stop`, which is both the earliest
moment the arguments are complete enough to decide on and the last moment
before the agent could act. A stream cut mid-`tool_use` drops the held block
rather than releasing it: forwarding a tool call the gate never got to see is
the one outcome this seam exists to prevent.

**Which agent is this request?** The registry is operator-owned. Gates are
registered at startup from `BYOAI_MANDATE_AGENT_ID`, or in code with
`register_proxy_gate(gate)`; a request cannot introduce an identity that was
not already configured. `X-BYOAI-Agent-Id` selects *among registered gates*
when one proxy fronts several agents — it is a selector, never a credential,
because the agent is the untrusted party at this seam and a header that could
name any mandate would let it pick its own scope.

A request whose agent cannot be resolved — an unregistered id in the header, or
no header when several gates are registered — is decided by
`BYOAI_MANDATE_POSTURE`: `fail_closed` withholds the block, `fail_open` allows
it and flags it. Either way a verdict with `reason: agent_unresolved` is
recorded and a `WARNING` is logged. It is never latched, because a startup
ordering problem is not a scope decision and should not halt a run.

| Env var | Default | Purpose |
| --- | --- | --- |
| `BYOAI_PROXY_ENFORCEMENT` | `0` | `1` turns proxy enforcement on |
| `BYOAI_MANDATE_AGENT_ID` | *(unset)* | agent id, or comma-separated ids, whose gates the proxy registers at startup |
| `BYOAI_PROXY_DENIAL_BLOCK` | `tool_result` | shape of the synthesized replacement block; `text` for clients whose SDK rejects a `tool_result` inside an assistant message |

**What this does not cover.** Only tools the model *requests through the
intercepted provider API*. A tool the agent's own code calls directly — a
helper it invokes without asking the model, an MCP client it drives itself —
never appears in a response body and is invisible here. That is what
`@governed_tool` is for. The two seams compose; neither alone is total.

The OpenAI-compat bridge (`OPENAI_COMPAT_MODELS`) is gated too. It is a separate
handler that returns before the Anthropic path's enforcement point, so it needs
its own hook — but it translates the upstream response into Anthropic shape
either way, so the same enforcer runs on it unchanged, buffered and streaming.

#### Gating an MCP server (`coriqo-mcp`, `byoai.integrations.coriqo_mcp`)

`pip install --pre "byoai-runtime[coriqo-mcp]"` adds `cryptography` (the
signed ledger), PyYAML (YAML mandate files) and uvicorn (`--http`).

```bash
coriqo-mcp --mandate coriqo.mandate.yaml -- <server command>          # stdio
coriqo-mcp --mandate coriqo.mandate.yaml --http --upstream http://127.0.0.1:9000
```

| Flag | Default | Purpose |
| --- | --- | --- |
| `--mandate FILE` | — | the `coriqo.mandate.yaml` (v1) to enforce. An invalid file stops start-up (exit 2) and lists each problem |
| `--coriqo-agent-id ID` | — | instead of a file: this agent's approved mandate, fetched from Coriqo and cached (enrolled device only) |
| `--environment ENV` | `$BYOAI_MANDATE_ENVIRONMENT` | where this runs; see `BYOAI_MANDATE_ENVIRONMENT` |
| `--recorder-dir DIR` | `$BYOAI_RECORDER_DIR` or `~/.byoai/recorder` | ledger, device key and the outbox of decisions waiting to go to Coriqo (`coriqo_mcp_verdicts.db`) |
| `--no-record` | off | decide calls but write nothing (no `cryptography` needed) |
| `--http` | off | relay an HTTP MCP server (streamable HTTP or SSE) instead of a stdio child |
| `--upstream URL` | — | with `--http`: the server's base URL. Requests keep their path and query |
| `--listen HOST:PORT` | `127.0.0.1:8808` | with `--http`: where `coriqo-mcp` listens |
| `--grace SECONDS` | `5` | how long the server gets to exit before SIGTERM, then SIGKILL, to its process group |
| `-v` | off | log each decision's operator detail to stderr |

The server command goes after `--`. On stdio, `coriqo-mcp` owns it: it runs in
its own process group and is stopped when the host disconnects or
`coriqo-mcp` gets SIGTERM, SIGINT or SIGHUP. Protocol traffic is the only thing
written to stdout; everything else goes to stderr. Decisions are sent to
Coriqo's verdict endpoint every 5 seconds when the device is enrolled and the
agent has a Coriqo id (`agent.id` in the file, or `--coriqo-agent-id`). The
README's `coriqo-mcp` section lists what is and is not checked.

#### The denial latch — repeats and the halt (`byoai.recorder.denial_latch`)

A denial stops one call. On its own that leaves an agent free to attempt the
same refused tool for as long as its loop keeps turning, and the record shows a
row of identical single denials with nothing tying them together. The latch ties
them together.

It is keyed on the run, the agent asking, and the tool. The first denial goes
into it; every later attempt at that tool is refused **from the latch, without
re-running the scope check**, because the same tool against the same snapshot
cannot answer differently. At the threshold — 3 attempts by default, counting
the first denial — the run is halted: every subsequent call in that run, including
tools that were in scope all along, raises `MandateRunHaltedError`.

```python
from byoai.errors import MandateDeniedError, MandateRunHaltedError
from byoai.recorder.denial_latch import run_scope

with run_scope(trajectory_id):        # names the run for every call inside
    try:
        result = send_payment("DE…", "10.00")
    except MandateRunHaltedError as exc:
        stop_the_run(exc.run_id, attempts=exc.attempts)   # the run is over
    except MandateDeniedError:
        pick_another_tool()                                # this tool is refused
```

`MandateRunHaltedError` subclasses `MandateDeniedError`, so every handler already
written keeps stopping the call, and `isinstance` (or `exc.halted`) is what tells
a supervising loop *this tool is refused* from *this run is over*.

**Only scope denials are latched.** A suspension is lifted, a stale snapshot
refreshes, a first snapshot arrives — all three deny under `fail_closed`, and all
three are transient. Remembering them would turn one refresh blip into a
permanently halted run, which is the outage the refresh path exists to prevent.
Only `out_of_scope` (and its delegated form) goes into the latch.

**A new mandate version clears that agent's buckets.** The latch's licence to
refuse without re-evaluating is that the answer cannot have changed; a new
mandate version is exactly when it can have, because somebody approved something.
The buckets go, and the halt with them if it was that agent's doing — one agent's
new mandate says nothing about what another did. The version is read once per
call from `MandateGate.latch_version`, which a `DelegatedGate` answers with the
delegator's live version, the pinned delegation and its own, combined. Both sides
of a lookup must be fed that one value: two sources look like a version flapping
on every call, and a flapping version wipes the buckets it just wrote.

**The model's sentence never changes.** First denial, fourth repeat, halt: all
of them are the same fixed `MODEL_MESSAGE`. Escalating the detail as the agent
tries harder would hand it a hint sheet at the moment it is probing the control.
The attempt count and the halt go to the operator — a `WARNING` on the raising
path, and `LatchedDenial.attempts` on the verdict path for whatever seals it.

**Which run.** `ProposedAction.trajectory_id` when it is set, else the run bound
by `run_scope()`, else a fallback id belonging to the `MandateGate` — one gate is
built per agent per run in every wiring here, and two gate objects are two
different mandates. The imprecision runs the safe way: an application reusing one
long-lived gate across several sequential runs shares one bucket until it names
them, which latches too eagerly rather than too late.

**Buckets carry the agent too**, because a delegated sub-agent and its delegator
share a run and not a scope — a child's denial must not latch a tool the parent
may still legitimately call. The halt is the exception and is run-wide: once a
run is over, which agent asks next is beside the point.

| Env var | Default | Purpose |
| --- | --- | --- |
| `BYOAI_MANDATE_HALT_THRESHOLD` | `3` | attempts at one already-denied tool before the run is halted, counting the first denial. Values below 1 and non-integers fall back to the default |

The process-wide latch reads that variable once, at import, so set it before
importing `byoai.recorder.governed_tool` — or pass the threshold in code.

`DenialLatch(threshold=…)` overrides it in code. `latch.reset(run_id)` clears one
run, for a supervisor that has taken its own decision about a halted one. A latch
also holds at most `max_runs` runs (1024 by default), dropping the oldest first,
so a process that runs for months does not accumulate a bucket per run.

**Latch state is per-process and in memory.** A run that spans two processes, or
a host that restarts mid-run, starts counting from zero. Nothing persists it yet.

#### Recording verdicts (`byoai.recorder.verdicts`)

A verdict that only ever reached your process logs is not evidence. This module
writes every gate decision — `allowed`, `flagged` and `blocked` alike — into the
same hash-chained local ledger the recorder already keeps, and ships them to
Coriqo in batches.

```python
from byoai.recorder.ledger import Ledger
from byoai.recorder.verdicts import (
    VerdictOutbox, VerdictRecorder, VerdictShipper, set_verdict_recorder,
)

ledger = Ledger("~/.byoai/recorder/ledger.db", device_id)
outbox = VerdictOutbox("~/.byoai/recorder/verdicts.db")
set_verdict_recorder(VerdictRecorder(ledger=ledger, outbox=outbox))

shipper = VerdictShipper(async_client, outbox)
await shipper.drain()          # or call ship_once() from your own loop
```

With no recorder bound, nothing is recorded and nothing breaks — same shape as
an unenrolled host getting a no-op gate.

**Allows are recorded too**, and that is the point of the denominator. "4,120
tool calls, 9 of them outside the mandate" is a sentence a risk committee can
use; "9 denials" is not.

**Recording is not on the decide path.** `MandateGate.decide()` still reads
memory and returns, with no I/O of any kind. The recorder is called from
`@governed_tool`'s enforcement seam, after the verdict exists — an agent's
availability must not become a function of whether a ledger write succeeded, and
`record()` never raises into a tool call either: a write it cannot make is logged
at `ERROR` and the call proceeds (or is refused) exactly as it would have.

**The ledger is authoritative; shipping is downstream of it.** A denial is
written whether or not Coriqo is reachable. Batches are claimed under a
`batch_key` that is persisted *before* the request goes out, so a resend after a
crash, a timeout or a `409` is the same batch rather than a second one, and
nothing leaves the queue until Coriqo has answered about it.

**A repeat is not another first denial.** The reason code carries the
distinction on the wire — `out_of_scope`, then `repeat_denied`, then
`run_halted` — and the local ledger event carries `attempts`, `halted`, `run_id`
and `principal` alongside it. So "the agent went at a control it had already
been refused, three times, and then the run halted" reads straight off the
record instead of being three identical rows.

**Stale mandate versions are recorded, not rejected.** Coriqo anchors a batch on
the agent's current version and reports `anchor_mandate_version_id` and
`stale_mandate_version_count` back; `VerdictShipResult` carries both and the
shipper logs a `WARNING` naming the drift, so a host whose snapshot has aged
learns it from the reply rather than by reading the chain weeks later.

**A `422` parks the batch rather than looping on it.** The rows stay in the
outbox marked `rejected` with the server's reason, and they are still in the
ledger — dropping a verdict is the one thing this module exists to prevent.

**The write is inline.** Both the ledger append and the outbox insert happen on
the calling thread, for every governed call, and inside an async tool that is on
the event loop. A failed write cannot fail a call, but a slow or locked sqlite
file will slow one — the recorder protects correctness, not latency.

**Tool arguments are never recorded or shipped.** `@governed_tool(capture_arguments=True)`
binds a call's arguments onto the `ProposedAction`, and a governed tool's
arguments routinely hold account numbers and credentials that nothing redacts
yet. The record keeps `arguments_captured`, a count, and never a key or a value —
not locally, and not on the wire.

| Field | Meaning |
| --- | --- |
| `MAX_VERDICT_BATCH` | `200` — Coriqo 422s an over-cap batch, so the cap is enforced before the request is built |
| `VerdictShipResult.duplicate` | Coriqo replayed a stored result and sealed nothing new |
| `VerdictShipResult.stale_mandate_version_count` | verdicts in the batch decided against a version that is no longer current |
| `VerdictShipResult.rejected` | the batch was refused with a `422` and parked |

Verdict events also ride the ordinary ledger-ingest path like every other event,
since that ships the whole chain contiguously. The batch endpoint is the second,
differently-shaped delivery: Coriqo seals **one** governance event per batch,
not one per verdict, because per-verdict sealing serialises on a row lock.

#### Delegated scope attenuation (`byoai.recorder.delegation`)

Two relations get confused with each other, and only one of them narrows scope.
*Nesting* is a sub-run of the same agent — one mandate already covers it.
*Delegation* is agent A handing work to agent B, and for that work B has no
mandate of its own: nobody approved B to act inside A's task.

So B's effective scope for that run is the **intersection** of B's own mandate
with A's effective scope at the moment of delegation, pinned to A's
`mandate_version_id`. Delegation can only narrow. If it could widen, spawning a
sub-agent would be a route to tools the parent was refused — and the easy route,
since a model that has just been denied is one prompt away from asking a helper.
B's standing mandate is untouched; the narrowing lives on the delegated run.

```python
from byoai.recorder.delegation import delegated_gate
from byoai.recorder.governed_tool import use_gate

child = delegated_gate(parent_gate, child_gate)   # intersection, pinned to the parent
with use_gate(child):
    await sub_agent.run(task)
```

`DelegatedGate` subclasses `MandateGate`, so `@governed_tool` needs no separate
wiring, and it *wraps* the child's gate rather than replacing it: suspension,
staleness, the fail-open/fail-closed fork and the unenrolled no-op path all still
decide, and the delegated scope only ever narrows the result.

It also keeps the delegator's gate and asks it first. The pinned scope is a
photograph taken when the delegation happened, and a photograph cannot notice
that the delegator has since been suspended or had its mandate narrowed —
consulting the live parent is what makes a revocation reach the sub-agent within
one refresh interval.

Enforcement and depth attenuate the same way tools do. The `mandate_enforcement`
that decides whether a delegated breach blocks or only flags is the *delegator's*,
and any `enforce` up the chain enforces; otherwise picking a sub-agent still in
observe rollout would be a working route around the parent's mandate. Likewise
`max_delegation_depth` is the tightest limit anywhere up the chain, so a middle
agent's own generous limit cannot loosen the root's.

Two snapshot fields govern it:

| Field | Meaning |
| --- | --- |
| `delegation_policy` | `attenuated` permits delegation; `none` forbids it. Absent or unrecognised is read as `none` — a snapshot that does not say delegation was approved has not approved it |
| `max_delegation_depth` | bounds the chain. `0` forbids delegation outright, `null` leaves the policy as the only gate. A value that was sent and cannot be read as an integer is treated as `0`, so a typo in a payload cannot lift a limit |

A refusal raises `DelegationRefusedError` where the delegation is set up, not at
the first tool call — there is no scope to build, and the integrator wiring the
sub-agent up is the right person to see it.

An **undeclared** delegation — one Coriqo was never told about — gets the empty
scope instead. It denies every tool under `enforce`, which is the same practical
outcome as a refusal, but it is a decision the record can explain rather than a
crash in a spawn path.

**`null` is not `[]`.** `allowed_tools: null` is unrestricted, `[]` permits
nothing, and `intersect_tools` branches on `is None` and nothing else: unrestricted
∩ X is X, and anything ∩ `[]` is `[]`. A falsy check here is how "permitted
nothing" becomes "permitted everything".

#### Rotating or revoking a device key

Rotate a device's key without losing verifiable continuity of the ledger:

```bash
byoai-recorder-rotate-key --key-dir ~/.byoai/recorder \
    --ledger ~/.byoai/recorder/ledger.db --reason rotation
```

The current key cross-signs the new public key, the handoff is sealed into
the ledger as a `KEY_ROTATED` event (the last thing the retiring key signs),
and only then does the on-disk key get replaced. `--reason` accepts
`rotation` (default), `revocation`, or `compromise` — same mechanism either
way, the value just records why for anyone reading the ledger later.
`coriqo-verify` follows a rotation across the key boundary instead of
reporting the device_id change as tampering, and still catches a forged
cross-signature. The preferred way to check it is `--pubkey`: pass the
key that was active at the ledger's very first entry (seq 1) — not
necessarily the device's current key — and `coriqo-verify` walks the whole
rotation timeline live from that starting key, validating every
cross-signature and rejecting a forged or re-rotated (retired-key) handoff
as it goes, without needing every intermediate key spelled out separately.
`--device-pubkey old_device_id=base64key` (repeatable) still exists for the
case where no starting key is supplied at all: without `--pubkey`, a
rotation's cross-signature is checked (if at all) only against whatever key
`--device-pubkey` gives for that rotation's own claimed old device_id, and
is otherwise reported as unchecked rather than failed. Once `--pubkey` is
given, `--device-pubkey` no longer decides anything about rotation
validity — it can only add an informational note if it disagrees with the
key the live timeline walk already established.

---

## Plugins

Unknown `provider` names in any `build_*` config dict resolve through Python
entry points before raising `ConfigurationError`:

| Entry point group | Resolves for |
| --- | --- |
| `byoai.providers` | `llm={"provider": "your-name", ...}` |
| `byoai.caches` | `cache={"provider": "your-name", ...}` |
| `byoai.vector_stores` | `vector_store={"provider": "your-name", ...}` |
| `byoai.semantic_caches` | `semantic_cache={"provider": "your-name", ...}` |
| `byoai.embedders` | `embedder={"provider": "your-name", ...}` |

A plugin package registers `your-name = "your_package.module:factory"` under
the relevant group; `factory(config_dict)` returns the built instance.

---

## What's intentionally *not* configurable

- **Fallback chain depth cap (10 tiers)** — a safety rail against
  infinite/mistaken fallback loops, not a tunable. Build `providers=[...]`
  directly if you need more.
- **Cache-write-failure-must-never-fail-the-request** — `CacheLookup`,
  `SemanticCacheLookup`, and `Runtime._write_back_cache` always swallow
  `ByoAIError` from the cache layer. This is a correctness invariant, not a
  policy choice: a cache outage degrading to "no cache" is always the right
  behavior, never a per-deployment decision.
