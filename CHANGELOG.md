# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(pre-1.0: minor versions may include breaking changes).

## [Unreleased]

### Added
- **Suspension reaches the workers the gate cannot see (TI-25).**
  `MandateGate(on_suspend=...)` (also `mandate_gate(...)` and
  `gate.add_suspend_hook()`) calls your hooks once when a snapshot moves the
  agent into `suspended`, so you can stop your own queue's consumers or
  workflow runs: Redis, NATS, Celery revoke, Temporal cancel. Examples are in
  `byoai.recorder.suspend`; none of those libraries is a dependency. Hooks may
  be sync or async; each one's return, failure or time-out is written to the
  ledger as a `worker_stop_ack` event (new `EventKind.WORKER_STOP_ACK`) with
  when it was called and when it answered. A gate with no hook behaves as
  before.
- `coriqo-mcp` stops the server it started when the agent is suspended:
  SIGTERM to its process group, then SIGKILL to anything left after the grace
  period (`--grace`, else the mandate file's `x-stop_grace_s` extension, else
  5 seconds), and records the exit as a `worker_stop_ack`. An agent already
  suspended at start-up never has its server started. Either way
  `coriqo-mcp` exits with status 3. New flags: `--on-suspend MODULE:FUNCTION`
  (repeatable) and `--on-suspend-timeout`. On the way out, `coriqo-mcp` now
  sends the ledger's unsent entries once more (`Recorder.close(final_ship=True)`),
  so the record of the stop reaches Coriqo in the same run instead of waiting
  for the next one.
- **`coriqo-mcp`: check an MCP server's tool calls against a mandate.**
  `coriqo-mcp --mandate coriqo.mandate.yaml -- <server command>` (stdio) or
  `--http --upstream <url>` (streamable HTTP and SSE). Each `tools/call` goes
  through `MandateGate` and the denial latch; the decision and a SHA-256 of
  the arguments go to the device-signed ledger; a refused call gets an MCP
  error result with the fixed sentence and never reaches the server; under
  `enforce`, `tools/list` shows only allowed tools. Default `mode: shadow`
  refuses nothing. New extra: `byoai-runtime[coriqo-mcp]`. A benchmark test
  measures the overhead; the README quotes the measured numbers.
- The runtime reads `coriqo.mandate.yaml` v1 directly
  (`byoai.recorder.mandate_file`), with the reference reader vendored
  byte-for-byte as `byoai/recorder/mandate_format.py` and a test that fails if
  the copy drifts.
- Mandate snapshots act on `prohibited_tools`, `on_violation`
  (`deny`, `deny_and_halt_run`, `alert_only`) and `environment`
  (`BYOAI_MANDATE_ENVIRONMENT`), and keep `output_inspection` for later. A
  snapshot without them decides exactly as before.
- `VerdictRecorder(checkpointer=...)` and `arguments_sha256` on verdict
  records (added only when a caller passes one).

### Fixed
- A tool on `approval_required_tools` ran at the proxy seam and through
  `@governed_tool` while it waited for approval: `RequireApproval` is neither
  an `Allow` nor a `Deny`, and both seams treated anything that was not a
  `Deny` as allowed. Both now refuse the call, report the request once, and do
  not latch it.

### Changed
- **Behaviour change: in the default `redact` mode a detected secret now stops
  the send (`403`) instead of being replaced.** Shield's policy has a new
  `actions` map (`secret`, `pii`, `flag`, each `block`, `warn`, `redact` or
  `log`; defaults `block`, `redact`, `log`). The strictest action of a
  message's hits wins, `observe` logs everything, and lowering a tier needs
  `"acknowledge": "less_private"`. `credential_assign` always warns. Three
  rules, `executable_masquerade`, `tool_intent` and `password_said`, are
  log-only now. Placeholders are numbered per message (`[EMAIL_1]`) instead of
  `[redacted-email]`.

### Added
- Gemini and Copilot can be turned on in Shield (`input_only_apps` in
  `/api/policy`): the input gate checks what is sent and attached there, though
  their traffic still can't be read. Settings says so.
- **Extension 0.10.0: an input gate.** Wrapping the page's network calls can't
  reliably stop a send (claude.ai sent through a hidden iframe's own `fetch`,
  then retried with other body types), so the message and the files are now
  checked when the user hands them to the page: Enter (not Shift/Alt/Ctrl/Cmd,
  not during IME composition) or a click on send in the compose box, a form
  submit, a picked file, a drop and a paste. The listeners run in the
  extension's isolated world, in the capture phase from `document_start`, so
  they run before any page handler and the page can't patch or read them. They
  use the same rules, `actions` and `files` policy as the network wrapper
  (`block` stops the event and shows a notice; `warn` shows the bar, and
  *Send anyway* / *Upload anyway* re-dispatch once through a one-shot flag;
  `redact` rewrites the box so the app sees the placeholders; a file that is
  blocked or removed never reaches the app's uploader). The network wrapper
  stays as the backstop. Gemini and Copilot get the gate too: the first
  protection for them beyond a record. New files: `shield-core.js` (the rule
  engine both worlds load, moved out of `content.js`), `sites.json` (message
  box, send button and file input selectors per app; the gate falls back to
  generic ones) and the generated `shield-sites.js`. Browser rows for sends and
  files now carry `stage` (`input` or `network`), and the network wrapper adds
  the `gate_id` of a send the gate just decided so the two rows can be matched;
  the Shield server accepts both. Text and files are read in the isolated world
  for rule names, counts and hashes only.
- **Shield for your own chat app.** New `byoai.shield_guard` (`check(body, files=)`
  returns `allow`, `warn`, `redact` or `block` with rule labels, redacted body and
  per-file facts) over the existing rules. `byoai-cache` gains an opt-in guard,
  `BYOAI_SHIELD_GUARD=off|observe|enforce` (default `off`), on `/v1/messages`,
  `/v1/chat/completions` and `/v1/responses`: `403` `coriqo_shield_blocked` in the
  provider's error shape, redacted bodies forwarded, streaming untouched, and a
  `shield_guard` recorder row without text. Also `byoai.shield_guard.fastapi`
  middleware and a plain-JS Express example in `examples/shield_guard_express/`.
- **Shield file evidence.** A per-app `files` policy (`allow`, `warn`, `block`;
  default `allow`; lowering needs `acknowledge: less_private`) applies to every
  uploaded file. Text-like files up to 5 MB are also read by the existing rules.
  The desktop proxy hashes each multipart file part (or an upload-path body)
  and records `desktop.chat.attachment` with `sha256`, `name_hash`, `scanned`,
  `flags` and `rules_version`; these rows are now shown and sealed. `warn`
  blocks there. `rules_version` is written into `shield-rules.js` by the
  generator. New `byoai shield check-file <path>` prints hash match, rules
  reproduce and seal verifies. `sha256` never syncs. Shield gains a Files
  setting per app and shows type, size, hash and "Not scanned" on file rows.
  The browser extension (0.9.0) does the same in the page: it recognises
  uploads by shape (a `FormData` with a file, claude.ai `wiggle/upload-file`,
  ChatGPT's pre-signed PUT to `*.oaiusercontent.com`, which it now watches over
  `XMLHttpRequest` for uploads only), hashes and checks the file, and asks first
  on `warn` (*Remove file*, *Upload anyway*, *Cancel*). `browser.chat.attachment`
  rows gain `sha256`, `scanned`, `flags`, `rules_version` and `verdict`, plus
  the raw `name` for the local Shield to hash and drop (see the extension's
  PRIVACY.md). Telemetry blobs (`/api/v2/rum`) and ChatGPT's `prepare` and
  `realtime` calls no longer count as attachments or unrecognised sends. The
  desktop proxy also treats ChatGPT's file-storage PUT as an upload.
- Extension 0.9.5: FormData chat bodies are checked (their text fields, redacted
  in place), a Blob body that can't be read is refused rather than sent, and
  the page can read `window.__shieldVersion` to confirm which build a tab runs.
- **Extension 0.9.4: a refused message can't be resent another way.** Found
  live: after Shield refused a message, claude.ai resent it with a stream
  body, which the extension let through unread. Stream, byte and
  URLSearchParams bodies on chat endpoints are now read and checked, a body
  that can't be read is refused while Shield governs the app, and chat sends
  over `XMLHttpRequest` get the same decision as over `fetch`.
- Extension 0.9.3: a blocked message now says why ("Shield stopped this
  message: it contains an AWS access key. It wasn't sent"), where before the
  app just put the text back in the box. ChatGPT's `sentinel` and `bazaar`
  calls no longer trip the "Shield may be out of date" check. After reloading
  or updating the extension, refresh open Claude and ChatGPT tabs: a tab
  opened before the reload keeps the old code until it is refreshed.
- **Extension 0.9.2: sends through a hidden iframe are checked too.** claude.ai
  sent a message through a same-origin `about:blank` iframe's native `fetch`,
  so it went out past every rule (the page's own wrapped `fetch` saw and
  refused a first attempt). Same-origin frames now get the page's `fetch`,
  `XMLHttpRequest` and `sendBeacon` wrappers: when their `contentWindow` or
  `contentDocument` is read, when they're added to the page, when
  `window.open` returns them, and when the extension runs in them
  (`all_frames`, `match_about_blank`). Requests made from web workers are
  still not checked.
- Extension 0.9.1: after Shield stops, removes or cancels a file, the page shows a
  notice that it wasn't uploaded (claude.ai and ChatGPT keep showing the file as
  attached after its upload fails).
- **Shield browser extension 0.8.0: a warn bar, health events and attachment
  facts.** A tier set to `warn` holds the send behind a bar in the page (send
  redacted, send anyway, cancel; 60 s without an answer cancels, and the
  original is never sent on a timeout). The desktop proxy has no UI in another
  app, so it treats `warn` as `redact`. Unrecognised send-looking POSTs (three
  in ten minutes, none inspected) emit `browser.health.unmatched` /
  `desktop.health.unmatched` and the popup says Shield may be out of date. A
  file attached in the page is recorded as `browser.chat.attachment` (type and
  size only in 0.8.0; hashed and checked from 0.9.0).
- **Desktop proxy: new app toggles, off by default.** `github_copilot`,
  `mistral`, `deepseek`, `groq`, `openrouter`, `together` and `gemini_api`.
  Fixtures come from public API documentation and are untested against live
  traffic. Cursor, Windsurf and Perplexity are not covered. Host matching is
  now exact or on a dot boundary instead of a substring.
- **Shield records which tools the AI ran for a browser reply.** Web search,
  code, connectors and memory run on ChatGPT's and Claude's own servers after
  the message has left, so no browser or proxy can stop them; until now they
  were invisible too. The extension (0.7.0) reads a copy of the reply stream
  as it arrives, keeps only tool names (`web.run`) and how many sites a search
  returned, and files a `browser.chat.reply` row. Shield attaches it to the
  message it answers, seals it with that message, and shows it as "Web
  search", "Code run" and so on in Activity and the detail view. Verified
  against ChatGPT's live stream; claude.ai's Anthropic-style tool blocks are
  read the same way.
- **The Shield browser extension (0.6.0) now replaces personal details
  before a message leaves the page.** Before this, *Replace personal details*
  and *block* only reached traffic that went through the desktop capture
  proxy; a message typed into ChatGPT or Claude in Chrome went out unchanged
  and was recorded as a length only, with no rule hits. On claude.ai and
  chatgpt.com the page capture now runs the proxy's own rules on the message
  fields of the send (`prompt`, `messages[].content` including ChatGPT
  `parts`, `input`) and, per the paired Shield's `GET /api/policy`, rewrites
  them (`redact`), also stops credential text or executable names with a
  `403` (`block`), or leaves them alone (`observe`, or an app switched off).
  Browser rows now carry `flags`, `redactions` and `verdict`, rule names
  only; `clean_browser_row` keeps just known names, and the Shield screen
  shows browser sends as redacted, stopped or flagged like desktop ones.
  The rules ship as `shield-rules.js`, generated by
  `scripts/gen_extension_rules.py` and checked against the Python rules by a
  test; `tests/fixtures/shield_redaction_cases.json` is run against both
  sides. Gemini and Copilot are still record-only in the browser, and
  Shield's Settings and the extension popup now say so. The consent version
  goes to 2, so an upgrade asks again before anything is rewritten.
- **Shield managed mode (Phase 1 of the MSP plan).** An enrolled Shield can
  now be put under central policy: it polls `POST /v1/shield/policy` (signed
  like the existing checkpoint post) every 10 minutes, at start, and on
  "Send now"; verifies the signed envelope (Ed25519 over the canonical
  document, tenant match, device null-or-own, version newer than what's
  applied, a pinned signing key) and stores it at
  `~/.byoai/shield/managed_policy.json`. Locked settings in the document
  override the local choice everywhere Shield reads policy; everything else
  stays the device's own. `POST /api/policy` refuses a change to a locked
  key with `409 Set by <managed_by>`; `GET /api/policy` reports
  `managed: {by, version, locked, fetched_at, error}`. A signed
  `policy: null` document unmanages the device. Every failure mode (bad
  signature, wrong tenant/device, rollback, unknown signing key, or just a
  failed poll) keeps the previously applied policy — never fail-open. The
  signing key is pinned from the enrolment response, or (already-enrolled
  devices) fetched once from `GET /api/v1/checkpoints/public-keys`. The
  Settings screen shows a "Managed by …" banner and disables locked
  controls. Every checkpoint/heartbeat now also reports its applied
  `policy_version` in the `shield` block, so drift is visible from Coriqo.

- **Self-hosted Shield server (Phase 1.5 of the MSP plan).** A free,
  single-org control plane, `byoai.shield_server` (`create_app(config)`) and
  the console script `byoai-shield-server` (`serve` / `mint-token` /
  `admin-token`), install via `byoai-runtime[shield-server]`. It speaks
  Phase 1's exact wire protocol — enrolment, device-signed checkpoints, the
  signed policy poll, and the public-keys endpoint — so the released
  `shield_publish.Publisher` enrols and reports to it with **no code
  changes**, only a different address. Own storage: single-use enrolment
  tokens (hash-only at rest, revocable, expiring), an append-only signed
  policy table (one monotonic version per org, `unique(version)`, a
  `threading.Lock` around every write), and per-device shield state; reuses
  `byoai.ingest.IngestStore` for enrolments and checkpoints and mounts the
  existing read-only `/v1/console/*` fleet router and the built console
  behind the admin bearer token. Deleting a device's policy override
  re-issues the org default at a fresh version (or a signed `policy: null`
  with no default), so a device never receives a version lower than one it
  already holds — the same override-delete-reissue rule Coriqo's Phase 1
  keeps. Proven against the real client: an integration test runs
  `shield_publish.Publisher` against `create_app()` over an httpx ASGI
  transport through the whole lifecycle (enrol, publish, admin sets policy,
  device polls and applies it with no drift, revoke, refusal state).

- **Enforced budgets (AD-11).** Three new mandate fields —
  `max_run_cost_usd`, `max_calls_per_minute`, `max_run_steps` — checked
  entirely locally in `decide()`, no I/O, alongside suspension. A breach is
  an ordinary `Deny` (reasons `budget_cost_exceeded`/
  `budget_call_rate_exceeded`/`budget_step_limit_exceeded`), sealed through
  the same verdict-reporting call every other denial already uses — no new
  endpoint. `max_calls_per_minute` is a sliding 60s window;
  `max_run_steps` counts distinct `step_index` values per `trajectory_id`;
  `max_run_cost_usd` is checked against a running per-trajectory total
  updated via the new `MandateGate.record_actual_cost()` (since `decide()`
  runs before a call and can't know that call's own cost). All three deny
  under both postures and regardless of `mandate_enforcement`, same as
  suspension and approval-required tools.

- **Approval-required tools (AD-10).** A third mandate tier between allowed
  and denied: `MandateSnapshot.approval_required_tools` marks a tool as
  needing a human decision before it may run. `MandateGate.decide()` returns
  a new `RequireApproval` verdict — never a live network wait, per the
  local-only decide() contract — computed 100% from cached state, with a
  `request_id` deterministic on `(tool, trajectory_id, step_index)` so a
  retried identical call resolves to the same pending request. Callers
  explicitly invoke the new `MandateGate.report_approval_request()` after
  seeing a `RequireApproval` (decide() itself stays pure — no I/O), which
  posts to a new `AsyncCoriqoAgentsClient.request_tool_approval()` as a
  best-effort background task. Once a human resolves it in Coriqo, the
  outcome — approve or deny that exact request — arrives in
  `resolved_approvals` on the host's next scheduled mandate-snapshot fetch,
  the same "resume on refresh" shape AD-9's suspend handling already uses,
  rather than any new push channel or blocking wait.

- **Suspend acknowledgement (AD-9).** `MandateGate` now fires an
  `on_suspend_observed` callback the moment a fetched snapshot transitions an
  agent from not-suspended into `suspended` — once per suspend cycle, not on
  every repeat fetch of an already-suspended snapshot. `mandate_gate()` wires
  this to a new `AsyncCoriqoAgentsClient.ack_suspend()` call, posted as a
  best-effort background task so it never blocks `decide()` or the refresh
  loop: Coriqo now shows a specific host as "confirmed stopped" rather than
  only a control-plane "suspended" flag with no evidence any host applied it.

- **The fleet console, served by one Mac.** `byoai-shield` now answers the
  console's read-only fleet API (`GET /v1/console/fleet`, `/fleet/devices`,
  `/fleet/findings`, `/fleet/coverage`) from its own seal chain, so
  `/console/<tenant>/fleet` on :17831 shows this Mac's real ledger instead of
  an empty screen. `byoai.integrations.shield_console` holds the rules: the
  chain is re-walked and the checkpoint signature re-checked on every read —
  the one host where "intact" is produced by the read path, not deferred to a
  verify job — so the Integrity panel gains an optional `local` evidence block
  (Merkle root, entry count, walk time, device id, and where the shipment goes).
  Receiving-side facts (batches arrived, ship lag, countersignatures) are null,
  never zero; the ship backlog is reported only while connected. Browser-relay
  and desktop wall-clock stamps are resolved against the clock that actually
  wrote each seal (`sent_at` is UTC, `wall_clock` is local). The fleet screen
  gained a live auto-refresh chip; the Coverage screen now publishes the
  shell's health dots and its real inclusion denominator instead of falling
  back to "unknown". Contract note: `Device.batches_received` became nullable
  in `web/src/api/schemas.ts`; every server that knows the number still sends
  an int, so no existing backend changes.

- **Devices register — `/console/<tenant>/fleet/devices` (design frame 10).**
  The overview's and the health dots' `Devices →` target is now a real screen:
  one row per enrolled device from the same `/v1/console/fleet/devices`
  contract, sorted quietest-first (never-heard-from above gone-quiet above
  reporting). A seq never renders without its device — the `.seq-scoped`
  token carries the device tail inline — and each liveness and key state
  keeps its own words ("never" is not a zero duration, "unverified — not a
  pass" is not red, the unchecked key note names the missing pubkey rather
  than implying a failure). The register publishes the shell's coverage and
  integrity dots from its own rows; ingest, which the endpoint does not
  carry, is left un-claimed rather than borrowing yesterday's green. Works
  on every host that answers the contract, local Shield included.

- **Findings list — `/console/<tenant>/evidence/findings`.** The `all N →`
  link off the overview now opens the full list: every open finding as a
  `.finding` row — severity dot, the CLI's own plain-language sentence, a
  device link, and its seq/range/session ref rendered through the shared
  `finding.ts` helper so the overview panel and this page can never drift on
  how a finding is addressed. The empty state says which of the two kinds of
  "no findings" you are reading: the local host re-hashed every entry on the
  read that produced the list; a fleet server's empty list can equally mean
  no verify job ran, and an absent check is not a pass. The shell's
  integrity dot published from this page keeps the same rule — an empty list
  reads `unknown`, not green, because the list cannot tell a clean walk from
  no walk.

- **Mandate verdict stream — `GET /v1/console/verdicts` and
  `/console/<tenant>/mandate/verdicts` (spec §6.5).** The `mandate stream →`
  link off the denial panel now opens a real screen. On this host every
  sealed interaction already carries its outcome, so the stream is the ledger
  read by decision: a stop is `denied`, a rule hit that still passed is
  `flagged`, the rest `allowed`, each addressed by device·seq. The posture
  banner is read from the live (managed-locked) policy mode, and
  `observe_flagged` is the whole value of observe — "N actions would have
  been stopped" — sent as `null` under enforcement rather than a `0` that
  would claim a counter that mode never runs. `latches` groups repeat denials
  after a first, the fact a flat verdict table hides. The page's shell dot
  says "observing" or "enforcing" from what the stream read, and the empty
  window is silence, not a clean pass.

- **Ledger and sealed-entry detail — `GET /v1/console/ledger`,
  `GET /v1/console/entries/<device_id>/<seq>` and their screens.** The rail's
  Ledger opens the sealed record itself, newest-first and cursor-paginated by
  chain height (the cursor is the oldest seq shown, so an entry sealed
  mid-browse cannot shift the page under the reader). `head()` and
  `missing_ranges()` are computed by the read that answers the request — a
  contiguous ledger is a result, not a stored claim, and the off-scope gap
  banner can only stay silent because the walk that just ran proved there is
  nothing to show. `sessions`/`trajectories` answer `null` on this host: they
  are ship-side rollups a single Mac does not compute, and an empty list
  would claim an answer it cannot give. Every `device·seq` link across the
  console (findings, register, verdict stream, latches) now lands on the
  entry page: the payload verbatim — no message text was ever sealed, the
  fingerprint keyed to the device — its Merkle fold path with sibling steps,
  the signed checkpoint's coverage of that height, and the portable
  offline-verifying receipt at `/api/receipt/<seal>`. A wrong device says
  "this host holds no ledger for that device"; a seq beyond the head says "a
  sealed entry is never absent" — the two absences are different facts and
  the endpoint names which.

- **Runtime (proxy) — `/console/<tenant>/runtime` on the cache host, spec
  §6.6.** The last section of the rail that reads a different API: the
  proxy's own `/v1/stats*` and `/v1/toggle`, fetched outside the fleet
  contract but through the same schema-validating client (a `base` option in
  `apiFetch`, not a second fetch stack with weaker rules). Two blocks side
  by side: *Estimated* wears the API's own "do not cite" warning
  permanently — the methodology string renders as first-class UI, never a
  tooltip — and *Tokenizer-verified* shows the durable totals with the
  percentage muted and caveated inline while `sample_count` is too small to
  support a rate. History is small multiples per model (one point per
  sampled request, oldest → newest), because variance must be visible before
  an aggregate is trusted; `retention_days: null` reads "all time — no prune
  has run in this process", never zero. The optimizer toggle is optimistic
  with explicit rollback and a stated failure. And because three hosts serve
  one build, the screen classifies a 404 as a fact about the host: Shield
  and the org server answer "Not the proxy" honestly instead of rendering a
  wall of zeros that would read as a quiet proxy.

- **Enrollment — `GET /v1/console/enrollment` and
  `/console/<tenant>/settings/enrollment`.** The blind-spot's counterpart
  screen: the overview says an unenrolled device is invisible, and this
  closes the loop by showing what *this* Mac's enrolment actually is — the
  organisation it ships to (or "not enrolled — nothing leaves this Mac"),
  the ship line's real state from the publisher (enrolled at, last send as a
  duration, next attempt with `0` normalised to *never*, unsent entries only
  while connected, the refused-device flag, the last error verbatim), the
  managed policy if any, and the invariant-4 sharing disclosure computed
  from the **effective** level — so a hand-edited local `sync: events` in
  policy.json, which the managed merge already collapses back to `seal`,
  cannot open a disclosure hole through the console either. The privacy-first
  claim is rendered as evidence, not assertion: ledger rows, rows still
  carrying text, sealed-with-text count, and the real file paths, all read
  from disk at request time.

### Fixed
- **A failed browser send marked the wrong message.** The status row walked
  the feed oldest-first, so a send that failed marked the oldest message to
  that app as failed instead of the newest.
- **Browser sends showed in UTC, and each one was listed twice.** The
  Shield screen showed a browser message at the extension's UTC stamp
  (18:18 for a message sent at 13:18 in Chicago); it now shows this Mac's
  local time, like every other row. The seal still binds the UTC stamp, so
  earlier browser rows aren't sealed again on restart; the fleet console
  and fleet sync read feed items as local time for every source, and only
  sealed payloads as UTC for browser rows. And the extension's
  Enter/click fallback, meant for sends that don't go over `fetch`, filed a
  second length-less row for every send the page capture had already
  recorded; the relay (extension 0.6.1) now holds the fallback row for up
  to 5 seconds and drops it when the page capture reports the same send.

## [0.1.0a7] - 2026-08-26

### Added
- **The console is served by the package.** `pip install byoai-runtime` then
  `byoai-cache console` serves the operator UI at
  `http://localhost:8787/console/` — one process, one port, no Node toolchain
  at the user's end. Built assets ship inside the wheel; a source checkout
  without a front-end build gets a 503 naming the build command rather than a
  404 or a blank page.
- **`/v1/console/*`** — a read-only HTTP surface over `byoai.ingest`, mounted
  into the proxy app behind the same auth gate as the rest of the API. The
  console now reads real shipped evidence instead of fixtures.

### Fixed
- **`pip install "byoai-runtime[agent-context-cache]"` produced a CLI that
  could not start.** `main.py` imports `..recorder.proxy_gate` at module scope
  for out-of-mandate denial, and that reaches `cryptography`, which lived only
  in the `recorder` extra — so `byoai-cache` raised `ModuleNotFoundError` on
  every invocation. Broken since the proxy gate landed and never caught,
  because nothing ever installed the built wheel and ran it. Found by doing
  exactly that while cutting this release.
- **The build no longer ships a console with no assets.** `build.yml` ran
  `python -m build` with no front-end step while `console_static/` is
  gitignored, so a released wheel would have installed cleanly and then 503'd
  the moment anyone opened the console. The release build now compiles the
  front end and fails outright if the assets are absent — an asset-less wheel
  that installs fine is worse than a build that stops.
- **`web/src/lib/` was never committed.** A bare `lib/` pattern inherited from
  the Python gitignore template silently matched it, so three source modules
  were skipped by `git add -A` without a word and the front end could not be
  built from a clean clone.
- **`byoai-cache status`/`console` report where the proxy actually is.** Both
  printed a URL derived from the current invocation's flags, so
  `start --port 9000` followed by a bare `console` handed you `:8787`.
- **The ingest rate chart stopped losing its last minute.** An entry received
  exactly at the window end fell one past the final bucket; since the window
  ends at *now*, this hit most requests and produced a false dip in the one
  chart used to spot a stalled recorder.

### Changed
- Device-side facts the ingest side cannot see — backlog, pending
  checkpoints, oldest unshipped — are reported as `null` rather than `0`, and
  the console renders them as unknown. Zero would have claimed "nothing
  outstanding" from data nobody has.

## [0.1.0a6] - 2026-08-26

### Added
- **Ingest read model (`byoai.ingest`).** `recorder/shipper.py` posted signed
  batches outward and nothing read them back, so there was no way to ask which
  enrolled devices had reported and what was missing. `IngestStore` is that
  side: a tenant-scoped store of accepted evidence plus the enrolment records
  needed to notice evidence that never arrived. Tenancy is derived from the
  enrolment that bound a device, never read off the request — batches carry no
  tenant identifier at all. Enrolment is a first-class table because it is the
  only thing that distinguishes a device that went quiet from one that never
  existed. Dedupe is scoped per device (a global `entry_hash` index let one
  device suppress another's evidence), liveness separates evidence from
  contact (an empty or replayed batch is contact, not proof of life), and both
  write paths share one guard so they cannot drift apart again.
- **Console front end (`web/`), not shipped in the wheel.** A Vite/React
  operator UI over the recorder's evidence, currently running against a mock
  API. `packages = ["src/byoai"]` keeps it out of the distribution; it is
  source-only until the HTTP layer between it and `byoai.ingest` exists.

### Changed
- **CI now runs on tags only.** Lint, type-check, docs build and the test
  matrix no longer run on every push or pull request to `main`; they run when
  a `v*` tag is pushed, or on demand via `workflow_dispatch`. This keeps CI
  spend proportional to releases, at the cost of nothing validating `main`
  between them.

### Fixed
- **`publish_session`'s `final_output` now honors `payload_mode` instead of
  always shipping raw.** Every other field `coriqo_agents.py` sends to Coriqo
  — tool call args/results, ledger inputs — was already digest-only, gated by
  `BYOAI_RECORDER_PAYLOAD_MODE`. The run's final decision text was the one
  exception: it shipped as literal, unredacted prose regardless of mode, so
  an agent whose output restated data from a tool result (a name pulled off a
  document, an amount from a transaction) sent it to Coriqo in the clear even
  under `redacted`/`hash-only`. `publish_session` takes a new `payload_mode`
  parameter (default `redacted`, matching the recorder's own default) and now
  passes `final_output` through the new `redact.redact_free_text` under
  `redacted` (masks known secret/PII substrings — email, SSN, credit card,
  API/AWS key — wherever they appear in the sentence; text with no fixed
  shape, like a name, still isn't caught, see that function's docstring) or
  drops it under `hash-only`. Callers should pass their `Recorder`'s
  `payload_mode` through explicitly (see `examples/agent_showcase`).
- **Proxy enforcement now covers the OpenAI-compat bridge.** That handler returns
  before the Anthropic path's enforcement point, so a tenant routing a model
  through `BYOAI_OPENAI_COMPAT_MODELS` got no enforcement at all — silently,
  while everything reported the agent as enforced. Both the buffered and
  streaming branches are gated now, by the same enforcer.

### Changed
- **`@governed_tool(capture_arguments=…)` now defaults to `False`.** A governed
  tool's arguments routinely carry account numbers, customer identifiers and
  credentials, and nothing redacts them yet, so capturing them by default meant
  a package built to produce a defensible record was quietly collecting secrets.
  Opt in per tool once the arguments are known to be safe.
- **`Verdict.__repr__` and `ProposedAction.__repr__` no longer render
  `detail` / `arguments`.** The dataclass-generated reprs put the denied tool,
  its mandate and the call's arguments into any log line, traceback or f-string
  that formatted them — including one an integrator writes back into a model's
  context. `MandateDeniedError` already kept `detail` out of `str()`; this
  closes the same hole on the verdict object itself. Read `.detail` and
  `.arguments` explicitly when logging for an operator.

### Added
- **`publish_session` takes a `redactor` parameter for name-level PII
  redaction.** The default `redact_free_text` only catches fixed-shape
  secrets/PII (email, SSN, credit card, API/AWS key) in a decision's
  `final_output` — a documented, deliberate limit, since general name/address
  detection needs something closer to NER, and bundling a model would add
  real weight (a non-trivial dependency plus cold-start cost) to a path
  meant to add near-zero latency per governed call, with no one choice
  fitting every integrator's accuracy/latency budget. `redact.TextRedactor`
  (`Callable[[str], str]`) is the new pluggable seam: pass your own
  (spaCy, a DLP SDK, a hand-rolled list) to `publish_session`'s `redactor`
  argument for detection beyond the default. Only called under
  `payload_mode=PayloadMode.REDACTED`.
- **Mandate enforcement at the proxy (`byoai.recorder.proxy_gate`).** Every
  `tool_use` block in a model response is now decided by the same `MandateGate`
  `@governed_tool` uses, before the agent sees it — enabled with
  `BYOAI_PROXY_ENFORCEMENT=1` and `BYOAI_MANDATE_AGENT_ID`. A denied block is
  withheld and replaced by a synthesized `tool_result` carrying only the fixed
  `MODEL_MESSAGE`, so the agent's loop handles it as an ordinary tool failure
  and never learns which tool it asked for; if nothing survived, `stop_reason`
  becomes `end_turn`. Streaming holds back only the frames of an unfinished
  `tool_use` block, never the response. Denials route through the same denial
  latch, so a repeat at the proxy counts toward the same halt threshold as one
  through the decorator, and every verdict is recorded through the same
  recorder. This exists because the buyer frequently does not own the agent's
  source, which is all `@governed_tool` can reach — and it covers only tools
  the model requests through the intercepted API, so the two seams are meant to
  run together.
- **`Reason.AGENT_UNRESOLVED`.** A proxy request whose agent cannot be resolved
  has no mandate to decide against, and is now decided by posture — `fail_closed`
  withholds, `fail_open` allows and flags — rather than silently allowing. Never
  latched: a misconfiguration should not halt a run.
- **Verdict recording and batched shipping (`byoai.recorder.verdicts`).** Every
  gate decision — `allowed`, `flagged` and `blocked` alike — is now appended to
  the local hash-chained ledger as a `mandate_verdict` event and queued for
  Coriqo, instead of reaching the integrator's process logs and nothing else.
  Allows are recorded because the denominator is what makes the denial count
  mean anything. The ledger is the authoritative record and shipping is strictly
  downstream of it: a denial is written whether or not Coriqo is reachable, and
  `record()` never raises into a tool call. `MandateGate.decide()` is unchanged
  and still performs no I/O — recording happens at `@governed_tool`'s
  enforcement seam, after the verdict exists.
  A latched repeat is not N identical rows: the first denial records
  `out_of_scope`, the next attempt `repeat_denied` with `attempts: 2`, and the
  one that trips the halt threshold `run_halted` with `halted: true`, with the
  run and the principal alongside them in the local event.
  `VerdictShipper` drains a durable `VerdictOutbox` into
  `POST /api/v1/agent-runtime/agents/{agent_id}/verdicts/batch` in batches of at
  most 200, device-signed; Coriqo seals one governance event per batch. A batch
  is claimed under a persisted `batch_key` before the request goes out, so a
  resend is the same batch. Tool arguments are never part of any of it — the
  record keeps `arguments_captured`, a count, and never a key or a value.
- **`AsyncCoriqoAgentsClient.record_verdict_batch` is retryable**, unlike every
  other write in the client, which stays non-retryable. The objection to
  retrying a write — a resent publish duplicating a governance record — does not
  apply here: `batch_key` is device-chosen and unique per device server-side, a
  repeat replays the stored result with `duplicate: true` and seals nothing, and
  concurrent duplicates race a unique index where the loser gets a `409` asking
  it to retry. `409` therefore joins the retry set for that one call. `422` does
  not: an over-cap batch, a `flagged`/`blocked` verdict with no reason, or a
  verdict naming a mandate version belonging to another agent are statements
  about the batch, so the shipper parks it (keeping the rows, marked `rejected`)
  rather than looping. The cap and the missing-reason case are caught before the
  request is built.
- **Mandate drift is surfaced to the operator.** Coriqo anchors a batch on the
  agent's current mandate version and reports `anchor_mandate_version_id` and
  `stale_mandate_version_count`; `VerdictShipResult` carries both and the shipper
  logs a `WARNING` naming the drift, so a host whose snapshot has aged learns it
  from the response rather than by reading the chain later.
- **`EventKind.MANDATE_VERDICT`**, the ledger event kind the above writes.
- **Denial latch (`byoai.recorder.denial_latch`).** A denial used to stop one
  call and nothing else, so an agent that ignored the refusal could attempt the
  same out-of-mandate tool for as long as its loop ran, and nothing counted it.
  The latch is keyed on `(run, principal, tool)`: the first denial is remembered,
  every later attempt at that tool is refused straight from the latch **without
  re-running the scope check** — the same tool against the same snapshot cannot
  answer differently — and at `BYOAI_MANDATE_HALT_THRESHOLD` attempts (default 3,
  counting the first denial) the run is halted. A halted run refuses every
  subsequent call, in-scope tools included, with `MandateRunHaltedError` (new, in
  `byoai.errors`, subclassing `MandateDeniedError`), so an existing handler still
  stops the call while `isinstance` / `exc.halted` tells a supervising loop "this
  tool is refused" from "this run is over"; `exc.attempts` and `exc.run_id` carry
  the finding. The model-facing string is the same fixed `MODEL_MESSAGE` across
  first denial, repeat and halt — escalating detail as an agent tries harder
  would hand it a hint sheet exactly when it is probing the control — while the
  count and the halt go to the operator `WARNING` and to `LatchedDenial.attempts`
  for the packet that will seal verdicts. The run is `ProposedAction.trajectory_id`,
  else the run bound by `run_scope()`, else a fallback id belonging to the
  `MandateGate`, so unrelated agents in one process never share a bucket and the
  latch is never silently off. Latch state is per-process and in memory: a run
  spanning processes, or a restarted host, starts counting from zero. Only scope
  denials are latched: a suspension, a stale snapshot and a missing one are all
  transient, and remembering them would turn one refresh blip into a permanently
  halted run. A new mandate version clears that agent's buckets, and its halt if
  it was that agent's doing, because that is the one thing that can change the
  answer; it is tracked per agent rather than per run so a delegator and its
  delegated child, which hold different versions, do not wipe each other's count.
- **Delegated scope attenuation (`byoai.recorder.delegation`).** When one agent
  hands work to another, the second has no mandate of its own for that run. Its
  effective scope is the intersection of its own mandate with the delegator's
  effective scope at the moment of delegation, pinned to the delegator's
  `mandate_version_id`, so delegation can only narrow and spawning a sub-agent is
  never a route to a tool the parent was refused. The child's standing mandate is
  untouched. `delegated_gate(parent, child)` returns a `DelegatedGate`, a
  `MandateGate` subclass that wraps the child's gate rather than replacing it —
  suspension, staleness and the fail-open/fail-closed fork still decide, and the
  delegated scope only narrows the result — so `@governed_tool` needs no separate
  wiring. `delegation_policy` must be `attenuated`; `none`, absent or
  unrecognised raises `DelegationRefusedError`, as does passing
  `max_delegation_depth` (where `0` forbids delegation and `null` leaves the
  policy as the only gate). An undeclared delegation gets the empty scope, which
  denies by rule rather than by accident. `intersect_tools` branches on `is None`
  and nothing else: unrestricted ∩ X is X, anything ∩ `[]` is `[]`. The delegated
  gate also keeps the delegator's gate and asks it first, so suspending or
  narrowing the delegator reaches the sub-agent it lent authority to within one
  refresh interval rather than never. `mandate_enforcement` and
  `max_delegation_depth` attenuate along with the tools — the delegator's dial
  decides whether a delegated breach blocks, any `enforce` up the chain enforces,
  and the depth limit is the tightest one anywhere up the chain. This applies
  to *delegation* between different agents, not to *nesting* — a sub-run of the
  same agent is already covered by that agent's one mandate.
- **`@governed_tool` (`byoai.recorder.governed_tool`).** The decorator integrators put on their own
  tool functions, and the seam where a mandate denial actually stops something: the gate is
  consulted first and on a `Deny` the wrapped function is never entered. One decorator handles sync
  and async tools, preserves `__name__`, `__doc__` and the signature via `functools.wraps` plus an
  explicit `__signature__`, defaults the tool name to `fn.__name__` and takes `name=` when the
  Python name and the approved name differ. A denial raises `MandateDeniedError` (new, in
  `byoai.errors`, deriving from `ByoAIError`), which is terminal and non-retryable by construction:
  `str(exc)` is the fixed `MODEL_MESSAGE` and nothing else — that string is what agent frameworks
  feed back into the model — while the tool, mandate version, staleness and reason live on
  `exc.verdict` / `exc.operator_detail` and in a `WARNING` logged on the raising path. `retryable`
  is `False` and there is no `retry_after`, so it cannot be mistaken for a transient provider error.
  A `Flag` still runs the function, which is what `mandate_enforcement: observe` is for. The gate
  is resolved per call from `@governed_tool(gate=…)` (a gate or a zero-argument factory) then from
  `set_default_gate()` / `use_gate()`, held in a `ContextVar` so two agents in one process do not
  share a mandate and tests do not leak bindings. With no gate bound, or a no-op gate from an
  unenrolled host, the decorator runs the function and logs one line.
- **Local mandate enforcement (`byoai.recorder.mandate`).** `MandateGate.decide()` answers whether
  a proposed tool call is inside the agent's approved scope from a cached snapshot, with no network
  I/O on the decide path — an agent whose availability depended on a governance service's is not
  one a bank ships. The snapshot refreshes on a background interval of half the per-agent
  `max_staleness_s`, handles Coriqo's `304` as "unchanged, still fresh", and survives a failed
  refresh with the cached snapshot intact, so a blip cannot become an outage. Verdicts are `Allow`,
  `Flag` (allowed and recorded, which is what `mandate_enforcement: observe` is for) and `Deny`,
  each carrying `reason`, `mandate_version_id` and `snapshot_age_s`; a `Deny` is terminal and its
  `model_message` is one fixed sentence, because a denial that explains itself is a hint sheet for
  routing around the control. `enforcement_posture` (`fail_open`/`fail_closed`) governs only the
  cases the gate cannot evaluate — a stale snapshot or none at all — while a suspended agent denies
  under both. `allowed_tools: null` (unrestricted) and `[]` (nothing permitted) stay distinct.
  New env vars `BYOAI_MANDATE_POSTURE` and `BYOAI_MANDATE_MAX_STALENESS_S` cover the window before
  the first snapshot lands. With no Coriqo identity configured the gate is a logged no-op; a static
  API-key identity is refused with `EnforcementIdentityUnavailableError`.
  `AsyncCoriqoAgentsClient.fetch_mandate_conditional()` is the conditional (`If-None-Match`) fetch
  behind it; `fetch_mandate()` is unchanged.
- **Enrollment records the Coriqo tenant.** `byoai-recorder-enroll` takes `--tenant-slug`, and a
  `tenant_slug` in the enrollment response takes precedence over it; either way it is persisted in
  `enrollment.json` and exposed as `CoriqoIdentity.tenant_slug`. An enrolled device can now set
  `X-Tenant-Slug` on signed enforcement requests from its own state, instead of also needing the
  legacy publish-only `BYOAI_CORIQO_TENANT_SLUG` in its environment.
  `AsyncCoriqoAgentsClient` resolves the tenant from an explicit `tenant_slug=`, then the identity,
  then `BYOAI_CORIQO_TENANT_SLUG`, and still refuses a signed call with none of them before it
  reaches the network. An `enrollment.json` written before this change loads unchanged, falls back
  to the env var, and logs one warning per process naming the re-enrollment command.
- **One Coriqo identity resolver (`byoai.recorder.identity`).** `resolve_identity()` returns the
  device-enrolled Ed25519 identity when this host has one, falls back to the static
  `BYOAI_CORIQO_API_KEY` credentials (publish-only, warned about once per process), and returns
  `None` when neither is configured. `CoriqoIdentity.require_enforcement()` is what mandate
  enforcement calls: it hands back a signer for a device identity and raises
  `EnforcementIdentityUnavailableError` for a static key, which cannot sign and, carrying
  `governance:approve`, would let an agent edit its own mandate. Key material stays inside
  `byoai.recorder.keys` — the identity holds a `Signer`, never raw bytes. New errors
  `CoriqoIdentityError` and `EnforcementIdentityUnavailableError` derive from `ByoAIError`.
  `CoriqoCredentials` and `CoriqoAgentsClient` are unchanged.
- **Async, retrying Coriqo client (`byoai.recorder.coriqo_async`).** `AsyncCoriqoAgentsClient`
  mirrors the synchronous client on `httpx.AsyncClient`, for the mandate-enforcement path: a
  runtime that refreshes a cached policy snapshot on a background interval can't block its event
  loop for a round trip, and shouldn't read one transient blip as a failed refresh. `RetryPolicy`
  retries 429/502/503/504 with exponential backoff and jitter and honours a server-sent
  `Retry-After` (and the `retry_after` on a `RateLimitError` from a transport hook) — but only for
  idempotent reads. Writes are sent once: a resent trace or verdict is a second decision in the
  record. The one opt-in exception, `RetryPolicy(retry_writes=True)`, covers `register_agent` with
  an `external_id`, which is Coriqo's own idempotency key.

  Enforcement calls (`fetch_mandate`, `record_verdict`, `record_signed_trace`) authenticate with
  the device key from `resolve_identity()` and never send `X-API-Key`, signing each attempt over
  canonical JSON of `{body_sha256, method, path, public_key, timestamp}` with the query string in
  the path and the signer's own key inside the signed bytes. A static-key identity raises
  `EnforcementIdentityUnavailableError` at the client. Errors keep the sync contract:
  `CoriqoAgentsError` with `status_code`/`detail`, `AgentSuspendedError` on 423.

  The synchronous `CoriqoAgentsClient` is unchanged.

- **`byoai.recorder.keys.load_device_key()`** — the load-only half of
  `load_or_create_device_key()`, returning `None` instead of minting a keypair when the directory
  has no key. It still reconciles an interrupted rotation first, so a confirmed staged key is
  promoted rather than reported absent.

### Changed
- `CoriqoAgentsError` now derives from `ByoAIError` as well as `RuntimeError`, so one
  `except ByoAIError` covers every runtime failure. Existing `except RuntimeError` code keeps
  working.

## [0.1.0a5] - 2026-08-14

### Added
- **Agent recorder (`byoai.recorder`, opt-in).** With `BYOAI_RECORDER_ENABLED=1`, `byoai-cache`
  seals every `tool_use`/`tool_result` pair the agent exchanges with the model into a local
  hash-chained SQLite ledger, signed in checkpoints by a device-held Ed25519 key. It tees bytes
  that have already been forwarded, so it never blocks or delays the token stream, and a recording
  failure is logged rather than failing the request unless `BYOAI_RECORDER_STRICT=1`. Ships behind
  its own extra: `pip install --pre "byoai-runtime[recorder]"`.

  New console scripts: `coriqo-verify` (offline verification — re-derives every hash from the
  stored ledger rather than trusting it, catching a tampered row, a deleted one, or a forged
  checkpoint signature), `byoai-recorder-enroll`, and `byoai-recorder-rotate-key` (rotates a
  device key with cross-signed continuity, so the handoff is itself sealed into the chain).

  `BYOAI_RECORDER_PAYLOAD_MODE` chooses what payload bytes reach the ledger — `hash-only`,
  `redacted` (the default; masks detected secrets and PII), or `full`. `payload_hash` always
  commits to the raw, unredacted payload regardless of mode, so redaction never weakens the
  evidence. Events carry `trace_id`/`span_id`/`parent_span_id` attribution, so a ledger holds
  enough lineage to reconstruct sub-agent trees and resumed sessions without changing the chain's
  flat, append-only shape.

- **Publishing runs to Coriqo's agent API (`byoai.recorder.coriqo_agents`).** Registers an agent
  with a Coriqo instance and publishes each recorded run as a trajectory plus one decision trace
  per sealed step, so Coriqo holds the agent registry, the mandate each agent may act under, and
  its own hash-chained trail of what the agent did.

  Two properties make what lands there evidence rather than telemetry: steps are read back out of
  the sealed ledger (nothing is published that wasn't recorded first), and each step's
  `args_hash`/`result_hash` are the ledger's own `payload_hash` values, with the row's
  `entry_hash` cited as an external grounding anchor. Both stores therefore commit to the same
  bytes — a hash off a Coriqo trace resolves to the sealed row behind it, and `coriqo-verify`
  still checks the ledger offline. Only digests cross the wire, never raw payloads.

  Nothing here runs automatically: session boundaries and agent identity are application concepts
  the recorder can't infer, so the caller drives it. Configured with `BYOAI_CORIQO_URL`,
  `BYOAI_CORIQO_API_KEY`, and `BYOAI_CORIQO_TENANT_SLUG`; unset means nothing is published.

- `Ledger.read_session()` — reconstructs one run from the ledger by `session_id`, replacing the
  hand-rolled SQLite query callers were otherwise writing.

- **`examples/agent_showcase`** — a runnable demo of nine banking and healthcare agents with a
  UI, live Anthropic/OpenAI calls (falling back to recorded transcripts when a key is absent),
  sealed replay, a tamper demo, and end-to-end Coriqo publishing. Serves on port 8001, since a
  local Coriqo API binds 8000.

### Fixed
- Recorder key revocation could be bypassed: stale-key detection gated on the device-controlled
  `ts_device` field, which the schema itself documents as untrusted, so a device could keep
  signing with a revoked key and backdate `ts_device` to slip past detection. Detection now keys
  off the `KEY_ROTATED` event's own trusted `seq`.
- `rotate_key()` promoted a staged key with two non-atomic `os.replace` calls, leaving a crash
  window with no live private key — after which key loading would silently generate a brand-new
  random orphan identity. Promotion now resolves deterministically to either the old or the new
  key after a crash at any point, never a third one.
- The `record_failure` marker inherited the `session_id` of whichever dropped event happened to
  be last in a batch, mislabelling earlier sessions' drops; it now uses a device-level sentinel.
- `byoai-recorder-enroll` crashed with a raw traceback when the on-disk device key was truncated
  or corrupt, instead of the clean `enrollment failed: …` exit — which is precisely the situation
  someone runs the command to recover from.
- Recorder robustness: `extract.py` no longer silently drops `tool_use` input when a delta arrives
  before its content-block start (it emits a parse-failure marker instead); the shipper no longer
  advances its watermark past server-rejected checkpoints; and Rekor audit-path reconstruction is
  iterative rather than recursive, so an adversarial `hashes` list can't exhaust the stack.

### Changed
- **Docs correction.** README and CONFIGURATION described the recorder's device ledger sync
  (`/v1/enroll`, `/v1/ingest/batch`) as an available feature. No Coriqo serves those endpoints —
  the client is built against the spec and exercised only against the mock server under
  `tests/recorder/`. Both documents now say so, and point at the agent API above as the
  integration that works today.

## [0.1.0a4] - 2026-08-10

### Fixed
- `SessionDedup` could replace an agent's task prompt with a dedup placeholder. It hashed every
  user-turn `text` block over 2,000 chars, but such a block is the *instruction*, not a file
  snapshot — a long prompt sent through the proxy came out the other side as
  `[byoai-runtime: Duplicate file snapshot detected (SHA: ...)]` and the model never saw the task.
  Dedup now considers `tool_result` blocks only and never rewrites user text.
- Dedup is no longer keyed on cross-request session state, which made it non-idempotent: the hash
  was recorded on first sight, so resending an identical body had the *second* copy collapsed. A
  client retrying a failed call therefore got a gutted request, and the failure looked like the
  environment was eating prompts. Occurrences are now compared within a single request body, so
  an identical resend produces an identical upstream request. This also makes the placeholder's
  claim true by construction — the surviving full copy is always present in the same request,
  where the old wording could point at content the model could no longer see.

  Consequence: `REDIS_URL` and `BYOAI_SESSION_TTL_SECONDS` no longer influence dedup. The hash
  stores are unchanged and still exported; dedup simply doesn't consult them.

## [0.1.0a3] - 2026-08-07

### Fixed
- Capped the core dependency at `httpx>=0.25,<1.0`. Installing an alpha requires `pip install
  --pre`, and `--pre` allows pre-releases for *every* package in the resolve, not just this one —
  so the uncapped requirement pulled `httpx 1.0.dev3`, whose API no longer has `httpx.Timeout`.
  A clean `pip install --pre "byoai-runtime[agent-context-cache]"` on 0.1.0a2 therefore installed
  a `byoai-cache` that raised `AttributeError` on import. Same hazard applies to any dependency
  that publishes a pre-release; this is the one that bit.

## [0.1.0a2] - 2026-08-07

### Fixed
- Docs told you to install the `byoai-cache` proxy with a bare `pip install byoai-runtime`, which
  produces a console script that fails on import: the proxy needs FastAPI, uvicorn, and redis, and
  the base package depends only on `httpx`. The correct install is
  `pip install --pre "byoai-runtime[agent-context-cache]"`, now used in the README, CONFIGURATION,
  and the getting-started extras list (which was also missing the `flask` and `agent-context-cache`
  extras entirely).

### Breaking
- Removed `Runtime(cache_ttl=...)`. TTL is now configured in exactly one place —
  `cache={"default_ttl": ...}`, or the matching arg on a pre-built `CacheStore`.
  `MemoryCache`/`RedisCache` now default `default_ttl` to `3600` (was `None`), so a cache
  built with no `default_ttl` no longer caches forever by accident.

### Added
- `BYOAI_RETENTION_DAYS` (default `90`) caps how long rows live in the proxy's durable SQLite
  log, applied once per proxy start. Previously the log was append-only with no ceiling, so the
  file and the unfiltered `SUM()` queries behind `/v1/stats/permanent` both grew with uptime.
  `0` restores the keep-forever behavior.
- `byoai-cache prune [--days N] [--no-vacuum]` applies the retention window on demand, for a
  proxy that has been running for months without a restart. The delete is safe against a live
  instance; reclaiming the freed space is not, so pass `--no-vacuum` (or stop the proxy) if one
  is running — `VACUUM` takes an exclusive lock that WAL mode does not let readers through.

- `docs/guides/testing.md` — testing a `Runtime`-based app without a real API key, Redis, or
  Postgres, using the existing in-process adapters (`providers=`/`vector_store=`/`embedder=`
  bare functions, `cache={"provider": "memory"}`, `MemoryJobQueue`).
- `Message` gained `tool_call_id`/`tool_calls`, completing the OpenAI-compatible tool-calling
  round trip (sending a tool result back). See `docs/guides/providers.md`.
- `MemorySemanticCache`/`RedisSemanticCache` and `PgVectorStore` gained `metric=`
  (`cosine`/`dot`/`euclidean` or `cosine`/`l2`/`inner_product` respectively, plus a custom
  callable for the semantic caches) instead of a hardcoded metric.
- `ProviderRouter`/`Runtime` gained `selection=` (`"ordered"` default, `"round_robin"`, or a
  custom callable) controlling which provider is tried first each call.
- `byoai.integrations.flask` (`attach`/`get_runtime`/`execute`/`stream_response`) — a Flask
  (WSGI) bridge to `Runtime`'s asyncio-native providers via a background event-loop thread.
  Requires the new `flask` extra; see `docs/guides/flask.md`.
- `Runtime.execute()`/`.stream()` gained `system_prompt=` (per-call override) and
  `provider_metadata=` (forwarded into the provider's own request payload, e.g. Anthropic's
  `metadata.user_id`).
- `Message.content` now accepts a list of provider content blocks, not just plain text;
  `ExecutionResult` gained `finish_reason`/`raw`. Anthropic/Bedrock/Vertex handle list-valued
  content today — see `docs/guides/providers.md`.
- `StreamChunk` gained `tool_call`, so a forced-`tool_choice` streaming call now actually
  yields content instead of nothing. Fixed across Anthropic, Bedrock/Vertex,
  OpenAI-compatible, and every transport (`transport.stream_frames()`, FastAPI/Flask SSE).
- `AnthropicProvider`/`AnthropicBedrockProvider`/`AnthropicVertexProvider` gained
  `cache_system=` for Anthropic's server-side prompt caching, and now parse
  `cache_read_input_tokens`/`cache_creation_input_tokens` into `Usage`.
- `providers=`/`vector_store=` now accept a bare async function directly — no class required —
  matching the existing `embedder=`/`Pipeline.add()` pattern.
- `AnthropicBedrockProvider`/`AnthropicVertexProvider` (`llm={"provider": "bedrock"/"vertex"}`)
  — Anthropic models via AWS Bedrock or Google Vertex AI. New `bedrock`/`vertex` extras.
- `PipelineNotFoundError`/`AllProvidersFailedError` — PEP 8-compliant names for the two
  exceptions that lacked the `Error` suffix (old names remain as aliases).
- `Runtime.aclose()` as an alias for `close()`.
- All library-owned HTTP clients send a `User-Agent: byoai-runtime/<version>` header.
- `default_params=` on `OpenAICompatProvider`/`build_openai_client` for query parameters
  applied to every request (how the Azure preset now passes `api-version`).
- Library logging on the `byoai.*` loggers (silent by default via `NullHandler`).
- CI now measures test coverage; the release workflow runs the full test matrix before
  publishing and pins the PyPI publish action to a commit SHA; builds are checked with
  `twine check --strict`.

### Changed
- `InMemoryHashStore` now caps hashes per session (`max_hashes_per_session`, default 5,000,
  oldest evicted first) in addition to the existing session cap, so peak memory is bounded by
  the two caps rather than growing with the length of any single conversation.
- `RedisHashStore` keeps mirroring every add into its in-memory fallback. Skipping the mirror
  while Redis is healthy would save memory, but it makes correctness depend on detecting
  recovery and replaying state between two stores; that was implemented, reviewed, and reverted
  after each edge case (partial failures, per-session vs. store-wide health, TTL expiry,
  concurrent writes mid-replay) turned out to be a way to silently report already-sent content
  as new. The mirror's cost is bounded by the `InMemoryHashStore` caps above.
- README's Quickstart now leads with a minimal "Hello world" example before the fuller
  "Production Setup" one.
- `build_cache`, `PgVectorStore`, `make_redis_client`, and the `azure_openai`/`pinecone`
  provider presets now raise `ConfigurationError` on invalid or missing config (a stale `url`
  left over from switching `provider` to `"memory"`, `min_size`/`max_size` pool kwargs colliding
  with the typed constructor args, `sentinels`/`service_name` given without `mode="sentinel"`,
  missing API keys) instead of silently ignoring it or failing later with an opaque error.
- `transport.parse_payload` raises `ConfigurationError` when a top-level field (e.g. `model`)
  collides with the same key inside `options`, instead of letting `options` silently win.
- `OpenAICompatEmbedder.embed_batch()` reorders responses by each item's own `"index"` field
  instead of trusting response order, fixing a silent vector/text mismatch against backends
  that return embeddings out of request order.
- README's vector-database list now only lists adapters that actually ship (pgvector,
  Pinecone, Qdrant), with a pointer to the `byoai.vector_stores` plugin mechanism for the rest.
- `Pipeline.remove()`/`.replace()` accept `name=` to target one stage among several of the same
  `stage_type`. Calling either with no matching criteria now raises `ConfigurationError`
  instead of silently matching nothing.
- Documented two known `RedisStreamQueue`/`RuntimeWorker` gaps in `docs/guides/workers.md`: no
  reclaim (`XCLAIM`/`XAUTOCLAIM`) for a crashed consumer's pending entries, and `RuntimeWorker`
  doesn't own or close the queue's connection.
- CI now gates on `pyright` (previously advisory); fixed ~60 pre-existing type errors this
  surfaced, mostly Optional-narrowing gaps in the Redis-backed adapters.
- `AnthropicProvider`/`GeminiProvider`'s construction-time API-key check now only backs off for
  an actual auth header in `default_headers=`, not any unrelated header.
- `PgVectorStore.search()` offloads embedding-literal construction to a thread above 1024
  dimensions, avoiding event-loop stalls on large vectors, and hoists invariant SQL parts out
  of the per-call query string.
- Version is now single-sourced from `src/byoai/_version.py` (`pyproject.toml` reads it
  dynamically), so `byoai.__version__` can no longer drift from the published package version.
- Robyn integration maps runtime errors to real HTTP statuses (`400`/`404`/`429`/`502`) instead
  of a blanket `422`.
- `AnthropicProvider`/`GeminiProvider` raise `ConfigurationError` at construction when neither
  an API key nor `default_headers` are supplied, instead of failing later with a 401.
- `Retry-After` headers in RFC 9110 HTTP-date form are now honored, not just delay-seconds form.
- pgvector filter compiler binds metadata field names as query parameters instead of splicing
  them into SQL text.
- OTel spans use GenAI semantic-convention attribute keys (`gen_ai.*`) — dashboards filtering on
  the old ad-hoc keys (`provider`, `model`, `input_tokens`) need updating.
- `MemorySemanticCache` runs its similarity math in a worker thread past 4096 entries.
- `ExecutionResult.context`/`RequestContext.documents` are precisely typed; `Runtime`'s
  `embedder=`/`semantic_cache=` are typed against their protocols.

### Fixed
- `ProviderRouter.complete()`/`.stream()` pass a shallow copy of `self.providers` to a custom
  `selection=` callable instead of the live list, so an in-place-mutating callable can no
  longer corrupt the router's provider order for every future call.
- `Runtime`'s non-cosine-metric threshold guard now reads the semantic cache's actually-resolved
  metric instead of re-deriving a `"cosine"` default, fixing a silent always-miss for
  plugin caches whose default metric isn't cosine.
- `RuntimeWorker._process()` no longer silently swallows an exception from
  `queue.push_result()`/`.ack()` raised after the runtime already answered; now logged and
  counted via the new `RuntimeWorker.errors`.
- Streaming adapters (OpenAI-compatible, Anthropic, Gemini) now raise `ProviderError` on an
  in-band `error` event mid-stream, instead of silently delivering a truncated generation as a
  clean success.
- FastAPI's `stream_response()` turns a mid-stream runtime error into a clean terminal SSE
  event instead of tearing the connection.
- Azure OpenAI preset passes `api-version` as a real query parameter (previously baked into
  `base_url`, where it broke httpx's path concatenation).
- `byoai.integrations.flask`'s bridge no longer hangs a request thread on shutdown or leaks
  provider connections behind in-flight/abandoned streams. `close()` now cancels pending
  futures, finalizes idle streams concurrently, and bounds total shutdown time to the
  requested `timeout` instead of stacking per-phase timeouts.
- `ContextResolver`'s session-history coercion no longer turns a tool-call-only assistant
  turn's `content: null` into the literal text `"None"`. That turn and its now-unanswerable
  `"tool"` replies are dropped, and adjacent same-role messages are merged at the resulting
  seam so truncation/dropping can't leave a provider-rejected same-role/wrong-starting-role
  history.
- Synchronous `execute()` now catches `concurrent.futures.CancelledError` and wraps it in
  `ByoAIError`, matching `stream_response()`'s existing behavior.
- `stream_response()`'s SSE loop no longer mislabels a genuine empty-message `ByoAIError` as
  `"request cancelled"`.

### Security
- `PgVectorStore` redacts a DSN's embedded password (`postgresql://user:pass@host` →
  `postgresql://***@host`) before a connection failure can leak it into an error message.

## [0.1.0a1] - 2026-07-29

Initial alpha release.

### Added
- Core runtime: `Runtime`, `Pipeline`/`PipelineStage`, `Middleware`, request context, and the
  structured error hierarchy (`ByoAIError`, `ProviderError`, `RateLimitError`, `AllProvidersFailed`, etc.).
- Provider router with fallback/failover, `httpx`-based OpenAI-compatible, Anthropic, and Gemini
  providers, plus an `embedder=` adapter for any OpenAI-compatible `/embeddings` endpoint.
- Cache adapters: in-memory and Redis (standalone/cluster/Sentinel), with namespaced isolation
  from existing application keys.
- Semantic (intent) cache — serve similar, not just identical, queries from cache via embedding
  similarity, in-process (`MemorySemanticCache`) or shared across workers on Redis
  (`RedisSemanticCache`).
- Vector store adapters for pgvector, Qdrant, and Pinecone, including a cross-provider AST filter
  parser and a `VectorRetrieve` pipeline stage for retrieval-augmented generation.
- Plugin system: unrecognized `provider` values for `llm=`, `cache=`, `vector_store=`,
  `embedder=`, and `semantic_cache=` resolve through Python entry points.
- OpenTelemetry tracing (`byoai.telemetry.otel`): one span per execution, per-stage child spans,
  provider lifecycle span events, and OTLP export (gRPC or HTTP) to an existing collector.
- `orjson`-backed hot-path JSON codec (`perf` extra) for lower-overhead request/response encoding.
- FastAPI integration (`byoai.integrations.fastapi`): `attach`, `get_runtime`, SSE `stream_response`.
- Robyn integration, WebSocket transport, and background queue workers.
- MCP integration (`byoai.integrations.mcp`): expose a runtime as an MCP tool server (`execute` /
  `execute_stream` tools) over stdio or streamable HTTP, standalone or mounted into an existing
  FastAPI/Starlette app.
- `CONFIGURATION.md`: authoritative parameter-by-parameter reference across every component.
- Provider adapters gained `retryable_status=` overrides and gateway-friendly path overrides
  (`chat_path=`/`messages_path=`/`embeddings_path=`); the embeddings adapter transparently chunks
  large `embed_batch()` calls via `max_batch_size=`.
- `RuntimeWorker` gained a `shutdown_timeout=` for bounded graceful shutdown;
  `MemoryJobQueue`/`RedisStreamQueue` gained backpressure/trim controls (`maxsize=`, `maxlen=`).
- Benchmark suite for JSON encoding, runtime throughput, and multi-process Robyn scaling
  (72.5k req/s aggregate across 8 processes on the cache-hit path).

### Fixed
- `byoai.integrations.robyn`'s SSE stream route (`POST /byoai/stream`) crashed with
  `AttributeError: 'dict' object has no attribute 'set'` on every call — it passed a plain dict
  as `StreamingResponse(headers=...)`, but Robyn's default-SSE-header code calls `.set()` on it,
  which only Robyn's own `Headers` type supports. Wrapped in `Headers(...)`.
- A malformed (non-JSON) 200 response — e.g. a misconfigured gateway returning an HTML error
  page — leaked a raw `json.JSONDecodeError` past every provider adapter (`OpenAICompatProvider`,
  `AnthropicProvider`, `GeminiProvider`, `OpenAICompatEmbedder`) instead of a `ProviderError`,
  breaking the router's retry/fallback and error-typing contract. Added a shared
  `parse_json_response()` helper used by all four.
- `SemanticCacheLookup` only caught `ByoAIError` around the embedder/store call, so a
  user-supplied `embedder=` callable (explicitly a supported use case — any
  `async (str) -> list[float]`) raising a plain exception (`ConnectionError`, `TimeoutError`,
  etc.) failed the whole request instead of degrading to a cache miss, contradicting the
  documented "a semantic-cache or embedder hiccup must never fail a request" guarantee.
  Broadened to catch any exception.

[Unreleased]: https://github.com/ravikings/byoai-runtime/compare/v0.1.0a5...HEAD
[0.1.0a5]: https://github.com/ravikings/byoai-runtime/compare/v0.1.0a4...v0.1.0a5
[0.1.0a4]: https://github.com/ravikings/byoai-runtime/compare/v0.1.0a3...v0.1.0a4
[0.1.0a3]: https://github.com/ravikings/byoai-runtime/compare/v0.1.0a2...v0.1.0a3
[0.1.0a2]: https://github.com/ravikings/byoai-runtime/compare/v0.1.0a1...v0.1.0a2
[0.1.0a1]: https://github.com/ravikings/byoai-runtime/releases/tag/v0.1.0a1
