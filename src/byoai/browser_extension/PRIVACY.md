# Coriqo Shield: Agent Capture — privacy notice

This extension records *that* you sent a message to an AI chat, never *what you
said*. On claude.ai and chatgpt.com it also replaces personal details in your
message before the message leaves the page, when your Shield's policy says to.
It does nothing until you agree on the welcome page it opens when you install
it, and you can turn it off again at any time from its popup.

## What it does

When you send a message on claude.ai, chatgpt.com (and chat.openai.com),
gemini.google.com or copilot.microsoft.com, the extension notes the fact and
hands it to **Shield, a separate program running on your own computer**
(`byoai-shield`). No other site is watched. Without Shield running, nothing is
recorded.

## What is collected

Per message you send:

| Field | Example | Why |
|---|---|---|
| `kind` | `browser.chat.request` | what happened |
| `app` | `chatgpt` | which app |
| `chars` | `42` | message length only |
| `wire` | `/backend-api/conversation` | truncated endpoint path |
| `sent_at` | ISO timestamp | when |
| `flags` | `["pii:emails"]` | names of the Shield rules the message matched, never the matched text |
| `redactions` | `["emails"]` | names of the rules whose matches were replaced before sending |
| `verdict` | `redacted(1)` | what Shield's policy did: `redacted(n)`, `redact`, `block`, `blocked`, `observe` or, after the warn bar, `warned→sent`, `warned→redacted` or `warned→cancelled` |

Per reply in which the AI ran tools (claude.ai and chatgpt.com), one more row:

| Field | Example | Why |
|---|---|---|
| `kind` | `browser.chat.reply` | what happened |
| `tools` | `["web.run"]` | names of the tools the AI ran on its own servers (web search, code, connectors), never what they found |
| `sources` | `9` | how many distinct sites a web search returned, never which |
| `send_id` | random | the same random id as the message it answers (also on that message's row), so a reply that finishes late is matched to the right message; it carries nothing about you |

Two more kinds of row carry no message text at all:

| Kind | Fields | Why |
|---|---|---|
| `browser.chat.attachment` | `app`, `name`, `mime`, `bytes`, `sha256`, `scanned`, `flags`, `rules_version`, `verdict` | a file was uploaded: its type, size and SHA-256, whether Shield's rules read it, the rule names that matched, the rules version and what happened (`allowed`, `blocked`, `cancelled`, `warned→uploaded`, `warned→removed`), never its content. `name` is described under "File hashing" below |
| `browser.health.unmatched` | `app`, `path` | three chat-like requests in ten minutes that Shield did not recognise (the site may have changed): the first 60 characters of the path, no query, no body. The popup then says "Shield may be out of date" |

Nothing else. The extension does not read page content, the DOM, cookies, form
fields, browsing history or the clipboard. The outgoing message is read in the
page for its length, the rule names above and, when Shield's policy is
*redact* or *block*, to replace personal details, then discarded: it is never
stored, logged or transmitted to Shield. The reply is read the same way, from
a copy of its stream as it arrives, only for the names of the tools the AI
ran and the number of sources a search returned; its text is not kept. The server side drops any unexpected
field, text included, before it reaches the record (`clean_browser_row`), and
accepts only known rule names.

## File hashing

When a file is uploaded to a covered app, the extension works out in the page
what is being sent. An upload is a form (`FormData`) that contains a file, on
any address, or a file body sent to a known upload address: claude.ai's
`wiggle/upload-file`, and the PUT to ChatGPT's file storage
(`*.oaiusercontent.com/files/<id>/raw`, sent with `XMLHttpRequest`, which the
extension now also watches, for uploads only). Nothing else counts: telemetry
that posts a text blob is not treated as an attachment.

Before a file form (`FormData`) is checked it is copied, and the copy is what is sent, so the hash and the check are of what goes out. For each file it computes the SHA-256 in the page (Web Crypto). For text-like
files up to 5 MB (`.txt .csv .json .env .pem` and the other extensions listed
in CONFIGURATION.md, or a `text/*` type) it also runs Shield's rules on the
decoded text, in the page. It sends Shield the hash, size, type, rule names,
whether the file was scanned, the version of the rules and what happened. PDFs,
images, Office files and anything over 5 MB are recorded as not scanned. The
file's content is never put in an event or kept, and no copy of the file is
kept.

The one thing that is sent about the file name: the raw `name` is in the
`browser.chat.attachment` row that goes to your local Shield (the address you
paired, on this Mac by default). Shield turns it into a keyed hash right away
and discards the name; the ledger and the sealed record keep only the hash. In
the extension the row waits in the send queue, which lives in
`chrome.storage.session` (memory, cleared when the browser session ends, not
written to disk), until it is delivered. The name is also shown
in the on-page warn bar, when the per-app file policy is `warn`, and nowhere
else. Files are never rewritten: the choices are *Remove file* (the upload
fails like a network error), *Upload anyway* and *Cancel*; 60 seconds without
an answer cancels.

Already true on this Mac: Shield keeps `sha256` and the keyed name hash only in
its local ledger and sealed record. They are not part of any sync level
(`seal`, `daily`, `events`), so neither leaves the device.

## What the input gate reads

From version 0.10.0, when you press Enter in a message box, click a send
button, submit a form, pick a file, or drop or paste a file, the extension
reads the message text or the file in its own isolated part of the page (a
part the site's scripts cannot read or change) to check it against the rules
described below, before the site receives it. This happens entirely in your
browser. The text and file contents are not stored, not put in any event and
not sent to Shield or anywhere else; only rule names, lengths, a file's hash,
type, size and name (hashed by Shield) go into the record, as before. To
remove a detail it may rewrite the message box, and to stop a file it may clear
the file picker. It does not read voice input or anything you have not sent,
picked, dropped or pasted.

## What it changes

On claude.ai and chatgpt.com (and chat.openai.com), when Shield's mode is
*redact* (the default) or *block*, emails, card numbers, phone numbers,
SSN-like numbers, wallet addresses and API keys in the message you send are
replaced with numbered placeholders such as `[EMAIL_1]` (the same value gets the same number within one message; the mapping is dropped after the send) before the request leaves the
page, so the AI provider never receives them. What happens is set per tier by Shield's `actions` policy
(`secret`: block, `pii`: redact, `flag`: log by default). *block* stops the
send: the chat app gets an error answer from the extension. *warn* holds the
send and shows a bar on the page with three buttons: *Send redacted* (the
default, Enter), *Send anyway* and *Cancel*. The bar names the kind of thing
found ("an AWS access key"), never the text itself. If you do nothing for 60
seconds the send is cancelled; the original is never sent without your choice. The rules
are the same ones Shield's desktop proxy uses (`shield-rules.js` is generated
from them). *Record only* (`observe`) leaves messages unchanged, and so does
an app switched off in Shield. Until the extension has heard from your Shield
it uses the default, *redact*.

On gemini.google.com and copilot.microsoft.com the network requests are only
noted, never rewritten: those sites send messages as form-encoded or websocket
traffic the extension can't safely rewrite. When those apps are turned on in
Shield (they are off in Shield's default policy, and checked like the others
until the extension has heard from your Shield), the input gate above still
checks what you send and attach there, with
the same actions: it can stop a send, rewrite the message box or clear the file
picker before the site receives anything. Other sends that don't go through the
page's `fetch` are noted, not rewritten. Attachments are read only as described
under "File hashing" and "What the input gate reads".

No account, device or user identifier is attached to rows. There is no
analytics, no telemetry, no advertising and no third-party request. The data is
never sold, and is not used or transferred for anything other than the single
purpose above (noting that a message was sent, on this computer).

## Where it goes

Only to `http://127.0.0.1:17831/api/browser` (the port is configurable, but the
extension refuses any address that is not this computer: see `isLocalEndpoint`
in `background.js`). The manifest's `host_permissions` are limited to
`127.0.0.1` and `localhost`, so this cannot be widened without a new release.
The extension only sends to a Shield that proves it holds the key it first
paired with; a different program on the same port receives nothing.

What Shield does with its own record on your computer is described in its
README. Shield can, if you choose to enrol it in Coriqo, send a signed
checkpoint (a hash and a count, no content) to a Coriqo tenant; that is a
setting of Shield, off by default, not of this extension.

## What the extension keeps in your browser

| Where | What | Lifetime |
|---|---|---|
| `chrome.storage.session` | rows waiting for Shield, at most 50 | cleared when the browser closes; older rows are dropped, never kept |
| `chrome.storage.local` `consent` | that you agreed, and when | until you turn capture off |
| `chrome.storage.local` `endpoint` | Shield's local address, if you changed it | until removed |
| `chrome.storage.local` `pinned_shield` | Shield's public key, saved when first paired | until you re-pair |
| `chrome.storage.local` `witness` / `rollback` | the highest count of sealed entries Shield reported (one number), and a flag if it later dropped | until you re-pair or accept |
| `chrome.storage.local` `shield_policy` | Shield's mode, its per-tier actions and which apps it covers, as your paired Shield reported them | refreshed from Shield; removed when you turn capture off |
| `chrome.storage.local` `health_unmatched` | the time the canary last fired, per app | until that app's sends are recognised again, or you turn capture off |
| `chrome.storage.local` `last_capture` / `today` | one "last message noted" time per app, and today's message count | overwritten on each send; removed when you turn capture off |

None of this contains message text, and none of it leaves your computer.

## Permissions, and why

- `storage`: the items above.
- `alarms`: retry sending to Shield if it was not running yet.
- `activeTab`: lets the popup show whether the tab you are looking at is
  covered, only when you open it.
- Host access to `127.0.0.1` / `localhost`: to reach Shield.
- Content scripts on the five chat sites listed above: to notice a send and,
  on claude.ai and chatgpt.com, replace personal details in it. One runs in
  the page so it can see (and rewrite) the send request (it must wrap `fetch`,
  since the sites' security policies block injecting anything else); the
  other relays the text-free fact to the extension, and passes Shield's mode
  back to the page. Neither loads remote code. All code ships in the package.

## Your choices

- **Turn it off:** popup → Details → *Turn capture off*. This stops recording
  and replacing, and removes anything still waiting to be sent, plus the
  per-app times, the count and the saved policy above.
- **Remove it:** uninstalling the extension stops capture at the source.
- **Erase what Shield already kept:** Shield's Settings → Privacy → *Remove
  now* (`POST /api/privacy/scrub`). Sealed entries stay, because removing
  them would break the seal; they hold only the fields listed above.
- **Access:** `/api/receipt/<seal>` on Shield exports a verifiable receipt.
  Agent runs published to Coriqo with Shield's seal chain send the receipt of
  each agent tool call. Receipts of chat messages are never sent, and a row
  holding a message preview stays on this computer.

## The record Shield keeps

Shield seals each entry into a Merkle chain signed with a key that stays on your
computer. That lets you prove the record was not edited afterwards. It holds
only the fields listed above. The extension asks before it starts, and its
popup always shows whether it is on.

## Contact

Questions or concerns: https://github.com/ravikings/byoai-runtime/issues
