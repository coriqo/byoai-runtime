/**
 * Coriqo Shield — browser capture, page world.
 *
 * Runs with "world": "MAIN", so this IS the same JavaScript world the page
 * uses: wrapping window.fetch here sees what the app sends without injection
 * into the DOM, which the surfaces' CSP blocks. It emits facts through a
 * CustomEvent that the isolated-world relay (content-relay.js) forwards to
 * the service worker.
 *
 * Same trust stance as the desktop proxy and the MCP gateway: what happened,
 * not what was said. The message text is read here, in the page, for three
 * things only: its length, which of Shield's rules it matches (rule names,
 * never the matched text), and — when Shield's policy says redact or block —
 * replacing personal details before the message leaves the browser. The
 * text itself is never put in an event, stored or sent to Shield.
 *
 * The rules come from shield-rules.js (generated from the Python ones, so
 * the proxy and the extension can't disagree about what an email is).
 */
(function () {
  'use strict'

  if (window.__shieldCapturePatched) return
  // A same-origin child frame (claude.ai keeps an about:blank iframe whose
  // fetch is untouched): the parent's capture arms it with its own wrappers,
  // so both share one policy and one record.
  try {
    if (window.parent !== window && typeof window.parent.__shieldArm === 'function') {
      window.parent.__shieldArm(window)
      return
    }
  } catch { /* cross-origin parent: this frame is its own page */ }
  window.__shieldCapturePatched = true
  // Which build this tab runs (a tab opened before a reload keeps old code).
  try { Object.defineProperty(window, '__shieldVersion', { value: '0.10.9' }) } catch { /* already set */ }

  // Which app this host is: from the generated shield-sites.js (sites.json).
  const site = ((window.__shieldSites && window.__shieldSites.sites) || [])
    .find((x) => Array.isArray(x.hosts) && x.hosts.includes(location.host))
  const app = site && site.app
  if (!app) return

  /*
   * The rule engine (shield-core.js, run just before this file, before any
   * page script). It is trusted only if it is the one that script defined: a
   * frozen value on a non-writable, non-configurable property, with no
   * "tampered" marker. Anything else (missing, or put there by the page)
   * means the checker isn't running, and a chat send on a governed app is
   * then refused rather than passed unchecked, with a health row saying why.
   */
  const coreDesc = Object.getOwnPropertyDescriptor(window, '__shieldCore')
  const coreOk = !!coreDesc && coreDesc.configurable === false && coreDesc.writable === false &&
    Object.isFrozen(coreDesc.value) && typeof coreDesc.value.engine === 'function' &&
    !Object.prototype.hasOwnProperty.call(window, '__shieldCoreTampered')
  const core = coreOk ? coreDesc.value : null

  const RULES = window.__shieldRules ||
    { secret: [], pii: [], flag: [], validators: {}, placeholder: {}, rule_actions: {}, default_actions: {}, covered_apps: [] }
  // Gemini's web client sends form-encoded batch RPC and Copilot a websocket,
  // so only these apps' messages can be read and rewritten.
  const covered = (RULES.covered_apps || []).includes(app)

  /*
   * What the relay tells us: whether the user agreed to capture, and Shield's
   * mode and per-app toggles (verified by the service worker against the
   * paired Shield). Until it arrives nothing is rewritten; with no policy
   * heard from Shield yet, the privacy-first default applies: redact.
   */
  let config = { consented: false, mode: 'redact', apps: null, actions: {}, files: {} }
  const { SCAN_MAX, ORDER, cleanActions, cleanFiles, passes, scan, redactWithRules, assessFiles, cleanMime } = core
    ? core.engine(RULES, () => config)
    : {
      SCAN_MAX: 2_000_000, ORDER: { log: 0, redact: 1, warn: 2, block: 3 }, cleanActions: () => ({}), cleanFiles: () => ({}),
      passes: () => true, scan: () => [], redactWithRules: (t) => t,
      // No checker: every file is stopped (level 2), never let through unread.
      assessFiles: async (_a, parts) => ({ facts: parts.map((p) => ({ name: p.name, mime: '', bytes: null, sha256: null,
        scanned: false, hits: [], unreadable: true })), labels: ['core_missing'], top: 2, level: () => 2, flagsOf: () => [] }),
      cleanMime: (m) => String(m || '').split(';')[0].trim().toLowerCase().slice(0, 60),
    }
  /*
   * Everything from the relay (config, warn answers) arrives on one
   * MessageChannel port that the relay transfers in a single event at
   * document_start. This script is listed first, so its listener is in place
   * before the relay posts and before any page script runs. The first port
   * wins and the event is hidden from page listeners; no window CustomEvent
   * can set the policy or answer a warn prompt, so a page can't forge either.
   */
  const PORT_MARK = 'shield-agent-port'
  let port = null
  function onPortMessage(ev) {
    const c = ev && ev.data
    if (!c || typeof c !== 'object') return
    if (c.t === 'config') {
      config = {
        consented: c.consented === true,
        mode: ['observe', 'redact', 'block'].includes(c.mode) ? c.mode : 'redact',
        apps: c.apps && typeof c.apps === 'object' ? c.apps : null,
        actions: cleanActions(c.actions),
        files: cleanFiles(c.files),
      }
    } else if (c.t === 'warn-result') {
      answered(c.send_id, c.choice)
    } else if (c.t === 'gate') {
      if (typeof c.gate_id === 'string' && c.gate_id.length <= 64) gate = { id: c.gate_id, at: Date.now() }
    } else if (c.t === 'relay-closed') {
      relayGone()
    }
  }
  window.addEventListener('message', (ev) => {
    if (!ev || ev.source !== window || ev.data !== PORT_MARK) return
    ev.stopImmediatePropagation() // page listeners never see the handover, or a later imitation
    if (port || !ev.ports || ev.ports.length !== 1) return
    port = ev.ports[0]
    port.onmessage = onPortMessage
  }, true)

  // Rewriting applies only where the user agreed, the app can be read, and
  // Shield governs it (an app turned off in Shield is left alone).
  const governing = () => config.consented && covered &&
    (config.apps === null || config.apps[app] === true)

  // --- the same logic as byoai.integrations.shield, in the same order ---

  function contentText(content) {
    if (typeof content === 'string') return content
    if (content && !Array.isArray(content) && typeof content === 'object' && Array.isArray(content.parts)) {
      return content.parts.filter((x) => typeof x === 'string').join('\n')
    }
    if (Array.isArray(content)) {
      return content
        .filter((b) => b && typeof b === 'object' && (b.type === 'text' || b.type === 'input_text'))
        .map((b) => String(b.text ?? '')).join('\n')
    }
    return ''
  }

  function messageText(body) {
    if (typeof body.prompt === 'string') return body.prompt
    const messages = body.messages
    if (Array.isArray(messages) && messages.length && messages[messages.length - 1] &&
        typeof messages[messages.length - 1] === 'object') {
      return contentText(messages[messages.length - 1].content)
    }
    const inp = body.input
    if (typeof inp === 'string') return inp
    if (Array.isArray(inp) && inp.length && inp[inp.length - 1] && typeof inp[inp.length - 1] === 'object') {
      return contentText(inp[inp.length - 1].content)
    }
    return ''
  }

  /*
   * Every string leaf of the body, at any depth, except the values of id-ish
   * keys (ids, model, signature, media type) and inline base64 payloads: system prompts, tool
   * results, documents and any future field are covered without listing them,
   * while conversation ids and timestamps can't trip the rules.
   */
  const SKIP_KEY = /^(id|uuid|model|signature|media_type|mime_?type|.*_(id|uuid))$/i
  // Inline payloads: a base64 blob or data: URI under `data`/`url`/`image_url`, never prose.
  const PAYLOAD_KEY = /^(data|url|image_url|source)$/i
  const isPayload = (k, v) => PAYLOAD_KEY.test(k) &&
    (/^data:[\w.+-]+\/[\w.+-]+;base64,/i.test(v) || /^[A-Za-z0-9+/=\s]{200,}$/.test(v))
  const MAX_DEPTH = 64
  function mapLeaves(node, fix, depth = 0) {
    if (!node || typeof node !== 'object' || depth > MAX_DEPTH) return
    for (const k of Array.isArray(node) ? node.keys() : Object.keys(node)) {
      const v = node[k]
      if (typeof v === 'string') {
        if (Array.isArray(node) || !(SKIP_KEY.test(k) || isPayload(k, v))) node[k] = fix(v)
      } else mapLeaves(v, fix, depth + 1)
    }
  }
  const mapTexts = (body, fix) => mapLeaves(body, fix)

  // What a block/warn/redact decision looks at: every leaf, joined.
  function allText(body) {
    const out = []
    mapLeaves(body, (s) => { out.push(s); return s })
    return out.join('\n')
  }

  // Returns the body unchanged (same string) when nothing matched.
  function redactJsonBody(raw, names) {
    let body
    try { body = JSON.parse(raw) } catch { return { raw, rules: [] } }
    if (!body || typeof body !== 'object' || Array.isArray(body)) return { raw, rules: [] }
    const hit = new Set()
    const state = {}
    mapTexts(body, (s) => redactWithRules(s, names, state, hit))
    if (!hit.size) return { raw, rules: [] }
    return { raw: JSON.stringify(body), rules: [...hit].sort() }
  }

  // --- the send ---

  /*
   * Everything decided about one outgoing body: its length, the rules it
   * matches, and what to do. `blocked` holds rule names when a hit's action is
   * block; `warn` holds the rule names to ask the user about (the strictest
   * action is warn). Otherwise the body is redacted per the hits' actions.
   */
  const redactable = (h) => h.tier !== 'flag' && (h.action === 'redact' || h.action === 'warn')
  function inspect(raw) {
    let body = null
    try { body = JSON.parse(raw) } catch { /* not JSON: length only */ }
    const isObj = body && typeof body === 'object' && !Array.isArray(body)
    const text = isObj ? messageText(body) : ''
    const facts = { chars: text ? text.length : raw.length }
    let decide = isObj ? allText(body) : ''
    let oversize = false
    if (decide.length > SCAN_MAX) {
      oversize = true // pii and flag rules scan head and tail; say so
    }
    if (!config.consented) return { facts, raw }
    const hits = decide ? scan(decide) : []
    const lastFlags = (text ? scan(text) : [])
    facts.flags = lastFlags.map((h) => `${h.tier}:${h.name}`) // last message, as Python
    if (oversize) facts.flags.push('flag:oversize')
    if (!governing()) return { facts, raw }
    if (!core) return { facts: { ...facts, verdict: 'blocked' }, raw, blocked: ['core_missing'] }
    const top = hits.reduce((m, h) => Math.max(m, ORDER[h.action]), 0)
    const named = (a) => hits.filter((h) => h.action === a).map((h) => h.name)
    if (top === ORDER.block) {
      return { facts: { ...facts, verdict: 'blocked' }, raw, blocked: named('block') }
    }
    const names = new Set(hits.filter(redactable).map((h) => h.name))
    if (top === ORDER.warn) {
      const keep = new Set(hits.filter((h) => h.tier !== 'flag' && h.action === 'redact').map((h) => h.name))
      return { facts, raw, warn: { labels: named('warn'), names, keep } }
    }
    let out = raw
    let redactions = []
    if (names.size) ({ raw: out, rules: redactions } = redactJsonBody(raw, names))
    facts.redactions = redactions
    facts.verdict = redactions.length ? `redacted(${redactions.length})` : config.mode
    return { facts, raw: out }
  }

  /*
   * warn: the send waits on the user, who answers through the relay's bar
   * (isolated world; this page can't be trusted to draw it). Results are
   * matched by send_id; one for an id that isn't waiting is ignored. Timeout
   * cancels: the original is never sent without an explicit choice.
   */
  const WARN_MS = 60_000
  const CHOICES = ['redacted', 'sent', 'cancelled', 'removed']
  const waiting = new Map()
  function askUser(sendId, labels, file) {
    // No live relay to show the bar: don't hang, redact (never send the original).
    if (!port) return Promise.resolve('no_relay')
    return new Promise((resolve) => {
      const timer = setTimeout(() => { waiting.delete(sendId); resolve('cancelled') }, WARN_MS)
      waiting.set(sendId, { resolve, timer })
      try { port.postMessage(file ? { t: 'warn', send_id: sendId, labels, file: true, name: file.name } : { t: 'warn', send_id: sendId, labels }) } catch { relayGone() }
    })
  }
  // The relay closed its end: nothing can answer, so every held send goes redacted.
  function relayGone() {
    port = null
    for (const [id, w] of [...waiting]) { clearTimeout(w.timer); waiting.delete(id); w.resolve('no_relay') }
  }
  // Only reached from the relay's port; an id that isn't waiting is ignored.
  function answered(sendId, choice) {
    const w = typeof sendId === 'string' && waiting.get(sendId)
    if (!w || !CHOICES.includes(choice)) return
    clearTimeout(w.timer)
    waiting.delete(sendId)
    w.resolve(choice)
  }

  // A random id for one send, carrying nothing about it.
  const newId = () => (crypto.randomUUID?.() ??
    Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join(''))

  /*
   * Rows for a send or a file say which layer saw them: this wrapper is the
   * backstop ("network"); the input gate in the isolated world writes "input".
   * When the gate decided a send just now it told us (over the private port)
   * and its id is added, so one send's two rows can be matched.
   */
  let gate = null
  const GATE_MS = 10_000
  function emit(detail) {
    if (detail && (detail.kind === 'browser.chat.request' || detail.kind === 'browser.chat.attachment')) {
      detail = { stage: 'network', ...detail }
      // One decision's id goes on the first network row after it, then it is spent.
      if (gate && detail.gate_id === undefined) {
        if (Date.now() - gate.at < GATE_MS) detail.gate_id = gate.id
        gate = null
      }
    }
    window.dispatchEvent(new CustomEvent('shield-agent-capture', { detail }))
  }

  // What the app gets instead of a reply when block mode stops a send; the
  // same answer the desktop proxy gives.
  function refusal(rules) {
    return new Response(JSON.stringify({
      error: { type: 'coriqo_shield_blocked', message: 'Stopped on this Mac: ' + rules.join(', ') },
    }), { status: 403, headers: { 'content-type': 'application/json', 'x-coriqo-shield': 'blocked' } })
  }

  const CHAT_PATHS = [
    /\/chat_conversations\//, // claude.ai message send
    /\/backend-(api|anon)\/(f\/)?conversation(\?|$)/, // chatgpt.com message send (plain and /f/ paths)
    /\/v1\/messages/, // Messages-API agent wire
    /\/v1\/chat\/completions/,
  ]
  const orig = window.fetch

  // One send whose body is in hand as a string: inspect, maybe rewrite,
  // ask or stop, record, then send.
  function send(self, input, init, raw, wire) {
    lastInspected = Date.now()
    const { facts, raw: out, blocked, warn } = inspect(raw)
    // Ties this send's reply row to it, however many sends overlap.
    const sendId = newId()
    const base = { app, wire: wire.slice(0, 60), send_id: sendId }
    if (warn) {
      return askUser(sendId, warn.labels).then((choice) => {
        if (choice === 'cancelled') {
          emit({ kind: 'browser.chat.request', ...base, ...facts, verdict: 'warned\u2192cancelled' })
          return refusal(warn.labels)
        }
        // Send anyway skips only the warned hits: redact-tier ones still go.
        const extra = choice === 'no_relay' ? { reason: 'no_relay' } : {}
        if (choice === 'sent') {
          const { raw: red, rules } = redactJsonBody(raw, warn.keep)
          emit({ kind: 'browser.chat.request', ...base, ...facts, redactions: rules, verdict: 'warned\u2192sent' })
          return go(self, input, init, raw, red, facts, sendId)
        }
        const { raw: red, rules } = redactJsonBody(raw, warn.names)
        emit({ kind: 'browser.chat.request', ...base, ...facts, redactions: rules, verdict: 'warned\u2192redacted', ...extra })
        return go(self, input, init, raw, red, facts, sendId)
      })
    }
    emit({ kind: 'browser.chat.request', ...base, ...facts })
    if (blocked) {
      // The app just puts the text back in the box; say why. Rule names only.
      try { port && port.postMessage({ t: 'notice', message: true, labels: blocked, verdict: 'blocked' }) } catch { /* relay gone */ }
      return Promise.resolve(refusal(blocked))
    }
    return go(self, input, init, raw, out, facts, sendId)
  }

  function go(self, input, init, raw, out, facts, sendId) {
    let args = [input, init]
    if (out !== raw && init && isForm(init.body)) {
      // A FormData chat body was checked as its text fields: put the
      // redacted fields back, keep everything else as it was.
      let red = {}
      try { red = JSON.parse(out) } catch { /* keep the fields */ }
      const next = new FormData()
      for (const [k, v] of init.body.entries()) {
        if (typeof v === 'string' && typeof red[k] === 'string') next.append(k, red[k])
        else next.append(k, v, v && v.name)
      }
      args = [input, { ...init, body: next }]
    } else if (out !== raw) {
      args = init && init.body != null
        ? [input, { ...init, body: out }]
        : [new Request(input, { body: out }), init]
    }
    return orig.apply(self, args).then((res) => {
      emit({ kind: 'browser.chat.status', app, chars: facts.chars, ok: res.ok, status: res.status })
      if (config.consented && covered && res.ok &&
          /event-stream/.test(res.headers.get('content-type') || '')) {
        try { watchReply(res.clone(), sendId) } catch { /* the reply is the app's, whatever happens here */ }
      }
      return res
    })
  }

  /*
   * Canary: chat POSTs that look like a send but that CHAT_PATHS didn't
   * recognise. Three in ten minutes with no send inspected means the site
   * probably changed; say so (path prefix only, no body) instead of failing
   * silently open.
   */
  const LOOSE_SEND = /conversation|completion|chat|messages/i
  // Requests that look like a send by name but are not one: an upload (handled
  // as a file, see below), Datadog telemetry, the realtime channel and ChatGPT's
  // prepare call. They never count toward "Shield may be out of date".
  const NOT_A_SEND = /\/(files|uploads?|attachments)(\/|$|\?)|\/wiggle\/upload-file$|\/backend-api\/files|\/backend-api\/f\/conversation\/prepare|\/realtime\/|\/api\/v2\/rum|\/backend-api\/(sentinel|bazaar)\//i
  const CANARY_MS = 10 * 60_000
  let unmatched = []
  let lastInspected = 0
  function canary(pathOnly) {
    const now = Date.now()
    unmatched = unmatched.filter((t) => now - t < CANARY_MS)
    unmatched.push(now)
    if (unmatched.length >= 3 && now - lastInspected >= CANARY_MS) {
      unmatched = []
      emit({ kind: 'browser.health.unmatched', app, path: pathOnly.slice(0, 60) })
    }
  }

  /*
   * Files. What counts as an upload is decided by shape, never by a path
   * word alone (telemetry posts Blobs too):
   *   (a) a FormData with at least one File/Blob entry, on any path;
   *   (b) a Blob, File, ArrayBuffer or typed array body on a known upload
   *       endpoint: claude.ai .../wiggle/upload-file, or a PUT to ChatGPT's
   *       pre-signed storage (*.oaiusercontent.com/files/<id>/raw).
   * For each file the page computes its SHA-256, and for text-like files up to
   * 5 MB runs Shield's rules on the text (rule names only). The file's bytes
   * and text are never put in an event or kept; the file name goes only into
   * the attachment row for the local Shield, which keeps a keyed hash of it.
   * Same checks as byoai.integrations.shield.inspect_file.
   */
  // By tag, not instanceof: a page's own realm objects (an iframe's Blob) still count.
  const tagOf = (v) => Object.prototype.toString.call(v)
  const isBlob = (v) => { const t = tagOf(v); return t === '[object Blob]' || t === '[object File]' }
  const isBytes = (v) => tagOf(v) === '[object ArrayBuffer]' || ArrayBuffer.isView(v)
  const isForm = (v) => tagOf(v) === '[object FormData]'
  const CLAUDE_UPLOAD = /^\/api\/organizations\/[^/]+\/conversations\/[^/]+\/wiggle\/upload-file\/?$/
  const GPT_UPLOAD_HOST = /\.oaiusercontent\.com$/
  const GPT_UPLOAD_PATH = /^\/files\/[^/]+\/raw\/?$/
  function knownUploadEndpoint(method, url) {
    let u
    try { u = new URL(url, location.href) } catch { return false }
    if (u.protocol !== 'https:') return false
    const host = u.hostname.replace(/\.$/, '') // a trailing dot names the same host
    if (method === 'POST' && host === 'claude.ai') return CLAUDE_UPLOAD.test(u.pathname)
    if (method === 'PUT') return GPT_UPLOAD_HOST.test(host) && GPT_UPLOAD_PATH.test(u.pathname)
    return false
  }
  const copyBytes = (b) => (ArrayBuffer.isView(b)
    ? new Uint8Array(b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength)).buffer
    : b.slice(0))
  const nameOf = (v) => (typeof v.name === 'string' && v.name ? v.name : null)
  /*
   * The files a body carries, or null when it is not an upload; `body` is what
   * must be sent instead of the original, a snapshot taken now, so what is
   * hashed and checked is what goes out even if the page changes its object
   * while the check runs: a FormData is copied, a mutable buffer is copied.
   * On a known endpoint a string, URLSearchParams or Document is read as bytes
   * (sent as the string it was), and a stream, which can't be read without
   * using it up, is recorded as not scanned.
   */
  function uploadOf(body, known) {
    if (isForm(body)) {
      const snap = new FormData()
      const parts = []
      for (const [k, v] of body.entries()) {
        snap.append(k, v)
        if (typeof v !== 'string' && isBlob(v)) parts.push({ blob: v, name: nameOf(v) })
      }
      return parts.length ? { parts, body: snap } : null
    }
    if (!known) return null
    const textPart = (str, mime, sendBody, scanText) => ({
      parts: [{ bytes: new TextEncoder().encode(str).buffer, name: null, raw: true, mime, scanText }], body: sendBody,
    })
    if (isBlob(body)) return { parts: [{ blob: body, name: nameOf(body), raw: true }], body }
    if (isBytes(body)) { const snap = copyBytes(body); return { parts: [{ bytes: snap, name: null, raw: true }], body: snap } }
    if (typeof body === 'string') return textPart(body, 'text/plain', body)
    const tag = tagOf(body)
    if (tag === '[object URLSearchParams]') {
      const str = body.toString()
      // The rules read the decoded values too: "key%3DAKIA..." hides a key from \b.
      let plain = str
      try { plain = decodeURIComponent(str.replace(/\+/g, ' ')) } catch { /* not decodable: read as is */ }
      return textPart(str, 'application/x-www-form-urlencoded', new window.URLSearchParams(str), plain)
    }
    if (body && body.nodeType === 9) {
      const str = new window.XMLSerializer().serializeToString(body)
      return textPart(str, 'text/html', str)
    }
    if (tag === '[object ReadableStream]') return { parts: [{ stream: true, name: null, raw: true }], body }
    return null
  }

  /*
   * Decide one upload (a list of files). Resolves to 'go' | 'block' | 'remove' |
   * 'cancel' and has already emitted one attachment row per file.
   */
  async function decideUpload(up) {
    const { facts, labels, top, level, flagsOf } = await assessFiles(app, up.parts)
    // One row per file; `verdictOf` gives each its own outcome.
    const finish = (verdictOf, out) => {
      // The app still shows a file whose upload was refused as attached;
      // tell the user it isn't. Names and rule names go to the relay's bar
      // only, never into an event.
      const stopped = facts.filter((f, i) => /blocked|removed|cancelled/.test(verdictOf(f, i)))
      if (stopped.length && port) {
        try {
          port.postMessage({ t: 'notice', names: stopped.map((f) => f.name || 'a file').slice(0, 5),
            labels: [...new Set(stopped.flatMap((f) => f.hits.map((h) => h.name)))],
            verdict: out === 'block' ? 'blocked' : out === 'go' || out === 'remove' ? 'removed' : 'cancelled' })
        } catch { /* relay gone: the record still says what happened */ }
      }
      facts.forEach((f, i) => emit({
        kind: 'browser.chat.attachment', app, name: f.name && f.name.slice(0, 512), mime: f.mime, bytes: f.bytes,
        sha256: f.sha256, scanned: f.scanned, flags: flagsOf(f), rules_version: RULES.rules_version,
        verdict: verdictOf(f, i),
      }))
      return out
    }
    if (top === 0) return finish(() => 'allowed', 'go')
    if (top === 2) return finish(() => 'blocked', 'block')
    const choice = await askUser(newId(), labels, { name: facts.length === 1 ? (facts[0].name || 'a file') : `${facts.length} files` })
    if (choice === 'sent') return finish((f) => (level(f) > 0 ? 'warned\u2192uploaded' : 'allowed'), 'go')
    if (choice === 'removed') {
      // Only the files that raised the warning come out; the rest go on.
      const flagged = new Set(facts.map((f, i) => (level(f) > 0 ? i : -1)).filter((i) => i >= 0))
      if (flagged.size < facts.length && isForm(up.body)) {
        // The file entries come in the same order as `parts`.
        const rest = new FormData()
        let n = 0
        for (const [k, v] of up.body.entries()) {
          if (typeof v !== 'string' && isBlob(v)) { if (flagged.has(n++)) continue }
          rest.append(k, v)
        }
        up.body = rest
        return finish((f) => (level(f) > 0 ? 'warned\u2192removed' : 'allowed'), 'go')
      }
      return finish(() => 'warned\u2192removed', 'remove')
    }
    return finish(() => 'cancelled', 'cancel') // cancel, timeout, or no bar to ask on
  }

  /*
   * When there is no time to read the file (a synchronous XHR, a beacon that
   * must answer at once): only the per-app file policy applies. block and warn
   * both stop it (nothing can ask); each file is recorded as not scanned, with
   * its size and no hash. Returns 'go' or 'block'.
   */
  function policyOnly(parts) {
    const act = config.mode === 'observe' ? 'allow' : (config.files[app] || 'allow')
    for (const p of parts) {
      emit({
        kind: 'browser.chat.attachment', app, name: p.name ? p.name.slice(0, 512) : null,
        mime: p.blob ? cleanMime(p.blob.type) : cleanMime(p.mime),
        bytes: p.blob ? p.blob.size : (p.bytes ? p.bytes.byteLength : null), sha256: null, scanned: false, flags: [],
        rules_version: RULES.rules_version, verdict: act === 'allow' ? 'allowed' : 'blocked',
      })
    }
    return act === 'allow' ? 'go' : 'block'
  }

  // Files are checked only where the user agreed and Shield governs the app.
  const filesGoverned = () => config.consented && (config.apps === null || config.apps[app] === true)

  /*
   * Which tools the AI ran for this reply, read from a copy of the reply
   * stream as it arrives: tool names and a count of the sources a search
   * returned. The reply's text passes through here only to be parsed as
   * JSON events and is dropped; nothing of it is kept or sent.
   *
   * ChatGPT streams each message as a whole object ({o: "add", v: {message}}):
   * a tool's own message carries author {role: "tool", name: "web.run"}, and
   * the assistant's call to it names it as the recipient. Anthropic-style
   * streams (claude.ai) announce a tool with a content_block_start whose
   * block is a tool_use or server_tool_use.
   */
  const TOOL_NAME = /^[A-Za-z0-9_.:-]{1,48}$/
  const MAX_TOOLS = 12
  const MAX_STREAM = 8 * 1024 * 1024 // stop reading a copy past this; the app keeps its own

  function toolsIn(ev, found) {
    const msg = ev?.v?.message ?? ev?.message
    if (msg && typeof msg === 'object') {
      const role = msg.author?.role
      if (role === 'tool' && typeof msg.author.name === 'string') found.tools.add(msg.author.name)
      else if (role === 'assistant' && typeof msg.recipient === 'string' &&
               msg.recipient !== 'all' && msg.recipient !== 'assistant') found.calls.add(msg.recipient)
      for (const g of msg.metadata?.search_result_groups ?? []) {
        if (g && typeof g.domain === 'string') found.domains.add(g.domain)
      }
    }
    const block = ev?.content_block
    if (ev?.type === 'content_block_start' && block &&
        (block.type === 'tool_use' || block.type === 'server_tool_use') && typeof block.name === 'string') {
      found.tools.add(block.name)
    }
  }

  function summarise(found) {
    // A call is only listed when no tool answered under that name or a
    // longer one (ChatGPT addresses "web", then "web.run" answers).
    const names = [...found.tools]
    for (const call of found.calls) {
      if (!names.some((n) => n === call || n.startsWith(call + '.'))) names.push(call)
    }
    return names.filter((n) => TOOL_NAME.test(n)).slice(0, MAX_TOOLS)
  }

  async function watchReply(copy, sendId) {
    const reader = copy.body?.getReader()
    if (!reader) return
    const decoder = new TextDecoder()
    const found = { tools: new Set(), calls: new Set(), domains: new Set() }
    let pending = ''
    let seen = 0
    const take = (line) => {
      if (!line.startsWith('data:')) return
      const data = line.slice(5).trim()
      if (!data || data === '[DONE]') return
      try { toolsIn(JSON.parse(data), found) } catch { /* a partial or non-JSON line */ }
    }
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        seen += value.byteLength
        if (seen > MAX_STREAM) { reader.cancel().catch(() => {}); break }
        pending += decoder.decode(value, { stream: true })
        const lines = pending.split('\n')
        pending = lines.pop()
        lines.forEach(take)
      }
      take(pending)
    } catch { /* the stream was cut: report what was seen */ }
    const tools = summarise(found)
    if (!tools.length || !config.consented) return
    emit({ kind: 'browser.chat.reply', app, send_id: sendId, tools, sources: found.domains.size })
  }

  // A body that is text however it was wrapped: a string, a String object, an
  // ArrayBuffer or a typed array. Anything else returns null.
  function bodyText(b) {
    if (typeof b === 'string') return b
    const tag = Object.prototype.toString.call(b)
    if (tag === '[object String]') return String(b)
    if (tag === '[object ArrayBuffer]' || ArrayBuffer.isView(b)) {
      try { return new TextDecoder().decode(b) } catch { return null }
    }
    return null
  }

  const refuseFile = () => refusal(['file upload'])
  const failed = () => Promise.reject(new TypeError('Failed to fetch'))
  function uploadFlow(self, input, init, up, body) {
    return decideUpload(up).then((out) => {
      if (out === 'block' || out === 'cancel') return refuseFile()
      if (out === 'remove') return failed()
      const args = up.body !== body ? [input, { ...init, body: up.body }] : [input, init]
      return orig.apply(self, args)
    })
  }
  // A fetch(Request): the body is read from a clone, and what is checked is
  // what is sent, as a new Request built from the same snapshot.
  async function requestFlow(self, input, init, known, ct) {
    let up = null
    try {
      up = /^multipart\/form-data/i.test(ct)
        ? uploadOf(await input.clone().formData(), false)
        : uploadOf(await input.clone().blob(), known)
    } catch {
      // Could not read it: pass it on, unless files are blocked, which is not bypassed by that.
      return config.files[app] === 'block' && config.mode !== 'observe' ? refuseFile() : orig.call(self, input, init)
    }
    if (!up) return orig.call(self, input, init)
    const out = await decideUpload(up)
    if (out === 'block' || out === 'cancel') return refuseFile()
    if (out === 'remove') return failed()
    const headers = {}
    for (const [k, v] of input.headers) if (!(isForm(up.body) && k.toLowerCase() === 'content-type')) headers[k] = v
    return orig.call(self, new Request(input, { body: up.body, headers }), init)
  }

  // A chat body that couldn't be read: refused while Shield governs the app
  // (a page that retries in another form must not get an unchecked send).
  function unreadableChat(self, input, init, path, consumed) {
    const strict = governing() && config.mode !== 'observe'
    emit({ kind: 'browser.chat.request', app, chars: null, wire: path.slice(0, 60),
      ...(strict ? { verdict: 'blocked', flags: ['flag:unreadable'] } : {}) })
    if (strict) return refusal(['unreadable'])
    return consumed ? null : orig.call(self, input, init)
  }

  // The checker didn't load (or the page put something in its place): say so once; sends are refused above.
  if (!core && covered) emit({ kind: 'browser.health.core_missing', app })

  window.fetch = function (input, init) {
    let url = ''
    try { url = typeof Request !== 'undefined' && input instanceof Request ? input.url : String(input) } catch { /* unreadable */ }
    const path = url.replace(/^https?:\/\/[^/]+/, '')
    const pathOnly = path.split('?')[0]
    try {
      const isRequestObject = typeof Request !== 'undefined' && input instanceof Request
      // Only sends: chat wires take a POST. A GET (a read), or a PUT/PATCH/DELETE
      // to a matching path (a rename, a delete), is not a message.
      const method = String((init && init.method) || (isRequestObject ? input.method : 'POST')).toUpperCase()
      const isChat = CHAT_PATHS.some((p) => p.test(path))
      const body = init && init.body
      if (filesGoverned() && (method === 'POST' || method === 'PUT')) {
        const known = knownUploadEndpoint(method, url)
        // A Request object carries its body itself (init.body absent): read a clone.
        const inRequest = isRequestObject && !(init && init.body != null)
        if (!inRequest) {
          const up = uploadOf(body, known)
          if (up) return uploadFlow(this, input, init, up, body)
        } else {
          const ct = String(input.headers.get('content-type') || '')
          if (/^multipart\/form-data/i.test(ct) || known) return requestFlow(this, input, init, known, ct)
        }
      }
      if (method === 'POST' && !isChat && covered && LOOSE_SEND.test(pathOnly) && !NOT_A_SEND.test(pathOnly)) {
        canary(pathOnly)
      }
      if (method === 'POST' && isChat) {
        const text = bodyText(body)
        if (text !== null) return send(this, input, init, text, path)
        if (typeof Blob !== 'undefined' && body instanceof Blob) {
          // A Blob on a chat path is the message itself: read it to inspect it.
          const self = this
          return body.text().then(
            (raw) => send(self, input, init, raw, path),
            () => unreadableChat(self, input, init, path))
        }
        // Found live: after a refusal claude.ai resends the same message with a
        // non-string body. A body that can't be read here must not go out
        // unchecked while Shield governs the app: it is refused.
        const self = this
        const unreadable = () => unreadableChat(self, input, init, path, true)
        if (isRequestObject && !(init && init.body)) {
          // A Request carries its body as a stream. Read a copy, so the send
          // can still be inspected and, when Shield says so, rewritten.
          return input.clone().text().then(
            (raw) => send(self, input, init, raw, path),
            () => unreadable() || orig.call(self, input, init))
        }
        if (body != null && !isForm(body)) {
          // A stream, bytes or URLSearchParams: read it whole (a stream can be
          // read only once), then send the text that was checked.
          const next = { ...init, body: undefined }
          delete next.duplex
          return new Response(body).text().then(
            (raw) => send(self, input, { ...next, body: raw }, raw, path),
            () => unreadable() || Promise.reject(new TypeError('Failed to fetch')))
        }
        if (isForm(body)) {
          // FormData on a chat path: its text fields are the message. Check
          // them as one body; rewrite them if redacted; file parts stay.
          const fields = {}
          for (const [k, v] of body.entries()) if (typeof v === 'string') fields[k] = v
          const raw = JSON.stringify(fields)
          return send(self, input, init, raw, path)
        }
      }
    } catch { /* capture must never break the chat */ }
    return orig.apply(this, arguments)
  }

  /*
   * XMLHttpRequest: ChatGPT uploads the file itself to its storage host with an
   * XHR PUT. Only an upload (see uploadOf) is held; every other request goes
   * straight to the original send, untouched. State is per open(): a held body
   * is never sent after the page aborts or opens the request again.
   */
  if (typeof XMLHttpRequest !== 'undefined') {
    const XP = XMLHttpRequest.prototype
    const origOpen = XP.open
    const origSend = XP.send
    const origAbort = XP.abort
    const meta = new WeakMap()
    XP.open = function (method, url) {
      try { meta.set(this, { method: String(method).toUpperCase(), url: String(url), sync: arguments[2] === false, token: {}, held: false }) } catch { /* unreadable */ }
      return origOpen.apply(this, arguments)
    }
    XP.abort = function () {
      const m = meta.get(this)
      if (m) { m.token = {}; m.held = false }
      return origAbort.apply(this, arguments)
    }
    /*
     * A refused upload ends the way a network failure does: readyState 4,
     * status 0, readystatechange, error, loadend (and the upload's own).
     * Done by really sending the request to a blob: address nothing serves, so
     * the browser produces those events itself; if that can't be done the
     * events are dispatched by hand.
     */
    function failLikeNetwork(xhr) {
      try {
        origOpen.call(xhr, 'POST', `blob:${location.origin || 'null'}/${newId()}`, true)
        origSend.call(xhr, ' ')
        return
      } catch { /* fall back below */ }
      const fire = (t, type) => { try { t.dispatchEvent(new window.ProgressEvent(type)) } catch { /* nothing to tell */ } }
      try { origAbort.call(xhr) } catch { /* not open */ }
      for (const t of [xhr.upload, xhr]) { if (t) { fire(t, 'error'); fire(t, 'loadend') } }
    }
    XP.send = function (body) {
      const m = meta.get(this)
      // A chat send over XHR gets the same decision as over fetch (a page can
      // fall back to XHR after fetch refused it).
      try {
        const p = m && String(m.url).replace(/^https?:\/\/[^/]+/, '')
        if (m && !m.held && m.method === 'POST' && typeof body === 'string' && CHAT_PATHS.some((re) => re.test(p))) {
          lastInspected = Date.now()
          const r = inspect(body)
          emit({ kind: 'browser.chat.request', app, wire: p.slice(0, 60), ...r.facts,
            ...(r.warn ? { verdict: 'warned\u2192redacted', reason: 'xhr' } : {}) })
          if (r.blocked) {
            try { port && port.postMessage({ t: 'notice', message: true, labels: r.blocked, verdict: 'blocked' }) } catch { /* relay gone */ }
            failLikeNetwork(this)
            return
          }
          const out = r.warn ? redactJsonBody(body, r.warn.names).raw : r.raw
          return origSend.call(this, out)
        }
      } catch { /* never break the page */ }
      if (m && m.held) throw new window.DOMException("Failed to execute 'send' on 'XMLHttpRequest': The object's state must be OPENED.", 'InvalidStateError')
      let up = null
      try {
        if (m && filesGoverned() && (m.method === 'POST' || m.method === 'PUT')) {
          up = uploadOf(body, knownUploadEndpoint(m.method, m.url))
        }
      } catch { up = null }
      if (!up) return origSend.apply(this, arguments)
      const xhr = this
      if (m.sync) {
        // A synchronous send can't wait for a hash: only the file policy applies.
        if (policyOnly(up.parts) === 'go') return origSend.call(xhr, up.body)
        throw new window.DOMException("Failed to execute 'send' on 'XMLHttpRequest': Failed to load", 'NetworkError')
      }
      m.held = true
      const token = m.token
      const settle = (out) => {
        const cur = meta.get(xhr)
        if (cur !== m || cur.token !== token || xhr.readyState !== 1) return // aborted or reopened while held
        m.held = false
        if (out === 'go') origSend.call(xhr, up.body)
        else failLikeNetwork(xhr)
      }
      decideUpload(up).then(settle, () => settle('go'))
    }
  }

  /*
   * Same-origin frames. A page can take a clean fetch or XMLHttpRequest from
   * an iframe it made (claude.ai does: its sends went out through an
   * about:blank frame's native fetch, past every rule). Every same-origin
   * frame the page can reach gets this window's wrappers: when its
   * contentWindow/contentDocument is read, when it is added to the document,
   * when window.open returns it, and when the extension's own script runs in
   * it (manifest: all_frames, match_about_blank).
   */
  function armFrame(w) {
    try {
      if (!w || w === window || w.__shieldCapturePatched) return
      void w.document // throws for a cross-origin frame: not ours to reach, and its sends aren't this page's
      Object.defineProperty(w, '__shieldCapturePatched', { value: true })
      w.fetch = window.fetch
      if (typeof XMLHttpRequest !== 'undefined' && w.XMLHttpRequest) {
        const P = w.XMLHttpRequest.prototype
        const XP = XMLHttpRequest.prototype
        P.open = XP.open
        P.send = XP.send
        P.abort = XP.abort
      }
      if (w.navigator && window.navigator && typeof window.navigator.sendBeacon === 'function') {
        w.navigator.sendBeacon = window.navigator.sendBeacon.bind(window.navigator)
      }
    } catch { /* a frame going away: nothing to arm */ }
  }
  Object.defineProperty(window, '__shieldArm', { value: armFrame })
  for (const C of [window.HTMLIFrameElement, window.HTMLFrameElement, window.HTMLObjectElement]) {
    try {
      const proto = C && C.prototype
      for (const [prop, toWin] of [['contentWindow', (v) => v], ['contentDocument', (v) => v && v.defaultView]]) {
        const d = proto && Object.getOwnPropertyDescriptor(proto, prop)
        if (!d || !d.get) continue
        Object.defineProperty(proto, prop, {
          configurable: true, enumerable: d.enumerable,
          get() { const v = d.get.call(this); armFrame(toWin(v)); return v },
        })
      }
    } catch { /* leave that element type alone */ }
  }
  try {
    const armAll = () => { for (let i = 0; i < window.frames.length; i++) armFrame(window.frames[i]) }
    new window.MutationObserver(armAll).observe(document, { childList: true, subtree: true })
    armAll()
  } catch { /* no DOM yet */ }
  try {
    const origOpen = window.open
    if (typeof origOpen === 'function') {
      window.open = function () { const w = origOpen.apply(this, arguments); armFrame(w); return w }
    }
  } catch { /* leave window.open alone */ }

  /*
   * sendBeacon: the same. It has to answer at once, so a `block` file policy
   * returns false right away; otherwise the beacon is checked and, if it may go,
   * sent when the check ends.
   */
  try {
    const nav = window.navigator
    const origBeacon = nav && nav.sendBeacon
    if (typeof origBeacon === 'function') {
      nav.sendBeacon = function (url, data) {
        try {
          if (filesGoverned()) {
            const up = uploadOf(data, knownUploadEndpoint('POST', String(url)))
            if (up) {
              if (config.mode !== 'observe' && config.files[app] === 'block') { policyOnly(up.parts); return false }
              decideUpload(up).then((out) => { if (out === 'go') origBeacon.call(nav, url, up.body) },
                () => origBeacon.call(nav, url, up.body))
              return true
            }
          }
        } catch { /* never break the page */ }
        return origBeacon.apply(this, arguments)
      }
    }
  } catch { /* no navigator */ }
})()
