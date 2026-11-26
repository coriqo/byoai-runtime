/**
 * Coriqo Shield — page-world event relay (isolated world).
 *
 * The page-world capture (content.js, "world": "MAIN") can't call
 * chrome.runtime, and this isolated world can't see the page's fetch. The
 * CustomEvent bridge joins them: relay what the page capture emits into
 * capture rows for the service worker, and pass the user's choice and
 * Shield's mode the other way, so the page capture knows whether to replace
 * personal details. It runs at document_start, before the page's first send.
 *
 * After the extension is reloaded or updated, old content scripts keep
 * running in already-open tabs with no extension behind them ("extension
 * context invalidated"). Every chrome.runtime call here is guarded so that
 * state degrades to doing nothing and a page reload fixes it — it never
 * throws into the host page's console.
 */
(function () {
  'use strict'

  function send(row) {
    try {
      chrome.runtime.sendMessage({ type: 'agent.capture', row }, () => {
        void chrome.runtime.lastError // channel closed without a reply is fine
      })
    } catch {
      // Context invalidated (extension reloaded): stop touching chrome.*.
      disable()
    }
  }

  let disabled = false
  // The key/click fallback's state (see maybeSend); up here because
  // disable() can run before the rest of this script has.
  // Enter and a click within this long are one send.
  const ONE_SEND_MS = 1500
  // How long the fallback row waits for the page capture to report the same
  // send before it is filed. Generous, since a slow page may start its fetch
  // late; a websocket-only send is just noted a few seconds later.
  const FETCH_WAIT_MS = 5000
  let lastSend = 0
  let lastFetchSend = 0
  let pendingFallback = null
  // Nothing is forwarded until the user has agreed on the welcome page. The
  // background worker checks again; this keeps the page-world facts from even
  // leaving this script while capture is off.
  // null until the stored choice has been read. A send in those first moments
  // is held (a few at most) rather than lost, then kept or dropped once known.
  let consented = null
  const held = []
  const announce = () => chrome.runtime.sendMessage({ type: 'agent.pageWatched' }, () => void chrome.runtime.lastError)
  const settle = (value) => {
    consented = value?.version === globalThis.SHIELD_CONSENT_VERSION
    if (consented) held.splice(0).forEach(send); else held.length = 0
    tellPage()
  }

  /*
   * The page-world capture decides whether to replace personal details from
   * what it hears here: the user's choice and Shield's policy, which the
   * service worker saves under `shield_policy` only after the paired Shield
   * proved itself. A string, because objects don't cross between worlds.
   */
  let policy = null
  let toPage = null
  const RULES = window.__shieldRules
  const core = window.__shieldCore // this world's own copy: the page can't reach it
  const sites = (window.__shieldSites && window.__shieldSites.sites) || []
  const found = sites.find((x) => Array.isArray(x.hosts) && x.hosts.includes(location.host)) ||
    { compose: [], send: [], upload: [] }
  // A copy, so an admin's selectors (below) never touch the shared profile.
  const site = { ...found, compose: [...(found.compose || [])], send: [...(found.send || [])] }
  const baseCompose = [...site.compose]
  const baseSend = [...site.send]
  // An admin-added site is on unless Shield's app toggles say it is off; the
  // admin's own selectors go before the generic ones, and only for this host.
  const isExtra = found.optional === true
  function applyExtra() {
    if (!isExtra) return
    const mine = (policy && Array.isArray(policy.extra_sites) ? policy.extra_sites : [])
      .find((x) => x && x.host === location.host)
    site.compose.splice(0, site.compose.length, ...((mine && mine.compose) || []), ...baseCompose)
    site.send.splice(0, site.send.length, ...((mine && mine.send) || []), ...baseSend)
  }
  const gateApp = site.app
  let cfg = { consented: false, mode: 'redact', apps: null, actions: {}, files: {} }
  const eng = gateApp && RULES && core && core.engine(RULES, () => cfg)
  // Why the gate did or didn't act, readable from the page for support (no text,
  // no rule matches: a state word only).
  let gateInfo = { state: '', via: '', kind: '', at: 0 } // what the popup's page check reports
  const diag = (s, kind) => {
    gateInfo = { state: s, via: gateInfo.via, kind: kind || gateInfo.kind, at: Date.now() }
    try { document.documentElement.setAttribute('data-shield-gate', s) } catch { /* no DOM yet */ }
  }
  diag(eng ? 'ready' : `off:${!gateApp ? `no-site:n=${sites.length}:h=${location.host}:top=${window === window.top}:g=${typeof window.__shieldSites}` : !RULES ? 'no-rules' : !core ? 'no-core' : 'no-engine'}`)
  const localWaiters = new Map()
  var gateListeners = null // eslint-disable-line no-var -- read by disable(), which can run first
  let bypass = false // one-shot: set only around the gate's own re-dispatch
  let pendingBar = false
  let lastDec = null
  let stopKeyUntil = 0 // a stopped Enter keydown: its keypress and keyup are stopped too
  let lastPointer = null

  function syncCfg() {
    applyExtra()
    if (!eng) return
    cfg = {
      consented: consented === true,
      mode: ['observe', 'redact', 'block'].includes(policy && policy.mode) ? policy.mode : 'redact',
      apps: policy && policy.apps && typeof policy.apps === 'object' ? policy.apps : null,
      actions: eng.cleanActions(policy && policy.actions),
      files: eng.cleanFiles(policy && policy.files),
    }
  }
  function tellPage() {
    syncCfg()
    if (!toPage) return
    toPage.postMessage({ t: 'config', consented: consented === true, mode: policy?.mode,
      apps: policy?.apps ?? null, actions: policy?.actions ?? null, files: policy?.files ?? null })
  }
  /*
   * One private MessageChannel to the page-world capture, transferred in a
   * single message now, at document_start, before page scripts run (content.js
   * is listed first and is already listening). A page can't send config or
   * warn answers on it: it never holds this end.
   */
  try {
    const channel = new MessageChannel()
    toPage = channel.port1
    toPage.onmessage = (ev) => {
      if (ev.data && ev.data.t === 'warn') onWarn(ev.data)
      else if (ev.data && ev.data.t === 'notice') onNotice(ev.data)
    }
    window.postMessage('shield-agent-port', '*', [channel.port2])
  } catch { toPage = null }

  try {
    chrome.storage.local.get(['consent', 'shield_policy'], (v) => {
      policy = v?.shield_policy ?? null
      settle(v?.consent)
      announce()
    })
    chrome.storage.onChanged.addListener((changes, area) => {
      if (area !== 'local') return
      if (changes.shield_policy) { policy = changes.shield_policy.newValue ?? null; tellPage() }
      if (!changes.consent) return
      settle(changes.consent.newValue)
      announce() // so this tab's badge follows the choice without a reload
    })
  } catch { disable() }

  // Sent now if the choice is known to be yes, held (a few) while it is unknown.
  function forward(row) {
    if (consented === null) { if (held.length < 5) held.push(row) } else if (consented) send(row)
  }

  function onCapture(ev) {
    const row = ev.detail
    if (row && row.kind && !disabled && consented !== false) {
      // The page capture saw this send, so the key/click fallback for the
      // same send is not a second message.
      if (row.kind === 'browser.chat.request') noteSend()
      forward(row)
    }
  }
  function disable() {
    disabled = true
    window.removeEventListener('shield-agent-capture', onCapture)
    // Tell the page first, so sends it is holding go redacted rather than wait.
    try { toPage && toPage.postMessage({ t: 'relay-closed' }) } catch { /* already closed */ }
    const closing = toPage
    toPage = null
    for (const w of bars.values()) w.finish('cancelled')
    try { closing && closing.close() } catch { /* already closed */ }
    clearTimeout(pendingFallback)
    document.removeEventListener('keydown', onKey, true)
    document.removeEventListener('click', onClick, true)
    removeGate()
  }

  window.addEventListener('shield-agent-capture', onCapture)

  /*
   * The warn bar. The page capture holds a send and asks for it here; the
   * bar lives in a closed Shadow DOM (the page's CSS and scripts can't
   * restyle or click it) and shows human names for the rules, never the
   * matched text: it may be screenshotted. Labels arrive from the page, which
   * can be forged, so only names in RULE_LABEL become text; anything else
   * reads as "sensitive data".
   */
  const RULE_LABEL = {
    anthropic_key: 'an Anthropic API key', openai_key: 'an OpenAI API key',
    aws_access_key: 'an AWS access key', github_token: 'a GitHub token',
    slack_token: 'a Slack token', google_api_key: 'a Google API key',
    stripe_key: 'a Stripe key', private_key_block: 'a private key',
    jwt: 'a JSON web token', conn_string: 'a database URL with a password',
    bearer: 'a bearer token', credential_assign: 'a password or key assignment',
    emails: 'an email address', cards: 'a card number', phone_numbers: 'a phone number',
    core_missing: "a check Shield couldn't run",
    ssn_like: 'a social security number', wallets: 'a crypto wallet address', iban: 'an IBAN',
  }
  const WARN_MS = 60_000
  const bars = new Map()
  let barHost = null
  let barBox = null

  function answer(sendId, choice) {
    const local = localWaiters.get(sendId)
    if (local) { localWaiters.delete(sendId); local(choice); return }
    try { toPage && toPage.postMessage({ t: 'warn-result', send_id: sendId, choice }) } catch { /* page gone */ }
  }

  function onWarnHost() {
    barHost = document.createElement('div')
    barHost.style.cssText = 'all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647'
    const root = barHost.attachShadow({ mode: 'closed' })
    const style = document.createElement('style')
    style.textContent = '.bar{font:14px system-ui,sans-serif;background:#1f2937;color:#fff;padding:10px 16px;' +
      'display:flex;gap:10px;align-items:center;flex-wrap:wrap;border-bottom:1px solid #4b5563}' +
      '.msg{flex:1 1 240px}button{font:inherit;border:1px solid #6b7280;border-radius:6px;padding:5px 12px;' +
      'background:#374151;color:#fff;cursor:pointer}button.main{background:#2563eb;border-color:#2563eb}'
    barBox = document.createElement('div')
    root.append(style, barBox)
    ;(document.documentElement || document.body).append(barHost)
  }

  function onWarn(req) {
    if (!req || typeof req.send_id !== 'string' || req.send_id.length > 64 || bars.has(req.send_id)) return
    const sendId = req.send_id
    // A file variant: the file's name is shown here, in the bar only, and
    // never goes into an event. Shown as text, cut short.
    const isFile = req.file === true
    const fileName = isFile && typeof req.name === 'string' ? req.name.slice(0, 80) : ''
    const asked = Array.isArray(req.labels) ? req.labels : []
    const unreadable = isFile && asked.includes('unreadable')
    const names = [...new Set(asked.filter((n) => n !== 'unreadable')
      .map((n) => RULE_LABEL[n] ?? 'sensitive data'))].slice(0, 5)
    let row
    let timer
    const finish = (choice) => {
      if (!bars.delete(sendId)) return
      clearTimeout(timer)
      try { row.remove(); if (!barBox.children.length) { barHost.remove(); barHost = null; barBox = null } } catch { /* page gone */ }
      answer(sendId, choice)
    }
    try {
      if (!barHost) onWarnHost()
      row = document.createElement('div')
      row.className = 'bar'
      row.setAttribute('role', 'alertdialog')
      const msg = document.createElement('span')
      msg.className = 'msg'
      msg.textContent = isFile
        ? `Shield asks before this file goes out${fileName ? ` (${fileName})` : ''}` +
          `${names.length ? `: it contains ${names.join(', ')}` : ''}.` +
          `${unreadable ? " Shield couldn't check this file." : ''}`
        : `This message contains ${names.join(', ') || 'sensitive data'}.`
      const mk = (label, choice, main) => {
        const b = document.createElement('button')
        b.textContent = label
        if (main) b.className = 'main'
        b.addEventListener('click', () => finish(choice))
        return b
      }
      const def = isFile ? mk('Remove file', 'removed', true) : mk('Send redacted', 'redacted', true)
      row.append(msg, def, mk(isFile ? 'Upload anyway' : 'Send anyway', 'sent'), mk('Cancel', 'cancelled'))
      row.addEventListener('keydown', (e) => { if (e.key === 'Escape') finish('cancelled') })
      barBox.append(row)
      def.focus?.() // Enter picks the default
    } catch { answer(sendId, 'cancelled'); return }
    timer = setTimeout(() => finish('cancelled'), WARN_MS)
    bars.set(sendId, { finish })
  }

  /*
   * After Shield stops or removes a file, the app may still show it as
   * attached (its upload just failed). A short notice says it isn't. Same
   * bar area and the same forgery rule: labels outside RULE_LABEL read as
   * "sensitive data", names are shown as text and cut short.
   */
  const NOTICE_MS = 20_000
  function onNotice(req) {
    if (!req) return
    const isMessage = req.message === true
    if (!isMessage && !Array.isArray(req.names)) return
    const names = isMessage ? ['this message'] : req.names.filter((n) => typeof n === 'string').map((n) => n.slice(0, 80)).slice(0, 5)
    if (!names.length) return
    const why = [...new Set((Array.isArray(req.labels) ? req.labels : [])
      .map((n) => RULE_LABEL[n] ?? 'sensitive data'))].slice(0, 5)
    const verb = req.verdict === 'blocked' ? 'stopped' : req.verdict === 'removed' ? 'removed' : 'cancelled'
    try {
      if (!barHost) onWarnHost()
      const row = document.createElement('div')
      row.className = 'bar'
      row.setAttribute('role', 'status')
      const msg = document.createElement('span')
      msg.className = 'msg'
      const list = names.join(', ')
      msg.textContent = req.retry === true
        ? "Shield couldn't send it for you; press send again."
        : req.rewrite === true
        ? "Shield couldn't rewrite this message; remove the details and send again."
        : isMessage
        ? `Shield stopped this message${why.length ? `: it contains ${why.join(', ')}` : ''}. It wasn't sent; ` +
          'remove that part and send again.'
        : `Shield ${verb} ${list}${why.length ? ` (it contains ${why.join(', ')})` : ''}. ` +
        `${names.length > 1 ? "They weren't" : "It wasn't"} uploaded; remove ${names.length > 1 ? 'them' : 'it'} ` +
        'from your message before sending.'
      const ok = document.createElement('button')
      ok.textContent = 'OK'
      let timer
      const close = () => {
        clearTimeout(timer)
        try { row.remove(); if (barBox && !barBox.children.length) { barHost.remove(); barHost = null; barBox = null } } catch { /* page gone */ }
      }
      ok.addEventListener('click', close)
      row.append(msg, ok)
      barBox.append(row)
      timer = setTimeout(close, NOTICE_MS)
    } catch { /* the record still says what happened */ }
  }

  /*
   * The input gate. The page's own JavaScript can always find another way to
   * send (a hidden iframe, a retry with another body), so the message and the
   * files are checked here first, in the isolated world, when the user hands
   * them to the page: Enter, the send button, a form submit, a picked file, a
   * drop, a paste. Listeners sit on `window` in the capture phase and are
   * registered at document_start, so they run before any page handler and the
   * page can neither patch nor read them. The text and files are read here
   * for rule names, counts and hashes only; they go into no event and are
   * never sent anywhere. The rules, actions and file policy are the ones the
   * network wrapper uses (shield-core.js), and that wrapper stays as the
   * backstop.
   */
  const governing = () => !disabled && eng && cfg.consented && (cfg.apps === null || cfg.apps[gateApp] === true || (isExtra && cfg.apps[gateApp] === undefined))
  const newId = () => (globalThis.crypto && crypto.randomUUID ? crypto.randomUUID()
    : Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(''))

  // closest() that also crosses open shadow roots, which a plain closest() stops at.
  const closestDeep = (el, sel) => {
    for (let n = el; n; n = n.getRootNode && n.getRootNode().host) {
      let m = null
      try { m = n.closest && n.closest(sel) } catch { /* bad selector */ }
      if (m) return m
    }
    return null
  }
  const closestAny = (el, sels) => {
    for (const sel of sels) { const m = closestDeep(el, sel); if (m) return m }
    return null
  }
  // Where the user really acted, even inside an open shadow root (window sees only the host).
  const tgt = (ev) => (ev.composedPath && ev.composedPath()[0]) || ev.target
  const queryAny = (root, sels) => {
    for (const sel of sels) { try { const m = root.querySelector(sel); if (m) return m } catch { /* bad selector */ } }
    return null
  }
  const GENERIC_COMPOSE = 'textarea, [contenteditable=""], [contenteditable="true"], [contenteditable="plaintext-only"], [role="textbox"]'
  const GENERIC_SEND = 'button[aria-label*="send" i], [role="button"][aria-label*="send" i], [data-testid*="send" i], ' +
    '[data-testid*="submit" i], button[type="submit"], button[aria-label*="submit" i], [role="button"][aria-label*="submit" i], ' +
    'button[aria-label~="ask" i], [role="button"][aria-label~="ask" i]'
  // A button that is labelled in words only ("Submit") still counts as a send control.
  const SEND_WORD = /\b(send|submit|ask)\b/i
  const BUTTONS = 'button, [role="button"], [type="submit"]'
  // Fields that are never a message box: search, rename and settings dialogs, menus.
  const NOT_COMPOSE = '[role="dialog"], [role="alertdialog"], dialog, [aria-modal="true"], [role="search"], [role="searchbox"], ' +
    '[role="combobox"], [role="listbox"], [role="menu"], [type="search"]'
  const NOT_COMPOSE_LABEL = /search|find|rename|filter|title|folder|name/i
  const labelOf = (el) => {
    const t = (el.textContent || '').trim()
    return `${el.getAttribute('aria-label') || ''} ${el.getAttribute('title') || ''} ${t.length <= 24 ? t : ''}`
  }
  const isSendLike = (el) => {
    try { if (el.matches(GENERIC_SEND)) return true } catch { /* bad selector */ }
    return SEND_WORD.test(labelOf(el))
  }
  const editableAttr = (n) => ['', 'true', 'plaintext-only'].includes(n.getAttribute && n.getAttribute('contenteditable'))
  // The editable field the user is in (a textarea or a contenteditable, shadow roots crossed), or null.
  function editableOf(t) {
    for (let n = t; n; n = n.parentNode || n.host) {
      if (n.nodeType !== 1) continue
      if (n.tagName === 'TEXTAREA') return n.disabled || n.readOnly ? null : n
      if (editableAttr(n)) return n
    }
    return null
  }
  function visible(el) {
    try {
      if (el.hidden) return false
      const st = window.getComputedStyle(el)
      return st.display !== 'none' && st.visibility !== 'hidden'
    } catch { return true }
  }
  // Search boxes, rename dialogs and the like are never edited by the fallback.
  function excluded(el) {
    if (closestDeep(el, NOT_COMPOSE)) return true
    const named = `${el.getAttribute('aria-label') || ''} ${el.getAttribute('placeholder') || ''} ${el.getAttribute('name') || ''} ${el.id || ''}`
    return NOT_COMPOSE_LABEL.test(named) || !visible(el)
  }
  // Every match of a selector under root, open shadow roots included (capped, so a huge page stays cheap).
  function deepAll(root, sel, out = [], budget = { n: 4000 }) {
    if (!root || !root.querySelectorAll) return out
    let found = []
    try { found = root.querySelectorAll(sel) } catch { /* bad selector */ }
    for (const m of found) out.push(m)
    for (const e of root.querySelectorAll('*')) {
      if (--budget.n < 0) break
      if (e.shadowRoot) deepAll(e.shadowRoot, sel, out, budget)
    }
    return out
  }
  const editablesIn = (root) => deepAll(root, GENERIC_COMPOSE).filter((e) => editableOf(e) === e || e.getAttribute('role') === 'textbox')
    .map((e) => editableOf(e)).filter((e, i, all) => e && all.indexOf(e) === i && !excluded(e))
  const area = (el) => { try { const r = el.getBoundingClientRect(); return r.width * r.height } catch { return 0 } }
  const deepActive = () => { let a = document.activeElement; while (a && a.shadowRoot && a.shadowRoot.activeElement) a = a.shadowRoot.activeElement; return a }
  // Of several fields, the one the user is in, else the only one, else the strictly largest.
  function pickEditable(list) {
    if (!list.length) return null
    const act = deepActive()
    const focused = list.find((e) => e === act || (act && e.contains && e.contains(act)))
    if (focused) return focused
    if (list.length === 1) return list[0]
    const sorted = [...list].sort((x, y) => area(y) - area(x))
    return area(sorted[0]) > area(sorted[1]) ? sorted[0] : null
  }
  // The field looks like a message box when a send control sits with it alone, or
  // it is the only or the largest field on the page.
  function looksLikeComposer(el) {
    if (!el || excluded(el)) return false
    let n = el
    for (let i = 0; n && i < 8; i++, n = n.parentNode || n.host) {
      if (!n.querySelectorAll) continue
      const btns = deepAll(n, BUTTONS).filter(isSendLike)
      if (btns.length) return editablesIn(n).length === 1
    }
    const all = editablesIn(document)
    if (all.length === 1) return all[0] === el
    const big = [...all].sort((x, y) => area(y) - area(x))
    return big[0] === el && area(el) > area(big[1])
  }
  // Enter is a send inside the site's own message box, or inside a field that
  // looks like one (see looksLikeComposer); a search field, a rename dialog or
  // an unrelated textarea is not one.
  function composeOf(t) {
    if (!t || !t.closest) return null
    const known = closestAny(t, site.compose)
    if (known) { gateInfo.via = 'site'; return known }
    const f = editableOf(t)
    if (f && looksLikeComposer(f)) { gateInfo.via = 'generic'; return f }
    return null
  }
  const sendOf = (t) => {
    if (!t || !t.closest) return null
    const known = closestAny(t, site.send)
    if (known) return known
    const b = closestDeep(t, BUTTONS)
    return b && isSendLike(b) ? b : null
  }
  // The message box a send button belongs to: the nearest ancestor that holds one
  // (site profile first, then any field), else the page's only or largest box.
  function composeFor(btn) {
    if (closestDeep(btn, NOT_COMPOSE)) return null
    for (let n = btn.parentNode || btn.host; n; n = n.parentNode || n.host) {
      if (!n.querySelector) continue
      const m = queryAny(n, site.compose)
      if (m) { gateInfo.via = 'site'; return m }
      const g = pickEditable(editablesIn(n))
      if (g) { gateInfo.via = 'generic'; return g }
    }
    const g = pickEditable(editablesIn(document))
    if (g) gateInfo.via = 'generic'
    return g
  }
  // The box inside a submitted form.
  function composeInForm(form) {
    if (closestDeep(form, NOT_COMPOSE)) return null
    const m = queryAny(form, site.compose)
    if (m) { gateInfo.via = 'site'; return m }
    const g = pickEditable(editablesIn(form))
    if (g) gateInfo.via = 'generic'
    return g
  }
  const isField = (el) => el.tagName === 'TEXTAREA' || el.tagName === 'INPUT'
  const readText = (el) => (isField(el) ? el.value : (el.innerText ?? el.textContent ?? ''))
  const stop = (ev) => { ev.preventDefault(); ev.stopImmediatePropagation() }

  /*
   * Put new text in the box so the framework notices: the native value
   * setter plus an input event for a textarea, select-all plus
   * execCommand('insertText') for a contenteditable (ProseMirror listens to
   * the beforeinput/input those fire).
   */
  function setText(el, text) {
    if (isField(el)) {
      const proto = el.tagName === 'TEXTAREA' ? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype
      const set = Object.getOwnPropertyDescriptor(proto, 'value')?.set
      if (set) set.call(el, text); else el.value = text
      el.dispatchEvent(new window.Event('input', { bubbles: true }))
      return true
    }
    // A contenteditable's editor model only follows real editing commands; if one
    // isn't taken, setting textContent would change what is drawn but not what
    // the app sends, so the caller stops the send instead.
    try {
      el.focus()
      const sel = window.getSelection()
      const range = document.createRange()
      range.selectNodeContents(el)
      sel.removeAllRanges()
      sel.addRange(range)
      let ok = true
      text.split('\n').forEach((line, i) => {
        if (i > 0) ok = document.execCommand('insertLineBreak') === true && ok
        if (line) ok = document.execCommand('insertText', false, line) === true && ok
      })
      if (!text) ok = document.execCommand('delete') === true && ok
      return ok
    } catch { return false }
  }

  const redactable = (h) => h.tier !== 'flag' && (h.action === 'redact' || h.action === 'warn')
  function judge(text) {
    const hits = text ? eng.scan(text) : []
    const top = hits.reduce((m, h) => Math.max(m, eng.ORDER[h.action]), 0)
    const named = (a) => hits.filter((h) => h.action === a).map((h) => h.name)
    const facts = { chars: text.length, flags: hits.map((h) => `${h.tier}:${h.name}`) }
    if (text.length > eng.SCAN_MAX) facts.flags.push('flag:oversize')
    return { hits, top, facts, blocked: named('block'), warned: named('warn'),
      names: new Set(hits.filter(redactable).map((h) => h.name)),
      keep: new Set(hits.filter((h) => h.tier !== 'flag' && h.action === 'redact').map((h) => h.name)) }
  }
  function redacted(text, names) {
    const hit = new Set()
    const out = eng.redactWithRules(text, names, {}, hit)
    return { out, rules: [...hit].sort() }
  }

  // This send has its row; the key/click fallback would be a second one.
  function noteSend() {
    lastFetchSend = Date.now()
    clearTimeout(pendingFallback)
    pendingFallback = null
  }
  function gateRow(row) {
    noteSend()
    forward({ kind: 'browser.chat.request', stage: 'input', app: gateApp, wire: 'input', ...row })
  }
  function tellGate(id) {
    try { toPage && toPage.postMessage({ t: 'gate', gate_id: id }) } catch { /* page gone */ }
  }

  function askLocal(labels, file) {
    return new Promise((resolve) => {
      const id = `gate-${newId()}`
      localWaiters.set(id, resolve)
      onWarn(file ? { send_id: id, labels, file: true, name: file.name } : { send_id: id, labels })
      if (!bars.has(id) && localWaiters.delete(id)) resolve('cancelled')
    })
  }

  // Send the message on, once, through the gate itself: it is let by the
  // one-shot flag, which only this code can set.
  function redo(kind, ev, compose, gateId) {
    bypass = true
    try {
      if (kind === 'submit' && ev.target && ev.target.requestSubmit) { ev.target.requestSubmit(); return }
      let btn = kind === 'click' ? sendOf(tgt(ev)) : null
      if (!btn || btn.disabled) btn = queryAny(document, site.send) || deepAll(document, BUTTONS).find(isSendLike)
      if (btn && !btn.disabled) { btn.click(); return }
      // No button: a synthetic Enter may not be taken as a send. If the box still
      // holds the same text a moment later, say so instead of failing silently.
      const held = readText(compose)
      compose.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Enter', code: 'Enter', keyCode: 13, which: 13,
        bubbles: true, cancelable: true, composed: true }))
      setTimeout(() => {
        if (disabled || !compose.isConnected || readText(compose) !== held) return
        gateRow({ chars: held.length, flags: [], gate_id: gateId, verdict: 'blocked', reason: 'send_retry_needed' })
        onNotice({ message: true, retry: true, labels: [], verdict: 'blocked' })
      }, 1500)
    } finally { bypass = false }
  }

  function gateSend(ev, kind, compose) {
    if (!eng) return diag('skip:no-engine')
    if (!compose) return diag(`skip:no-compose:${kind}`, kind)
    if (bypass) { bypass = false; return }
    const text = readText(compose)
    const halt = () => { stop(ev); if (kind === 'key') stopKeyUntil = Date.now() + 2000 }
    if (!text.trim()) return diag('skip:empty')
    if (!governing()) return diag(`skip:not-governing:${cfg.consented ? 'c' : 'nc'}:${cfg.apps === null ? 'all' : cfg.apps[gateApp] ? 'on' : 'off'}`)
    diag('judged', kind)
    const now = Date.now()
    // pointerdown then click, or Enter then the form's submit, are one send: one
    // decision. A repeat of the same text any other way is a new send, judged and recorded.
    const pair = lastDec && now - lastDec.at < 1000 && (text === lastDec.text || text === lastDec.after) &&
      ((lastDec.evType === 'pointerdown' && ev.type === 'click') || (ev.type === 'submit' && lastDec.evType !== 'submit'))
    if (pair) {
      if (lastDec.stopped) halt()
      return
    }
    if (pendingBar) { halt(); return }
    const id = newId()
    const j = judge(text)
    const dec = { at: now, text, after: null, stopped: false, evType: ev.type }
    lastDec = dec
    const noticeStop = (labels) => onNotice({ message: true, labels, verdict: 'blocked' })
    if (j.top === eng.ORDER.block) {
      dec.stopped = true
      halt()
      gateRow({ ...j.facts, gate_id: id, verdict: 'blocked' })
      noticeStop(j.blocked)
      return
    }
    // Rewrites the box; false if what the framework holds still has a name to hide.
    const rewrite = (names) => {
      const { out, rules } = redacted(text, names)
      if (!rules.length) return { rules }
      if (!setText(compose, out)) return null
      dec.after = readText(compose)
      const left = judge(dec.after).hits.some((h) => redactable(h) && names.has(h.name))
      return left ? null : { rules }
    }
    const failClosed = (labels) => {
      dec.stopped = true
      gateRow({ ...j.facts, gate_id: id, verdict: 'blocked', reason: 'rewrite_failed' })
      onNotice({ message: true, rewrite: true, labels, verdict: 'blocked' })
    }
    if (j.top === eng.ORDER.warn) {
      dec.stopped = true
      halt()
      pendingBar = true
      askLocal(j.warned).then((choice) => {
        pendingBar = false
        dec.at = Date.now()
        if (choice !== 'sent' && choice !== 'redacted') {
          gateRow({ ...j.facts, gate_id: id, verdict: 'warned→cancelled' })
          return
        }
        const r = rewrite(choice === 'sent' ? j.keep : j.names)
        if (!r) { failClosed(j.warned); return }
        gateRow({ ...j.facts, gate_id: id, redactions: r.rules,
          verdict: choice === 'sent' ? 'warned→sent' : 'warned→redacted' })
        tellGate(id)
        dec.stopped = false
        redo(kind, ev, compose, id)
      })
      return
    }
    let rules = []
    if (j.names.size) {
      const r = rewrite(j.names)
      if (!r) { halt(); failClosed(j.warned.concat(j.blocked)); return }
      rules = r.rules
    }
    gateRow({ ...j.facts, gate_id: id, redactions: rules,
      verdict: rules.length ? `redacted(${rules.length})` : cfg.mode })
    tellGate(id)
  }

  function onGateKey(ev) {
    if (ev.key !== 'Enter' || ev.shiftKey || ev.altKey || ev.isComposing || ev.keyCode === 229) return
    // Ctrl/Cmd+Enter is a send in several apps, so it is gated like Enter.
    const t = tgt(ev)
    const c = composeOf(t)
    if (!c) {
      // An editable field that is not a message box: left alone, and said so.
      const f = t && t.closest ? editableOf(t) : null
      if (f) diag(excluded(f) ? 'skip:excluded:key' : 'skip:no-compose:key', 'key')
      return
    }
    gateSend(ev, 'key', c)
  }
  function onGateKeyAfter(ev) {
    if (ev.key !== 'Enter' || Date.now() >= stopKeyUntil) return
    stop(ev)
    if (ev.type === 'keyup') stopKeyUntil = 0
  }
  function onGateClick(ev) {
    const btn = sendOf(tgt(ev))
    if (!btn || !eng) return
    const now = Date.now()
    // A blocked pointerdown also stops the click that follows it, whatever the box holds by then.
    if (!bypass && ev.type === 'click' && lastPointer && lastPointer.btn === btn && lastPointer.stopped &&
        now - lastPointer.at < 1000) { stop(ev); return }
    const c = composeFor(btn)
    if (!c) { if (ev.type === 'click') diag('skip:no-compose:click', 'click'); return }
    gateSend(ev, 'click', c)
    if (ev.type === 'pointerdown') lastPointer = { btn, at: now, stopped: ev.defaultPrevented }
  }
  function onGateSubmit(ev) {
    const form = ev.target
    if (!form || !form.querySelector) return
    const c = composeInForm(form)
    if (!c) { diag('skip:no-compose:submit', 'submit'); return }
    gateSend(ev, 'submit', c)
  }

  // --- files ---

  const isFileInput = (t) => t && t.tagName === 'INPUT' && t.type === 'file'
  const pendingInputs = new WeakSet()
  const nameOfFile = (f) => (f && f.name ? String(f.name) : 'a file')

  function tryDataTransfer(list, origin) {
    try {
      const dt = new window.DataTransfer()
      for (const f of list) dt.items.add(f)
      // Text that came with a pasted or dropped file goes along.
      for (const t of origin ? Array.from(origin.types || []) : []) {
        if (t !== 'Files') { try { dt.setData(t, origin.getData(t)) } catch { /* unreadable type */ } }
      }
      return dt
    } catch { return null }
  }

  // Hand the (possibly reduced) files to the page. False if that can't be done.
  function release(kind, target, list, all, originDt) {
    if (kind === 'input') {
      if (list.length !== all.length) {
        const dt = tryDataTransfer(list, null)
        if (!dt) return false
        try { target.files = dt.files } catch { return false }
        if (!target.files || target.files.length !== list.length) return false
      }
      for (const type of ['input', 'change']) {
        bypass = true
        try { target.dispatchEvent(new window.Event(type, { bubbles: true, composed: true })) } finally { bypass = false }
      }
      return true
    }
    const dt = tryDataTransfer(list, originDt)
    if (!dt) return false
    const init = { bubbles: true, cancelable: true, composed: true }
    const Ctor = kind === 'drop' ? window.DragEvent : window.ClipboardEvent
    let ev
    try { ev = new Ctor(kind, { ...init, [kind === 'drop' ? 'dataTransfer' : 'clipboardData']: dt }) } catch { ev = null }
    const prop = kind === 'drop' ? 'dataTransfer' : 'clipboardData'
    if (!ev || !ev[prop] || ev[prop].files.length !== list.length) {
      ev = new window.Event(kind, init)
      Object.defineProperty(ev, prop, { value: dt })
    }
    bypass = true
    try { target.dispatchEvent(ev) } finally { bypass = false }
    return true
  }
  function clear(kind, target) {
    if (kind === 'input') { try { target.value = '' } catch { /* read-only */ } }
  }

  async function processFiles(kind, target, files, originDt) {
    let a
    try { a = await eng.assessFiles(gateApp, files.map((f) => ({ blob: f, name: f.name }))) } catch { a = null }
    if (!a) { clear(kind, target); onNotice({ names: files.map(nameOfFile).slice(0, 5), labels: [], verdict: 'cancelled' }); return }
    const gate_id = newId()
    const rows = (verdictOf) => a.facts.forEach((f, i) => forward({
      kind: 'browser.chat.attachment', stage: 'input', app: gateApp, name: f.name && f.name.slice(0, 512),
      mime: f.mime, bytes: f.bytes, sha256: f.sha256, scanned: f.scanned, flags: a.flagsOf(f),
      rules_version: RULES.rules_version, gate_id, verdict: verdictOf(f, i) }))
    const say = (idx, verdict) => onNotice({ names: idx.map((i) => nameOfFile(files[i])).slice(0, 5),
      labels: [...new Set(idx.flatMap((i) => a.facts[i].hits.map((h) => h.name)))], verdict })
    const all = files.map((_, i) => i)
    const flagged = all.filter((i) => a.level(a.facts[i]) > 0)
    const cancel = (verdict) => { clear(kind, target); say(all, verdict) }
    const go = (list) => {
      if (!release(kind, target, list.map((i) => files[i]), files, originDt)) { cancel('cancelled'); return false }
      return true
    }
    if (a.top === 0) { rows(() => 'allowed'); go(all); return }
    if (a.top === 2) { rows(() => 'blocked'); cancel('blocked'); return }
    const choice = await askLocal(a.labels, { name: files.length === 1 ? nameOfFile(files[0]) : `${files.length} files` })
    if (choice === 'sent') { rows((f) => (a.level(f) > 0 ? 'warned→uploaded' : 'allowed')); go(all); return }
    if (choice === 'removed') {
      const rest = all.filter((i) => !flagged.includes(i))
      rows((f) => (a.level(f) > 0 ? 'warned→removed' : 'allowed'))
      if (rest.length) { if (go(rest)) say(flagged, 'removed') } else { clear(kind, target); say(flagged, 'removed') }
      return
    }
    rows(() => 'cancelled')
    cancel('cancelled')
  }

  function onGateFileInput(ev) {
    const t = tgt(ev)
    if (!eng || !isFileInput(t)) return
    if (bypass) { bypass = false; return }
    if (!t.files || !t.files.length || !governing()) return
    stop(ev)
    if (pendingInputs.has(t)) return // its `input` and `change` are one pick
    pendingInputs.add(t)
    processFiles('input', t, Array.from(t.files), null).catch(() => clear('input', t))
      .finally(() => pendingInputs.delete(t))
  }
  function onGateFileEvent(ev, dt, kind) {
    if (!eng) return
    if (bypass) { bypass = false; return }
    const files = dt && dt.files ? Array.from(dt.files) : []
    if (!files.length || !governing()) return
    stop(ev)
    processFiles(kind, tgt(ev), files, dt).catch(() => {})
  }
  const onGateDrop = (ev) => onGateFileEvent(ev, ev.dataTransfer, 'drop')
  const onGatePaste = (ev) => onGateFileEvent(ev, ev.clipboardData, 'paste')

  function installGate() {
    if (!eng || gateListeners) return
    gateListeners = [['keydown', onGateKey], ['click', onGateClick], ['pointerdown', onGateClick],
      ['submit', onGateSubmit], ['change', onGateFileInput], ['input', onGateFileInput],
      ['drop', onGateDrop], ['paste', onGatePaste], ['keypress', onGateKeyAfter], ['keyup', onGateKeyAfter]]
    for (const [type, fn] of gateListeners) window.addEventListener(type, fn, true)
  }
  function removeGate() {
    for (const [type, fn] of gateListeners || []) window.removeEventListener(type, fn, true)
    gateListeners = null
  }
  syncCfg()
  installGate()

  /*
   * The popup's "Copy page check": facts about this page's controls and the
   * gate's last decision, so a selector that misses can be fixed without live
   * access. Tag, role, aria-label, data-testid and type only (each cut short);
   * never a field's text or value, and never what the user typed. Asked for by
   * the popup through activeTab; nothing leaves the browser until the user
   * copies it.
   */
  const cut = (v) => (v == null ? '' : String(v).replace(/\s+/g, ' ').slice(0, 60))
  const shape = (el) => ({
    tag: el.tagName.toLowerCase(), role: cut(el.getAttribute('role')), aria_label: cut(el.getAttribute('aria-label')),
    data_testid: cut(el.getAttribute('data-testid')), type: cut(el.getAttribute('type')),
    editable: el.tagName === 'TEXTAREA' || editableAttr(el),
  })
  function pageCheck() {
    const count = (sel) => { try { return deepAll(document, sel).length } catch { return 0 } }
    const act = deepActive()
    const focused = act && act !== document.body ? editableOf(act) || act : null
    const buttons = deepAll(document, BUTTONS).filter((b) => /send|submit|ask/i.test(labelOf(b)) || isSendLike(b)).slice(0, 12)
    return {
      host: location.host, framed: window !== window.top, version: chrome.runtime.getManifest().version,
      gate: document.documentElement.getAttribute('data-shield-gate') || '', last_kind: gateInfo.kind, found_by: gateInfo.via,
      last_at: gateInfo.at ? new Date(gateInfo.at).toISOString() : '',
      app: gateApp || '', consented: cfg.consented, mode: cfg.mode,
      app_on: cfg.apps === null ? 'all' : cfg.apps[gateApp] === true ? 'on' : 'off',
      compose_selectors: Object.fromEntries(site.compose.map((x) => [x, count(x)])),
      send_selectors: Object.fromEntries(site.send.map((x) => [x, count(x)])),
      generic_editables: editablesIn(document).length,
      focused: focused ? { ...shape(focused), excluded: excluded(focused), looks_like_composer: looksLikeComposer(editableOf(focused) || focused) } : null,
      buttons: buttons.map(shape),
    }
  }
  try {
    chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
      if (!msg || msg.type !== 'shield.pageCheck') return
      try { reply(pageCheck()) } catch (e) { reply({ host: location.host, gate: 'check-failed', error: String(e && e.message).slice(0, 80) }) }
    })
  } catch { /* extension context gone: a page reload fixes it */ }

  // Fallback for sends that don't go over fetch: watch the send control so a
  // websocket-only send is still recorded as data-free activity. Enter or a
  // click comes before the app's fetch, so the fallback row waits (see
  // FETCH_WAIT_MS) and is dropped if the page capture records the same send.
  function onKey(ev) {
    if (ev.key === 'Enter' && ev.target &&
        ev.target.matches?.('textarea, [contenteditable="true"], input')) {
      maybeSend()
    }
  }
  function onClick(ev) {
    if (ev.target.closest?.('button[data-testid="send-button"], button[aria-label*="Send"]')) {
      maybeSend()
    }
  }
  function maybeSend() {
    if (disabled || consented === false) return
    const now = Date.now()
    if (now - lastSend < ONE_SEND_MS) return // Enter and the click for one send
    lastSend = now
    if (now - lastFetchSend < FETCH_WAIT_MS) return // the page capture already has it
    clearTimeout(pendingFallback)
    pendingFallback = setTimeout(() => {
      pendingFallback = null
      if (disabled || consented === false) return
      forward({ kind: 'browser.chat.request', app: location.host, chars: null, wire: 'input' })
    }, FETCH_WAIT_MS)
  }

  document.addEventListener('keydown', onKey, true)
  document.addEventListener('click', onClick, true)
})()
