/**
 * Popup: is Shield running, is it YOUR Shield, is this tab covered, one button
 * to open Shield. State is asked of the service worker and the local server;
 * the popup renders those facts, it never invents them. It checks once and
 * must never be able to hang on "Checking Shield".
 */
const el = (id) => document.getElementById(id)

const FALLBACK_ENDPOINT = 'http://127.0.0.1:17831/api/browser'
const APPS = {
  'claude.ai': 'Claude',
  'chatgpt.com': 'ChatGPT',
  'chat.openai.com': 'ChatGPT',
  'gemini.google.com': 'Gemini',
  'copilot.microsoft.com': 'Copilot',
  'copilot.com': 'Copilot',
  'copilot.cloud.microsoft': 'Copilot',
  'm365.cloud.microsoft': 'Copilot',
}
let lastRender = null
const STALE_AFTER_MS = 7 * 24 * 3600 * 1000

/*
 * The status icon is a line drawing on the 24px icon size. Record integrity
 * (verified, failed) uses the reticle seal's own drawing, as everywhere else
 * in Shield; the other states are a pending seal, an alert triangle and a
 * paused circle. Built from DOM nodes, never from a string of markup.
 */
const SVG_NS = 'http://www.w3.org/2000/svg'
const ICON_DRAWINGS = {
  pending: ['seal', 'dot'],
  verified: ['seal', 'M11.6 16.3l3.1 3.1 5.9-6.4'],
  failed: ['seal', 'M12.5 12.5l7 7M19.5 12.5l-7 7'],
  alert: ['line', 'M16 5l12 21H4zM16 13v6M16 23v.1'],
  off: ['line', 'M16 5a11 11 0 100 22 11 11 0 000-22zM11 16h10'],
}
function drawIcon(name) {
  const [kind, glyph] = ICON_DRAWINGS[name] || ICON_DRAWINGS.pending
  const svg = document.createElementNS(SVG_NS, 'svg')
  svg.setAttribute('viewBox', '0 0 32 32')
  const add = (tag, attrs) => {
    const node = document.createElementNS(SVG_NS, tag)
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v)
    svg.append(node)
  }
  const stroke = { fill: 'none', stroke: 'currentColor', 'stroke-linecap': 'round', 'stroke-linejoin': 'round' }
  if (kind === 'seal') {
    add('circle', { cx: 16, cy: 16, r: 11, 'stroke-width': 3.6, ...stroke })
    if (glyph === 'dot') add('circle', { cx: 16, cy: 16, r: 4.6, fill: 'currentColor' })
    else add('path', { d: glyph, 'stroke-width': 2.4, ...stroke })
  } else {
    add('path', { d: glyph, 'stroke-width': 2.4, ...stroke })
  }
  el('icon').replaceChildren(svg)
}

document.addEventListener('DOMContentLoaded', async () => {
  drawIcon('pending')
  el('ext-id').textContent = chrome.runtime.id
  wire()
  await refresh()
})

let consented = false

/*
 * Admin-added sites that this browser has not allowed yet: one plain line per
 * site and a button. chrome.permissions.request only works from a click, so the
 * button is the whole reason this lives in the popup. Also says when the
 * service worker could not set a site up.
 */
async function renderExtraSites() {
  const box = el('extra-sites')
  box.textContent = ''
  box.hidden = true
  try {
    const X = globalThis.SHIELD_EXTRA_SITES
    const store = await chrome.storage.local.get(['shield_policy', 'extra_sites_status'])
    const wanted = X.cleanExtraSites(store.shield_policy?.extra_sites, globalThis.SHIELD_OPTIONAL_SITES)
    const granted = new Set()
    for (const s of wanted) {
      if (await chrome.permissions.contains({ origins: [X.originOf(s.host)] })) granted.add(s.host)
    }
    const line = (text) => { const p = document.createElement('p'); p.className = 'help'; p.textContent = text; box.append(p) }
    for (const site of X.pendingGrants(wanted, granted)) {
      line(X.grantLine(site))
      const b = document.createElement('button')
      b.className = 'small'
      b.textContent = `Allow ${site.host}`
      b.addEventListener('click', async () => {
        let ok = false
        try { ok = await chrome.permissions.request({ origins: [X.originOf(site.host)] }) } catch { ok = false }
        if (ok) await send({ type: 'agent.syncExtraSites' }).catch(() => null)
        else b.textContent = `Not allowed. Click to try again: ${site.host}`
        await renderExtraSites()
      })
      box.append(b)
    }
    const off = store.extra_sites_status?.off
    if (off && wanted.length) line(`${off} Reload the extension at chrome://extensions, or ask your administrator.`)
    box.hidden = !box.childNodes.length
  } catch { /* the popup still works without this block */ }
}

let coriqoOff = false
async function coriqoPolicy() {
  let raw = {}
  try { raw = (await chrome.storage.managed?.get(null)) || {} } catch { /* none */ }
  return globalThis.CoriqoLink.linkPolicy(raw)
}

// Sign-in is optional and separate from capture; the popup only says where it stands and opens the page.
async function renderCoriqo() {
  try {
    const s = await chrome.storage.local.get(['coriqo_session', 'coriqo_link'])
    const L = globalThis.CoriqoLink
    const btn = el('connect-coriqo')
    const line = el('coriqo-line')
    coriqoOff = !(await coriqoPolicy()).enabled
    btn.disabled = coriqoOff
    if (coriqoOff) {
      line.textContent = 'Your organisation has turned off connecting to Coriqo.'
      btn.textContent = 'Connect to Coriqo'
      return
    }
    if (L.sessionExpired(s.coriqo_session)) { // expired is signed out
      await chrome.storage.local.remove('coriqo_session')
      s.coriqo_session = null
    }
    if (s.coriqo_link && L.linkSummary(s.coriqo_link)) {
      line.textContent = L.linkSummary(s.coriqo_link)
      btn.textContent = 'Coriqo account'
    } else if (s.coriqo_session) {
      line.textContent = `Signed in${s.coriqo_session.email ? ` as ${s.coriqo_session.email}` : ''}. This computer isn't connected yet.`
      btn.textContent = 'Connect this computer'
    } else {
      line.textContent = 'Optional: link this computer to your Coriqo account.'
      btn.textContent = 'Connect to Coriqo'
    }
  } catch { /* the popup works without it */ }
}

async function refresh() {
  renderCoriqo()
  renderExtraSites()
  // A cold worker can miss the timeout; fall back to what is stored rather than
  // showing "off" for someone whose capture is running.
  const asked = await withTimeout(send({ type: 'agent.getConsent' }), 3000).catch(() => null)
  consented = asked ? !!asked.granted : (await chrome.storage.local.get('consent')).consent?.version === globalThis.SHIELD_CONSENT_VERSION
  el('consent-box').hidden = !consented
  if (!consented) {
    // Nothing is checked or shown as "working" until the user has agreed.
    const endpoint = (await withTimeout(send({ type: 'agent.getEndpoint' }), 1500).catch(() => null))?.endpoint
      || FALLBACK_ENDPOINT
    lastRender = { probed: { state: 'off', endpoint }, app: await currentApp() }
    render(lastRender.probed, lastRender.app)
    el('gate-line').hidden = true
    return
  }
  const [probed, app] = await Promise.all([probe(), currentApp()])
  lastRender = { probed, app }
  render(probed, app)
  await showGate(app)
}

async function showGate(app) {
  const line = el('gate-line')
  line.hidden = true
  if (!app || !app.name) return
  const check = await pageCheck()
  const text = gateLine(check && check.gate, check)
  line.textContent = text
  line.hidden = !text
}

async function probe() {
  const check = await withTimeout(send({ type: 'agent.checkServer' }), 2500).catch(() => undefined)
  const endpoint = check?.endpoint || FALLBACK_ENDPOINT
  const state = check?.state || 'unreachable'
  if (state !== 'ok' && state !== 'paired') return { state, endpoint }
  try {
    const res = await withTimeout(fetch(baseOf(endpoint) + '/api/verify', { cache: 'no-store' }), 1500)
    if (!res.ok) throw new Error(String(res.status))
    const verify = await res.json()
    // The background worker owns the witness (one writer, so an Accept cannot
    // race a check); a shorter record stays flagged until "Accept".
    const noted = await withTimeout(send({ type: 'agent.noteWitness', total: verify.sealed_total }), 1500)
      .catch(() => null)
    if (noted?.shorter) return { state, endpoint, verify, apps: {}, shorter: noted.shorter }
    let apps = {}
    let mode = null
    try {
      const policy = await withTimeout(fetch(baseOf(endpoint) + '/api/policy', { cache: 'no-store' }), 1500)
      const p = await policy.json()
      apps = p.apps || {}
      mode = p.mode || null
    } catch { /* an older Shield: say nothing rather than guess */ }
    return { state, endpoint, verify, apps, mode }
  } catch {
    return { state: 'unreachable', endpoint }
  }
}

async function currentApp() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    const host = tab?.url ? new URL(tab.url).host : ''
    const seen = (await chrome.storage.local.get('last_capture')).last_capture || {}
    const today = (await chrome.storage.local.get('today')).today
    const health = (await chrome.storage.local.get('health_unmatched')).health_unmatched || {}
    const stale = Object.keys(health).filter((k) => Date.now() - health[k] < 24 * 3600 * 1000)
      .map((k) => ({ claude: 'Claude', chatgpt: 'ChatGPT' })[k]).filter(Boolean)
    return { host, name: APPS[host] || null, lastSeen: seen[host] || null, outdated: stale,
      seen, notedToday: today?.day === new Date().toDateString() ? today.n : 0 }
  } catch {
    return { host: '', name: null, lastSeen: null, seen: {}, notedToday: 0 }
  }
}

/*
 * Ask the open tab's content script what it found (activeTab, no new
 * permission). No answer means its scripts are not running there. The reply
 * holds control shapes and the gate's state only, never what was typed.
 */
async function pageCheck() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    if (!tab || tab.id == null) return null
    return await withTimeout(new Promise((resolve) => {
      try {
        chrome.tabs.sendMessage(tab.id, { type: 'shield.pageCheck' }, { frameId: 0 }, (r) => { void chrome.runtime.lastError; resolve(r || null) })
      } catch { resolve(null) }
    }), 1500)
  } catch { return null }
}

/*
 * One plain line for what the gate last did on this page, with where to fix it,
 * or '' when there is nothing to say. Values are those of data-shield-gate.
 */
function gateLine(gate, check) {
  if (!check) return 'Shield\'s page checks are not running in this tab. Reload the tab. If this stays, choose Copy page check and send it to us.'
  const g = check.gate || ''
  if (g.startsWith('off:')) return 'Shield\'s page checks did not finish starting here. Reload the tab, or update the extension at chrome://extensions.'
  if (g.startsWith('skip:no-compose')) return 'Shield could not tell which box on this page is the message box, so your last message was not checked. Choose Copy page check and send it to us.'
  if (g.startsWith('skip:excluded')) return 'Your last Enter was in a search, rename or dialog field, which Shield does not check.'
  if (g === 'skip:not-governing:nc:all' || g.startsWith('skip:not-governing:nc')) return 'Capture is off, so messages here are not checked. Choose Review and turn on.'
  if (g.startsWith('skip:not-governing')) return 'Shield is set not to check this app, so messages here are not checked. Turn it on in Shield, Settings.'
  return ''
}

const baseOf = (endpoint) => endpoint.replace(/\/api\/browser$/, '')

function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms)),
  ])
}

function ago(ms) {
  const mins = Math.max(1, Math.round((Date.now() - ms) / 60000))
  if (mins < 60) return `${mins} min ago`
  const hours = Math.round(mins / 60)
  if (hours < 48) return `${hours} h ago`
  return `${Math.round(hours / 24)} days ago`
}

const shortAddress = (endpoint) => { try { return new URL(endpoint).host } catch { return endpoint } }

function render({ state, endpoint, verify, apps, mode, shorter }, app) {
  el('endpoint').value = endpoint
  el('addr').textContent = shortAddress(endpoint)
  el('addr').title = baseOf(endpoint)
  el('version').textContent = `v${chrome.runtime.getManifest?.().version ?? ''}`
  const set = (kind, icon, title, detail) => {
    el('status').className = `status ${kind}`
    drawIcon(icon)
    el('state-title').textContent = title
    el('state-detail').textContent = detail
  }
  const primary = el('open-shield')
  el('help').hidden = true
  el('trust').hidden = true
  el('accept').hidden = true
  primary.hidden = false
  primary.textContent = 'Open Shield'
  el('tab').textContent = ''

  if (state === 'off') {
    set('wait', 'off', 'Capture is off',
      'Shield is not recording anything from your browser. Review what it does, then turn it on.')
    primary.textContent = 'Review and turn on'
    primary.dataset.welcome = '1'
    return
  }
  delete primary.dataset.welcome
  if (state === 'mismatch') {
    set('bad', 'alert', "That isn't your Shield",
      "Something else on this Mac is answering at Shield's address, so nothing is being sent to it.")
    primary.hidden = true
    el('trust').hidden = false
    return
  }
  if (state === 'unverifiable') {
    set('bad', 'alert', "Shield can't prove who it is",
      'This Shield is too old to pair with the extension. Update it, then reopen this window.')
    primary.hidden = true
    return
  }
  if (state === 'unreachable') {
    set('bad', 'alert', "Shield isn't running",
      'Messages you send now are held here for a short while, up to 50, then dropped.')
    el('help').hidden = false
    primary.textContent = 'Check again'
    primary.dataset.retry = '1'
    return
  }
  delete primary.dataset.retry
  const v = verify || {}
  const n = v.entries
  if (shorter) {
    set('bad', 'failed', "Shield's record is shorter than it was",
      `It held ${shorter.was} sealed entries and now holds ${shorter.now}. Something deleted or reset it.`)
    el('accept').hidden = false
  } else if (v.incidents && v.incidents.length) {
    set('bad', 'failed', 'The record was reset',
      `${v.incidents[0].at}: Shield could not read its record file and started a new one. The old file was kept.`)
  } else if (v.tamper_evident === false) {
    set('bad', 'failed', 'The record failed verification',
      'An entry no longer matches the signed checkpoint. Open Shield to see where.')
  } else {
    set('ok', 'verified', state === 'paired' ? 'Paired with your Shield' : 'Shield is on',
      typeof n === 'number'
        ? `${n} sealed ${n === 1 ? 'entry' : 'entries'}, all verified.`
        : 'The record is intact.')
  }
  const tab = el('tab')
  const appKey = { Claude: 'claude', ChatGPT: 'chatgpt', Gemini: 'gemini', Copilot: 'copilot' }[app.name]
  if (app.name && apps && apps[appKey] === false) {
    tab.textContent = `Shield is set not to record ${app.name}. Turn it on in Shield's settings and messages here will be noted.`
  } else if (app.name) {
    const b = Object.assign(document.createElement('b'), { textContent: app.name })
    if (app.lastSeen && Date.now() - app.lastSeen < STALE_AFTER_MS) {
      tab.append('Shield watches ', b, ` on this tab. Last message noted ${ago(app.lastSeen)}.`)
    } else {
      tab.append('Shield watches ', b, app.lastSeen
        ? ` on this tab, but has not noted a message in over a week. Send one to check it still works.`
        : ' on this tab. No message noted yet. Send one to check it works.')
    }
  } else if (app.host) {
    tab.textContent = `This tab (${app.host}) is not one Shield covers.`
  }
  if (app.name && !(apps && apps[appKey] === false)) tab.append(' ' + protection(appKey, mode))
  if (app.outdated && app.outdated.length) {
    tab.append(` Shield may be out of date for ${app.outdated.join(' and ')}: chat traffic it does not recognise was seen.`)
  }
  if (app.notedToday > 0) {
    tab.append(` Noted today across all apps: ${app.notedToday}.`)
  }
}

// What happens to a message sent from this tab, in one sentence. Only Claude
// and ChatGPT send their messages as JSON the extension can read and rewrite.
function protection(appKey, mode) {
  if (appKey !== 'claude' && appKey !== 'chatgpt') {
    if (mode === 'observe') return 'Messages go out unchanged: Shield is set to record only.'
    return 'Shield checks your message in the box when you press Enter or Send, and replaces personal details there first. Best effort: not yet confirmed on every page. If it cannot find the box, it says so below.'
  }
  if (mode === 'observe') return 'Messages go out unchanged: Shield is set to record only.'
  if (mode === 'block') return 'Personal details are replaced before a message leaves this page, and high-risk messages are stopped.'
  return 'Personal details are replaced before a message leaves this page.'
}

function wire() {
  el('connect-coriqo').addEventListener('click', () => {
    if (coriqoOff) return
    chrome.tabs.create({ url: chrome.runtime.getURL('login.html') })
    window.close()
  })
  el('open-shield').addEventListener('click', async (ev) => {
    if (ev.currentTarget.dataset.welcome) {
      chrome.tabs.create({ url: chrome.runtime.getURL('welcome.html') })
      window.close()
      return
    }
    if (ev.currentTarget.dataset.retry) { await refresh(); return }
    const endpoint = el('endpoint').value || FALLBACK_ENDPOINT
    chrome.tabs.create({ url: baseOf(endpoint) + '/shield' })
    window.close()
  })
  el('trust').addEventListener('click', async () => {
    await send({ type: 'agent.checkServer', trustCurrent: true })
    await refresh()
  })
  el('accept').addEventListener('click', async () => {
    const button = el('accept')
    const check = await withTimeout(fetch(baseOf(el('endpoint').value || FALLBACK_ENDPOINT) + '/api/verify', { cache: 'no-store' }).then((r) => r.json()), 3000).catch(() => null)
    if (check && Number.isInteger(check.sealed_total)) {
      const done = await withTimeout(send({ type: 'agent.acceptRecord', total: check.sealed_total }), 3000).catch(() => null)
      if (done && !done.error) { await refresh(); return }
    }
    // Say so, rather than leaving the warning in place with no reaction.
    const label = button.textContent
    button.textContent = 'Shield did not answer, try again'
    setTimeout(() => { button.textContent = label }, 2500)
  })
  el('turn-off').addEventListener('click', async () => {
    const button = el('turn-off')
    const done = await withTimeout(send({ type: 'agent.setConsent', granted: false }), 5000).catch(() => null)
    await refresh() // shows the real state, even if the reply was slow
    if ((done && !done.error) || !consented) return
    const label = button.textContent
    button.textContent = 'Could not turn off, try again'
    setTimeout(() => { button.textContent = label }, 2500)
  })
  el('open-privacy').addEventListener('click', (ev) => {
    ev.preventDefault()
    chrome.tabs.create({ url: chrome.runtime.getURL('PRIVACY.md') })
    window.close()
  })
  el('copy-id').addEventListener('click', () => {
    navigator.clipboard.writeText(chrome.runtime.id)
    el('copy-id').textContent = 'Copied'
    setTimeout(() => { el('copy-id').textContent = 'Copy id' }, 1200)
  })
  // An administrator who set the port owns it: no "change address", and a line saying who manages it.
  withTimeout(send({ type: 'agent.getEndpoint' }), 1500).then((r) => {
    if (!r?.managed) return
    el('change-addr').hidden = true
    el('addr').title = `Set by ${r.managedBy || 'your administrator'}`
  }).catch(() => {})
  el('change-addr').addEventListener('click', (ev) => {
    ev.preventDefault()
    el('change-box').hidden = false
    el('endpoint').focus()
  })
  el('copy-addr').addEventListener('click', () => {
    navigator.clipboard.writeText(el('addr').title)
    el('copy-addr').textContent = 'Copied'
    setTimeout(() => { el('copy-addr').textContent = 'Copy' }, 1200)
  })
  el('copy-diag').addEventListener('click', () => {
    const { probed, app } = lastRender || {}
    const lines = [
      `Coriqo Shield extension ${chrome.runtime.getManifest?.().version ?? '?'}`,
      `Extension id: ${chrome.runtime.id}`,
      `Browser: ${navigator.userAgent}`,
      `Shield address: ${probed?.endpoint ?? '?'}`,
      `State: ${probed?.state ?? '?'}`,
      `Sealed entries: ${probed?.verify?.sealed_total ?? '?'}  Record intact: ${probed?.verify?.tamper_evident ?? '?'}`,
      `Apps on in Shield: ${JSON.stringify(probed?.apps ?? {})}`,
      `Noted today: ${app?.notedToday ?? 0}`,
      `Last noted: ${JSON.stringify(Object.fromEntries(Object.entries(app?.seen ?? {}).map(([h, ms]) => [h, new Date(ms).toISOString()])))}`,
    ]
    navigator.clipboard.writeText(lines.join('\n'))
    el('copy-diag').textContent = 'Copied'
    setTimeout(() => { el('copy-diag').textContent = 'Copy details for a bug report' }, 1400)
  })
  el('copy-page').addEventListener('click', async () => {
    const check = await pageCheck()
    const { probed } = lastRender || {}
    const out = { extension: chrome.runtime.getManifest?.().version ?? '?', shield_state: probed?.state ?? '?',
      page: check || 'no answer: the content scripts are not running in this tab' }
    navigator.clipboard.writeText(JSON.stringify(out, null, 2))
    el('copy-page').textContent = 'Copied'
    setTimeout(() => { el('copy-page').textContent = 'Copy page check' }, 1400)
  })
  el('save').addEventListener('click', async () => {
    const msg = el('msg')
    const r = await send({ type: 'agent.setEndpoint', endpoint: el('endpoint').value.trim() })
    msg.className = `msg ${r && r.ok ? 'ok' : 'bad'}`
    msg.textContent = r && r.ok ? 'Saved.' : (r?.error || 'That is not a Shield address on this Mac.')
    if (r && r.ok) await refresh()
  })
}

function send(msg) {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(msg, (r) => {
        void chrome.runtime.lastError
        resolve(r)
      })
    } catch { resolve(undefined) }
  })
}
