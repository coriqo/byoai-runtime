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

document.addEventListener('DOMContentLoaded', async () => {
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

async function refresh() {
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
    return
  }
  const [probed, app] = await Promise.all([probe(), currentApp()])
  lastRender = { probed, app }
  render(probed, app)
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
    el('icon').textContent = icon
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
    set('wait', '•', 'Capture is off',
      'Shield is not recording anything from your browser. Review what it does, then turn it on.')
    primary.textContent = 'Review and turn on'
    primary.dataset.welcome = '1'
    return
  }
  delete primary.dataset.welcome
  if (state === 'mismatch') {
    set('bad', '!', "That isn't your Shield",
      "Something else on this Mac is answering at Shield's address, so nothing is being sent to it.")
    primary.hidden = true
    el('trust').hidden = false
    return
  }
  if (state === 'unverifiable') {
    set('bad', '!', "Shield can't prove who it is",
      'This Shield is too old to pair with the extension. Update it, then reopen this window.')
    primary.hidden = true
    return
  }
  if (state === 'unreachable') {
    set('bad', '!', "Shield isn't running",
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
    set('bad', '!', "Shield's record is shorter than it was",
      `It held ${shorter.was} sealed entries and now holds ${shorter.now}. Something deleted or reset it.`)
    el('accept').hidden = false
  } else if (v.incidents && v.incidents.length) {
    set('bad', '!', 'The record was reset',
      `${v.incidents[0].at}: Shield could not read its record file and started a new one. The old file was kept.`)
  } else if (v.tamper_evident === false) {
    set('bad', '!', 'The record does not check out',
      'An entry no longer matches the signed checkpoint. Open Shield to see where.')
  } else {
    set('ok', '✓', state === 'paired' ? 'Paired with your Shield' : 'Shield is on',
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
    return 'Messages here go out unchanged: Shield can only note that they were sent.'
  }
  if (mode === 'observe') return 'Messages go out unchanged: Shield is set to record only.'
  if (mode === 'block') return 'Personal details are replaced before a message leaves this page, and high-risk messages are stopped.'
  return 'Personal details are replaced before a message leaves this page.'
}

// Renders the same `coriqo_session` login.js writes on a successful sign-in
// — read-only here, this popup never signs anyone in or out itself.
function refreshCoriqoAccount() {
  chrome.storage.local.get('coriqo_session', (v) => {
    const session = v.coriqo_session
    const status = el('coriqo-account-status')
    const button = el('open-login')
    if (session) {
      status.textContent = `Signed in as ${session.email} (${session.tenant_slug}).`
      button.textContent = 'Manage account'
    } else {
      status.textContent = 'Not signed in.'
      button.textContent = 'Sign in to Coriqo'
    }
  })
}

function wire() {
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
  el('open-login').addEventListener('click', () => {
    chrome.tabs.create({ url: chrome.runtime.getURL('login.html') })
    window.close()
  })
  refreshCoriqoAccount()
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
