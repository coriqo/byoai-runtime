/**
 * Coriqo Shield — browser capture service worker.
 *
 * Buffers rows from the content scripts and ships them to the local Shield
 * server's /api/browser endpoint, which runs the SAME shared ruleset and
 * seals the interaction into the same Merkle chain as the desktop proxy and
 * the MCP gateway.
 *
 * MV3 kills the worker ~30s after it goes idle, and with it any timer it
 * scheduled and any in-memory state. That turns "queued for 50 rows"
 * silently into "lost on the next coffee break" — think a 4-hour server
 * outage while the worker restarted 400 times — a misleading failure mode.
 * Mitigation, being honest about blind spots: the queue and the fields of
 * a pending retry live in chrome.storage.session (cleared with the browser
 * session, ~RAM semantics), and chrome.alarms drives a re-flush so a
 * worker restart still delivers — within the same cap: if the server
 * stays off, old rows are dropped, never stored forever.
 */
const ENDPOINT_KEY = 'endpoint'

const DEFAULT_ENDPOINT = 'http://127.0.0.1:17831/api/browser'
// Earlier builds defaulted to :8300, which Consul and others also use. A saved
// copy of that old default is treated as "never customised" and follows the
// new default; any other saved endpoint is the user's choice and is kept.
const LEGACY_DEFAULT_ENDPOINT = 'http://127.0.0.1:8300/api/browser'
const resolveEndpoint = (saved) =>
  !saved || saved === LEGACY_DEFAULT_ENDPOINT ? DEFAULT_ENDPOINT : saved

const PIN_KEY = 'pinned_shield'
const LAST_CAPTURE_KEY = 'last_capture'
const WITNESS_KEY = 'witness'
const ROLLBACK_KEY = 'rollback'
// The user's agreement to capture, given on the welcome page. Nothing is
// queued, sent or counted until it exists; withdrawing it removes it again.
const CONSENT_KEY = 'consent'
importScripts('consent.js', 'managed-settings.js')
const CONSENT_VERSION = globalThis.SHIELD_CONSENT_VERSION
const isGranted = (value) => value?.version === CONSENT_VERSION
// A synchronous copy of the stored choice. Every gate reads this right before it
// queues, counts or sends, with no await in between, so a withdrawal (which flips
// it first) cannot slip behind a check that already passed.
let consentOn = false
const hasConsent = async () => { await restore(); return consentOn }
importScripts('extra-sites.js', 'shield-optional.js')
const EXTRA = globalThis.SHIELD_EXTRA_SITES
const EXTRA_STATUS_KEY = 'extra_sites_status'
const TODAY_KEY = 'today'
// app -> when Shield last saw chat traffic it does not recognise (the canary).
const HEALTH_KEY = 'health_unmatched'
// Shield's mode and per-app toggles, as the paired Shield reported them. The
// page-world capture reads it (through content-relay.js) to decide whether to
// replace personal details; with none saved yet, it redacts.
const POLICY_KEY = 'shield_policy'
const MODES = ['observe', 'redact', 'block']
const ACTIONS = ['block', 'warn', 'redact', 'log']
const FILE_ACTIONS = ['allow', 'warn', 'block']
const POLICY_APPS = ['claude', 'chatgpt', 'gemini', 'copilot']
const IDENTITY_PREFIX = 'byoai-shield-identity:'

const b64bytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))

/*
 * A port is not exclusive: another process on this Mac can listen on Shield's
 * address before Shield does and answer "ok" to anything. So before rows are
 * sent, Shield must prove it holds the device key this extension paired with:
 * it signs a fresh nonce, and the signature is checked against the public key
 * pinned on first contact. First contact is trust-on-first-use; after that, a
 * different server is refused until the user chooses to trust it.
 * Returns 'ok' | 'paired' | 'mismatch' | 'unverifiable' | 'unreachable'.
 */
async function checkServer(endpoint, { trustCurrent = false } = {}) {
  let identity
  try {
    const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)),
      (b) => b.toString(16).padStart(2, '0')).join('')
    const base = endpoint.replace(/\/api\/browser$/, '')
    const res = await fetch(`${base}/api/identity?nonce=${nonce}`, { cache: 'no-store' })
    if (res.status === 404) return { state: 'unverifiable' }
    if (!res.ok) return { state: 'unreachable' }
    identity = await res.json()
    const key = await crypto.subtle.importKey(
      'raw', b64bytes(identity.public_key), { name: 'Ed25519' }, false, ['verify'])
    const sig = b64bytes(String(identity.sig).replace(/^ed25519:/, ''))
    const signed = new TextEncoder().encode(IDENTITY_PREFIX + nonce)
    if (!(await crypto.subtle.verify({ name: 'Ed25519' }, key, sig, signed))) {
      return { state: 'mismatch' }
    }
  } catch (err) {
    return { state: err instanceof TypeError && !identity ? 'unreachable' : 'unverifiable' }
  }
  const saved = (await chrome.storage.local.get(PIN_KEY))[PIN_KEY]
  if (!saved || trustCurrent) {
    await chrome.storage.local.set({ [PIN_KEY]: identity.public_key })
    // A different Shield has its own count. Cleared inside the witness queue so a
    // check already waiting for the old Shield cannot write after it.
    await serially(async () => {
      await chrome.storage.local.remove([WITNESS_KEY, ROLLBACK_KEY])
      rolledBack = false
    })
    return { state: 'paired', deviceId: identity.device_id }
  }
  return { state: saved === identity.public_key ? 'ok' : 'mismatch', deviceId: identity.device_id }
}

/*
 * Save Shield's current mode and app toggles. Only from a Shield that just
 * proved it holds the paired key: anything else on the port could otherwise
 * switch redaction off by answering "observe". Nothing about the user is
 * sent to ask; a failure keeps what was saved before.
 */
let policyAskedAt = 0
async function refreshPolicy(endpoint, { verified = false } = {}) {
  if (!consentOn) return
  policyAskedAt = Date.now()
  try {
    if (!verified) {
      const check = await checkServer(endpoint)
      if (check.state !== 'ok' && check.state !== 'paired') return
    }
    const res = await fetch(`${endpoint.replace(/\/api\/browser$/, '')}/api/policy`, { cache: 'no-store' })
    if (!res.ok) return
    const p = await res.json()
    const apps = {}
    for (const app of POLICY_APPS) if (typeof p?.apps?.[app] === 'boolean') apps[app] = p.apps[app]
    const actions = {}
    for (const tier of ['secret', 'pii', 'flag']) {
      if (ACTIONS.includes(p?.actions?.[tier])) actions[tier] = p.actions[tier]
    }
    const files = {}
    for (const app of POLICY_APPS) if (FILE_ACTIONS.includes(p?.files?.[app])) files[app] = p.files[app]
    if (!consentOn) return // withdrawn while asking
    // Admin-added sites: only curated hosts survive, at most MAX_SITES.
    const extra_sites = EXTRA.cleanExtraSites(p?.extra_sites, globalThis.SHIELD_OPTIONAL_SITES)
    await chrome.storage.local.set({
      [POLICY_KEY]: { mode: MODES.includes(p?.mode) ? p.mode : 'redact', apps, actions, files, extra_sites, at: Date.now() },
    })
    syncExtraSites(extra_sites)
  } catch { /* unreachable: keep what was saved */ }
}

/*
 * Admin-added sites. Shield policy (already verified above) lists curated
 * hosts; each one that this browser has been allowed to run on gets the same
 * scripts the manifest injects, registered at runtime. A host the user has not
 * allowed yet is not touched: the popup says which one and offers the button.
 * Every outcome is written to `extra_sites_status` so nothing fails silently.
 */
let extraChain = Promise.resolve()
function syncExtraSites(wanted) {
  return (extraChain = extraChain.then(() => doSyncExtraSites(wanted), () => doSyncExtraSites(wanted)))
}
async function doSyncExtraSites(wantedIn) {
  const status = { at: Date.now(), errors: {}, off: null }
  try {
    const wanted = consentOn ? (wantedIn || []) : []
    if (!chrome.scripting?.registerContentScripts) {
      status.off = wanted.length ? 'This browser has no scripting API, so admin-added sites cannot be checked.' : null
      return
    }
    const granted = new Set()
    for (const site of wanted) {
      try {
        if (await chrome.permissions.contains({ origins: [EXTRA.originOf(site.host)] })) granted.add(site.host)
      } catch (e) { status.errors[site.host] = String(e?.message || e) }
    }
    const registered = (await chrome.scripting.getRegisteredContentScripts())
      .filter((r) => r.id.startsWith('shield-extra-'))
    const plan = EXTRA.planExtraSites({ wanted, registered, granted })
    // Unregister first: a removed site stops being checked as soon as policy says so.
    if (plan.unregister.length) await chrome.scripting.unregisterContentScripts({ ids: plan.unregister })
    if (plan.update.length) await chrome.scripting.updateContentScripts(plan.update)
    if (plan.register.length) await chrome.scripting.registerContentScripts(plan.register)
    for (const host of plan.needsPermission) status.errors[host] = status.errors[host] || 'needs permission'
  } catch (e) {
    status.off = `Admin-added sites could not be set up: ${String(e?.message || e)}`
  } finally {
    try { await chrome.storage.local.set({ [EXTRA_STATUS_KEY]: status }) } catch { /* nothing to report to */ }
  }
}
const syncExtraFromStore = async () => {
  await restore()
  const kept = (await chrome.storage.local.get(POLICY_KEY))[POLICY_KEY]
  return syncExtraSites(kept?.extra_sites || [])
}
chrome.permissions?.onAdded?.addListener(() => { syncExtraFromStore() })
chrome.permissions?.onRemoved?.addListener(() => { syncExtraFromStore() })

// A content script shares the extension's id but runs for a web page and reports
// that page's URL; only our own pages (the popup) report an extension URL.
const isExtensionPage = (sender) =>
  sender.id === chrome.runtime.id && String(sender.url || '').startsWith(chrome.runtime.getURL(''))

let witnessChain = Promise.resolve()
// The witness and the rollback flag are read, compared and written here and
// nowhere else. The popup asks through messages, and every request runs one
// after another, so an Accept cannot land between a check's read and write.
const serially = (fn) => (witnessChain = witnessChain.then(fn, fn))

/*
 * Shield's record lives in files the user's own account can edit. The browser
 * profile is a second place, so the extension remembers the highest count of
 * sealed entries Shield has reported (a single number, never content). If
 * Shield later reports fewer, its record was deleted or rolled back, and the
 * popup says so. Re-pairing with a different Shield starts a fresh witness.
 * Returns the {was, now} of a shorter record (and keeps it flagged), else null.
 */
function noteWitness(total) {
  return serially(async () => {
    // Once a shorter record has been seen the warning stays until the user
    // accepts it (which clears ROLLBACK_KEY). It must not fade just because a
    // later batch reports a count that has caught up again.
    const store = await chrome.storage.local.get([WITNESS_KEY, ROLLBACK_KEY])
    if (store[ROLLBACK_KEY]) { rolledBack = true; return store[ROLLBACK_KEY] }
    if (!Number.isInteger(total)) return null
    const seen = store[WITNESS_KEY]?.total ?? 0
    if (total < seen) {
      const shorter = { was: seen, now: total }
      await chrome.storage.local.set({ [ROLLBACK_KEY]: shorter })
      rolledBack = true
      return shorter
    }
    if (total > seen) await chrome.storage.local.set({ [WITNESS_KEY]: { total } })
    return null
  })
}

function acceptRecord(total) {
  return serially(async () => {
    await chrome.storage.local.set({ [WITNESS_KEY]: { total } })
    await chrome.storage.local.remove(ROLLBACK_KEY)
    rolledBack = false
    setOfflineIfQueued()
  })
}

// Even length-only facts are personal data once they accumulate over time
// (a length timeline is still a usage pattern). A queue without a cap keeps
// them indefinitely when the server is off — days or weeks — which turns a
// temporary blind spot into a stored record nobody asked for. 50 rows ≈ the
// send rate of a normal day; anything older is dropped, not retried forever.
const MAX_QUEUED = 50

const QUEUE_KEY = 'queue'
const RETRY_AT_KEY = 'retry_at'

let queue = []
let timer = null
let restoring = null

const WATCHED_HOST = ['claude.ai', 'chatgpt.com', 'chat.openai.com', 'gemini.google.com', 'copilot.microsoft.com', 'copilot.com', 'copilot.cloud.microsoft', 'm365.cloud.microsoft']

/*
 * Badge on the Shield-covered surfaces: while a Shield page (claude.ai,
 * chatgpt.com) is open, the toolbar shows a check — "this page is watched".
 * Cheap, honest signal; per-tab state lives in the SW's memory.
 * Badge = flow of rows. Green "OK" = page watched; number = rows queued
 * (waiting on the local server); "-" = Shield offline (flush failed).
 */
const WATCHED_BADGE = 'OK'
const OFFLINE_BADGE = '-'

// A watched page tells us it is open (content-relay.js), which needs no
// "tabs" permission. Chrome clears a tab's own badge when it navigates away.
async function markPageWatched(tabId) {
  if (!tabId) return
  if (await hasConsent()) {
    // Each watched page load re-reads Shield's mode, at most once a minute.
    if (Date.now() - policyAskedAt > 60_000) getEndpoint().then((e) => refreshPolicy(e))
    chrome.action.setBadgeText({ tabId, text: WATCHED_BADGE })
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#16a34a' })
    chrome.action.setTitle({ tabId, title: WORKING_TITLE })
  } else {
    chrome.action.setBadgeText({ tabId, text: 'off' })
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#6b7280' })
    chrome.action.setTitle({ tabId, title: 'Shield capture is off. Open this popup to review and turn it on.' })
  }
}

const WORKING_TITLE = 'Shield on this page: personal details are replaced before sending; app, time and length are noted. No message content leaves.'

function setOffline() {
  chrome.action.setBadgeText({ text: OFFLINE_BADGE })
  chrome.action.setBadgeBackgroundColor({ color: '#dc2626' })
  chrome.action.setTitle({ title: 'Shield is offline on this Mac — start it with byoai-shield. Rows are being dropped after 50 queued.' })
}

function setRefused(why) {
  const text = why === 'shorter'
    ? "Shield's record is shorter than it was. Open this popup."
    : why === 'old'
      ? 'Shield is too old to prove it is yours. Update it (pip install -U byoai) and restart it.'
      : "The server on Shield's address isn't your Shield. Nothing is being sent. Open this popup."
  chrome.action.setBadgeText({ text: '!' })
  chrome.action.setBadgeBackgroundColor({ color: '#b42318' })
  chrome.action.setTitle({ title: text })
}

// True while a shorter record is unacknowledged; kept in step with storage so
// no later "all good" badge update can hide it.
let rolledBack = false

function setWorking() {
  if (!consentOn) { chrome.action.setBadgeText({ text: '' }); return }
  if (rolledBack) { setRefused('shorter'); return }
  chrome.action.setBadgeText({ text: WATCHED_BADGE })
  chrome.action.setBadgeBackgroundColor({ color: '#16a34a' })
  chrome.action.setTitle({ title: WORKING_TITLE })
}

function setOfflineIfQueued() {
  if (rolledBack) setRefused('shorter')
  else if (queue.length) setOffline()
  else setWorking()
}

chrome.runtime.onInstalled.addListener((details) => {
  chrome.action.setBadgeText({ text: '' })
  syncExtraFromStore() // an update may have dropped runtime-registered scripts
  // First install: show exactly what this does and ask, before anything runs.
  // Also for someone upgrading from a build that asked less (before 0.5 it
  // captured without asking; before 0.6 it never rewrote a message): they are
  // now off until they choose, so tell them once.
  const before = String(details?.previousVersion || '').split('.').map(Number)
  const askedLess = details?.reason === 'update' && (before[0] === 0 && before[1] < 6)
  if (details?.reason === 'install' || askedLess) {
    chrome.tabs.create({ url: chrome.runtime.getURL('welcome.html') })
  }
})

// A worker that starts fresh (cold start, after termination, after browser
// restart) resumes from what it persisted — or, finding nothing, honestly
// reports the gap.
chrome.runtime.onStartup.addListener(() => { syncExtraFromStore() })
restore()

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return
  if (CONSENT_KEY in changes) {
    consentOn = isGranted(changes[CONSENT_KEY].newValue)
    if (!consentOn) chrome.action.setBadgeText({ text: '' })
  }
  if (!(ROLLBACK_KEY in changes)) return
  rolledBack = !!changes[ROLLBACK_KEY].newValue
  if (rolledBack) setRefused('shorter'); else setOfflineIfQueued()
})

function restore() {
  // A failed read leaves the safe defaults (capture off), never a rejected promise.
  return (restoring ??= doRestore().catch(() => {}))
}

async function doRestore() {
  const kept = await chrome.storage.local.get([ROLLBACK_KEY, CONSENT_KEY])
  rolledBack = !!kept[ROLLBACK_KEY]
  consentOn = isGranted(kept[CONSENT_KEY])
  const store = chrome.storage?.session
  if (!store) return // test harness or older Chrome; memory-only mode
  const data = await store.get([QUEUE_KEY, RETRY_AT_KEY])
  // Rows queued by a build from before consent existed are not sent on the
  // strength of a choice the user never made.
  if (Array.isArray(data[QUEUE_KEY]) && consentOn) {
    queue = data[QUEUE_KEY].slice(-MAX_QUEUED)
  } else if (data[QUEUE_KEY]?.length) {
    queue = []
    await store.set({ [QUEUE_KEY]: [] })
  }
  const retry_at = data[RETRY_AT_KEY]
  if (retry_at && Date.now() < retry_at) {
    timer = setTimeout(flush, retry_at - Date.now())
  } else if (retry_at) {
    // A retry was due while the worker was dead — deliver now.
    flush()
  }
  setOfflineIfQueued()
}

async function persist() {
  const store = chrome.storage?.session
  if (!store) return
  const data = { [QUEUE_KEY]: queue }
  if (timer) data[RETRY_AT_KEY] = Date.now() + 10_000
  await store.set(data)
}

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (msg?.type === 'agent.capture' && msg.row) {
    // Only our own content scripts may file capture rows. Another extension
    // or a page can't reach this listener at all, but a compromised page's
    // relay path would — sender.id is our extension's own ID for any
    // listener entry from our content scripts, undefined otherwise.
    if (sender.id !== chrome.runtime.id) {
      reply?.({ error: 'not the Shield capture relay' })
      return false
    }
    restore().then(() => {
      if (!consentOn) { reply?.({ error: 'capture is off' }); return }
      noteCapture(sender.tab?.url, msg.row.kind)
      noteHealth(msg.row)
      queue.push({ ...msg.row, sent_at: new Date().toISOString(), row_id: crypto.randomUUID() })
      if (queue.length > MAX_QUEUED) queue = queue.slice(-MAX_QUEUED)
      persist()
      scheduleFlush()
      reply?.({ queued: queue.length })
    }, () => reply?.({ error: 'failed' }))
    return true
  } else if (msg?.type === 'agent.checkServer') {
    getEndpoint().then(async (endpoint) => {
      // Re-pairing is the user's decision, made in the popup. Anything coming
      // from a web page's tab (content scripts) can ask for a check, never
      // for a change of who is trusted.
      const r = await checkServer(endpoint, { trustCurrent: msg.trustCurrent === true && isExtensionPage(sender) })
      if (r.state === 'ok' || r.state === 'paired') refreshPolicy(endpoint, { verified: true })
      reply?.({ ...r, endpoint })
    }).catch(() => reply?.({ state: 'unreachable' }))
    return true
  } else if (msg?.type === 'agent.pageWatched') {
    if (sender.id === chrome.runtime.id && sender.tab) markPageWatched(sender.tab.id)
    return false
  } else if (msg?.type === 'agent.setConsent') {
    if (!isExtensionPage(sender)) { reply?.({ error: 'not allowed' }); return false }
    // After restore(), so a late restore cannot overwrite the new choice with the old one.
    restore().then(() => {
      consentOn = msg.granted === true          // first, before any other await
      if (!consentOn) dropEverythingWaiting()
      const done = consentOn
        ? chrome.storage.local.set({ [CONSENT_KEY]: { version: CONSENT_VERSION, at: Date.now() } })
          .then(() => { getEndpoint().then((e) => refreshPolicy(e)) })
        : chrome.storage.local.remove([CONSENT_KEY, LAST_CAPTURE_KEY, TODAY_KEY, POLICY_KEY, HEALTH_KEY])
          .then(() => syncExtraSites([])) // withdrawn: admin-added sites stop too
      return done
    }).then(() => reply?.({ ok: true }), () => reply?.({ error: 'failed' }))
    return true
  } else if (msg?.type === 'agent.getConsent') {
    restore().then(() => reply?.({ granted: consentOn }))
    return true
  } else if (msg?.type === 'agent.noteWitness' || msg?.type === 'agent.acceptRecord') {
    // Only the popup (an extension page) may move the witness; a content
    // script is a web page's neighbour and gets no say in what is trusted.
    if (!isExtensionPage(sender) || !Number.isInteger(msg.total)) {
      reply?.({ error: 'not allowed' })
      return false
    }
    const job = msg.type === 'agent.noteWitness' ? noteWitness(msg.total) : acceptRecord(msg.total)
    job.then((shorter) => reply?.({ shorter: shorter || null }), () => reply?.({ error: 'failed' }))
    return true
  } else if (msg?.type === 'agent.syncExtraSites') {
    if (!isExtensionPage(sender)) { reply?.({ error: 'not allowed' }); return false }
    syncExtraFromStore().then(() => reply?.({ ok: true }), () => reply?.({ error: 'failed' }))
    return true
  } else if (msg?.type === 'agent.getEndpoint') {
    Promise.all([getEndpoint(), globalThis.ShieldManaged.readManaged(chrome.storage)]).then(([endpoint, managed]) =>
      reply?.({ endpoint, managed: managed.managed, managedBy: managed.managedBy }))
  } else if (msg?.type === 'agent.setEndpoint') {
    // The batcher carries Shield metadata; redirecting it anywhere but the
    // local Shield server would exfiltrate that record off the machine.
    // Same local-only rule the server enforces on inbound requests.
    globalThis.ShieldManaged.readManaged(chrome.storage).then((managed) => {
      // An administrator set the port: it is not the person's to change.
      if (managed.managed) { reply?.({ error: 'set by your administrator' }); return }
      if (isLocalEndpoint(msg.endpoint)) {
        chrome.storage.local.set({ [ENDPOINT_KEY]: msg.endpoint }, () => reply?.({ ok: true }))
      } else {
        reply?.({ error: 'endpoint must be a localhost Shield server' })
      }
    })
  }
  return true // async reply
})

// Withdrawing means nothing waiting is sent later, and nothing is retried.
function dropEverythingWaiting() {
  queue = []
  chrome.alarms?.clear('shield-retry')
  clearTimeout(timer); timer = null
  persist()
  chrome.action.setBadgeText({ text: '' })
}

// One timestamp per app, overwritten on every send: enough for the popup to
// say "last message noted 3 min ago" and to show when capture has gone quiet,
// and nothing that grows into a usage history.
// Sends from several tabs land here together; each one reads the counter,
// adds to it and writes it back, so they run one at a time or one overwrites
// the other.
let noteChain = Promise.resolve()
function noteCapture(url, kind) {
  noteChain = noteChain.then(() => recordCapture(url, kind))
  return noteChain
}

async function recordCapture(url, kind) {
  try {
    const host = new URL(url).host
    if (!WATCHED_HOST.includes(host)) return
    const store = await chrome.storage.local.get([LAST_CAPTURE_KEY, TODAY_KEY])
    if (!consentOn) return // withdrawn while we were reading: write nothing back
    const seen = store[LAST_CAPTURE_KEY] || {}
    const day = new Date().toDateString()
    const today = store[TODAY_KEY]?.day === day ? store[TODAY_KEY].n : 0
    await chrome.storage.local.set({
      [LAST_CAPTURE_KEY]: { ...seen, [host]: Date.now() },
      // Messages only (a request row), not the status row that follows each one.
      [TODAY_KEY]: { day, n: today + (kind === 'browser.chat.request' ? 1 : 0) },
    })
  } catch { /* the badge and queue matter more than this note */ }
}

// The canary: remember an app whose chat traffic went unrecognised, and
// forget it once a send of that app is inspected again.
async function noteHealth(row) {
  try {
    if (row.kind !== 'browser.health.unmatched' && !(row.kind === 'browser.chat.request' && row.chars != null)) return
    if (typeof row.app !== 'string' || !/^[a-z]{1,20}$/.test(row.app)) return
    const seen = (await chrome.storage.local.get(HEALTH_KEY))[HEALTH_KEY] || {}
    if (row.kind === 'browser.health.unmatched') seen[row.app] = Date.now()
    else if (row.app in seen) delete seen[row.app]
    else return
    if (!consentOn) return
    await chrome.storage.local.set({ [HEALTH_KEY]: seen })
  } catch { /* a note, not a dependency */ }
}

function isLocalEndpoint(candidate) {
  try {
    const url = new URL(String(candidate))
    return url.pathname.endsWith('/api/browser') &&
      (url.hostname === '127.0.0.1' || url.hostname === 'localhost' ||
        url.hostname === '[::1]' || url.hostname === '::1') &&
      (url.protocol === 'http:' || url.protocol === 'https:')
  } catch {
    return false
  }
}

function scheduleFlush() {
  // Not before restore() has read the rollback flag, or a shorter record
  // could show as a green check for a moment after the worker wakes.
  restore().then(setWorking)
  if (timer) return
  timer = setTimeout(flush, 2000)
  // The in-page timer dies with the worker; the alarm survives restarts and
  // re-flushes whatever the worker comes back to find (or missed).
  chrome.alarms?.create('shield-retry', { delayInMinutes: 1.1 })
  persist()
}

chrome.alarms?.onAlarm?.addListener((alarm) => {
  if (alarm.name === 'shield-retry') flush()
})

async function flush() {
  timer = null
  await restore()
  if (!consentOn) { dropEverythingWaiting(); return }
  const batch = queue
  queue = []
  persist()
  if (!batch.length) { return }
  try {
    const endpoint = await getEndpoint()
    const check = await checkServer(endpoint)
    if (check.state !== 'ok' && check.state !== 'paired') throw new Error(check.state)
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ rows: batch }),
    })
    if (!res.ok) throw new Error(String(res.status))
    if (Date.now() - policyAskedAt > 60_000) refreshPolicy(endpoint, { verified: true })
    const reply = await res.json().catch(() => null)
    if (await noteWitness(reply?.sealed_total)) setRefused('shorter')
    else setWorking() // synced: green check
    chrome.alarms?.clear('shield-retry')
  } catch (err) {
    // Server not up yet: put the rows back, retry later — inside the same
    // cap, so an off-again server days out still means dropped rows, not
    // an ever-growing local record.
    if (!consentOn) { dropEverythingWaiting(); return } // withdrawn mid-send: do not put rows back
    queue = [...batch, ...queue].slice(-MAX_QUEUED)
    const mismatch = err?.message === 'mismatch'
    const old = err?.message === 'unverifiable'
    // A different program on the port will not turn into Shield in seconds, so
    // it waits for the slow alarm. An unverifiable (older) Shield is fixed by
    // updating and restarting it, so it is asked again soon and recovers by
    // itself without the user touching the extension.
    if (!mismatch) timer = setTimeout(flush, old ? 30000 : 10000)
    chrome.alarms?.create('shield-retry', { delayInMinutes: 1.1 })
    if (mismatch) setRefused(); else if (old) setRefused('old'); else setOffline()
    persist()
  }
}

// The administrator's port (managed storage) wins over the person's saved
// choice; with none set, behaviour is exactly as before.
async function getEndpoint() {
  const managed = await globalThis.ShieldManaged.readManaged(chrome.storage)
  const saved = await new Promise((resolve) =>
    chrome.storage.local.get(ENDPOINT_KEY, (v) => resolve(v[ENDPOINT_KEY])))
  return globalThis.ShieldManaged.pickEndpoint(managed, saved, resolveEndpoint)
}
