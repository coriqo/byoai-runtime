/**
 * Coriqo account sign-in for the extension — the login building block for
 * the public self-serve install path.
 *
 * Deliberately NOT wired into `chrome.runtime.onInstalled` yet: today's
 * extension only supports pairing with a LOCAL Shield server
 * (`background.js`'s `isLocalEndpoint()` refuses anything else) — the
 * direct-to-Coriqo capture pipeline this login is *for* (WebCrypto device
 * key, JS redaction rules, direct sync) does not
 * exist yet. Gating the current, working, local-only flow behind a login
 * wall with no capture behind it would only add friction for zero benefit.
 * This page is reachable today as an optional, manual entry point (a link
 * in the popup's Details panel) so the auth half can be built, tested and
 * committed independently of that data-plane work.
 *
 * Talks directly to Coriqo's public (no-JWT) magic-link endpoints from the
 * extension's own origin — the same "CORS answers for our origin, no host
 * permission needed" approach already used for the local Shield pairing
 * check in `background.js`, and the one `/v1/shield/*` already relies on.
 * `/api/v1/auth/*` needs the same allowance on Coriqo's side; this file
 * assumes it exists rather than working around its
 * absence.
 */
const API_BASE_KEY = 'coriqo_api_base'
const SESSION_KEY = 'coriqo_session'
const CLIENT_ID_KEY = 'coriqo_client_id'
// No default here: CoriqoLink.resolveBase falls back to https://app.coriqo.io.
// http to this computer is allowed only in an unpacked build (no update_url).
const isDevBuild = () => !chrome.runtime.getManifest().update_url

const el = (id) => document.getElementById(id)

// The administrator's decision (managed storage), read the way shield_port is.
async function getPolicy() {
  let raw = {}
  try { raw = (await chrome.storage.managed?.get(['coriqo_link', 'coriqo_api_base'])) || {} } catch { /* none */ }
  return globalThis.CoriqoLink.linkPolicy(raw)
}

async function getApiBase() {
  const policy = await getPolicy()
  const v = await new Promise((resolve) => chrome.storage.local.get(API_BASE_KEY, resolve))
  return globalThis.CoriqoLink.resolveBase({ policy, stored: v[API_BASE_KEY], devBuild: isDevBuild() })
}

const BAD_BASE_TEXT = 'The saved Coriqo address is not allowed in this build (it must be https://). Remove the saved address to use the default.'
const OFF_TEXT = 'Your organisation has turned off connecting to Coriqo on this computer.'

function getClientId() {
  // Validate after the callback, inside the promise: a throw in the callback itself would
  // never reject, and sign-in would hang with no message.
  return new Promise((resolve, reject) => chrome.storage.local.get(CLIENT_ID_KEY, (v) => {
    try {
      resolve(globalThis.CoriqoLink.checkClientId(v[CLIENT_ID_KEY] || globalThis.CoriqoLink.CLIENT_ID))
    } catch (err) {
      reject(err)
    }
  }))
}

// An expired session counts as signed out and is removed.
function getSession() {
  return new Promise((resolve) =>
    chrome.storage.local.get(SESSION_KEY, (v) => {
      const s = v[SESSION_KEY] || null
      if (globalThis.CoriqoLink.sessionExpired(s)) { chrome.storage.local.remove(SESSION_KEY, () => resolve(null)); return }
      resolve(s)
    }))
}

function setSession(session) {
  return new Promise((resolve) => chrome.storage.local.set({ [SESSION_KEY]: session }, () => chrome.storage.local.remove(SKIP_KEY, resolve)))
}

function clearSession() {
  return new Promise((resolve) => chrome.storage.local.remove([SESSION_KEY, SKIP_KEY], resolve))
}

const LINK_KEY = 'coriqo_link'
const SKIP_KEY = 'coriqo_skipped'
const PIN_KEY = 'pinned_shield' // background.js pins the paired Shield's key here

function sendBg(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, (r) => resolve(r)))
}

async function onOAuth() {
  if (!(await getPolicy()).enabled) return setMsg('request-msg', OFF_TEXT, 'bad')
  chrome.storage.local.remove(SKIP_KEY)
  el('oauth-start').disabled = true
  setMsg('request-msg', 'Opening Coriqo…')
  try {
    const L = globalThis.CoriqoLink
    const base = await getApiBase()
    const clientId = await getClientId()
    const redirectUri = chrome.identity.getRedirectURL()
    const pkce = await L.makePkce(crypto)
    const url = L.buildAuthorizeUrl({ base, clientId, redirectUri, challenge: pkce.challenge, state: pkce.state })
    const returned = await chrome.identity.launchWebAuthFlow({ url, interactive: true })
    const code = L.parseRedirect(returned, { redirectUri, state: pkce.state })
    const t = await L.exchangeCode({ fetchImpl: fetch, base, clientId, redirectUri, code, verifier: pkce.verifier })
    const list = t.tenants.length ? t.tenants : (t.tenant_slug ? [t.tenant_slug] : [])
    const tenant = L.pickTenant(list, L.detectRegion({ language: navigator.language,
      timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone }), t.tenant_slug)
    if (!tenant) throw new Error('no_tenant')
    await setSession({ access_token: t.access_token, email: t.email || '', tenant_slug: tenant,
      tenants: list, at: Date.now(), expires_at: t.expires_at, via: 'oauth' })
    setMsg('request-msg', '')
    await showDone()
  } catch (err) {
    const m = err?.message || ''
    setMsg('request-msg',
      m === 'denied' || /canceled|cancelled|did not approve/i.test(m) ? 'Sign-in was cancelled.'
        : m === 'no_tenant' ? 'Your account has no workspace yet. Ask your Coriqo admin to add you.'
          : m === 'bad_base' ? 'The Coriqo address must start with https://.'
          : m === 'bad_client_id' ? 'The saved Coriqo client id is not valid.'
            : /^http:/.test(m) ? 'Coriqo had a problem. Try again shortly.'
              : "Couldn't sign in. Check your connection and try again.", 'bad')
  } finally {
    el('oauth-start').disabled = false
  }
}

async function showDone() {
  const session = await getSession()
  el('done-email').textContent = session.email || ''
  const L = globalThis.CoriqoLink
  const tenants = session.tenants || []
  const region = L.detectRegion({ language: navigator.language, timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone })
  const picked = L.pickTenant(tenants, region, session.tenant_slug)
  const wrap = el('tenants')
  wrap.replaceChildren(...tenants.map((slug) => {
    const lab = L.tenantLabel(slug)
    const row = document.createElement('label')
    row.className = 'choice'
    const radio = Object.assign(document.createElement('input'), { type: 'radio', name: 'tenant', value: slug, checked: slug === picked })
    const text = document.createElement('span')
    const name = Object.assign(document.createElement('span'), { className: 'name', textContent: lab.name })
    text.append(name)
    if (lab.region) text.append(Object.assign(document.createElement('span'), { className: 'region', textContent: lab.region }))
    row.append(radio, text)
    if (lab.regionKey && lab.regionKey === region && tenants.length > 1) {
      row.append(Object.assign(document.createElement('span'), { className: 'tag', textContent: 'Near you' }))
    }
    return row
  }))
  el('tenant-field').hidden = tenants.length < 2
  const shown = L.tenantLabel(picked || session.tenant_slug)
  el('done-workspace').textContent = shown.region ? `${shown.name}, ${shown.region}` : shown.name
  // OAuth sessions can connect a computer; a magic-link session has no
  // device-enrolment right, so the card is not offered.
  el('connect-card').hidden = session.via !== 'oauth'
  const linked = await new Promise((r) => chrome.storage.local.get(LINK_KEY, (v) => r(v[LINK_KEY] || null)))
  if (linked && L.linkSummary(linked)) setMsg('connect-msg', L.linkSummary(linked), 'ok')
  showStep('done')
}

async function onConnect() {
  const L = globalThis.CoriqoLink
  const btn = el('connect')
  btn.disabled = true
  el('limit-help').hidden = true
  const fail = (text) => { setMsg('connect-msg', text, 'bad'); btn.disabled = false }
  if (!(await getPolicy()).enabled) return fail(OFF_TEXT)
  try {
    setMsg('connect-msg', 'Checking Shield on this computer…')
    const check = await sendBg({ type: 'agent.checkServer' })
    if (!check || !['ok', 'paired'].includes(check.state)) {
      return fail(check?.state === 'mismatch'
        ? 'Another program answered where Shield should be. Open the popup and check the address.'
        : 'Start Shield on this computer first (byoai-shield), then try again.')
    }
    const pinned = (await new Promise((r) => chrome.storage.local.get(PIN_KEY, (v) => r(v[PIN_KEY]))))
    try {
      await L.verifiedShieldKey({ fetchImpl: fetch, endpoint: check.endpoint, pinned, cryptoImpl: crypto })
    } catch {
      return fail("Couldn't confirm this computer's Shield key. Reopen the popup and pair again.")
    }

    const session = await getSession()
    if (!session?.access_token) {
      // The token is dropped after a link; linking again needs a fresh sign-in.
      await clearSession()
      btn.disabled = false
      showStep('request')
      return setMsg('request-msg', 'Sign in again to connect this computer.', 'bad')
    }
    const base = await getApiBase()
    const tenant = document.querySelector('#tenants input[name=tenant]:checked')?.value || session.tenant_slug
    setMsg('connect-msg', 'Asking Coriqo…')
    const device = { publicKey: pinned, label: `${navigator.platform || 'computer'}`, platform: navigator.platform,
      extensionVersion: chrome.runtime.getManifest().version }
    // Prove the Shield holds the key: Coriqo gives a one-time nonce, the Shield signs it. A server
    // that does not ask for a proof (older) is asked without one. An expired or used nonce is
    // fetched again once.
    let grant
    for (let attempt = 0; attempt < 2; attempt++) {
      const nonce = await L.requestProofNonce({ fetchImpl: fetch, base, accessToken: session.access_token, tenant })
      const proof = nonce ? await L.requestDeviceProof({ fetchImpl: fetch, endpoint: check.endpoint, base, nonce, tenant, pinned }) : null
      grant = await L.requestEnrolGrant({ fetchImpl: fetch, base, accessToken: session.access_token, tenant, device, proof })
      if (grant.reason !== 'device_proof_invalid' || attempt === 1) break
    }
    if (!grant.ok) {
      if (grant.reason === 'device_limit_reached') {
        const of = grant.limit != null ? ` (${grant.count ?? grant.limit} of ${grant.limit} in use)` : ''
        if (grant.upgradeUrl) { el('upgrade').href = grant.upgradeUrl; el('limit-help').hidden = false }
        return fail(`Your plan's device limit is reached${of}. Nothing was connected.`)
      }
      if (grant.reason === 'device_proof_invalid' || grant.reason === 'device_proof_required') {
        return fail("Coriqo couldn't confirm this computer's key. Reopen the popup, pair again, and retry. Nothing was connected.")
      }
      if (grant.reason === 'signed_out') {
        await clearSession()
        showStep('request')
        return setMsg('request-msg', 'Your sign-in expired. Sign in again.', 'bad')
      }
      return fail(`Coriqo had a problem (${grant.status}). Try again shortly.`)
    }
    setMsg('connect-msg', 'Connecting…')
    await L.linkLocalShield({ fetchImpl: fetch, endpoint: check.endpoint, base, token: grant.token })
    await new Promise((r) => chrome.storage.local.set({ [LINK_KEY]: {
      tenant, device_index: grant.deviceIndex, device_limit: grant.deviceLimit, at: Date.now() } }, r))
    // The token has done its job: keep only what the pages show.
    const { access_token: _drop, ...kept } = session
    await setSession(kept)
    setMsg('connect-msg', L.linkSummary({ tenant, device_index: grant.deviceIndex, device_limit: grant.deviceLimit }), 'ok')
    btn.disabled = false
  } catch (err) {
    const m = err?.message || ''
    if (m === 'signed_out') { // an expired token: forget it, and send the person back to sign in
      await clearSession()
      btn.disabled = false
      showStep('request')
      return setMsg('request-msg', 'Your sign-in expired. Sign in again.', 'bad')
    }
    fail(m === 'bad_base' ? BAD_BASE_TEXT
      : m.startsWith('shield:') ? m.slice(7) : "Couldn't connect. Check your connection and try again.")
  }
}

function showStep(name) {
  for (const s of ['request', 'consume', 'done']) {
    el(`step-${s}`).classList.toggle('active', s === name)
  }
}

function setMsg(id, text, kind) {
  const node = el(id)
  node.textContent = text || ''
  node.className = `msg${kind ? ` ${kind}` : ''}`
}

// The magic link's URL carries the raw token as `?magic_token=...` (see
// coriqo's `_magic_link_url`). Accept either the full pasted URL or a bare
// token, so "paste the link" and "paste just the code" both work — nobody
// reading this UI knows or should need to know which one they have.
function extractToken(pasted) {
  const trimmed = pasted.trim()
  try {
    const url = new URL(trimmed)
    const fromQuery = url.searchParams.get('magic_token')
    if (fromQuery) return fromQuery
  } catch {
    /* not a URL — treat the whole thing as the token */
  }
  return trimmed
}

let pendingEmail = ''
let pendingWorkspace = ''

// True while a sign-in, a link or an email request is under way: Skip and Esc then do nothing,
// so a skip can never close the page in the middle of one.
let busy = false
const working = (fn) => async (...args) => {
  busy = true
  try { return await fn(...args) } finally { busy = false }
}

// Skip for now: remember the choice and close. Nothing is sent anywhere, no token is
// stored, and no enrolment is attempted; the popup keeps a quiet Sign in entry.
async function onSkip() {
  if (busy) return
  await new Promise((resolve) => chrome.storage.local.set({ [SKIP_KEY]: { at: Date.now() } }, resolve))
  setMsg('request-msg', 'Skipped. Shield keeps working on this computer. You can sign in later from the popup.', 'ok')
  el('skip').disabled = true
  try { window.close() } catch { /* a tab opened by hand stays; the message above is the answer */ }
}

async function init() {
  el('skip').addEventListener('click', onSkip)
  document.addEventListener('keydown', (e) => {
    // Esc skips, but never while a sign-in is under way or on the later steps.
    if (e.key === 'Escape' && el('step-request').classList.contains('active') && !el('skip').disabled) onSkip()
  })
  el('oauth-start').addEventListener('click', working(onOAuth))
  el('connect').addEventListener('click', working(onConnect))

  el('email').addEventListener('input', updateSendEnabled)
  el('workspace').addEventListener('input', updateSendEnabled)
  el('token').addEventListener('input', () => {
    el('consume').disabled = el('token').value.trim().length === 0
  })

  el('send').addEventListener('click', working(onSend))
  el('consume').addEventListener('click', working(onConsume))
  el('back').addEventListener('click', () => {
    setMsg('consume-msg', '')
    showStep('request')
  })
  el('sign-out').addEventListener('click', async () => {
    await clearSession()
    chrome.storage.local.remove(LINK_KEY)
    el('email').value = ''
    el('workspace').value = ''
    el('token').value = ''
    updateSendEnabled()
    showStep('request')
  })
  el('open-privacy').addEventListener('click', (ev) => {
    ev.preventDefault()
    chrome.tabs.create({ url: chrome.runtime.getURL('PRIVACY.md') })
  })
  el('open-privacy-2').addEventListener('click', (ev) => {
    ev.preventDefault()
    chrome.tabs.create({ url: chrome.runtime.getURL('PRIVACY.md') })
  })
  if (!(await getPolicy()).enabled) {
    el('oauth-start').disabled = true
    showStep('request')
    setMsg('request-msg', OFF_TEXT, 'bad')
    return
  }
  const session = await getSession()
  if (session) {
    await showDone()
  } else {
    showStep('request')
  }
}

function updateSendEnabled() {
  el('send').disabled = !(el('email').value.includes('@') && el('workspace').value.trim())
}

async function onSend() {
  if (!(await getPolicy()).enabled) return setMsg('request-msg', OFF_TEXT, 'bad')
  const email = el('email').value.trim()
  const workspace = el('workspace').value.trim()
  el('send').disabled = true
  setMsg('request-msg', 'Sending…')
  try {
    const base = await getApiBase()
    const res = await fetch(`${base}/api/v1/auth/magic-link`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email, tenant_slug: workspace }),
    })
    // A response that arrived but said no is a different failure from the
    // request never reaching Coriqo at all — "check your connection" is the
    // wrong advice for a real server error, and retrying it immediately
    // just repeats a doomed request.
    if (!res.ok) throw new Error(`http:${res.status}`)
    // The endpoint is deliberately generic on success (anti-enumeration) —
    // this UI has nothing more specific to say either, and saying more
    // would contradict the one honest thing the backend promises.
    pendingEmail = email
    pendingWorkspace = workspace
    setMsg('request-msg', '')
    showStep('consume')
  } catch (err) {
    const httpStatus = /^http:(\d+)$/.exec(err?.message || '')?.[1]
    setMsg(
      'request-msg',
      err?.message === 'bad_base' ? BAD_BASE_TEXT
        : httpStatus
          ? `Coriqo had a problem (${httpStatus}). Try again shortly.`
          : "Couldn't reach Coriqo. Check your connection and try again.",
      'bad',
    )
    el('send').disabled = false
  }
}

async function onConsume() {
  if (!(await getPolicy()).enabled) return setMsg('consume-msg', OFF_TEXT, 'bad')
  const token = extractToken(el('token').value)
  el('consume').disabled = true
  setMsg('consume-msg', 'Signing in…')
  try {
    const base = await getApiBase()
    const res = await fetch(`${base}/api/v1/auth/magic-link/consume`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ token, tenant_slug: pendingWorkspace }),
    })
    if (res.status === 404) throw new Error('invalid')
    if (res.status === 410) throw new Error('expired')
    if (!res.ok) throw new Error(`http:${res.status}`)
    const body = await res.json()
    await setSession({
      access_token: body.access_token,
      email: pendingEmail,
      tenant_slug: pendingWorkspace,
      at: Date.now(),
    })
    setMsg('consume-msg', '')
    el('done-email').textContent = pendingEmail
    el('done-workspace').textContent = pendingWorkspace
    showStep('done')
  } catch (err) {
    const httpStatus = /^http:(\d+)$/.exec(err?.message || '')?.[1]
    const msg = err?.message === 'bad_base' ? BAD_BASE_TEXT
      : err?.message === 'expired'
      ? 'This sign-in link expired. Go back and send a new one.'
      : err?.message === 'invalid'
        ? "That link or code didn't match — check you copied all of it."
        : httpStatus
          ? `Coriqo had a problem (${httpStatus}). Try again shortly.`
          : "Couldn't reach Coriqo. Check your connection and try again."
    setMsg('consume-msg', msg, 'bad')
    el('consume').disabled = false
  }
}

init()
