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
// Dev default. Production base is configured once Coriqo's real host is
// decided — deliberately not hardcoded to a guessed production URL.
const DEFAULT_API_BASE = 'http://localhost:8000'

const el = (id) => document.getElementById(id)

function getApiBase() {
  return new Promise((resolve) =>
    chrome.storage.local.get(API_BASE_KEY, (v) => resolve(v[API_BASE_KEY] || DEFAULT_API_BASE)))
}

function getSession() {
  return new Promise((resolve) =>
    chrome.storage.local.get(SESSION_KEY, (v) => resolve(v[SESSION_KEY] || null)))
}

function setSession(session) {
  return new Promise((resolve) => chrome.storage.local.set({ [SESSION_KEY]: session }, resolve))
}

function clearSession() {
  return new Promise((resolve) => chrome.storage.local.remove(SESSION_KEY, resolve))
}

const LINK_KEY = 'coriqo_link'
const PIN_KEY = 'pinned_shield' // background.js pins the paired Shield's key here

function sendBg(msg) {
  return new Promise((resolve) => chrome.runtime.sendMessage(msg, (r) => resolve(r)))
}

async function onOAuth() {
  el('oauth-start').disabled = true
  setMsg('request-msg', 'Opening Coriqo…')
  try {
    const L = globalThis.CoriqoLink
    const base = await getApiBase()
    const redirectUri = chrome.identity.getRedirectURL()
    const pkce = await L.makePkce(crypto)
    const url = L.buildAuthorizeUrl({ base, redirectUri, challenge: pkce.challenge, state: pkce.state })
    const returned = await chrome.identity.launchWebAuthFlow({ url, interactive: true })
    const code = L.parseRedirect(returned, { redirectUri, state: pkce.state })
    const t = await L.exchangeCode({ fetchImpl: fetch, base, redirectUri, code, verifier: pkce.verifier })
    const list = t.tenants.length ? t.tenants : (t.tenant_slug ? [t.tenant_slug] : [])
    const tenant = L.pickTenant(list, L.detectRegion({ language: navigator.language,
      timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone }), t.tenant_slug)
    if (!tenant) throw new Error('no_tenant')
    await setSession({ access_token: t.access_token, email: t.email || '', tenant_slug: tenant,
      tenants: list, at: Date.now(), via: 'oauth' })
    setMsg('request-msg', '')
    await showDone()
  } catch (err) {
    const m = err?.message || ''
    setMsg('request-msg',
      m === 'denied' || /canceled|cancelled|did not approve/i.test(m) ? 'Sign-in was cancelled.'
        : m === 'no_tenant' ? 'Your account has no workspace yet. Ask your Coriqo admin to add you.'
          : m === 'bad_base' ? 'The Coriqo address must start with https://.'
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
  if (linked) setMsg('connect-msg', `Connected: device ${linked.device_index ?? '?'}${linked.device_limit ? ` of ${linked.device_limit}` : ''} in ${linked.tenant}.`, 'ok')
  showStep('done')
}

async function onConnect() {
  const L = globalThis.CoriqoLink
  const btn = el('connect')
  btn.disabled = true
  el('limit-help').hidden = true
  const fail = (text) => { setMsg('connect-msg', text, 'bad'); btn.disabled = false }
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
    const base = await getApiBase()
    const tenant = document.querySelector('#tenants input[name=tenant]:checked')?.value || session.tenant_slug
    setMsg('connect-msg', 'Asking Coriqo…')
    const grant = await L.requestEnrolGrant({
      fetchImpl: fetch, base, accessToken: session.access_token, tenant,
      device: { publicKey: pinned, label: `${navigator.platform || 'computer'}`, platform: navigator.platform,
        extensionVersion: chrome.runtime.getManifest().version },
    })
    if (!grant.ok) {
      if (grant.reason === 'device_limit_reached') {
        const of = grant.limit != null ? ` (${grant.count ?? grant.limit} of ${grant.limit} in use)` : ''
        if (grant.upgradeUrl) { el('upgrade').href = grant.upgradeUrl; el('limit-help').hidden = false }
        return fail(`Your plan's device limit is reached${of}. Nothing was connected.`)
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
    setMsg('connect-msg', `Connected: device ${grant.deviceIndex ?? '?'}${grant.deviceLimit ? ` of ${grant.deviceLimit}` : ''} in ${tenant}.`, 'ok')
    btn.disabled = false
  } catch (err) {
    const m = err?.message || ''
    fail(m.startsWith('shield:') ? m.slice(7) : "Couldn't connect. Check your connection and try again.")
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

async function init() {
  el('oauth-start').addEventListener('click', onOAuth)
  el('connect').addEventListener('click', onConnect)
  const session = await getSession()
  if (session) {
    await showDone()
  } else {
    showStep('request')
  }

  el('email').addEventListener('input', updateSendEnabled)
  el('workspace').addEventListener('input', updateSendEnabled)
  el('token').addEventListener('input', () => {
    el('consume').disabled = el('token').value.trim().length === 0
  })

  el('send').addEventListener('click', onSend)
  el('consume').addEventListener('click', onConsume)
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
}

function updateSendEnabled() {
  el('send').disabled = !(el('email').value.includes('@') && el('workspace').value.trim())
}

async function onSend() {
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
      httpStatus
        ? `Coriqo had a problem (${httpStatus}). Try again shortly.`
        : "Couldn't reach Coriqo. Check your connection and try again.",
      'bad',
    )
    el('send').disabled = false
  }
}

async function onConsume() {
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
    const msg = err?.message === 'expired'
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
