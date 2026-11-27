/**
 * Sign in to Coriqo and link this computer: the client half of the extension's
 * on-ramp. Plain functions with every outside dependency passed in, so the
 * same file runs in the extension and under node in the tests.
 *
 * Flow: OAuth 2.0 authorization code with PKCE (S256, no client secret) ->
 * ask Coriqo for a one-time enrolment token for THIS device (it counts devices
 * and may refuse or bill extra ones) -> hand the token to the local Shield,
 * which redeems it on the unchanged `/v1/enroll`. The device key never leaves
 * the Shield; only its public half is sent to Coriqo here.
 *
 * Coriqo's side (OAuth client, tenants, device entitlement, billing) is not in
 * this repo. The shapes this file expects are documented in CONFIGURATION.md.
 */
;(function (root) {
  const CLIENT_ID = 'coriqo-shield-extension' // the default; the `coriqo_client_id` setting overrides it

  function b64url(bytes) {
    let s = ''
    for (const b of bytes) s += String.fromCharCode(b)
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }

  // https, or http to this computer only: an access token must not cross a network in the clear.
  function checkBase(url) {
    let u
    try { u = new URL(String(url).trim()) } catch { throw new Error('bad_base') }
    const local = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname)
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && local)) throw new Error('bad_base')
    if (u.username || u.password) throw new Error('bad_base')
    return u.origin
  }

  // A client id is either a short registered name or the https address of a client metadata
  // document; anything else (a space, a script URL, an overlong value) is refused rather than sent.
  function checkClientId(value) {
    const v = String(value ?? '').trim()
    if (/^[A-Za-z0-9._-]{1,128}$/.test(v)) return v
    try {
      const u = new URL(v)
      if (u.protocol === 'https:' && !u.username && !u.password && v.length <= 512) return v
    } catch { /* fall through */ }
    throw new Error('bad_client_id')
  }

  async function makePkce(cryptoImpl) {
    const rand = (n) => b64url(cryptoImpl.getRandomValues(new Uint8Array(n)))
    const verifier = rand(32) // 43 chars, inside RFC 7636's 43..128
    const digest = await cryptoImpl.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
    return { verifier, challenge: b64url(new Uint8Array(digest)), state: rand(16) }
  }

  function buildAuthorizeUrl({ base, clientId = CLIENT_ID, redirectUri, challenge, state, tenant }) {
    const u = new URL('/oauth/authorize', checkBase(base))
    u.searchParams.set('response_type', 'code')
    u.searchParams.set('client_id', checkClientId(clientId))
    u.searchParams.set('redirect_uri', redirectUri)
    u.searchParams.set('code_challenge', challenge)
    u.searchParams.set('code_challenge_method', 'S256')
    u.searchParams.set('state', state)
    if (tenant) u.searchParams.set('tenant', tenant)
    return u.toString()
  }

  // The browser hands back whatever the provider redirected to. Accept it only
  // if it is our redirect, carries our state, and has a code: anything else is
  // a forged or replayed redirect and signs nobody in.
  function parseRedirect(returned, { redirectUri, state }) {
    let u
    try { u = new URL(returned) } catch { throw new Error('bad_redirect') }
    const mine = new URL(redirectUri)
    if (u.origin !== mine.origin || u.pathname !== mine.pathname) throw new Error('bad_redirect')
    const params = u.searchParams
    if (params.get('state') !== state) throw new Error('bad_state')
    if (params.get('error')) throw new Error(params.get('error') === 'access_denied' ? 'denied' : 'oauth_error')
    const code = params.get('code')
    if (!code) throw new Error('bad_redirect')
    return code
  }

  async function exchangeCode({ fetchImpl, base, clientId = CLIENT_ID, redirectUri, code, verifier }) {
    const res = await fetchImpl(new URL('/oauth/token', checkBase(base)).toString(), {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code', client_id: checkClientId(clientId), redirect_uri: redirectUri,
        code, code_verifier: verifier,
      }).toString(),
    })
    if (!res.ok) throw new Error(`http:${res.status}`)
    const body = await res.json()
    if (typeof body?.access_token !== 'string' || !body.access_token) throw new Error('bad_token')
    return {
      access_token: body.access_token,
      tenant_slug: typeof body.tenant_slug === 'string' ? body.tenant_slug : null,
      // Every tenant the user may use; the person picks when there is more than one.
      tenants: Array.isArray(body.tenants) ? body.tenants.filter((t) => typeof t === 'string') : [],
      email: typeof body.email === 'string' ? body.email : null,
    }
  }

  // Ask Coriqo for a one-time enrolment token for this device. A refusal for
  // the device count is a normal answer, not an error: it comes back as
  // `{ ok: false, reason: 'device_limit_reached', ... }` and is never retried.
  async function requestEnrolGrant({ fetchImpl, base, accessToken, tenant, device }) {
    const res = await fetchImpl(new URL('/v1/enroll/self', checkBase(base)).toString(), {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        authorization: `Bearer ${accessToken}`,
        'x-tenant-slug': tenant,
      },
      body: JSON.stringify({
        device_public_key: device.publicKey,
        device_label: String(device.label || '').slice(0, 80),
        platform: String(device.platform || '').slice(0, 40),
        extension_version: String(device.extensionVersion || '').slice(0, 20),
      }),
    })
    if (res.status === 401 || res.status === 403) return { ok: false, reason: 'signed_out' }
    if (res.status === 402 || res.status === 409) {
      let body = {}
      try { body = await res.json() } catch { /* keep the generic refusal */ }
      const d = body?.detail && typeof body.detail === 'object' ? body.detail : body
      let upgradeUrl = null
      try {
        // Only an https link is shown as a link; anything else is dropped.
        const u = new URL(d.upgrade_url)
        if (u.protocol === 'https:') upgradeUrl = u.toString()
      } catch { /* none */ }
      return {
        ok: false, reason: 'device_limit_reached',
        limit: Number.isInteger(d.limit) ? d.limit : null,
        count: Number.isInteger(d.count) ? d.count : null,
        upgradeUrl,
      }
    }
    if (!res.ok) return { ok: false, reason: 'server', status: res.status }
    const body = await res.json()
    if (typeof body?.token !== 'string' || !body.token) return { ok: false, reason: 'server', status: res.status }
    return {
      ok: true, token: body.token,
      deviceIndex: Number.isInteger(body.device_index) ? body.device_index : null,
      deviceLimit: Number.isInteger(body.device_limit) ? body.device_limit : null,
      billingState: typeof body.billing_state === 'string' ? body.billing_state : null,
    }
  }

  const shieldBase = (endpoint) => String(endpoint).replace(/\/api\/browser$/, '').replace(/\/$/, '')
  const b64bytes = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0))

  // The Shield's own proof that it holds `pinned` right now: it signs a fresh
  // nonce with the device key. Returns the public key, or throws. A different
  // program on the port, or a different key, is refused: Coriqo must count the
  // key this extension paired with, never whatever answers.
  async function verifiedShieldKey({ fetchImpl, endpoint, pinned, cryptoImpl }) {
    if (!pinned) throw new Error('not_paired')
    const nonce = Array.from(cryptoImpl.getRandomValues(new Uint8Array(16)),
      (b) => b.toString(16).padStart(2, '0')).join('')
    const res = await fetchImpl(`${shieldBase(endpoint)}/api/identity?nonce=${nonce}`, { cache: 'no-store' })
    if (!res.ok) throw new Error('unreachable')
    const id = await res.json()
    if (id?.public_key !== pinned) throw new Error('key_mismatch')
    const key = await cryptoImpl.subtle.importKey('raw', b64bytes(id.public_key), { name: 'Ed25519' }, false, ['verify'])
    const sig = b64bytes(String(id.sig).replace(/^ed25519:/, ''))
    const signed = new TextEncoder().encode('byoai-shield-identity:' + nonce)
    if (!(await cryptoImpl.subtle.verify({ name: 'Ed25519' }, key, sig, signed))) throw new Error('key_mismatch')
    return id.public_key
  }

  // Hand the token to the local Shield. The caller has already confirmed the
  // Shield is the one this extension paired with.
  async function linkLocalShield({ fetchImpl, endpoint, base, token }) {
    const res = await fetchImpl(`${shieldBase(endpoint)}/api/coriqo/link`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ base_url: checkBase(base), token }),
    })
    let body = {}
    try { body = await res.json() } catch { /* generic below */ }
    if (!res.ok) throw new Error(`shield:${typeof body.error === 'string' ? body.error : res.status}`)
    return body
  }

  // ---- workspaces: readable names and a region suggestion -------------------
  // A workspace slug looks like `coriqo_msp_usa`: who it is for, then the region it lives in.
  const REGIONS = { usa: 'United States', uk: 'United Kingdom', eu: 'European Union', ca: 'Canada', au: 'Australia' }
  const EU = new Set(['AT', 'BE', 'BG', 'HR', 'CY', 'CZ', 'DK', 'EE', 'FI', 'FR', 'DE', 'GR', 'HU', 'IE', 'IT', 'LV',
    'LT', 'LU', 'MT', 'NL', 'PL', 'PT', 'RO', 'SK', 'SI', 'ES', 'SE'])

  function splitTenant(slug) {
    const parts = String(slug).toLowerCase().split(/[_-]+/).filter(Boolean)
    const last = parts[parts.length - 1]
    const region = parts.length > 1 && REGIONS[last] ? last : null
    const name = (region ? parts.slice(0, -1) : parts)
      .map((w) => (w === 'msp' || w === 'it' ? w.toUpperCase() : w[0].toUpperCase() + w.slice(1))).join(' ')
    return { name: name || String(slug), region }
  }

  // "Coriqo MSP" and "United States", for display; the slug itself is never changed.
  function tenantLabel(slug) {
    const { name, region } = splitTenant(slug)
    return { name, region: region ? REGIONS[region] : null, regionKey: region }
  }

  // Where the user probably is, from the browser's own time zone first (a default
  // en-US browser in Berlin is still in Berlin) and its language second.
  // Read here and used here: nothing about it is sent anywhere.
  const TZ_EU = new Set(['Amsterdam', 'Berlin', 'Brussels', 'Paris', 'Madrid', 'Rome', 'Vienna', 'Lisbon', 'Dublin',
    'Stockholm', 'Copenhagen', 'Helsinki', 'Warsaw', 'Prague', 'Budapest', 'Athens', 'Bucharest', 'Sofia', 'Zagreb',
    'Bratislava', 'Ljubljana', 'Tallinn', 'Riga', 'Vilnius', 'Luxembourg', 'Malta', 'Nicosia'])
  const TZ_CA = /^America\/(Toronto|Vancouver|Edmonton|Winnipeg|Halifax|St_Johns|Regina|Montreal|Moncton|Glace_Bay|Whitehorse|Iqaluit|Yellowknife|Dawson|Goose_Bay)$/
  const TZ_US = /^(America\/(New_York|Chicago|Denver|Los_Angeles|Phoenix|Anchorage|Detroit|Boise|Juneau|Adak|Indiana\/.+|Kentucky\/.+|North_Dakota\/.+)|Pacific\/Honolulu|US\/.+)$/

  function detectRegion({ language = '', timeZone = '' } = {}) {
    if (TZ_CA.test(timeZone)) return 'ca'
    if (TZ_US.test(timeZone)) return 'usa'
    if (timeZone === 'Europe/London' || timeZone === 'Europe/Belfast') return 'uk'
    if (/^Europe\//.test(timeZone) && TZ_EU.has(timeZone.slice(7))) return 'eu'
    if (/^Australia\//.test(timeZone)) return 'au'
    const country = (/[-_]([A-Za-z]{2})\b/.exec(language) || [])[1]?.toUpperCase()
    if (country === 'US') return 'usa'
    if (country === 'GB') return 'uk'
    if (country && EU.has(country)) return 'eu'
    if (country === 'CA') return 'ca'
    if (country === 'AU') return 'au'
    return null
  }

  // The workspace to preselect. Coriqo's own choice (`preferred`) always wins: which
  // workspace a user belongs to is Coriqo's to say, not a guess. The region only decides
  // when Coriqo named none, then the first one. Only ever one of `tenants`.
  function pickTenant(tenants, region, preferred) {
    const list = Array.isArray(tenants) ? tenants : []
    if (list.includes(preferred)) return preferred
    return (region && list.find((t) => splitTenant(t).region === region)) || list[0] || null
  }

  const api = { CLIENT_ID, checkClientId, tenantLabel, detectRegion, pickTenant, checkBase, makePkce, buildAuthorizeUrl, parseRedirect, exchangeCode,
    requestEnrolGrant, linkLocalShield, verifiedShieldKey }
  root.CoriqoLink = api
  if (typeof module !== 'undefined' && module.exports) module.exports = api
})(typeof globalThis !== 'undefined' ? globalThis : this)
