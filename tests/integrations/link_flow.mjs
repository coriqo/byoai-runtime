// Drives the extension's sign-in + link flow (coriqo-link.js) the way login.js does,
// with the browser's OAuth window replaced by a function that approves the request.
// usage: node link_flow.mjs <coriqoBase> <shieldBase> [extensionOrigin]
import { createRequire } from 'node:module'
import { webcrypto } from 'node:crypto'
const require = createRequire(import.meta.url)
const L = require('../../src/byoai/browser_extension/coriqo-link.js')
const [base, shield, origin = 'chrome-extension://abcdefghijklmnop'] = process.argv.slice(2)
const redirectUri = 'https://abcdefghijklmnop.chromiumapp.org/'
const fetchImpl = (url, init = {}) => fetch(url, { ...init, headers: { ...(init.headers || {}), origin } })

const out = {}
try {
  // first contact: pin the Shield's key (background.js does this on pairing)
  const nonce = 'a'.repeat(32)
  const id = await (await fetch(`${shield}/api/identity?nonce=${nonce}`)).json()
  const pinned = id.public_key

  const pkce = await L.makePkce(webcrypto)
  const url = L.buildAuthorizeUrl({ base, redirectUri, challenge: pkce.challenge, state: pkce.state })
  const u = new URL(url)
  const returned = `${redirectUri}?code=goodcode&state=${u.searchParams.get('state')}`   // the user approved
  const code = L.parseRedirect(returned, { redirectUri, state: pkce.state })
  const t = await L.exchangeCode({ fetchImpl, base, redirectUri, code, verifier: pkce.verifier })

  const key = await L.verifiedShieldKey({ fetchImpl, endpoint: `${shield}/api/browser`, pinned, cryptoImpl: webcrypto })
  const grant = await L.requestEnrolGrant({ fetchImpl, base, accessToken: t.access_token,
    tenant: t.tenants[0], device: { publicKey: key, label: 'test', platform: 'test', extensionVersion: '1' } })
  out.grant = { ...grant, token: grant.token ? '<set>' : undefined }
  if (grant.ok) {
    try { await L.linkLocalShield({ fetchImpl, endpoint: `${shield}/api/browser`, base, token: grant.token }); out.linked = true }
    catch (e) { out.linked = false; out.linkError = e.message }
  }
} catch (e) { out.error = e.message }
console.log(JSON.stringify(out))
