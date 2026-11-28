// Joining a Coriqo workspace by paying: the helpers the login page and the background script use.
import { describe, expect, it } from 'vitest'
import { createRequire } from 'node:module'
import { REPO } from './env.mjs'
import path from 'node:path'
import fs from 'node:fs'

const L = createRequire(import.meta.url)(path.join(REPO, 'src/byoai/browser_extension/coriqo-link.js'))
const BASE = 'https://app.coriqo.io'
const NOW = 1_800_000_000_000

const STATE = 'ab'.repeat(32)
const msg = { type: 'coriqo.join.finished', connect: true, state: STATE, tenant: 'acme_msp' }
const pending = { region: 'usa', state: STATE, at: NOW - 60_000 }
const acc = (o = {}) => L.acceptJoinMessage({ msg, senderOrigin: BASE, base: BASE, pending, now: NOW, ...o })

async function bg({ managed, pending, twice = false, burst = 0, msgOverride }) {
  const store = { coriqo_pending_join: pending }
  const calls = { tabs: 0 }
  const tick = () => new Promise((r) => setTimeout(r, 1))
  const chrome = {
    storage: {
      local: { get: async () => { await tick(); return { ...store } }, set: async (o) => { await tick(); Object.assign(store, o) } },
      managed: { get: async () => { await tick(); return managed } },
    },
    runtime: { getManifest: () => ({}), getURL: (x) => x },
    tabs: { create: () => { calls.tabs++ } },
  }
  const fn = new Function('chrome', 'globalThis', extract('background.js', 'handleJoinMessage') + extract('background.js', 'handleJoinOnce') + '; return handleJoinMessage')(chrome, { CoriqoLink: L })
  if (burst) {
    const ok = await Promise.all(Array.from({ length: burst }, () => fn(msgOverride || msg, { origin: BASE })))
    return { ok, store, calls }
  }
  let ok = await fn(msgOverride || msg, { origin: BASE })
  if (twice) ok = [ok, await fn(msgOverride || msg, { origin: BASE })]
  return { ok, store, calls }
}

describe('join helpers', () => {
  it('builds an address with region, source and state only', () => {
    const u = new URL(L.joinUrl({ base: BASE, region: 'uk', state: STATE }))
    expect(u.origin + u.pathname).toBe('https://app.coriqo.io/join')
    expect([...u.searchParams.keys()].sort()).toEqual(['region', 'source', 'state'])
    expect(u.searchParams.get('state')).toBe(STATE)
    expect([...new URL(L.joinUrl({ base: BASE, state: STATE })).searchParams.keys()].sort()).toEqual(['source', 'state'])
    expect(() => L.joinUrl({ base: 'http://evil.example', state: STATE })).toThrow('bad_base')
  })

  it('makeJoinState gives 64 lowercase hex, different each call', () => {
    const c = { getRandomValues: (a) => { for (let i = 0; i < a.length; i++) a[i] = Math.floor(Math.random() * 256); return a } }
    const a = L.makeJoinState(c), b = L.makeJoinState(c)
    expect(a).toMatch(/^[0-9a-f]{64}$/)
    expect(a).not.toBe(b)
  })

  it('accepts the finished message and returns its tenant', () => {
    expect(acc()).toEqual({ ok: true, connect: true, tenant: 'acme_msp' })
    expect(acc({ msg: { ...msg, connect: false } }).connect).toBe(false)
  })

  it('refuses a state that differs, is missing, short or uppercase', () => {
    expect(acc({ msg: { ...msg, state: 'cd'.repeat(32) } }).ok).toBe(false)
    expect(acc({ msg: { ...msg, state: undefined } }).ok).toBe(false)
    expect(acc({ msg: { ...msg, state: 'ab'.repeat(31) }, pending: { ...pending, state: 'ab'.repeat(31) } }).ok).toBe(false)
    const up = 'AB'.repeat(32)
    expect(acc({ msg: { ...msg, state: up }, pending: { ...pending, state: up } }).ok).toBe(false)
    expect(acc({ pending: { region: 'usa', at: NOW - 1000 } }).ok).toBe(false)
  })

  it('refuses a tenant that does not match the slug pattern', () => {
    for (const t of [undefined, '', 'Acme', '1abc', 'a-b', 'a'.repeat(52), 'a b', 5]) {
      expect(acc({ msg: { ...msg, tenant: t } }).ok).toBe(false)
    }
  })

  it('treats anything but connect === true as no connect', () => {
    expect(acc({ msg: { ...msg, connect: 'yes' } }).connect).toBe(false)
  })

  it('refuses a page that is not the Coriqo address in use', () => {
    for (const origin of ['https://evil.example', 'http://app.coriqo.io', 'https://app.coriqo.io.evil.example', undefined]) {
      expect(acc({ senderOrigin: origin }).ok).toBe(false)
    }
  })

  it('refuses when no join was started, or it is an hour old, or the clock ran backwards', () => {
    expect(L.acceptJoinMessage({ msg, senderOrigin: BASE, base: BASE, pending: null, now: NOW }).ok).toBe(false)
    expect(L.acceptJoinMessage({ msg, senderOrigin: BASE, base: BASE, pending: { ...pending, at: NOW - 3_600_001 }, now: NOW }).ok).toBe(false)
    expect(L.acceptJoinMessage({ msg, senderOrigin: BASE, base: BASE, pending: { ...pending, at: NOW + 5 }, now: NOW }).ok).toBe(false)
  })

  it('refuses any other message type', () => {
    for (const m of [{ type: 'other' }, { type: 'coriqo.join.finished ' }, { type: undefined }]) {
      expect(L.acceptJoinMessage({ msg: m && { ...msg, ...m }, senderOrigin: BASE, base: BASE, pending, now: NOW }).ok).toBe(false)
    }
  })

  it('accepts http only for this computer in a dev build base', () => {
    const local = 'http://localhost:5173'
    expect(L.acceptJoinMessage({ msg, senderOrigin: local, base: local, pending, now: NOW }).ok).toBe(true)
    expect(L.acceptJoinMessage({ msg, senderOrigin: local, base: 'http://evil.example', pending, now: NOW }).ok).toBe(false)
  })
})

// ---- the login page and background script, run from their real source with stubs ----
const EXT = path.join(REPO, 'src/byoai/browser_extension')
const read = (f) => fs.readFileSync(path.join(EXT, f), 'utf8')
function extract(file, name) {
  const src = read(file)
  const s = src.indexOf(`async function ${name}`)
  if (s < 0) throw new Error(`${name} not found in ${file}`)
  return src.slice(s, src.indexOf('\n}\n', s) + 2)
}
const mkStore = (init = {}) => {
  const store = { ...init }
  return { store, chrome: { storage: { local: {
    get: (k, cb) => cb(Object.fromEntries([].concat(k).map((x) => [x, store[x]]))),
    set: (o, cb) => { Object.assign(store, o); cb?.() },
    remove: (k, cb) => { for (const x of [].concat(k)) delete store[x]; cb?.() } } } } }
}
const fresh = () => ({ region: 'usa', state: STATE, tenant: 'acme_usa', at: Date.now() - 1000, accepted: true, connect: true })
function mkRun({ pend, oauth, session, confirm = true, picked, after, policy = true }) {
  const { store, chrome } = mkStore(pend ? { coriqo_pending_join: pend } : {})
  const calls = { oauth: 0, connect: 0 }
  globalThis.CoriqoLink = L
  const fn = new Function('chrome', 'PENDING_JOIN_KEY', 'onOAuth', 'getSession', 'onConnect', 'confirmAutoConnect', 'document', 'getPolicy',
    extract('login.js', 'runAfterJoin') + '; return runAfterJoin')(chrome, 'coriqo_pending_join',
    async () => { calls.oauth++; return oauth }, async () => session, async (t) => { calls.connect++; calls.tenant = t },
    async () => { after?.(); return confirm },
    { querySelector: () => (picked === undefined ? null : { value: typeof picked === 'function' ? picked() : picked }) }, async () => ({ enabled: policy }))
  return { fn, calls, store }
}
const goodSession = (over = {}) => ({ via: 'oauth', at: Date.now() + 5, tenant_slug: 'acme_usa', tenants: ['acme_usa'], ...over })

describe('E1 auto-join never connects with an older session', () => {
  it('does not connect when sign-in was cancelled but an older session is stored', async () => {
    const r = mkRun({ pend: fresh(), oauth: false, session: { via: 'oauth', at: 1, tenant_slug: 'old', tenants: ['old'] } })
    expect(await r.fn()).toBe(true)
    expect(r.calls.connect).toBe(0)
  })
  it('does not connect when onOAuth says true but the session predates this run', async () => {
    const r = mkRun({ pend: fresh(), oauth: true, session: goodSession({ at: Date.now() - 600_000 }) })
    await r.fn()
    expect(r.calls.connect).toBe(0)
  })
  it('does not connect when the session names another workspace than the join', async () => {
    const r = mkRun({ pend: fresh(), oauth: true, session: goodSession({ tenant_slug: 'acme_uk', tenants: ['acme_uk', 'acme_usa'] }) })
    await r.fn()
    expect(r.calls.connect).toBe(0)
  })
  it('does not connect when the joined workspace is missing from the account', async () => {
    const r = mkRun({ pend: fresh(), oauth: true, session: goodSession({ tenant_slug: 'acme_corp', tenants: ['acme_corp'] }) })
    await r.fn()
    expect(r.calls.connect).toBe(0)
  })
  it('connects once for a fresh session in the joined workspace, and consumes the flag', async () => {
    const r = mkRun({ pend: fresh(), oauth: true, session: goodSession() })
    expect(await r.fn()).toBe(true)
    expect(r.calls.connect).toBe(1)
    expect(r.calls.tenant).toBe('acme_usa') // onConnect is told the joined workspace, not left to read the picker
    expect(r.store.coriqo_pending_join).toBeUndefined()
  })
  it('does not connect when connect was not ticked', async () => {
    const r = mkRun({ pend: { ...fresh(), connect: false }, oauth: true, session: goodSession() })
    await r.fn()
    expect(r.calls.connect).toBe(0)
  })
  it('manual flow unchanged: no accepted flag means no run at all', async () => {
    const r = mkRun({ pend: { tenant: 'x', at: Date.now() }, oauth: true, session: goodSession() })
    expect(await r.fn()).toBe(false)
    expect(r.calls.oauth).toBe(0)
    expect(r.calls.connect).toBe(0)
  })
})

describe('Y1 nothing changes during the auto-connect window', () => {
  it('does not connect when the picker moves to another workspace in the window', async () => {
    let pick = 'acme_usa'
    const r = mkRun({ pend: fresh(), oauth: true, session: goodSession(), picked: () => pick, after: () => { pick = 'acme_uk' } })
    await r.fn()
    expect(r.calls.connect).toBe(0)
  })
  it('does not connect when the stored session changes workspace in the window', async () => {
    const sess = goodSession()
    const r = mkRun({ pend: fresh(), oauth: true, session: sess, after: () => { sess.tenant_slug = 'acme_uk' } })
    await r.fn()
    expect(r.calls.connect).toBe(0)
  })
  it('does not connect when sign-in is gone or linking was turned off in the window', async () => {
    const sess = goodSession()
    const a = mkRun({ pend: fresh(), oauth: true, session: sess, after: () => { sess.via = 'link' } })
    await a.fn()
    expect(a.calls.connect).toBe(0)
    const b = mkRun({ pend: fresh(), oauth: true, session: goodSession(), policy: false })
    await b.fn()
    expect(b.calls.connect).toBe(0)
  })
  it('connects once when nothing changed', async () => {
    const r = mkRun({ pend: fresh(), oauth: true, session: goodSession(), picked: 'acme_usa' })
    await r.fn()
    expect(r.calls.connect).toBe(1)
  })
  it('the picker is disabled while the status shows, and freed after', () => {
    const src = read('login.js')
    expect(src).toMatch(/r\.disabled = true/)
    expect(src).toMatch(/r\.disabled = false/)
  })
})

describe('E2 the person gets a window to stop the auto-connect', () => {
  it('does not connect when the person cancels', async () => {
    const r = mkRun({ pend: fresh(), oauth: true, session: goodSession(), confirm: false })
    await r.fn()
    expect(r.calls.connect).toBe(0)
  })
  it('only the join page can message the extension, and localhost only in the dev manifest', () => {
    const m = JSON.parse(read('manifest.json'))
    expect(m.externally_connectable.matches.sort()).toEqual(['http://localhost/join*', 'https://app.coriqo.io/join*'])
    expect(m.externally_connectable.matches.every((x) => /^https?:\/\/[^/]+\/join\*$/.test(x))).toBe(true)
  })
  it('host_permissions are what HEAD had (the Shield endpoint and dev Coriqo need all of localhost)', () => {
    const m = JSON.parse(read('manifest.json'))
    expect(m.host_permissions).toEqual(['http://127.0.0.1/*', 'http://localhost/*'])
  })
  it('login.html has the status line and a Cancel button', () => {
    const h = read('login.html')
    expect(h).toContain('id="auto-status"')
    expect(h).toContain('id="auto-cancel"')
    expect(h).toContain('Connecting this computer')
  })
})

describe('E4 stale flags and the admin off switch', () => {
  it('exports the one-hour TTL', () => { expect(L.JOIN_TTL_MS).toBe(3_600_000) })
  it('runAfterJoin drops a flag older than the TTL without signing in', async () => {
    const r = mkRun({ pend: { ...fresh(), at: Date.now() - 3_600_001 }, oauth: true, session: goodSession() })
    expect(await r.fn()).toBe(false)
    expect(r.calls.oauth).toBe(0)
    expect(r.calls.connect).toBe(0)
    expect(r.store.coriqo_pending_join).toBeUndefined()
  })
  it('login page load clears a pending join older than the TTL, keeps a fresh one', async () => {
    for (const [at, kept] of [[Date.now() - 3_600_001, false], [Date.now() - 1000, true]]) {
      const { store, chrome } = mkStore({ coriqo_pending_join: { tenant: 't', at } })
      await new Function('chrome', 'PENDING_JOIN_KEY', extract('login.js', 'clearStalePendingJoin') + '; return clearStalePendingJoin')(
        chrome, 'coriqo_pending_join')()
      // the helper reads the TTL from the loaded link module
      expect(store.coriqo_pending_join !== undefined).toBe(kept)
    }
  })
  it('accepts a join while linking is on', async () => {
    const r = await bg({ managed: {}, pending: { region: 'usa', state: STATE, at: Date.now() - 1000 } })
    expect(r.ok).toBe(true)
    expect(r.calls.tabs).toBe(1)
    expect(r.store.coriqo_pending_join.accepted).toBe(true)
    expect(r.store.coriqo_pending_join.tenant).toBe('acme_msp') // from the message, not the page's own guess
  })
  it('an accepted join is used up: a second message opens no second tab', async () => {
    const r = await bg({ managed: {}, pending: { region: 'usa', state: STATE, at: Date.now() - 1000 }, twice: true })
    expect(r.ok).toEqual([true, false])
    expect(r.calls.tabs).toBe(1)
  })
  it('a burst of concurrent messages opens exactly one tab', async () => {
    const r = await bg({ managed: {}, pending: { region: 'usa', state: STATE, at: Date.now() - 1000 }, burst: 5 })
    expect(r.ok.filter(Boolean).length).toBe(1)
    expect(r.calls.tabs).toBe(1)
  })
  it('if the login tab never ran, the page may try again after a minute (but not before)', async () => {
    const stuck = (ago) => ({ region: 'usa', state: STATE, at: Date.now() - 5000, accepted: true, accepted_at: Date.now() - ago, connect: true })
    const late = await bg({ managed: {}, pending: stuck(61_000) })
    expect(late.ok).toBe(true)
    expect(late.calls.tabs).toBe(1)
    const early = await bg({ managed: {}, pending: stuck(5_000) })
    expect(early.ok).toBe(false)
    expect(early.calls.tabs).toBe(0)
  })
  it('refuses early when the admin turned linking off: no flag, no tab', async () => {
    const r = await bg({ managed: { coriqo_link: 'disabled' }, pending: { region: 'usa', state: STATE, at: Date.now() - 1000 } })
    expect(r.ok).toBe(false)
    expect(r.calls.tabs).toBe(0)
    expect(r.store.coriqo_pending_join.accepted).toBeUndefined()
  })
})

describe('Y1 the connect itself enrols in the joined workspace', () => {
  it('onConnect prefers the workspace it is given over the picker', () => {
    const src = extract('login.js', 'onConnect')
    expect(src).toMatch(/async function onConnect\(forcedTenant\)/)
    expect(src.indexOf('forcedTenant')).toBeLessThan(src.indexOf("#tenants input[name=tenant]:checked"))
  })
  it('the manual button calls onConnect with no workspace, never the click event', () => {
    expect(read('login.js'))
      .toMatch(/addEventListener\('click', working\(\(\) => onConnect\(\)\)\)/)
  })
})

describe('review fixes: a failed sign-in keeps the join, a used one cannot run twice', () => {
  it('keeps the join open for a retry (accepted off) when sign-in did not work', async () => {
    const r = mkRun({ pend: fresh(), oauth: false, session: null })
    expect(await r.fn()).toBe(true)
    expect(r.calls.connect).toBe(0)
    expect(r.store.coriqo_pending_join).toMatchObject({ tenant: 'acme_usa', accepted: false })
  })
  it('uses the join up once signed in, even when connect was not ticked', async () => {
    const r = mkRun({ pend: { ...fresh(), connect: false }, oauth: true, session: goodSession() })
    await r.fn()
    expect(r.store.coriqo_pending_join).toBeUndefined()
  })
  it('drops a join that is over an hour old without signing in', async () => {
    const r = mkRun({ pend: { ...fresh(), at: Date.now() - 3_700_000 }, oauth: true, session: goodSession() })
    expect(await r.fn()).toBe(false)
    expect(r.calls.oauth).toBe(0)
    expect(r.store.coriqo_pending_join).toBeUndefined()
  })
  it('isPendingJoinFresh: an hour, never the future, never garbage', () => {
    const now = 1_800_000_000_000
    expect(L.isPendingJoinFresh({ at: now - 1000 }, now)).toBe(true)
    expect(L.isPendingJoinFresh({ at: now - 3_600_001 }, now)).toBe(false)
    expect(L.isPendingJoinFresh({ at: now + 5 }, now)).toBe(false)
    expect(L.isPendingJoinFresh({ at: 'x' }, now)).toBe(false)
    expect(L.isPendingJoinFresh(null, now)).toBe(false)
  })
  it('says why when a sign-in has no workspace, and offers a retry', () => {
    const src = read('login.js')
    expect(src).toMatch(/If you just paid, give it a minute and sign in again/)
    expect(read('login.html')).toMatch(/id="join-retry"/)
  })
  it('keeps the browser-only limits card open by default', () => {
    expect(read('login.html')).toMatch(/<details class="card" id="upsell-card" open>/)
  })
})

describe('no MSP workspace names ship in the extension', () => {
  it('no shipped file names an MSP workspace', () => {
    for (const f of fs.readdirSync(EXT, { recursive: true })) {
      const full = path.join(EXT, f)
      if (!fs.statSync(full).isFile() || /\.(png|jpg|ico)$/.test(f)) continue
      const t = fs.readFileSync(full, 'utf8')
      expect(t, f).not.toMatch(new RegExp('coriqo' + '_msp|JOIN_TENANTS|joinTenantFor'))
    }
  })
})

describe('review fixes: the workspace cannot be swapped by a later message, and the person sees it', () => {
  it('a later message with the same state cannot change the workspace Coriqo already named', async () => {
    const first = { type: 'coriqo.join.finished', connect: true, state: STATE, tenant: 'acme_usa' }
    const second = { ...first, tenant: 'other_ws' }
    const pending = { region: 'usa', state: STATE, at: Date.now() - 1000, accepted: false, tenant: 'acme_usa' }
    const r = await bg({ managed: {}, pending, msgOverride: second })
    expect(r.ok).toBe(false)
    expect(r.calls.tabs).toBe(0)
    expect(r.store.coriqo_pending_join.tenant).toBe('acme_usa')
    const same = await bg({ managed: {}, pending, msgOverride: first })
    expect(same.ok).toBe(true)
  })
  it('the cancel window names the workspace that is about to be connected', () => {
    expect(read('login.html')).toMatch(/id="auto-ws"/)
    expect(read('login.js')).toMatch(/el\('auto-ws'\)\.textContent = workspace/)
  })
  it('the join regions are the known regions, not a second list', () => {
    expect(read('coriqo-link.js')).toMatch(/JOIN_REGIONS = Object\.keys\(REGIONS\)/)
  })
})

describe('a person with no Coriqo account can start from the first screen', () => {
  it('the first screen offers Join, wired to the same join start', () => {
    expect(read('login.html')).toMatch(/id="join-new"/)
    const src = read('login.js')
    expect(src).toMatch(/el\('join-new'\)\.addEventListener\('click', working\(\(\) => onJoin\('request-msg'\)\)\)/)
    expect(src).toMatch(/async function onJoin\(msgId = 'join-msg'\)/)
    expect(extract('login.js', 'onJoin')).not.toMatch(/setMsg\('join-msg'/) // the status goes to the step that is showing
  })
})

describe('the first screen says what is free and what is paid, in two clear paths', () => {
  const html = () => read('login.html')
  it('an existing account is covered by its organisation, a new personal account needs a paid plan', () => {
    const h = html()
    expect(h).toMatch(/I have a Coriqo account[\s\S]*covered\s+by your organisation: no payment/)
    expect(h).toMatch(/I'm new to Coriqo[\s\S]*Personal and non-business accounts need a paid plan/)
    expect(h).toMatch(/Work for an organisation that uses Coriqo\? Don't pay here: ask your administrator to add you/)
  })
  it('the email link sits behind a fold, and every control the script needs is still there once', () => {
    const h = html()
    expect(h).toMatch(/<details class="sees" id="email-link">[\s\S]*id="send"[\s\S]*<\/details>/)
    for (const id of ['oauth-start', 'join-new', 'email', 'workspace', 'send', 'request-msg', 'skip', 'lead']) {
      expect([...h.matchAll(new RegExp(`id="${id}"`, 'g'))].length, id).toBe(1)
    }
  })
  it('names no price, plan or payment provider (the amounts live on Coriqo)', () => {
    expect(html()).not.toMatch(/stripe|\$\d|per month|\/mo\b|focused|pro plan/i)
  })
})

describe('review fixes: the first screen keeps its promises honest', () => {
  const h = () => read('login.html')
  it('says pairing with a local Shield needs no account and no payment, on every step', () => {
    const html = h()
    const leadAt = html.indexOf('id="lead"')
    expect(html.slice(leadAt, leadAt + 400)).toMatch(/needs no account and no payment/)
    expect(leadAt).toBeLessThan(html.indexOf('id="step-request"')) // outside the steps, so no step hides it
  })
  it('does not promise the computer connects: that depends on the box the person ticks on Coriqo', () => {
    expect(h()).toMatch(/If you tick the box there, Shield then connects this computer/)
    expect(h()).not.toMatch(/connects this computer when you finish/)
  })
  it('the email field label matches the copy that any email works', () => {
    expect(h()).toMatch(/<label for="email">Email<\/label>/)
    expect(h()).not.toMatch(/Work email/)
  })
})


describe('join offer (price line comes from Coriqo at run time)', () => {
  const ok = (summary) => ({ summary })
  it('parseJoinOffer accepts a normal summary only', () => {
    expect(L.parseJoinOffer(ok('one plan, billed on Coriqo'))).toBe('one plan, billed on Coriqo')
    for (const bad of [null, undefined, 'x', 5, [], {}, ok(''), ok(7), ok('a'.repeat(121)), ok('a <b> c'), ok('a\nb'), ok('a\u0007b')]) {
      expect(L.parseJoinOffer(bad)).toBeNull()
    }
    expect(L.parseJoinOffer(ok('a'.repeat(120)))).toBe('a'.repeat(120))
  })
  it('parseJoinOffer rejects bidi and zero-width format characters', () => {
    for (const c of ['\u202e', '\u200b', '\u200f', '\u2066', '\u2069', '\ufeff']) {
      expect(L.parseJoinOffer(ok(`Free ${c}now`))).toBeNull()
    }
  })
  it('fetchJoinOffer refuses redirects', async () => {
    let seen
    await L.fetchJoinOffer({ fetchImpl: async (u, i) => { seen = i; return res(200, { summary: 'S' }) }, base: BASE })
    expect(seen.redirect).toBe('error')
  })
  const res = (status, body, json = true) => ({ status, ok: status === 200, json: async () => { if (!json) throw new Error('x'); return body } })
  it('fetchJoinOffer returns the string, or null on any failure', async () => {
    let seen
    const good = async (url, init) => { seen = { url, init }; return res(200, { summary: 'S' }) }
    expect(await L.fetchJoinOffer({ fetchImpl: good, base: BASE })).toBe('S')
    expect(seen.url).toBe(`${BASE}/api/v1/billing/msp-join/offer`)
    expect(seen.init.credentials).toBe('omit')
    expect(seen.init.method || 'GET').toBe('GET')
    expect(await L.fetchJoinOffer({ fetchImpl: async () => { throw new Error('net') }, base: BASE })).toBeNull()
    expect(await L.fetchJoinOffer({ fetchImpl: async () => res(503, { summary: 'S' }), base: BASE })).toBeNull()
    expect(await L.fetchJoinOffer({ fetchImpl: async () => res(200, null, false), base: BASE })).toBeNull()
    expect(await L.fetchJoinOffer({ fetchImpl: good, base: 'http://evil.example' })).toBeNull()
    expect(await L.fetchJoinOffer({ fetchImpl: good, base: 'nonsense' })).toBeNull()
  })
  it('fetchJoinOffer gives up on a hung fetch', async () => {
    const t = Date.now()
    expect(await L.fetchJoinOffer({ fetchImpl: () => new Promise(() => {}), base: BASE, timeoutMs: 20 })).toBeNull()
    expect(Date.now() - t).toBeLessThan(1000)
  })
  const dir = path.join(REPO, 'src/byoai/browser_extension')
  const loginJs = fs.readFileSync(path.join(dir, 'login.js'), 'utf8')
  it('login.js fills #join-cost with textContent, after the policy-off return', () => {
    expect(fs.readFileSync(path.join(dir, 'login.html'), 'utf8')).toMatch(/<p id="join-cost"><\/p>/)
    expect(loginJs).toMatch(/node\.textContent\s*=/)
    expect(loginJs).not.toMatch(/innerHTML/)
    const off = loginJs.indexOf("setMsg('request-msg', OFF_TEXT, 'bad')\n    return")
    const call = loginJs.indexOf('fetchJoinOffer')
    expect(off).toBeGreaterThan(0)
    expect(call).toBeGreaterThan(off)
  })
  it('nothing numeric or priced is hardcoded in the shipped files', () => {
    for (const f of ['login.html', 'login.js', 'coriqo-link.js']) {
      const s = fs.readFileSync(path.join(dir, f), 'utf8')
      expect(s, f).not.toMatch(/\$\d/)
      expect(s, f).not.toMatch(/per month|per year|a year/i)
    }
    for (const f of fs.readdirSync(dir).filter((x) => /\.(js|html|json|md)$/.test(x))) {
      expect(fs.readFileSync(path.join(dir, f), 'utf8'), f).not.toMatch(/\$\d/)
    }
  })
})

describe('review fixes: the price card reads cleanly and never contradicts itself', () => {
  const L2 = createRequire(import.meta.url)(path.join(REPO, 'src/byoai/browser_extension/coriqo-link.js'))
  it('a summary of only spaces is not a price, and surrounding spaces are trimmed', () => {
    expect(L2.parseJoinOffer({ summary: '     ' })).toBeNull()
    expect(L2.parseJoinOffer({ summary: '\t ' })).toBeNull()
    expect(L2.parseJoinOffer({ summary: '  X per month  ' })).toBe('X per month')
  })
  it('the card adds no full stop of its own, so a summary that ends in punctuation is not doubled', () => {
    const src = read('login.js')
    expect(src).toMatch(/`Price: \$\{line\}`/)
    expect(src).not.toMatch(/`Price: \$\{line\}\./)
  })
  it('the paid-plan paragraph does not say connecting costs nothing; the organisation sentence is its own paragraph', () => {
    const h = read('login.html')
    const paid = h.match(/<p><b>Personal and non-business accounts need a paid plan\.<\/b>[\s\S]*?<\/p>/)[0]
    expect(paid).not.toMatch(/no cost|covered by your organisation/)
    expect(h).toMatch(/<p>Work for an organisation that uses Coriqo\? Don't pay here[\s\S]*?at no cost to you\.<\/p>/)
  })
  it('loadJoinCost reuses the node it looked up', () => {
    const body = read('login.js').match(/async function loadJoinCost\(\) \{[\s\S]*?\n\}/)[0]
    expect(body.match(/el\('join-cost'\)/g).length).toBe(1)
  })
})
