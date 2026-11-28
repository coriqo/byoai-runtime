// Joining a Coriqo workspace by paying: the helpers the login page and the background script use.
import { describe, expect, it } from 'vitest'
import { createRequire } from 'node:module'
import { REPO } from './env.mjs'
import path from 'node:path'
import fs from 'node:fs'

const L = createRequire(import.meta.url)(path.join(REPO, 'src/byoai/browser_extension/coriqo-link.js'))
const BASE = 'https://app.coriqo.io'
const NOW = 1_800_000_000_000
const msg = { type: 'coriqo.join.finished', connect: true }
const pending = { tenant: 'coriqo_msp_usa', at: NOW - 60_000 }

describe('join helpers', () => {
  it('picks the UK workspace for the UK and Europe, and the US one for everyone else', () => {
    expect(L.joinTenantFor('uk')).toBe('coriqo_msp_uk')
    expect(L.joinTenantFor('eu')).toBe('coriqo_msp_uk')
    expect(L.joinTenantFor('usa')).toBe('coriqo_msp_usa')
    expect(L.joinTenantFor(null)).toBe('coriqo_msp_usa')
  })

  it('builds an address with the workspace and source only', () => {
    const u = new URL(L.joinUrl({ base: BASE, tenant: 'coriqo_msp_uk' }))
    expect(u.origin + u.pathname).toBe('https://app.coriqo.io/join')
    expect([...u.searchParams.keys()].sort()).toEqual(['source', 'tenant'])
    expect(() => L.joinUrl({ base: 'http://evil.example', tenant: 'x' })).toThrow('bad_base')
  })

  it('accepts the finished message from the Coriqo page for a join it started', () => {
    expect(L.acceptJoinMessage({ msg, senderOrigin: BASE, base: BASE, pending, now: NOW })).toEqual({ ok: true, connect: true })
    expect(L.acceptJoinMessage({ msg: { ...msg, connect: false }, senderOrigin: BASE, base: BASE, pending, now: NOW }).connect).toBe(false)
  })

  it('treats anything but connect === true as no connect', () => {
    expect(L.acceptJoinMessage({ msg: { type: msg.type, connect: 'yes' }, senderOrigin: BASE, base: BASE, pending, now: NOW }).connect).toBe(false)
  })

  it('refuses a page that is not the Coriqo address in use', () => {
    for (const origin of ['https://evil.example', 'http://app.coriqo.io', 'https://app.coriqo.io.evil.example', undefined]) {
      expect(L.acceptJoinMessage({ msg, senderOrigin: origin, base: BASE, pending, now: NOW }).ok).toBe(false)
    }
  })

  it('refuses when no join was started, or it is an hour old, or the clock ran backwards', () => {
    expect(L.acceptJoinMessage({ msg, senderOrigin: BASE, base: BASE, pending: null, now: NOW }).ok).toBe(false)
    expect(L.acceptJoinMessage({ msg, senderOrigin: BASE, base: BASE, pending: { ...pending, at: NOW - 3_600_001 }, now: NOW }).ok).toBe(false)
    expect(L.acceptJoinMessage({ msg, senderOrigin: BASE, base: BASE, pending: { ...pending, at: NOW + 5 }, now: NOW }).ok).toBe(false)
  })

  it('refuses any other message type', () => {
    for (const m of [null, {}, { type: 'other' }, { type: 'coriqo.join.finished ' }]) {
      expect(L.acceptJoinMessage({ msg: m, senderOrigin: BASE, base: BASE, pending, now: NOW }).ok).toBe(false)
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
const fresh = () => ({ tenant: 'coriqo_msp_usa', at: Date.now() - 1000, accepted: true, connect: true })
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
const goodSession = (over = {}) => ({ via: 'oauth', at: Date.now() + 5, tenant_slug: 'coriqo_msp_usa', tenants: ['coriqo_msp_usa'], ...over })

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
    const r = mkRun({ pend: fresh(), oauth: true, session: goodSession({ tenant_slug: 'coriqo_msp_uk', tenants: ['coriqo_msp_uk', 'coriqo_msp_usa'] }) })
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
    expect(r.calls.tenant).toBe('coriqo_msp_usa') // onConnect is told the joined workspace, not left to read the picker
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
    let pick = 'coriqo_msp_usa'
    const r = mkRun({ pend: fresh(), oauth: true, session: goodSession(), picked: () => pick, after: () => { pick = 'coriqo_msp_uk' } })
    await r.fn()
    expect(r.calls.connect).toBe(0)
  })
  it('does not connect when the stored session changes workspace in the window', async () => {
    const sess = goodSession()
    const r = mkRun({ pend: fresh(), oauth: true, session: sess, after: () => { sess.tenant_slug = 'coriqo_msp_uk' } })
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
    const r = mkRun({ pend: fresh(), oauth: true, session: goodSession(), picked: 'coriqo_msp_usa' })
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
  async function bg({ managed, pending, twice = false, burst = 0 }) {
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
      const ok = await Promise.all(Array.from({ length: burst }, () => fn(msg, { origin: BASE })))
      return { ok, store, calls }
    }
    let ok = await fn(msg, { origin: BASE })
    if (twice) ok = [ok, await fn(msg, { origin: BASE })]
    return { ok, store, calls }
  }
  it('accepts a join while linking is on', async () => {
    const r = await bg({ managed: {}, pending: { tenant: 't', at: Date.now() - 1000 } })
    expect(r.ok).toBe(true)
    expect(r.calls.tabs).toBe(1)
    expect(r.store.coriqo_pending_join.accepted).toBe(true)
  })
  it('an accepted join is used up: a second message opens no second tab', async () => {
    const r = await bg({ managed: {}, pending: { tenant: 't', at: Date.now() - 1000 }, twice: true })
    expect(r.ok).toEqual([true, false])
    expect(r.calls.tabs).toBe(1)
  })
  it('a burst of concurrent messages opens exactly one tab', async () => {
    const r = await bg({ managed: {}, pending: { tenant: 't', at: Date.now() - 1000 }, burst: 5 })
    expect(r.ok.filter(Boolean).length).toBe(1)
    expect(r.calls.tabs).toBe(1)
  })
  it('if the login tab never ran, the page may try again after a minute (but not before)', async () => {
    const stuck = (ago) => ({ tenant: 't', at: Date.now() - 5000, accepted: true, accepted_at: Date.now() - ago, connect: true })
    const late = await bg({ managed: {}, pending: stuck(61_000) })
    expect(late.ok).toBe(true)
    expect(late.calls.tabs).toBe(1)
    const early = await bg({ managed: {}, pending: stuck(5_000) })
    expect(early.ok).toBe(false)
    expect(early.calls.tabs).toBe(0)
  })
  it('refuses early when the admin turned linking off: no flag, no tab', async () => {
    const r = await bg({ managed: { coriqo_link: 'disabled' }, pending: { tenant: 't', at: Date.now() - 1000 } })
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
    expect(r.store.coriqo_pending_join).toMatchObject({ tenant: 'coriqo_msp_usa', accepted: false })
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
