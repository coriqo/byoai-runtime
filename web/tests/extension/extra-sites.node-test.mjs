// Runs with node's own runner, no web dependencies installed:
//   node --test web/tests/extension/extra-sites.node-test.mjs
// (The name keeps vitest's *.test.mjs glob from picking it up.)
// The chrome API is a stub; live behaviour in a real browser is not covered.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import { fileURLToPath } from 'node:url'

const EXT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'src', 'byoai', 'browser_extension')
const read = (f) => readFileSync(path.join(EXT, f), 'utf8')
const manifest = JSON.parse(read('manifest.json'))
const curated = JSON.parse(read('optional_sites.json')).sites

const plain = (x) => JSON.parse(JSON.stringify(x))
const eq = (a, b) => assert.deepEqual(plain(a), plain(b))
const load = () => {
  const ctx = { globalThis: null }
  ctx.globalThis = ctx
  vm.createContext(ctx)
  vm.runInContext(read('shield-optional.js'), ctx)
  vm.runInContext(read('extra-sites.js'), ctx)
  return ctx
}
const X = load().SHIELD_EXTRA_SITES
const OPT = load().SHIELD_OPTIONAL_SITES
const H = curated[0].host

test('manifest list, generated script and optional_sites.json agree; no broad pattern', () => {
  eq(manifest.optional_host_permissions, curated.map((c) => `https://${c.host}/*`))
  eq(OPT.map((o) => o.host), curated.map((c) => c.host))
  assert.ok(manifest.permissions.includes('scripting'))
  for (const p of manifest.optional_host_permissions) assert.match(p, /^https:\/\/[a-z0-9.-]+\/\*$/)
})

test('registered scripts are the same files and worlds as the static entries', () => {
  const [main, iso] = X.definitionsFor(H)
  const [sMain, sIso] = manifest.content_scripts
  eq(main.js, sMain.js)
  assert.equal(main.world, 'MAIN')
  assert.equal(main.allFrames, sMain.all_frames)
  assert.equal(main.matchAboutBlank, sMain.match_about_blank)
  eq(iso.js, sIso.js)
  assert.equal(iso.world, undefined)
  eq(main.matches, [`https://${H}/*`])
})

test('cleanExtraSites keeps only curated hosts and trims fields', () => {
  const out = X.cleanExtraSites([
    { host: H, app: 'My <app>', compose: ['textarea', 5, 'x'.repeat(201)] },
    { host: 'evil.example.com' }, { host: H }, null, 'x'], OPT)
  assert.equal(out.length, 1)
  eq(out[0], { host: H, app: H, compose: ['textarea'], send: [] })
  eq(X.cleanExtraSites(undefined, OPT), [])
  eq(X.cleanExtraSites([{ host: H }], []), [])
})

test('plan: register granted, ask for ungranted, unregister removed, update changed', () => {
  const wanted = [{ host: H }, { host: curated[1].host }]
  let p = X.planExtraSites({ wanted, registered: [], granted: new Set([H]) })
  assert.equal(p.register.length, 2)
  eq(p.needsPermission, [curated[1].host])
  const reg = X.definitionsFor(H).map((d) => ({ id: d.id, js: d.js, matches: d.matches, world: d.world }))
  p = X.planExtraSites({ wanted, registered: reg, granted: new Set([H]) })
  eq([p.register.length, p.update.length, p.unregister.length], [0, 0, 0])
  reg[0].js = ['old.js']
  p = X.planExtraSites({ wanted, registered: reg, granted: new Set([H]) })
  assert.equal(p.update.length, 1)
  p = X.planExtraSites({ wanted: [], registered: reg, granted: new Set() })
  assert.equal(p.unregister.length, 2)
  // a script that is not ours is never touched
  p = X.planExtraSites({ wanted: [], registered: [{ id: 'other', js: [], matches: [] }], granted: new Set() })
  eq(p.unregister, [])
})

test('popup wording names the site and says what to do', () => {
  const line = X.grantLine({ app: 'Mistral chat', host: H })
  assert.match(line, /Mistral chat/)
  assert.ok(line.includes(H))
  assert.match(line, /allow/)
  eq(X.pendingGrants([{ host: H }], new Set([H])), [])
})

// ---- the service worker, with a stubbed chrome ----
function worker({ granted = [], scripting = true, stored = {} } = {}) {
  const calls = []
  const registered = []
  const local = { ...stored }
  const listeners = {}
  const ev = (name) => ({ addListener: (f) => { (listeners[name] ||= []).push(f) } })
  const chrome = {
    runtime: { id: 'x', getURL: () => 'chrome-extension://x/', onInstalled: ev('inst'), onStartup: ev('start'), onMessage: ev('msg') },
    action: { setBadgeText() {}, setBadgeBackgroundColor() {} },
    tabs: { create() {} },
    alarms: { onAlarm: ev('alarm'), clear() {}, create() {} },
    storage: {
      local: {
        get: async (k) => (typeof k === 'string' ? { [k]: local[k] } : Object.fromEntries((Array.isArray(k) ? k : Object.keys(k || {})).map((x) => [x, local[x]]))),
        set: async (o) => { Object.assign(local, o) },
        remove: async (ks) => { for (const k of [].concat(ks)) delete local[k] },
      },
      session: undefined,
      onChanged: ev('changed'),
    },
    permissions: {
      contains: async ({ origins }) => origins.every((o) => granted.includes(o)),
      onAdded: ev('added'), onRemoved: ev('removed'),
    },
  }
  if (scripting) {
    chrome.scripting = {
      getRegisteredContentScripts: async () => registered.map((r) => ({ ...r })),
      registerContentScripts: async (defs) => { calls.push(['register', defs.map((d) => d.id)]); registered.push(...defs) },
      updateContentScripts: async (defs) => { calls.push(['update', defs.map((d) => d.id)]) },
      unregisterContentScripts: async ({ ids }) => {
        calls.push(['unregister', ids])
        for (const id of ids) registered.splice(registered.findIndex((r) => r.id === id), 1)
      },
    }
  }
  const ctx = {
    chrome, console, setTimeout, clearTimeout, crypto: { randomUUID: () => 'u' }, atob, fetch: async () => ({ ok: false }),
    importScripts: (...fs) => { for (const f of fs) vm.runInContext(read(f), ctx) },
  }
  ctx.globalThis = ctx
  vm.createContext(ctx)
  vm.runInContext(read('background.js') + '\n;globalThis.__sync = (w) => syncExtraSites(w); globalThis.__consent = (v) => { consentOn = v }', ctx)
  return { ctx, calls, local, registered, listeners }
}
const origin = (h) => `https://${h}/*`

test('worker: granted host registers, ungranted is reported, never silent', async () => {
  const w = worker({ granted: [origin(H)] })
  w.ctx.__consent(true)
  await w.ctx.__sync([{ host: H, app: 'A' }, { host: curated[1].host, app: 'B' }])
  eq(w.calls, [['register', [`shield-extra-main-${H}`, `shield-extra-iso-${H}`]]])
  assert.equal(w.local.extra_sites_status.errors[curated[1].host], 'needs permission')
  assert.equal(w.local.extra_sites_status.off, null)
})

test('worker: removing the site unregisters; withdrawn consent unregisters all', async () => {
  const w = worker({ granted: [origin(H)] })
  w.ctx.__consent(true)
  await w.ctx.__sync([{ host: H, app: 'A' }])
  await w.ctx.__sync([])
  assert.equal(w.calls.at(-1)[0], 'unregister')
  assert.equal(w.registered.length, 0)
  await w.ctx.__sync([{ host: H, app: 'A' }])
  w.ctx.__consent(false)
  await w.ctx.__sync([{ host: H, app: 'A' }])
  assert.equal(w.registered.length, 0)
})

test('worker: no scripting API says so instead of failing silently', async () => {
  const w = worker({ scripting: false })
  w.ctx.__consent(true)
  await w.ctx.__sync([{ host: H, app: 'A' }])
  assert.match(w.local.extra_sites_status.off, /scripting/)
})

test('worker: an API error is stored with its reason', async () => {
  const w = worker({ granted: [origin(H)] })
  w.ctx.__consent(true)
  w.ctx.chrome.scripting.registerContentScripts = async () => { throw new Error('boom') }
  await w.ctx.__sync([{ host: H, app: 'A' }])
  assert.match(w.local.extra_sites_status.off, /boom/)
})
