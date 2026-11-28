// @vitest-environment node
/**
 * Managed settings (managed_schema.json + managed-settings.js): an administrator
 * can pick Shield's local port and nothing else. Offline: a stubbed chrome, no
 * browser. The service worker is loaded for real, so the endpoint it uses and
 * the "set by your administrator" refusal are the shipped code paths.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import { REPO } from './env.mjs'

const EXT = path.join(REPO, 'src', 'byoai', 'browser_extension')
const read = (f) => readFileSync(path.join(EXT, f), 'utf8')

function load(file) {
  const ctx = { globalThis: null }
  ctx.globalThis = ctx
  vm.createContext(ctx)
  vm.runInContext(read(file), ctx)
  return ctx.ShieldManaged
}
const M = load('managed-settings.js')

describe('parseManaged', () => {
  it('is not managed with no policy', () => {
    for (const raw of [undefined, null, {}, 'x', 7, []]) {
      expect(M.parseManaged(raw)).toEqual({ managed: false, port: null, endpoint: null, managedBy: null })
    }
  })
  it('builds the endpoint on this computer from a valid port only', () => {
    expect(M.parseManaged({ shield_port: 18000 })).toMatchObject({
      managed: true, port: 18000, endpoint: 'http://127.0.0.1:18000/api/browser' })
  })
  it.each([80, 1023, 65536, 17831.5, '17831', true, null, NaN, -1])('ignores port %s', (port) => {
    expect(M.parseManaged({ shield_port: port }).managed).toBe(false)
  })
  it('never takes a host: unknown keys cannot move the endpoint', () => {
    const r = M.parseManaged({ shield_port: 17831, endpoint: 'https://evil.example/api/browser', host: 'evil.example' })
    expect(r.endpoint).toBe('http://127.0.0.1:17831/api/browser')
  })
  it('keeps a trimmed, capped label', () => {
    expect(M.parseManaged({ managed_by: '  Contoso IT ' }).managedBy).toBe('Contoso IT')
    expect(M.parseManaged({ managed_by: 'x'.repeat(200) }).managedBy).toHaveLength(64)
    expect(M.parseManaged({ managed_by: '   ' }).managedBy).toBeNull()
    expect(M.parseManaged({ managed_by: 5 }).managedBy).toBeNull()
  })
  it('a label alone does not lock the address', () => {
    expect(M.parseManaged({ managed_by: 'Contoso IT' }).managed).toBe(false)
  })
})

describe('readManaged', () => {
  it('reads chrome.storage.managed', async () => {
    const storage = { managed: { get: async () => ({ shield_port: 18001 }) } }
    expect((await M.readManaged(storage)).endpoint).toBe('http://127.0.0.1:18001/api/browser')
  })
  it('treats a missing area or a throwing read as not managed', async () => {
    expect((await M.readManaged({})).managed).toBe(false)
    expect((await M.readManaged(undefined)).managed).toBe(false)
    expect((await M.readManaged({ managed: { get: async () => { throw new Error('no policy') } } })).managed).toBe(false)
  })
})

describe('pickEndpoint', () => {
  const resolveSaved = (s) => s || 'http://127.0.0.1:17831/api/browser'
  it('managed wins over a saved choice', () => {
    const managed = M.parseManaged({ shield_port: 18002 })
    expect(M.pickEndpoint(managed, 'http://127.0.0.1:9999/api/browser', resolveSaved)).toBe('http://127.0.0.1:18002/api/browser')
  })
  it('without policy, behaves as before', () => {
    expect(M.pickEndpoint(M.parseManaged(null), undefined, resolveSaved)).toBe('http://127.0.0.1:17831/api/browser')
    expect(M.pickEndpoint(M.parseManaged(null), 'http://127.0.0.1:9999/api/browser', resolveSaved)).toBe('http://127.0.0.1:9999/api/browser')
  })
})

describe('manifest and service worker', () => {
  const manifest = JSON.parse(read('manifest.json'))
  it('declares the schema file, which exists and is valid', () => {
    expect(manifest.storage).toEqual({ managed_schema: 'managed_schema.json' })
    const schema = JSON.parse(read('managed_schema.json'))
    expect(Object.keys(schema.properties).sort()).toEqual(['coriqo_api_base', 'coriqo_link', 'managed_by', 'shield_port'])
    expect(schema.properties.shield_port).toMatchObject({ type: 'integer', minimum: 1024, maximum: 65535 })
  })
  it('adds no permission (managed storage needs none)', () => {
    expect(manifest.permissions).toEqual(['storage', 'activeTab', 'alarms', 'scripting', 'identity'])
    expect(manifest.host_permissions).toEqual(['http://127.0.0.1/*', 'http://localhost/*'])
  })

  function worker({ managed, saved }) {
    let listener
    const local = { endpoint: saved }
    const chrome = {
      runtime: { id: 'ext', onMessage: { addListener: (fn) => { listener ??= fn } }, onMessageExternal: { addListener() {} }, onInstalled: { addListener() {} },
        onStartup: { addListener() {} }, getURL: (p) => p },
      storage: {
        managed: { get: async () => { if (!managed) throw new Error('none'); return managed } },
        local: { get: (keys, cb) => { const k = typeof keys === 'string' ? keys : null; const v = k ? { [k]: local[k] } : { ...local }; return cb ? cb(v) : Promise.resolve(v) },
          set: (obj, cb) => { Object.assign(local, obj); cb?.(); return Promise.resolve() }, remove: async () => {} },
        session: { get: async () => ({}), set: async () => {}, remove: async () => {} },
        onChanged: { addListener() {} },
      },
      alarms: { create() {}, clear() {}, onAlarm: { addListener() {} } },
      tabs: { onUpdated: { addListener() {} }, onRemoved: { addListener() {} }, query: async () => [] },
      scripting: {}, action: { setBadgeText() {}, setBadgeBackgroundColor() {}, setIcon() {}, setTitle() {} },
    }
    const ctx = { chrome, console, setTimeout, clearTimeout, URL, crypto: globalThis.crypto, fetch: async () => { throw new Error('offline') },
      importScripts: (...files) => files.forEach((f) => vm.runInContext(read(f), ctx)), atob, btoa, TextEncoder, Uint8Array }
    ctx.globalThis = ctx
    vm.createContext(ctx)
    vm.runInContext(read('background.js'), ctx)
    const ask = (msg) => new Promise((resolve) => {
      listener(msg, { id: 'ext', url: 'chrome-extension://ext/popup.html' }, resolve)
    })
    return { ask, local }
  }

  it('uses the managed port and says so', async () => {
    const w = worker({ managed: { shield_port: 18003, managed_by: 'Contoso IT' }, saved: 'http://127.0.0.1:9999/api/browser' })
    expect(await w.ask({ type: 'agent.getEndpoint' })).toEqual({
      endpoint: 'http://127.0.0.1:18003/api/browser', managed: true, managedBy: 'Contoso IT' })
  })
  it('refuses a person changing a managed address', async () => {
    const w = worker({ managed: { shield_port: 18003 }, saved: undefined })
    expect(await w.ask({ type: 'agent.setEndpoint', endpoint: 'http://127.0.0.1:9999/api/browser' }))
      .toEqual({ error: 'set by your administrator' })
    expect(w.local.endpoint).toBeUndefined()
  })
  it('unmanaged: default endpoint, and a local address can still be saved; a remote one cannot', async () => {
    const w = worker({ managed: null, saved: undefined })
    expect(await w.ask({ type: 'agent.getEndpoint' })).toMatchObject({ endpoint: 'http://127.0.0.1:17831/api/browser', managed: false })
    expect(await w.ask({ type: 'agent.setEndpoint', endpoint: 'http://127.0.0.1:9999/api/browser' })).toEqual({ ok: true })
    expect(await w.ask({ type: 'agent.setEndpoint', endpoint: 'https://evil.example/api/browser' }))
      .toEqual({ error: 'endpoint must be a localhost Shield server' })
  })
})
