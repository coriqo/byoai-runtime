// @vitest-environment node
/**
 * The extension's local counts (shield-stats.js) and what they change in the
 * service worker, popup and welcome page: the extension shows its value with
 * no desktop Shield installed. Offline: a stubbed chrome, no browser.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import { REPO } from './env.mjs'

const EXT = path.join(REPO, 'src', 'byoai', 'browser_extension')
const read = (f) => readFileSync(path.join(EXT, f), 'utf8')
const ctx0 = { globalThis: null }
ctx0.globalThis = ctx0
vm.createContext(ctx0)
vm.runInContext(read('shield-stats.js'), ctx0)
const S = ctx0.ShieldStats
const NOW = new Date(2026, 10, 28, 15, 0, 0).getTime()
const DAY = 24 * 3600 * 1000

const req = (o) => ({ kind: 'browser.chat.request', chars: 120, flags: [], redactions: [], verdict: 'redact', ...o })

describe('factsOf', () => {
  it('counts a checked message, redacted personal details and matched rules', () => {
    const f = S.factsOf(req({ flags: ['pii:email', 'pii:card', 'flag:oversize'], redactions: ['email', 'card'], verdict: 'redacted(2)' }), 'chatgpt.com')
    expect(f).toEqual({ app: 'chatgpt', checked: 1, secrets: 0, personal: 2, warned: 0, rules: ['email', 'card'] })
  })
  it('a blocked secret is stopped; personal details in a stopped message are not "replaced"', () => {
    const f = S.factsOf(req({ flags: ['secret:aws_key', 'pii:email'], verdict: 'blocked' }), 'claude.ai')
    expect(f).toMatchObject({ secrets: 1, personal: 0 })
  })
  it('a warning is counted; cancelled after a warning stops the secret', () => {
    expect(S.factsOf(req({ flags: ['secret:credential_assign'], verdict: 'warned→cancelled' }), 'claude.ai')).toMatchObject({ warned: 1, secrets: 1 })
    expect(S.factsOf(req({ flags: ['secret:credential_assign'], verdict: 'warned→sent' }), 'claude.ai')).toMatchObject({ warned: 1, secrets: 0 })
  })
  it('record-only mode stops and replaces nothing', () => {
    expect(S.factsOf(req({ flags: ['secret:jwt', 'pii:email'], verdict: 'observe' }), 'chatgpt.com')).toMatchObject({ secrets: 0, personal: 0, checked: 1 })
  })
  it('ignores other rows, unread messages and hosts it does not cover', () => {
    expect(S.factsOf({ kind: 'browser.chat.status', chars: 3 }, 'chatgpt.com')).toBeNull()
    expect(S.factsOf(req({ chars: null }), 'chatgpt.com')).toBeNull()
    expect(S.factsOf(req(), 'evil.example')).toBeNull()
    expect(S.factsOf(null, 'chatgpt.com')).toBeNull()
  })
  it('keeps no text: odd rule names and anything outside the facts are dropped', () => {
    const f = S.factsOf(req({ flags: ['pii:jane.doe@example.com', 'pii:email'], redactions: ['email'], text: 'secret words', preview: 'x' }), 'chatgpt.com')
    expect(f.rules).toEqual(['email'])
    expect(JSON.stringify(f)).not.toMatch(/jane|secret words|example/)
  })
})

describe('add / prune / summarize', () => {
  const f = (o = {}) => ({ app: 'chatgpt', checked: 1, secrets: 0, personal: 1, warned: 0, rules: ['email'], ...o })
  it('stores numbers per app per day, nothing else', () => {
    let s = S.add(undefined, f(), NOW)
    s = S.add(s, f({ app: 'claude', secrets: 1, personal: 0, rules: ['aws_key'] }), NOW)
    expect(s).toEqual({ v: 1, days: { [S.dayKey(NOW)]: {
      chatgpt: { checked: 1, secrets: 0, personal: 1, warned: 0, rules: { email: 1 } },
      claude: { checked: 1, secrets: 1, personal: 0, warned: 0, rules: { aws_key: 1 } } } } })
  })
  it('keeps 30 days and drops older ones and junk', () => {
    let s
    for (let d = 0; d < 45; d++) s = S.add(s, f(), NOW - (44 - d) * DAY)
    s.days['not-a-day'] = { chatgpt: { checked: 9 } }
    s.days[S.dayKey(NOW)].evil = { checked: 5 }
    const kept = S.prune(s, NOW)
    expect(Object.keys(kept.days)).toHaveLength(30)
    expect(kept.days[S.dayKey(NOW - 30 * DAY)]).toBeUndefined()
    expect(kept.days[S.dayKey(NOW)].evil).toBeUndefined()
  })
  it('caps rule names per app per day', () => {
    let s
    for (let i = 0; i < 60; i++) s = S.add(s, f({ rules: [`r${i}`] }), NOW)
    expect(Object.keys(s.days[S.dayKey(NOW)].chatgpt.rules)).toHaveLength(40)
  })
  it('summarizes today and the week', () => {
    let s = S.add(undefined, f(), NOW - 9 * DAY)
    s = S.add(s, f({ secrets: 2 }), NOW - 3 * DAY)
    s = S.add(s, f({ app: 'claude' }), NOW)
    expect(S.summarize(s, NOW, 7)).toEqual({ checked: 2, secrets: 2, personal: 2, warned: 0, apps: ['Claude', 'ChatGPT'] })
    expect(S.summarize(s, NOW, 1)).toMatchObject({ checked: 1, apps: ['Claude'] })
  })
  it('says it in one calm line', () => {
    const week = { checked: 15, secrets: 3, personal: 12, warned: 0, apps: ['ChatGPT', 'Claude'] }
    expect(S.weekLine(week, { checked: 4 })).toBe('This week: 3 secrets stopped, 12 personal details replaced and 15 messages checked on ChatGPT and Claude. Today: 4 messages checked.')
    expect(S.weekLine({ checked: 1, secrets: 0, personal: 0, apps: ['Gemini'] }, { checked: 0 })).toBe('This week: 1 message checked, nothing to stop on Gemini.')
    expect(S.weekLine({ checked: 0, apps: [] }, { checked: 0 })).toMatch(/^Nothing checked yet/)
  })
})

describe('popup state when no local Shield answers', () => {
  const pick = (o) => S.standaloneState({ state: 'unreachable', managed: false, ...o })
  it('never paired, default address, known unmanaged: protecting, not an error', () => {
    expect(pick({})).toBe('protecting')
  })
  it('paired before, a custom address or an administrator port: a note that it is away', () => {
    expect(pick({ pin: 'AAAA' })).toBe('away')
    expect(pick({ customEndpoint: true })).toBe('away')
    expect(pick({ managed: true })).toBe('away')
  })
  it('managed state unknown (no answer in time) counts as expected, never protecting', () => {
    expect(pick({ managed: null })).toBe('away')
    expect(S.shieldExpected({})).toBe(true)
    expect(S.shieldExpected({ managed: false })).toBe(false)
  })
  it('a paired Shield whose record check failed keeps the existing warning', () => {
    expect(pick({ pin: 'AAAA', verifyFailed: true })).toBe('unreachable')
  })
  it('every state of a Shield that answers is unchanged', () => {
    for (const state of ['ok', 'paired', 'mismatch', 'unverifiable', 'off']) {
      expect(S.standaloneState({ state, pin: 'AAAA', managed: false })).toBe(state)
    }
  })
  it('the popup reads managed storage itself, shows a stored rollback over the calm states, and marks verify failures', () => {
    const js = read('popup.js')
    expect(js).toContain('readManaged(chrome.storage)')
    expect(js).not.toMatch(/send\(\{ type: 'agent.getEndpoint' \}\), 1500\)\.catch\(\(\) => null\),\n\s*\]\)/)
    expect(js).toContain('if (stored.rollback) probed.shorter = stored.rollback')
    expect(js).toContain("if (shorter && (state === 'unreachable' || state === 'away' || state === 'protecting'))")
    expect(js.indexOf('if (shorter && (state')).toBeLessThan(js.indexOf("if (state === 'protecting') {"))
    expect(js).toContain("return { state: 'unreachable', endpoint, verifyFailed: true }")
    expect(read('popup.html').indexOf('managed-settings.js')).toBeLessThan(read('popup.html').indexOf('popup.js'))
  })
  it('the popup wires it: protecting copy, the optional desktop line, no red alert', () => {
    const js = read('popup.js')
    const html = read('popup.html')
    expect(js).toContain("set('ok', 'on', 'Protecting this browser', week())")
    expect(js).toContain("\"Your Shield desktop app isn't answering\"")
    expect(html).toContain('Optional: the Shield desktop app adds a sealed record and covers apps outside the browser.')
    expect(html.indexOf('shield-stats.js')).toBeLessThan(html.indexOf('popup.js'))
  })
})

describe('welcome page', () => {
  const html = read('welcome.html')
  it('asks for nothing to be installed or run', () => {
    expect(html).not.toMatch(/You need Shield running/)
    expect(html).not.toMatch(/Start Shield with/)
    expect(html).toContain('Nothing to install')
    expect(html).toContain('Shield is on in this browser. Try it now.')
    expect(html).toContain('4242 4242 4242 4242')
    expect(html).toMatch(/Optional: the Shield desktop app/)
  })
  it('discloses the local counts', () => {
    expect(html).toMatch(/keeps counts in this browser/)
    expect(read('PRIVACY.md')).toContain('`local_counts`')
  })
})

describe('service worker', () => {
  function worker(initial = {}, managed = null) {
    let listener
    const local = { ...initial }
    const get = (keys) => {
      const ks = keys == null ? Object.keys(local) : [].concat(keys)
      return Object.fromEntries(ks.filter((k) => k in local).map((k) => [k, local[k]]))
    }
    const chrome = {
      runtime: { id: 'ext', onMessage: { addListener: (fn) => { listener ??= fn } }, onMessageExternal: { addListener() {} }, onInstalled: { addListener() {} },
        onStartup: { addListener() {} }, getURL: (p) => `chrome-extension://ext/${p}` },
      storage: {
        managed: { get: async () => { if (!managed) throw new Error('none'); return managed } },
        local: { get: async (keys, cb) => { await null; const v = get(keys); return cb ? cb(v) : v },
          set: (obj, cb) => { Object.assign(local, structuredClone(obj)); cb?.(); return Promise.resolve() },
          remove: async (keys) => { for (const k of [].concat(keys)) delete local[k] } },
        session: { get: async () => ({}), set: async () => {}, remove: async () => {} },
        onChanged: { addListener() {} },
      },
      alarms: { create() {}, clear() {}, onAlarm: { addListener() {} } },
      permissions: {},
      tabs: { create() {} },
      scripting: {}, action: { setBadgeText: (o) => badges.push(o.text), setBadgeBackgroundColor() {}, setTitle() {} },
    }
    const badges = []
    const ctx = { chrome, console, setTimeout: () => 0, clearTimeout() {}, URL, crypto: globalThis.crypto, fetch: async () => { throw new TypeError('offline') },
      importScripts: (...files) => files.forEach((f) => vm.runInContext(read(f), ctx)), atob, btoa, TextEncoder, Uint8Array }
    ctx.globalThis = ctx
    vm.createContext(ctx)
    vm.runInContext(read('background.js'), ctx)
    const page = { id: 'ext', url: 'chrome-extension://ext/popup.html' }
    const tab = (host) => ({ id: 'ext', url: `https://${host}/c/1`, tab: { id: 1, url: `https://${host}/c/1` } })
    const ask = (msg, sender = page) => new Promise((resolve) => listener(msg, sender, resolve))
    const settle = () => new Promise((r) => setImmediate(r))
    return { ask, tab, local, settle, ctx, badges }
  }
  const row = req({ flags: ['pii:email'], redactions: ['email'], verdict: 'redacted(1)' })

  it('counts nothing before consent', async () => {
    const w = worker()
    expect(await w.ask({ type: 'agent.capture', row }, w.tab('chatgpt.com'))).toEqual({ error: 'capture is off' })
    await w.settle()
    expect(w.local.local_counts).toBeUndefined()
  })
  it('counts with consent and no Shield answering, keeps no text, and turning capture off clears it', async () => {
    const w = worker({ consent: { version: 2, at: 1 } })
    await w.ask({ type: 'agent.capture', row: { ...row, text: 'mail jane@example.com' } }, w.tab('chatgpt.com'))
    await w.ask({ type: 'agent.capture', row }, w.tab('claude.ai'))
    for (let i = 0; i < 5; i++) await w.settle()
    const day = Object.values(w.local.local_counts.days)[0]
    expect(day.chatgpt).toMatchObject({ checked: 1, personal: 1, rules: { email: 1 } })
    expect(day.claude).toMatchObject({ checked: 1, personal: 1 })
    expect(JSON.stringify(w.local.local_counts)).not.toMatch(/jane|example|https?:/)
    expect(await w.ask({ type: 'agent.setConsent', granted: false })).toEqual({ ok: true })
    expect(w.local.local_counts).toBeUndefined()
  })
  it('does not count an app Shield is set not to check', async () => {
    const w = worker({ consent: { version: 2, at: 1 }, shield_policy: { mode: 'redact', apps: { chatgpt: false } } })
    await w.ask({ type: 'agent.capture', row }, w.tab('chatgpt.com'))
    for (let i = 0; i < 5; i++) await w.settle()
    expect(w.local.local_counts).toBeUndefined()
  })

  describe('badge when rows cannot be delivered', () => {
    const last = (w) => w.badges[w.badges.length - 1]
    const run = async (initial, managed) => {
      const w = worker({ consent: { version: 2, at: 1 }, ...initial }, managed)
      for (let i = 0; i < 5; i++) await w.settle()
      await w.ctx.setOfflineIfPaired()
      return last(w)
    }
    it('never set up: stays green', async () => { expect(await run({})).toBe('OK') })
    it('paired: offline', async () => { expect(await run({ pinned_shield: 'AAAA' })).toBe('-') })
    it('custom address, never paired: offline', async () => {
      expect(await run({ endpoint: 'http://127.0.0.1:9999/api/browser' })).toBe('-')
    })
    it('the old default address is not a choice: stays green', async () => {
      expect(await run({ endpoint: 'http://127.0.0.1:8300/api/browser' })).toBe('OK')
    })
    it('administrator port, never paired: offline', async () => {
      expect(await run({}, { shield_port: 18000 })).toBe('-')
    })
    it('a refusal set while the check reads storage is not overwritten', async () => {
      const w = worker({ pinned_shield: 'AAAA' })
      for (let i = 0; i < 5; i++) await w.settle()
      const pending = w.ctx.setOfflineIfPaired()
      w.ctx.setRefused('shorter')
      await pending
      expect(last(w)).toBe('!')
    })
  })
})
