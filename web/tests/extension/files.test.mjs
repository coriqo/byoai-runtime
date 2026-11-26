// @vitest-environment node
/**
 * File evidence in the extension: which requests are uploads, the decision
 * (allow, block, warn with all three choices and the timeout), the SHA-256,
 * text scanning, XHR uploads, and that no file content reaches an event.
 * Request shapes come from the anonymised live captures in
 * tests/fixtures/uploads/.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import { Blob as NodeBlob } from 'node:buffer'
import { JSDOM, VirtualConsole } from 'jsdom'
import { connectPage, fakeChannel, postPort } from './port.mjs'
import { REPO } from './env.mjs'

const EXT = path.join(REPO, 'src', 'byoai', 'browser_extension')
const read = (f) => readFileSync(path.join(EXT, f), 'utf8')
const SITES_JS = readFileSync(path.join(EXT, 'shield-sites.js'), 'utf8')
const CORE_JS = readFileSync(path.join(EXT, 'shield-core.js'), 'utf8')
const CONTENT_JS = read('content.js')
const RELAY_JS = read('content-relay.js')
const CONSENT_JS = read('consent.js')
const FIX = (f) => JSON.parse(readFileSync(path.join(REPO, 'tests', 'fixtures', 'uploads', f), 'utf8'))

// Real browsers have Blob.prototype.arrayBuffer; this jsdom's Blob does not.
if (!Blob.prototype.arrayBuffer) {
  Blob.prototype.arrayBuffer = function () {
    return new Promise((resolve, reject) => {
      const r = new FileReader()
      r.onload = () => resolve(r.result)
      r.onerror = () => reject(r.error)
      r.readAsArrayBuffer(this)
    })
  }
}

const textOf = async (f) => new TextDecoder().decode(await f.arrayBuffer())
// undici's FormData, for tests that build a real (node) Request: jsdom's would not be read by it.
const NODE_FORMDATA = (await new Response('a=1', { headers: { 'content-type': 'application/x-www-form-urlencoded' } }).formData()).constructor
const AWS = 'AKIAIOSFODNN7EXAMPLE'
const EMAIL = 'ann@example.com'
const HELLO_SHA = '5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03'
const VERSION = 'abc123def456'
const RULES = {
  secret: [['aws_access_key', '\\b(AKIA|ASIA)[0-9A-Z]{16}\\b', ''],
    ['private_key_block', '-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----', '']],
  pii: [['emails', '[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}', 'i']],
  flag: [['tool_intent', '\\bdeploy\\b', 'i']],
  validators: {}, placeholder: { emails: 'EMAIL', aws_access_key: 'SECRET', private_key_block: 'SECRET' }, rule_actions: {},
  default_actions: { secret: 'block', pii: 'redact', flag: 'log' }, covered_apps: ['claude', 'chatgpt'],
  rules_version: VERSION,
}
const CLAUDE_UPLOAD = '/api/organizations/o/conversations/c/wiggle/upload-file'
const GPT_PUT = 'https://files.oaiusercontent.com/files/f1/raw'

function world({ host = 'claude.ai', config = {}, relay = false, realRules = false, nodeForms = false, core = 'ok' } = {}) {
  const dom = new JSDOM('<!doctype html><body></body>', { url: `https://${host}/`, virtualConsole: new VirtualConsole() })
  const win = dom.window
  const sent = []
  const xhrSent = []
  const captured = []
  const w = { shadow: null }
  const attach = win.Element.prototype.attachShadow
  win.Element.prototype.attachShadow = function (init) { w.shadow = attach.call(this, { ...init, mode: 'open' }); return w.shadow }
  if (realRules) vm.runInContext(read('shield-rules.js'), vm.createContext({ window: win }))
  else win.__shieldRules = RULES
  const beacons = []
  win.navigator.sendBeacon = (u, d) => { beacons.push({ url: String(u), body: d }); return true }
  win.fetch = async (input, init) => {
    // A Request keeps its body inside; read it back from a clone so tests can see what went out.
    const body = init?.body ?? (input instanceof Request ? await input.clone().text() : null)
    sent.push({ url: String(input.url ?? input), body, request: input instanceof Request ? input : null })
    return new Response('{}')
  }
  const XP = win.XMLHttpRequest.prototype
  const realOpen = XP.open
  const realSend = XP.send
  const urls = new WeakMap()
  XP.open = function (_m, u) { urls.set(this, String(u)); return realOpen.apply(this, arguments) }
  // A request to a blob: address is how the extension makes a refused upload fail; let jsdom fail it for real.
  XP.send = function (b) { if (String(urls.get(this)).startsWith('blob:')) return realSend.apply(this, arguments); xhrSent.push(b) }
  win.addEventListener('shield-agent-capture', (ev) => captured.push(ev.detail))
  const policy = relay ? { mode: config.mode ?? 'redact', apps: null, actions: config.actions ?? null, files: config.files ?? null } : null
  const ctx = vm.createContext({ window: win, document: win.document, location: win.location, CustomEvent: win.CustomEvent,
    Request, Response, TextDecoder, TextEncoder, crypto, FormData: nodeForms ? NODE_FORMDATA : FormData, Blob, JSON, URL, ArrayBuffer, Uint8Array,
    XMLHttpRequest: win.XMLHttpRequest, TypeError, Request, URLSearchParams, ReadableStream,
    MessageChannel: function () { return fakeChannel() },
    setTimeout: (f, ms) => setTimeout(f, ms), clearTimeout: (t) => clearTimeout(t), Date: { now: () => Date.now() },
    chrome: { runtime: { lastError: undefined, sendMessage: (_m, cb) => cb?.() },
      storage: { local: { get: (_k, cb) => cb({ consent: { version: 2 }, shield_policy: policy }) }, onChanged: { addListener() {} } } } })
  win.postMessage = (data, _o, transfer) => postPort(win, win.Event, transfer[0], data)
  vm.runInContext(CONSENT_JS, ctx)
  vm.runInContext(SITES_JS, ctx)
  // 'tampered': the page got there first (it can't, in a top frame; this is the check that catches it).
  if (core === 'tampered') win.__shieldCore = { engine: () => ({ scan: () => [], assessFiles: async () => ({ facts: [], labels: [], top: 0, level: () => 0, flagsOf: () => [] }) }) }
  if (core !== 'missing') vm.runInContext(CORE_JS, ctx)
  vm.runInContext(CONTENT_JS, ctx)
  if (relay) vm.runInContext(RELAY_JS, ctx)
  else w.relay = connectPage(win, win.Event, { consented: true, mode: 'redact', apps: null, ...config })
  const post = (body, p = CLAUDE_UPLOAD) => win.fetch(`https://${host}${p}`, { method: 'POST', body })
  const rows = () => captured.filter((r) => r.kind === 'browser.chat.attachment')
  return { win, w, sent, xhrSent, captured, post, rows, beacons }
}
const uploadForm = (content, name = 'hello.txt', type = 'text/plain') => {
  const f = new FormData()
  f.set('file', new File([content], name, { type }))
  return f
}

let cur = null
const make = (o) => (cur = world(o))
const buttons = () => Object.fromEntries([...cur.w.shadow.querySelectorAll('button')].map((b) => [b.textContent, b]))
const barUp = () => vi.waitFor(() => expect(cur.w.shadow?.querySelector('button')).toBeTruthy())
const xhrPut = (win, body, url = GPT_PUT) => {
  const x = new win.XMLHttpRequest()
  const events = []
  for (const t of ['error', 'loadend']) x.addEventListener(t, () => events.push(t))
  x.onreadystatechange = () => { if (x.readyState === 4) events.push('rs4') }
  x.open('PUT', url)
  x.send(body)
  return { x, events }
}

beforeEach(() => { vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] }) })
afterEach(() => { vi.useRealTimers() })

describe('fixtures describe what the code recognises', () => {
  it('the live shapes are the ones under test', () => {
    expect(FIX('claude_ai.json').upload.path_pattern).toContain('wiggle/upload-file')
    expect(FIX('chatgpt.json').steps[1]).toMatchObject({ method: 'PUT', transport: 'XMLHttpRequest' })
  })
})

describe('what is an upload', () => {
  it('a claude FormData file: hashed, named only in the attachment row, and sent on', async () => {
    const w = make({})
    const form = uploadForm('hello\n')
    await w.post(form)
    expect(w.sent).toHaveLength(1)
    expect([...w.sent[0].body.entries()].map(([k, v]) => [k, v.name])).toEqual([['file', 'hello.txt']])
    expect(w.rows()).toEqual([{ kind: 'browser.chat.attachment', stage: 'network', app: 'claude', name: 'hello.txt', mime: 'text/plain',
      bytes: 6, sha256: HELLO_SHA, scanned: true, flags: [], rules_version: VERSION, verdict: 'allowed' }])
  })
  it('a FormData file on any path counts', async () => {
    const w = make({})
    await w.post(uploadForm('hello\n'), '/some/other/place')
    expect(w.rows()).toHaveLength(1)
  })
  it('a Blob to Datadog RUM is not an attachment, and neither is a string', async () => {
    const w = make({})
    await w.post(new Blob(['telemetry'], { type: 'text/plain' }), '/api/v2/rum')
    await w.post('telemetry', '/api/v2/rum')
    await w.post(new Blob(['x']), '/some/unknown/path')
    expect(w.rows()).toEqual([])
    expect(w.sent).toHaveLength(3)
  })
  it('a Blob body to the claude upload endpoint counts', async () => {
    const w = make({})
    await w.post(new Blob(['hello\n'], { type: 'text/plain' }))
    expect(w.rows()[0]).toMatchObject({ sha256: HELLO_SHA })
  })
  it('a FormData with only string entries (chatgpt realtime) is not an attachment', async () => {
    const w = make({ host: 'chatgpt.com' })
    const f = new FormData()
    f.set('sdp', 'v=0'); f.set('session', '{}')
    await w.post(f, '/realtime/wm')
    expect(w.rows()).toEqual([])
    expect(w.sent).toHaveLength(1)
  })
  it('a Blob to the chatgpt metadata endpoint is not an attachment', async () => {
    const w = make({ host: 'chatgpt.com' })
    await w.post(new Blob(['{}']), '/backend-api/files')
    expect(w.rows()).toEqual([])
  })
  it('a raw ArrayBuffer is copied: what is hashed is what is sent', async () => {
    const w = make({})
    const buf = new TextEncoder().encode('hello\n')
    const p = w.post(buf)
    buf.fill(0x41) // the page changes it after handing it over
    await p
    expect(w.rows()[0].sha256).toBe(HELLO_SHA)
    expect(new TextDecoder().decode(w.sent[0].body)).toBe('hello\n')
  })
  it('nothing is checked before the user agreed or when Shield is off for the app', async () => {
    const w = make({ config: { consented: false } })
    await w.post(uploadForm('hello\n'))
    expect(w.rows()).toEqual([])
    const off = make({ config: { apps: { claude: false } } })
    await off.post(uploadForm(AWS))
    expect(off.rows()).toEqual([])
    expect(off.sent).toHaveLength(1)
  })
})

describe('the decision', () => {
  it('block by file policy stops the upload with the shield refusal', async () => {
    const w = make({ config: { files: { claude: 'block' } } })
    const res = await w.post(uploadForm('hello\n'))
    expect(res.status).toBe(403)
    expect((await res.json()).error.type).toBe('coriqo_shield_blocked')
    expect(w.sent).toEqual([])
    expect(w.rows()[0]).toMatchObject({ verdict: 'blocked', sha256: HELLO_SHA })
  })
  it('a secret in a text file blocks by the rules, whatever the file policy', async () => {
    const w = make({})
    const res = await w.post(uploadForm(`key ${AWS}\n`, 'notes.txt'))
    expect(res.status).toBe(403)
    expect(w.rows()[0]).toMatchObject({ verdict: 'blocked', flags: ['secret:aws_access_key'], scanned: true })
  })
  it('a redact-tier hit counts as warn, so the upload is held', async () => {
    const w = make({ relay: true })
    const p = w.post(uploadForm(`mail ${EMAIL}\n`, 'c.csv'))
    await barUp()
    expect(Object.keys(buttons())).toEqual(['Remove file', 'Upload anyway', 'Cancel'])
    buttons().Cancel.click()
    expect((await p).status).toBe(403)
  })
  it('a UTF-16 text file is decoded and scanned', async () => {
    const w = make({})
    const u16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(`key ${AWS}`, 'utf16le')])
    const res = await w.post(uploadForm(u16, 'x.txt'))
    expect(res.status).toBe(403)
  })
  it('a renamed file that is not text-like is not read', async () => {
    const w = make({})
    await w.post(uploadForm(AWS, 'x.bin', 'application/octet-stream'))
    expect(w.rows()[0]).toMatchObject({ scanned: false, flags: [], verdict: 'allowed' })
  })
  it('observe mode records and lets everything go', async () => {
    const w = make({ config: { mode: 'observe', files: { claude: 'block' } } })
    await w.post(uploadForm(`key ${AWS}`))
    expect(w.sent).toHaveLength(1)
    expect(w.rows()[0]).toMatchObject({ verdict: 'allowed', flags: ['secret:aws_access_key'] })
  })
})

describe('warn (claude, FormData)', () => {
  const opts = { relay: true, config: { files: { claude: 'warn' }, actions: { secret: 'warn' } } }
  it('shows the file name and labels in the bar only; three choices', async () => {
    const w = make(opts)
    const p = w.post(uploadForm(`key ${AWS}`, 'payroll.txt'))
    await barUp()
    const text = cur.w.shadow.textContent
    expect(text).toContain('payroll.txt')
    expect(text).toContain('an AWS access key')
    expect(text).not.toContain(AWS)
    expect(Object.keys(buttons())).toEqual(['Remove file', 'Upload anyway', 'Cancel'])
    expect(w.sent).toEqual([])
    buttons().Cancel.click()
    await p
  })
  it('Upload anyway sends it', async () => {
    const w = make(opts)
    const p = w.post(uploadForm('hello\n'))
    await barUp()
    buttons()['Upload anyway'].click()
    await p
    expect(w.sent).toHaveLength(1)
    expect(w.rows()[0].verdict).toBe('warned→uploaded')
  })
  it('Remove file fails the request like a network error', async () => {
    const w = make(opts)
    const p = w.post(uploadForm('hello\n'))
    const seen = p.then(() => 'resolved', (e) => e)
    await barUp()
    buttons()['Remove file'].click()
    expect(await seen).toBeInstanceOf(TypeError)
    expect(w.sent).toEqual([])
    expect(w.rows()[0].verdict).toBe('warned→removed')
  })
  it('Cancel refuses', async () => {
    const w = make(opts)
    const p = w.post(uploadForm('hello\n'))
    await barUp()
    buttons().Cancel.click()
    expect((await p).status).toBe(403)
    expect(w.sent).toEqual([])
    expect(w.rows()[0].verdict).toBe('cancelled')
  })
  it('a timeout cancels', async () => {
    const w = make(opts)
    const p = w.post(uploadForm('hello\n'))
    await barUp()
    await vi.advanceTimersByTimeAsync(60_001)
    expect((await p).status).toBe(403)
    expect(w.sent).toEqual([])
    expect(w.rows()[0].verdict).toBe('cancelled')
  })
})

describe('chatgpt XHR PUT to the storage host', () => {
  const blob = () => new Blob(['hello\n'], { type: 'text/plain' })
  it('allow: sent, with a row', async () => {
    const w = make({ host: 'chatgpt.com' })
    const { events } = xhrPut(w.win, blob())
    await vi.waitFor(() => expect(w.xhrSent).toHaveLength(1))
    expect(events).toEqual([])
    expect(w.rows()[0]).toMatchObject({ app: 'chatgpt', sha256: HELLO_SHA, mime: 'text/plain', verdict: 'allowed', name: null })
  })
  it('block: never sent, ends with error then loadend, no throw', async () => {
    const w = make({ host: 'chatgpt.com', config: { files: { chatgpt: 'block' } } })
    const { events } = xhrPut(w.win, blob())
    await vi.waitFor(() => expect(events).toEqual(['rs4', 'error', 'loadend']))
    expect(w.xhrSent).toEqual([])
    expect(w.rows()[0].verdict).toBe('blocked')
  })
  it('warn: Upload anyway sends; Remove and Cancel fail it; timeout cancels', async () => {
    const opts = { host: 'chatgpt.com', relay: true, config: { files: { chatgpt: 'warn' } } }
    let w = make(opts)
    let r = xhrPut(w.win, blob())
    await barUp()
    buttons()['Upload anyway'].click()
    await vi.waitFor(() => expect(w.xhrSent).toHaveLength(1))
    expect(w.rows()[0].verdict).toBe('warned→uploaded')

    w = make(opts); r = xhrPut(w.win, blob())
    await barUp()
    buttons()['Remove file'].click()
    await vi.waitFor(() => expect(r.events).toEqual(['rs4', 'error', 'loadend']))
    expect(w.xhrSent).toEqual([])
    expect(w.rows()[0].verdict).toBe('warned→removed')

    w = make(opts); r = xhrPut(w.win, blob())
    await barUp()
    buttons().Cancel.click()
    await vi.waitFor(() => expect(r.events).toEqual(['rs4', 'error', 'loadend']))
    expect(w.rows()[0].verdict).toBe('cancelled')

    w = make(opts); r = xhrPut(w.win, blob())
    await barUp()
    await vi.advanceTimersByTimeAsync(60_001)
    await vi.waitFor(() => expect(r.events).toEqual(['rs4', 'error', 'loadend']))
    expect(w.xhrSent).toEqual([])
    expect(w.rows()[0].verdict).toBe('cancelled')
  })
  it('anything else through XHR is left alone', async () => {
    const w = make({ host: 'chatgpt.com', config: { files: { chatgpt: 'block' } } })
    for (const [m, u, b] of [['PUT', 'https://evil.example.com/files/f1/raw', new Blob(['x'])],
      ['PUT', 'https://evil-oaiusercontent.com/files/f1/raw', new Blob(['x'])],
      ['PUT', 'https://files.oaiusercontent.com/other', new Blob(['x'])],
      ['POST', GPT_PUT, new Blob(['x'])], ['POST', 'https://chatgpt.com/api/v2/rum', new Blob(['x'])]]) {
      const x = new w.win.XMLHttpRequest(); x.open(m, u); x.send(b)
    }
    expect(w.xhrSent).toHaveLength(5)
    expect(w.rows()).toEqual([])
  })
})

describe('the canary ignores what is not a send', () => {
  it('prepare, realtime, rum and uploads never raise unmatched', async () => {
    const w = make({ host: 'chatgpt.com' })
    for (let i = 0; i < 4; i++) {
      await w.post(null, '/backend-api/f/conversation/prepare')
      await w.post(null, '/realtime/wm')
      await w.post('x', '/api/v2/rum')
      await w.post(null, '/backend-api/files/process_upload_stream')
    }
    expect(w.captured.some((r) => r.kind === 'browser.health.unmatched')).toBe(false)
  })
  it('a real unknown chat path still does', async () => {
    const w = make({ host: 'chatgpt.com' })
    for (let i = 0; i < 3; i++) await w.post('{}', '/backend-api/new_chat_send')
    expect(w.captured.some((r) => r.kind === 'browser.health.unmatched')).toBe(true)
  })
})

describe('size, speed and privacy', () => {
  it('a 5 MB text file is hashed and scanned in reasonable time', async () => {
    const line = 'name,city,note about the quarter, nothing to see here at all\n'
    const text = line.repeat(Math.floor((5 * 1024 * 1024) / line.length))
    const w = make({})
    const t0 = Date.now()
    await w.post(uploadForm(text, 'big.csv'))
    expect(Date.now() - t0).toBeLessThan(10_000)
    expect(w.rows()[0]).toMatchObject({ scanned: true, flags: [] })
    expect(w.rows()[0].bytes).toBeLessThanOrEqual(5 * 1024 * 1024)
  })
  it('over 5 MB is hashed but not scanned', async () => {
    const w = make({})
    await w.post(uploadForm(`${AWS}\n` + 'a'.repeat(5 * 1024 * 1024), 'huge.txt'))
    expect(w.rows()[0]).toMatchObject({ scanned: false, flags: [], verdict: 'allowed' })
    expect(w.rows()[0].sha256).toMatch(/^[0-9a-f]{64}$/)
  })
  it('no file content in any event, on any path', async () => {
    const w = make({ relay: true, config: { files: { claude: 'warn' }, actions: { secret: 'warn' } } })
    const secret = `SECRETBODY ${AWS} ${EMAIL}`
    const p = w.post(uploadForm(secret, 'a.txt'))
    await barUp()
    expect(cur.w.shadow.textContent).not.toContain('SECRETBODY')
    buttons()['Upload anyway'].click()
    await p
    const p2 = w.post(uploadForm(secret, 'b.txt'), '/upload')
    await barUp()
    buttons()['Remove file'].click()
    await p2.catch(() => {})
    const dump = JSON.stringify(w.captured)
    for (const bit of ['SECRETBODY', AWS, EMAIL]) expect(dump).not.toContain(bit)
  })
})


// ---- review round 2: each repro is a test ---------------------------------

const CHAT = '/api/organizations/o/chat_conversations/c/completion'
const KEYS = JSON.parse(readFileSync(path.join(REPO, 'tests', 'fixtures', 'uploads', 'key_redaction_vectors.json'), 'utf8')).vectors
const expand = (t) => t.replace(/\{A(\d+)\}/g, (_m, n) => 'A'.repeat(Number(n)))
const T = `key=${AWS}\n`
const known = 'https://claude.ai' + CLAUDE_UPLOAD
const multipart = (content, name = 'k.txt', type = 'text/plain') =>
  `--BND1\r\nContent-Disposition: form-data; name="file"; filename="${name}"\r\nContent-Type: ${type}\r\n\r\n${content}\r\n--BND1--\r\n`
const mpRequest = (content) => new Request(known, { method: 'POST',
  headers: { 'content-type': 'multipart/form-data; boundary=BND1' }, body: multipart(content) })

describe('F1: a bare upload that reads as text is read, whatever its type', () => {
  for (const type of ['application/json', '', 'application/x-x509-ca-cert', 'application/x-yaml', 'application/octet-stream', 'application/x-pem-file']) {
    it(`GPT XHR PUT type ${JSON.stringify(type)}`, async () => {
      const w = make({ host: 'chatgpt.com' })
      const { events } = xhrPut(w.win, new Blob([T], { type }))
      await vi.waitFor(() => expect(events).toContain('loadend'))
      expect(w.rows()[0]).toMatchObject({ verdict: 'blocked', scanned: true, flags: ['secret:aws_access_key'] })
    })
  }
  it('a bare binary body is hashed, not read', async () => {
    const w = make({ host: 'chatgpt.com' })
    xhrPut(w.win, new Blob([new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0xff, 0xd8, 0xff, 0xfe])]))
    await vi.waitFor(() => expect(w.xhrSent).toHaveLength(1))
    expect(w.rows()[0]).toMatchObject({ scanned: false, verdict: 'allowed' })
  })
  it('a JSON or YAML type is text for a named FormData file too', async () => {
    const w = make({})
    expect((await w.post(uploadForm(T, 'blob', 'application/json'))).status).toBe(403)
    expect((await w.post(uploadForm(T, 'blob', 'application/x-yaml'))).status).toBe(403)
  })
})

describe('F2: the FormData that is checked is the one that is sent', () => {
  it('a file swapped in after fetch() was called is not what goes out', async () => {
    const w = make({})
    const f = uploadForm('hello\n', 'a.txt')
    const p = w.post(f)
    f.set('file', new File([T], 'a.txt', { type: 'text/plain' }))
    await p
    const body = w.sent[0].body
    expect(await textOf(body.get('file'))).toBe('hello\n')
    expect(w.rows()[0].sha256).toBe(HELLO_SHA)
  })
  it('the same over XHR', async () => {
    const w = make({ host: 'chatgpt.com' })
    const x = new w.win.XMLHttpRequest(); x.open('POST', 'https://claude.ai' + CLAUDE_UPLOAD)
    const f = uploadForm('hello\n', 'a.txt')
    x.send(f)
    f.set('file', new File([T], 'a.txt', { type: 'text/plain' }))
    await vi.waitFor(() => expect(w.xhrSent).toHaveLength(1))
    expect(await textOf(w.xhrSent[0].get('file'))).toBe('hello\n')
  })
})

describe('F3: fetch(Request)', () => {
  it('a multipart Request with a secret is stopped, and one without goes out intact', async () => {
    const w = make({ nodeForms: true })
    const res = await w.win.fetch(mpRequest(T.trim())) // undici can't parse a part ending in a newline
    expect(res.status).toBe(403)
    expect(w.sent).toEqual([])
    expect(w.rows()[0]).toMatchObject({ verdict: 'blocked', flags: ['secret:aws_access_key'] })
    const ok = make({ nodeForms: true })
    await ok.win.fetch(mpRequest('hello'))
    expect(ok.sent).toHaveLength(1)
    expect(ok.rows()[0].sha256).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
    expect(await ok.sent[0].request.headers.get('content-type')).toMatch(/multipart\/form-data/)
    expect(ok.sent[0].body).toContain('hello')
  })
  it('a Blob Request to a known endpoint is checked, and unreadable + block fails closed', async () => {
    const w = make({ host: 'chatgpt.com' })
    const res = await w.win.fetch(new Request(GPT_PUT, { method: 'PUT', body: new NodeBlob([T]) }))
    expect(res.status).toBe(403)
    const b = make({ config: { files: { claude: 'block' } } })
    const bad = { url: known, method: 'POST', headers: new Headers({ 'content-type': 'multipart/form-data; boundary=BND1' }),
      clone() { throw new Error('locked') } }
    Object.setPrototypeOf(bad, Request.prototype)
    expect((await b.win.fetch(bad)).status).toBe(403)
  })
})

describe('F4: other bodies on a known upload endpoint', () => {
  it('a string and URLSearchParams are read as bytes', async () => {
    const w = make({})
    expect((await w.win.fetch(known, { method: 'POST', body: T })).status).toBe(403)
    const u = await w.win.fetch(known, { method: 'POST', body: new URLSearchParams({ f: T }) })
    expect(u.status).toBe(403)
    expect(w.rows().map((r) => r.verdict)).toEqual(['blocked', 'blocked'])
  })
  it('a stream is recorded as not scanned and follows the file policy', async () => {
    const stream = () => new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(T)); c.close() } })
    const w = make({})
    await w.win.fetch(known, { method: 'POST', body: stream(), duplex: 'half' })
    expect(w.rows()[0]).toMatchObject({ scanned: false, verdict: 'allowed', sha256: null })
    const b = make({ config: { files: { claude: 'block' } } })
    const res = await b.win.fetch(known, { method: 'POST', body: stream(), duplex: 'half' })
    expect(res.status).toBe(403)
    expect(b.sent).toEqual([])
  })
  it('an XHR Document is read as its serialisation', async () => {
    const w = make({})
    const x = new w.win.XMLHttpRequest(); x.open('POST', known)
    const d = w.win.document.implementation.createHTMLDocument('')
    d.body.textContent = T
    x.send(d)
    await vi.waitFor(() => expect(w.rows()).toHaveLength(1))
    expect(w.rows()[0].verdict).toBe('blocked')
  })
  it('sendBeacon: a block policy answers false; a secret is not sent; a clean one is', async () => {
    const b = make({ config: { files: { claude: 'block' } } })
    expect(b.win.navigator.sendBeacon(known, uploadForm('hello\n'))).toBe(false)
    expect(b.beacons).toEqual([])
    const w = make({})
    expect(w.win.navigator.sendBeacon(known, uploadForm(T))).toBe(true)
    await vi.waitFor(() => expect(w.rows()).toHaveLength(1))
    expect(w.beacons).toEqual([])
    w.win.navigator.sendBeacon(known, uploadForm('hello\n'))
    await vi.waitFor(() => expect(w.beacons).toHaveLength(1))
    expect(await textOf(w.beacons[0].body.get('file'))).toBe('hello\n')
  })
  it('trailing slash and trailing-dot hosts are the same endpoints', async () => {
    const w = make({ host: 'chatgpt.com' })
    const { events } = xhrPut(w.win, new Blob([T]), 'https://files.oaiusercontent.com./files/f1/raw/')
    await vi.waitFor(() => expect(events).toContain('loadend'))
    expect(w.rows()[0].verdict).toBe('blocked')
  })
})

describe('F5: UTF-16 without a byte-order mark', () => {
  for (const [label, enc] of [['LE', (s) => Buffer.from(s, 'utf16le')], ['BE', (s) => Buffer.from(s, 'utf16le').swap16()]]) {
    it(label, async () => {
      const w = make({})
      const res = await w.post(uploadForm(enc(T), 'k.txt'))
      expect(res.status).toBe(403)
      expect(w.rows()[0].flags).toEqual(['secret:aws_access_key'])
    })
  }
})

describe('F6: XHR ends, and is held, like a real one', () => {
  it('a blocked upload ends in readyState 4, status 0, with readystatechange, error, loadend', async () => {
    const w = make({ host: 'chatgpt.com', config: { files: { chatgpt: 'block' } } })
    const x = new w.win.XMLHttpRequest()
    const ev = []
    x.onreadystatechange = () => ev.push('rsc' + x.readyState)
    for (const t of ['error', 'loadend', 'load', 'abort']) x.addEventListener(t, () => ev.push(t))
    x.open('PUT', GPT_PUT)
    x.send(new Blob(['hello\n']))
    await vi.waitFor(() => expect(ev).toContain('loadend'))
    expect(ev.filter((e) => e !== 'rsc1' && e !== 'rsc2')).toEqual(['rsc4', 'error', 'loadend'])
    expect([x.readyState, x.status]).toEqual([4, 0])
    expect(w.xhrSent).toEqual([])
  })
  it('a synchronous upload follows the file policy at once: allow sends, block and warn throw NetworkError', () => {
    const put = (files) => {
      const w = make({ host: 'chatgpt.com', config: { files: { chatgpt: files } } })
      const x = new w.win.XMLHttpRequest(); x.open('PUT', GPT_PUT, false)
      let err = null
      try { x.send(new Blob(['hello\n'])) } catch (e) { err = e }
      return { w, err }
    }
    const a = put('allow')
    expect(a.err).toBeNull()
    expect(a.w.xhrSent).toHaveLength(1)
    expect(a.w.rows()[0]).toMatchObject({ scanned: false, verdict: 'allowed', sha256: null, bytes: 6 })
    for (const p of ['block', 'warn']) {
      const r = put(p)
      expect(r.err.name).toBe('NetworkError')
      expect(r.w.xhrSent).toEqual([])
      expect(r.w.rows()[0].verdict).toBe('blocked')
    }
  })
  it('a second send while one is held throws InvalidStateError', async () => {
    const w = make({ host: 'chatgpt.com' })
    const x = new w.win.XMLHttpRequest(); x.open('PUT', GPT_PUT)
    x.send(new Blob(['hello\n']))
    let err = null
    try { x.send(new Blob(['again'])) } catch (e) { err = e }
    expect(err.name).toBe('InvalidStateError')
    await vi.waitFor(() => expect(w.xhrSent).toHaveLength(1))
  })
  it('a held body is never sent after the page aborts or opens the request again', async () => {
    const w = make({ host: 'chatgpt.com', relay: true, config: { files: { chatgpt: 'warn' } } })
    const x = new w.win.XMLHttpRequest(); x.open('PUT', GPT_PUT)
    x.send(new Blob(['secret body']))
    await barUp()
    x.abort()
    x.open('POST', 'https://chatgpt.com/other')
    x.send('clean')
    buttons()['Upload anyway'].click()
    await vi.advanceTimersByTimeAsync(50)
    expect(w.xhrSent).toEqual(['clean'])
  })
})

describe('F8: private keys', () => {
  it('redaction handles a header alone and a header with a body up to 8192 characters', async () => {
    for (const v of KEYS) {
      const w = make({ config: { actions: { secret: 'redact' } } })
      await w.post(JSON.stringify({ prompt: expand(v.in) }), CHAT)
      expect(JSON.parse(w.sent[0].body).prompt).toBe(expand(v.out))
    }
  })
  it('5 MB of repeated headers scans and redacts fast', async () => {
    const unit = '-----BEGIN PRIVATE KEY-----'
    const text = unit.repeat(Math.floor((5 * 1024 * 1024 - 64) / unit.length))
    const w = make({ realRules: true, config: { actions: { secret: 'log', pii: 'log', flag: 'log' } } })
    const t0 = performance.now()
    await w.post(uploadForm(text, 'a.txt'))
    expect(performance.now() - t0).toBeLessThan(500)
    expect(w.rows()[0].flags).toContain('secret:private_key_block')
    const r = make({ realRules: true, config: { actions: { secret: 'redact' } } })
    const t1 = performance.now()
    await r.post(JSON.stringify({ prompt: text }), CHAT)
    expect(performance.now() - t1).toBeLessThan(500)
    expect(JSON.parse(r.sent[0].body).prompt.includes('PRIVATE KEY')).toBe(false)
  })
})

// ---- review round 3 ---------------------------------------------------------

describe('Remove file drops only the flagged files', () => {
  const two = () => {
    const f = new FormData()
    f.append('a', new File(['hello\n'], 'clean.txt', { type: 'text/plain' }))
    f.append('note', 'keep me')
    f.append('b', new File([`use ${AWS}\n`], 'keys.txt', { type: 'text/plain' }))
    return f
  }
  const opts = { relay: true, config: { files: { claude: 'allow' }, actions: { secret: 'warn' } } }
  it('sends the clean file and the fields, with one verdict per file', async () => {
    const w = make(opts)
    const p = w.post(two())
    await barUp()
    buttons()['Remove file'].click()
    await p
    const sent = w.sent[0].body
    expect([...sent.keys()]).toEqual(['a', 'note'])
    expect(await textOf(sent.get('a'))).toBe('hello\n')
    expect(w.rows().map((r) => [r.name, r.verdict])).toEqual([['clean.txt', 'allowed'], ['keys.txt', 'warned→removed']])
  })
  it('Upload anyway sends both; the clean file stays allowed', async () => {
    const w = make(opts)
    const p = w.post(two())
    await barUp()
    buttons()['Upload anyway'].click()
    await p
    expect([...w.sent[0].body.keys()]).toEqual(['a', 'note', 'b'])
    expect(w.rows().map((r) => r.verdict)).toEqual(['allowed', 'warned→uploaded'])
  })
  it('when the file policy itself warns, every file is flagged and nothing remains: the upload fails', async () => {
    const w = make({ relay: true, config: { files: { claude: 'warn' }, actions: { secret: 'warn' } } })
    const p = w.post(two()).then(() => 'sent', (e) => e)
    await barUp()
    buttons()['Remove file'].click()
    expect(await p).toBeInstanceOf(TypeError)
    expect(w.sent).toEqual([])
    expect(w.rows().map((r) => r.verdict)).toEqual(['warned→removed', 'warned→removed'])
  })
})

describe('a file that cannot be read still leaves a row', () => {
  const broken = () => {
    const f = new FormData()
    const file = new File(['x'], 'a.txt', { type: 'text/plain' })
    file.arrayBuffer = async () => { throw new Error('unreadable') }
    f.append('file', file)
    return f
  }
  it('allow: goes, recorded as not scanned with no hash and flag:unreadable', async () => {
    const w = make({})
    await w.post(broken())
    expect(w.sent).toHaveLength(1)
    expect(w.rows()[0]).toMatchObject({ scanned: false, sha256: null, flags: ['flag:unreadable'], verdict: 'allowed', bytes: 1 })
  })
  it('block: stopped, and still recorded', async () => {
    const w = make({ config: { files: { claude: 'block' } } })
    expect((await w.post(broken())).status).toBe(403)
    expect(w.rows()[0]).toMatchObject({ sha256: null, flags: ['flag:unreadable'], verdict: 'blocked' })
  })
  it('warn: the bar says it could not be checked', async () => {
    const w = make({ relay: true, config: { files: { claude: 'warn' } } })
    const p = w.post(broken())
    await barUp()
    expect(cur.w.shadow.textContent).toContain("couldn't check")
    buttons()['Upload anyway'].click()
    await p
    expect(w.rows()[0]).toMatchObject({ flags: ['flag:unreadable'], verdict: 'warned→uploaded' })
  })
})

describe('the "not uploaded" notice', () => {
  const notice = () => cur.w.shadow?.querySelector('[role=status]')?.textContent ?? ''
  it('a blocked file says it was stopped and is not attached, without the matched text', async () => {
    make({ relay: true })
    await cur.post(uploadForm(`key ${AWS}\n`, 'notes.txt'))
    await vi.waitFor(() => expect(notice()).toContain('Shield stopped notes.txt'))
    expect(notice()).toContain('an AWS access key')
    expect(notice()).toContain("It wasn't uploaded")
    expect(notice()).not.toContain(AWS)
  })
  it('a cancelled file gets the notice; an allowed one does not', async () => {
    make({ relay: true, config: { files: { claude: 'warn' } } })
    const p = cur.post(uploadForm('hello\n', 'a.txt'))
    await barUp()
    buttons().Cancel.click()
    await p
    await vi.waitFor(() => expect(notice()).toContain('Shield cancelled a.txt'))
    make({ relay: true })
    await cur.post(uploadForm('hello\n', 'b.txt'))
    expect(notice()).toBe('')
  })
})

describe('same-origin frames get the same checks', () => {
  const CHAT = '/api/organizations/o/chat_conversations/c/completion'
  const body = JSON.stringify({ prompt: `is this valid aws_access_key_id=${AWS}` })
  it("a send through a hidden iframe's fetch is blocked like the page's own", async () => {
    make({})
    const f = cur.win.document.createElement('iframe')
    cur.win.document.body.append(f)
    const res = await f.contentWindow.fetch(`https://claude.ai${CHAT}`, { method: 'POST', body })
    expect(res.status).toBe(403)
    expect(cur.sent).toEqual([])
  })
  it('a frame reached through window.frames is armed too', async () => {
    make({})
    const f = cur.win.document.createElement('iframe')
    cur.win.document.body.append(f)
    await Promise.resolve() // the MutationObserver arms it on the next microtask
    const res = await cur.win.frames[0].fetch(`https://claude.ai${CHAT}`, { method: 'POST', body })
    expect(res.status).toBe(403)
    expect(cur.sent).toEqual([])
  })
  it('the frame is marked, so arming is done once', () => {
    make({})
    const f = cur.win.document.createElement('iframe')
    cur.win.document.body.append(f)
    expect(f.contentWindow.__shieldCapturePatched).toBe(true)
    expect(f.contentWindow.fetch).toBe(cur.win.fetch)
  })
})

describe('a blocked message says why', () => {
  it('shows "Shield stopped this message" with the rule label, never the key', async () => {
    make({ relay: true })
    const res = await cur.win.fetch('https://claude.ai/api/organizations/o/chat_conversations/c/completion',
      { method: 'POST', body: JSON.stringify({ prompt: `test key aws_access_key_id=${AWS}` }) })
    expect(res.status).toBe(403)
    const text = () => cur.w.shadow?.querySelector('[role=status]')?.textContent ?? ''
    await vi.waitFor(() => expect(text()).toContain('Shield stopped this message'))
    expect(text()).toContain('an AWS access key')
    expect(text()).not.toContain(AWS)
  })
})

describe('a retry with another body type is checked too', () => {
  const U = 'https://claude.ai/api/organizations/o/chat_conversations/c/completion'
  const msg = (t) => JSON.stringify({ prompt: t })
  const stream = (s) => new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(s)); c.close() } })
  it('a ReadableStream body with a key is read and blocked', async () => {
    make({})
    const res = await cur.win.fetch(U, { method: 'POST', body: stream(msg(`k ${AWS}`)), duplex: 'half' })
    expect(res.status).toBe(403)
    expect(cur.sent).toEqual([])
  })
  it('a clean stream body goes out as the text that was checked', async () => {
    make({})
    await cur.win.fetch(U, { method: 'POST', body: stream(msg('hello')), duplex: 'half' })
    expect(cur.sent[0].body).toBe(msg('hello'))
  })
  it('bytes and URLSearchParams are read too', async () => {
    make({})
    const r1 = await cur.win.fetch(U, { method: 'POST', body: new TextEncoder().encode(msg(`k ${AWS}`)) })
    expect(r1.status).toBe(403)
    expect(cur.sent).toEqual([])
  })
  it('a chat send over XHR with a key never goes out', () => {
    make({})
    const x = new cur.win.XMLHttpRequest()
    x.open('POST', U)
    x.send(msg(`k ${AWS}`))
    expect(cur.xhrSent).toEqual([])
  })
  it('a clean chat send over XHR is redacted and sent', () => {
    make({})
    const x = new cur.win.XMLHttpRequest()
    x.open('POST', U)
    x.send(msg(`mail ${EMAIL}`))
    expect(cur.xhrSent[0]).toContain('[EMAIL_1]')
  })
})

describe('FormData and unreadable chat bodies', () => {
  const U = 'https://claude.ai/api/organizations/o/chat_conversations/c/completion'
  it('a FormData chat body with a key is blocked', async () => {
    make({})
    const f = new FormData()
    f.set('prompt', `k ${AWS}`)
    const res = await cur.win.fetch(U, { method: 'POST', body: f })
    expect(res.status).toBe(403)
    expect(cur.sent).toEqual([])
  })
  it('a FormData chat body with an email goes out redacted, as FormData', async () => {
    make({})
    const f = new FormData()
    f.set('prompt', `mail ${EMAIL}`)
    await cur.win.fetch(U, { method: 'POST', body: f })
    const b = cur.sent[0].body
    expect(Object.prototype.toString.call(b)).toBe('[object FormData]')
    expect(b.get('prompt')).toContain('[EMAIL_1]')
  })
  it('a Blob that cannot be read is refused, not sent', async () => {
    make({})
    const blob = new Blob(['x'])
    blob.text = () => Promise.reject(new Error('nope'))
    const res = await cur.win.fetch(U, { method: 'POST', body: blob })
    expect(res.status).toBe(403)
    expect(cur.sent).toEqual([])
  })
  it('rows say they are network rows; a gate id goes on the first one after it, once', async () => {
    const w = make({})
    await w.post(uploadForm('hello\n'))
    w.w.relay.postMessage({ t: 'gate', gate_id: 'gate-1234abcd' })
    await w.post(uploadForm('again\n'))
    await w.post(uploadForm('third\n'))
    expect(w.rows().map((r) => [r.stage, r.gate_id])).toEqual([['network', undefined], ['network', 'gate-1234abcd'], ['network', undefined]])
  })
  for (const core of ['missing', 'tampered']) {
    it(`no trusted checker (${core}): a chat send and an upload are refused, and a health row says why`, async () => {
      const w = make({ core })
      expect(w.captured.filter((r) => r.kind === 'browser.health.core_missing')).toEqual([{ kind: 'browser.health.core_missing', app: 'claude' }])
      const res = await w.win.fetch('https://claude.ai/api/organizations/o/chat_conversations/c/completion',
        { method: 'POST', body: JSON.stringify({ prompt: 'hello there' }) })
      expect(res.status).toBe(403)
      const up = await w.post(uploadForm('hello\n'))
      expect(up.status).toBe(403)
      expect(w.sent).toEqual([])
    })
  }
  it('the build is visible to the page', () => {
    make({})
    expect(cur.win.__shieldVersion).toBe('0.10.7')
  })
})
