// @vitest-environment node
/**
 * The input gate (content-relay.js, isolated world): what the user hands the
 * page (Enter, the send button, a form submit, a picked file, a drop, a paste)
 * is checked before any page handler runs. jsdom stands in for the page; the
 * "site" is a set of listeners registered after the relay, exactly where a
 * real app's would sit.
 */
import { describe, expect, it, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import { JSDOM, VirtualConsole } from 'jsdom'
import { fakeChannel } from './port.mjs'
import { REPO } from './env.mjs'

const EXT = path.join(REPO, 'src', 'byoai', 'browser_extension')
const read = (f) => readFileSync(path.join(EXT, f), 'utf8')
const AWS = 'AKIAIOSFODNN7EXAMPLE'
const EMAIL = 'ann@example.com'
const RULES = {
  secret: [['aws_access_key', '\\b(AKIA|ASIA)[0-9A-Z]{16}\\b', ''],
    ['private_key_block', '-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----', '']],
  pii: [['emails', '[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}', 'i']],
  flag: [], validators: {}, placeholder: { emails: 'EMAIL', aws_access_key: 'SECRET', private_key_block: 'SECRET' },
  rule_actions: {}, default_actions: { secret: 'block', pii: 'redact', flag: 'log' },
  covered_apps: ['claude', 'chatgpt'], rules_version: 'abc123def456',
}
const HTML = {
  'claude.ai': '<div id="c" contenteditable="true" aria-label="Write your prompt to Claude"></div>' +
    '<button id="send" aria-label="Send message"></button><input id="f" type="file">',
  'chatgpt.com': '<div id="prompt-textarea" contenteditable="true"></div>' +
    '<button id="send" data-testid="send-button"></button><input id="f" type="file">',
  'copilot.microsoft.com': '<form id="form"><textarea id="userInput"></textarea>' +
    '<button id="send" data-testid="submit-button" type="submit"></button></form>',
  'gemini.google.com': '<div id="c" contenteditable="true" role="textbox"></div>' +
    '<button id="send" aria-label="Send message"></button>',
}
const EDIT_BOX = '<textarea id="prefs"></textarea>'
const NO_BUTTON = '<div id="c" contenteditable="true" aria-label="Write your prompt to Claude"></div>'

function gate({ host = 'claude.ai', config = {}, html, consent = { version: 2 }, exec = 'ok' } = {}) {
  const dom = new JSDOM(`<!doctype html><body>${html ?? HTML[host]}</body>`, { url: `https://${host}/`, virtualConsole: new VirtualConsole() })
  const win = dom.window
  const w = { shadow: null, rows: [], toPage: [], seen: { keydown: 0, click: 0, submit: 0, change: 0, drop: 0, paste: 0 }, texts: [], fileCounts: [] }
  const attach = win.Element.prototype.attachShadow
  win.Element.prototype.attachShadow = function (init) { w.shadow = attach.call(this, { ...init, mode: 'open' }); return w.shadow }
  win.__shieldRules = RULES
  // jsdom has no execCommand; stand in for a browser's editing commands (a real editor takes these up).
  const box = () => win.document.querySelector('#c, #prompt-textarea, #userInput')
  if (exec !== 'none') {
    win.document.execCommand = (cmd, _ui, val) => {
      if (exec === 'false') return false
      const sel = win.getSelection()
      if (cmd === 'insertText') {
        if (sel.rangeCount && !sel.isCollapsed) { box().textContent = ''; sel.removeAllRanges() }
        box().textContent += val
      } else if (cmd === 'insertLineBreak') box().textContent += '\n'
      else if (cmd === 'delete') box().textContent = ''
      return true
    }
  }
  class DT {
    constructor() { this._f = []; this.types = []; this.items = { add: (f) => this._f.push(f) } }
    get files() { return this._f }
    setData() {}
    getData() { return '' }
  }
  win.DataTransfer = DT
  const policy = { mode: config.mode ?? 'redact', apps: null, actions: config.actions ?? null, files: config.files ?? null }
  const ctx = vm.createContext({ window: win, document: win.document, location: win.location, CustomEvent: win.CustomEvent,
    JSON, crypto, TextDecoder, TextEncoder, Uint8Array, ArrayBuffer,
    MessageChannel: function () { return fakeChannel() },
    setTimeout: (f, ms) => setTimeout(f, ms), clearTimeout: (t) => clearTimeout(t), Date: { now: () => Date.now() },
    chrome: { runtime: { lastError: undefined, sendMessage: (m, cb) => { if (m.type === 'agent.capture') w.rows.push(m.row); cb?.() } },
      storage: { local: { get: (_k, cb) => cb({ consent, shield_policy: policy }) }, onChanged: { addListener() {} } } } })
  win.postMessage = (_d, _o, transfer) => { w.port = transfer[0]; w.port.onmessage = (ev) => w.toPage.push(ev.data) }
  // The tests use a small rule set (as files.test.mjs does), so shield-rules.js is not loaded.
  for (const f of ['shield-sites.js', 'shield-core.js', 'consent.js', 'content-relay.js']) vm.runInContext(read(f), ctx)
  // The "site": listeners added after the relay's, where an app would put them.
  const doc = win.document
  const compose = doc.querySelector('#c, #prompt-textarea, #userInput')
  w.doc = doc
  const send = doc.querySelector('#send')
  const readBox = () => (compose.tagName === 'TEXTAREA' ? compose.value : compose.textContent)
  for (const t of ['keydown', 'click', 'submit', 'change', 'drop', 'paste']) {
    win.addEventListener(t, (ev) => {
      w.seen[t]++
      w.texts.push(readBox())
      if (t === 'submit') ev.preventDefault() // jsdom: no navigation
      const files = ev.target?.files ?? ev.dataTransfer?.files ?? ev.clipboardData?.files
      if (files) w.fileCounts.push(Array.from(files).map((f) => f.name))
    })
  }
  w.sent = 0
  send?.addEventListener('click', () => { w.sent++ })
  w.win = win
  w.compose = compose
  w.send = send
  w.type = (text) => { if (compose.tagName === 'TEXTAREA') compose.value = text; else compose.textContent = text }
  w.key = (init = {}, target = compose) => {
    const ev = new win.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true, ...init })
    target.dispatchEvent(ev)
    return ev
  }
  w.click = (type = 'click') => {
    const ev = new win.Event(type, { bubbles: true, cancelable: true })
    send.dispatchEvent(ev)
    return ev
  }
  w.noticeText = () => w.shadow?.textContent ?? ''
  w.buttons = () => Object.fromEntries([...(w.shadow?.querySelectorAll('button') ?? [])].map((b) => [b.textContent, b]))
  w.barUp = () => vi.waitFor(() => expect(w.shadow?.querySelector('button.main')).toBeTruthy())
  w.requests = () => w.rows.filter((r) => r.kind === 'browser.chat.request')
  w.attachments = () => w.rows.filter((r) => r.kind === 'browser.chat.attachment')
  return w
}

// A file input whose `files` a test can set and the gate can reassign, as a real one allows.
function fileInput(w, list) {
  const input = w.win.document.querySelector('#f')
  const state = { files: list }
  Object.defineProperty(input, 'files', { configurable: true, get: () => state.files, set: (v) => { state.files = Array.from(v) } })
  Object.defineProperty(input, 'value', { configurable: true, get: () => '', set: () => { state.files = [] } })
  return { input, state }
}
const file = (name, content) => new File([content], name, { type: 'text/plain' })
const pick = (input) => { input.dispatchEvent(new (input.ownerDocument.defaultView.Event)('change', { bubbles: true })) }
const dropOf = (w, files, kind = 'drop') => {
  const ev = new w.win.Event(kind, { bubbles: true, cancelable: true })
  Object.defineProperty(ev, kind === 'drop' ? 'dataTransfer' : 'clipboardData', { value: { files, types: ['Files'], getData: () => '' } })
  w.win.document.body.dispatchEvent(ev)
  return ev
}

describe('input gate: sending a message', () => {
  it('Enter with a key in it: stopped, the site never sees it, a notice says why', () => {
    const w = gate()
    w.compose.addEventListener('keydown', () => { w.seen.own = (w.seen.own ?? 0) + 1 })
    w.type(`my key is ${AWS}`)
    const ev = w.key()
    expect(ev.defaultPrevented).toBe(true)
    expect(w.seen.keydown).toBe(0)
    expect(w.seen.own ?? 0).toBe(0)
    expect(w.noticeText()).toContain('Shield stopped this message')
    expect(w.noticeText()).toContain('an AWS access key')
    expect(w.requests()).toMatchObject([{ stage: 'input', app: 'claude', verdict: 'blocked', flags: ['secret:aws_access_key'], chars: 30 }])
  })
  it('the send button, pointerdown then click: one decision, the site handler never runs', () => {
    const w = gate({ host: 'chatgpt.com' })
    w.send.addEventListener('click', () => { w.seen.own = (w.seen.own ?? 0) + 1 })
    w.type(`token ${AWS}`)
    expect(w.click('pointerdown').defaultPrevented).toBe(true)
    expect(w.click('click').defaultPrevented).toBe(true)
    expect(w.sent).toBe(0)
    expect(w.seen.own ?? 0).toBe(0)
    expect(w.requests()).toHaveLength(1)
    expect(w.shadow.querySelectorAll('.bar')).toHaveLength(1)
  })
  it('a form submit with a key is stopped', () => {
    const w = gate({ host: 'copilot.microsoft.com' })
    w.type(`k ${AWS}`)
    const ev = new w.win.Event('submit', { bubbles: true, cancelable: true })
    w.win.document.querySelector('#form').dispatchEvent(ev)
    expect(ev.defaultPrevented).toBe(true)
    expect(w.seen.submit).toBe(0)
    expect(w.requests()[0]).toMatchObject({ stage: 'input', verdict: 'blocked' })
  })
  it('Shift+Enter and an IME composition pass untouched', () => {
    const w = gate()
    w.type(`k ${AWS}`)
    expect(w.key({ shiftKey: true }).defaultPrevented).toBe(false)
    expect(w.key({ isComposing: true }).defaultPrevented).toBe(false)
    expect(w.key({ keyCode: 229 }).defaultPrevented).toBe(false)
    expect(w.seen.keydown).toBe(3)
    expect(w.rows).toEqual([])
  })
  it('an email is rewritten before the site handler reads the box (contenteditable)', () => {
    const w = gate()
    w.type(`mail ${EMAIL} now`)
    const ev = w.key()
    expect(ev.defaultPrevented).toBe(false)
    expect(w.seen.keydown).toBe(1)
    expect(w.texts).toEqual(['mail [EMAIL_1] now'])
    expect(w.requests()).toMatchObject([{ stage: 'input', verdict: 'redacted(1)', redactions: ['emails'] }])
  })
  it('a textarea is rewritten with the native setter and an input event', () => {
    const w = gate({ host: 'copilot.microsoft.com' })
    let inputs = 0
    w.compose.addEventListener('input', () => inputs++)
    w.type(`${EMAIL} and ${EMAIL}`)
    w.key()
    expect(w.compose.value).toBe('[EMAIL_1] and [EMAIL_1]')
    expect(inputs).toBe(1)
    expect(w.texts).toEqual(['[EMAIL_1] and [EMAIL_1]'])
  })
  it('gemini, which the network wrapper cannot rewrite, is covered by the gate', () => {
    const w = gate({ host: 'gemini.google.com' })
    w.type(`me ${EMAIL}`)
    w.key()
    expect(w.texts).toEqual(['me [EMAIL_1]'])
    expect(w.requests()[0]).toMatchObject({ app: 'gemini', stage: 'input' })
  })
  it('a clean message goes through, one row, and the page is told its gate id', () => {
    const w = gate()
    w.type('hello there')
    expect(w.key().defaultPrevented).toBe(false)
    expect(w.seen.keydown).toBe(1)
    const [row] = w.requests()
    expect(row).toMatchObject({ stage: 'input', verdict: 'redact', chars: 11, flags: [] })
    expect(w.toPage.filter((m) => m.t === 'gate')).toEqual([{ t: 'gate', gate_id: row.gate_id }])
  })
  it('an empty box, observe mode and no consent are left alone', () => {
    expect(gate().key().defaultPrevented).toBe(false)
    const obs = gate({ config: { mode: 'observe' } })
    obs.type(`k ${AWS}`)
    expect(obs.key().defaultPrevented).toBe(false)
    expect(obs.seen.keydown).toBe(1)
    const no = gate({ consent: null })
    no.type(`k ${AWS}`)
    expect(no.key().defaultPrevented).toBe(false)
    expect(no.rows).toEqual([])
  })
  it('a warn: the send waits, Send anyway re-dispatches once through the gate, and the token is spent', async () => {
    const w = gate({ config: { actions: { secret: 'warn' } } })
    w.type(`${AWS} ${EMAIL}`)
    expect(w.key().defaultPrevented).toBe(true)
    await w.barUp()
    expect(w.noticeText()).toContain('This message contains an AWS access key')
    expect(w.sent).toBe(0)
    w.buttons()['Send anyway'].click()
    await vi.waitFor(() => expect(w.sent).toBe(1))
    // the key stays (the user chose that), the redact-tier email does not
    expect(w.texts.at(-1)).toBe(`${AWS} [EMAIL_1]`)
    expect(w.requests().at(-1)).toMatchObject({ verdict: 'warned→sent', redactions: ['emails'] })
    // a second send is not waved through: it warns again
    w.type(`${AWS} again`)
    expect(w.key().defaultPrevented).toBe(true)
    await w.barUp()
    expect(w.seen.keydown).toBe(0)
  })
  it('a warn: Send redacted replaces both', async () => {
    const w = gate({ config: { actions: { secret: 'warn' } } })
    w.type(`${AWS} ${EMAIL}`)
    w.key()
    await w.barUp()
    w.buttons()['Send redacted'].click()
    await vi.waitFor(() => expect(w.sent).toBe(1))
    expect(w.texts.at(-1)).toBe('[SECRET_1] [EMAIL_1]')
    expect(w.requests().at(-1)).toMatchObject({ verdict: 'warned→redacted' })
  })
  it('a warn: Cancel sends nothing', async () => {
    const w = gate({ config: { actions: { secret: 'warn' } } })
    w.type(AWS)
    w.key()
    await w.barUp()
    w.buttons().Cancel.click()
    await vi.waitFor(() => expect(w.requests().at(-1)).toMatchObject({ verdict: 'warned→cancelled' }))
    expect(w.sent + w.seen.keydown).toBe(0)
  })
  it('a warn with no send button re-dispatches Enter, and it passes the gate once', async () => {
    const w = gate({ html: NO_BUTTON, config: { actions: { secret: 'warn' } } })
    w.type(AWS)
    w.key()
    await w.barUp()
    w.buttons()['Send anyway'].click()
    await vi.waitFor(() => expect(w.seen.keydown).toBe(1))
    expect(w.requests().at(-1)).toMatchObject({ verdict: 'warned→sent' })
  })
  it('no message text is in any event, row or port message', async () => {
    const w = gate({ config: { actions: { secret: 'warn' } } })
    w.type(`${AWS} ${EMAIL} secret plans`)
    w.key()
    await w.barUp()
    w.buttons()['Send redacted'].click()
    await vi.waitFor(() => expect(w.sent).toBe(1))
    const dump = JSON.stringify([w.rows, w.toPage])
    for (const s of [AWS, EMAIL, 'secret plans']) expect(dump).not.toContain(s)
  })
})

describe('input gate: files', () => {
  it('a picked file with a key is blocked: cleared, the site never sees the change, the row and notice say so', async () => {
    const w = gate()
    const { input, state } = fileInput(w, [file('keys.txt', `aws ${AWS}`)])
    input.addEventListener('change', () => { w.seen.own = (w.seen.own ?? 0) + 1 })
    pick(input)
    await vi.waitFor(() => expect(w.attachments()).toHaveLength(1))
    expect(state.files).toEqual([])
    expect(w.seen.change).toBe(0)
    expect(w.seen.own ?? 0).toBe(0)
    expect(w.attachments()[0]).toMatchObject({ stage: 'input', verdict: 'blocked', name: 'keys.txt', scanned: true, flags: ['secret:aws_access_key'] })
    expect(w.attachments()[0].sha256).toMatch(/^[0-9a-f]{64}$/)
    expect(w.noticeText()).toContain('keys.txt')
    expect(JSON.stringify(w.rows)).not.toContain(AWS)
  })
  it('a clean file is let through by a fresh change event, and the next pick is checked again', async () => {
    const w = gate()
    const { input } = fileInput(w, [file('ok.txt', 'hello')])
    pick(input)
    await vi.waitFor(() => expect(w.seen.change).toBe(1))
    expect(w.attachments()[0]).toMatchObject({ stage: 'input', verdict: 'allowed', name: 'ok.txt' })
    pick(input)
    await vi.waitFor(() => expect(w.attachments()).toHaveLength(2))
  })
  it('a warn on files: Remove file keeps only the clean ones', async () => {
    const w = gate({ config: { actions: { secret: 'warn' } } })
    const { input, state } = fileInput(w, [file('bad.txt', AWS), file('good.txt', 'hi')])
    pick(input)
    await w.barUp()
    expect(w.noticeText()).toContain('an AWS access key')
    w.buttons()['Remove file'].click()
    await vi.waitFor(() => expect(w.seen.change).toBe(1))
    expect(state.files.map((f) => f.name)).toEqual(['good.txt'])
    expect(w.fileCounts.at(-1)).toEqual(['good.txt'])
    expect(w.attachments().map((r) => r.verdict)).toEqual(['warned→removed', 'allowed'])
  })
  it('a warn on files: Upload anyway keeps them all, Cancel clears', async () => {
    const w = gate({ config: { actions: { secret: 'warn' } } })
    const a = fileInput(w, [file('bad.txt', AWS)])
    pick(a.input)
    await w.barUp()
    w.buttons()['Upload anyway'].click()
    await vi.waitFor(() => expect(w.seen.change).toBe(1))
    expect(a.state.files).toHaveLength(1)
    expect(w.attachments().at(-1)).toMatchObject({ verdict: 'warned→uploaded' })
    pick(a.input)
    await vi.waitFor(() => expect(w.buttons().Cancel).toBeTruthy())
    w.buttons().Cancel.click()
    await vi.waitFor(() => expect(a.state.files).toEqual([]))
    expect(w.seen.change).toBe(1)
  })
  it('a dropped file with a key is blocked; a clean one arrives in a re-dispatched drop', async () => {
    const w = gate()
    expect(dropOf(w, [file('k.txt', AWS)]).defaultPrevented).toBe(true)
    await vi.waitFor(() => expect(w.attachments()).toHaveLength(1))
    expect(w.seen.drop).toBe(0)
    expect(w.attachments()[0]).toMatchObject({ stage: 'input', verdict: 'blocked' })
    dropOf(w, [file('ok.txt', 'fine')])
    await vi.waitFor(() => expect(w.seen.drop).toBe(1))
    expect(w.fileCounts.at(-1)).toEqual(['ok.txt'])
  })
  it('a pasted file: Remove file re-dispatches the paste with only the clean file', async () => {
    const w = gate({ config: { actions: { secret: 'warn' } } })
    dropOf(w, [file('bad.txt', AWS), file('good.txt', 'x')], 'paste')
    await w.barUp()
    w.buttons()['Remove file'].click()
    await vi.waitFor(() => expect(w.seen.paste).toBe(1))
    expect(w.fileCounts.at(-1)).toEqual(['good.txt'])
  })
  it('a paste with no files is left alone', () => {
    const w = gate()
    expect(dropOf(w, [], 'paste').defaultPrevented).toBe(false)
    expect(w.seen.paste).toBe(1)
  })
})

describe('input gate: review findings', () => {
  it('Ctrl+Enter and Cmd+Enter are gated like Enter', () => {
    for (const mod of ['metaKey', 'ctrlKey']) {
      const w = gate({ host: 'chatgpt.com' })
      w.type(`key ${AWS}`)
      expect(w.key({ [mod]: true }).defaultPrevented).toBe(true)
      expect(w.seen.keydown).toBe(0)
      expect(w.requests()[0]).toMatchObject({ verdict: 'blocked', stage: 'input' })
    }
  })
  it('Enter in a textarea that is not the message box is not a send: no gate, no rows', () => {
    const w = gate({ html: HTML['claude.ai'] + EDIT_BOX })
    const t = w.win.document.querySelector('#prefs')
    t.value = `me ${EMAIL} ${AWS}`
    expect(w.key({}, t).defaultPrevented).toBe(false)
    expect(t.value).toBe(`me ${EMAIL} ${AWS}`)
    expect(w.rows).toEqual([])
    expect(w.noticeText()).toBe('')
  })
  it('the copilot profile has no bare "textarea" selector', () => {
    const sites = JSON.parse(read('sites.json')).sites
    for (const s of sites) expect(s.compose).not.toContain('textarea')
  })
  it('with two boxes, the send button checks the box beside it', () => {
    const w = gate({ host: 'chatgpt.com', config: { mode: 'block' },
      html: '<div id="prompt-textarea" contenteditable="true"></div><button id="send" data-testid="send-button"></button>' +
        '<div id="edit"><textarea id="e"></textarea><button id="esend" aria-label="Send">Send</button></div>' })
    const d = w.win.document
    d.querySelector('#e').value = `fix ${AWS}`
    let sent = 0
    d.querySelector('#esend').addEventListener('click', () => sent++)
    const ev = new w.win.MouseEvent('click', { bubbles: true, cancelable: true })
    d.querySelector('#esend').dispatchEvent(ev)
    expect(ev.defaultPrevented).toBe(true)
    expect(sent).toBe(0)
  })
  it('a blocked pointerdown also stops the click after it, even if the box changed', () => {
    const w = gate({ host: 'chatgpt.com' })
    w.type(`k ${AWS}`)
    expect(w.click('pointerdown').defaultPrevented).toBe(true)
    w.type('something harmless now')
    expect(w.click('click').defaultPrevented).toBe(true)
    expect(w.sent).toBe(0)
  })
  it('a contenteditable that will not take the rewrite stops the send, says so, and records no redaction', () => {
    for (const exec of ['none', 'false']) {
      const w = gate({ exec })
      w.type(`mail ${EMAIL}`)
      expect(w.key().defaultPrevented).toBe(true)
      expect(w.seen.keydown).toBe(0)
      expect(w.compose.textContent).toBe(`mail ${EMAIL}`) // no textContent fallback
      expect(w.noticeText()).toContain("This box wouldn't take the edit")
      expect(w.requests()).toMatchObject([{ verdict: 'blocked', reason: 'rewrite_failed', stage: 'input' }])
      expect(w.requests()[0].redactions).toBeUndefined()
    }
  })
  it('a stop offers Mask it: the box is masked, nothing is sent, and the next send passes', () => {
    const w = gate()
    w.type(`k ${AWS} and ${EMAIL}`)
    expect(w.key().defaultPrevented).toBe(true)
    w.buttons()['Mask it'].click()
    expect(w.compose.textContent).toBe('k [SECRET_1] and [EMAIL_1]')
    expect(w.noticeText()).toContain('Press send when you are ready')
    expect(w.sent).toBe(0)
    expect(w.key().defaultPrevented).toBe(false)
    expect(w.seen.keydown).toBe(1)
    expect(JSON.stringify(w.requests())).not.toContain(AWS)
  })
  it('when the box will not take the edit, Copy safe version puts the masked text on the clipboard', () => {
    const w = gate({ exec: 'false' })
    const copied = []
    Object.defineProperty(w.win.navigator, 'clipboard', { value: { writeText: (t) => copied.push(t) }, configurable: true })
    w.type(`k ${AWS}`)
    w.key()
    w.buttons()['Mask it'].click()
    w.buttons()['Copy safe version'].click()
    expect(copied).toEqual(['k [SECRET_1]'])
    expect(w.compose.textContent).toBe(`k ${AWS}`)
  })
  it('a warn whose rewrite fails stops too', async () => {
    const w = gate({ exec: 'false', config: { actions: { secret: 'warn' } } })
    w.type(`${AWS} ${EMAIL}`)
    w.key()
    await w.barUp()
    w.buttons()['Send redacted'].click()
    await vi.waitFor(() => expect(w.requests().at(-1)).toMatchObject({ verdict: 'blocked', reason: 'rewrite_failed' }))
    expect(w.sent).toBe(0)
  })
  it('a message box inside an open shadow root is found and gated', () => {
    const w = gate({ html: '<div id="host"></div><button id="send" aria-label="Send message"></button>' })
    const sr = w.win.document.querySelector('#host').attachShadow({ mode: 'open' })
    sr.innerHTML = '<div id="in" contenteditable="true" aria-label="Write your prompt to Claude"></div>'
    const box = sr.querySelector('#in')
    box.textContent = `k ${AWS}`
    const ev = new w.win.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true, composed: true })
    box.dispatchEvent(ev)
    expect(ev.defaultPrevented).toBe(true)
    expect(w.seen.keydown).toBe(0)
    expect(w.requests()[0]).toMatchObject({ verdict: 'blocked' })
  })
  it('a blocked Enter also stops its keypress and keyup, so a site that sends on keyup does not', () => {
    const w = gate()
    let sentOnKeyup = 0
    w.win.addEventListener('keyup', (ev) => { if (ev.key === 'Enter') sentOnKeyup++ })
    w.type(`k ${AWS}`)
    expect(w.key().defaultPrevented).toBe(true)
    const up = new w.win.KeyboardEvent('keyup', { key: 'Enter', bubbles: true, cancelable: true })
    w.compose.dispatchEvent(up)
    expect(up.defaultPrevented).toBe(true)
    expect(sentOnKeyup).toBe(0)
    // a later, unrelated keyup is not swallowed
    const later = new w.win.KeyboardEvent('keyup', { key: 'Enter', bubbles: true, cancelable: true })
    w.compose.dispatchEvent(later)
    expect(sentOnKeyup).toBe(1)
  })
  it('a repeated identical allowed send is recorded again; only the pointerdown-click pair is one send', () => {
    const w = gate({ host: 'chatgpt.com' })
    w.type('hello there')
    w.key()
    w.key()
    expect(w.requests()).toHaveLength(2)
    expect(w.requests()[0].gate_id).not.toBe(w.requests()[1].gate_id)
    const p = gate({ host: 'chatgpt.com' })
    p.type('hello there')
    p.click('pointerdown')
    p.click('click')
    expect(p.requests()).toHaveLength(1)
  })
  it('with no send button and an Enter the site ignores, the user is told to press send', async () => {
    const w = gate({ html: NO_BUTTON, config: { actions: { secret: 'warn' } } })
    w.type(AWS)
    w.key()
    await w.barUp()
    w.buttons()['Send anyway'].click()
    await vi.waitFor(() => expect(w.requests().at(-1)).toMatchObject({ verdict: 'blocked', reason: 'send_retry_needed' }), { timeout: 3000 })
    expect(w.noticeText()).toContain("Shield couldn't press send for you")
  })
})
