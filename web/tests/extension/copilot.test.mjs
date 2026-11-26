// @vitest-environment node
/**
 * Microsoft Copilot-shaped pages through the input gate (content-relay.js):
 * Enter, the send button and a form submit must turn an email into [EMAIL_1]
 * and leave data-shield-gate at "judged", whatever markup the page uses
 * (the old textarea, a contenteditable role=textbox with a "Submit" button,
 * a box inside an open shadow root). Fields that are not a message box
 * (search, rename dialogs) are never edited, and the popup's page check holds
 * no message text.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import { JSDOM, VirtualConsole } from 'jsdom'
import { fakeChannel } from './port.mjs'
import { REPO } from './env.mjs'

const EXT = path.join(REPO, 'src', 'byoai', 'browser_extension')
const read = (f) => readFileSync(path.join(EXT, f), 'utf8')
const EMAIL = 'ann@example.com'
const RULES = {
  secret: [], pii: [['emails', '[a-z0-9._%+-]+@[a-z0-9.-]+\\.[a-z]{2,}', 'i']], flag: [], validators: {},
  placeholder: { emails: 'EMAIL' }, rule_actions: {}, default_actions: { secret: 'block', pii: 'redact', flag: 'log' },
  covered_apps: ['copilot'], rules_version: 'abc123def456',
}

// Three ways Copilot has drawn its message box. The form wraps the box and the button.
const MARKUP = {
  textarea: (b) => `<form id="form"><textarea id="box" data-testid="composer-input"></textarea>${b}</form>`,
  editable: (b) => `<form id="form"><div id="box" contenteditable="true" role="textbox"></div>${b}</form>`,
  shadow: (b) => `<form id="form"><div id="host"></div>${b}</form>`,
}
const BUTTON = {
  testid: '<button id="send" type="button" data-testid="submit-button"></button>',
  word: '<button id="send" type="button">Submit</button>',
  aria: '<button id="send" type="button" aria-label="Submit message"></button>',
  ask: '<button id="send" type="button" aria-label="Ask Copilot"></button>',
}

function page({ host = 'copilot.cloud.microsoft', html, shadow = false, config = {}, consent = { version: 2 } }) {
  const dom = new JSDOM(`<!doctype html><body>${html}</body>`, { url: `https://${host}/`, virtualConsole: new VirtualConsole() })
  const win = dom.window
  const doc = win.document
  const w = { win, doc, rows: [], seen: [] }
  if (shadow) {
    const root = doc.querySelector('#host').attachShadow({ mode: 'open' })
    root.innerHTML = '<div id="box" contenteditable="true" role="textbox"></div>'
    w.box = root.querySelector('#box')
  } else w.box = doc.querySelector('#box')
  w.edit = (text) => { if (w.box.tagName === 'TEXTAREA') w.box.value = text; else w.box.textContent = text }
  w.text = () => (w.box.tagName === 'TEXTAREA' ? w.box.value : w.box.textContent)
  // jsdom has no editing commands; stand in for the browser's (a real editor takes these up).
  doc.execCommand = (cmd, _ui, val) => {
    if (cmd === 'insertText') w.box.textContent = (w.fresh ? '' : w.box.textContent) + val
    else if (cmd === 'delete') w.box.textContent = ''
    w.fresh = false
    return true
  }
  win.getSelection = () => ({ removeAllRanges() { w.fresh = true }, addRange() {} })
  win.__shieldRules = RULES
  const policy = { mode: config.mode ?? 'redact', apps: config.apps ?? null, actions: null, files: null }
  let onMessage = null
  const ctx = vm.createContext({ window: win, document: doc, location: win.location, CustomEvent: win.CustomEvent,
    JSON, crypto, TextDecoder, TextEncoder, Uint8Array, ArrayBuffer, MessageChannel: function () { return fakeChannel() },
    setTimeout: (f, ms) => setTimeout(f, ms), clearTimeout, Date,
    chrome: { runtime: { lastError: undefined, getManifest: () => ({ version: 'test' }),
      onMessage: { addListener: (f) => { onMessage = f } },
      sendMessage: (m, cb) => { if (m.type === 'agent.capture') w.rows.push(m.row); cb?.() } },
    storage: { local: { get: (_k, cb) => cb({ consent, shield_policy: policy }) }, onChanged: { addListener() {} } } } })
  win.postMessage = () => {}
  for (const f of ['shield-sites.js', 'shield-core.js', 'consent.js', 'content-relay.js']) vm.runInContext(read(f), ctx)
  // The "site": listeners after the relay's, reading the box the way the app would.
  win.addEventListener('keydown', () => w.seen.push(w.text()))
  win.addEventListener('click', () => w.seen.push(w.text()))
  win.addEventListener('submit', (ev) => { w.seen.push(w.text()); ev.preventDefault() })
  w.gate = () => doc.documentElement.getAttribute('data-shield-gate')
  w.check = () => { let out; onMessage({ type: 'shield.pageCheck' }, {}, (r) => { out = r }); return out }
  const enterIn = (el) => el.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true, composed: true }))
  w.enter = () => enterIn(w.box)
  w.enterIn = enterIn
  w.clickEl = (el) => el.dispatchEvent(new win.MouseEvent('click', { bubbles: true, cancelable: true, composed: true }))
  w.click = () => w.clickEl(doc.querySelector('#send'))
  w.submit = () => doc.querySelector('#form').dispatchEvent(new win.Event('submit', { bubbles: true, cancelable: true }))
  return w
}

const CASES = [
  { name: 'old textarea', markup: 'textarea', button: BUTTON.testid },
  { name: 'textarea, Submit word', markup: 'textarea', button: BUTTON.word },
  ...Object.entries(BUTTON).map(([k, button]) => ({ name: `contenteditable, ${k} button`, markup: 'editable', button })),
  { name: 'shadow-DOM box', markup: 'shadow', button: BUTTON.word },
]

describe('Copilot-shaped pages: an email typed is redacted before the page reads it', () => {
  for (const c of CASES) {
    for (const via of ['enter', 'click', 'submit']) {
      it(`${c.name}: ${via}`, () => {
        const w = page({ html: MARKUP[c.markup](c.button), shadow: c.markup === 'shadow' })
        w.edit(`mail ${EMAIL} now`)
        w[via]()
        expect(w.seen).toEqual(['mail [EMAIL_1] now'])
        expect(w.gate()).toBe('judged')
        expect(w.rows.filter((r) => r.kind === 'browser.chat.request')).toMatchObject([{ stage: 'input', verdict: 'redacted(1)' }])
      })
    }
  }
})

describe('fields that are not the message box', () => {
  const PLUS = (extra) => MARKUP.editable(BUTTON.word) + extra
  it('a search box is never edited and the gate says why', () => {
    const w = page({ html: PLUS('<div role="search"><textarea id="q" aria-label="Search chats"></textarea></div>') })
    const q = w.doc.querySelector('#q')
    q.value = `find ${EMAIL}`
    w.enterIn(q)
    expect(q.value).toBe(`find ${EMAIL}`)
    expect(w.gate()).toBe('skip:excluded:key')
  })
  it('a rename dialog is never edited, even with a submit button in it', () => {
    const w = page({ html: PLUS('<div role="dialog"><textarea id="q"></textarea><button id="ok" type="submit">Submit</button></div>') })
    const q = w.doc.querySelector('#q')
    q.value = `x ${EMAIL}`
    w.clickEl(w.doc.querySelector('#ok'))
    w.enterIn(q)
    expect(q.value).toBe(`x ${EMAIL}`)
    expect(w.rows).toEqual([])
  })
  it('an unrelated second textarea is left alone but recorded', () => {
    const w = page({ html: PLUS('<textarea id="q"></textarea>') })
    const q = w.doc.querySelector('#q')
    q.value = `x ${EMAIL}`
    w.enterIn(q)
    expect(q.value).toBe(`x ${EMAIL}`)
    expect(w.gate()).toBe('skip:no-compose:key')
  })
})

describe('the box is unrecognised on a covered host', () => {
  it('the only editable field on the page is treated as the message box (fails closed)', () => {
    const w = page({ html: '<div id="box" contenteditable="true"></div>' })
    w.edit(`me ${EMAIL}`)
    w.enter()
    expect(w.seen).toEqual(['me [EMAIL_1]'])
    expect(w.gate()).toBe('judged')
  })
})

describe('never silent: reasons and the page check', () => {
  it('capture off says so', () => {
    const w = page({ html: MARKUP.textarea(BUTTON.testid), consent: null })
    w.edit(`me ${EMAIL}`)
    w.enter()
    expect(w.seen).toEqual([`me ${EMAIL}`])
    expect(w.gate()).toBe('skip:not-governing:nc:all')
  })
  it('the app switched off says so', () => {
    const w = page({ html: MARKUP.textarea(BUTTON.testid), config: { apps: { copilot: false } } })
    w.edit(`me ${EMAIL}`)
    w.enter()
    expect(w.gate()).toBe('skip:not-governing:c:off')
  })
  it('the page check lists controls and holds no message text', () => {
    const w = page({ html: MARKUP.editable(BUTTON.word) })
    w.edit(`secret plan for ${EMAIL}`)
    w.enter()
    const out = w.check()
    expect(out.error).toBeUndefined()
    const json = JSON.stringify(out)
    expect(json).not.toContain(EMAIL)
    expect(json).not.toContain('secret plan')
    expect(out).toMatchObject({ host: 'copilot.cloud.microsoft', version: 'test', gate: 'judged', app: 'copilot', found_by: 'generic' })
    expect(out.buttons[0]).toMatchObject({ tag: 'button', type: 'button' })
    expect(out.compose_selectors['textarea#userInput']).toBe(0)
  })
})
