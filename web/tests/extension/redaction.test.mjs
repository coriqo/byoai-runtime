// @vitest-environment node
/**
 * The extension's page capture (content.js + the generated shield-rules.js),
 * run in a bare JavaScript context with a stand-in page: its own fetch, its
 * own event target. No browser needed, so this always runs.
 *
 * The cases come from tests/fixtures/shield_redaction_cases.json, which the
 * Python suite checks against the desktop proxy's rules too. Both passing is
 * what makes "Replace personal details" mean the same thing in the browser.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import vm from 'node:vm'
import { REPO, sleep } from './env.mjs'
import { connectPage } from './port.mjs'

const EXT = path.join(REPO, 'src', 'byoai', 'browser_extension')
const RULES_JS = readFileSync(path.join(EXT, 'shield-rules.js'), 'utf8')
const SITES_JS = readFileSync(path.join(EXT, 'shield-sites.js'), 'utf8')
const CORE_JS = readFileSync(path.join(EXT, 'shield-core.js'), 'utf8')
const CONTENT_JS = readFileSync(path.join(EXT, 'content.js'), 'utf8')
const { cases } = JSON.parse(readFileSync(path.join(REPO, 'tests', 'fixtures', 'shield_redaction_cases.json'), 'utf8'))

const SEND_PATH = { 'claude.ai': '/api/organizations/o/chat_conversations/c/completion', 'chatgpt.com': '/backend-api/conversation' }

/** A page on `host` with the capture loaded; `config` is what the relay would say. */
function page(host, config, reply = () => new Response('{}', { status: 200 })) {
  const target = new EventTarget()
  const sent = []
  const captured = []
  const window = {
    location: { host },
    addEventListener: target.addEventListener.bind(target),
    removeEventListener: target.removeEventListener.bind(target),
    dispatchEvent: target.dispatchEvent.bind(target),
    async fetch(input, init) {
      sent.push(input instanceof Request ? await input.text() : init?.body)
      return reply()
    },
  }
  window.addEventListener('shield-agent-capture', (ev) => captured.push(ev.detail))
  const ctx = vm.createContext({ window, location: window.location, CustomEvent, Request, Response, TextDecoder, crypto, FormData, Blob, setTimeout, clearTimeout, Date })
  vm.runInContext(RULES_JS, ctx)
  vm.runInContext(SITES_JS, ctx)
  vm.runInContext(CORE_JS, ctx)
  vm.runInContext(CONTENT_JS, ctx)
  // The relay hands over its port, then the config, as it does in the browser.
  const relay = config ? connectPage(window, Event, config) : null
  const send = (raw, init = {}) =>
    window.fetch(`https://${host}${SEND_PATH[host] ?? '/v1/messages'}`, { method: 'POST', body: raw, ...init })
  return { window, sent, captured, send, relay }
}

const agreed = (mode, apps = null) => ({ consented: true, mode, apps })

describe('page capture: the shared redaction cases', () => {
  for (const c of cases) {
    it(c.name, async () => {
      const host = c.name.startsWith('chatgpt') ? 'chatgpt.com' : 'claude.ai'
      const p = page(host, { ...agreed(c.mode), ...(c.actions ? { actions: c.actions } : {}) })
      const raw = c.raw ?? JSON.stringify(c.body)
      if (c.expect.warn_redacts) {
        // The extension shows a bar instead of redacting silently: answer it
        // "Send redacted" and check it sends what the proxy would.
        let asked = 0
        p.relay.onmessage = (ev) => {
          if (ev.data.t !== 'warn') return
          asked++
          p.relay.postMessage({ t: 'warn-result', send_id: ev.data.send_id, choice: 'redacted' })
        }
        await p.send(raw)
        expect(asked).toBe(1)
        expect(p.captured[0].verdict).toMatch(/^warned/)
        const out = JSON.parse(p.sent[0])
        for (const [k, v] of Object.entries(c.expect.warn_redacts)) expect(out[k]).toBe(v)
        return
      }
      const res = await p.send(raw)
      const [request] = p.captured
      expect(request.kind).toBe('browser.chat.request')
      expect(request.chars).toBe(c.expect.chars)
      expect(request.flags).toEqual(c.expect.flags)
      expect(request.verdict).toBe(c.expect.verdict)
      if (c.expect.blocked) {
        expect(p.sent).toEqual([])                     // never left the page
        expect(res.status).toBe(403)
        expect((await res.json()).error.message).toBe(`Stopped on this Mac: ${c.expect.blocked.join(', ')}`)
        expect(p.captured).toHaveLength(1)             // no status row for a send that never happened
        return
      }
      expect(request.redactions).toEqual(c.expect.redactions)
      if (c.expect.body === null) expect(p.sent).toEqual([raw])   // byte for byte
      else expect(JSON.parse(p.sent[0])).toEqual(c.expect.body)
      expect(p.captured[1]).toMatchObject({ kind: 'browser.chat.status', ok: true, status: 200 })
      // What goes to Shield never holds the message.
      expect(JSON.stringify(p.captured)).not.toMatch(/coriqo\.io|415-555|sk-abc|hunter2/)
    })
  }
})

describe('page capture: when it leaves a message alone', () => {
  const email = JSON.stringify({ prompt: 'mail ann@example.com' })

  it('changes nothing before the user agreed, and names no rules', async () => {
    const p = page('claude.ai', { consented: false, mode: 'redact' })
    await p.send(email)
    expect(p.sent).toEqual([email])
    expect(p.captured[0].flags).toBeUndefined()
  })

  it('changes nothing until the relay has spoken', async () => {
    const p = page('claude.ai', null)
    await p.send(email)
    expect(p.sent).toEqual([email])
  })

  it('leaves an app alone that Shield is set not to cover', async () => {
    const p = page('claude.ai', agreed('redact', { claude: false, chatgpt: true }))
    await p.send(email)
    expect(p.sent).toEqual([email])
    expect(p.captured[0]).toMatchObject({ flags: ['pii:emails'] })
    expect(p.captured[0].verdict).toBeUndefined()
  })

  it('redacts by default when no policy has been heard from Shield', async () => {
    const p = page('claude.ai', { consented: true })
    await p.send(email)
    expect(JSON.parse(p.sent[0]).prompt).toBe('mail [EMAIL_1]')
  })

  it('does not rewrite Gemini, whose sends it cannot read', async () => {
    const p = page('gemini.google.com', agreed('redact'))
    const raw = JSON.stringify({ prompt: 'mail ann@example.com' })
    await p.window.fetch('https://gemini.google.com/v1/messages', { method: 'POST', body: raw })
    expect(p.sent).toEqual([raw])
    expect(p.captured[0].verdict).toBeUndefined()
  })

  it('does not touch a read, or a path that is not a send', async () => {
    const p = page('claude.ai', agreed('redact'))
    await p.window.fetch('https://claude.ai/api/account', { method: 'POST', body: email })
    await p.window.fetch('https://claude.ai' + SEND_PATH['claude.ai'], { method: 'GET' })
    expect(p.sent).toEqual([email, undefined])
    expect(p.captured).toEqual([])
  })
})

describe('page capture: a send made with a Request object', () => {
  it('reads a copy of the body and rewrites it', async () => {
    const p = page('chatgpt.com', agreed('redact'))
    const body = JSON.stringify({ messages: [{ content: { parts: ['to ann@example.com'] } }] })
    await p.window.fetch(new Request('https://chatgpt.com/backend-api/conversation', { method: 'POST', body }))
    expect(JSON.parse(p.sent[0]).messages[0].content.parts[0]).toBe('to [EMAIL_1]')
    expect(p.captured[0]).toMatchObject({ chars: 18, redactions: ['emails'], verdict: 'redacted(1)' })
  })
})

describe('page capture: a FormData chat body', () => {
  // Was passed on unread; a page that retries a refused send as FormData
  // must not get past the rules.
  it('reads its text fields and redacts them in place', async () => {
    const p = page('claude.ai', agreed('redact'))
    const form = new FormData()
    form.set('prompt', 'mail ann@example.com')
    await p.window.fetch('https://claude.ai' + SEND_PATH['claude.ai'], { method: 'POST', body: form })
    expect(p.sent[0].get('prompt')).toBe('mail [EMAIL_1]')
    expect(p.captured[0]).toMatchObject({ kind: 'browser.chat.request', app: 'claude', redactions: ['emails'] })
  })
})

// The shapes ChatGPT streamed for "what is the weather in houston today?"
// (2026-09-28): whole messages as {o: "add", v: {message}} events, text cut.
const add = (message) => `data: ${JSON.stringify({ p: '', o: 'add', v: { message } })}\n\n`
const CHATGPT_SEARCH = [
  'event: delta_encoding\ndata: "v1"\n\n',
  add({ author: { role: 'user' }, recipient: 'all', content: { content_type: 'text', parts: ['what is the weather in houston today?'] } }),
  add({ author: { role: 'assistant' }, recipient: 'web', content: { content_type: 'text', parts: [''] } }),
  add({ author: { role: 'assistant' }, recipient: 'web.run', content: { content_type: 'text', parts: ['{"search_query":[{"q":"Houston weather today"}]}'] } }),
  add({ author: { role: 'tool', name: 'web.run' }, recipient: 'all', content: { content_type: 'text', parts: [''] },
    metadata: { search_result_groups: [{ domain: 'weather.gov' }, { domain: 'weather.com' }, { domain: 'weather.gov' }] } }),
  'data: {"o":"append","p":"/message/content/parts/0","v":"It is 91\\u00b0F and sunny in Houston."}\n\n',
  add({ author: { role: 'assistant' }, recipient: 'all', content: { content_type: 'text', parts: ['It is 91°F and sunny in Houston.'] } }),
  'data: [DONE]\n\n',
]
const streamOf = (events, split = 7) => () => {
  const bytes = new TextEncoder().encode(events.join(''))
  // Delivered in small chunks, so events are cut mid-line as on the wire.
  return new Response(new ReadableStream({
    start(c) { for (let i = 0; i < bytes.length; i += split) c.enqueue(bytes.slice(i, i + split)); c.close() },
  }), { status: 200, headers: { 'content-type': 'text/event-stream; charset=utf-8' } })
}
const settle = () => sleep(20)   // lets the copy of the stream finish being read

describe('page capture: which tools the AI ran for a reply', () => {
  it('names the tools and counts the sources, and keeps none of the reply', async () => {
    const p = page('chatgpt.com', agreed('redact'), streamOf(CHATGPT_SEARCH))
    const res = await p.send(JSON.stringify({ messages: [{ content: { parts: ['weather?'] } }] }))
    expect(await res.text()).toContain('sunny')          // the app still gets the whole reply
    await settle()
    const reply = p.captured.find((r) => r.kind === 'browser.chat.reply')
    expect(reply).toEqual({ kind: 'browser.chat.reply', app: 'chatgpt', send_id: p.captured[0].send_id, tools: ['web.run'], sources: 2, evidence_level: 'observed_requested' })
    expect(p.captured[0].send_id).toMatch(/^[0-9a-f-]{32,36}$/)
    expect(JSON.stringify(p.captured)).not.toMatch(/91°|sunny|Houston weather/)
  })

  it('files no reply row when no tool ran', async () => {
    const plain = [CHATGPT_SEARCH[0], CHATGPT_SEARCH[1], CHATGPT_SEARCH[6], CHATGPT_SEARCH[7]]
    const p = page('chatgpt.com', agreed('redact'), streamOf(plain))
    await (await p.send(JSON.stringify({ prompt: 'hi' }))).text()
    await settle()
    expect(p.captured.map((r) => r.kind)).toEqual(['browser.chat.request', 'browser.chat.status'])
  })

  it('reads nothing before the user agreed', async () => {
    const p = page('chatgpt.com', { consented: false, mode: 'redact' }, streamOf(CHATGPT_SEARCH))
    await (await p.send(JSON.stringify({ prompt: 'hi' }))).text()
    await settle()
    expect(p.captured.some((r) => r.kind === 'browser.chat.reply')).toBe(false)
  })

  it('reads an Anthropic-style tool block', async () => {
    const events = [
      'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"server_tool_use","name":"web_search","input":{}}}\n\n',
      'event: message_stop\ndata: {"type":"message_stop"}\n\n',
    ]
    const p = page('claude.ai', agreed('redact'), streamOf(events))
    await (await p.send(JSON.stringify({ prompt: 'hi' }))).text()
    await settle()
    expect(p.captured.find((r) => r.kind === 'browser.chat.reply')).toMatchObject({ tools: ['web_search'], sources: 0, evidence_level: 'observed_requested' })
  })
})
