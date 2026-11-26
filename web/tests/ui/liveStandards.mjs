/**
 * Live UI pass for the Shield standard: drives every Shield screen and state in
 * a real Chrome at 1440, 768 and 390 pixels, light and dark, takes a screenshot
 * of each, and probes the rendered page for what a unit test cannot see.
 *
 *   cd web && npm run dev                       # one dev server, port 5174
 *   node tests/ui/liveStandards.mjs [filter]    # in another shell
 *
 * Needs puppeteer-core (a dev dependency) and a Chrome:
 *   CHROME_PATH   the browser (default: Chrome on macOS)
 *   BASE          the dev server (default http://localhost:5174)
 *   OUT           where screenshots and report.json go
 *   ONLY          comma list of scenario names to run
 *
 * The Shield window talks to `/shield-api/*`: this script answers those calls
 * itself (fixtures.mjs), so no Shield process has to run. The Shield server
 * console runs on the dev server's own mock service worker. The extension's
 * popup and welcome page are opened from the extension folder with `chrome.*`
 * stubbed, the way the vitest/jsdom tests stub it.
 *
 * Probes, per screen: sideways scroll, controls under the target size (44px
 * at 768 and 390, 32px at 1440), icons off the 12/16/20/24/32/48 scale, raw
 * ids and snake_case codes in text people read, text under WCAG AA contrast
 * (dark and light), console errors. A probe that fires is listed in
 * report.json and printed; the script exits 1 when any does.
 */
import puppeteer from 'puppeteer-core'
import { mkdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as F from './fixtures.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const REPO = path.resolve(HERE, '..', '..', '..')
const EXT = path.join(REPO, 'src', 'byoai', 'browser_extension')
const CHROME = process.env.CHROME_PATH ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const BASE = process.env.BASE ?? 'http://localhost:5174'
const OUT = process.env.OUT ?? path.join(HERE, 'shots')
const ONLY = (process.env.ONLY ?? process.argv[2] ?? '').split(',').filter(Boolean)
const WIDTHS = [[1440, 900], [768, 1024], [390, 844]]
const THEMES = ['light', 'dark']
const ADMIN_TOKEN = 'test-admin-token'
const TOKEN_KEY = 'byoai.shieldServer.adminToken'

mkdirSync(OUT, { recursive: true })

/* ------------------------------------------------------------ the answers */

const base = () => ({
  items: F.makeItems(), verify: F.VERIFY_OK, policy: F.POLICY, privacy: F.PRIVACY, coriqo: F.CORIQO_OFF, apps: F.APPS_INSTALLED,
})
/** What `/shield-api/<path>` answers for a scenario; `{status, body}` or a delay can override. */
function answer(state, url, method) {
  const p = url.pathname.replace('/shield-api', '')
  const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })
  if (state.fail?.some((f) => p.startsWith(f))) return json({ error: 'down' }, 503)
  if (method === 'POST' && p === '/policy') return json({ ...state.policy, ...JSON.parse(state.lastBody || '{}') })
  if (method === 'POST') return json({ error: 'This demo does not write.' }, 400)
  if (p === '/feed') return json(F.feed(state.items))
  if (p === '/verify') return json(state.verify)
  if (p === '/policy') return json(state.policy)
  if (p === '/privacy') return json(state.privacy)
  if (p === '/coriqo') return json(state.coriqo)
  if (p === '/apps') return json(state.apps)
  if (p.startsWith('/receipt/')) return json(F.RECEIPT_OK(p.split('/').pop()))
  return json({ error: 'not found' }, 404)
}

/* ---------------------------------------------------------- the scenarios */

const click = async (page, text, scope = 'button') => {
  const ok = await page.evaluate((t, sc) => {
    const el = [...document.querySelectorAll(sc)].find((b) => b.textContent.trim().startsWith(t) && !b.disabled)
    if (!el) return false
    el.click()
    return true
  }, text, scope)
  if (!ok) throw new Error(`no ${scope} "${text}"`)
  await settle(page)
}
const settle = (page, ms = 350) => new Promise((r) => setTimeout(r, ms))

const SHIELD = (tab, extra = '') => `/shield?tab=${tab}${extra}`
const scenarios = [
  // --- the Shield window
  { name: 'trust-default', url: SHIELD('trust') },
  { name: 'trust-empty', url: SHIELD('trust'), state: { items: [] } },
  { name: 'trust-all-clean', url: SHIELD('trust'), state: { items: F.makeItems(12, { allClean: true }) } },
  { name: 'trust-unreachable', url: SHIELD('trust'), state: { fail: ['/feed', '/verify', '/policy', '/privacy'] } },
  { name: 'trust-record-broken', url: SHIELD('trust'), state: { verify: F.VERIFY_BROKEN } },
  { name: 'trust-weaker-policy', url: SHIELD('trust'), state: { policy: F.POLICY_WEAK } },
  { name: 'trust-stale-text', url: SHIELD('trust'), state: { policy: F.POLICY_WEAK, privacy: F.PRIVACY_STALE } },
  { name: 'trust-filtered-none', url: SHIELD('trust'), after: async (p) => { await p.type('input[type=search]', 'zzzz'); await settle(p) } },
  { name: 'trust-row-sheet', url: SHIELD('trust'), after: async (p) => { await p.click('.shield-row'); await settle(p) } },
  { name: 'trust-file-sheet', url: SHIELD('trust'), after: async (p) => { await click(p, 'Show')?.catch?.(() => 0); await p.evaluate(() => [...document.querySelectorAll('.shield-row')].find((r) => r.textContent.includes('Uploaded a file'))?.click()); await settle(p) } },
  { name: 'ledger-default', url: SHIELD('ledger') },
  { name: 'ledger-empty', url: SHIELD('ledger'), state: { items: [] } },
  { name: 'ledger-record-broken', url: SHIELD('ledger'), state: { verify: F.VERIFY_BROKEN } },
  { name: 'ledger-unreachable', url: SHIELD('ledger'), state: { fail: ['/feed', '/verify'] } },
  { name: 'ledger-receipt-fails', url: SHIELD('ledger'), after: async (p) => {
    await p.type('textarea', JSON.stringify({ kind: 'byoai.receipt.v2', seal: 'abcd', payload: { a: 1 }, merkle: {} }))
    await click(p, 'Check receipt') } },
  { name: 'timeline-default', url: SHIELD('timeline') },
  { name: 'timeline-empty', url: SHIELD('timeline'), state: { items: [] } },
  { name: 'timeline-unreachable', url: SHIELD('timeline'), state: { fail: ['/feed'] } },
  { name: 'timeline-journey', url: SHIELD('timeline', '&focus=it-2') },
  { name: 'timeline-journey-gone', url: SHIELD('timeline', '&focus=nope') },
  { name: 'settings-default', url: SHIELD('settings') },
  { name: 'settings-managed', url: SHIELD('settings'), state: { policy: F.POLICY_MANAGED, privacy: F.PRIVACY_STALE } },
  { name: 'settings-coriqo-connected', url: SHIELD('settings'), state: { coriqo: F.CORIQO_ON } },
  { name: 'settings-coriqo-refused', url: SHIELD('settings'), state: { coriqo: F.CORIQO_BAD } },
  { name: 'settings-unreachable', url: SHIELD('settings'), state: { fail: ['/policy'] } },
  { name: 'settings-confirm-dialog', url: SHIELD('settings'), after: async (p) => {
    await p.evaluate(() => { const r = document.querySelector('input[type=radio][name=shield-mode]:not(:checked)'); r?.click() }); await settle(p) } },
  // --- the Shield server console (mock service worker)
  { name: 'server-token-prompt', url: '/console/acme/shield-server/devices', server: true, token: false },
  { name: 'server-devices', url: '/console/acme/shield-server/devices', server: true },
  { name: 'server-devices-revoke', url: '/console/acme/shield-server/devices', server: true, after: async (p) => { await click(p, 'Revoke') } },
  { name: 'server-policy', url: '/console/acme/shield-server/policy', server: true },
  { name: 'server-policy-stop', url: '/console/acme/shield-server/policy', server: true, after: async (p) => { await click(p, 'Stop managing') } },
  { name: 'server-enrol', url: '/console/acme/shield-server/enrol', server: true },
  { name: 'server-enrol-minted', url: '/console/acme/shield-server/enrol', server: true, after: async (p) => {
    await p.type('input[placeholder*="Alice"]', 'Front desk Mac'); await click(p, 'Mint token'); await settle(p, 600) } },
]

/* ------------------------------------------------------ the extension pages */

const POPUP_STATES = {
  'popup-on-claude': { consent: true, check: 'paired', verify: { tamper_evident: true, entries: 412, sealed_total: 412 }, host: 'claude.ai' },
  'popup-on-other-tab': { consent: true, check: 'ok', verify: { tamper_evident: true, entries: 1, sealed_total: 1 }, host: 'example.com' },
  'popup-capture-off': { consent: false, check: 'ok', host: 'claude.ai' },
  'popup-unreachable': { consent: true, check: 'unreachable', host: 'claude.ai' },
  'popup-wrong-program': { consent: true, check: 'mismatch', host: 'claude.ai' },
  'popup-too-old': { consent: true, check: 'unverifiable', host: 'claude.ai' },
  'popup-record-shorter': { consent: true, check: 'ok', verify: { tamper_evident: true, entries: 3, sealed_total: 3 }, shorter: { was: 9, now: 3 }, host: 'claude.ai' },
  'popup-record-failed': { consent: true, check: 'ok', verify: { tamper_evident: false, entries: 9, sealed_total: 9 }, host: 'claude.ai' },
  'popup-details-open': { consent: true, check: 'paired', verify: { tamper_evident: true, entries: 412, sealed_total: 412 }, host: 'claude.ai', open: true },
}

function chromeStub(cfg) {
  return `(() => {
    const cfg = ${JSON.stringify(cfg)}
    const reply = (msg) => {
      switch (msg.type) {
        case 'agent.getConsent': return { granted: cfg.consent }
        case 'agent.getEndpoint': return { endpoint: 'http://127.0.0.1:17831/api/browser' }
        case 'agent.checkServer': return { state: cfg.check, endpoint: 'http://127.0.0.1:17831/api/browser' }
        case 'agent.noteWitness': return cfg.shorter ? { shorter: cfg.shorter } : { shorter: null }
        case 'agent.setConsent': return { ok: true }
        default: return { ok: true }
      }
    }
    window.chrome = {
      runtime: {
        id: 'jbbongpiablbbmfflcaafjbeejeododc', lastError: undefined,
        getManifest: () => ({ version: '0.10.9' }), getURL: (f) => f,
        sendMessage: (msg, cb) => { const r = reply(msg); if (typeof cb === 'function') { setTimeout(() => cb(r), 0); return } return Promise.resolve(r) },
      },
      storage: { local: { get: async (k) => {
        const all = { consent: cfg.consent ? { version: globalThis.SHIELD_CONSENT_VERSION } : undefined,
          last_capture: cfg.host ? { [cfg.host]: Date.now() - 4 * 60000 } : {}, today: { day: new Date().toDateString(), n: 17 }, health_unmatched: {} }
        return typeof k === 'string' ? { [k]: all[k] } : all } } },
      tabs: { query: async () => [{ id: 1, url: 'https://' + (cfg.host || 'example.com') + '/chat/1' }],
        sendMessage: (id, m, o, cb) => cb({ gate: '' }), create() {} },
      permissions: { contains: async () => true, request: async () => true },
    }
  })()`
}

/* ------------------------------------------------------------------ probes */

const SCALE = [12, 16, 20, 24, 32, 48]
async function probe(page, { width, kind }) {
  return page.evaluate((width, kind, SCALE) => {
    const out = { hscroll: false, targets: [], icons: [], rawIds: [], lowContrast: [], tinyText: [] }
    out.hscroll = document.documentElement.scrollWidth > window.innerWidth + 1
    const visible = (el) => {
      const r = el.getBoundingClientRect(); const cs = getComputedStyle(el)
      return r.width > 0 && r.height > 0 && cs.visibility !== 'hidden' && cs.display !== 'none' && !el.closest('[hidden]') && !el.closest('.sr-only')
    }
    const scope = kind === 'console' ? document.querySelector('main.content') ?? document : document
    const dialogs = [...document.querySelectorAll('[role=dialog],[role=alertdialog]')]
    const roots = kind === 'console' ? [scope, ...dialogs] : [document]
    const min = kind === 'popup' ? 32 : width >= 960 ? 32 : 44
    const seen = new Set()
    for (const root of roots) {
      for (const el of root.querySelectorAll('button, input:not([type=hidden]), select, textarea, summary, a[href], [role=button]')) {
        if (seen.has(el) || !visible(el) || el.disabled) continue
        seen.add(el)
        if (el.tagName === 'A' && el.closest('p, li, dd, span, label') && !el.closest('nav')) continue // inline link in a sentence
        let r = el.getBoundingClientRect()
        const lab = el.closest('label')
        if (lab && (el.type === 'checkbox' || el.type === 'radio')) r = lab.getBoundingClientRect()
        if (r.height < min - 0.5 || (r.width < min - 0.5 && el.tagName !== 'INPUT')) {
          out.targets.push(`${el.tagName.toLowerCase()}${el.className ? '.' + String(el.className).split(' ')[0] : ''} "${(el.textContent || el.getAttribute('aria-label') || el.placeholder || '').trim().slice(0, 28)}" ${Math.round(r.width)}x${Math.round(r.height)}`)
        }
      }
    }
    for (const svg of document.querySelectorAll('svg')) {
      if (!visible(svg)) continue
      const r = svg.getBoundingClientRect()
      const w = Math.round(r.width * 2) / 2
      if (!SCALE.includes(w) || Math.abs(r.width - r.height) > 0.5) out.icons.push(`${svg.getAttribute('data-icon') ?? svg.getAttribute('data-seal') ?? 'svg'} ${w}x${Math.round(r.height)}`)
    }
    const clone = (kind === 'console' ? (document.querySelector('main.content') ?? document.body) : document.body).cloneNode(true)
    clone.querySelectorAll('.mono,.hash,.hash-chip,code,pre,input,textarea,option,select,kbd,script,style,.sr-only,details.sheet-raw').forEach((n) => n.remove())
    const text = clone.innerText ?? clone.textContent ?? ''
    const pats = [/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/, /\b[0-9a-f]{16,}\b/, /\b[a-z]{2,}_[a-z0-9_]{2,}\b/]
    for (const re of pats) for (const line of text.split('\n')) { const m = line.match(re); if (m) out.rawIds.push(m[0] + '  in  "' + line.trim().slice(0, 60) + '"') }
    // contrast of every text node, against the colour it actually sits on
    const parse = (c) => {
      let m = c.match(/^rgba?\(([^)]+)\)$/)
      if (m) { const p = m[1].split(/[ ,/]+/).filter(Boolean).map(Number); return [p[0], p[1], p[2], p[3] ?? 1] }
      m = c.match(/^color\(srgb ([^)]+)\)$/)
      if (m) { const p = m[1].split(/[ /]+/).filter(Boolean).map(Number); return [p[0] * 255, p[1] * 255, p[2] * 255, p[3] ?? 1] }
      return null
    }
    const over = (f, b) => [f[0] * f[3] + b[0] * (1 - f[3]), f[1] * f[3] + b[1] * (1 - f[3]), f[2] * f[3] + b[2] * (1 - f[3]), 1]
    const lum = ([r, g, b]) => { const f = (c) => { const s = c / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4 }; return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b) }
    const bgOf = (el) => {
      const chain = []
      for (let e = el; e; e = e.parentElement) { const c = parse(getComputedStyle(e).backgroundColor); if (c && c[3] > 0) chain.push(c); if (c && c[3] === 1) break }
      let bg = [255, 255, 255, 1]
      const body = parse(getComputedStyle(document.body).backgroundColor); if (body) bg = body[3] === 1 ? body : over(body, bg)
      for (const c of chain.reverse()) bg = over(c, bg)
      return bg
    }
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT)
    const done = new Set()
    for (let n = walker.nextNode(); n; n = walker.nextNode()) {
      const el = n.parentElement
      if (!el || done.has(el) || !n.textContent.trim() || !visible(el) || el.closest('script,style,[disabled],:disabled,[inert]')) continue
      if (kind === 'console' && el.closest('.rail, .topbar')) continue
      done.add(el)
      const cs = getComputedStyle(el)
      const fg = parse(cs.color); if (!fg) continue
      let a = Number(cs.opacity); for (let e = el.parentElement; e; e = e.parentElement) a *= Number(getComputedStyle(e).opacity)
      const bg = bgOf(el)
      const f = over([fg[0], fg[1], fg[2], fg[3] * a], bg)
      const [hi, lo] = [lum(f), lum(bg)].sort((x, y) => y - x)
      const ratio = (hi + 0.05) / (lo + 0.05)
      const size = parseFloat(cs.fontSize); const bold = Number(cs.fontWeight) >= 700
      const need = size >= 24 || (size >= 18.66 && bold) ? 3 : 4.5
      if (ratio < need) out.lowContrast.push(`${ratio.toFixed(2)}<${need} "${n.textContent.trim().slice(0, 30)}" <${el.tagName.toLowerCase()}.${String(el.className).split(' ')[0]}>`)
      if (size < 12 - 0.01) out.tinyText.push(`${size}px "${n.textContent.trim().slice(0, 24)}"`)
    }
    return out
  }, width, kind, SCALE)
}

/* ------------------------------------------------------------------- driver */

const report = []
const fails = []
const browser = await puppeteer.launch({ executablePath: CHROME, headless: 'new', args: ['--no-sandbox', '--allow-file-access-from-files'] })

async function run(scn, [width, height], theme, kind) {
  const page = await browser.newPage()
  const errors = []
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`))
  page.on('console', (m) => { if (m.type() === 'error' && !/favicon|Failed to load resource/.test(m.text())) errors.push(`console: ${m.text().slice(0, 140)}`) })
  await page.setViewport({ width, height, deviceScaleFactor: 1 })
  await page.emulateMediaFeatures([{ name: 'prefers-color-scheme', value: theme }, { name: 'prefers-reduced-motion', value: 'reduce' }])
  const state = { ...base(), ...(scn.state ?? {}) }
  if (kind === 'popup' || kind === 'welcome') {
    await page.evaluateOnNewDocument(chromeStub(scn.cfg ?? {}))
    await page.setRequestInterception(true)
    page.on('request', (req) => {
      const u = new URL(req.url())
      if (u.hostname === '127.0.0.1' && u.pathname === '/api/verify') return req.respond({ status: 200, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify(scn.cfg?.verify ?? {}) })
      if (u.hostname === '127.0.0.1' && u.pathname === '/api/policy') return req.respond({ status: 200, contentType: 'application/json', headers: { 'access-control-allow-origin': '*' }, body: JSON.stringify({ apps: { claude: true }, mode: 'redact' }) })
      return req.continue()
    })
    await page.goto(`file://${path.join(EXT, kind === 'popup' ? 'popup.html' : 'welcome.html')}`)
    await settle(page, 700)
    if (scn.cfg?.open) await page.evaluate(() => { document.querySelector('details').open = true })
    if (scn.after) await scn.after(page)
  } else {
    await page.setRequestInterception(true)
    page.on('request', (req) => {
      const u = new URL(req.url())
      if (u.pathname.startsWith('/shield-api/')) {
        state.lastBody = req.postData()
        const a = answer(state, u, req.method())
        return req.respond({ status: a.status, contentType: a.contentType, body: a.body, headers: { 'access-control-allow-origin': '*' } })
      }
      return req.continue()
    })
    if (scn.server) {
      await page.evaluateOnNewDocument((k, v, set) => { if (set) try { sessionStorage.setItem(k, v) } catch { /* private */ } }, TOKEN_KEY, ADMIN_TOKEN, scn.token !== false)
    }
    await page.goto(BASE + scn.url, { waitUntil: 'networkidle2' })
    await settle(page, scn.server ? 900 : 600)
    if (scn.after) { try { await scn.after(page) } catch (e) { errors.push(`script: ${e.message}`) } }
  }
  const file = path.join(OUT, `${scn.name}__${width}__${theme}.png`)
  await page.screenshot({ path: file, fullPage: true })
  const probes = await probe(page, { width, kind })
  const row = { name: scn.name, width, theme, file, errors, ...probes }
  report.push(row)
  const bad = [
    probes.hscroll && 'sideways scroll', probes.targets.length && `targets: ${probes.targets.join('; ')}`,
    probes.icons.length && `icons: ${probes.icons.join('; ')}`, probes.rawIds.length && `raw ids: ${probes.rawIds.join('; ')}`,
    probes.lowContrast.length && `contrast: ${probes.lowContrast.slice(0, 6).join('; ')}`, probes.tinyText.length && `text under 12px: ${probes.tinyText.join('; ')}`,
    errors.length && `errors: ${errors.join('; ')}`,
  ].filter(Boolean)
  if (bad.length) { fails.push(`${scn.name} @${width} ${theme}: ${bad.join(' | ')}`) }
  await page.close()
}

const todo = [
  ...scenarios.map((s) => ({ s, kind: s.server ? 'console' : 'window' })),
  ...Object.entries(POPUP_STATES).map(([name, cfg]) => ({ s: { name, cfg }, kind: 'popup' })),
  { s: { name: 'welcome-ask', cfg: {} }, kind: 'welcome' },
  { s: { name: 'welcome-on', cfg: {}, after: async (p) => { await p.click('#agree'); await settle(p) } }, kind: 'welcome' },
  { s: { name: 'welcome-off', cfg: {}, after: async (p) => { await p.click('#decline'); await settle(p) } }, kind: 'welcome' },
].filter(({ s }) => ONLY.length === 0 || ONLY.some((o) => s.name.includes(o)))

for (const { s, kind } of todo) {
  const sizes = kind === 'popup' ? [[344, 700]] : WIDTHS
  for (const size of sizes) for (const theme of THEMES) {
    try { await run(s, size, theme, kind) } catch (e) { fails.push(`${s.name} @${size[0]} ${theme}: RUN FAILED ${e.message}`) }
  }
}
await browser.close()
writeFileSync(path.join(OUT, 'report.json'), JSON.stringify(report, null, 1))
console.log(`${report.length} screens captured in ${OUT}`)
if (fails.length) { console.log(`\n${fails.length} findings:\n` + fails.join('\n')); process.exit(1) }
console.log('no findings')
