/**
 * Real-browser test for sign-in and linking: the extension signs in with OAuth
 * (PKCE) against a stub of Coriqo, asks it for a one-time enrolment token for
 * this device, and hands that to a real Shield, which enrols on /v1/enroll.
 * Coriqo's side is a stub here; the real one is private.
 */
import { describe, expect, it, afterAll } from 'vitest'
import puppeteer from 'puppeteer-core'
import { spawn } from 'node:child_process'
import { existsSync, readFileSync, mkdtempSync } from 'node:fs'
import http from 'node:http'
import { createHash } from 'node:crypto'
import { REPO, chromiumPath, pythonPath, skipReason, until, waitForServer } from './env.mjs'
import path from 'node:path'
import os from 'node:os'

const EXT = path.join(REPO, 'src', 'byoai', 'browser_extension')
const EXT_ID = 'jbbongpiablbbmfflcaafjbeejeododc'
const PORT = 18800 + Math.floor(Math.random() * 300)
const SKIP = skipReason()
if (SKIP) console.warn(`[ext-test] link: skipped — ${SKIP}`)

let shield, coriqo, browser

function stubCoriqo(seen, clients) {
  const challenges = new Map()
  const keys = []
  const minted = new Map()
  return http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x')
    let raw = ''
    req.on('data', (c) => (raw += c))
    req.on('end', () => {
      seen.push(`${req.method} ${url.pathname}`)
      const json = (code, body) => { res.writeHead(code, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)) }
      if (req.method === 'GET' && url.pathname === '/oauth/authorize') {
        if (url.searchParams.get('scope') !== 'devices:link') return json(400, { error: 'invalid_scope' })
        clients.push(url.searchParams.get('client_id'))
        const code = 'c' + challenges.size
        challenges.set(code, url.searchParams.get('code_challenge'))
        const back = new URL(url.searchParams.get('redirect_uri'))
        back.searchParams.set('code', code)
        back.searchParams.set('state', url.searchParams.get('state'))
        res.writeHead(302, { location: back.toString() }); return res.end()
      }
      if (url.pathname === '/oauth/token') {
        const f = new URLSearchParams(raw)
        const want = challenges.get(f.get('code'))
        const got = createHash('sha256').update(f.get('code_verifier') || '').digest('base64url')
        if (!want || want !== got) return json(400, { error: 'invalid_grant' })
        return json(200, { access_token: 'at_1', token_type: 'Bearer', expires_in: 600 })
      }
      if (url.pathname === '/oauth/userinfo') {
        if (req.headers.authorization !== 'Bearer at_1') return json(401, {})
        return json(200, { sub: 'u1', email: 'a@b.test', tenants: ['coriqo_msp_usa', 'coriqo_msp_uk'] })
      }
      if (url.pathname === '/v1/enroll/self') {
        if (req.headers.authorization !== 'Bearer at_1') return json(401, {})
        const b = JSON.parse(raw)
        if (!keys.includes(b.device_public_key)) {
          if (keys.length >= 1) return json(402, { error: 'device_limit_reached', limit: 1, count: keys.length, upgrade_url: 'https://billing.test/add' })
          keys.push(b.device_public_key)
        }
        const tok = `cik_live_coriqo_msp_usa.${minted.size}`
        minted.set(tok, b.device_public_key)
        return json(200, { token: tok, device_index: keys.indexOf(b.device_public_key) + 1, device_limit: 1, billing_state: 'included' })
      }
      if (url.pathname === '/v1/enroll') {
        const b = JSON.parse(raw)
        if (minted.get(b.token) !== b.public_key) return json(404, { detail: 'invalid' })
        minted.delete(b.token)
        return json(200, { device_id: 'dev_1', tenant_slug: 'coriqo_msp_usa' })
      }
      json(404, {})
    })
  })
}

describe.skipIf(SKIP)('extension sign-in and link (real browser)', () => {
  afterAll(async () => {
    await browser?.close?.()
    shield?.kill?.()
    coriqo?.close()
  })

  it('signs in with OAuth and links this computer to a stub Coriqo', { timeout: 120_000 }, async () => {
    const seen = []
    const clients = []
    coriqo = stubCoriqo(seen, clients)
    await new Promise((r) => coriqo.listen(0, '127.0.0.1', r))
    const base = `http://127.0.0.1:${coriqo.address().port}`

    const dataDir = mkdtempSync(path.join(os.tmpdir(), 'link-data-'))
    const ledger = path.join(dataDir, 'captures.jsonl')
    shield = spawn(pythonPath(), ['-m', 'byoai.integrations.shield', ledger, '--port', String(PORT)], {
      cwd: REPO, stdio: 'ignore',
      // HOME is the scratch dir, so the device key and enrolment never touch the real ~/.byoai/shield
      env: { ...process.env, HOME: dataDir, BYOAI_CORIQO_LINK_HOSTS: `127.0.0.1:${coriqo.address().port}` },
    })
    await waitForServer(PORT)

    browser = await puppeteer.launch({
      executablePath: chromiumPath(), headless: false,
      args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`,
        '--user-data-dir=' + path.join(os.tmpdir(), `link-profile-${Date.now()}`), '--no-first-run'],
    })
    const worker = await (await browser.waitForTarget((t) => t.type() === 'service_worker', { timeout: 15_000 })).worker()
    await worker.evaluate((p, b) => chrome.storage.local.set({
      endpoint: `http://127.0.0.1:${p}/api/browser`, coriqo_api_base: b,
      coriqo_client_id: 'https://coriqo.test/shield-client.json' }), PORT, base)

    // Pair with the Shield first (first contact pins its key), as a user does by opening the popup.
    const popup = await browser.newPage()
    await popup.goto(`chrome-extension://${EXT_ID}/popup.html`)
    await popup.waitForFunction(() => document.getElementById('state-title').textContent !== 'Checking Shield', { timeout: 10_000 })

    // The way in: a fresh install offers sign-in on the welcome page and in the popup, on a click.
    const opensLogin = async (from, selector) => {
      const before = (await browser.pages()).filter((p) => p.url().endsWith('/login.html')).length
      await from.bringToFront() // clicks do not reach a background tab
      from.click(selector).catch(() => {}) // the popup closes itself after opening the page, so the click may never settle
      await until(async () => (await browser.pages()).filter((p) => p.url().endsWith('/login.html')).length > before,
        10_000, 'the sign-in page to open').catch(async (e) => { throw new Error(`${e.message} after clicking ${selector}; pages: ${(await browser.pages()).map((p) => p.url()).join(' | ')}`) })
    }
    const welcome = await browser.newPage()
    await welcome.goto(`chrome-extension://${EXT_ID}/welcome.html`)
    await opensLogin(welcome, '#connect-coriqo')
    await welcome.close()
    expect(await popup.$eval('#coriqo-line', (n) => n.textContent)).toMatch(/Optional: link this computer/)
    await opensLogin(popup, '#connect-coriqo')

    // A saved client id that is not valid must say so, not hang the sign-in.
    const bad = await browser.newPage()
    await worker.evaluate(() => chrome.storage.local.set({ coriqo_client_id: 'not valid' }))
    await bad.goto(`chrome-extension://${EXT_ID}/login.html`)
    await bad.click('#oauth-start')
    await bad.waitForFunction(() => /client id is not valid/.test(document.getElementById('request-msg').textContent), { timeout: 10_000 })
    expect(await bad.$eval('#oauth-start', (b) => b.disabled)).toBe(false)
    await bad.close()
    await worker.evaluate(() => chrome.storage.local.set({ coriqo_client_id: 'https://coriqo.test/shield-client.json' }))

    const page = await browser.newPage()
    await page.emulateTimezone('America/New_York') // the region guess reads the time zone; pin it so the test is the same everywhere
    await page.goto(`chrome-extension://${EXT_ID}/login.html`)
    await page.click('#oauth-start')
    await page.waitForFunction(() => document.getElementById('step-done').classList.contains('active'), { timeout: 30_000 })
    // two workspaces: a picker with readable names, the one near the user preselected
    expect(await page.$$eval('#tenants input[name=tenant]', (o) => o.map((x) => x.value))).toEqual(['coriqo_msp_usa', 'coriqo_msp_uk'])
    expect(await page.$$eval('#tenants .name', (o) => o.map((x) => x.textContent))).toEqual(['Coriqo MSP', 'Coriqo MSP'])
    expect(await page.$$eval('#tenants .region', (o) => o.map((x) => x.textContent))).toEqual(['United States', 'United Kingdom'])
    expect(await page.$eval('#tenants input:checked', (n) => n.value)).toBe('coriqo_msp_usa') // Coriqo named none; the pinned time zone is US

    await page.click('#connect')
    await page.waitForFunction(() => /^Connected to Coriqo: Coriqo MSP, United States\. Device 1 of 1\./.test(document.getElementById('connect-msg').textContent), { timeout: 30_000 })
      .catch(async (e) => {
        throw new Error(`${e.message}; the page said: "${await page.$eval('#connect-msg', (n) => n.textContent)}"; Coriqo saw ${seen.join(', ')}`)
      })

    const state = path.join(dataDir, '.byoai', 'shield', 'keys', 'enrollment.json')
    await until(() => existsSync(state), 10_000, 'the Shield to be enrolled')
    expect(JSON.parse(readFileSync(state, 'utf8')).tenant_slug).toBe('coriqo_msp_usa')
    expect(seen).toContain('GET /oauth/authorize')
    expect(clients).toEqual(['https://coriqo.test/shield-client.json']) // the configured client id is what Coriqo is sent
    expect(seen.filter((s) => s === 'POST /v1/enroll').length).toBe(1)

    // A second press: this Mac is enrolled, so Shield keeps its identity and says so.
    await page.click('#connect')
    await page.waitForFunction(() => /already connected/i.test(document.getElementById('connect-msg').textContent), { timeout: 30_000 })
    expect(seen.filter((s) => s === 'POST /v1/enroll').length).toBe(1)
  })
})
