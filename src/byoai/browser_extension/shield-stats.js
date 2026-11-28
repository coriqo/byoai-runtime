/**
 * The extension's own record of what it did, so it shows its value with no
 * desktop app installed. Counts only: per app, per day, how many messages were
 * checked, how many secrets were stopped, how many personal details were
 * replaced and how many warnings were shown, plus how often each rule matched
 * (by rule name, e.g. "email"). Never message text, never the values that were
 * replaced, never a URL: the app is one of a fixed list of names.
 *
 * Kept in chrome.storage.local under `local_counts`, for the last KEEP_DAYS
 * days; older days are dropped on every write. The service worker writes it
 * (only with consent), the popup reads it, and turning capture off removes it.
 *
 * Shape: { v: 1, days: { 'YYYY-MM-DD': { <app>: { checked, secrets, personal,
 *   warned, rules: { <rule name>: n } } } } }
 */
(function () {
  'use strict'
  const KEY = 'local_counts'
  const KEEP_DAYS = 30
  const MAX_RULES = 40 // per app per day; the shipped ruleset has fewer
  const APP_OF_HOST = {
    'claude.ai': 'claude',
    'chatgpt.com': 'chatgpt',
    'chat.openai.com': 'chatgpt',
    'gemini.google.com': 'gemini',
    'copilot.microsoft.com': 'copilot',
    'copilot.com': 'copilot',
    'copilot.cloud.microsoft': 'copilot',
    'm365.cloud.microsoft': 'copilot',
  }
  const APP_NAMES = { claude: 'Claude', chatgpt: 'ChatGPT', gemini: 'Gemini', copilot: 'Copilot' }
  const RULE = /^[a-z0-9_]{1,40}$/
  const FIELDS = ['checked', 'secrets', 'personal', 'warned']

  const pad = (n) => String(n).padStart(2, '0')
  // The person's own calendar day, so "today" matches theirs.
  const dayKey = (ms) => { const d = new Date(ms); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}` }
  const daysBack = (now, n) => Array.from({ length: n }, (_, i) => {
    const d = new Date(now); d.setHours(12, 0, 0, 0); d.setDate(d.getDate() - i); return dayKey(d.getTime())
  })

  /*
   * What one capture row adds to the counts, or null when it adds nothing.
   * Reads only the text-free facts the row already carries for Shield: its
   * kind, length, rule flags ("tier:name"), redacted rule names and verdict.
   */
  function factsOf(row, host) {
    const app = APP_OF_HOST[host]
    if (!app || !row || row.kind !== 'browser.chat.request') return null
    if (typeof row.chars !== 'number') return null // not read, so not checked
    const verdict = typeof row.verdict === 'string' ? row.verdict : ''
    const flags = Array.isArray(row.flags) ? row.flags.filter((f) => typeof f === 'string') : []
    const redactions = new Set(Array.isArray(row.redactions) ? row.redactions.filter((r) => typeof r === 'string') : [])
    const stopped = verdict === 'blocked' || verdict === 'warned→cancelled'
    const tiers = {}
    const rules = []
    for (const f of flags) {
      const [tier, name] = f.split(':')
      if ((tier !== 'secret' && tier !== 'pii') || !RULE.test(name || '')) continue
      tiers[name] = tier
      rules.push(name)
    }
    let secrets = 0
    let personal = 0
    for (const name of new Set(rules)) {
      // A secret counts as stopped when the message did not go, or went with it replaced.
      if (tiers[name] === 'secret' && (stopped || redactions.has(name))) secrets++
      if (tiers[name] === 'pii' && !stopped && redactions.has(name)) personal++
    }
    return { app, checked: 1, secrets, personal, warned: verdict.startsWith('warned') ? 1 : 0, rules: [...new Set(rules)] }
  }

  // Keep only well-formed recent days; anything else in storage is dropped.
  function prune(stats, now) {
    const keep = new Set(daysBack(now, KEEP_DAYS))
    const days = {}
    const src = stats && typeof stats === 'object' && stats.days && typeof stats.days === 'object' ? stats.days : {}
    for (const day of Object.keys(src)) {
      if (!keep.has(day) || !src[day] || typeof src[day] !== 'object') continue
      const apps = {}
      for (const app of Object.keys(src[day])) {
        if (!APP_NAMES[app]) continue
        const c = src[day][app] || {}
        const out = { rules: {} }
        for (const f of FIELDS) out[f] = Number.isInteger(c[f]) && c[f] > 0 ? c[f] : 0
        for (const [r, n] of Object.entries(c.rules || {}).slice(0, MAX_RULES)) {
          if (RULE.test(r) && Number.isInteger(n) && n > 0) out.rules[r] = n
        }
        apps[app] = out
      }
      days[day] = apps
    }
    return { v: 1, days }
  }

  function add(stats, facts, now) {
    const out = prune(stats, now)
    if (!facts) return out
    const day = dayKey(now)
    const apps = (out.days[day] ||= {})
    const c = (apps[facts.app] ||= { checked: 0, secrets: 0, personal: 0, warned: 0, rules: {} })
    for (const f of FIELDS) c[f] += facts[f] || 0
    for (const r of facts.rules) {
      if (r in c.rules || Object.keys(c.rules).length < MAX_RULES) c.rules[r] = (c.rules[r] || 0) + 1
    }
    return out
  }

  // Totals over the last `days` days (1 = today), and which apps had any.
  function summarize(stats, now, days) {
    const clean = prune(stats, now)
    const total = { checked: 0, secrets: 0, personal: 0, warned: 0, apps: [] }
    const seen = new Set()
    for (const day of daysBack(now, days)) {
      for (const [app, c] of Object.entries(clean.days[day] || {})) {
        for (const f of FIELDS) total[f] += c[f]
        if (c.checked) seen.add(app)
      }
    }
    total.apps = Object.keys(APP_NAMES).filter((a) => seen.has(a)).map((a) => APP_NAMES[a])
    return total
  }

  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`
  const list = (names) => names.length < 2 ? names.join('') : `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`

  // One calm sentence for the popup about the last 7 days.
  function weekLine(week, today) {
    if (!week.checked) return 'Nothing checked yet. Send a message on one of the apps below and Shield checks it in the page.'
    const parts = []
    if (week.secrets) parts.push(`${plural(week.secrets, 'secret', 'secrets')} stopped`)
    if (week.personal) parts.push(`${plural(week.personal, 'personal detail', 'personal details')} replaced`)
    if (!parts.length) parts.push(`${plural(week.checked, 'message', 'messages')} checked, nothing to stop`)
    else parts.push(`${plural(week.checked, 'message', 'messages')} checked`)
    const head = `This week: ${list(parts)} on ${list(week.apps)}.`
    return today.checked ? `${head} Today: ${plural(today.checked, 'message', 'messages')} checked.` : head
  }

  /*
   * Is a desktop Shield expected on this computer? Yes when one was paired (a
   * pinned key), when someone saved their own address for it, or when an
   * administrator set its port. `managed` is true, false, or null for "could not
   * tell", which counts as expected: only a known never-set-up install is calm.
   * The badge (background.js) and the popup both ask this one question.
   */
  function shieldExpected({ pin, customEndpoint, managed }) {
    return !!pin || !!customEndpoint || managed !== false
  }

  /*
   * The popup state for what the probe found. A Shield that answers keeps every
   * existing state. One that proved itself but then failed its record check
   * keeps the existing "isn't running" warning. One that does not answer at all
   * is 'protecting' when none was ever expected, else 'away'.
   */
  function standaloneState({ state, verifyFailed = false, ...expect }) {
    if (state !== 'unreachable' || verifyFailed) return state
    return shieldExpected(expect) ? 'away' : 'protecting'
  }

  const api = { shieldExpected, standaloneState, KEY, KEEP_DAYS, APP_OF_HOST, APP_NAMES, dayKey, factsOf, prune, add, summarize, weekLine }
  globalThis.ShieldStats = api
  if (typeof module !== 'undefined' && module.exports) module.exports = api
})()
