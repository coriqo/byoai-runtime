/**
 * Canned Shield API answers for the live UI pass (liveStandards.mjs). They
 * follow the zod schemas in web/src/api/shield.ts: the pass drives the real
 * screens against these, with no Shield process running.
 */
const HEX = (n, seed) => {
  let s = ''
  let x = seed * 2654435761 % 4294967296
  while (s.length < n) { x = (x * 1664525 + 1013904223) % 4294967296; s += x.toString(16).padStart(8, '0') }
  return s.slice(0, n)
}

const APPS = ['Claude · Chrome', 'ChatGPT · Chrome', 'Gemini · Chrome', 'Copilot · Chrome', 'Claude · Desktop', 'ChatGPT · Desktop']
const VERBS = [
  'Sent a message', 'Sent a message', 'Asked about a customer record', 'Sent a message with an attachment',
  'The agent called a tool', 'Sent a long prompt asking for a summary of the quarterly compliance report with every open item listed',
]

export function makeItems(n = 24, { allClean = false } = {}) {
  const items = []
  const today = new Date()
  for (let i = 0; i < n; i++) {
    const d = new Date(today.getTime() - i * 3 * 3600_000)
    const pad = (v) => String(v).padStart(2, '0')
    const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
    const kind = allClean ? 0 : i % 6
    const base = {
      id: `it-${i}`, source: i % 5 === 4 ? 'mcp' : i % 7 === 0 ? 'desktop' : 'browser',
      surface: APPS[i % APPS.length], ts: `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`, date,
      verb: VERBS[i % VERBS.length], status: 'answered', verdict: 'redact', chars: 120 + i * 7,
      redactions: [], tools: [], tier: 'ok', flags: [], seal: HEX(16, i + 1), response_stream: false,
    }
    if (kind === 1) Object.assign(base, { tier: 'warn', flags: [{ tier: 'pii', rule: 'emails' }], redactions: ['[EMAIL_1]'] })
    if (kind === 2) Object.assign(base, { tier: 'bad', status: 'blocked', flags: [{ tier: 'high', rule: 'aws_access_key' }, { tier: 'pii', rule: 'weird_new_rule' }] })
    if (kind === 3) Object.assign(base, { tier: 'warn', flags: [{ tier: 'conduct', rule: 'reply_toxic' }], reply: 'The assistant replied with a short refusal and a pointer to the policy.' })
    if (kind === 4) Object.assign(base, { tools: ['web.run', 'api_tool_search'], sources: 4 })
    if (kind === 5) Object.assign(base, { tier: 'warn', flags: [{ tier: 'pii', rule: 'cards' }, { tier: 'pii', rule: 'phone_numbers' }], redactions: ['[CARD_1]', '[PHONE_1]'] })
    items.push(base)
  }
  items[1].file = { mime: 'text/csv', bytes: 40_960, sha256: HEX(64, 99), scanned: true }
  items[1].verb = 'Uploaded a file'
  items[7].file = { mime: 'application/pdf', bytes: 912_000, sha256: HEX(64, 98), scanned: false }
  items[7].verb = 'Uploaded a file'
  return items
}

export function feed(items) {
  const today = items[0]?.date
  const todays = items.filter((i) => i.date === today)
  return {
    counts: { checked: todays.length, caught: todays.filter((i) => i.tier === 'warn').length, high_risk: todays.filter((i) => i.tier === 'bad').length },
    total: items.length, offset: 0, limit: 200, has_more: false, items,
  }
}

export const VERIFY_OK = {
  tamper_evident: true, entries: 412, merkle_root: HEX(64, 7),
  checkpoint: { root: HEX(64, 7), height: 412, device_id: `dev_${HEX(24, 5)}`, sig_valid: true },
}
export const VERIFY_BROKEN = { tamper_evident: false, entries: 412, broken_at: 188, reason: 'leaf_hash_mismatch', merkle_root: null, checkpoint: null }

export const POLICY = {
  mode: 'redact', apps: { claude: true, chatgpt: true, gemini: true, copilot: false, github_copilot: false, mistral: false },
  keep_text: false, retention_days: 30, notice: true,
  actions: { secret: 'block', pii: 'redact', flag: 'log' },
  files: { claude: 'warn', chatgpt: 'allow', gemini: 'allow', copilot: 'allow' },
  covered_apps: ['claude', 'chatgpt', 'github_copilot', 'mistral'], input_only_apps: ['gemini', 'copilot'],
}
export const POLICY_WEAK = { ...POLICY, mode: 'observe', keep_text: true }
export const POLICY_MANAGED = {
  ...POLICY, managed: { by: 'Acme IT', version: 4, locked: ['mode', 'retention_days', 'notice'], fetched_at: '2026-11-25T09:00:00Z', error: null },
  sharing: { level: 'daily', by: 'Acme IT', since: '2026-10-01T00:00:00Z', words: 'Acme IT receives a daily count of messages checked and flagged, by app. No message text.' },
}

export const PRIVACY = {
  ledger_rows: 412, rows_with_text: 0, oldest_row: '2026-10-28', rows_past_retention: 0, sealed_with_text: 0,
  keep_text: false, retention_days: 30, mode: 'redact', ledger_path: '/Users/demo/.byoai/shield/captures.jsonl',
  seal_path: '/Users/demo/.byoai/shield/seal.json', device_id: `dev_${HEX(24, 5)}`,
}
export const PRIVACY_STALE = { ...PRIVACY, rows_with_text: 31, rows_past_retention: 6, sealed_with_text: 4 }

export const CORIQO_OFF = { connected: false, last_height: 0, has_new: false, every_hours: 6, needs_attention: false }
export const CORIQO_ON = {
  connected: true, base_url: 'https://app.coriqo.com', tenant: 'acme', device_id: `dev_${HEX(24, 5)}`,
  last_sent_at: Math.floor(Date.now() / 1000) - 3600 * 2, last_height: 400, has_new: true, next_attempt_at: Math.floor(Date.now() / 1000) + 1800,
  every_hours: 6, needs_attention: false,
}
export const CORIQO_BAD = { ...CORIQO_ON, last_error: 'Coriqo refused this Mac: the enrolment was revoked by an administrator. Enrol again with a new token.', needs_attention: true }

export const APPS_INSTALLED = { claude: true, chatgpt: false, gemini: false, copilot: false }

export const RECEIPT_OK = (seal) => ({ kind: 'byoai.receipt.v2', seal, height: 3, payload: { interaction: 'x' }, merkle: { proof: { leaf_index: 0, leaf_hash: HEX(64, 1), steps: [], root_hex: HEX(64, 1) } }, self_check: { entry_hash_ok: true, chain_intact: true, chain_height: 3, verified_at: '2026-11-26T10:00:00Z' } })
