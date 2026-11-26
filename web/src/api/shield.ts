/**
 * Coriqo shield (capture ledger) client — the broker between the browser-side
 * trust model and the capture backend. It sticks to the console's existing
 * API conventions: typed, schema-checked responses, explicit states per error
 * kind, no silent fallbacks. The shield itself lives on the Python side
 * (`byoai.integrations.shield`), proxied at `/shield-api` from Vite and
 * `/console/{tenant}/shield` in production.
 */
import { z } from 'zod'

/* ----------------------------------------------------------------- schema */

export const ShieldFlag = z.object({
  tier: z.enum(['agent', 'high', 'pii', 'conduct']),
  rule: z.string().min(1),
})

/** What Shield knows about an uploaded file: type, size and SHA-256, never the
 * name or content. ``scanned: false`` means the rules did not read it. */
export const ShieldFile = z.object({
  mime: z.string().nullish(),
  bytes: z.number().int().nonnegative().nullish(),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  name_hash: z.string().nullish(),
  scanned: z.boolean().nullish(),
  rules_version: z.string().nullish(),
})
export type ShieldFile = z.infer<typeof ShieldFile>

export const SHIELD_SOURCES = ['mcp', 'desktop', 'browser'] as const

export const ShieldItem = z.object({
  id: z.string().min(1),
  source: z.enum(['mcp', 'desktop', 'browser']),
  surface: z.string().min(1),
  ts: z.string(),
  date: z.string(),
  verb: z.string(),
  reply: z.string().nullish(),
  status: z.enum(['answered', 'running', 'failed', 'blocked']),
  verdict: z.string().nullish(),
  chars: z.number().nullish(),
  redactions: z.array(z.string()).nullish(),
  /** Tools the AI app ran for the reply (browser), e.g. "web.run"; names only. */
  tools: z.array(z.string()).nullish(),
  sources: z.number().nullish(),
  tier: z.enum(['ok', 'warn', 'bad']),
  flags: z.array(ShieldFlag),
  response_stream: z.boolean().optional(),
  tool: z.string().nullish(),
  identity: z.record(z.unknown()).nullish(),
  usage: z.record(z.unknown()).nullish(),
  latency_ms: z.number().nullish(),
  seal: z.string().min(1),
  /** Present on rows for an uploaded file. */
  file: ShieldFile.nullish(),
})

export const ShieldFeed = z.object({
  counts: z.object({
    checked: z.number().int().nonnegative(),
    caught: z.number().int().nonnegative(),
    high_risk: z.number().int().nonnegative(),
  }),
  total: z.number().int(),
  offset: z.number().int(),
  limit: z.number().int(),
  has_more: z.boolean(),
  items: z.array(ShieldItem),
  /** Paging fields (absent from a Shield older than this change). */
  matched: z.number().int().nonnegative().optional(),
  newer: z.number().int().nonnegative().optional(),
  capacity: z.number().int().positive().nullish(),
  focus_item: ShieldItem.nullish(),
  newest_id: z.string().nullish(),
})

export const ShieldCheckpoint = z.object({
  root: z.string().min(1).nullish(),
  height: z.number().int(),
  device_id: z.string().min(1).nullish(),
  sig_valid: z.boolean().nullish(),
})

export const ShieldVerify = z.object({
  tamper_evident: z.boolean(),
  entries: z.number().int().nullish(),
  broken_at: z.number().int().nullish(),
  reason: z.string().nullish(),
  merkle_root: z.string().nullish(),
  checkpoint: ShieldCheckpoint.nullish(),
})

export const ShieldReceipt = z.object({
  kind: z.literal('byoai.receipt.v2'),
  seal: z.string(),
  height: z.number(),
  payload: z.record(z.unknown()),
  merkle: z.object({
    proof: z.object({
      leaf_index: z.number(),
      leaf_hash: z.string(),
      steps: z.array(z.object({ sibling: z.string(), side: z.string() })).nullish(),
      root_hex: z.string(),
    }),
    checkpoint: z.record(z.unknown()).nullish(),
  }),
  self_check: z.object({
    entry_hash_ok: z.boolean(),
    chain_intact: z.boolean(),
    chain_height: z.number(),
    verified_at: z.string(),
  }),
})

export async function fetchReceipt(seal: string) {
  const res = await fetch(`/shield-api/receipt/${seal}`, { cache: 'no-store' })
  if (!res.ok) throw new Error(`${res.status} receipt ${seal}`)
  return ShieldReceipt.parse(await res.json())
}

export const RETENTION_DAYS = [7, 30, 90, 365] as const

/** An MSP's Coriqo tenant sets policy centrally; present only once this
 * device has ever received one. ``by``/``locked`` are null/empty while a
 * signed ``policy: null`` document has unmanaged the device (its version
 * is kept, so a replayed older envelope is still refused as a rollback). */
export const ShieldManaged = z.object({
  by: z.string().nullable(),
  version: z.number().int().nullable(),
  locked: z.array(z.string()),
  fetched_at: z.string().nullable(),
  error: z.string().nullable(),
})
export type ShieldManaged = z.infer<typeof ShieldManaged>

/** Who receives this device's activity, and what, in the words the person
 * reads. Present when a managed policy names an organisation, or the level is
 * above seal (``by`` is then "Your administrator" if none is named). */
export const ShieldSharing = z.object({
  level: z.enum(['seal', 'daily', 'events']),
  by: z.string(),
  since: z.string().nullable(),
  words: z.string(),
})
export type ShieldSharing = z.infer<typeof ShieldSharing>

export const ShieldAction = z.enum(['block', 'warn', 'redact', 'log'])
export type ShieldAction = z.infer<typeof ShieldAction>

/** What happens to a file uploaded to an app. "warn" asks first in the
 * browser; the desktop proxy can't ask, so it stops the upload. */
export const ShieldFileAction = z.enum(['allow', 'warn', 'block'])
export type ShieldFileAction = z.infer<typeof ShieldFileAction>

export const ShieldPolicy = z.object({
  mode: z.enum(['observe', 'redact', 'block']),
  apps: z.record(z.boolean()),
  keep_text: z.boolean(),
  retention_days: z.number().int().positive(),
  notice: z.boolean(),
  /** What happens per kind of hit: secrets, personal details, flags. */
  actions: z.object({ secret: ShieldAction, pii: ShieldAction, flag: ShieldAction }).optional(),
  /** Per app: what happens to an uploaded file. */
  files: z.record(ShieldFileAction).optional(),
  /** Apps the capture proxy can read. Served, not saved: the others can't
   * be turned on yet. */
  covered_apps: z.array(z.string()).optional(),
  /** Apps checked only at input, by the browser extension's gate. */
  input_only_apps: z.array(z.string()).optional(),
  managed: ShieldManaged.optional(),
  sharing: ShieldSharing.optional(),
})
export type ShieldPolicy = z.infer<typeof ShieldPolicy>

/** What Shield holds on disk right now — read from the ledger, not assumed. */
export const ShieldPrivacy = z.object({
  ledger_rows: z.number().int().nonnegative(),
  rows_with_text: z.number().int().nonnegative(),
  oldest_row: z.string().nullable(),
  rows_past_retention: z.number().int().nonnegative(),
  sealed_with_text: z.number().int().nonnegative(),
  keep_text: z.boolean(),
  retention_days: z.number().int(),
  mode: z.enum(['observe', 'redact', 'block']),
  less_private: z.boolean().optional(),
  ledger_path: z.string().nullish(),
  seal_path: z.string().nullish(),
  device_id: z.string().nullish(),
})
export type ShieldPrivacy = z.infer<typeof ShieldPrivacy>

export const ShieldScrub = ShieldPrivacy.extend({
  scrubbed: z.number().int().nonnegative(),
  deleted: z.number().int().nonnegative(),
})

/* ------------------------------------------------------------------ calls */

export interface ShieldPage {
  /** Treated as an opaque page number (`0`, `1`, …) — the shield server
   * clamps at 200 rows/page and reports back what it actually served. */
  page: number
  perPage: number
}

async function get<T>(path: string, schema: z.ZodType<T>): Promise<T> {
  const res = await fetch(`/shield-api${path}`, { cache: 'no-store' })
  if (!res.ok) throw new Error(`${res.status} from shield (${path})`)
  return schema.parse(await res.json())
}

export function fetchFeed(page: ShieldPage) {
  const qs = `/feed?limit=${Math.min(page.perPage, 200)}&offset=${page.page * page.perPage}`
  return get(qs, ShieldFeed)
}

export interface FeedQuery {
  limit: number
  offset: number
  /** Server-side filters, applied before paging. */
  need?: string
  since?: string
  /** Hide rows newer than this id, so a page holds still while rows arrive. */
  anchor?: string
  /** Also return this row as `focus_item`, wherever it sits. */
  focus?: string
}

export function fetchFeedPage(q: FeedQuery) {
  const p = new URLSearchParams({ limit: String(Math.min(q.limit, 200)), offset: String(q.offset) })
  for (const k of ['need', 'since', 'anchor', 'focus'] as const) {
    const v = q[k]
    if (v && !(k === 'need' && v === 'all')) p.set(k, v)
  }
  return get(`/feed?${p}`, ShieldFeed)
}

export function fetchVerify() {
  return get('/verify', ShieldVerify)
}

export function fetchPolicy() {
  return get('/policy', ShieldPolicy)
}

async function post<T>(path: string, body: unknown, schema: z.ZodType<T>): Promise<T> {
  const res = await fetch(`/shield-api${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  })
  const json: unknown = await res.json().catch(() => ({}))
  if (!res.ok) {
    const msg = (json as { error?: string }).error
    throw new Error(msg ?? `${res.status} from shield (${path})`)
  }
  return schema.parse(json)
}

/** `acknowledge` is required by the server for any change that makes Shield
 * less private than it is now (record-only mode, stored previews). */
export function savePolicy(next: Partial<ShieldPolicy> & { acknowledge?: 'less_private' }) {
  return post('/policy', next, ShieldPolicy)
}

export function fetchPrivacy() {
  return get('/privacy', ShieldPrivacy)
}

/** This Mac's link to a Coriqo tenant. Nothing secret: after a one-time
 * enrolment the Mac signs every request with its own key. */
export const ShieldCoriqo = z.object({
  connected: z.boolean(),
  base_url: z.string().nullish(),
  tenant: z.string().nullish(),
  device_id: z.string().nullish(),
  enrolled_at: z.string().nullish(),
  last_sent_at: z.number().nullish(),
  last_height: z.number().int().nonnegative(),
  /** Something was sealed since the last accepted send. */
  has_new: z.boolean(),
  next_attempt_at: z.number().nullish(),
  every_hours: z.number(),
  last_error: z.string().nullish(),
  needs_attention: z.boolean(),
  marketing_url: z.string().nullish(),
})
export type ShieldCoriqo = z.infer<typeof ShieldCoriqo>
/** What enrol and "Send now" answer with: the same status, minus the link. */
const ShieldCoriqoStatus = ShieldCoriqo.omit({ marketing_url: true })

export function fetchCoriqo() {
  return get('/coriqo', ShieldCoriqo)
}

/** One-time setup: a Coriqo admin mints an enrolment token; paste it here. */
export function enrolWithCoriqo(next: { base_url: string; token: string }) {
  return post('/coriqo/enrol', next, ShieldCoriqoStatus)
}

/** Send the current seal now instead of waiting for the next scheduled send.
 * A failure is recorded in the status and retried on its own. */
export function publishSeal() {
  return post('/publish', {}, ShieldCoriqoStatus)
}

/** Which of the known AI apps are installed on this Mac (read from
 * /Applications on each call). */
export function fetchInstalledApps() {
  return get('/apps', z.record(z.boolean()))
}

/** Replace stored message text with fingerprints and apply retention. */
export function scrubStoredText() {
  return post('/privacy/scrub', {}, ShieldScrub)
}


export type ShieldVerify = z.infer<typeof ShieldVerify>
