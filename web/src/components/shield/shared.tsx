/**
 * Pieces every Shield screen uses: the brand seal, icons on the size scale,
 * banners, the copy button and hash chip, rule and app labels, the date
 * filter, the shared feed query, the notice strip and the receipt download
 * button. A screen reaches for these before it writes markup of its own.
 */
import { useEffect, useRef, useState } from 'react'
import type { ReactNode, RefObject } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import { fetchFeed, fetchReceipt } from '@/api/shield'
import type { ShieldPolicy } from '@/api/shield'

export type Item = Awaited<ReturnType<typeof fetchFeed>>['items'][number]
export type Tier = Item['tier']

export const RULE_LABEL: Record<string, string> = {
  emails: 'email address', cards: 'card number', wallets: 'wallet address',
  phone_numbers: 'phone number', ssn_like: 'SSN-like number', api_keys: 'API key',
  password_said: 'credentials mentioned', executable_masquerade: 'dangerous file',
  credential_block: 'credentials in text', tool_intent: 'agent action intent',
  connector_tool_call: 'tool call', reply_pii_echo: 'personal data echoed in reply',
  anthropic_key: 'Anthropic API key', openai_key: 'OpenAI API key', aws_access_key: 'AWS access key',
  github_token: 'GitHub token', slack_token: 'Slack token', google_api_key: 'Google API key',
  stripe_key: 'Stripe key', private_key_block: 'private key', jwt: 'login token (JWT)',
  conn_string: 'database password', bearer: 'bearer token', credential_assign: 'password or secret',
  iban: 'bank account (IBAN)', oversize: 'very large message',
  too_many_files: 'very many files', unreadable: 'file that could not be checked',
  reply_leak: 'secret echoed in reply', reply_toxic: 'harsh language in reply',
}

export const APP_NAME: Record<string, string> = {
  claude: 'Claude', chatgpt: 'ChatGPT', gemini: 'Gemini', copilot: 'Copilot',
  github_copilot: 'GitHub Copilot', mistral: 'Mistral', deepseek: 'DeepSeek', groq: 'Groq',
  openrouter: 'OpenRouter', together: 'Together', gemini_api: 'Gemini API',
}

/** A stored code read as words: "api_tool.run" becomes "Api tool run". */
export function humanize(code: string) {
  const words = code.replace(/[._-]+/g, ' ').trim()
  return words ? words[0]!.toUpperCase() + words.slice(1) : code
}

export const ruleLabel = (rule: string) => RULE_LABEL[rule] ?? humanize(rule)

/* ------------------------------------------------------- brand and icons */

/** The reticle seal: the Coriqo mark, in seal blue, no tile, never recoloured. */
export function SealMark({ size = 24 }: { size?: IconSize }) {
  return (
    <svg className={`icon icon-${size}`} viewBox="0 0 32 32" aria-hidden="true" data-seal="mark"
      style={{ color: 'var(--seal)' }}>
      <circle cx="16" cy="16" r="11" fill="none" stroke="currentColor" strokeWidth="3.6" />
      <circle cx="16" cy="16" r="4.6" fill="currentColor" />
    </svg>
  )
}

const SEAL_GLYPH = {
  verified: 'M11.6 16.3l3.1 3.1 5.9-6.4',
  review: 'M16 11v5.6M16 20.8v.2',
  failed: 'M12.5 12.5l7 7M19.5 12.5l-7 7',
  pending: null,
} as const
const SEAL_COLOR = {
  verified: 'var(--validated)', review: 'var(--pending)', failed: 'var(--off-scope)', pending: 'var(--ink-soft)',
} as const

/** The same drawing in a status colour, for record integrity only: green
 * verified, amber to review, red failed, grey not yet checked. From 24px up
 * the core carries a glyph, so the state is a shape as well as a colour. */
export function StatusSeal({ status, size = 24, label }: {
  status: keyof typeof SEAL_GLYPH
  size?: IconSize
  label?: string
}) {
  const glyph = SEAL_GLYPH[status]
  return (
    <svg className={`icon icon-${size}`} viewBox="0 0 32 32" data-seal={status}
      role={label ? 'img' : undefined} aria-label={label} aria-hidden={label ? undefined : true}
      style={{ color: SEAL_COLOR[status], overflow: 'visible' }}>
      <circle cx="16" cy="16" r="11" fill="none" stroke="currentColor" strokeWidth="3.6" />
      {glyph && size >= 24
        ? <path d={glyph} fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
        : <circle cx="16" cy="16" r="4.6" fill="currentColor" />}
    </svg>
  )
}

/** The only icon sizes there are: 12 inline status, 16 rows and buttons, 20
 * panels and alerts, 24 nav and banners, 32 stat tiles, 48 empty states. */
export type IconSize = 12 | 16 | 20 | 24 | 32 | 48

const ICON_PATH = {
  close: 'M6 6l12 12M18 6L6 18',
  download: 'M12 4v11M7 11l5 5 5-5M5 20h14',
  copy: 'M9 9h10v11H9zM5 15V4h10',
  'chevron-left': 'M15 6l-6 6 6 6',
  'chevron-right': 'M9 6l6 6-6 6',
  external: 'M14 4h6v6M20 4l-9 9M18 14v5H5V6h5',
  'check-circle': 'M12 21a9 9 0 100-18 9 9 0 000 18zM8 12.5l3 3 5-6',
  'alert-circle': 'M12 21a9 9 0 100-18 9 9 0 000 18zM12 7.5v5.5M12 16.5v.1',
  'alert-triangle': 'M12 4l9 16H3zM12 10v4.5M12 17.5v.1',
  info: 'M12 21a9 9 0 100-18 9 9 0 000 18zM12 11v5.5M12 7.5v.1',
} as const
export type IconName = keyof typeof ICON_PATH

/** A line icon from the set above, on the size scale, hidden from assistive tech. */
export function Icon({ name, size = 16 }: { name: IconName; size?: IconSize }) {
  return (
    <svg className={`icon icon-${size}`} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" data-icon={name}>
      <path d={ICON_PATH[name]} />
    </svg>
  )
}

type Tone = 'info' | 'ok' | 'warn' | 'bad'
const TONE_ICON: Record<Tone, IconName> = {
  info: 'info', ok: 'check-circle', warn: 'alert-triangle', bad: 'alert-circle',
}

/** A message that must not be missed. The tone is a shape (icon) and a tint,
 * and the text says what it means; colour is never the only carrier. */
export function Banner({ tone, role, className, testId, children }: {
  tone: Tone
  role?: 'status' | 'alert'
  className?: string
  testId?: string
  children: ReactNode
}) {
  return (
    <div className={`banner ${tone}${className ? ` ${className}` : ''}`} role={role} data-testid={testId}>
      <Icon name={TONE_ICON[tone]} size={20} />
      {children}
    </div>
  )
}

/** Copies `text` and says so. The clipboard can be blocked; the value stays on screen then. */
export function CopyButton({ text, label = 'Copy', ariaLabel }: { text: string; label?: string; ariaLabel?: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch { /* clipboard blocked: the value is still on screen */ }
  }
  return (
    <button type="button" className="btn ghost sm icon" aria-label={ariaLabel}
      onClick={e => { e.stopPropagation(); void copy() }}>
      <Icon name="copy" size={16} />{copied ? 'Copied' : label}
    </button>
  )
}

/** An identifier as a person meets it: the start of it, a copy button, the
 * whole value in the tooltip. Never inside a sentence. */
export function HashChip({ value, noun, short = 12 }: { value: string; noun: string; short?: number }) {
  return (
    <span className="hash-chip">
      <span className="hash" title={value}>{value.length > short ? `${value.slice(0, short)}…` : value}</span>
      <CopyButton text={value} ariaLabel={`Copy the full ${noun}`} />
    </span>
  )
}

/** Keeps Tab inside a dialog, starts on `initial` (or the first control) and
 * hands focus back to what had it when the dialog closes. */
export function useFocusTrap(ref: RefObject<HTMLElement>, initial?: RefObject<HTMLElement>) {
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null
    const box = ref.current
    const focusables = () => Array.from(box?.querySelectorAll<HTMLElement>(
      'button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, a[href], [tabindex]:not([tabindex="-1"])',
    ) ?? [])
    ;(initial?.current ?? focusables()[0])?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'Tab') return
      const items = focusables()
      const first = items[0]
      const last = items[items.length - 1]
      if (!first || !last) return
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus() }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus() }
    }
    box?.addEventListener('keydown', onKey)
    return () => { box?.removeEventListener('keydown', onKey); before?.focus?.() }
  }, [ref, initial])
}

export function flagTagClass(tier: string) {
  return tier === 'agent' ? 'info' : tier === 'high' ? 'bad' : 'warn'
}

export function tierLabel(it: Item) {
  if (it.unreadable) return 'Cannot show'
  if (it.status === 'blocked') return 'Blocked'
  return it.tier === 'bad' ? 'High risk' : it.tier === 'warn' ? 'Flagged' : 'No exception'
}

export function tierTagClass(tier: Tier) {
  return tier === 'bad' ? 'bad' : tier === 'warn' ? 'warn' : 'ok'
}

/* ------------------------------------------------------------ date filter */

export type When = 'today' | '7' | '30' | 'all'
export const WHEN_OPTIONS: readonly (readonly [When, string])[] = [
  ['today', 'Today'], ['7', 'Last 7 days'], ['30', 'Last 30 days'], ['all', 'All time'],
]

function localDay(ms: number) {
  const d = new Date(ms)
  return new Date(d.getTime() - d.getTimezoneOffset() * 60_000).toISOString().slice(0, 10)
}

export const today = () => localDay(Date.now())

/** Whether an item's local date falls inside the chosen window. */
export function inWhen(date: string | undefined, when: When, now = Date.now()): boolean {
  if (when === 'all') return true
  const d = (date ?? '').slice(0, 10)
  const end = localDay(now)
  if (when === 'today') return d === end
  const start = localDay(now - (Number(when) - 1) * 86_400_000)
  return Boolean(d) && d >= start && d <= end
}

/** First local day of a window ("" for all time), for the server's `since`. */
export function whenStart(when: When, now = Date.now()): string {
  if (when === 'all') return ''
  return localDay(when === 'today' ? now : now - (Number(when) - 1) * 86_400_000)
}

/* ------------------------------------------------------------------- feed */

/** The newest 200 interactions, shared by every tab (one fetch, one answer).
 * Filtering and paging happen on this list, so a filter never hides rows that
 * sit on a page the server didn't send. */
export function useFeed() {
  return useQuery({
    queryKey: ['shield-feed'],
    queryFn: () => fetchFeed({ page: 0, perPage: 200 }),
    refetchInterval: 3_000,
  })
}

/* ---------------------------------------------------------------- notice */

/** Always on while `notice` is set, so whoever uses the Mac can see what
 * Shield does without opening anything. Not dismissible by design. */
export function NoticeStrip({ policy }: { policy: ShieldPolicy }) {
  return (
    <Banner tone="info" role="status" className="shield-notice">
      <span>
        Shield checks what you send to AI apps from this Mac.{' '}
        {policy.mode === 'observe'
          ? 'Messages go out unchanged; it records which rules matched.'
          : 'Personal details are replaced before a message leaves.'}{' '}
        {policy.keep_text
          ? 'It keeps a short preview of each message with those details removed.'
          : 'It keeps the rule matches and message length, not your words.'}
      </span>
    </Banner>
  )
}

/* --------------------------------------------------------------- receipt */

export function ReceiptButton({ seal, label = 'Receipt' }: { seal: string; label?: string }) {
  const dl = useMutation({
    mutationFn: () => fetchReceipt(seal),
    onSuccess: receipt => {
      const blob = new Blob([JSON.stringify(receipt, null, 1)], { type: 'application/json' })
      downloadBlob(blob, `byoai-receipt-${seal}.json`)
    },
  })
  return (
    <>
      <button onClick={() => dl.mutate()} disabled={dl.isPending || !seal} className="btn ghost sm icon">
        <Icon name="download" size={16} />{dl.isPending ? 'Preparing…' : label}
      </button>
      {dl.isError && <span className="tag bad" role="alert">No receipt: {dl.error.message}</span>}
    </>
  )
}

export function downloadBlob(blob: Blob, name: string) {
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = name
  a.click()
  URL.revokeObjectURL(a.href)
}

export function WhenFilter({ value, onChange }: { value: When; onChange: (w: When) => void }) {
  return (
    <div className="group" role="group" aria-label="Date range">
      <span className="fkey">When</span>
      {WHEN_OPTIONS.map(([key, label]) => (
        <button key={key} className={`filter ${value === key ? 'on' : ''}`}
          aria-pressed={value === key} onClick={() => onChange(key)}>
          {label}
        </button>
      ))}
    </div>
  )
}

/** A tool name as ChatGPT or Claude reports it, in words. Unknown names are shown as they are. */
const TOOL_LABEL: Record<string, string> = {
  'web.run': 'Web search', web: 'Web search', web_search: 'Web search', browser: 'Web search',
  python: 'Code run', 'python.exec': 'Code run', code_execution: 'Code run',
  bio: 'Memory', canmore: 'Canvas', file_search: 'File search', myfiles_browser: 'File search',
  image_gen: 'Image generation', 'dalle.text2im': 'Image generation',
}
export const toolLabel = (name: string) =>
  TOOL_LABEL[name] ?? (name.startsWith('api_tool') || name.includes('connector') ? `Connector: ${humanize(name)}` : humanize(name))

export type Need = 'all' | 'warn' | 'bad' | 'mcp' | 'browser'
export const NEED_OPTIONS: readonly (readonly [Need, string])[] = [
  ['all', 'All'], ['warn', 'Flagged'], ['bad', 'Blocked or high risk'],
  ['mcp', 'Tool calls'], ['browser', 'In browser'],
]

export function matchesNeed(it: Item, need: Need) {
  if (need === 'warn') return it.tier === 'warn'
  if (need === 'bad') return it.tier === 'bad'
  if (need === 'mcp') return it.source === 'mcp'
  if (need === 'browser') return it.source === 'browser'
  return true
}

export function NeedFilter({ value, onChange }: { value: Need; onChange: (n: Need) => void }) {
  return (
    <div className="group" role="group" aria-label="Show">
      <span className="fkey">Show</span>
      {NEED_OPTIONS.map(([key, label]) => (
        <button key={key} className={`filter ${value === key ? 'on' : ''}`}
          aria-pressed={value === key} onClick={() => onChange(key)}>
          {label}
        </button>
      ))}
    </div>
  )
}

/* ------------------------------------------------------------ primitives */

/** Rows per page a reader can choose. The default is a named constant, not a
 * policy: it is a per-reader display choice kept in the URL, and Shield has no
 * display-settings store (its policy is signed and managed by an admin). */
export const PAGE_SIZES = [25, 50, 100] as const
export const DEFAULT_PAGE_SIZE = 25

/** Previous / next paging with "Showing 26 to 50 of 305 events" and a page
 * size. The screen owns the state (Timeline keeps it in the URL). Same words
 * as the Coriqo app's pager. */
export function Pager({ page, pages, from, to, total, pageSize, onPage, onPageSize, noun = 'rows', note }: {
  page: number; pages: number; from: number; to: number; total: number; pageSize: number
  onPage: (page: number) => void
  onPageSize?: (size: number) => void
  noun?: string
  /** A caveat that stays visible, e.g. that older rows are not in this list. */
  note?: string
}) {
  if (!total) return null
  return (
    <nav className="pager" aria-label={`${noun} pages`} data-testid="pager">
      <span className="page-stat" data-testid="pager-range" aria-live="polite">
        Showing {from} to {to} of {total.toLocaleString()} {noun}
      </span>
      <span className="spacer" />
      {onPageSize && (
        <label className="pager-size">
          Rows per page
          <select value={pageSize} onChange={e => onPageSize(Number(e.target.value))}>
            {PAGE_SIZES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
      )}
      <button className="btn sm icon" disabled={page <= 1} aria-label="Previous page" onClick={() => onPage(page - 1)}>
        <Icon name="chevron-left" size={16} />Previous
      </button>
      <span className="page-stat" data-testid="pager-page">Page {page} of {pages}</span>
      <button className="btn sm icon" disabled={page >= pages} aria-label="Next page" onClick={() => onPage(page + 1)}>
        Next<Icon name="chevron-right" size={16} />
      </button>
      {note && <p className="pager-note">{note}</p>}
    </nav>
  )
}

/** "1 record", "12 records". */
export function plural(n: number, one: string, many = `${one}s`) {
  return `${n.toLocaleString()} ${n === 1 ? one : many}`
}

/** Opens every section: a short title, then at most one line of help. The
 * accent tone marks the section the reader came to the page for. */
export function SectionHead({ id, title, help, accent, action }: {
  id: string
  title: string
  help?: ReactNode
  accent?: boolean
  action?: ReactNode
}) {
  return (
    <header className="sec-head">
      <div className="sec-title">
        <span className={`sec-dot ${accent ? 'accent' : ''}`} aria-hidden="true" />
        <h2 className="label" id={id}>{title}</h2>
        {action && <span className="sec-action">{action}</span>}
      </div>
      {help && <p className="sec-help">{help}</p>}
    </header>
  )
}

/** A yes/no question that needs a deliberate answer. Esc or the backdrop
 * cancels; focus starts on Cancel so Enter never confirms by accident. */
export function ConfirmDialog({ title, children, confirmLabel, onConfirm, onCancel, busy }: {
  title: string
  children: ReactNode
  confirmLabel: string
  onConfirm: () => void
  onCancel: () => void
  busy?: boolean
}) {
  const cancelRef = useRef<HTMLButtonElement>(null)
  const boxRef = useRef<HTMLDivElement>(null)
  useFocusTrap(boxRef, cancelRef)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onCancel() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onCancel])
  return (
    <div className="dialog-backdrop" onClick={e => { if (e.target === e.currentTarget) onCancel() }}>
      <div ref={boxRef} className="dialog" role="alertdialog" aria-modal="true"
        aria-labelledby="dialog-h" aria-describedby="dialog-body">
        <h2 id="dialog-h">{title}</h2>
        <div id="dialog-body" className="dialog-body">{children}</div>
        <div className="dialog-actions">
          <button ref={cancelRef} className="btn" onClick={onCancel}>Cancel</button>
          <button className="btn danger" onClick={onConfirm} disabled={busy}>{confirmLabel}</button>
        </div>
      </div>
    </div>
  )
}

const fileSize = (n: number) => n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`

/** Evidence for one uploaded file: type, size, the start of its SHA-256 with a
 * button for the whole hash, the rules that matched and whether it was read. */
export function FileEvidence({ item }: { item: Item }) {
  const f = item.file
  if (!f) return null
  return (
    <span className="file-evidence" data-testid="file-evidence">
      <span className="tag info">{f.mime || 'unknown type'}</span>
      {f.bytes != null && <span className="muted">{fileSize(f.bytes)}</span>}
      <HashChip value={f.sha256} noun="SHA-256" short={16} />
      {f.scanned === false && <span className="tag unknown">Not scanned</span>}
      {item.flags.map(fl => (
        <span key={fl.rule} className={`tag ${flagTagClass(fl.tier)}`}>{ruleLabel(fl.rule)}</span>
      ))}
    </span>
  )
}
