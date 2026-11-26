/**
 * Settings: what Shield may keep, what it does before a message leaves, which
 * apps it covers, and the optional link to a Coriqo account. The rail says
 * where every file lives, read from the running shield.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import {
  RETENTION_DAYS, enrolWithCoriqo, fetchCoriqo, fetchInstalledApps, fetchPolicy, fetchPrivacy,
  publishSeal, savePolicy, scrubStoredText,
} from '@/api/shield'
import type { ShieldAction, ShieldFileAction, ShieldPolicy, ShieldSharing } from '@/api/shield'
import { APP_NAME, Banner, ConfirmDialog, Icon, SectionHead, plural } from './shared'

const MODES = [
  ['redact', 'Check and act', 'Each kind of hit gets the action set below. By default a secret stops the send and personal details become placeholders such as [EMAIL_1].', true],
  ['observe', 'Record only', 'Messages go out unchanged. Shield records which rules matched.', false],
] as const

type Kind = 'observe' | 'keep_text' | 'actions' | 'files'
type Weaker = { change: Partial<ShieldPolicy>; kinds: Kind[] }

const TIERS = [
  ['secret', 'Secrets', 'API keys and tokens, private keys, login tokens, database passwords.'],
  ['pii', 'Personal details', 'Emails, card and phone numbers, SSNs, IBANs, wallet addresses.'],
  ['flag', 'Signals', 'Words like "deploy" or "password", executable file names. Recorded only by default.'],
] as const
const ACTION_LABEL: Record<ShieldAction, string> = {
  block: 'Block the send', warn: 'Ask first', redact: 'Redact', log: 'Record only',
}
const STRICT: ShieldAction[] = ['log', 'redact', 'warn', 'block']
const FILE_LABEL: Record<ShieldFileAction, string> = {
  allow: 'Allow', warn: 'Ask first', block: 'Block',
}
const FILE_STRICT: ShieldFileAction[] = ['allow', 'warn', 'block']
const DEFAULT_ACTIONS = { secret: 'block', pii: 'redact', flag: 'log' } as const
// Apps only the desktop proxy sees, through their public API.
const API_APPS = new Set(['github_copilot', 'mistral', 'deepseek', 'groq', 'openrouter', 'together', 'gemini_api'])

export function Settings() {
  const qc = useQueryClient()
  const [asking, setAsking] = useState<Weaker | null>(null)
  const policy = useQuery({ queryKey: ['shield-policy'], queryFn: fetchPolicy })
  const installed = useQuery({ queryKey: ['shield-apps'], queryFn: fetchInstalledApps, refetchInterval: 10_000 })
  const save = useMutation({
    mutationFn: (next: Partial<ShieldPolicy> & { acknowledge?: 'less_private' }) => savePolicy(next),
    onSuccess: data => {
      qc.setQueryData(['shield-policy'], data)
      setAsking(null)
      void qc.invalidateQueries({ queryKey: ['shield-privacy'] })
    },
  })
  /** Changes that make Shield less private go through a confirmation first;
   * the server refuses them without the acknowledgement. */
  const change = (next: Partial<ShieldPolicy>) => {
    const p = policy.data
    const kinds: Kind[] = []
    if (p && next.mode === 'observe' && p.mode !== 'observe') kinds.push('observe')
    if (p && next.keep_text && !p.keep_text) kinds.push('keep_text')
    if (p && next.actions) {
      const now = p.actions ?? DEFAULT_ACTIONS
      const lower = (Object.keys(next.actions) as (keyof typeof now)[])
        .some(t => STRICT.indexOf(next.actions![t]) < STRICT.indexOf(now[t]))
      if (lower) kinds.push('actions')
    }
    if (p && next.files) {
      const now = p.files ?? {}
      const lower = Object.entries(next.files).some(
        ([app, a]) => FILE_STRICT.indexOf(a) < FILE_STRICT.indexOf(now[app] ?? 'allow'))
      if (lower) kinds.push('files')
    }
    // Every lowering in this change is listed in one dialog, and one confirmation covers them all.
    if (kinds.length) return setAsking({ change: next, kinds })
    save.mutate(next)
  }
  if (policy.isPending) return <p className="empty-row" role="status">Loading settings…</p>
  if (policy.isError) {
    return (
      <p className="empty-row" role="alert">
        <b>Can't reach Shield on this Mac.</b>
        Start it with <code className="mono">byoai-shield</code>, then reload this page.
      </p>
    )
  }
  const p = policy.data
  const inputOnly = new Set(p.input_only_apps ?? [])
  const covered = new Set([...(p.covered_apps ?? Object.keys(p.apps)), ...inputOnly])
  const locked = new Set(p.managed?.locked ?? [])

  return (
    <div className="shield-split">
      <div className="shield-main">
        {(p.managed?.by || locked.size > 0) && (
          <Banner tone="info" role="status">
            <span>Managed by {p.managed?.by || 'your administrator'}. Locked settings can only be changed there.</span>
          </Banner>
        )}
        {p.sharing && (
          <Banner tone={p.sharing.level === 'seal' ? 'info' : 'warn'} role="status" testId="sharing-banner">
            <span>
              {p.sharing.words}
              {sharingSince(p.sharing.since)}
            </span>
          </Banner>
        )}
        {p.managed?.error && (
          <Banner tone="warn" role="status">
            <span>Managed policy: {p.managed.error}</span>
          </Banner>
        )}

        <section className="settings-block" aria-labelledby="mode-h">
          <SectionHead id="mode-h" title="Before a message leaves" accent
            help="What Shield does to personal details in what you send." />
          {locked.has('mode') && <p className="muted setting-help">Set by {p.managed?.by || 'your administrator'}.</p>}
          {p.mode === 'block' && (
            <p className="muted setting-help">This Mac uses the older "stop high-risk sends" setting. It now works
              the same as Check and act: what stops a send is set per kind below.</p>
          )}
          {MODES.map(([mode, title, note, recommended]) => (
            <label key={mode} className="mode-row">
              <input type="radio" name="shield-mode" checked={p.mode === mode || (mode === 'redact' && p.mode === 'block')}
                disabled={locked.has('mode')}
                onChange={() => change({ mode })} />
              <b>{title}{recommended && <> <span className="tag ok">Recommended</span></>}</b>
              <span>{note}</span>
            </label>
          ))}
          {p.mode !== 'observe' && TIERS.map(([tier, title, note]) => {
            const cur = (p.actions ?? DEFAULT_ACTIONS)[tier]
            return (
              <label key={tier} className="row-app">
                <span>
                  <b>{title}</b>
                  <span className="muted setting-help">{note}</span>
                </span>
                <select aria-label={`${title}: action`} value={cur}
                  onChange={e => change({ actions: { ...(p.actions ?? DEFAULT_ACTIONS), [tier]: e.target.value as ShieldAction } })}>
                  {STRICT.slice().reverse().map(a => <option key={a} value={a}>{ACTION_LABEL[a]}</option>)}
                </select>
              </label>
            )
          })}
          <p className="muted setting-help">
            In Chrome, the Shield extension applies this before a message leaves claude.ai and chatgpt.com;
            "Ask first" shows a bar with Send redacted, Send anyway and Cancel. On Gemini and Copilot it checks
            the message box when you press Enter or Send and replaces details there: best effort, not yet
            confirmed on every page. The desktop proxy can't show the bar, so there "Ask first" replaces.
            Uploaded files are set under Files you upload.
          </p>
        </section>

        <section className="settings-block" aria-labelledby="files-h">
          <SectionHead id="files-h" title="Files you upload"
            help="Shield records each file's SHA-256, size and type. Text files are also checked with the rules above." />
          {Object.keys(p.apps).filter(app => covered.has(app)).map(app => (
            <label key={app} className="row-app">
              <span><b>{APP_NAME[app] ?? app}</b></span>
              <select aria-label={`${APP_NAME[app] ?? app}: files`} value={p.files?.[app] ?? 'allow'}
                onChange={e => change({ files: { ...(p.files ?? {}), [app]: e.target.value as ShieldFileAction } })}>
                {FILE_STRICT.map(a => <option key={a} value={a}>{FILE_LABEL[a]}</option>)}
              </select>
            </label>
          ))}
          <p className="muted setting-help">
            Text-like files up to 5 MB (.txt, .csv, .json, .env, .pem, code and similar) are read on this Mac by the same
            rules; PDFs, images and Office files are recorded as "Not scanned" and only this setting applies. The desktop
            proxy can't ask, so there "Ask first" stops the upload. Shield keeps no copy of a file or its name.
          </p>
        </section>

        <PrivacySettings policy={p} save={change} saving={save.isPending} locked={locked} />

        <section className="settings-block" aria-labelledby="apps-h">
          <SectionHead id="apps-h" title="Apps"
            help="On: Shield checks what the app sends. Off: its traffic passes through, unchecked and unrecorded." />
          {locked.has('apps') && <p className="muted setting-help">Set by {p.managed?.by || 'your administrator'}.</p>}
          {Object.entries(p.apps).map(([app, on]) => {
            const where = inputOnly.has(app)
              ? 'Checked in Chrome as you send or attach (Shield extension 0.10 or later). Shield can\'t read its traffic, so the desktop proxy doesn\'t check it.'
              : API_APPS.has(app)
              ? 'Checked when the desktop proxy sees its API traffic. Not yet tested against live traffic.'
              : installed.data
              ? installed.data[app] ? 'Installed on this Mac.' : 'Not found in Applications; the web version is still covered.'
              : ''
            return covered.has(app) ? (
              <label key={app} className="row-app">
                <span>
                  <b>{APP_NAME[app] ?? app}</b>
                  {where && <span className="muted setting-help">{where}</span>}
                </span>
                <input type="checkbox" checked={Boolean(on)} disabled={locked.has('apps')}
                  onChange={() => save.mutate({ apps: { ...p.apps, [app]: !on } })} />
              </label>
            ) : (
              <div key={app} className="row-app inert">
                <span>
                  <b>{APP_NAME[app] ?? app}</b>
                  <span className="muted setting-help">
                    Not covered yet. Shield can't read this app's messages, so it can't check them.
                  </span>
                </span>
                <span className="tag unknown">Not covered</span>
              </div>
            )
          })}
        </section>

        <CoriqoLink />

        <p className="note">
          Changes reach the proxy within about two seconds. No restart needed.
          {save.isError && !asking ? ` Last change wasn't saved: ${save.error.message}` : ''}
        </p>
      </div>
      <aside className="shield-rail">
        <DataLocation sharing={p.sharing} />
      </aside>

      {asking && (() => {
        const only = asking.kinds.length === 1 ? asking.kinds[0] : null
        const NOTE: Record<Kind, string> = {
          observe: 'Emails, card numbers, phone numbers and keys will reach the AI app as typed. Shield will only record which rules matched. The notice on this Mac will say so.',
          keep_text: 'Shield will store up to 200 characters of each message on this Mac, with personal details removed. The rest of what you type still isn\'t kept.',
          actions: 'More of what you type will reach the AI app as typed. Shield will still record which rules matched.',
          files: 'Files will reach the AI app with less checking. Shield will still record each file\'s hash and which rules matched.',
        }
        return (
          <ConfirmDialog
            title={only === 'observe' ? 'Send messages unchanged?' : only === 'keep_text' ? 'Keep message previews?' : 'Make Shield less strict?'}
            confirmLabel={only === 'observe' ? 'Send unchanged' : only === 'keep_text' ? 'Keep previews' : 'Make less strict'}
            busy={save.isPending}
            onCancel={() => { setAsking(null); save.reset() }}
            onConfirm={() => save.mutate({ ...asking.change, acknowledge: 'less_private' })}>
            {only
              ? <p>{NOTE[only]}</p>
              : <ul>{asking.kinds.map(k => <li key={k}>{NOTE[k]}</li>)}</ul>}
            {save.isError && <p role="alert">Not saved: {save.error.message}</p>}
          </ConfirmDialog>
        )
      })()}
    </div>
  )
}

function PrivacySettings({ policy, save, saving, locked }: {
  policy: ShieldPolicy
  save: (next: Partial<ShieldPolicy>) => void
  saving: boolean
  locked: Set<string>
}) {
  const qc = useQueryClient()
  const privacy = useQuery({ queryKey: ['shield-privacy'], queryFn: fetchPrivacy })
  const scrub = useMutation({
    mutationFn: scrubStoredText,
    onSuccess: data => qc.setQueryData(['shield-privacy'], data),
  })
  const pv = privacy.data
  const by = policy.managed?.by
  return (
    <section className="settings-block privacy-block" aria-labelledby="privacy-h">
      <SectionHead id="privacy-h" title="What Shield keeps" />

      <label className="row-app">
        <span>
          <b>Keep a preview of each message</b>
          <span className="muted setting-help">
            Off: Shield keeps the length and a fingerprint, never the words. On:
            it also keeps up to 200 characters with personal details removed,
            so you can see what was sent.
            {locked.has('keep_text') && ` Set by ${by}.`}
          </span>
        </span>
        <input type="checkbox" checked={policy.keep_text} disabled={saving || locked.has('keep_text')}
          onChange={() => save({ keep_text: !policy.keep_text })} />
      </label>

      <label className="row-app">
        <span>
          <b>Keep history for</b>
          <span className="muted setting-help">
            Older records are deleted when Shield starts and when you remove stored text below.
            Sealed entries stay, so receipts keep working.
            {locked.has('retention_days') && ` Set by ${by}.`}
          </span>
        </span>
        <select value={policy.retention_days} disabled={saving || locked.has('retention_days')}
          onChange={e => save({ retention_days: Number(e.target.value) })}>
          {RETENTION_DAYS.map(d => (
            <option key={d} value={d}>{d === 365 ? '1 year' : `${d} days`}</option>
          ))}
        </select>
      </label>

      <label className="row-app">
        <span>
          <b>Show the notice on this Mac</b>
          <span className="muted setting-help">
            The strip at the top of Shield that tells whoever uses this Mac what Shield checks and keeps.
            {locked.has('notice') && ` Set by ${by}.`}
          </span>
        </span>
        <input type="checkbox" checked={policy.notice} disabled={saving || locked.has('notice')}
          onChange={() => save({ notice: !policy.notice })} />
      </label>

      <div className="row-app">
        <span>
          <b>Remove stored text</b>
          <span className="muted setting-help">
            {pv
              ? pv.rows_with_text > 0
                ? `${plural(pv.rows_with_text, 'record')} written before these settings still ${pv.rows_with_text === 1 ? 'holds' : 'hold'} message text. This replaces it with the length and fingerprint, and deletes records older than ${policy.retention_days} days.`
                : `No stored records hold message text.${pv.rows_past_retention ? ` ${pv.rows_past_retention.toLocaleString()} are older than ${policy.retention_days} days and will be deleted.` : ''}`
              : 'Checking the ledger…'}
          </span>
          {pv && pv.sealed_with_text > 0 && (
            <span className="muted setting-help">
              {plural(pv.sealed_with_text, 'sealed entry', 'sealed entries')} include text with personal
              details removed. They are left as they are: changing a sealed entry is what the
              seal exists to detect.
            </span>
          )}
          {scrub.data && (
            <span className="setting-help" role="status">
              Removed text from {plural(scrub.data.scrubbed, 'record')} and deleted{' '}
              {plural(scrub.data.deleted, 'older record')}.
            </span>
          )}
          {scrub.isError && <span className="setting-help">Cleanup failed: {scrub.error.message}</span>}
        </span>
        <button className="btn sm" onClick={() => scrub.mutate()}
          disabled={scrub.isPending || !pv || (pv.rows_with_text === 0 && pv.rows_past_retention === 0)}>
          {scrub.isPending ? 'Removing…' : 'Remove now'}
        </button>
      </div>
    </section>
  )
}

/** " Since <local date>." from the policy's ISO timestamp, or nothing. */
function sharingSince(iso: string | null) {
  const d = iso ? new Date(iso) : null
  return d && !Number.isNaN(d.getTime()) ? ` Since ${d.toLocaleDateString()}.` : ''
}

function ago(epochSeconds: number) {
  const mins = Math.max(0, Math.round((Date.now() / 1000 - epochSeconds) / 60))
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins} min ago`
  const h = Math.round(mins / 60)
  return h < 48 ? `${h} h ago` : `${Math.round(h / 24)} days ago`
}

function whenNext(epochSeconds: number) {
  const mins = Math.round((epochSeconds - Date.now() / 1000) / 60)
  if (mins <= 1) return 'within a minute'
  if (mins < 60) return `in about ${mins} min`
  return `in about ${Math.round(mins / 60)} h`
}

/** The link to a Coriqo tenant. Set up once with an enrolment token; after
 * that it sends this Mac's signed seal on its own, rarely, and retries by
 * itself. The only state that asks for a person is Coriqo refusing the Mac. */
function CoriqoLink() {
  const qc = useQueryClient()
  const info = useQuery({ queryKey: ['shield-coriqo'], queryFn: fetchCoriqo, refetchInterval: 30_000 })
  const [form, setForm] = useState({ base_url: '', token: '' })
  const [reconnect, setReconnect] = useState(false)
  const enrol = useMutation({
    mutationFn: () => enrolWithCoriqo(form),
    onSuccess: () => {
      setForm({ base_url: '', token: '' })
      setReconnect(false)
      void qc.invalidateQueries({ queryKey: ['shield-coriqo'] })
    },
  })
  const send = useMutation({
    mutationFn: publishSeal,
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['shield-coriqo'] }),
  })
  const ci = info.data
  const showForm = !ci?.connected || reconnect || ci.needs_attention

  return (
    <section className="settings-block coriqo" aria-labelledby="coriqo-h">
      <SectionHead id="coriqo-h" title="Coriqo" help="Optional. Sends this Mac's seal (its root, entry count and signature; no messages, no rule matches) to your Coriqo tenant, so it sits with the rest of your AI evidence." />

      {info.isPending && <p className="muted setting-help" role="status">Checking the connection…</p>}

      {ci?.connected && (
        <dl className="keeps-list stacked coriqo-status">
          <dt>Connected to</dt>
          <dd>{ci.tenant ?? 'your tenant'} · <span className="mono">{ci.base_url}</span></dd>
          <dt>Last sent</dt>
          <dd>
            {ci.last_sent_at
              ? `${ago(ci.last_sent_at)}, covering ${plural(ci.last_height, 'entry', 'entries')}`
              : 'Not yet. The first send happens within a minute.'}
          </dd>
          <dt>Next</dt>
          <dd>
            {!ci.has_new
              ? `Nothing new to send. Shield sends at most every ${ci.every_hours} hours, and only when there's something new.`
              : ci.next_attempt_at
                ? `New activity, sending ${whenNext(ci.next_attempt_at)}.`
                : 'New activity, sending within a minute.'}
          </dd>
        </dl>
      )}

      {ci?.last_error && (
        <Banner tone={ci.needs_attention ? 'bad' : 'warn'} role={ci.needs_attention ? 'alert' : 'status'}>
          <span>{ci.last_error}</span>
        </Banner>
      )}

      {ci?.connected && !showForm && (
        <div className="coriqo-row">
          <button className="btn" disabled={send.isPending || !ci.has_new}
            onClick={() => send.mutate()}>
            {send.isPending ? 'Sending…' : 'Send now'}
          </button>
          <button className="btn ghost icon" onClick={() => window.open(ci.base_url ?? '', '_blank', 'noopener')}>
            Open Coriqo<Icon name="external" size={16} />
          </button>
          <button className="btn ghost sm" onClick={() => setReconnect(true)}>Connect again</button>
        </div>
      )}
      {send.isError && <p className="setting-help" role="alert">Not sent: {send.error.message}</p>}

      {showForm && (
        <>
          <p className="muted setting-help">
            In Coriqo, an admin creates an enrolment token for this Mac. Paste it below with your
            Coriqo address. The token works once; after that this Mac identifies itself with its
            own key, so there's no password or API key to keep.
          </p>
          <form className="coriqo-form enrol" onSubmit={e => { e.preventDefault(); enrol.mutate() }}>
            <label>
              <span className="fkey">Coriqo address</span>
              <input value={form.base_url} placeholder={ci?.base_url ?? 'https://app.coriqo.com'}
                inputMode="url" autoComplete="url"
                onChange={e => setForm({ ...form, base_url: e.target.value })} />
            </label>
            <label>
              <span className="fkey">Enrolment token</span>
              <input type="password" autoComplete="off" value={form.token} placeholder="cik_live_…"
                onChange={e => setForm({ ...form, token: e.target.value })} />
            </label>
            <button className="btn primary" type="submit"
              disabled={enrol.isPending || !form.base_url.trim() || !form.token.trim()}>
              {enrol.isPending ? 'Connecting…' : 'Connect this Mac'}
            </button>
          </form>
          {enrol.isError && <p className="setting-help" role="alert">Not connected: {enrol.error.message}</p>}
          {reconnect && <button className="btn ghost sm" onClick={() => setReconnect(false)}>Cancel</button>}
        </>
      )}

    </section>
  )
}

function DataLocation({ sharing }: { sharing?: ShieldSharing }) {
  const privacy = useQuery({ queryKey: ['shield-privacy'], queryFn: fetchPrivacy })
  const pv = privacy.data
  return (
    <section className="panel" aria-labelledby="where-h">
      <SectionHead id="where-h" title="Where your data lives" />
      <dl className="keeps-list stacked">
        <dt>Records</dt>
        <dd className="mono">{pv?.ledger_path ?? '…'}</dd>
        <dt>Seal chain</dt>
        <dd className="mono">{pv?.seal_path ?? '…'}</dd>
        <dt>Device key</dt>
        <dd>
          <span className="mono">{pv?.device_id ?? 'created on first seal'}</span>
          {' · '}Ed25519 private key, file mode 0600. It never leaves this Mac.
        </dd>
        <dt>Leaves this Mac</dt>
        <dd>{sharing && sharing.level !== 'seal'
          ? 'Only what the notice at the top of this page describes.'
          : 'Nothing, unless you ship the seal to Coriqo. No account, no cloud copy, no sync by default.'}</dd>
      </dl>
    </section>
  )
}
