/**
 * Trust: is Shield working, what did it catch, and what does it keep. The
 * activity list is the work; "What Shield keeps" sits in the rail beside it.
 * The list pages on the server and its state lives in the URL
 * (`?page=2&size=50&need=warn&when=7&q=card`); the figures above it are exact
 * counts over every row Shield holds today, not the page on screen.
 */
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { fetchPrivacy, savePolicy, scrubStoredText } from '@/api/shield'
import type { ShieldPolicy, ShieldPrivacy, ShieldVerify } from '@/api/shield'
import type { ShieldSearch } from '@/routes/shield'
import { FeedError, NewRows, usePagedFeed } from './paging'
import type { PatchSearch } from './paging'
import {
  Banner, DEFAULT_PAGE_SIZE, HashChip, NeedFilter, Pager, SectionHead, StatusSeal, WhenFilter, flagTagClass, humanize,
  plural, ruleLabel, toolLabel, whenStart,
} from './shared'
import type { Item, Need, When } from './shared'

export function Trust({ verify, policy, search: url, patch, onOpen, goSettings, goLedger }: {
  verify: ShieldVerify | undefined
  policy: ShieldPolicy | undefined
  search: ShieldSearch
  patch: PatchSearch
  onOpen: (it: Item) => void
  goSettings: () => void
  /** Where a failed verification sends the reader: the sealed entries. */
  goLedger?: () => void
}) {
  const need: Need = url.need ?? 'all'
  const when: When = url.when ?? 'today'
  const size = url.size ?? DEFAULT_PAGE_SIZE
  const page = url.page ?? 1
  const q = url.q ?? ''
  // The search box types freely; the URL (and the server) follow once typing pauses.
  const [typed, setTyped] = useState(q)
  useEffect(() => { setTyped(q) }, [q])
  useEffect(() => {
    if (typed.trim() === q) return
    const id = setTimeout(() => patch({ q: typed.trim() || undefined, page: undefined }, true), 350)
    return () => clearTimeout(id)
  }, [typed, q, patch])

  const { feed, data, items: shown, matched, shown: range, headRef, goPage, showNew, setSize, capped, error } = usePagedFeed({
    scope: 'trust', page, size, patch,
    query: { need, since: whenStart(when), q, summarySince: whenStart('today') },
  })
  // Exact over every row held today, from the server; none until the first answer.
  const counts = data?.summary
  const filtered = need !== 'all' || when !== 'today' || q !== ''
  // Only a narrower view than the whole list is "matching"; All time is wider than today.
  const narrowed = need !== 'all' || q !== '' || when === '7' || when === '30'
  const reset = () => { setTyped(''); patch({ need: undefined, when: undefined, q: undefined, page: undefined }) }
  const pick = (n: Need) => patch({ need: n === 'all' ? undefined : n, when: undefined, page: undefined })
  const intact = verify?.tamper_evident && verify.checkpoint?.sig_valid !== false
  return (
    <div className="shield-split">
      <div className="shield-main">
        <section className={`verdict ${!verify ? 'unknown' : intact ? 'ok' : 'bad'}`} aria-live="polite">
          <div className="state">
            <StatusSeal size={32} status={!verify ? 'pending' : intact ? 'verified' : 'failed'} />
            {!verify ? 'Checking…' : intact ? 'Shield is on' : 'Record failed verification'}
          </div>
          <p className="reading">
            {!counts ? 'Counting today\'s messages…'
              : counts.high_risk ? `${plural(counts.high_risk, 'message')} blocked or flagged high risk today.`
                : counts.flagged ? `Personal details flagged in ${plural(counts.flagged, 'message')} today.`
                  : 'No exceptions today.'}
          </p>
          <p className="verdict-facts">
            {verify
              ? intact
                ? <>
                  <span>{plural(verify.entries ?? 0, 'sealed entry', 'sealed entries')}, tamper-evident and verified</span>
                  {verify.merkle_root && <span>Root <HashChip value={verify.merkle_root} noun="root hash" /></span>}
                </>
                : <>
                  <span>Verification fails at entry {verify.broken_at ?? 'unknown'}: {humanize(verify.reason ?? 'entry does not match its seal')}.</span>
                  {goLedger && <button className="btn sm" onClick={goLedger}>Open the sealed entries</button>}
                </>
              : <span>Checking the seal chain…</span>}
          </p>
        </section>

        <div className="shield-stats" role="group" aria-label="Today. Select a figure to filter the activity.">
          <StatButton lead label="checked today" value={counts?.checked} on={need === 'all'} onClick={() => pick('all')} />
          <StatButton label="flagged" value={counts?.flagged} tone="warn" on={need === 'warn'} onClick={() => pick('warn')} />
          <StatButton label="high risk" value={counts?.high_risk} tone="bad" on={need === 'bad'} onClick={() => pick('bad')} />
          <StatButton label="tool calls" value={counts?.mcp} on={need === 'mcp'} onClick={() => pick('mcp')} />
          <StatButton label="in browser" value={counts?.browser} on={need === 'browser'} onClick={() => pick('browser')} />
        </div>

        <section aria-labelledby="activity-h">
          <SectionHead id="activity-h" title="Activity" accent />
          <div className="filterbar">
            <NeedFilter value={need} onChange={n => patch({ need: n === 'all' ? undefined : n, page: undefined })} />
            <WhenFilter value={when} onChange={w => patch({ when: w === 'today' ? undefined : w, page: undefined })} />
            <input
              type="search" aria-label="Search activity"
              placeholder="Search app, rule or summary"
              value={typed}
              onChange={e => setTyped(e.target.value)}
            />
          </div>
          <NewRows n={data?.newer ?? 0} noun="new event" onShow={showNew} />
          <h2 className="sr-only" tabIndex={-1} ref={headRef}>
            Activity, page {range.page} of {range.pages}
          </h2>
          <div className={`rows${feed.isPlaceholderData ? ' tl-busy' : ''}`} aria-busy={feed.isFetching}>
            {feed.isPending && <div className="empty-row" role="status">Loading activity…</div>}
            {error && <FeedError error={error.kind} status={'status' in error ? error.status : undefined} onRetry={() => void feed.refetch()} />}
            {data && matched === 0 && (
              <div className="empty-row">
                {data.total
                  ? <>
                    {filtered
                      ? <><b>No events match these filters.</b> Shield holds {plural(data.total, 'event')} in all; filters only change this view.</>
                      : <><b>Nothing recorded today.</b> Shield holds {plural(data.total, 'event')} from earlier days.</>}
                    {filtered
                      ? <button className="btn sm" onClick={reset}>Clear filters</button>
                      : <button className="btn sm" onClick={() => patch({ when: 'all', page: undefined })}>Show all time</button>}
                  </>
                  : 'Nothing recorded yet. Chat in Claude or ChatGPT with the capture proxy on, or call the MCP tools.'}
              </div>
            )}
            {shown.map(it => <Row key={it.id} item={it} onOpen={() => onOpen(it)} />)}
          </div>
          {data && matched > 0 && (
            <Pager page={range.page} pages={range.pages} from={range.from} to={range.to} total={matched} pageSize={range.size}
              noun={narrowed ? 'matching events' : 'events'} onPage={goPage} onPageSize={setSize}
              note={capped ? `Shield lists its latest ${data.capacity?.toLocaleString()} events. Older ones stay in the ledger file and its seal chain.` : undefined} />
          )}
        </section>
      </div>

      <aside className="shield-rail">
        <KeepsPanel policy={policy} goSettings={goSettings} />
      </aside>
    </div>
  )
}

function StatButton({ label, value, tone, lead, on, onClick }: {
  label: string; value: number | undefined; tone?: 'warn' | 'bad'; lead?: boolean; on: boolean; onClick: () => void
}) {
  return (
    <button className={`stat-btn ${tone ?? ''} ${lead ? 'lead' : ''} ${on ? 'on' : ''}`}
      aria-pressed={on} onClick={onClick}>
      <span className="value">{value === undefined ? '–' : value.toLocaleString()}</span>
      <span className="unit">{label}</span>
    </button>
  )
}

export function Row({ item, onOpen }: { item: Item; onOpen: () => void }) {
  const n = item.redactions?.length ?? 0
  return (
    <button className="shield-row" data-tier={item.tier} onClick={onOpen}>
      <span className="row-body">
        <span className="app-name">{item.surface}</span>
        <span className="what">{item.verb}</span>
        <span className="row-meta">
          {item.source === 'mcp' && <span className="tag info">Tool call</span>}
          {item.source === 'browser' && <span className="tag info">In browser</span>}
          {item.status === 'blocked' && <span className="tag bad">Blocked on this Mac</span>}
          {n > 0 && <span className="tag ok">{n === 1 ? '1 detail replaced' : `${n} details replaced`}</span>}
          {[...new Set((item.tools ?? []).map(toolLabel))].map(t => <span key={t} className="tag info">{t}</span>)}
          {item.flags.map(f => (
            <span key={f.rule} className={`tag ${flagTagClass(f.tier)}`}>{ruleLabel(f.rule)}</span>
          ))}
        </span>
        {item.reply && <span className="reply">{item.reply}</span>}
      </span>
      <span className="when">{item.ts}</span>
    </button>
  )
}

const MODE_EFFECT: Record<ShieldPolicy['mode'], string> = {
  redact: 'Replaced with a label before the message leaves this Mac.',
  block: 'Replaced before sending. Messages carrying credentials or executable files are stopped here.',
  observe: 'Recorded as rule matches only. Messages are sent unchanged.',
}

/** Each line is read from the ledger and the saved policy, so it states what
 * is on disk now, not what we intend. */
function KeepsPanel({ policy, goSettings }: {
  policy: ShieldPolicy | undefined
  goSettings: () => void
}) {
  const qc = useQueryClient()
  const privacy = useQuery({ queryKey: ['shield-privacy'], queryFn: fetchPrivacy, refetchInterval: 15_000 })
  // Undo only what is weaker than the default: Record only goes back to
  // redact, previews go off, and a stricter "block" stays. Tightening never
  // needs a confirmation.
  const restore = useMutation({
    mutationFn: () => savePolicy({
      keep_text: false,
      ...(policy?.mode === 'observe' ? { mode: 'redact' as const } : {}),
    }),
    onSuccess: data => {
      qc.setQueryData(['shield-policy'], data)
      void qc.invalidateQueries({ queryKey: ['shield-privacy'] })
    },
  })
  if (privacy.isError) {
    return <section className="panel"><p className="muted" role="alert">Can't read what Shield keeps: Shield isn't running. Start it with <code className="mono">byoai-shield</code>.</p></section>
  }
  if (!policy || !privacy.data) {
    return <section className="panel"><p className="muted" role="status">Reading what Shield keeps…</p></section>
  }
  const pv = privacy.data
  const weaker = policy.mode === 'observe' || policy.keep_text
  return (
    <section className="panel keeps" aria-labelledby="keeps-h">
      <SectionHead id="keeps-h" title="What Shield keeps"
        action={<button className="btn ghost sm" onClick={goSettings}>Change</button>} />
      {weaker && (
        <Banner tone="warn" role="status" className="keeps-alert">
          <span><b>Less private than the default.</b>{' '}
            {[policy.mode === 'observe' && 'Messages go out unchanged.',
              policy.keep_text && 'Previews of messages are kept.'].filter(Boolean).join(' ')}</span>
          <button className="btn sm" disabled={restore.isPending} onClick={() => restore.mutate()}>
            {restore.isPending ? 'Restoring…' : 'Restore defaults'}
          </button>
        </Banner>
      )}
      <dl className="keeps-list stacked">
        <dt>Message text</dt>
        <dd>
          {policy.keep_text
            ? 'A preview of up to 200 characters, with personal details removed.'
            : 'Not kept. Shield stores the length and a fingerprint only this Mac can recompute.'}
        </dd>
        <dt>Personal details</dt>
        <dd>{MODE_EFFECT[policy.mode]}</dd>
        <dt>History</dt>
        <dd>
          {plural(pv.ledger_rows, 'record')}, kept for {policy.retention_days} days.
          {pv.rows_past_retention > 0 && (
            <> {pv.rows_past_retention.toLocaleString()} {pv.rows_past_retention === 1 ? 'is' : 'are'} older
              and go at the next cleanup or restart.</>
          )}
        </dd>
        <dt>Sent to Coriqo</dt>
        <dd>Only if you ship the seal: its root, entry count and signed checkpoint. No messages, no rule matches.</dd>
      </dl>
      {pv.rows_with_text > 0 && <CleanupAlert privacy={pv} />}
    </section>
  )
}

function CleanupAlert({ privacy }: { privacy: ShieldPrivacy }) {
  const qc = useQueryClient()
  const scrub = useMutation({
    mutationFn: scrubStoredText,
    onSuccess: data => qc.setQueryData(['shield-privacy'], data),
  })
  return (
    <Banner tone="warn" className="keeps-alert">
      <span>
        {plural(privacy.rows_with_text, 'older record')} still{' '}
        {privacy.rows_with_text === 1 ? 'holds' : 'hold'} message text from before these settings.
      </span>
      <button className="btn sm" disabled={scrub.isPending} onClick={() => scrub.mutate()}>
        {scrub.isPending ? 'Removing…' : 'Remove stored text'}
      </button>
      {scrub.isError && <span role="alert">Cleanup failed: {scrub.error.message}</span>}
    </Banner>
  )
}
