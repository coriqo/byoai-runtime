/**
 * Timeline: everything Shield recorded, grouped by day, newest first, one page
 * at a time. Paging and the two filters run on the server (so a filter counts
 * every row Shield holds, not just the page on screen) and live in the URL:
 * `?tab=timeline&page=3&size=50&when=7&need=warn`, so a reload or Back lands on
 * the same page. Arriving with `focus` (from a row's "Open in Timeline") shows
 * that interaction's journey at the top and highlights its step.
 */
import { useEffect } from 'react'
import type { ReactNode } from 'react'
import type { ShieldSearch } from '@/routes/shield'
import { FeedError, NewRows, usePagedFeed } from './paging'
import type { PatchSearch } from './paging'
import {
  Banner, DEFAULT_PAGE_SIZE, HashChip, NeedFilter, Pager, WhenFilter, flagTagClass, plural, ruleLabel, tierLabel, tierTagClass, today, whenStart,
} from './shared'
import type { Item, Need, When } from './shared'

export function Timeline({ search, patch, onOpen }: {
  search: ShieldSearch
  patch: PatchSearch
  onOpen: (it: Item) => void
}) {
  const { focus } = search
  const need: Need = search.need ?? 'all'
  const when: When = search.when ?? 'all'
  const size = search.size ?? DEFAULT_PAGE_SIZE
  const page = search.page ?? 1
  const since = whenStart(when)
  const { feed, data, items, matched, pages, shown, headRef, goPage, showNew, setSize, capped, error } = usePagedFeed({
    scope: 'timeline', page, size, patch, query: { need, since, focus },
  })
  const focused = data?.focus_item ?? undefined

  useEffect(() => {
    if (!focused) return
    document.getElementById(`tl-${focused.id}`)?.scrollIntoView({ block: 'center' })
  }, [focused?.id])

  const filtered = need !== 'all' || when !== 'all'

  const days = new Map<string, Item[]>()
  for (const it of items) {
    const d = it.date || 'Undated'
    days.set(d, [...(days.get(d) ?? []), it])
  }
  const t = today()
  return (
    <div className="shield-timeline">
      {focus && data && !focused && (
        <Banner tone="warn">
          <span>That interaction is no longer in Shield's list. Shield keeps the latest {data.capacity ?? 400}; its sealed entry stays in the ledger.</span>
          <button className="btn sm" onClick={() => patch({ focus: undefined })}>Dismiss</button>
        </Banner>
      )}
      {focused && <Journey it={focused} onClose={() => patch({ focus: undefined })} onOpen={() => onOpen(focused)} />}

      <div className="filterbar">
        <WhenFilter value={when} onChange={w => patch({ when: w === 'all' ? undefined : w, page: undefined })} />
        <NeedFilter value={need} onChange={n => patch({ need: n === 'all' ? undefined : n, page: undefined })} />
      </div>

      <NewRows n={data?.newer ?? 0} noun="new event" onShow={showNew} />

      {error && <FeedError error={error.kind} status={'status' in error ? error.status : undefined} onRetry={() => void feed.refetch()} />}
      {feed.isPending && <p className="empty-row" role="status">Loading the timeline…</p>}
      {data && matched === 0 && (
        <p className="empty-row">
          {data.total
            ? <>
              <b>No events match these filters.</b>
              Shield holds {plural(data.total, 'event')} in all; filters only change this view.
              <button className="btn sm" onClick={() => patch({ need: undefined, when: undefined, page: undefined })}>Clear filters</button>
            </>
            : 'Nothing recorded yet. Start the capture proxy and chat, or call the MCP tools.'}
        </p>
      )}

      <div aria-busy={feed.isFetching} className={feed.isPlaceholderData ? 'tl-busy' : undefined}>
        <h2 className="sr-only" tabIndex={-1} ref={headRef}>
          Timeline, page {page} of {pages}
        </h2>
        {[...days.entries()].map(([d, rows]) => (
          <section key={d} className="tl-day">
            <h2 className="label">{d === t ? 'Today' : d}</h2>
            <ol className="tl-list">
              {rows.map(it => (
                <li key={it.id} id={`tl-${it.id}`} data-tier={it.tier}
                  className={it.id === focus ? 'focused' : undefined}>
                  <button className="tl-step" onClick={() => patch({ focus: it.id })}>
                    <span className="tl-top">
                      <span>
                        <b>{it.surface}</b>
                        {it.tier !== 'ok' && <> <span className={`tag ${tierTagClass(it.tier)}`}>{tierLabel(it)}</span></>}
                      </span>
                      <span className="when">{it.ts}</span>
                    </span>
                    <span className="muted">{it.verb}</span>
                    {it.flags.length > 0 && (
                      <span className="row-meta">
                        {it.flags.map(f => (
                          <span key={f.rule} className={`tag ${flagTagClass(f.tier)}`}>{ruleLabel(f.rule)}</span>
                        ))}
                      </span>
                    )}
                  </button>
                </li>
              ))}
            </ol>
          </section>
        ))}
      </div>

      {data && matched > 0 && (
        <Pager page={shown.page} pages={shown.pages} from={shown.from} to={shown.to} total={matched} pageSize={shown.size} noun={filtered ? 'matching events' : 'events'}
          onPage={goPage} onPageSize={setSize}
          note={capped ? `Shield lists its latest ${data.capacity?.toLocaleString()} events. Older ones stay in the ledger file and its seal chain.` : undefined} />
      )}
    </div>
  )
}

/** How one interaction became evidence: sent → checked → outcome → sealed. */
function Journey({ it, onClose, onOpen }: { it: Item; onClose: () => void; onOpen: () => void }) {
  const flags = it.flags.map(f => ruleLabel(f.rule))
  const n = it.redactions?.length ?? 0
  const outcome = it.status === 'blocked'
    ? { dot: 'r', title: 'Blocked on this Mac', body: 'The message never reached the AI app.' }
    : it.status === 'running'
      ? { dot: 'y', title: 'Still running', body: '' }
      : it.status === 'failed'
        ? { dot: 'r', title: 'The call failed', body: '' }
        : {
          dot: 'g',
          title: n ? `Sent with ${n === 1 ? '1 detail' : `${n} details`} replaced` : 'Sent',
          body: it.reply ?? (it.response_stream ? 'Reply streamed back.' : ''),
        }
  const steps: { dot: string; title: string; body: ReactNode }[] = [
    { dot: 'g', title: it.source === 'mcp' ? 'The agent called a tool' : it.source === 'browser' ? 'A message was sent in the browser' : 'A message was sent', body: it.verb },
    {
      dot: it.tier === 'bad' ? 'r' : flags.length ? 'y' : 'g',
      title: flags.length ? 'Shield checked it: rules matched' : 'Shield checked it: nothing matched',
      body: flags.join(' · '),
    },
    outcome,
    ...(it.seal
      ? [{
        dot: 'g', title: 'Sealed',
        body: <>
          The record and its proof stay on this Mac{it.latency_ms ? ` (${Math.round(it.latency_ms)} ms)` : ''}.{' '}
          <HashChip value={it.seal} noun="seal" short={16} />
        </>,
      }]
      : []),
  ]
  return (
    <section className="panel journey" aria-labelledby="journey-h">
      <div className="panel-head">
        <h2 className="label" id="journey-h">How this interaction became a record · {it.date} {it.ts}</h2>
        <span className="spacer" />
        <button className="btn ghost sm" onClick={onOpen}>Details</button>
        <button className="btn ghost sm" onClick={onClose} aria-label="Close journey">Close</button>
      </div>
      <ol className="journey-steps">
        {steps.map(s => (
          <li key={s.title} data-dot={s.dot}>
            <b>{s.title}</b>
            {s.body ? <p>{s.body}</p> : null}
          </li>
        ))}
      </ol>
    </section>
  )
}
