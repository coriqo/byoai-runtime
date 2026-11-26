/**
 * Timeline: everything Shield recorded, grouped by day, newest first, one page
 * at a time. Paging and the two filters run on the server (so a filter counts
 * every row Shield holds, not just the page on screen) and live in the URL:
 * `?tab=timeline&page=3&size=50&when=7&need=warn`, so a reload or Back lands on
 * the same page. Arriving with `focus` (from a row's "Open in Timeline") shows
 * that interaction's journey at the top and highlights its step.
 */
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { fetchFeedPage } from '@/api/shield'
import type { ShieldSearch } from '@/routes/shield'
import {
  Banner, DEFAULT_PAGE_SIZE, HashChip, NeedFilter, Pager, WhenFilter, flagTagClass, plural, ruleLabel, tierLabel, tierTagClass, today, whenStart,
} from './shared'
import type { Item, Need, When } from './shared'

export function Timeline({ search, patch, onOpen }: {
  search: ShieldSearch
  patch: (p: Partial<ShieldSearch>, replace?: boolean) => void
  onOpen: (it: Item) => void
}) {
  const { focus } = search
  const need: Need = search.need ?? 'all'
  const when: When = search.when ?? 'all'
  const size = search.size ?? DEFAULT_PAGE_SIZE
  const page = search.page ?? 1
  // Pinned to the newest row on first load: rows that arrive later do not push
  // this page's rows down, they are offered as "N new events".
  const [anchor, setAnchor] = useState<string | undefined>()
  const since = whenStart(when)

  const feed = useQuery({
    queryKey: ['shield-timeline', { page, size, need, since, anchor, focus }],
    queryFn: () => fetchFeedPage({ limit: size, offset: (page - 1) * size, need, since, anchor, focus }),
    placeholderData: keepPreviousData,
    gcTime: 0, // a cached answer is a stale newest row, which would re-pin the anchor
    refetchInterval: 3_000,
  })
  const data = feed.data
  const items = data?.items ?? []
  const matched = data?.matched ?? items.length
  const pages = Math.max(1, Math.ceil(matched / size))
  const focused = data?.focus_item ?? undefined

  useEffect(() => {
    // Not from placeholder data: after "Show them" that is still the old newest row.
    if (!anchor && !feed.isPlaceholderData && data?.newest_id) setAnchor(data.newest_id)
  }, [anchor, feed.isPlaceholderData, data?.newest_id])

  // A page past the end (an old link, or a filter that shrank the list) lands on the last page.
  useEffect(() => {
    if (data && !feed.isPlaceholderData && matched > 0 && items.length === 0 && page > pages) patch({ page: pages > 1 ? pages : undefined }, true)
  }, [data, feed.isPlaceholderData, matched, items.length, page, pages, patch])

  useEffect(() => {
    if (!focused) return
    document.getElementById(`tl-${focused.id}`)?.scrollIntoView({ block: 'center' })
  }, [focused?.id])

  const headRef = useRef<HTMLHeadingElement>(null)
  const goPage = (n: number) => {
    patch({ page: n > 1 ? n : undefined })
    // Keep the reader's place: the new page starts at its top, focus on the list.
    requestAnimationFrame(() => { headRef.current?.focus(); headRef.current?.scrollIntoView({ block: 'start' }) })
  }
  const filtered = need !== 'all' || when !== 'all'
  const showNew = () => { setAnchor(undefined); patch({ page: undefined }) }

  const days = new Map<string, Item[]>()
  for (const it of items) {
    const d = it.date || 'Undated'
    days.set(d, [...(days.get(d) ?? []), it])
  }
  const t = today()
  // The range, page and size shown come from the answer on screen, so while the
  // next answer loads they still agree with the rows (not with the URL).
  const shownSize = data?.limit ?? size
  const shownPage = data ? Math.floor(data.offset / shownSize) + 1 : page
  const shownPages = Math.max(1, Math.ceil(matched / shownSize))
  const from = matched ? (data?.offset ?? 0) + 1 : 0
  const to = Math.min(matched, (data?.offset ?? 0) + items.length)
  const err = feed.isError ? feed.error.message : ''
  const unreachable = feed.error instanceof TypeError
  const serverError = /^\d{3} from shield/.test(err)
  const capped = data?.capacity != null && data.total >= data.capacity

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

      {!!data?.newer && (
        <Banner tone="info" className="tl-new" role="status">
          <span>{plural(data.newer, 'new event')} since you opened this page.</span>
          <button className="btn sm" onClick={showNew}>Show them</button>
        </Banner>
      )}

      {feed.isError && (
        <p className="empty-row" role="alert">
          {unreachable ? (
            <>
              <b>Can't reach Shield on this Mac.</b>
              Start it with <code className="mono">byoai-shield</code>, then try again.
            </>
          ) : serverError ? (
            <>
              <b>Shield answered with an error ({err.slice(0, 3)}).</b>
              Try again. If it keeps failing, restart <code className="mono">byoai-shield</code>.
            </>
          ) : (
            <>
              <b>Shield sent an answer this page can't read.</b>
              Restart <code className="mono">byoai-shield</code> and reload. If it continues, update the app and Shield to the same version.
            </>
          )}
          <button className="btn sm" onClick={() => void feed.refetch()}>Try again</button>
        </p>
      )}
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
        <Pager page={shownPage} pages={shownPages} from={from} to={to} total={matched} pageSize={shownSize} noun={filtered ? 'matching events' : 'events'}
          onPage={goPage} onPageSize={s => patch({ size: s === DEFAULT_PAGE_SIZE ? undefined : s, page: undefined })}
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
