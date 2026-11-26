/**
 * Server-side paging shared by Timeline, Ledger and Trust: one hook for the
 * query, the anchor that keeps a page still while rows arrive, the redirect
 * from a page past the end and the focus move after a page change, plus the
 * banner and the three error states every list shows the same way.
 */
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { useCallback, useEffect, useRef, useState } from 'react'
import { fetchFeedPage } from '@/api/shield'
import type { FeedQuery } from '@/api/shield'
import type { ShieldSearch } from '@/routes/shield'
import { Banner, DEFAULT_PAGE_SIZE, plural } from './shared'

export type PatchSearch = (p: Partial<ShieldSearch>, replace?: boolean) => void

export function usePagedFeed({ scope, page, size, query, patch }: {
  /** Names the list in the query cache, so tabs never share an answer. */
  scope: string
  page: number
  size: number
  query: Omit<FeedQuery, 'limit' | 'offset' | 'anchor'>
  patch: PatchSearch
}) {
  // Pinned to the newest row on first load: rows that arrive later do not push
  // this page's rows down, they are offered as "N new".
  const [anchor, setAnchor] = useState<string | undefined>()
  const feed = useQuery({
    queryKey: ['shield-feed', scope, { page, size, anchor, ...query }],
    queryFn: () => fetchFeedPage({ ...query, limit: size, offset: (page - 1) * size, anchor }),
    placeholderData: keepPreviousData,
    gcTime: 0, // a cached answer is a stale newest row, which would re-pin the anchor
    refetchInterval: 3_000,
  })
  const data = feed.data
  const items = data?.items ?? []
  const matched = data?.matched ?? items.length
  const pages = Math.max(1, Math.ceil(matched / size))

  useEffect(() => {
    // Not from placeholder data: after "Show them" that is still the old newest row.
    if (!anchor && !feed.isPlaceholderData && data?.newest_id) setAnchor(data.newest_id)
  }, [anchor, feed.isPlaceholderData, data?.newest_id])

  // A page past the end (an old link, or a filter that shrank the list) lands on the last page.
  useEffect(() => {
    if (data && !feed.isPlaceholderData && matched > 0 && items.length === 0 && page > pages) patch({ page: pages > 1 ? pages : undefined }, true)
  }, [data, feed.isPlaceholderData, matched, items.length, page, pages, patch])

  const headRef = useRef<HTMLHeadingElement>(null)
  const goPage = useCallback((n: number) => {
    patch({ page: n > 1 ? n : undefined })
    // Keep the reader's place: the new page starts at its top, focus on the list.
    requestAnimationFrame(() => { headRef.current?.focus(); headRef.current?.scrollIntoView({ block: 'start' }) })
  }, [patch])
  const showNew = useCallback(() => { setAnchor(undefined); patch({ page: undefined }) }, [patch])
  const setSize = useCallback((s: number) => patch({ size: s === DEFAULT_PAGE_SIZE ? undefined : s, page: undefined }), [patch])

  // The range, page and size shown come from the answer on screen, so while the
  // next answer loads they still agree with the rows (not with the URL).
  const shownSize = data?.limit ?? size
  const shown = {
    size: shownSize,
    page: data ? Math.floor(data.offset / shownSize) + 1 : page,
    pages: Math.max(1, Math.ceil(matched / shownSize)),
    from: matched ? (data?.offset ?? 0) + 1 : 0,
    to: Math.min(matched, (data?.offset ?? 0) + items.length),
  }
  const err = feed.isError ? feed.error.message : ''
  return {
    feed, data, items, matched, pages, shown, headRef, goPage, showNew, setSize,
    capped: data?.capacity != null && data.total >= data.capacity,
    error: !feed.isError ? null
      : feed.error instanceof TypeError ? ({ kind: 'unreachable' } as const)
        : /^\d{3} from shield/.test(err) ? ({ kind: 'server', status: err.slice(0, 3) } as const)
          : ({ kind: 'unreadable' } as const),
  }
}

/** Rows arrived after this page was pinned; the reader decides when to move. */
export function NewRows({ n, noun, onShow }: { n: number; noun: string; onShow: () => void }) {
  if (!n) return null
  return (
    <Banner tone="info" className="tl-new" role="status">
      <span>{plural(n, noun)} since you opened this page.</span>
      <button className="btn sm" onClick={onShow}>Show them</button>
    </Banner>
  )
}

/** Unreachable, error answer and unreadable answer say different things and fix different things. */
export function FeedError({ error, status, onRetry }: {
  error: 'unreachable' | 'server' | 'unreadable'; status?: string; onRetry: () => void
}) {
  return (
    <p className="empty-row" role="alert">
      {error === 'unreachable' ? (
        <>
          <b>Can't reach Shield on this Mac.</b>
          Start it with <code className="mono">byoai-shield</code>, then try again.
        </>
      ) : error === 'server' ? (
        <>
          <b>Shield answered with an error ({status}).</b>
          Try again. If it keeps failing, restart <code className="mono">byoai-shield</code>.
        </>
      ) : (
        <>
          <b>Shield sent an answer this page can't read.</b>
          Restart <code className="mono">byoai-shield</code> and reload. If it continues, update the app and Shield to the same version.
        </>
      )}
      <button className="btn sm" onClick={onRetry}>Try again</button>
    </p>
  )
}
