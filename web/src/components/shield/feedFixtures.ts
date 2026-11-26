import type { FeedQuery } from '@/api/shield'

/** A feed row as the server serves it; `seal` is set so it counts as sealed. */
export const row = (i: number, extra: object = {}) => ({
  id: `i${i}`, tier: 'ok', status: 'answered', surface: `App ${i}`, source: 'browser', date: '2026-09-01', ts: '10:00',
  verb: `Sent message ${i}`, flags: [], seal: `${String(i).padStart(4, '0')}abcdef0123456789abcdef`, ...extra,
})

/** The server's answer for `total` matching rows: the slice the query asks for. */
export function feedOf(total: number, q: FeedQuery, extra: object = {}) {
  const items = Array.from({ length: Math.max(0, Math.min(q.limit, total - q.offset)) }, (_, k) => row(q.offset + k))
  return {
    counts: { checked: total, caught: 0, high_risk: 0 }, total, offset: q.offset, limit: q.limit,
    has_more: q.offset + q.limit < total, items, matched: total, newer: 0, capacity: 400, newest_id: 'i0', focus_item: null, ...extra,
  }
}
