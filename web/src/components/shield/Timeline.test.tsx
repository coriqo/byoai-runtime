// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { FeedQuery } from '@/api/shield'
import { Timeline } from './Timeline'
import { Pager } from './shared'

const calls: FeedQuery[] = []
let reply: (q: FeedQuery) => unknown = () => ({})
vi.mock('@/api/shield', async orig => ({
  ...(await orig<object>()),
  fetchFeedPage: async (q: FeedQuery) => { calls.push(q); return reply(q) },
}))

const row = (i: number) => ({
  id: `i${i}`, tier: 'ok', status: 'ok', surface: `App ${i}`, source: 'browser', date: '2026-09-01', ts: '10:00',
  verb: `Sent message ${i}`, flags: [], seal: '',
})
function feedOf(total: number, q: FeedQuery, extra: object = {}) {
  const items = Array.from({ length: Math.max(0, Math.min(q.limit, total - q.offset)) }, (_, k) => row(q.offset + k))
  return {
    counts: { checked: total, caught: 0, high_risk: 0 }, total, offset: q.offset, limit: q.limit,
    has_more: q.offset + q.limit < total, items, matched: total, newer: 0, capacity: 400, newest_id: 'i0', focus_item: null, ...extra,
  }
}

function mount(search = {}, patch = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const ui = (s: object) => (
    <QueryClientProvider client={qc}><Timeline search={{ tab: 'timeline', ...s }} patch={patch} onOpen={() => {}} /></QueryClientProvider>
  )
  const r = render(ui(search))
  return { patch, rerender: (s: object) => r.rerender(ui(s)) }
}

beforeEach(() => { calls.length = 0; reply = q => feedOf(312, q) })
afterEach(cleanup)

describe('Pager', () => {
  const base = { page: 2, pages: 3, from: 26, to: 50, total: 60, pageSize: 25 }
  it('says which rows are shown and which page this is', () => {
    render(<Pager {...base} onPage={() => {}} noun="events" />)
    expect(screen.getByTestId('pager-range').textContent).toBe('Showing 26 to 50 of 60 events')
    expect(screen.getByTestId('pager-page').textContent).toBe('Page 2 of 3')
  })
  it('moves one page and changes the size; ends are disabled', () => {
    const onPage = vi.fn(); const onPageSize = vi.fn()
    const { rerender } = render(<Pager {...base} onPage={onPage} onPageSize={onPageSize} />)
    fireEvent.click(screen.getByRole('button', { name: 'Previous page' }))
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    fireEvent.change(screen.getByLabelText('Rows per page'), { target: { value: '50' } })
    expect(onPage.mock.calls).toEqual([[1], [3]])
    expect(onPageSize).toHaveBeenCalledWith(50)
    rerender(<Pager {...base} page={1} from={1} to={25} onPage={onPage} />)
    expect((screen.getByRole('button', { name: 'Previous page' }) as HTMLButtonElement).disabled).toBe(true)
    rerender(<Pager {...base} page={3} onPage={onPage} />)
    expect((screen.getByRole('button', { name: 'Next page' }) as HTMLButtonElement).disabled).toBe(true)
  })
  it('renders nothing for an empty list and shows a caveat when given one', () => {
    const { container, rerender } = render(<Pager {...base} total={0} onPage={() => {}} />)
    expect(container.firstChild).toBeNull()
    rerender(<Pager {...base} onPage={() => {}} note="Older ones stay in the ledger." />)
    expect(screen.getByText('Older ones stay in the ledger.')).toBeTruthy()
  })
})

describe('Timeline paging', () => {
  it('asks the server for the page in the URL and shows the range', async () => {
    mount({ page: 3, size: 50 })
    await screen.findByText('Sent message 100')
    expect(calls[0]).toMatchObject({ limit: 50, offset: 100, need: 'all' })
    expect(screen.getByTestId('pager-range').textContent).toBe('Showing 101 to 150 of 312 events')
  })
  it('puts page, size and filters in the URL through patch', async () => {
    const { patch } = mount({ page: 2 })
    await screen.findByTestId('pager')
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    expect(patch).toHaveBeenLastCalledWith({ page: 3 })
    fireEvent.click(screen.getByRole('button', { name: 'Previous page' }))
    expect(patch).toHaveBeenLastCalledWith({ page: undefined })
    fireEvent.change(screen.getByLabelText('Rows per page'), { target: { value: '100' } })
    expect(patch).toHaveBeenLastCalledWith({ size: 100, page: undefined })
    fireEvent.click(screen.getByRole('button', { name: 'Flagged' }))
    expect(patch).toHaveBeenLastCalledWith({ need: 'warn', page: undefined })
  })
  it('pins the page to the newest row so arriving rows do not shift it', async () => {
    mount()
    await waitFor(() => expect(calls.some(c => c.anchor === 'i0')).toBe(true))
  })
  it('offers new events instead of moving the page', async () => {
    reply = q => feedOf(312, q, { newer: 3 })
    const { patch } = mount({ page: 2 })
    fireEvent.click(await screen.findByRole('button', { name: 'Show them' }))
    expect(patch).toHaveBeenLastCalledWith({ page: undefined })
    // it asks again without the anchor, to learn the new newest row
    await waitFor(() => {
      const firstAnchored = calls.findIndex(c => c.anchor)
      expect(firstAnchored).toBeGreaterThan(-1)
      expect(calls.slice(firstAnchored).some(c => !c.anchor)).toBe(true)
    })
    expect(screen.getByText('3 new events since you opened this page.')).toBeTruthy()
  })
  it('goes to the last page when the URL page is past the end', async () => {
    reply = q => feedOf(60, q)
    const { patch } = mount({ page: 9 })
    await waitFor(() => expect(patch).toHaveBeenCalledWith({ page: 3 }, true))
  })
  it('says why it is empty and clears filters', async () => {
    reply = q => feedOf(0, q, { total: 40, matched: 0 })
    const { patch } = mount({ need: 'bad' })
    await screen.findByText('No events match these filters.')
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(patch).toHaveBeenCalledWith({ need: undefined, when: undefined, page: undefined })
  })
  it('says nothing is recorded yet when Shield holds nothing', async () => {
    reply = q => feedOf(0, q)
    mount()
    await screen.findByText(/Nothing recorded yet/)
    expect(screen.queryByTestId('pager')).toBeNull()
  })
  it('keeps the list while the next page loads', async () => {
    const m = mount()
    await screen.findByText('Sent message 0')
    reply = () => new Promise(() => {})
    m.rerender({ page: 2 })
    expect(screen.getByText('Sent message 0')).toBeTruthy()
    expect(document.querySelector('.tl-busy')).not.toBeNull()
  })
  it('tells an unreachable Shield from an error answer', async () => {
    reply = () => { throw new TypeError('Failed to fetch') }
    mount()
    await screen.findByText("Can't reach Shield on this Mac.")
    cleanup()
    reply = () => { throw new Error('500 from shield (/feed)') }
    mount()
    await screen.findByText('Shield answered with an error (500).')
    expect(screen.getByRole('button', { name: 'Try again' })).toBeTruthy()
    cleanup()
    reply = () => { throw new Error('zod issue') }
    mount()
    await screen.findByText("Shield sent an answer this page can't read.")
  })
  it('warns when a focused interaction is gone, and shows the journey when it is not on the page', async () => {
    reply = q => feedOf(10, q, { focus_item: null })
    mount({ focus: 'gone' })
    await screen.findByText(/no longer in Shield's list/)
    cleanup()
    reply = q => feedOf(312, q, { focus_item: row(300) })
    mount({ page: 1, focus: 'i300' })
    await screen.findByText(/How this interaction became a record/)
  })
  it('notes the cap so older rows are never dropped silently', async () => {
    reply = q => feedOf(400, q)
    mount()
    await screen.findByText(/Shield lists its latest 400 events/)
  })
})
