// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { FeedQuery } from '@/api/shield'
import { Ledger } from './Ledger'
import { feedOf } from './feedFixtures'

const calls: FeedQuery[] = []
let reply: (q: FeedQuery) => unknown = () => ({})
vi.mock('@/api/shield', async orig => ({
  ...(await orig<object>()),
  fetchFeedPage: async (q: FeedQuery) => { calls.push(q); return reply(q) },
  fetchVerify: async () => ({ tamper_evident: true, entries: 299, merkle_root: 'a'.repeat(64), checkpoint: { height: 299, device_id: 'b'.repeat(64) } }),
}))

function mount(search = {}, patch = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const ui = (s: object) => (
    <QueryClientProvider client={qc}><Ledger search={{ tab: 'ledger', ...s }} patch={patch} onOpen={() => {}} /></QueryClientProvider>
  )
  const r = render(ui(search))
  return { patch, rerender: (s: object) => r.rerender(ui(s)) }
}

beforeEach(() => { calls.length = 0; reply = q => feedOf(299, q) })
afterEach(cleanup)

describe('Ledger paging', () => {
  it('asks the server for the sealed rows of the page in the URL and says which it shows', async () => {
    mount({ page: 2, size: 25 })
    await screen.findByText('Sent message 25')
    expect(calls[0]).toMatchObject({ limit: 25, offset: 25, sealed: true, need: 'all' })
    expect(screen.getByTestId('pager-range').textContent).toBe('Showing 26 to 50 of 299 sealed records')
    expect(screen.getByTestId('pager-page').textContent).toBe('Page 2 of 12')
    expect(screen.getAllByRole('row')).toHaveLength(26) // header + 25
  })
  it('puts page, size and filters in the URL through patch', async () => {
    const { patch } = mount({ page: 2 })
    await screen.findByTestId('pager')
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    expect(patch).toHaveBeenLastCalledWith({ page: 3 })
    fireEvent.click(screen.getByRole('button', { name: 'Previous page' }))
    expect(patch).toHaveBeenLastCalledWith({ page: undefined })
    fireEvent.change(screen.getByLabelText('Rows per page'), { target: { value: '50' } })
    expect(patch).toHaveBeenLastCalledWith({ size: 50, page: undefined })
    fireEvent.click(screen.getByRole('button', { name: 'Last 7 days' }))
    expect(patch).toHaveBeenLastCalledWith({ when: '7', page: undefined })
    fireEvent.click(screen.getByRole('button', { name: 'Flagged' }))
    expect(patch).toHaveBeenLastCalledWith({ need: 'warn', page: undefined })
  })
  it('sends the filters to the server so they count every sealed row', async () => {
    mount({ need: 'bad', when: '7' })
    await screen.findByTestId('pager')
    expect(calls[0]).toMatchObject({ sealed: true, need: 'bad' })
    expect(String(calls[0]?.since)).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(screen.getByTestId('pager-range').textContent).toContain('matching sealed records')
  })
  it('goes to the last page when the URL page is past the end, without a history step', async () => {
    reply = q => feedOf(60, q)
    const { patch } = mount({ page: 9 })
    await waitFor(() => expect(patch).toHaveBeenCalledWith({ page: 3 }, true))
  })
  it('offers new sealed records instead of moving the page', async () => {
    reply = q => feedOf(299, q, { newer: 4 })
    const { patch } = mount({ page: 2 })
    expect(await screen.findByText('4 new sealed records since you opened this page.')).toBeTruthy()
    await waitFor(() => expect(calls.some(c => c.anchor === 'i0')).toBe(true))
    fireEvent.click(screen.getByRole('button', { name: 'Show them' }))
    expect(patch).toHaveBeenLastCalledWith({ page: undefined })
  })
  it('keeps the rows while the next page loads', async () => {
    const m = mount()
    await screen.findByText('Sent message 0')
    reply = () => new Promise(() => {})
    m.rerender({ page: 2 })
    expect(screen.getByText('Sent message 0')).toBeTruthy()
    expect(document.querySelector('.tl-busy')).not.toBeNull()
  })
  it('says nothing is sealed yet when nothing is, and offers no pager', async () => {
    reply = q => feedOf(0, q)
    mount()
    await screen.findByText(/Nothing sealed yet/)
    expect(screen.queryByTestId('pager')).toBeNull()
  })
  it('says the filters hide everything, and clears them', async () => {
    reply = q => feedOf(0, q, { total: 40 })
    const { patch } = mount({ need: 'bad' })
    await screen.findByText('No sealed records match these filters.')
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(patch).toHaveBeenCalledWith({ need: undefined, when: undefined, page: undefined })
  })
  it('tells an unreachable Shield from an error answer from an unreadable one', async () => {
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
  it('names the cap so older sealed records are never dropped silently', async () => {
    reply = q => feedOf(120, q, { total: 400, capacity: 400 })
    mount()
    await screen.findByText(/sealed records of its latest 400 events/)
  })
})
