// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { FeedQuery } from '@/api/shield'
import { Trust } from './Trust'
import { feedOf } from './feedFixtures'

const calls: FeedQuery[] = []
let reply: (q: FeedQuery) => unknown = () => ({})
vi.mock('@/api/shield', async orig => ({
  ...(await orig<object>()),
  fetchFeedPage: async (q: FeedQuery) => { calls.push(q); return reply(q) },
  fetchPrivacy: async () => ({ ledger_rows: 0, rows_past_retention: 0, rows_with_text: 0, sealed_with_text: 0 }),
}))

const summary = { checked: 312, flagged: 41, high_risk: 7, mcp: 90, browser: 200 }
const verify = { tamper_evident: true, entries: 312, merkle_root: 'a'.repeat(64), checkpoint: { height: 312, device_id: 'b'.repeat(64) } }

function mount(search = {}, patch = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const ui = (s: object) => (
    <QueryClientProvider client={qc}>
      <Trust verify={verify as never} policy={undefined} search={s} patch={patch} onOpen={() => {}} goSettings={() => {}} />
    </QueryClientProvider>
  )
  const r = render(ui(search))
  return { patch, rerender: (s: object) => r.rerender(ui(s)) }
}

beforeEach(() => { calls.length = 0; reply = q => feedOf(60, q, { summary }) })
afterEach(() => { cleanup(); vi.useRealTimers() })

describe('Trust server paging', () => {
  it('asks the server for the page, today by default, with exact counts', async () => {
    mount({ page: 2 })
    await screen.findByText('Sent message 25')
    expect(calls[0]).toMatchObject({ limit: 25, offset: 25, need: 'all', q: '' })
    expect(String(calls[0]?.since)).toMatch(/^\d{4}-\d{2}-\d{2}$/)
    expect(calls[0]?.summarySince).toBe(calls[0]?.since)
    expect(screen.getByTestId('pager-range').textContent).toBe('Showing 26 to 50 of 60 events')
  })
  it('shows the server counts for every row held, not the page', async () => {
    mount()
    await screen.findByText('312')
    expect(screen.getByText('41')).toBeTruthy()
    expect(screen.getByText('7')).toBeTruthy()
    // high risk wins the sentence
    expect(screen.getByText('7 messages blocked or flagged high risk today.')).toBeTruthy()
    cleanup()
    reply = q => feedOf(60, q, { summary: { ...summary, high_risk: 0 } })
    mount()
    expect(await screen.findByText('Personal details flagged in 41 messages today.')).toBeTruthy()
  })
  it('does not claim a clean day before the counts arrive', async () => {
    reply = () => new Promise(() => {})
    mount()
    expect(screen.getByText(/Counting today/)).toBeTruthy()
    expect(screen.queryByText('No exceptions today.')).toBeNull()
  })
  it('keeps the counts while a filter narrows the list', async () => {
    reply = q => feedOf(q.need === 'warn' ? 41 : 312, q, { summary })
    mount({ need: 'warn' })
    await screen.findByTestId('pager')
    expect(screen.getByTestId('pager-range').textContent).toContain('of 41 matching events')
    expect(screen.getByText('312')).toBeTruthy()
  })
  it('puts page, size, filters and a figure click in the URL', async () => {
    const { patch } = mount({ page: 2 })
    await screen.findByTestId('pager')
    fireEvent.click(screen.getByRole('button', { name: 'Next page' }))
    expect(patch).toHaveBeenLastCalledWith({ page: 3 })
    fireEvent.change(screen.getByLabelText('Rows per page'), { target: { value: '100' } })
    expect(patch).toHaveBeenLastCalledWith({ size: 100, page: undefined })
    fireEvent.click(screen.getByRole('button', { name: 'Last 30 days' }))
    expect(patch).toHaveBeenLastCalledWith({ when: '30', page: undefined })
    fireEvent.click(screen.getByRole('button', { name: /flagged/ }))
    expect(patch).toHaveBeenLastCalledWith({ need: 'warn', when: undefined, page: undefined })
  })
  it('sends the search to the server once typing pauses, replacing the history step', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const { patch } = mount()
    await screen.findByTestId('pager')
    fireEvent.change(screen.getByLabelText('Search activity'), { target: { value: 'card' } })
    expect(patch).not.toHaveBeenCalled()
    await act(async () => { await vi.advanceTimersByTimeAsync(400) })
    expect(patch).toHaveBeenLastCalledWith({ q: 'card', page: undefined }, true)
  })
  it('offers new events instead of moving the page', async () => {
    reply = q => feedOf(60, q, { summary, newer: 2 })
    const { patch } = mount({ page: 2 })
    expect(await screen.findByText('2 new events since you opened this page.')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Show them' }))
    expect(patch).toHaveBeenLastCalledWith({ page: undefined })
  })
  it('goes to the last page when the URL page is past the end', async () => {
    reply = q => feedOf(30, q, { summary })
    const { patch } = mount({ page: 9 })
    await waitFor(() => expect(patch).toHaveBeenCalledWith({ page: 2 }, true))
  })
  it('says why it is empty: nothing today, filters, or nothing recorded', async () => {
    reply = q => feedOf(0, q, { summary, total: 40 })
    const { patch } = mount()
    await screen.findByText('Nothing recorded today.')
    fireEvent.click(screen.getByRole('button', { name: 'Show all time' }))
    expect(patch).toHaveBeenLastCalledWith({ when: 'all', page: undefined })
    cleanup()
    const m = mount({ need: 'bad' })
    await screen.findByText('No events match these filters.')
    fireEvent.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(m.patch).toHaveBeenLastCalledWith({ need: undefined, when: undefined, q: undefined, page: undefined })
    cleanup()
    reply = q => feedOf(0, q, { summary })
    mount()
    await screen.findByText(/Nothing recorded yet/)
  })
  it('tells unreachable from an error answer, and retries', async () => {
    reply = () => { throw new TypeError('Failed to fetch') }
    mount()
    await screen.findByText("Can't reach Shield on this Mac.")
    cleanup()
    reply = () => { throw new Error('503 from shield (/feed)') }
    mount()
    await screen.findByText('Shield answered with an error (503).')
    expect(screen.getByRole('button', { name: 'Try again' })).toBeTruthy()
  })
  it('keeps the list while the next page loads', async () => {
    const m = mount()
    await screen.findByText('Sent message 0')
    reply = () => new Promise(() => {})
    m.rerender({ page: 2 })
    expect(screen.getByText('Sent message 0')).toBeTruthy()
    expect(document.querySelector('.tl-busy')).not.toBeNull()
  })
})
