import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { setupServer } from 'msw/node'

import { PolicyPanel } from './PolicyPanel'
import { newTestQueryClient, renderWithClient } from './testUtils'
import {
  shieldServerHandlers,
  resetShieldServerMocks,
  seedDefaultPolicy,
  seedDeviceOverride,
} from '@/mocks/shieldServerHandlers'
import { ADMIN_TOKEN, DEFAULT_POLICY, SHIELD_DEVICES } from '@/mocks/shieldServerFixtures'
import { clearStoredAdminToken, setStoredAdminToken } from '@/api/shieldServer'

const server = setupServer(...shieldServerHandlers)
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => {
  server.resetHandlers()
  resetShieldServerMocks()
  clearStoredAdminToken()
})
afterAll(() => server.close())

describe('PolicyPanel — stop managing', () => {
  it('does not call DELETE until the confirm dialog is accepted', async () => {
    setStoredAdminToken(ADMIN_TOKEN)
    let deleteCalls = 0
    server.events.on('request:match', ({ request }) => {
      if (request.method === 'DELETE' && request.url.includes('/policy')) deleteCalls += 1
    })

    render(renderWithClient(<PolicyPanel />))

    const stopButton = await screen.findByRole('button', { name: /stop managing/i })
    fireEvent.click(stopButton)

    // The confirm dialog appears; the DELETE must not have fired yet.
    expect(await screen.findByRole('alertdialog')).toBeTruthy()
    expect(deleteCalls).toBe(0)

    fireEvent.click(screen.getByRole('button', { name: /yes, stop managing/i }))

    await waitFor(() => expect(deleteCalls).toBe(1))
  })

  it('cancelling the confirm dialog never issues the DELETE', async () => {
    setStoredAdminToken(ADMIN_TOKEN)
    let deleteCalls = 0
    server.events.on('request:match', ({ request }) => {
      if (request.method === 'DELETE' && request.url.includes('/policy')) deleteCalls += 1
    })

    render(renderWithClient(<PolicyPanel />))
    fireEvent.click(await screen.findByRole('button', { name: /stop managing/i }))
    fireEvent.click(await screen.findByRole('button', { name: /cancel/i }))

    expect(deleteCalls).toBe(0)
  })
})

describe('PolicyPanel — per-device override editor resets when the device changes', () => {
  it('opening remove-confirm on device A, then switching to B, never DELETEs B', async () => {
    setStoredAdminToken(ADMIN_TOKEN)
    const deviceA = SHIELD_DEVICES[0]!
    const deviceB = SHIELD_DEVICES[1]!
    const defaultDocument = DEFAULT_POLICY!.document
    seedDeviceOverride(deviceA.device_id, {
      document: { ...defaultDocument, device_id: deviceA.device_id, version: 10 },
      signature: DEFAULT_POLICY!.signature,
    })

    const deleteUrls: string[] = []
    server.events.on('request:match', ({ request }) => {
      if (request.method === 'DELETE' && request.url.includes('/policy')) deleteUrls.push(request.url)
    })

    render(renderWithClient(<PolicyPanel />))

    const select = await screen.findByLabelText('Device', { exact: true })
    fireEvent.change(select, { target: { value: deviceA.device_id } })

    const removeButton = await screen.findByRole('button', { name: /remove override/i })
    fireEvent.click(removeButton)
    expect(await screen.findByRole('alertdialog')).toBeTruthy()

    // Switch to device B WITHOUT confirming or cancelling device A's dialog.
    fireEvent.change(select, { target: { value: deviceB.device_id } })

    // Wait past the loading transition to B's own SETTLED state (it has no
    // override) — without `key={selected}` on DeviceOverrideEditor, React
    // reuses the same component instance across the switch, so device A's
    // leftover `confirmRemove: true` local state would re-render the confirm
    // dialog again once B's query resolves, not just during the brief
    // in-between loading state.
    await screen.findByText(/currently follows the tenant default/i)

    expect(screen.queryByRole('alertdialog')).toBeNull()
    expect(deleteUrls.some((url) => url.includes(deviceB.device_id))).toBe(false)
    expect(deleteUrls).toHaveLength(0)
  })
})

describe('PolicyPanel — a background refetch never wipes unsaved edits', () => {
  it('keeps a dirty edit through a refetch, and shows a reload banner once the version moves', async () => {
    setStoredAdminToken(ADMIN_TOKEN)
    const qc = newTestQueryClient()

    render(renderWithClient(<PolicyPanel />, qc))

    // The fixture default policy is mode "redact".
    const redactRadio = await screen.findByRole('radio', { name: 'Check and act' })
    await waitFor(() => expect(redactRadio).toHaveProperty('checked', true))

    // Dirty the form: switch to "block" without saving.
    fireEvent.click(screen.getByRole('radio', { name: 'Check and block high-risk sends' }))
    expect(screen.getByRole('radio', { name: 'Check and block high-risk sends' })).toHaveProperty('checked', true)

    // A background refetch with NOTHING changed server-side must not touch
    // the dirty edit at all.
    await qc.invalidateQueries({ queryKey: ['shield-server', 'policy', 'default'] })
    await waitFor(() => expect(qc.isFetching()).toBe(0))
    expect(screen.getByRole('radio', { name: 'Check and block high-risk sends' })).toHaveProperty('checked', true)
    expect(screen.queryByText(/changed on the server/i)).toBeNull()

    // Now the server actually moves (another admin's save) while still dirty
    // here: the edit must still survive, but a reload banner must appear.
    const newVersion = (DEFAULT_POLICY!.document.version ?? 0) + 1
    seedDefaultPolicy({
      document: { ...DEFAULT_POLICY!.document, version: newVersion, policy: {
        ...DEFAULT_POLICY!.document.policy!, mode: 'observe',
      } },
      signature: DEFAULT_POLICY!.signature,
    })
    await qc.invalidateQueries({ queryKey: ['shield-server', 'policy', 'default'] })
    await waitFor(() => expect(qc.isFetching()).toBe(0))

    expect(screen.getByRole('radio', { name: 'Check and block high-risk sends' })).toHaveProperty('checked', true)
    expect(await screen.findByText(new RegExp(`changed on the server \\(v ${newVersion}\\)`, 'i')))
      .toBeTruthy()

    // Reloading takes the server's version, discarding the local edit.
    fireEvent.click(screen.getByRole('button', { name: /reload/i }))
    await waitFor(() => expect(screen.getByRole('radio', { name: 'Record only' })).toHaveProperty('checked', true))
    expect(screen.queryByText(/changed on the server/i)).toBeNull()
  })
})
