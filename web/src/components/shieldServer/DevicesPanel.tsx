/**
 * Shield devices — the fleet table for the free, self-hosted Shield server.
 */
import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { fetchDevices, revokeDevice, type ShieldServerDevice } from '@/api/shieldServer'
import { useAuthWatch } from './AdminAuth'
import { ConfirmDialog, HashChip, SectionHead } from '@/components/shield/shared'

const POLL_MS = 30_000

function shortId(id: string): string {
  return id.length <= 12 ? id : `${id.slice(0, 8)}…${id.slice(-4)}`
}

function ago(iso: string | null): string {
  if (iso === null) return 'never'
  const t = Date.parse(iso)
  if (Number.isNaN(t)) return iso
  const mins = Math.max(0, Math.round((Date.now() - t) / 60_000))
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const h = Math.round(mins / 60)
  return h < 48 ? `${h}h ago` : `${Math.round(h / 24)}d ago`
}

export function DevicesPanel() {
  const qc = useQueryClient()
  const query = useQuery({
    queryKey: ['shield-server', 'devices'],
    queryFn: ({ signal }) => fetchDevices(signal),
    refetchInterval: POLL_MS,
  })
  useAuthWatch(query)

  const [confirming, setConfirming] = useState<ShieldServerDevice | null>(null)
  const revoke = useMutation({
    mutationFn: (deviceId: string) => revokeDevice(deviceId),
    onSuccess: () => {
      setConfirming(null)
      void qc.invalidateQueries({ queryKey: ['shield-server', 'devices'] })
    },
  })

  if (query.isPending) return <p className="empty-row" role="status">Loading devices…</p>
  if (query.isError) {
    return (
      <p className="empty-row" role="alert">
        Couldn't load devices: {query.error.message}. Check that the Shield server is running, then reload.
      </p>
    )
  }

  const devices = query.data.devices
  const counts = {
    protecting: devices.filter((d) => d.protecting === true).length,
    quiet: devices.filter((d) => d.protecting === false).length,
    unheard: devices.filter((d) => d.protecting === null).length,
    revoked: devices.filter((d) => d.revoked).length,
  }

  return (
    <section className="panel" aria-labelledby="shield-devices-h">
      <SectionHead
        id="shield-devices-h"
        title="Shield devices"
        accent
        help="Every Mac enrolled with this Shield server, and whether it's currently protecting."
      />
      {devices.length > 0 && (
        <div className="shield-stats wide" role="group" aria-label="Device status counts">
          <div className="stat-btn lead static">
            <span className="value">{devices.length}</span>
            <span className="unit">enrolled</span>
          </div>
          <div className="stat-btn static">
            <span className="value">{counts.protecting}</span>
            <span className="unit">protecting</span>
          </div>
          <div className="stat-btn warn static">
            <span className="value">{counts.quiet}</span>
            <span className="unit">quiet</span>
          </div>
          <div className="stat-btn warn static">
            <span className="value">{counts.unheard}</span>
            <span className="unit">not heard from</span>
          </div>
          <div className="stat-btn bad static">
            <span className="value">{counts.revoked}</span>
            <span className="unit">revoked</span>
          </div>
        </div>
      )}
      {devices.length === 0 ? (
        <p className="empty-row">
          <b>No devices enrolled yet.</b>
          Mint a token under Enrol a Mac and paste it into Shield's settings on that Mac.
        </p>
      ) : (
        <div className="table-scroll">
        <table className="table" aria-describedby="shield-devices-h">
          <thead>
            <tr>
              <th>Label</th>
              <th>Device id</th>
              <th>Last seen</th>
              <th>Status</th>
              <th>Policy version (running / assigned)</th>
              <th>Drift</th>
              <th>Revoked</th>
              <th aria-label="Actions" />
            </tr>
          </thead>
          <tbody>
            {devices.map((d) => (
              <tr key={d.device_id}>
                <td>{d.label ?? <span className="muted">Unlabelled</span>}</td>
                <td><HashChip value={d.device_id} noun="device id" /></td>
                <td>{ago(d.last_seen)}</td>
                <td>
                  {d.protecting === null ? (
                    <span className="tag unknown">Not heard from yet</span>
                  ) : d.protecting ? (
                    <span className="tag ok">Protecting</span>
                  ) : (
                    <>
                      <span className="tag warn">Quiet</span>
                      {d.reasons.length > 0 && <span className="muted setting-help">{d.reasons.join('; ')}</span>}
                    </>
                  )}
                </td>
                <td className="mono">
                  {d.policy_version ?? '—'} / {d.assigned_version ?? '—'}
                </td>
                <td>
                  {d.drift ? <span className="tag bad">Out of sync</span> : <span className="tag ok">In sync</span>}
                </td>
                <td>{d.revoked ? <span className="tag bad">Revoked</span> : <span className="muted">No</span>}</td>
                <td>
                  {!d.revoked && (
                    <button
                      className="btn ghost sm"
                      type="button"
                      onClick={() => setConfirming(d)}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      )}

      {confirming && (
        <ConfirmDialog
          title={`Revoke ${confirming.label ?? shortId(confirming.device_id)}?`}
          confirmLabel={revoke.isPending ? 'Revoking…' : 'Revoke device'}
          busy={revoke.isPending}
          onCancel={() => setConfirming(null)}
          onConfirm={() => revoke.mutate(confirming.device_id)}
        >
          <p>
            This device will be refused on its next request. It stops protecting immediately and
            cannot be un-revoked — re-enrol it with a fresh token if it should come back.
          </p>
          {revoke.isError && <p role="alert">Not revoked: {revoke.error.message}</p>}
        </ConfirmDialog>
      )}
    </section>
  )
}
