/**
 * Shield policy — tenant default editor plus per-device overrides
 * (Phase 1.5 console section).
 */
import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  deleteDefaultPolicy,
  deleteDevicePolicy,
  fetchDefaultPolicy,
  fetchDevicePolicy,
  fetchDevices,
  saveDefaultPolicy,
  saveDevicePolicy,
  validateLockedKeys,
  validatePolicyDoc,
  type ShieldServerPolicyEnvelope,
} from '@/api/shieldServer'
import { useAuthWatch } from './AdminAuth'
import { defaultPolicyDoc, PolicyForm, type PolicyFormValue } from './PolicyForm'
import { Banner, ConfirmDialog, HashChip, SectionHead } from '@/components/shield/shared'

/** Local edit state tracks `managed_by` alongside the policy/locked
 * `PolicyForm` edits, even though `PolicyForm` itself doesn't expose a field
 * for it yet — the server's PUT requires it (see `_policy_body` on the
 * backend), so the value the tenant/device already has is round-tripped
 * unchanged on every save rather than silently dropped. */
interface FormState extends PolicyFormValue {
  readonly managedBy: string
}

function toFormValue(
  policy: ReturnType<typeof defaultPolicyDoc> | null,
  locked: string[],
  managedBy: string | null,
): FormState {
  return { policy: policy ?? defaultPolicyDoc(), locked, managedBy: managedBy ?? '' }
}

/** Keeps a `FormState` in sync with a polled server envelope WITHOUT
 * clobbering unsaved edits: a background refetch (react-query's default
 * `refetchOnWindowFocus`, the 30s device poll invalidating this query too,
 * ...) used to always overwrite `form` from `query.data` on every fetch, so
 * typing into the policy editor and then merely switching tabs and back
 * could silently wipe what you'd typed.
 *
 * Rule: only reset the form from the server while it ISN'T dirty. Once the
 * admin has touched the form, a later fetch is only ever compared, never
 * applied — if its `version` has moved on (someone else saved, or this
 * admin saved from another tab), `changedOnServer` goes true and the caller
 * shows "this changed on the server, reload?" instead of silently doing
 * either "discard the fetch" or "discard the edit" on the admin's behalf.
 */
function useServerSyncedForm(envelope: ShieldServerPolicyEnvelope | undefined) {
  const [form, setFormState] = useState<FormState | null>(null)
  const [dirty, setDirty] = useState(false)
  const [syncedVersion, setSyncedVersion] = useState<number | null>(null)

  useEffect(() => {
    if (!envelope || dirty) return
    setFormState(toFormValue(envelope.policy, envelope.locked, envelope.managed_by))
    setSyncedVersion(envelope.version)
  }, [envelope, dirty])

  const setForm = (next: FormState) => {
    setDirty(true)
    setFormState(next)
  }

  /** Discard local edits and take the latest server state — what "Reload"
   * on the changed-on-server banner does. */
  const reload = () => {
    if (envelope) {
      setFormState(toFormValue(envelope.policy, envelope.locked, envelope.managed_by))
      setSyncedVersion(envelope.version)
    }
    setDirty(false)
  }

  /** A save just landed: the form's own edits are now what the server holds
   * — clear dirty and adopt the version it was saved at, rather than
   * waiting for the next poll to notice. */
  const markSaved = (saved: ShieldServerPolicyEnvelope) => {
    setDirty(false)
    setSyncedVersion(saved.version)
  }

  const changedOnServer = dirty && envelope !== undefined && envelope.version !== syncedVersion

  return { form, setForm, dirty, changedOnServer, reload, markSaved }
}

function ChangedOnServerBanner({
  version, onReload,
}: { version: number | null; onReload: () => void }) {
  return (
    <Banner tone="warn" role="status">
      <span>This policy changed on the server (v {version ?? 'unknown'}). Reload?</span>
      <button className="btn ghost sm" type="button" onClick={onReload}>
        Reload
      </button>
    </Banner>
  )
}

export function PolicyPanel() {
  const qc = useQueryClient()
  const query = useQuery({
    queryKey: ['shield-server', 'policy', 'default'],
    queryFn: ({ signal }) => fetchDefaultPolicy(signal),
  })
  useAuthWatch(query)

  const { form, setForm, changedOnServer, reload, markSaved } = useServerSyncedForm(query.data)

  const save = useMutation({
    mutationFn: (next: FormState) =>
      saveDefaultPolicy({ policy: next.policy, locked: next.locked }, next.managedBy),
    onSuccess: (data) => {
      qc.setQueryData(['shield-server', 'policy', 'default'], data)
      markSaved(data)
      void qc.invalidateQueries({ queryKey: ['shield-server', 'devices'] })
    },
  })

  const [confirmStop, setConfirmStop] = useState(false)
  const stopManaging = useMutation({
    mutationFn: () => deleteDefaultPolicy(),
    onSuccess: (data) => {
      qc.setQueryData(['shield-server', 'policy', 'default'], data)
      markSaved(data)
      setConfirmStop(false)
      void qc.invalidateQueries({ queryKey: ['shield-server', 'devices'] })
    },
  })

  if (query.isPending || form === null) {
    return <p className="empty-row" role="status">Loading policy…</p>
  }
  if (query.isError) {
    return (
      <p className="empty-row" role="alert">
        Couldn't load the tenant policy: {query.error.message}
      </p>
    )
  }

  const errors = [...validatePolicyDoc(form.policy), ...validateLockedKeys(form.locked)]
  const envelope = query.data

  return (
    <section className="panel" aria-labelledby="shield-policy-h">
      <SectionHead
        id="shield-policy-h"
        title="Tenant default policy"
        accent
        help="What every enrolled device does by default. A device follows this unless it has its own override below."
      />

      <dl className="keeps-list stacked">
        <dt>Version</dt>
        <dd className="mono">{envelope.version ?? 'unmanaged'}</dd>
        <dt>Signing key</dt>
        <dd>{envelope.key_id ? <HashChip value={envelope.key_id} noun="signing key id" /> : <span className="muted">not signed yet</span>}</dd>
        <dt>Managed by</dt>
        <dd>{envelope.managed_by ?? <span className="muted">not set</span>}</dd>
      </dl>

      {envelope.policy === null && (
        <Banner tone="info" role="status">
          <span>No default policy is set. Saving one puts every enrolled device under management.</span>
        </Banner>
      )}

      {changedOnServer && <ChangedOnServerBanner version={envelope.version} onReload={reload} />}

      <PolicyForm
        value={{ policy: form.policy, locked: form.locked }}
        onChange={(next) => setForm({ ...next, managedBy: form.managedBy })}
      />

      <div className="button-row">
        <button
          className="btn primary"
          type="button"
          disabled={save.isPending || errors.length > 0}
          onClick={() => save.mutate(form)}
        >
          {save.isPending ? 'Saving…' : 'Save policy'}
        </button>
        {envelope.policy !== null && (
          <button
            className="btn danger ghost"
            type="button"
            onClick={() => setConfirmStop(true)}
          >
            Stop managing
          </button>
        )}
      </div>
      {save.isError && <p role="alert">Not saved: {save.error.message}</p>}

      <DeviceOverrides />

      {confirmStop && (
        <ConfirmDialog
          title="Stop managing this tenant's devices?"
          confirmLabel={stopManaging.isPending ? 'Stopping…' : 'Yes, stop managing'}
          busy={stopManaging.isPending}
          onCancel={() => setConfirmStop(false)}
          onConfirm={() => stopManaging.mutate()}
        >
          <p>
            A signed "no longer managed" document is issued at a new version. Every device polling
            in will unmanage itself and fall back to its own local settings. This cannot be
            undone — you would need to set a new default policy to manage devices again.
          </p>
          {stopManaging.isError && <p role="alert">{stopManaging.error.message}</p>}
        </ConfirmDialog>
      )}
    </section>
  )
}

function DeviceOverrides() {
  const devicesQuery = useQuery({
    queryKey: ['shield-server', 'devices'],
    queryFn: ({ signal }) => fetchDevices(signal),
  })
  useAuthWatch(devicesQuery)
  const [selected, setSelected] = useState<string>('')

  const devices = useMemo(() => devicesQuery.data?.devices ?? [], [devicesQuery.data])

  return (
    <section className="settings-block" aria-labelledby="shield-overrides-h">
      <SectionHead
        id="shield-overrides-h"
        title="Per-device overrides"
        help="Pick a device to see or set a policy that replaces the tenant default just for it."
      />
      {devices.length === 0 ? (
        <p className="muted">No devices enrolled yet. Enrol a Mac first; its override is set here.</p>
      ) : (
        <>
          <label>
            <span className="fkey">Device</span>
            <select value={selected} onChange={(e) => setSelected(e.target.value)}>
              <option value="">Choose a device…</option>
              {devices.map((d) => (
                <option key={d.device_id} value={d.device_id}>
                  {d.label ?? `Unlabelled device ${d.device_id.slice(0, 8)}`}
                </option>
              ))}
            </select>
          </label>
          {selected && (
            // `key`: switching devices must reset the form, confirm-remove
            // state and pending mutations — without it React reuses the same
            // component instance across a device switch (same position in
            // the tree), so a confirm dialog opened for one device could
            // fire its DELETE against whichever device is now selected.
            <DeviceOverrideEditor key={selected} deviceId={selected} onRemoved={() => setSelected('')} />
          )}
        </>
      )}
    </section>
  )
}

function DeviceOverrideEditor({
  deviceId,
  onRemoved,
}: {
  deviceId: string
  onRemoved: () => void
}) {
  const qc = useQueryClient()
  const query = useQuery({
    queryKey: ['shield-server', 'policy', 'device', deviceId],
    queryFn: ({ signal }) => fetchDevicePolicy(deviceId, signal),
  })
  useAuthWatch(query)

  const { form, setForm, changedOnServer, reload, markSaved } = useServerSyncedForm(query.data)

  const save = useMutation({
    mutationFn: (next: FormState) =>
      saveDevicePolicy(deviceId, { policy: next.policy, locked: next.locked }, next.managedBy),
    onSuccess: (data) => {
      qc.setQueryData(['shield-server', 'policy', 'device', deviceId], data)
      markSaved(data)
      void qc.invalidateQueries({ queryKey: ['shield-server', 'devices'] })
    },
  })

  const [confirmRemove, setConfirmRemove] = useState(false)
  const remove = useMutation({
    mutationFn: () => deleteDevicePolicy(deviceId),
    onSuccess: () => {
      setConfirmRemove(false)
      void qc.invalidateQueries({ queryKey: ['shield-server', 'devices'] })
      onRemoved()
    },
  })

  if (query.isPending || form === null) return <p className="empty-row" role="status">Loading override…</p>
  if (query.isError) {
    return <p className="empty-row" role="alert">Couldn't load this device's policy: {query.error.message}</p>
  }

  const errors = [...validatePolicyDoc(form.policy), ...validateLockedKeys(form.locked)]
  const hasOverride = query.data.policy !== null

  return (
    <div className="policy-override">
      {!hasOverride && (
        <p className="muted setting-help">
          This device currently follows the tenant default. Saving here creates an override.
        </p>
      )}
      {changedOnServer && <ChangedOnServerBanner version={query.data.version} onReload={reload} />}
      <PolicyForm
        value={{ policy: form.policy, locked: form.locked }}
        onChange={(next) => setForm({ ...next, managedBy: form.managedBy })}
      />
      <div className="button-row">
        <button
          className="btn primary"
          type="button"
          disabled={save.isPending || errors.length > 0}
          onClick={() => save.mutate(form)}
        >
          {save.isPending ? 'Saving…' : hasOverride ? 'Save override' : 'Create override'}
        </button>
        {hasOverride && (
          <button className="btn ghost" type="button" onClick={() => setConfirmRemove(true)}>
            Remove override
          </button>
        )}
      </div>
      {save.isError && <p role="alert">Not saved: {save.error.message}</p>}

      {confirmRemove && (
        <ConfirmDialog
          title="Remove this device's override?"
          confirmLabel={remove.isPending ? 'Removing…' : 'Remove override'}
          busy={remove.isPending}
          onCancel={() => setConfirmRemove(false)}
          onConfirm={() => remove.mutate()}
        >
          <p>The device falls back to the tenant default policy at a fresh version.</p>
          {remove.isError && <p role="alert">{remove.error.message}</p>}
        </ConfirmDialog>
      )}
    </div>
  )
}
