/**
 * The policy-editing form shared by the tenant default and per-device
 * overrides: same fields (mode, apps, keep_text, retention, notice), same
 * lock checkboxes, same client-side validation mirroring the server rules
 * (`shield.apply_policy_update`).
 */
import { APP_NAME, Banner } from '@/components/shield/shared'
import {
  LOCKABLE_KEYS,
  RETENTION_DAYS,
  validateLockedKeys,
  validatePolicyDoc,
  type LockableKey,
  type ShieldServerPolicyDoc,
} from '@/api/shieldServer'

const KEY_LABEL: Record<LockableKey, string> = {
  mode: 'Mode',
  apps: 'Apps',
  keep_text: 'Keep previews',
  retention_days: 'Retention',
  notice: 'Notice',
}

const KNOWN_APPS = ['claude', 'chatgpt', 'gemini', 'copilot'] as const

/** What each stored mode is called on screen: the words the Shield window uses. */
const MODE_LABEL = {
  observe: 'Record only',
  redact: 'Check and act',
  block: 'Check and block high-risk sends',
} as const

export interface PolicyFormValue {
  readonly policy: ShieldServerPolicyDoc
  readonly locked: string[]
}

export function defaultPolicyDoc(): ShieldServerPolicyDoc {
  return {
    mode: 'redact',
    apps: Object.fromEntries(KNOWN_APPS.map((a) => [a, true])),
    keep_text: false,
    retention_days: 30,
    notice: true,
  }
}

export function PolicyForm({
  value,
  onChange,
  disabledKeys,
}: {
  value: PolicyFormValue
  onChange: (next: PolicyFormValue) => void
  /** Keys the server would refuse (locked by the tenant default) — disabled,
   * not just visually muted, so a per-device override can't silently pretend
   * to touch a field it cannot actually change. */
  disabledKeys?: ReadonlySet<string>
}) {
  const { policy, locked } = value
  const locks = new Set(locked)
  const disabled = disabledKeys ?? new Set<string>()
  const errors = [...validatePolicyDoc(policy), ...validateLockedKeys(locked)]

  const set = (patch: Partial<ShieldServerPolicyDoc>) =>
    onChange({ policy: { ...policy, ...patch }, locked })

  const toggleLock = (key: LockableKey) => {
    const next = locks.has(key) ? locked.filter((k) => k !== key) : [...locked, key]
    onChange({ policy, locked: next })
  }

  const apps = { ...Object.fromEntries(KNOWN_APPS.map((a) => [a, false])), ...policy.apps }

  return (
    <div className="policy-form">
      <fieldset disabled={disabled.has('mode')}>
        <legend>Mode</legend>
        {(['observe', 'redact', 'block'] as const).map((m) => (
          <label key={m} className="mode-row">
            <input
              type="radio"
              name="policy-mode"
              checked={policy.mode === m}
              disabled={disabled.has('mode')}
              onChange={() => set({ mode: m })}
            />
            {MODE_LABEL[m]}
          </label>
        ))}
        <LockBox k="mode" locks={locks} onToggle={toggleLock} />
      </fieldset>

      <fieldset disabled={disabled.has('apps')}>
        <legend>Apps</legend>
        {KNOWN_APPS.map((app) => (
          <label key={app} className="row-app">
            <span>{APP_NAME[app] ?? app}</span>
            <input
              type="checkbox"
              checked={Boolean(apps[app])}
              disabled={disabled.has('apps')}
              onChange={() => set({ apps: { ...policy.apps, [app]: !apps[app] } })}
            />
          </label>
        ))}
        <LockBox k="apps" locks={locks} onToggle={toggleLock} />
      </fieldset>

      <fieldset disabled={disabled.has('keep_text')}>
        <legend>Keep text</legend>
        <label className="row-app">
          <span>Keep a preview of each message</span>
          <input
            type="checkbox"
            checked={policy.keep_text}
            disabled={disabled.has('keep_text')}
            onChange={() => set({ keep_text: !policy.keep_text })}
          />
        </label>
        <LockBox k="keep_text" locks={locks} onToggle={toggleLock} />
      </fieldset>

      <fieldset disabled={disabled.has('retention_days')}>
        <legend>Retention</legend>
        <label>
          <span className="fkey">Keep history for</span>
          <select
            value={policy.retention_days}
            disabled={disabled.has('retention_days')}
            onChange={(e) => set({ retention_days: Number(e.target.value) as ShieldServerPolicyDoc['retention_days'] })}
          >
            {RETENTION_DAYS.map((d) => (
              <option key={d} value={d}>
                {d === 365 ? '1 year' : `${d} days`}
              </option>
            ))}
          </select>
        </label>
        <LockBox k="retention_days" locks={locks} onToggle={toggleLock} />
      </fieldset>

      <fieldset disabled={disabled.has('notice')}>
        <legend>Notice</legend>
        <label className="row-app">
          <span>Show the notice on the device</span>
          <input
            type="checkbox"
            checked={policy.notice}
            disabled={disabled.has('notice')}
            onChange={() => set({ notice: !policy.notice })}
          />
        </label>
        <LockBox k="notice" locks={locks} onToggle={toggleLock} />
      </fieldset>

      {errors.length > 0 && (
        <Banner tone="warn" role="alert">
          <ul className="error-list">
            {errors.map((e) => (
              <li key={e.field}>{e.message}</li>
            ))}
          </ul>
        </Banner>
      )}
    </div>
  )
}

function LockBox({
  k,
  locks,
  onToggle,
}: {
  k: LockableKey
  locks: ReadonlySet<string>
  onToggle: (k: LockableKey) => void
}) {
  return (
    <label className="muted setting-help lock-row">
      <input type="checkbox" checked={locks.has(k)} onChange={() => onToggle(k)} />
      {' '}Lock {KEY_LABEL[k].toLowerCase()} for devices
    </label>
  )
}

export { LOCKABLE_KEYS }
