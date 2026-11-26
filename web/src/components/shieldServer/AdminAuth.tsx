/**
 * Admin-token gate for the free, self-hosted Shield server console
 * (Phase 1.5). Every call under `/api/v1/shield/*` needs `Authorization:
 * Bearer <admin token>`; a 401 anywhere under this section means the token is
 * missing or wrong, and the fix is the same prompt no matter which panel hit
 * it. The token lives in `sessionStorage` only (never `localStorage`, never
 * sent anywhere but this server) and every read/write is wrapped in try/catch
 * in `api/shieldServer.ts`, because a private window or a locked-down
 * `sessionStorage` must degrade to "no token remembered", not crash the page.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { useQueryClient, type UseQueryResult } from '@tanstack/react-query'
import {
  clearStoredAdminToken,
  getStoredAdminToken,
  isAuthError,
  setStoredAdminToken,
} from '@/api/shieldServer'
import { useFocusTrap } from '@/components/shield/shared'

interface AdminAuthValue {
  readonly token: string | null
  readonly promptOpen: boolean
  readonly reportAuthError: () => void
  readonly submitToken: (raw: string) => void
  readonly signOut: () => void
}

const AdminAuthContext = createContext<AdminAuthValue | null>(null)

export function AdminAuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const [token, setToken] = useState<string | null>(() => getStoredAdminToken())
  const [promptOpen, setPromptOpen] = useState(() => getStoredAdminToken() === null)

  const reportAuthError = useCallback(() => {
    setPromptOpen(true)
  }, [])

  const submitToken = useCallback(
    (raw: string) => {
      const trimmed = raw.trim()
      if (!trimmed) return
      setStoredAdminToken(trimmed)
      setToken(trimmed)
      setPromptOpen(false)
      // A fresh token invalidates every query that failed under the old (or
      // absent) one — otherwise the screen would keep showing the auth
      // failure state until something else happened to trigger a refetch.
      void qc.invalidateQueries({ queryKey: ['shield-server'] })
    },
    [qc],
  )

  const signOut = useCallback(() => {
    clearStoredAdminToken()
    setToken(null)
    setPromptOpen(true)
  }, [])

  return (
    <AdminAuthContext.Provider
      value={{ token, promptOpen, reportAuthError, submitToken, signOut }}
    >
      {children}
    </AdminAuthContext.Provider>
  )
}

export function useAdminAuth(): AdminAuthValue {
  const ctx = useContext(AdminAuthContext)
  if (ctx === null) throw new Error('useAdminAuth must be used within AdminAuthProvider')
  return ctx
}

/**
 * Wraps any query result from `api/shieldServer.ts` and opens the token
 * prompt the moment it settles into a `ShieldServerAuthError`. Every panel
 * (`Devices`, `Policy`, `Enrol`) calls this on its own queries so the prompt
 * appears regardless of which screen the admin lands on with a stale token.
 */
export function useAuthWatch(query: UseQueryResult<unknown, Error>): void {
  const { reportAuthError } = useAdminAuth()
  useEffect(() => {
    if (query.error && isAuthError(query.error)) reportAuthError()
  }, [query.error, reportAuthError])
}

/** The admin-token prompt. A modal that cannot be dismissed (no token, no
 * console), so focus is held inside it until a token is submitted. */
function TokenPrompt({ onSubmit }: { onSubmit: (raw: string) => void }) {
  const [draft, setDraft] = useState('')
  const boxRef = useRef<HTMLDivElement>(null)
  useFocusTrap(boxRef)
  return (
    <div className="dialog-backdrop">
      <div
        ref={boxRef}
        className="dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="admin-token-h"
        aria-describedby="admin-token-body"
      >
        <h2 id="admin-token-h">Admin token required</h2>
        <div id="admin-token-body" className="dialog-body">
          <p className="muted">
            Paste the admin token this Shield server printed on first run (also written to{' '}
            <span className="mono">BYOAI_SHIELD_SERVER_DATA/admin_token</span>). It is kept only
            for this browser tab.
          </p>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              onSubmit(draft)
              setDraft('')
            }}
          >
            <label htmlFor="shield-admin-token-input">
              <span className="fkey">Admin token</span>
            </label>
            <input
              id="shield-admin-token-input"
              data-testid="admin-token-input"
              type="password"
              autoComplete="off"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
            <div className="dialog-actions">
              <button className="btn primary" type="submit" disabled={!draft.trim()}>
                Continue
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  )
}

export function AdminTokenGate({ children }: { children: ReactNode }) {
  const { token, promptOpen, submitToken, signOut } = useAdminAuth()
  return (
    <>
      {token !== null && (
        <div className="session-bar">
          <span className="muted">Admin session active</span>
          <button className="btn ghost sm" type="button" onClick={signOut}>
            Sign out
          </button>
        </div>
      )}
      {children}
      {promptOpen && <TokenPrompt onSubmit={submitToken} />}
    </>
  )
}
