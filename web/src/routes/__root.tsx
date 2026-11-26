/**
 * The shell.
 *
 * Left rail — Fleet · Ledger · Evidence · Mandate · Runtime · Settings, with
 * Fleet as the default landing route. Top bar, left to right: the scope chip,
 * breadcrumbs, the ⌘K search trigger, and the three health dots.
 *
 * Everything the shell displays comes from the URL (scope) or from the page
 * below it (inclusion and the health rollups, published upward through
 * ShellStatusContext). The shell never fetches a second copy of a number the
 * page already has — two fetches means two answers, and the chip would then
 * be describing a screen the user is not looking at.
 *
 * Navigation is done through `router.history` rather than typed `Link`s
 * because the rail addresses sections whose route files are owned by other
 * parts of the app and may not exist yet; a rail item that vanishes when its
 * screen is unwritten is worse than one that lands on a not-found.
 */
import { useCallback, useEffect, useMemo, useState } from 'react'
import { ScopeQSProvider } from '@/app/hrefContext'
import { withScope } from '@/lib/withScope'
import {
  Outlet,
  createRootRoute,
  useLocation,
  useRouter,
} from '@tanstack/react-router'
import { Crumbs, type Crumb } from '../components/Crumbs'
import { HealthDots } from '../components/HealthDots'
import { ScopeChip } from '../components/ScopeChip'
import { SealMark } from '../components/shield/shared'
import {
  PublishShellStatusContext,
  ShellStatusContext,
  scopeSearchToParams,
  useScopeSearch,
  useTenant,
  type ScopeSearch,
  type ShellStatus,
} from '../app/scope'

export const Route = createRootRoute({
  component: Root,
  // A wrong URL still gets the shell, the rail and a way out — a 404 that
  // strands you with no navigation is a dead end.
  notFoundComponent: NotFound,
})

interface Section {
  readonly key: string
  readonly label: string
  readonly glyph: string
  /** The `g`-prefixed shortcut key. */
  readonly hotkey: string
  readonly path: (tenant: string) => string
}

const SECTIONS: readonly Section[] = [
  { key: 'fleet', label: 'Fleet', glyph: '◉', hotkey: 'f', path: (t) => `/console/${t}/fleet` },
  {
    key: 'shield-devices',
    label: 'Shield devices',
    glyph: '⛨',
    hotkey: 'd',
    path: (t) => `/console/${t}/shield-server/devices`,
  },
  {
    key: 'shield-policy',
    label: 'Shield policy',
    glyph: '§',
    hotkey: 'p',
    path: (t) => `/console/${t}/shield-server/policy`,
  },
  {
    key: 'shield-enrol',
    label: 'Enrol a Mac',
    glyph: '+',
    hotkey: 'n',
    path: (t) => `/console/${t}/shield-server/enrol`,
  },
  { key: 'ledger', label: 'Ledger', glyph: '▤', hotkey: 'l', path: (t) => `/console/${t}/ledger` },
  { key: 'evidence', label: 'Evidence', glyph: '✓', hotkey: 'e', path: (t) => `/console/${t}/evidence` },
  { key: 'mandate', label: 'Mandate', glyph: '⚖', hotkey: 'm', path: (t) => `/console/${t}/mandate` },
  { key: 'runtime', label: 'Runtime', glyph: '◷', hotkey: 'r', path: (t) => `/console/${t}/runtime` },
]

const SETTINGS: Section = {
  key: 'settings',
  label: 'Settings',
  glyph: '⚙',
  hotkey: ',',
  path: (t) => `/console/${t}/settings`,
}

/** `⌘K` and the top-bar search box both raise this. The command palette
 *  listens for it; until one exists, nothing happens and nothing breaks. */
export const PALETTE_EVENT = 'byoai:open-palette'

/** `/shield` is the per-Mac screen for whoever uses the machine, not part of
 * the admin console, so it gets no fleet rail and no scope chip. Split here
 * rather than inside Shell so Shell's hooks always run in the same order. */
function Root() {
  const { pathname } = useLocation()
  // Only the Shield page itself: an unmatched /shield/… path falls through to
  // the shell, whose not-found page has a way out.
  if (pathname === '/shield' || pathname === '/shield/') return <Outlet />
  return <Shell />
}

function Shell() {
  const router = useRouter()
  const location = useLocation()
  // Tenant and scope are read from the URL (both `strict: false` under the
  // hood): the shell renders above the tenant route and must still work on
  // `/`, on a not-found, and while a route is loading.
  const [status, setStatus] = useState<ShellStatus>({})
  const [sheetOpen, setSheetOpen] = useState(false)

  const tenant = useTenant()
  const search = useScopeSearch()
  // The active slice, provided to the tree so every link carries it. Kept in
  // context rather than a module global: the hotkey handler below closes over
  // this value, and a global written during render went stale in exactly that
  // closure while still looking correct everywhere else.
  const scopeQS = new URLSearchParams(scopeSearchToParams(search)).toString()

  const go = useCallback(
    (href: string) => {
      router.history.push(href)
    },
    [router],
  )

  const publish = useCallback((next: ShellStatus | null) => {
    setStatus(next ?? {})
  }, [])

  /** Scope changes are URL changes — back/forward walk scope history. */
  const onScopeChange = useCallback(
    (next: ScopeSearch) => {
      const qs = new URLSearchParams(scopeSearchToParams(next)).toString()
      go(location.pathname + (qs ? `?${qs}` : ''))
    },
    [go, location.pathname],
  )

  const activeKey = useMemo(() => {
    // Highlight a section only when the path actually names one. Defaulting to
    // 'fleet' lit the Fleet item on tenant-less paths like /console, telling
    // the user they were somewhere they were not.
    const parts = location.pathname.split('/')
    const section = parts[3] ?? null
    // The shield server console has three sibling sections under one path
    // segment (`shield-server/devices|policy|enrol`), so the rail key has to
    // be read from the fourth segment, not the third, or all three rail items
    // would light up together (or none would).
    if (section === 'shield-server') return `shield-${parts[4] ?? ''}`
    return section
  }, [location.pathname])

  // Keyboard model: `g` then a section key, `?` for the sheet, `⌘K` for
  // the palette. An operator console that requires a mouse is a toy.
  useEffect(() => {
    let pendingG = false
    let gTimer: number | undefined
    function typing(t: EventTarget | null): boolean {
      if (!(t instanceof HTMLElement)) return false
      return (
        t.isContentEditable ||
        t.tagName === 'INPUT' ||
        t.tagName === 'TEXTAREA' ||
        t.tagName === 'SELECT'
      )
    }
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        window.dispatchEvent(new CustomEvent(PALETTE_EVENT))
        return
      }
      if (typing(e.target) || e.metaKey || e.ctrlKey || e.altKey) return
      if (e.key === 'Escape') {
        setSheetOpen(false)
        return
      }
      if (e.key === '?') {
        e.preventDefault()
        setSheetOpen((v) => !v)
        return
      }
      if (pendingG) {
        pendingG = false
        window.clearTimeout(gTimer)
        const hit = [...SECTIONS, SETTINGS].find(
          (s) => s.hotkey === e.key.toLowerCase(),
        )
        if (hit) {
          e.preventDefault()
          go(withScope(hit.path(tenant), scopeQS))
        }
        return
      }
      if (e.key.toLowerCase() === 'g') {
        pendingG = true
        // A chord that never expires would swallow the next keystroke a user
        // types a minute later.
        gTimer = window.setTimeout(() => {
          pendingG = false
        }, 1200)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('keydown', onKey)
      window.clearTimeout(gTimer)
    }
  }, [go, tenant, scopeQS])

  const crumbs = useMemo(
    () => buildCrumbs(location.pathname, tenant),
    [location.pathname, tenant],
  )

  return (
    <ShellStatusContext.Provider value={status}>
      <PublishShellStatusContext.Provider value={publish}>
        <ScopeQSProvider value={scopeQS}>
        <div className="app">
          <nav className="rail" aria-label="Sections">
            <span className="brand-lockup">
              <SealMark size={24} />
              <span className="wordmark">Coriqo</span>
            </span>
            {SECTIONS.map((s) => (
              <RailItem
                scopeQS={scopeQS}
                key={s.key}
                section={s}
                tenant={tenant}
                active={activeKey === s.key}
                onGo={go}
              />
            ))}
            <div className="rail-spacer" />
            <RailItem
                scopeQS={scopeQS}
              section={SETTINGS}
              tenant={tenant}
              active={activeKey === SETTINGS.key}
              onGo={go}
            />
          </nav>
          <div>
            <header className="topbar">
              <ScopeChip
                search={search}
                inclusion={status.inclusion}
                onChange={onScopeChange}
              />
              <Crumbs items={crumbs} onNavigate={go} />
              <div className="spacer" />
              <button
                type="button"
                className="search"
                onClick={() => window.dispatchEvent(new CustomEvent(PALETTE_EVENT))}
              >
                Search sessions, traces, hashes… <kbd>⌘K</kbd>
              </button>
              <HealthDots
                coverage={status.coverage}
                integrity={status.integrity}
                ingest={status.ingest}
                onJump={go}
              />
            </header>
            <main className="content">
              <Outlet />
            </main>
          </div>
        </div>
        {sheetOpen ? <KeySheet onClose={() => setSheetOpen(false)} /> : null}
        </ScopeQSProvider>
      </PublishShellStatusContext.Provider>
    </ShellStatusContext.Provider>
  )
}

function RailItem({
  section,
  tenant,
  active,
  onGo,
  scopeQS,
}: {
  section: Section
  tenant: string
  active: boolean
  onGo: (href: string) => void
  scopeQS: string
}) {
  // Rail navigation preserves the slice too: pressing `g l` mid-investigation
  // should not quietly widen the scope back to the tenant default.
  const href = withScope(section.path(tenant), scopeQS)
  return (
    <a
      className={active ? 'rail-item active' : 'rail-item'}
      href={href}
      aria-current={active ? 'page' : undefined}
      onClick={(e) => {
        if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return
        e.preventDefault()
        onGo(href)
      }}
    >
      <span className="glyph" aria-hidden="true">
        {section.glyph}
      </span>{' '}
      {section.label}
    </a>
  )
}

/** `/console/acme-prod/fleet/coverage` → Fleet / Coverage, every segment but
 *  the last a link back. */
export function buildCrumbs(pathname: string, tenant: string): Crumb[] {
  const parts = pathname.split('/').filter((p) => p !== '')
  // ['console', tenant, section, ...rest]
  const rest = parts.slice(2)
  if (rest.length === 0) return [{ label: tenant }]
  const out: Crumb[] = []
  let href = `/console/${tenant}`
  rest.forEach((seg, i) => {
    href += `/${seg}`
    // The last segment is where you already are, so it carries no link.
    out.push(
      i === rest.length - 1
        ? { label: titleCase(seg) }
        : { label: titleCase(seg), href },
    )
  })
  return out
}

function titleCase(seg: string): string {
  // decodeURIComponent throws URIError on a stray '%' or a truncated escape.
  // This runs in the root shell's render path with no error boundary above it,
  // so an unthrown-away exception here blanks the entire console — rail, top
  // bar and page — over one unreadable breadcrumb segment. Fall back to the
  // raw text: an ugly crumb is strictly better than no application.
  let decoded: string
  try {
    decoded = decodeURIComponent(seg)
  } catch {
    decoded = seg
  }
  // Ids stay verbatim — `d1-ops-runner-02` is not "D1 Ops Runner 02".
  if (/[_]|\d/.test(decoded)) return decoded
  return decoded.charAt(0).toUpperCase() + decoded.slice(1)
}

function NotFound() {
  return (
    <div className="empty">
      <div className="headline">There is nothing at this address.</div>
      <p className="muted">
        The URL does not match any screen in the console. Use the rail, or press{' '}
        <kbd>g</kbd> then <kbd>f</kbd> for Fleet.
      </p>
    </div>
  )
}

/** `?` — the shortcut sheet. Same key/meaning pills the palette footer uses. */
function KeySheet({ onClose }: { onClose: () => void }) {
  return (
    <div className="palette-scrim" onClick={onClose}>
      <div
        className="palette"
        role="dialog"
        aria-label="Keyboard shortcuts"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="group-label label">Keyboard</div>
        <div className="keysheet keysheet-sheet">
          {[
            ['⌘K', 'search sessions, traces, hashes'],
            ['g then f', 'Fleet'],
            ['g then l', 'Ledger'],
            ['g then e', 'Evidence'],
            ['g then m', 'Mandate'],
            ['g then r', 'Runtime'],
            ['g then ,', 'Settings'],
            // Only bindings this handler actually implements are listed.
            // j/k, Enter and y are planned but not wired yet; naming
            // them here told the user an action existed and then did nothing
            // when they pressed it — the console making a claim it cannot keep.
            ['?', 'this sheet'],
            ['esc', 'close'],
          ].map(([k, meaning]) => (
            <span className="status" key={k}>
              <kbd>{k}</kbd> <span className="muted">{meaning}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}
