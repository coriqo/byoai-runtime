/**
 * Coriqo Shield: the screen for the person at this Mac. It lives outside the
 * admin console (`/console/…` is the fleet view), so it renders without the
 * console shell: no scope chip, no fleet rail.
 *
 * The tab and the focused interaction are in the URL (`?tab=timeline&focus=…`)
 * so "Open in Timeline" is a real link and back/forward walk between tabs.
 */
import { useQuery } from '@tanstack/react-query'
import { createFileRoute, useNavigate } from '@tanstack/react-router'
import { useCallback, useEffect, useState } from 'react'
import { fetchPolicy, fetchVerify } from '@/api/shield'
import { Ledger } from '@/components/shield/Ledger'
import { Settings } from '@/components/shield/Settings'
import { Sheet } from '@/components/shield/Sheet'
import { Timeline } from '@/components/shield/Timeline'
import { Trust } from '@/components/shield/Trust'
import { HashChip, NoticeStrip, SealMark } from '@/components/shield/shared'
import type { Item } from '@/components/shield/shared'

const TABS = ['trust', 'ledger', 'timeline', 'settings'] as const
type Tab = (typeof TABS)[number]
const TAB_LABEL: Record<Tab, string> = {
  trust: 'Trust', ledger: 'Ledger', timeline: 'Timeline', settings: 'Settings',
}

interface ShieldSearch {
  tab?: Tab
  focus?: string
}

export const Route = createFileRoute('/shield')({
  validateSearch: (s: Record<string, unknown>): ShieldSearch => ({
    tab: TABS.includes(s.tab as Tab) ? (s.tab as Tab) : undefined,
    focus: typeof s.focus === 'string' && s.focus ? s.focus : undefined,
  }),
  component: ShieldPage,
})

function ShieldPage() {
  const { tab = 'trust', focus } = Route.useSearch()
  const navigate = useNavigate({ from: '/shield' })
  const [sheet, setSheet] = useState<Item | null>(null)
  useEffect(() => {
    const before = document.title
    document.title = `Coriqo Shield · ${TAB_LABEL[tab]}`
    return () => { document.title = before }
  }, [tab])
  const verify = useQuery({ queryKey: ['shield-verify'], queryFn: fetchVerify, refetchInterval: 10_000 })
  const policy = useQuery({ queryKey: ['shield-policy'], queryFn: fetchPolicy })

  const go = useCallback((next: ShieldSearch) => {
    void navigate({ search: next })
  }, [navigate])
  const openTimeline = useCallback((id: string) => {
    setSheet(null)
    go({ tab: 'timeline', focus: id })
  }, [go])
  const closeSheet = useCallback(() => setSheet(null), [])

  return (
    <main className="shield-page">
      <div className="shield-panel">
        <header className="panel-head shield-head">
          <div>
            <div className="title-row">
              <span className="brand-lockup">
                <SealMark size={24} />
                <h1>Coriqo Shield</h1>
              </span>
              <span className="tag info">this Mac</span>
              {verify.data
                ? verify.data.tamper_evident
                  ? <span className="tag ok">Record verified</span>
                  : <span className="tag bad">Record failed verification</span>
                : verify.isError
                  ? <span className="tag warn">Shield not reachable</span>
                  : <span className="tag unknown">Checking</span>}
            </div>
            <p className="one-liner">
              Checks what you send to AI apps, replaces personal details before
              they leave, and keeps a tamper-evident record you can verify later.
            </p>
          </div>
          {verify.data?.checkpoint?.device_id && (
            <div className="keys">
              <span className="fkey">Device</span>
              <HashChip value={verify.data.checkpoint.device_id} noun="device id" short={18} />
            </div>
          )}
        </header>

        {policy.data?.notice && <NoticeStrip policy={policy.data} />}

        <nav className="shield-nav" aria-label="Shield sections">
          {TABS.map(key => (
            <button key={key} className={key === tab ? 'on' : ''}
              aria-current={key === tab ? 'page' : undefined}
              onClick={() => { if (key !== tab) go({ tab: key }) }}>
              {TAB_LABEL[key]}
            </button>
          ))}
        </nav>

        {tab === 'trust' && (
          <Trust verify={verify.data} policy={policy.data} onOpen={setSheet}
            goSettings={() => go({ tab: 'settings' })} goLedger={() => go({ tab: 'ledger' })} />
        )}
        {tab === 'ledger' && <Ledger onOpen={setSheet} />}
        {tab === 'timeline' && (
          <Timeline focus={focus} onOpen={setSheet}
            setFocus={id => go({ tab: 'timeline', focus: id })} />
        )}
        {tab === 'settings' && <Settings />}
      </div>

      {sheet && (
        <Sheet item={sheet} onClose={closeSheet}
          onOpenTimeline={tab === 'timeline' && focus === sheet.id ? undefined : openTimeline} />
      )}
    </main>
  )
}
