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
import { HashChip, NEED_OPTIONS, NoticeStrip, PAGE_SIZES, SealMark, WHEN_OPTIONS } from '@/components/shield/shared'
import type { Item, Need, When } from '@/components/shield/shared'

const TABS = ['trust', 'ledger', 'timeline', 'settings'] as const
type Tab = (typeof TABS)[number]
const TAB_LABEL: Record<Tab, string> = {
  trust: 'Trust', ledger: 'Ledger', timeline: 'Timeline', settings: 'Settings',
}

export interface ShieldSearch {
  tab?: Tab
  focus?: string
  /** Timeline paging and filters; absent means the default (page 1, 25 rows, All, All time). */
  page?: number
  size?: number
  when?: When
  need?: Need
}

export const Route = createFileRoute('/shield')({
  validateSearch: (s: Record<string, unknown>): ShieldSearch => ({
    tab: TABS.includes(s.tab as Tab) ? (s.tab as Tab) : undefined,
    focus: typeof s.focus === 'string' && s.focus ? s.focus : undefined,
    page: Number.isInteger(Number(s.page)) && Number(s.page) > 1 ? Number(s.page) : undefined,
    size: (PAGE_SIZES as readonly number[]).includes(Number(s.size)) && Number(s.size) !== PAGE_SIZES[0] ? Number(s.size) : undefined,
    when: WHEN_OPTIONS.some(([k]) => k === s.when) && s.when !== 'all' ? (s.when as When) : undefined,
    need: NEED_OPTIONS.some(([k]) => k === s.need) && s.need !== 'all' ? (s.need as Need) : undefined,
  }),
  component: ShieldPage,
})

function ShieldPage() {
  const search = Route.useSearch()
  const { tab = 'trust', focus } = search
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
  /** Change part of the Timeline's URL state; each change is a history step, so Back undoes it. */
  const patch = useCallback((p: Partial<ShieldSearch>, replace = false) => {
    void navigate({ search: prev => ({ ...prev, tab: 'timeline', ...p }), replace })
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
          <Timeline search={search} patch={patch} onOpen={setSheet} />
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
