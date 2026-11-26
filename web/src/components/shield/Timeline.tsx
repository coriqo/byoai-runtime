/**
 * Timeline: everything Shield recorded, grouped by day, newest first. Arriving
 * with `focus` (from a row's "Open in Timeline") shows that interaction's
 * journey at the top and highlights its step, so the reader lands on it.
 */
import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import {
  Banner, HashChip, NeedFilter, WhenFilter, flagTagClass, inWhen, matchesNeed, plural, ruleLabel, tierLabel, tierTagClass, today, useFeed,
} from './shared'
import type { Item, Need, When } from './shared'

export function Timeline({ focus, setFocus, onOpen }: {
  focus: string | undefined
  setFocus: (id: string | undefined) => void
  onOpen: (it: Item) => void
}) {
  const [need, setNeed] = useState<Need>('all')
  const [when, setWhen] = useState<When>('all')
  const feed = useFeed()
  const items = feed.data?.items ?? []
  const focused = focus ? items.find(it => it.id === focus) : undefined

  useEffect(() => {
    if (!focused) return
    document.getElementById(`tl-${focused.id}`)?.scrollIntoView({ block: 'center' })
  }, [focused?.id])

  const visible = items.filter(it => matchesNeed(it, need) && inWhen(it.date, when))
  const days = new Map<string, Item[]>()
  for (const it of visible) {
    const d = it.date || 'Undated'
    days.set(d, [...(days.get(d) ?? []), it])
  }
  const t = today()

  return (
    <div className="shield-timeline">
      {focus && !focused && feed.data && (
        <Banner tone="warn">
          <span>That interaction isn't in the latest 200 anymore.</span>
          <button className="btn sm" onClick={() => setFocus(undefined)}>Dismiss</button>
        </Banner>
      )}
      {focused && <Journey it={focused} onClose={() => setFocus(undefined)} onOpen={() => onOpen(focused)} />}

      <div className="filterbar">
        <WhenFilter value={when} onChange={setWhen} />
        <NeedFilter value={need} onChange={setNeed} />
        <span className="muted">{visible.length} of {items.length} recorded</span>
      </div>

      {feed.isError && (
        <p className="empty-row" role="alert">
          <b>Can't reach Shield on this Mac.</b>
          Start it with <code className="mono">byoai-shield</code>, then reload this page.
        </p>
      )}
      {feed.isPending && <p className="empty-row" role="status">Loading the timeline…</p>}
      {feed.data && visible.length === 0 && (
        <p className="empty-row">
          {items.length
            ? 'Nothing matches these filters. Try All time and All; filters only change this view.'
            : 'Nothing recorded yet. Start the capture proxy and chat, or call the MCP tools.'}
        </p>
      )}
      {[...days.entries()].map(([d, rows]) => (
        <section key={d} className="tl-day">
          <h2 className="label">{d === t ? 'Today' : d} · {plural(rows.length, 'event')}</h2>
          <ol className="tl-list">
            {rows.map(it => (
              <li key={it.id} id={`tl-${it.id}`} data-tier={it.tier}
                className={it.id === focus ? 'focused' : undefined}>
                <button className="tl-step" onClick={() => setFocus(it.id)}>
                  <span className="tl-top">
                    <span>
                      <b>{it.surface}</b>
                      {it.tier !== 'ok' && <> <span className={`tag ${tierTagClass(it.tier)}`}>{tierLabel(it)}</span></>}
                    </span>
                    <span className="when">{it.ts}</span>
                  </span>
                  <span className="muted">{it.verb}</span>
                  {it.flags.length > 0 && (
                    <span className="row-meta">
                      {it.flags.map(f => (
                        <span key={f.rule} className={`tag ${flagTagClass(f.tier)}`}>{ruleLabel(f.rule)}</span>
                      ))}
                    </span>
                  )}
                </button>
              </li>
            ))}
          </ol>
        </section>
      ))}
    </div>
  )
}

/** How one interaction became evidence: sent → checked → outcome → sealed. */
function Journey({ it, onClose, onOpen }: { it: Item; onClose: () => void; onOpen: () => void }) {
  const flags = it.flags.map(f => ruleLabel(f.rule))
  const n = it.redactions?.length ?? 0
  const outcome = it.status === 'blocked'
    ? { dot: 'r', title: 'Blocked on this Mac', body: 'The message never reached the AI app.' }
    : it.status === 'running'
      ? { dot: 'y', title: 'Still running', body: '' }
      : it.status === 'failed'
        ? { dot: 'r', title: 'The call failed', body: '' }
        : {
          dot: 'g',
          title: n ? `Sent with ${n === 1 ? '1 detail' : `${n} details`} replaced` : 'Sent',
          body: it.reply ?? (it.response_stream ? 'Reply streamed back.' : ''),
        }
  const steps: { dot: string; title: string; body: ReactNode }[] = [
    { dot: 'g', title: it.source === 'mcp' ? 'The agent called a tool' : it.source === 'browser' ? 'A message was sent in the browser' : 'A message was sent', body: it.verb },
    {
      dot: it.tier === 'bad' ? 'r' : flags.length ? 'y' : 'g',
      title: flags.length ? 'Shield checked it: rules matched' : 'Shield checked it: nothing matched',
      body: flags.join(' · '),
    },
    outcome,
    ...(it.seal
      ? [{
        dot: 'g', title: 'Sealed',
        body: <>
          The record and its proof stay on this Mac{it.latency_ms ? ` (${Math.round(it.latency_ms)} ms)` : ''}.{' '}
          <HashChip value={it.seal} noun="seal" short={16} />
        </>,
      }]
      : []),
  ]
  return (
    <section className="panel journey" aria-labelledby="journey-h">
      <div className="panel-head">
        <h2 className="label" id="journey-h">How this interaction became a record · {it.date} {it.ts}</h2>
        <span className="spacer" />
        <button className="btn ghost sm" onClick={onOpen}>Details</button>
        <button className="btn ghost sm" onClick={onClose} aria-label="Close journey">Close</button>
      </div>
      <ol className="journey-steps">
        {steps.map(s => (
          <li key={s.title} data-dot={s.dot}>
            <b>{s.title}</b>
            {s.body ? <p>{s.body}</p> : null}
          </li>
        ))}
      </ol>
    </section>
  )
}
