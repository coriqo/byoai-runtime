/**
 * The detail drawer for one interaction: what happened, which rules matched,
 * and a way on to its Timeline journey or its receipt. Opened from a row on
 * Activity, the Ledger or the Timeline.
 */
import { useEffect, useRef } from 'react'
import { Banner, FileEvidence, HashChip, Icon, ReceiptButton, flagTagClass, ruleLabel, tierLabel, tierTagClass, toolLabel, useFocusTrap } from './shared'
import type { Item } from './shared'

const VERDICT: Record<Item['tier'], string> = {
  bad: 'A high-risk rule matched: credentials or a dangerous file name.',
  warn: 'Personal details or harsh language matched a rule.',
  ok: 'No rule matched.',
}

function what(it: Item) {
  if (it.status === 'blocked') return 'Blocked on this Mac. The message never reached the AI app.'
  if ((it.redactions?.length ?? 0) > 0) {
    return `Sent with ${it.redactions!.length === 1 ? '1 detail' : `${it.redactions!.length} details`} replaced.`
  }
  if (it.status === 'running') return 'Still running.'
  if (it.status === 'failed') return 'The call failed.'
  return it.verdict === 'observe' ? 'Sent unchanged (record-only mode).' : 'Sent.'
}

export function Sheet({ item, onClose, onOpenTimeline }: {
  item: Item
  onClose: () => void
  onOpenTimeline?: (id: string) => void
}) {
  const closeRef = useRef<HTMLButtonElement>(null)
  const sheetRef = useRef<HTMLElement>(null)
  useFocusTrap(sheetRef, closeRef)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const { verb, ...record } = item
  return (
    <div className="sheet-backdrop" onClick={e => { if (e.target === e.currentTarget) onClose() }}>
      <aside ref={sheetRef} className="sheet" role="dialog" aria-modal="true" aria-labelledby="sheet-h">
        <header className="sheet-head">
          <span className={`tag ${tierTagClass(item.tier)}`}>{tierLabel(item)}</span>
          <h2 id="sheet-h">{item.surface}</h2>
          <button ref={closeRef} className="btn ghost sm icon" onClick={onClose} aria-label="Close"><Icon name="close" size={16} /></button>
        </header>
        <p className="muted sheet-meta">
          {item.date} {item.ts} · {item.source === 'mcp' ? 'MCP tool call' : item.source === 'browser' ? 'Browser message' : 'Chat message'}
          {item.chars != null && ` · ${item.chars.toLocaleString()} characters`}
        </p>
        <p className="sheet-line">{verb}</p>
        <Banner tone={item.tier === 'ok' ? 'info' : item.tier === 'bad' ? 'bad' : 'warn'}>
          <span><b>{what(item)}</b> {VERDICT[item.tier]}</span>
        </Banner>

        {item.file && (<>
          <h3 className="label">File</h3>
          <p><FileEvidence item={item} /></p>
          <p className="muted">
            The hash is what <code>shasum -a 256</code> prints for the file that was sent. Shield keeps no copy of the file or its name.
            {item.file.scanned === false && ' The rules did not read this file type; only the per-app file setting applied.'}
          </p>
        </>)}

        {/* A file's rule hits are already shown with its evidence above. */}
        {!item.file && (<>
        <h3 className="label">Rules matched</h3>
        {item.flags.length === 0
          ? <p className="muted">None.</p>
          : (
            <ul className="sheet-flags">
              {item.flags.map(f => (
                <li key={f.rule}>
                  <span className={`tag ${flagTagClass(f.tier)}`}>{ruleLabel(f.rule)}</span>
                  {f.tier === 'conduct' && <span className="muted"> conduct, not personal data</span>}
                </li>
              ))}
            </ul>
          )}
        </>)}

        {(item.tools?.length ?? 0) > 0 && (<>
          <h3 className="label">Tools the AI used</h3>
          <p>
            {[...new Set(item.tools!.map(toolLabel))].join(', ')}
            {item.sources ? ` · ${item.sources} ${item.sources === 1 ? 'source' : 'sources'}` : ''}
          </p>
          <p className="muted">Run by the app on its own servers, after the message left. Shield records which tools, not what they found.</p>
        </>)}

        <h3 className="label">Seal</h3>
        {item.seal
          ? <p><HashChip value={item.seal} noun="seal" short={16} /></p>
          : <p className="muted">Not sealed yet: the call is still running.</p>}

        <div className="sheet-actions">
          {onOpenTimeline && (
            <button className="btn primary" onClick={() => onOpenTimeline(item.id)}>Open in Timeline</button>
          )}
          {item.seal && <ReceiptButton seal={item.seal} label="Download receipt" />}
        </div>

        <details className="sheet-raw">
          <summary>The record as stored</summary>
          <pre className="mono">{JSON.stringify(record, null, 1)}</pre>
        </details>
      </aside>
    </div>
  )
}
