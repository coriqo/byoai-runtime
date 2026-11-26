/**
 * Ledger: every sealed entry with its receipt, the chain export, and (in the
 * rail) the offline check anyone can run on a receipt without trusting us.
 */
import { useMutation, useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { fetchVerify } from '@/api/shield'
import { checkReceipt } from '@/lib/receipt'
import type { ReceiptCheck } from '@/lib/receipt'
import { Banner, FileEvidence, HashChip, ReceiptButton, SectionHead, downloadBlob, humanize, plural, tierLabel, tierTagClass, useFeed } from './shared'
import type { Item } from './shared'

export function Ledger({ onOpen }: { onOpen: (it: Item) => void }) {
  const verify = useQuery({ queryKey: ['shield-verify'], queryFn: fetchVerify, refetchInterval: 10_000 })
  const feed = useFeed()
  const sealed = (feed.data?.items ?? []).filter(it => it.seal)
  const v = verify.data

  // Fetched at click time: the export must match the chain now, not the
  // copy the screen last polled.
  const exportChain = useMutation({
    mutationFn: fetchVerify,
    onSuccess: fresh => downloadBlob(
      new Blob([JSON.stringify(fresh, null, 1)], { type: 'application/json' }),
      'byoai-chain-state.json'),
  })

  return (
    <div className="shield-split">
      <div className="shield-main">
        <SectionHead id="ledger-h" title="Sealed entries" accent />
        <div className="ledger-head">
          {v
            ? v.tamper_evident
              ? <span className="tag ok">Verified</span>
              : <span className="tag bad" role="alert">Verification fails at entry {v.broken_at ?? 'unknown'}: {humanize(v.reason ?? 'entry does not match its seal')}</span>
            : <span className="tag unknown">Checking…</span>}
          {v?.tamper_evident && (
            <span className="verdict-facts">
              <span>{plural(v.entries ?? 0, 'sealed entry', 'sealed entries')}</span>
              {v.merkle_root && <span>Root <HashChip value={v.merkle_root} noun="root hash" /></span>}
              <span>Device {v.checkpoint?.device_id
                ? <HashChip value={v.checkpoint.device_id} noun="device id" short={18} />
                : 'not signed yet'}</span>
            </span>
          )}
          <span className="spacer" />
          <button className="btn sm" disabled={exportChain.isPending} onClick={() => exportChain.mutate()}>
            {exportChain.isPending ? 'Exporting…' : 'Export chain state'}
          </button>
          {exportChain.isError && <span className="tag bad" role="alert">Export failed: {exportChain.error.message}</span>}
        </div>
        <p className="ledger-note">
          Each entry is sealed when Shield checks it. The seal covers the app,
          the verdict, the rules matched, the message length and its
          fingerprint, not the words. Entries are folded into a Merkle tree
          signed with this Mac's device key. Edit an entry later and its
          receipt fails verification.
        </p>
        {feed.isError && (
          <p className="empty-row" role="alert">
            <b>Can't reach Shield on this Mac.</b>
            Start it with <code className="mono">byoai-shield</code>, then reload this page.
          </p>
        )}
        {feed.isPending && <p className="empty-row" role="status">Loading sealed entries…</p>}
        <div className="table-scroll">
          <table className="shield-table">
            <thead>
              <tr><th>When</th><th>App</th><th>What happened</th><th>Result</th><th>Seal</th><th aria-label="Receipt" /></tr>
            </thead>
            <tbody>
              {sealed.map(it => (
                <tr key={it.id} onClick={() => onOpen(it)} className="clickable">
                  <td>{it.date} {it.ts?.slice(0, 5)}</td>
                  <td>{it.surface.split(' ·')[0]}</td>
                  <td className="verb-cell">{it.verb}{it.file && <><br /><FileEvidence item={it} /></>}</td>
                  <td><span className={`tag ${tierTagClass(it.tier)}`}>{tierLabel(it)}</span></td>
                  <td><span className="hash" title={it.seal}>{it.seal.slice(0, 16)}</span></td>
                  <td onClick={e => e.stopPropagation()}><ReceiptButton seal={it.seal} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {feed.data && sealed.length === 0 && (
          <p className="empty-row">
            Nothing sealed yet. Everything Shield checks appears here with its seal and a receipt.
          </p>
        )}
      </div>
      <aside className="shield-rail">
        <ReceiptVerifier />
      </aside>
    </div>
  )
}

function ReceiptVerifier() {
  const [text, setText] = useState('')
  const [res, setRes] = useState<ReceiptCheck | null>(null)
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    try { setRes(await checkReceipt(text)) } finally { setBusy(false) }
  }
  return (
    <section className="panel" aria-labelledby="verify-h">
      <SectionHead id="verify-h" title="Check a receipt"
        help="Paste a downloaded receipt. This browser recomputes its hashes; nothing is sent anywhere." />
      <textarea
        className="receipt-input mono" aria-label="Receipt JSON"
        placeholder='{"kind":"byoai.receipt.v2", …}'
        value={text} onChange={e => { setText(e.target.value); setRes(null) }}
      />
      <button className="btn primary" disabled={busy || !text.trim()} onClick={run}>
        {busy ? 'Checking…' : 'Check receipt'}
      </button>
      {res && (
        <Banner tone={res.ok ? 'ok' : 'bad'} role="status" className="receipt-result">
          {res.ok
            ? res.level === 'merkle'
              ? (
                <div>
                  <span><b>Receipt checks out.</b> The entry matches its seal and its proof leads to the root below. The device signature on that root is checked on the Mac that exported it.</span>
                  <p className="verdict-facts">
                    {res.root && <span>Root <HashChip value={res.root} noun="root hash" /></span>}
                    {res.deviceId && <span>Device <HashChip value={res.deviceId} noun="device id" short={18} /></span>}
                  </p>
                </div>
              )
              : <span><b>The entry matches its seal.</b> This receipt has no Merkle proof, so it can't be tied to a root.</span>
            : (
              <div>
                <span><b>Receipt fails verification.</b> {res.why}</span>
                {res.computed && res.claimed && (
                  <p className="verdict-facts">
                    <span>Computed <HashChip value={res.computed} noun="computed hash" /></span>
                    <span>Receipt says <HashChip value={res.claimed} noun="claimed hash" /></span>
                  </p>
                )}
              </div>
            )}
        </Banner>
      )}
    </section>
  )
}
