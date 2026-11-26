/**
 * Offline check of a Shield receipt (`byoai.receipt.v2`), run entirely in the
 * browser: no request, no server, no account.
 *
 * It redoes the receipt's own math with the same rules as
 * `src/byoai/recorder/merkle.py`:
 *
 *   leaf = sha256(0x00 || canonical(payload))      first 16 hex = the seal
 *   node = sha256(0x01 || left || right)           a step's `side` is where
 *                                                  the sibling sits
 *
 * and checks the fold lands on the root the receipt's checkpoint names. The
 * checkpoint's Ed25519 signature is not checked here: the receipt carries the
 * signature but not every field that was signed, so that check stays with the
 * Mac that exported it. The result says so rather than implying more.
 */

export type ReceiptCheck =
  | { ok: true; level: 'merkle' | 'payload'; root?: string; deviceId?: string }
  /** `computed` and `claimed` are the two values that disagree, shown as facts, never in the sentence. */
  | { ok: false; why: string; computed?: string; claimed?: string }

/** Sorted keys, compact separators: byte-equal to the recorder's canonical
 * form for the strings, numbers, booleans and nulls a seal payload holds. */
export function canonical(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`
  const o = v as Record<string, unknown>
  return `{${Object.keys(o).sort().map(k => `${JSON.stringify(k)}:${canonical(o[k])}`).join(',')}}`
}

const hex = (u8: Uint8Array) => [...u8].map(b => b.toString(16).padStart(2, '0')).join('')
const bytes = (h: string) => Uint8Array.from(h.match(/../g) ?? [], x => parseInt(x, 16))

async function sha256(...parts: Uint8Array[]): Promise<string> {
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let o = 0
  for (const p of parts) { all.set(p, o); o += p.length }
  return hex(new Uint8Array(await crypto.subtle.digest('SHA-256', all)))
}

const LEAF = new Uint8Array([0x00])
const NODE = new Uint8Array([0x01])
const HEX64 = /^[0-9a-f]{64}$/

interface Step { sibling: string; side: string }

export async function checkReceipt(text: string): Promise<ReceiptCheck> {
  let r: {
    kind?: string
    seal?: string
    payload?: unknown
    merkle?: {
      proof?: { steps?: Step[] | null; root_hex?: string }
      checkpoint?: { root_hex?: string; device_id?: string } | null
    }
  }
  if (!globalThis.crypto?.subtle) {
    return {
      ok: false,
      why: 'This browser only allows hashing on a secure page. Open Shield at localhost or over https, or check the receipt with coriqo-verify.',
    }
  }
  let unsafeNumber = false
  try {
    // A whole number past 2^53 can't round-trip through a browser number, so
    // re-hashing it here would wrongly report tampering. Say so instead.
    r = JSON.parse(text, (_k, v: unknown) => {
      if (typeof v === 'number' && Number.isInteger(v) && !Number.isSafeInteger(v)) unsafeNumber = true
      return v
    })
  } catch {
    return { ok: false, why: "That isn't valid JSON. Paste a receipt exactly as it was downloaded." }
  }
  if (unsafeNumber) {
    return {
      ok: false,
      why: 'This receipt holds a number too large for a browser to check exactly. Check it with coriqo-verify instead; nothing here says it was changed.',
    }
  }
  if (r?.kind !== 'byoai.receipt.v2') {
    return { ok: false, why: 'This is not a Shield receipt (version 2). Paste a receipt exactly as it was downloaded.' }
  }
  const leaf = await sha256(LEAF, new TextEncoder().encode(canonical(r.payload)))
  if (leaf.slice(0, 16) !== r.seal) {
    return {
      ok: false,
      why: "The entry doesn't match its seal. The receipt was changed after export.",
      computed: leaf.slice(0, 16),
      claimed: r.seal,
    }
  }
  const proof = r.merkle?.proof
  if (!proof?.root_hex) return { ok: true, level: 'payload' }

  let node = leaf
  for (const step of proof.steps ?? []) {
    if (!HEX64.test(step.sibling)) return { ok: false, why: 'The proof holds a malformed hash.' }
    node = step.side === 'right'
      ? await sha256(NODE, bytes(node), bytes(step.sibling))
      : await sha256(NODE, bytes(step.sibling), bytes(node))
  }
  if (node !== proof.root_hex) {
    return {
      ok: false,
      why: 'The proof does not lead to the root the receipt claims. The receipt was changed after export.',
      computed: node,
      claimed: proof.root_hex,
    }
  }
  const cp = r.merkle?.checkpoint
  if (cp?.root_hex && cp.root_hex !== proof.root_hex) {
    return { ok: false, why: "The proof's root and the checkpoint's root disagree." }
  }
  return { ok: true, level: 'merkle', root: proof.root_hex, deviceId: cp?.device_id }
}
