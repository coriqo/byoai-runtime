// @vitest-environment node
/**
 * Guards for the Shield UI standard. Shield is a separate codebase from the
 * Coriqo app, so it mirrors the rules rather than importing them: tokens only,
 * system sans with the serif for titles, sentence case, the icon scale, 44px
 * targets, the seal's navy on every filled control, one visible focus ring,
 * dark mode through tokens, and contrast that clears WCAG AA in both themes.
 *
 * Surfaces covered: web/src (the Shield window and the Shield server console)
 * and the extension's own pages (popup.html, welcome.html). `tokens.css` is the
 * one place a colour, shadow or size literal may appear; the extension's
 * `shield-tokens.css` is generated from it (tests/integrations/test_shield_tokens.py).
 *
 * Counts that cannot reach zero in this change are ratcheted in
 * `shieldStandardsBaseline.json` with the reason beside each: they may go
 * down, never up.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const WEB_SRC = path.resolve(HERE, '..')
const REPO = path.resolve(WEB_SRC, '..', '..')
const EXT = path.join(REPO, 'src', 'byoai', 'browser_extension')
const BASELINE = JSON.parse(readFileSync(path.join(HERE, 'shieldStandardsBaseline.json'), 'utf8')) as {
  counts: Record<string, number>
}

const read = (p: string) => readFileSync(p, 'utf8')
function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name)
    if (statSync(p).isDirectory()) walk(p, out)
    else out.push(p)
  }
  return out
}

const rel = (p: string) => path.relative(REPO, p)
const isSource = (p: string) =>
  /\.(tsx?|css)$/.test(p) && !/\.test\.|\.gen\.|[\\/]mocks[\\/]|[\\/]__/.test(p) && !p.endsWith('tokens.css')
const SRC_FILES = walk(WEB_SRC).filter(isSource)
const CSS_FILES = SRC_FILES.filter(p => p.endsWith('.css'))
const TSX_FILES = SRC_FILES.filter(p => /\.tsx$/.test(p))
const EXT_PAGES = ['popup.html', 'welcome.html'].map(f => path.join(EXT, f))
const SHIELD_CSS = path.join(HERE, 'shield.css')
const COMPONENTS_CSS = path.join(HERE, 'components.css')
const TOKENS = read(path.join(HERE, 'tokens.css'))

const stripComments = (css: string) => css.replace(/\/\*[\s\S]*?\*\//g, '')
/** `[selector, body]` for every flat rule, including those inside @media. */
function rules(css: string): [string, string][] {
  const out: [string, string][] = []
  for (const m of stripComments(css).matchAll(/([^{}]*)\{([^{}]*)\}/g)) out.push([m[1]!.trim(), m[2]!])
  return out
}
/** The CSS inside every <style> block of an HTML page. */
const styleOf = (html: string) => [...html.matchAll(/<style>([\s\S]*?)<\/style>/g)].map(m => m[1]).join('\n')

const SURFACE_CSS: [string, string][] = [
  ...CSS_FILES.map(p => [rel(p), read(p)] as [string, string]),
  ...EXT_PAGES.map(p => [rel(p), styleOf(read(p))] as [string, string]),
]

describe('tokens: one file, no literals anywhere else', () => {
  it('no hex, rgb or hsl colour outside tokens.css', () => {
    const bad: string[] = []
    const files: [string, string][] = [
      ...SRC_FILES.map(p => [rel(p), stripComments(read(p))] as [string, string]),
      ...EXT_PAGES.map(p => [rel(p), read(p).replace(/<!--[\s\S]*?-->/g, '')] as [string, string]),
    ]
    for (const [name, text] of files) {
      for (const m of text.matchAll(/#[0-9a-fA-F]{3,8}\b|\b(?:rgba?|hsla?)\(/g)) {
        // `#` anchors and ids are not colours: a colour literal is hex digits only.
        const line = text.slice(0, m.index).split('\n').length
        bad.push(`${name}:${line} ${m[0]}`)
      }
    }
    expect(bad).toEqual([])
  })

  it('no box-shadow literal: a shadow is a token', () => {
    const bad: string[] = []
    for (const [name, css] of SURFACE_CSS) {
      for (const [sel, body] of rules(css)) {
        for (const m of body.matchAll(/box-shadow:\s*([^;]+);?/g)) {
          const v = m[1]!.trim()
          // An inset edge or a focus ring built from tokens only is a state, not an elevation.
          if (!/^(var\(--shadow-(sm|md|lg)\)|var\(--lift\)|none|inset 0 0 0 1px var\(--[a-z-]+\)|inset 3px 0 0 var\(--[a-z-]+\)|0 0 0 3px var\(--[a-z-]+\))$/.test(v)) {
            bad.push(`${name}: ${sel} { box-shadow: ${v} }`)
          }
        }
      }
    }
    expect(bad).toEqual([])
  })

  it('every colour token in tokens.css has a dark value (light-dark, an alias, a mix, or the brand constant)', () => {
    const INVARIANT = new Set(['--seal', '--seal-tile'])
    const bad: string[] = []
    for (const m of TOKENS.matchAll(/^\s*(--[a-z0-9-]+):\s*([^;]+);/gm)) {
      const [, name, value] = m
      if (!/#[0-9a-fA-F]{3,8}\b|rgba?\(/.test(value!)) continue
      if (/light-dark\(|color-mix\(/.test(value!) || INVARIANT.has(name!)) continue
      bad.push(`${name}: ${value}`)
    }
    expect(bad).toEqual([])
  })
})

describe('type: system sans, the serif for titles, sentence case, the scale', () => {
  it('font sizes name the type scale; no bare px or rem', () => {
    const bad: string[] = []
    for (const [name, css] of SURFACE_CSS) {
      for (const [sel, body] of rules(css)) {
        for (const m of body.matchAll(/font-size:\s*([^;]+)/g)) {
          const v = m[1]!.trim()
          if (!/^(var\(--(text-[a-z]+|t-[a-z]+)\)|inherit|0)$/.test(v)) bad.push(`${name}: ${sel} { font-size: ${v} }`)
        }
        for (const m of body.matchAll(/\bfont:\s*([^;]+)/g)) {
          if (/\b\d+(\.\d+)?(px|rem|em)\b/.test(m[1]!)) bad.push(`${name}: ${sel} { font: ${m[1]} }`)
        }
      }
    }
    expect(bad).toEqual([])
  })

  it('TSX sets a font size inline only from a token', () => {
    const bad = TSX_FILES.filter(p => /fontSize\s*:(?!\s*['"]var\(--(text|t)-)/.test(read(p))).map(rel)
    expect(bad).toEqual([])
  })

  it('no uppercase text-transform and no positive letter-spacing (tracking) on any surface', () => {
    const bad: string[] = []
    for (const [name, css] of SURFACE_CSS) {
      for (const [sel, body] of rules(css)) {
        if (/text-transform:\s*uppercase/.test(body)) bad.push(`${name}: ${sel} uppercase`)
        const ls = body.match(/letter-spacing:\s*([^;]+)/)
        if (ls && !ls[1]!.trim().startsWith('-')) bad.push(`${name}: ${sel} letter-spacing ${ls[1]}`)
      }
    }
    expect(bad).toEqual([])
  })

  it('mono is for identifiers only: only these selectors may set the mono face', () => {
    const ALLOWED = [
      '.mono', '.hash', '.ref', '.tl-row .seq', '.seq-scoped', '.payload', '.empty code', '.addr',
      '.help code', '.brand .ver', 'input[type=text]', 'code', '.tree li', '.tree', '.span-id', 'pre',
    ]
    const bad: string[] = []
    for (const [name, css] of SURFACE_CSS) {
      for (const [sel, body] of rules(css)) {
        if (!/font-family:\s*var\(--font-mono\)|font:[^;]*var\(--font-mono\)/.test(body)) continue
        const sels = sel.split(',').map(s => s.trim().replace(/^.*\}\s*/, ''))
        if (!sels.every(s => ALLOWED.some(a => s === a || s.startsWith(`${a} `) || s.startsWith(`${a}.`) || s.startsWith(`${a}:`)))) {
          bad.push(`${name}: ${sel}`)
        }
      }
    }
    expect(bad).toEqual([])
  })

  const ACRONYM_OR_NAME = new Set([
    'Shield', 'Coriqo', 'Mac', 'Macs', 'Claude', 'ChatGPT', 'Gemini', 'Copilot', 'MCP', 'AI', 'SHA', 'IBAN', 'JWT',
    'Chrome', 'Merkle', 'Ed25519', 'API', 'GitHub', 'Anthropic', 'OpenAI', 'AWS', 'SSN', 'Slack', 'Google', 'Stripe',
  ])
  function titleCased(text: string): boolean {
    const words = text.trim().split(/\s+/).slice(1).filter(w => /^[A-Za-z]/.test(w))
    const caps = words.filter(w => /^[A-Z][a-z]/.test(w) && !ACRONYM_OR_NAME.has(w.replace(/[^A-Za-z0-9]/g, '')))
    return caps.length >= 1 && words.length >= 1 && caps.length >= Math.min(2, words.length)
  }

  it('headings and section titles are sentence case', () => {
    const bad: string[] = []
    for (const p of TSX_FILES.filter(f => /shield|Shield|routes/.test(f))) {
      const text = read(p)
      for (const m of text.matchAll(/\btitle="([^"]+)"/g)) if (titleCased(m[1]!)) bad.push(`${rel(p)}: ${m[1]}`)
      for (const m of text.matchAll(/<h[1-3][^>]*>([^<{]+)</g)) if (titleCased(m[1]!)) bad.push(`${rel(p)}: ${m[1]}`)
    }
    for (const p of EXT_PAGES) {
      for (const m of read(p).matchAll(/<(h[1-3]|summary)[^>]*>([^<]+)</g)) if (titleCased(m[2]!)) bad.push(`${rel(p)}: ${m[2]}`)
    }
    expect(bad).toEqual([])
  })
})

describe('icons: the 12 / 16 / 20 / 24 / 32 / 48 scale', () => {
  const SCALE = new Set([12, 16, 20, 24, 32, 48])
  it('every icon size in a component is on the scale', () => {
    const bad: string[] = []
    for (const p of TSX_FILES) {
      const text = read(p)
      for (const m of text.matchAll(/<(?:Icon|SealMark|StatusSeal)\b[^>]*?\bsize=\{(\d+)\}/g)) {
        if (!SCALE.has(Number(m[1]))) bad.push(`${rel(p)}: size ${m[1]}`)
      }
      for (const m of text.matchAll(/<svg[^>]*\b(?:width|height)="(\d+)"/g)) {
        if (!SCALE.has(Number(m[1]))) bad.push(`${rel(p)}: svg ${m[1]}`)
      }
    }
    for (const p of EXT_PAGES) {
      for (const m of read(p).matchAll(/<svg[^>]*\b(?:width|height)="(\d+)"/g)) {
        if (!SCALE.has(Number(m[1]))) bad.push(`${rel(p)}: svg ${m[1]}`)
      }
    }
    expect(bad).toEqual([])
  })

  it('the icon size classes and tokens are exactly the scale', () => {
    const classes = [...stripComments(read(SHIELD_CSS)).matchAll(/\.icon-(\d+)\s*\{/g)].map(m => Number(m[1]))
    expect(new Set(classes)).toEqual(SCALE)
    const tokens = [...TOKENS.matchAll(/--icon-[a-z]+:\s*(\d+)px/g)].map(m => Number(m[1]))
    expect(new Set(tokens)).toEqual(SCALE)
  })
})

describe('targets and focus', () => {
  it('tokens: 44px target, applied below 960px and on touch screens', () => {
    expect(TOKENS).toMatch(/--target:\s*44px/)
    expect(TOKENS).toMatch(/@media \(max-width: 960px\), \(pointer: coarse\)\s*\{\s*:root\s*\{\s*--target-min:\s*var\(--target\)/)
  })

  const MUST_HAVE_TARGET = [
    '.btn', '.shield-nav button', '.filterbar input', '.filterbar button.filter', '.shield-row', '.stat-btn',
    '.tl-step', '.row-app', '.mode-row', '.coriqo-form input',
  ]
  it.each(MUST_HAVE_TARGET)('%s has a minimum target height', sel => {
    const all = [...rules(read(COMPONENTS_CSS)), ...rules(read(SHIELD_CSS))]
    const hit = all.filter(([s]) => s.split(',').some(x => x.trim() === sel || x.trim().endsWith(sel)))
    expect(hit.length, `no rule for ${sel}`).toBeGreaterThan(0)
    expect(hit.some(([, body]) => /min-height:\s*var\(--target(-min)?\)/.test(body)), `${sel} needs min-height: var(--target-min)`).toBe(true)
  })

  it('the extension pages size their controls from the same tokens', () => {
    for (const p of EXT_PAGES) {
      const css = styleOf(read(p))
      expect(css, rel(p)).toMatch(/button[^{]*\{[^}]*min-height:\s*var\(--target/)
    }
  })

  it('one visible focus ring: no rule removes the outline without a replacement', () => {
    const bad: string[] = []
    for (const [name, css] of SURFACE_CSS) {
      for (const [sel, body] of rules(css)) {
        if (/outline:\s*none/.test(body) && !/:focus:not\(:focus-visible\)/.test(sel)) bad.push(`${name}: ${sel}`)
      }
    }
    expect(bad).toEqual([])
    expect(stripComments(read(COMPONENTS_CSS))).toMatch(/:focus-visible\s*\{\s*outline:\s*2px solid var\(--azure\)/)
  })
})

describe('brand: the reticle seal and the action navy', () => {
  it('no filled control uses the azure; every .primary uses the action fill', () => {
    const bad: string[] = []
    for (const [name, css] of SURFACE_CSS) {
      for (const [sel, body] of rules(css)) {
        const control = /(^|[\s.,>])(btn|button|primary)\b|\bbutton\b/.test(sel)
        if (control && /background(-color)?:\s*var\(--azure/.test(body)) bad.push(`${name}: ${sel} fills with azure`)
        if (/\.primary\b/.test(sel) && /background/.test(body) && !/background:\s*var\(--action/.test(body)) {
          bad.push(`${name}: ${sel} is not the action fill`)
        }
      }
    }
    expect(bad).toEqual([])
  })

  it('the action tokens: tile navy in light, the accent in dark', () => {
    expect(TOKENS).toMatch(/--action:\s*light-dark\(#0A1834,/i)
    expect(TOKENS).toMatch(/--seal:\s*#3F7BFF/i)
  })

  it('the seal is the one mark: the popup, the welcome page and the app draw the same reticle', () => {
    const reticle = /<circle[^>]*\br="11"[\s\S]*?<circle[^>]*\br="4\.6"/
    for (const p of EXT_PAGES) {
      const html = read(p)
      expect(html, rel(p)).toMatch(reticle)
      // The shield-with-a-tick drawing the popup used to wear.
      expect(html, rel(p)).not.toMatch(/M12 3l8 3v6c0/)
    }
    expect(read(path.join(WEB_SRC, 'components', 'shield', 'shared.tsx'))).toMatch(/r="11"[\s\S]*?r="4\.6"/)
  })

  it('the wordmark is the sans (never uppercase, never mono)', () => {
    const css = rules(read(COMPONENTS_CSS)).filter(([s]) => s === '.wordmark').map(([, b]) => b).join('')
    expect(css).toMatch(/font-family:\s*var\(--font-ui\)/)
    expect(css).not.toMatch(/uppercase|font-mono/)
  })
})

describe('shape and space', () => {
  it('a round marker keeps an equal box (aspect-ratio) so a flex row never makes an oval', () => {
    const bad: string[] = []
    for (const [name, css] of SURFACE_CSS) {
      for (const [sel, body] of rules(css)) {
        if (/border-radius:\s*50%/.test(body) && !/aspect-ratio:\s*1/.test(body)) bad.push(`${name}: ${sel}`)
      }
    }
    expect(bad).toEqual([])
  })

  it('radius, padding, margin and gap are tokens (shield.css has none bare; components.css is ratcheted)', () => {
    const bare = (css: string) => {
      let n = 0
      for (const [, body] of rules(css)) {
        for (const m of body.matchAll(/(?:padding|margin|gap|border-radius)[a-z-]*:\s*([^;]+)/g)) {
          const v = m[1]!.replace(/var\([^)]*\)/g, '').replace(/calc\([^)]*\)/g, '')
          if (/(?<![\d.])(?!1px\b)\d*\.?\d+(px|rem)\b/.test(v.replace(/-1px/g, ''))) n += 1
        }
      }
      return n
    }
    expect(bare(read(SHIELD_CSS))).toBe(0)
    expect(bare(read(COMPONENTS_CSS))).toBeLessThanOrEqual(BASELINE.counts['components.css bare spacing']!)
    for (const p of EXT_PAGES) expect(bare(styleOf(read(p))), rel(p)).toBe(0)
  })
})

/* ---------------------------------------------------------------- contrast */

type RGBA = [number, number, number, number]
function splitTop(s: string): string[] {
  const out: string[] = []
  let depth = 0
  let cur = ''
  for (const ch of s) {
    if (ch === '(') depth += 1
    if (ch === ')') depth -= 1
    if (ch === ',' && depth === 0) { out.push(cur.trim()); cur = '' } else cur += ch
  }
  out.push(cur.trim())
  return out
}
const DECLS = new Map<string, string>()
for (const m of TOKENS.matchAll(/^\s*(--[a-z0-9-]+):\s*([^;]+);/gm)) DECLS.set(m[1]!, m[2]!.trim())

function colour(value: string, dark: boolean): RGBA {
  const v = value.trim()
  const ld = v.match(/^light-dark\((.*)\)$/s)
  if (ld) { const [l, d] = splitTop(ld[1]!); return colour(dark ? d! : l!, dark) }
  const ref = v.match(/^var\((--[a-z0-9-]+)\)$/)
  if (ref) return colour(DECLS.get(ref[1]!)!, dark)
  if (v === 'transparent') return [0, 0, 0, 0]
  const hex = v.match(/^#([0-9a-f]{6})$/i)
  if (hex) { const n = parseInt(hex[1]!, 16); return [(n >> 16) & 255, (n >> 8) & 255, n & 255, 1] }
  const rgba = v.match(/^rgba?\(([^)]*)\)$/)
  if (rgba) { const p = rgba[1]!.split(',').map(x => Number(x.trim())); return [p[0]!, p[1]!, p[2]!, p[3] ?? 1] }
  const mix = v.match(/^color-mix\(in srgb,\s*(.*)\)$/s)
  if (mix) {
    const [a, b] = splitTop(mix[1]!).slice(0, 2)
    const part = (s: string): [string, number | null] => {
      const m = s.match(/^(.*?)(?:\s+(\d+(?:\.\d+)?)%)?$/s)!
      return [m[1]!.trim(), m[2] === undefined ? null : Number(m[2]) / 100]
    }
    const [ca, pa0] = part(a!)
    const [cb, pb0] = part(b!)
    const pa = pa0 ?? (pb0 === null ? 0.5 : 1 - pb0)
    const A = colour(ca, dark)
    const B = colour(cb, dark)
    // CSS mixes premultiplied: a share of the colour, and of its opacity.
    const alpha = A[3] * pa + B[3] * (1 - pa)
    const ch = (i: 0 | 1 | 2) => alpha === 0 ? 0 : (A[i] * A[3] * pa + B[i] * B[3] * (1 - pa)) / alpha
    return [ch(0), ch(1), ch(2), alpha]
  }
  throw new Error(`cannot read colour ${v}`)
}
const over = (fg: RGBA, bg: RGBA): RGBA => {
  const a = fg[3]
  return [fg[0] * a + bg[0] * (1 - a), fg[1] * a + bg[1] * (1 - a), fg[2] * a + bg[2] * (1 - a), 1]
}
const lum = ([r, g, b]: RGBA) => {
  const f = (c: number) => { const s = c / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4 }
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)
}
const ratio = (a: RGBA, b: RGBA) => {
  const [hi, lo] = [lum(a), lum(b)].sort((x, y) => y - x) as [number, number]
  return (hi + 0.05) / (lo + 0.05)
}

describe.each([['light', false], ['dark', true]] as const)('contrast (WCAG 2.x AA), %s theme', (_name, dark) => {
  const tok = (n: string) => colour(`var(${n})`, dark)
  const surfaces = ['--paper', '--field', '--paper-2']
  const text = (fg: string, bgName: string, bg: RGBA = tok(bgName)) => ratio(over(tok(fg), bg), bg)

  it.each(surfaces)('ink and muted ink clear 4.5:1 on %s', s => {
    expect(text('--ink', s)).toBeGreaterThanOrEqual(4.5)
    expect(text('--ink-soft', s)).toBeGreaterThanOrEqual(4.5)
  })

  it.each(['--validated', '--pending', '--off-scope', '--azure-soft'])('%s text clears 4.5:1 on the surfaces and on its own tint', fg => {
    for (const s of ['--paper', '--field']) expect(text(fg, s), `${fg} on ${s}`).toBeGreaterThanOrEqual(4.5)
    const tint = fg === '--azure-soft' ? '--azure-glow' : `${fg}-bg`
    const base = tok('--field')
    const bg = over(tok(tint), base)
    expect(ratio(tok(fg), bg), `${fg} on ${tint}`).toBeGreaterThanOrEqual(4.5)
  })

  it('ink and muted ink clear 4.5:1 on every tint a banner or tag can wear', () => {
    for (const t of ['--validated-bg', '--pending-bg', '--off-scope-bg', '--azure-glow']) {
      const bg = over(tok(t), tok('--field'))
      expect(ratio(tok('--ink'), bg), t).toBeGreaterThanOrEqual(4.5)
      expect(ratio(tok('--ink-soft'), bg), `muted on ${t}`).toBeGreaterThanOrEqual(4.5)
    }
  })

  it('the text on a filled control clears 4.5:1 on its fill and its hover fill', () => {
    expect(ratio(tok('--on-action'), tok('--action'))).toBeGreaterThanOrEqual(4.5)
    expect(ratio(tok('--on-action'), tok('--action-hover'))).toBeGreaterThanOrEqual(4.5)
    expect(ratio(tok('--on-status'), tok('--off-scope'))).toBeGreaterThanOrEqual(4.5)
    expect(ratio(tok('--on-status'), tok('--validated'))).toBeGreaterThanOrEqual(4.5)
  })

  it('control edges, the focus ring and the action fill clear 3:1 against the surfaces (WCAG 1.4.11)', () => {
    for (const s of ['--paper', '--field']) {
      expect(ratio(tok('--control'), tok(s)), `control on ${s}`).toBeGreaterThanOrEqual(3)
      expect(ratio(tok('--azure'), tok(s)), `azure on ${s}`).toBeGreaterThanOrEqual(3)
      expect(ratio(tok('--action'), tok(s)), `action on ${s}`).toBeGreaterThanOrEqual(3)
    }
  })
})
