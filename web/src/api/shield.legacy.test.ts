import { describe, expect, it } from 'vitest'
import raw from './fixtures/feed_legacy_rows.json'
import { ShieldFeed, UNREADABLE_VERB } from './shield'

describe('a feed with legacy rows', () => {
  it('parses the recorded server response, every flag tier in the contract', () => {
    const feed = ShieldFeed.parse(raw)
    expect(feed.items).toHaveLength(raw.items.length)
    expect(feed.items.some(i => i.unreadable)).toBe(false)
  })

  it('maps the internal tiers a Shield from before the contract still sends', () => {
    const old = structuredClone(raw)
    old.items[0]!.flags = [{ tier: 'secret', rule: 'api_keys' }, { tier: 'flag', rule: 'password_said' }]
    const feed = ShieldFeed.parse(old)
    expect(feed.items[0]!.flags.map(f => f.tier)).toEqual(['high', 'agent'])
    expect(feed.items[0]!.unreadable).toBeUndefined()
  })

  it('keeps a row it cannot read, countable and never clean, and the rest of the list', () => {
    const bad = structuredClone(raw)
    bad.items[1]!.flags = [{ tier: 'mystery', rule: 'x' }]
    const feed = ShieldFeed.parse(bad)
    expect(feed.items).toHaveLength(raw.items.length)
    const row = feed.items[1]!
    expect(row.unreadable).toBe(true)
    expect(row.tier).not.toBe('ok')
    expect(row.id).toBe(raw.items[1]!.id)
    expect(row.verb).toBe(UNREADABLE_VERB)
    expect(feed.items[0]!.unreadable).toBeUndefined()
    expect(JSON.stringify(row)).not.toContain('mystery')
  })

  it('survives a row that is not an object at all', () => {
    const bad = structuredClone(raw) as { items: unknown[] }
    bad.items[0] = 42
    const feed = ShieldFeed.parse(bad)
    expect(feed.items[0]!).toMatchObject({ unreadable: true, tier: 'warn' })
  })
})
