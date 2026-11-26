/**
 * Admin-added sites: the pure logic, with no chrome.* calls, so it runs the
 * same in the service worker (importScripts), the popup and node tests.
 *
 * Shield policy lists `extra_sites`; only hosts that are also in the curated
 * list (shield-optional.js, generated from optional_sites.json, and the same
 * origins as the manifest's optional_host_permissions) are ever acted on.
 */
(function (root) {
  'use strict'

  const MAX_SITES = 20
  const originOf = (host) => `https://${host}/*`
  const idOf = (world, host) => `shield-extra-${world}-${host}`

  // The same scripts the static manifest entries inject, in the same worlds.
  const MAIN_JS = ['shield-rules.js', 'shield-sites.js', 'shield-core.js', 'content.js']
  const ISO_JS = ['shield-iso.js', 'consent.js', 'content-relay.js']

  /** Script definitions for one host (what registerContentScripts takes). */
  function definitionsFor(host) {
    const matches = [originOf(host)]
    return [
      { id: idOf('main', host), matches, js: MAIN_JS, world: 'MAIN', runAt: 'document_start',
        allFrames: true, matchAboutBlank: true, persistAcrossSessions: true },
      { id: idOf('iso', host), matches, js: ISO_JS, runAt: 'document_start', persistAcrossSessions: true },
    ]
  }

  /**
   * Clean what the signed policy said: keep only curated hosts, at most
   * MAX_SITES, names and selectors trimmed. Anything else is dropped (the
   * server refuses such writes; this is the second check on the device).
   */
  function cleanExtraSites(raw, curated) {
    if (!Array.isArray(raw)) return []
    const allowed = new Set((curated || []).map((c) => c.host))
    const out = []
    const seen = new Set()
    for (const item of raw.slice(0, MAX_SITES)) {
      const host = item && typeof item.host === 'string' ? item.host.toLowerCase() : ''
      if (!allowed.has(host) || seen.has(host)) continue
      seen.add(host)
      const app = typeof item.app === 'string' && /^[A-Za-z0-9][A-Za-z0-9 .-]{0,39}$/.test(item.app) ? item.app : host
      const sel = (v) => (Array.isArray(v) ? v.filter((s) => typeof s === 'string' && s && s.length <= 200).slice(0, 5) : [])
      out.push({ host, app, compose: sel(item.compose), send: sel(item.send) })
    }
    return out
  }

  const sig = (d) => JSON.stringify([d.js, d.matches, d.world || 'ISOLATED'])

  /**
   * What to do now. `wanted` is the cleaned list, `registered` what Chrome
   * reports, `granted` a Set of hosts whose origin permission is held.
   * Returns { register, update, unregister, needsPermission }: register and
   * update hold full definitions, unregister holds ids.
   */
  function planExtraSites({ wanted, registered, granted }) {
    const have = new Map((registered || []).map((r) => [r.id, r]))
    const want = new Map()
    const needsPermission = []
    for (const site of wanted || []) {
      if (!granted.has(site.host)) { needsPermission.push(site.host); continue }
      for (const def of definitionsFor(site.host)) want.set(def.id, def)
    }
    const register = []
    const update = []
    for (const [id, def] of want) {
      const cur = have.get(id)
      if (!cur) register.push(def)
      else if (sig(cur) !== sig(def)) update.push(def)
    }
    const unregister = [...have.keys()].filter((id) => id.startsWith('shield-extra-') && !want.has(id))
    return { register, update, unregister, needsPermission }
  }

  /** The sites an admin listed that this browser has not allowed yet. */
  const pendingGrants = (wanted, granted) => (wanted || []).filter((s) => !granted.has(s.host))

  /** Plain words for the popup: which site needs permission, and why. */
  const grantLine = (site) =>
    `Your administrator added ${site.app}. Shield cannot check it until you allow this browser to run on ${site.host}.`

  const api = { MAX_SITES, originOf, definitionsFor, cleanExtraSites, planExtraSites, pendingGrants, grantLine }
  root.SHIELD_EXTRA_SITES = api
  if (typeof module !== 'undefined' && module.exports) module.exports = api
})(typeof globalThis !== 'undefined' ? globalThis : this)
