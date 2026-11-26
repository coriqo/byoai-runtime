/**
 * Settings an administrator pushes through the browser's managed storage
 * (Chrome policy / ExtensionSettings, see managed_schema.json). Pure logic, no
 * chrome.* calls, so it is tested without a browser.
 *
 * Only two things can be set, and neither can point the extension anywhere new:
 *   shield_port  an integer 1024-65535. The endpoint is built from it as
 *                http://127.0.0.1:<port>/api/browser, so a policy can choose
 *                which port the local Shield uses, never another host.
 *   managed_by   a short label shown to the person.
 * Anything else, or a value of the wrong type, is ignored. The pairing check
 * (the device key pinned on first contact) is unchanged: policy never skips it.
 */
(function (root) {
  const MIN_PORT = 1024
  const MAX_PORT = 65535
  const MAX_LABEL = 64

  function parseManaged(raw) {
    const out = { managed: false, port: null, endpoint: null, managedBy: null }
    if (!raw || typeof raw !== 'object') return out
    const port = raw.shield_port
    if (Number.isInteger(port) && port >= MIN_PORT && port <= MAX_PORT) {
      out.port = port
      out.endpoint = `http://127.0.0.1:${port}/api/browser`
      out.managed = true
    }
    if (typeof raw.managed_by === 'string') {
      const label = raw.managed_by.trim().slice(0, MAX_LABEL)
      if (label) out.managedBy = label
    }
    return out
  }

  /** The endpoint to use: the managed one when set, else the person's saved choice. */
  function pickEndpoint(managed, saved, resolveSaved) {
    return managed && managed.endpoint ? managed.endpoint : resolveSaved(saved)
  }

  /** Read chrome.storage.managed; an absent policy (it throws on some builds) is "not managed". */
  async function readManaged(storage) {
    try {
      const area = storage && storage.managed
      if (!area) return parseManaged(null)
      return parseManaged(await area.get(null))
    } catch {
      return parseManaged(null)
    }
  }

  const api = { parseManaged, pickEndpoint, readManaged, MIN_PORT, MAX_PORT }
  root.ShieldManaged = api
  if (typeof module !== 'undefined' && module.exports) module.exports = api
})(typeof globalThis !== 'undefined' ? globalThis : this)
