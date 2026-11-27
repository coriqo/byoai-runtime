/**
 * Welcome page: the consent step. Choosing "Agree" tells the service worker to
 * start capture; "Not now" leaves it off. Nothing else happens on this page.
 */
const el = (id) => document.getElementById(id)

async function choose(granted) {
  el('err').hidden = true
  try {
    const reply = await chrome.runtime.sendMessage({ type: 'agent.setConsent', granted })
    if (!reply || reply.error) throw new Error(reply?.error || 'no reply')
  } catch {
    el('err').hidden = false
    return
  }
  el('ask').hidden = true
  el(granted ? 'on' : 'off').hidden = false
}

el('agree').addEventListener('click', () => choose(true))
el('decline').addEventListener('click', () => choose(false))

el('connect-coriqo').addEventListener('click', () => chrome.tabs.create({ url: chrome.runtime.getURL('login.html') }))
