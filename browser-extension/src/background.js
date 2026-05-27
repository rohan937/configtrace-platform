/* ConfigTrace browser helper — background service worker (MV3).
 *
 * Scope of this worker is deliberately tiny: it only seeds default prefs in
 * chrome.storage.local on install. It does NOT:
 *   • listen for tab navigation events,
 *   • inject scripts dynamically,
 *   • make network requests,
 *   • read tab URLs,
 *   • or relay messages between content scripts and the popup.
 *
 * Everything the user sees runs in the popup and the content script. This
 * worker simply guarantees that defaults exist the first time the extension
 * is loaded.
 */

const DEFAULTS = Object.freeze({
  panel_enabled: true,
  app_base_url:  "https://app.configtrace.org"
});

chrome.runtime.onInstalled.addListener(function (details) {
  // On fresh install or update, ensure each default key exists without
  // overwriting any values the user has already chosen.
  chrome.storage.local.get(Object.keys(DEFAULTS), function (existing) {
    if (chrome.runtime.lastError) return;
    const updates = {};
    for (const k of Object.keys(DEFAULTS)) {
      if (existing[k] === undefined) {
        updates[k] = DEFAULTS[k];
      }
    }
    if (Object.keys(updates).length > 0) {
      chrome.storage.local.set(updates);
    }
  });
});
