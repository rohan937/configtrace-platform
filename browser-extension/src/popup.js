/* ConfigTrace browser helper — popup logic.
 *
 * Loaded after guidance.js so CT_LINKS, ctDetectProviderContext, etc. are
 * available on globalThis.
 *
 * Behaviour:
 *   • Reads the active tab's URL (URL is only exposed to the popup when the
 *     tab matches one of our host_permissions — no extra `tabs` permission
 *     is requested).
 *   • If the URL matches a known provider context, shows the context details.
 *   • Otherwise shows the "no supported provider" hint.
 *   • Renders six outbound links built from the (configurable) app base URL.
 *   • Lets the user toggle the injected panel and edit the app base URL,
 *     persisting to chrome.storage.local.
 *
 * NO network requests are made.
 * NO DOM is read from the active tab.
 */
(function ctPopupMain() {
  "use strict";

  const $ = (id) => document.getElementById(id);

  const ctxSection   = $("ctxSection");
  const noCtxSection = $("noCtxSection");
  const ctxProv      = $("ctxProv");
  const ctxTitle     = $("ctxTitle");
  const ctxGuidance  = $("ctxGuidance");
  const ctxMonitors  = $("ctxMonitors");

  const linkApp      = $("linkApp");
  const linkTimeline = $("linkTimeline");
  const linkNeeds    = $("linkNeeds");
  const linkDemo     = $("linkDemo");
  const linkDocs     = $("linkDocs");
  const linkTrust    = $("linkTrust");

  const panelEnabled = $("panelEnabled");
  const appBaseInput = $("appBase");
  const saveBtn      = $("saveBtn");
  const saveState    = $("saveState");

  // ── Load stored prefs and render links/settings ────────────────────────
  chrome.storage.local.get(["panel_enabled", "app_base_url"], function (prefs) {
    panelEnabled.checked =
      prefs.panel_enabled === undefined ? true : !!prefs.panel_enabled;

    const base = (typeof prefs.app_base_url === "string" && prefs.app_base_url)
      ? prefs.app_base_url
      : CT_APP_DEFAULT_BASE;

    appBaseInput.value = base;
    renderLinks(base);
  });

  // ── Active-tab context detection ───────────────────────────────────────
  // No `tabs` permission requested — `tab.url` is only populated for tabs
  // matching this extension's host_permissions, which is exactly the
  // behaviour we want.
  chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
    const tab = tabs && tabs[0];
    const url = tab && tab.url;
    let ctx = null;
    if (typeof url === "string" && url) {
      try { ctx = ctDetectProviderContext(url); } catch (_) { ctx = null; }
    }

    if (ctx) {
      ctxProv.textContent     = ctx.provider;
      ctxTitle.textContent    = ctx.title;
      ctxGuidance.textContent = ctx.guidance;

      // Clear any previous render without using innerHTML.
      while (ctxMonitors.firstChild) ctxMonitors.removeChild(ctxMonitors.firstChild);
      if (Array.isArray(ctx.monitors) && ctx.monitors.length) {
        const label = document.createElement("div");
        label.className = "monitors-label";
        label.textContent = "ConfigTrace monitors";
        ctxMonitors.appendChild(label);

        const ul = document.createElement("ul");
        ul.className = "monitors-list";
        ctx.monitors.forEach(function (m) {
          const li = document.createElement("li");
          li.textContent = m;
          ul.appendChild(li);
        });
        ctxMonitors.appendChild(ul);
      }
      ctxSection.hidden   = false;
      noCtxSection.hidden = true;
    } else {
      ctxSection.hidden   = true;
      noCtxSection.hidden = false;
    }
  });

  // ── Save settings ──────────────────────────────────────────────────────
  saveBtn.addEventListener("click", function () {
    const base = sanitizeBase(appBaseInput.value) || CT_APP_DEFAULT_BASE;
    const updates = {
      panel_enabled: !!panelEnabled.checked,
      app_base_url:  base
    };
    chrome.storage.local.set(updates, function () {
      appBaseInput.value = base;
      renderLinks(base);
      flashSaved();
    });
  });

  panelEnabled.addEventListener("change", function () {
    chrome.storage.local.set({ panel_enabled: !!panelEnabled.checked }, flashSaved);
  });

  function flashSaved() {
    saveState.textContent = "Saved.";
    setTimeout(function () { saveState.textContent = ""; }, 1500);
  }

  // ── Helpers ────────────────────────────────────────────────────────────
  function renderLinks(base) {
    const b = sanitizeBase(base) || CT_APP_DEFAULT_BASE;
    linkApp.href      = b + CT_LINKS.app;
    linkTimeline.href = b + CT_LINKS.timeline;
    linkNeeds.href    = b + CT_LINKS.needsReview;
    linkDemo.href     = CT_LINKS.demo;
    linkDocs.href     = CT_LINKS.docs;
    linkTrust.href    = CT_LINKS.trust;
  }

  /** Ensures the base URL is https:// and strips trailing slashes. */
  function sanitizeBase(value) {
    if (typeof value !== "string") return null;
    const trimmed = value.trim();
    if (!trimmed) return null;
    if (!/^https:\/\//i.test(trimmed)) return null;
    return trimmed.replace(/\/+$/, "");
  }
})();
