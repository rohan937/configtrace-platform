/* ConfigTrace browser helper — content script.
 *
 * Runs on the 8 supported provider consoles (see manifest content_scripts.matches).
 * Detects the page context using URL patterns only (see guidance.js) and, when
 * a context is found, mounts a small read-only panel via a Shadow DOM so it
 * cannot bleed CSS into — or read DOM from — the host page.
 *
 * SAFETY GUARANTEES (must remain true):
 *   • Does NOT read DOM content, form values, secrets, customer data,
 *     source code, payment data, order data, database rows, logs, or files.
 *   • Does NOT modify provider settings or inject buttons that would.
 *   • Does NOT issue any network requests. All "links" are plain <a href> —
 *     navigation only happens if the user clicks.
 *   • Does NOT auto-fill, auto-submit, or interact with provider forms.
 *   • Does NOT use eval, new Function, or remote-loaded code.
 */
(function ctContentMain() {
  "use strict";

  // Detection is a no-op if guidance.js failed to load — defensive only.
  if (typeof ctDetectProviderContext !== "function") return;

  // Skip non-top frames (iframes inside provider consoles — we only render once).
  if (window.top !== window) return;

  const url = location.href;
  const ctx = ctDetectProviderContext(url);
  if (!ctx) return; // unknown URL — no panel.

  // Pull prefs + per-context dismissal state from chrome.storage.local.
  const dismissKey = "dismissed_ctx_" + ctx.contextKey;
  const keys = ["panel_enabled", "app_base_url", dismissKey];

  chrome.storage.local.get(keys, function (prefs) {
    if (chrome.runtime.lastError) return;            // storage unavailable — give up quietly.
    if (prefs.panel_enabled === false) return;       // user disabled the panel globally.
    if (prefs[dismissKey] === true) return;          // user dismissed this context.

    const appBase = (typeof prefs.app_base_url === "string" && prefs.app_base_url.startsWith("https://"))
      ? prefs.app_base_url.replace(/\/+$/, "")
      : CT_APP_DEFAULT_BASE;

    mountPanel(ctx, appBase, dismissKey);
  });

  // ────────────────────────────────────────────────────────────────────────
  // Mount panel into a closed Shadow DOM attached to a fresh wrapper element.
  // The wrapper is a normal element on the page; the shadow root isolates CSS
  // so we cannot accidentally style — or be styled by — the host page.
  // ────────────────────────────────────────────────────────────────────────
  function mountPanel(ctx, appBase, dismissKey) {
    // Avoid double-mounting on SPA route changes / re-entry.
    if (document.getElementById("ct-ext-root")) return;

    const root = document.createElement("div");
    root.id = "ct-ext-root";
    // Outer host element should be invisible/inert until shadow content renders.
    root.style.all = "initial";
    root.style.position = "fixed";
    root.style.zIndex = "2147483646";
    root.style.right = "16px";
    root.style.bottom = "16px";
    root.style.maxWidth = "340px";

    // Shadow root keeps panel CSS sandboxed from the host page.
    const shadow = root.attachShadow({ mode: "closed" });

    const style = document.createElement("style");
    style.textContent = panelCss();
    shadow.appendChild(style);

    shadow.appendChild(buildPanel(ctx, appBase, dismissKey, root));

    // Attach as last child of <html> so it stays above page content
    // even if the host page mutates <body>.
    (document.documentElement || document.body).appendChild(root);
  }

  function buildPanel(ctx, appBase, dismissKey, hostEl) {
    const wrap = elm("div", "panel");

    // Header
    const hdr = elm("div", "hdr");
    const brandWrap = elm("div", "brand-wrap");
    brandWrap.appendChild(elm("span", "brand-mark", "CT"));
    brandWrap.appendChild(elm("span", "brand-name", "ConfigTrace"));
    hdr.appendChild(brandWrap);

    const closeBtn = elm("button", "close", "×");
    closeBtn.type = "button";
    closeBtn.setAttribute("aria-label", "Dismiss ConfigTrace panel");
    closeBtn.addEventListener("click", function () {
      const update = {};
      update[dismissKey] = true;
      chrome.storage.local.set(update);
      try { hostEl.remove(); } catch (_) {}
    });
    hdr.appendChild(closeBtn);
    wrap.appendChild(hdr);

    // Provider / context line
    const ctxLine = elm("div", "ctx-line");
    ctxLine.appendChild(elm("span", "prov-chip", ctx.provider));
    ctxLine.appendChild(elm("span", "ctx-title", ctx.title));
    wrap.appendChild(ctxLine);

    // Guidance prose
    wrap.appendChild(elm("p", "guidance", ctx.guidance));

    // Monitors list
    if (Array.isArray(ctx.monitors) && ctx.monitors.length) {
      const label = elm("div", "label", "ConfigTrace monitors");
      wrap.appendChild(label);
      const ul = elm("ul", "monitors");
      ctx.monitors.forEach(function (m) {
        ul.appendChild(elm("li", "monitor-li", m));
      });
      wrap.appendChild(ul);
    }

    // Links
    const links = elm("div", "links");
    links.appendChild(linkRow("Open ConfigTrace",     appBase + CT_LINKS.app));
    links.appendChild(linkRow("Open Timeline",        appBase + CT_LINKS.timeline));
    links.appendChild(linkRow("Open Needs Review",    appBase + CT_LINKS.needsReview));
    if (ctx.docsPath) {
      links.appendChild(linkRow("View provider guidance", CT_DOCS_BASE + ctx.docsPath));
    } else {
      links.appendChild(linkRow("ConfigTrace docs", CT_LINKS.docs));
    }
    wrap.appendChild(links);

    // Footer note
    const note = elm("div", "note",
      "Read-only browser helper. Does not change provider settings or read page contents.");
    wrap.appendChild(note);

    return wrap;
  }

  function linkRow(label, href) {
    const a = document.createElement("a");
    a.className = "link";
    a.href = href;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.textContent = label;
    const arrow = elm("span", "arrow", "→");
    a.appendChild(arrow);
    return a;
  }

  function elm(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = text;
    return e;
  }

  // ────────────────────────────────────────────────────────────────────────
  // Inline CSS — kept in JS so no separate stylesheet is registered against
  // the host page (everything lives inside the shadow root).
  // ────────────────────────────────────────────────────────────────────────
  function panelCss() {
    return [
      ":host, * { box-sizing: border-box; }",
      ".panel {",
      "  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Inter, sans-serif;",
      "  background: #0D1021;",
      "  color: #DDE3F0;",
      "  border: 1px solid #252D48;",
      "  border-radius: 12px;",
      "  padding: 14px 14px 12px;",
      "  box-shadow: 0 16px 40px rgba(0,0,0,.45), 0 0 0 1px rgba(255,255,255,.02);",
      "  width: 320px;",
      "  font-size: 13px;",
      "  line-height: 1.5;",
      "}",
      ".hdr { display:flex; align-items:center; justify-content:space-between; margin-bottom:10px; }",
      ".brand-wrap { display:flex; align-items:center; gap:8px; }",
      ".brand-mark {",
      "  display:inline-flex; align-items:center; justify-content:center;",
      "  width:22px; height:22px; border-radius:5px;",
      "  background:#4B7CF6; color:#fff; font-weight:700; font-size:10px;",
      "  font-family:'JetBrains Mono', ui-monospace, monospace;",
      "}",
      ".brand-name { font-size:13px; font-weight:600; color:#DDE3F0; }",
      ".close {",
      "  border:1px solid #252D48; background:transparent; color:#8590A6;",
      "  width:22px; height:22px; border-radius:5px;",
      "  font-size:14px; line-height:1; cursor:pointer; padding:0;",
      "}",
      ".close:hover { color:#DDE3F0; border-color:#4B7CF6; }",
      ".ctx-line { display:flex; align-items:center; gap:8px; margin-bottom:10px; flex-wrap:wrap; }",
      ".prov-chip {",
      "  font-family:'JetBrains Mono', ui-monospace, monospace;",
      "  font-size:10px; font-weight:700; letter-spacing:.5px;",
      "  background:rgba(75,124,246,.12); color:#6B94FF;",
      "  border:1px solid rgba(75,124,246,.28);",
      "  padding:2px 7px; border-radius:4px;",
      "}",
      ".ctx-title { font-size:13px; font-weight:600; color:#DDE3F0; }",
      ".guidance { color:#8590A6; font-size:12.5px; margin:0 0 10px; line-height:1.55; }",
      ".label {",
      "  font-family:'JetBrains Mono', ui-monospace, monospace;",
      "  font-size:10px; letter-spacing:1px; text-transform:uppercase;",
      "  color:#4A5268; margin-bottom:6px;",
      "}",
      ".monitors { list-style:none; padding:0; margin:0 0 10px; }",
      ".monitor-li {",
      "  font-size:12px; color:#8590A6; line-height:1.45;",
      "  padding:3px 0;",
      "  position:relative; padding-left:14px;",
      "}",
      ".monitor-li::before {",
      "  content:'→'; position:absolute; left:0; top:3px;",
      "  font-family:'JetBrains Mono', ui-monospace, monospace;",
      "  font-size:11px; color:#4B7CF6;",
      "}",
      ".links { display:flex; flex-direction:column; gap:4px; padding-top:8px; border-top:1px solid #1C2238; }",
      ".link {",
      "  display:flex; align-items:center; justify-content:space-between;",
      "  text-decoration:none; color:#DDE3F0;",
      "  font-size:12.5px; padding:7px 8px; border-radius:6px;",
      "  background:transparent; border:1px solid transparent;",
      "}",
      ".link:hover { background:#171C30; border-color:#252D48; color:#6B94FF; }",
      ".link .arrow { color:#4A5268; font-family:'JetBrains Mono', ui-monospace, monospace; }",
      ".link:hover .arrow { color:#6B94FF; }",
      ".note {",
      "  margin-top:10px; padding-top:9px; border-top:1px solid #1C2238;",
      "  font-family:'JetBrains Mono', ui-monospace, monospace;",
      "  font-size:10.5px; color:#4A5268; line-height:1.5;",
      "}"
    ].join("\n");
  }
})();
