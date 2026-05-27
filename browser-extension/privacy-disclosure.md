# Privacy Disclosure — ConfigTrace Provider Console Helper

**Extension:** ConfigTrace Provider Console Helper
**Version:** 0.1.0
**Manifest version:** 3
**Last updated:** 2026-05-27

This document describes — in technical detail — exactly what the
ConfigTrace browser extension does with data on the user's machine.
It is intended both for:

- the maintainer, as a source of truth pasted into the Chrome Web Store
  Developer Dashboard during submission, and
- end users, as a clear technical accounting of the extension's behaviour.

> **Note:** This is a technical disclosure. It is **not** a substitute for
> a formal privacy policy reviewed by counsel. A dedicated public privacy
> policy URL is still required before Chrome Web Store public submission.
> See *Outstanding work* at the bottom.

---

## 1. What the extension does

When the user visits one of the 8 supported provider admin consoles
(AWS, GitHub, Stripe, Cloudflare, Vercel, Supabase, Firebase, Shopify),
the extension:

1. Inspects the URL of the current tab (`window.location.hostname`,
   `pathname`, and `hash`) to detect which provider context the page
   represents (e.g. *AWS Security Groups*, *GitHub branch protection*,
   *Stripe webhooks*).
2. If a context is recognized, injects a small read-only helper panel
   into the bottom-right corner of the page (rendered inside a closed
   Shadow DOM, isolated from the host page).
3. Renders a toolbar popup that shows the same detected context plus
   one-click links back to ConfigTrace.

The user can:

- Dismiss the in-page panel per-context (panel will not re-mount on that
  context until storage is cleared).
- Disable the in-page panel globally from the toolbar popup.
- Override the ConfigTrace app base URL from the toolbar popup.

---

## 2. What data the extension reads

| Source                                  | Read?                  | Purpose                                                                        |
| --------------------------------------- | :--------------------: | ------------------------------------------------------------------------------ |
| URL of the active tab                   | Yes (URL string only)  | Pattern-match against supported provider hosts/paths to detect page context.   |
| `chrome.storage.local`                  | Yes (three keys only)  | Read user preferences (panel enabled, dismissed contexts, optional base URL).  |
| Tab title                               | No                     | Not read.                                                                      |
| DOM content of provider pages           | **No**                 | Never accessed.                                                                |
| Form values on provider pages           | **No**                 | Never accessed.                                                                |
| Cookies, localStorage of provider pages | **No**                 | Never accessed.                                                                |
| Page selection / clipboard              | **No**                 | Never accessed.                                                                |
| Browsing history                        | **No**                 | Never accessed.                                                                |
| Network requests / responses            | **No**                 | Not intercepted (no `webRequest` permission).                                  |
| Downloaded files                        | **No**                 | Not accessed (no `downloads` permission).                                      |

### Explicitly never accessed

- Secret values (API keys, tokens, passwords, Admin API access tokens).
- Customer data of any kind, on any provider.
- Source code (GitHub repository file contents, Vercel deployed code,
  Cloudflare Worker scripts).
- Payment data, charge data, or transaction history (Stripe, Shopify).
- Order contents, checkout payloads, or inventory data (Shopify).
- Database rows or query results (Supabase, Firebase).
- File contents in object storage (S3, Firebase Storage, Supabase
  Storage, Shopify file uploads).
- Theme files or storefront content (Shopify).
- Logs, traces, runtime telemetry, or analytics data.

---

## 3. What data the extension sends

**Nothing.** Version 0.1.0 of the extension performs zero outbound network
requests:

- No `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, or
  `importScripts` calls anywhere in `background.js`, `contentScript.js`,
  `guidance.js`, `popup.js`, or `popup.html`.
- Outbound `<a href>` links open ConfigTrace pages only when the user
  clicks. Navigation is performed by the browser as a normal page load.
- The extension does not send analytics, telemetry, error reports, or
  diagnostics anywhere.

A `grep` across the extension source confirms the absence of dynamic-
code patterns:

```
grep -rE 'eval\(|new Function\(|fetch\(|XMLHttpRequest|WebSocket|importScripts\(' browser-extension/
# → no matches
```

---

## 4. Local storage

The extension stores up to three keys in `chrome.storage.local`. All keys
are stored unencrypted because none of them are sensitive.

| Key                              | Type    | Default                          | Purpose                                                  |
| -------------------------------- | ------- | -------------------------------- | -------------------------------------------------------- |
| `panel_enabled`                  | boolean | `true`                           | Global toggle for the injected helper panel.             |
| `app_base_url`                   | string  | `"https://app.configtrace.org"`  | Overridable ConfigTrace app base URL (must be `https://`). |
| `dismissed_ctx_<context_key>`    | boolean | absent                           | Per-context dismissal of the panel (set when × clicked). |

Storage stays inside the user's browser profile. It is removed when:

- The user clicks **Remove extension** in `chrome://extensions/`.
- The user clears extension data via Chrome settings.
- The user manually calls `chrome.storage.local.clear()` from DevTools
  (instructions in `README.md`).

There is no server-side copy.

---

## 5. Permissions

The extension requests the **minimum** set of permissions:

```json
"permissions":      ["storage"],
"host_permissions": [
  "https://console.aws.amazon.com/*",
  "https://*.console.aws.amazon.com/*",
  "https://github.com/*",
  "https://dashboard.stripe.com/*",
  "https://dash.cloudflare.com/*",
  "https://vercel.com/*",
  "https://*.vercel.com/*",
  "https://supabase.com/dashboard/*",
  "https://console.firebase.google.com/*",
  "https://admin.shopify.com/*"
]
```

Explicitly **not** requested (verified by `grep`):

- `<all_urls>` — extension does not need site access beyond the 8 provider
  hosts.
- `webRequest` — extension does not intercept or modify network traffic.
- `cookies` — extension does not read or write cookies.
- `downloads` — extension does not initiate or read downloads.
- `history` — extension does not access browsing history.
- `tabs` — extension reads the active tab URL via the host-permission
  grant; the `tabs` permission would broaden URL visibility unnecessarily.
- `activeTab` — extension does not need ephemeral URL access tied to a
  user gesture.
- `scripting` — extension uses declarative `content_scripts` only; it
  does not inject scripts at runtime.

The `github.com/*` host pattern is broader than ideal. The content
script's own URL test inside `guidance.js` short-circuits unless the
path matches `/{owner}/{repo}/settings/...`, so the panel does not
render on code browsing, issues, PRs, or profile pages.

---

## 6. Code-execution boundaries

The extension does not load remote code. The Content Security Policy in
`manifest.json` explicitly restricts script sources to `'self'`:

```json
"content_security_policy": {
  "extension_pages": "script-src 'self'; object-src 'self'"
}
```

The extension does not use `eval`, `new Function`, `setTimeout(string, ...)`,
or `setInterval(string, ...)`. The in-page panel is rendered into a
closed Shadow DOM so the host page cannot reach into it (and the panel
cannot accidentally read or modify host-page DOM).

---

## 7. Retention

- All extension state is **local only**, stored in `chrome.storage.local`.
- Retention is determined by the user (uninstalling the extension or
  clearing browser data removes all extension state).
- The extension does not maintain or transmit any server-side state.
- The extension does not maintain a history of past detections,
  dismissals, or visited pages beyond the simple boolean dismissal flags
  described in §4.

---

## 8. Contact

| Channel         | Value                                                                                         |
| --------------- | --------------------------------------------------------------------------------------------- |
| Support email   | **TBD — placeholder** (e.g. `support@configtrace.org`)                                        |
| Support website | `https://configtrace.org/docs.html`                                                           |
| Data-access doc | `https://configtrace.org/docs/data-access.html` (ConfigTrace product-wide data-access policy) |

---

## 9. Outstanding work before Chrome Web Store public submission

This disclosure document is technically accurate but not a formal privacy
policy. The following items must be resolved by the maintainer before a
public Chrome Web Store submission:

- [ ] Decide whether to publish `privacy.html` on the marketing site or
      link directly to `docs/data-access.html`. Chrome Web Store requires
      a publicly accessible privacy policy URL.
- [ ] Replace the *TBD — placeholder* support email with a real address.
- [ ] Have counsel (or at minimum the project owner) review this document
      and convert it into a publishable privacy policy.

Until those items are resolved, the extension can still be loaded via
**Load unpacked** in developer mode and used internally.
