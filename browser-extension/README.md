# ConfigTrace — Provider Console Helper (Prototype)

A **read-only** Chrome browser extension prototype (Manifest V3) that
recognizes the **8 ConfigTrace-supported provider consoles** and shows a
small, dismissible panel with contextual safety guidance and outbound links
back to ConfigTrace.

This is M58.23 — a **prototype**, not a published extension. It is not
listed on the Chrome Web Store.

---

## What it does

- **Detects the provider console** the user is currently on, using **URL
  patterns only** (hostname + pathname + URL hash).
- Maps the URL to a short, **static guidance card** from a hand-written
  catalog (`src/guidance.js`).
- Injects a **small, dismissible panel** in the bottom-right corner of the
  console page, rendered inside a **closed Shadow DOM** so it cannot
  interact with or be styled by the host page.
- Provides a **toolbar popup** that shows the detected context, a settings
  toggle, an app-base-URL field, and outbound links to:
  - ConfigTrace app home
  - Timeline
  - Needs Review queue
  - Public demo
  - Documentation
  - Trust & data access docs
- Persists per-context dismissal and global panel-enabled state in
  `chrome.storage.local`.

## What it does **not** do

This extension is intentionally read-only. It does **not**:

- Modify any provider settings.
- Inject buttons that change provider settings.
- Auto-fill or auto-submit any provider forms.
- Execute remediation, run Terraform, or open GitHub PRs.
- Mutate AWS, Firebase, Supabase, Stripe, GitHub, Cloudflare, Vercel, or
  Shopify resources.
- Read DOM content, form values, secrets, customer data, source code,
  payment data, order data, database rows, logs, or file contents from
  the host page.
- Send page contents to ConfigTrace (no network requests are made by the
  extension in M58.23).
- Load remote code, use `eval`, or run code from outside the extension
  bundle.
- Request `<all_urls>`, `webRequest`, `cookies`, `downloads`, or `history`
  permissions.

The injected panel and the popup contain plain `<a href>` links only.
Navigation happens only when the user clicks.

---

## Supported provider URLs

The extension only runs on:

| Provider   | Host pattern(s)                                                       |
| ---------- | --------------------------------------------------------------------- |
| AWS        | `console.aws.amazon.com`, `*.console.aws.amazon.com`                  |
| GitHub     | `github.com` (only on `/{owner}/{repo}/settings/...` paths)           |
| Stripe     | `dashboard.stripe.com`                                                |
| Cloudflare | `dash.cloudflare.com`                                                 |
| Vercel     | `vercel.com`, `*.vercel.com`                                          |
| Supabase   | `supabase.com/dashboard/...`                                          |
| Firebase   | `console.firebase.google.com`                                         |
| Shopify    | `admin.shopify.com`                                                   |

Detected context examples:

- **AWS Security Groups** (`SecurityGroup` in pathname or hash)
- **AWS IAM**, **AWS Route 53**, **AWS S3**
- **GitHub branch protection**, **environments**, **webhooks**, **actions
  secrets**, generic **repo settings**
- **Stripe webhooks**, **API keys**, **settings**, generic dashboard
- **Cloudflare DNS**, **WAF / firewall / rulesets**, **SSL/TLS**, generic
  dashboard
- **Vercel env vars**, **domains**, **deploy hooks / git**, project
  settings, dashboard
- **Supabase RLS / policies / table editor**, **auth**, **storage**, generic
  dashboard
- **Firebase Firestore rules**, **Storage rules**, **Auth**, **App Check**,
  **Remote Config**, generic console
- **Shopify apps & scopes**, **webhooks/notifications**, **settings**,
  generic admin

The complete list lives in `src/guidance.js`.

---

## Permissions

Only the minimum needed to mount a panel on the 8 supported provider URLs:

```json
{
  "permissions": ["storage"],
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
}
```

The popup detects the active-tab URL without requesting `tabs` —
`tab.url` is only populated for tabs covered by the existing
`host_permissions`, which is exactly what we want.

Notably **not requested**: `<all_urls>`, `activeTab`, `tabs`, `scripting`,
`webRequest`, `cookies`, `downloads`, `history`, `webNavigation`.

> Caveat on `github.com/*`: the manifest match pattern covers all of
> github.com, but the content script's own URL-path check inside
> `guidance.js` short-circuits unless the path looks like
> `/{owner}/{repo}/settings/...`. The panel will not render on code
> browsing, issues, PRs, profiles, or other GitHub pages.

---

## Install locally (developer mode)

This prototype is **not** published to the Chrome Web Store. To use it:

1. Open Chrome → `chrome://extensions/`.
2. Toggle **Developer mode** (top-right).
3. Click **Load unpacked**.
4. Select the `browser-extension/` folder.
5. Pin the **ConfigTrace** action button to your toolbar.
6. Visit any supported provider console (e.g.
   `https://console.aws.amazon.com/ec2/home#SecurityGroups`) — a small
   ConfigTrace panel will appear in the bottom-right.

To disable the injected panel, click the toolbar icon → uncheck
**"Show panel on supported provider consoles"** → **Save**.

To point the extension at a non-default ConfigTrace deployment, edit
**App base URL** in the popup (must be `https://`).

To reset dismissed contexts: open `chrome://extensions/` → ConfigTrace →
**Inspect views: service worker** → in DevTools console run
`chrome.storage.local.clear()`.

---

## Architecture

```
browser-extension/
├── manifest.json              MV3 manifest
├── README.md                  this file
└── src/
    ├── background.js          service worker — seeds default prefs only
    ├── guidance.js            shared catalog + URL-based context detection
    ├── contentScript.js       injects shadow-DOM panel on provider pages
    ├── popup.html             toolbar popup markup
    ├── popup.js               toolbar popup logic
    └── popup.css              toolbar popup styles
```

- **Manifest V3**, service worker, no inline scripts, default CSP.
- `guidance.js` is loaded both into the content-script isolated world and
  the popup page. It exposes `CT_GUIDANCE`, `CT_PROVIDERS`, `CT_LINKS`,
  `CT_APP_DEFAULT_BASE`, `CT_DOCS_BASE`, and `ctDetectProviderContext`.
- The injected panel lives in a **closed Shadow DOM** (`mode: "closed"`)
  attached to a single `<div>` appended to `<html>`. The host page cannot
  reach it, and panel CSS cannot leak into the host page.
- The popup uses `chrome.tabs.query({active: true, currentWindow: true})`
  with no `tabs` permission — relying on host permissions for URL access.
- No icons are bundled in this prototype; Chrome will use the default
  puzzle-piece icon.

---

## Data & security boundaries (summary)

| Boundary                                    | Status  |
| ------------------------------------------- | :-----: |
| URL-pattern-only context detection          |   ✓     |
| Shadow-DOM-isolated injected panel          |   ✓     |
| No `eval`, no `new Function`, no remote code|   ✓     |
| No network requests from the extension      |   ✓     |
| No DOM scraping of host pages               |   ✓     |
| No form auto-fill or auto-submit            |   ✓     |
| No provider mutations                       |   ✓     |
| No Terraform execution                      |   ✓     |
| No GitHub PR creation from extension        |   ✓     |
| No `<all_urls>` / `webRequest` / `cookies`  |   ✓     |
| Outbound links open in new tabs (user gesture) | ✓    |

See [`docs/data-access.html`](https://configtrace.org/docs/data-access.html)
on the public site for the full ConfigTrace data-access policy.

---

## Future work (intentionally **not** in M58.23)

These are tracked for follow-up milestones. They are **not** implemented
here and the prototype contains no scaffolding for them yet:

- Authenticated workspace context (token entry, sign-in, OAuth).
- Fetching recent ConfigTrace risks via the ConfigTrace API.
- Matching a resource visible on the provider page (e.g. a specific
  security-group ID in the URL hash) to a ConfigTrace resource.
- Pre-aggregated, anonymized signal back to ConfigTrace for triage.
- Browser-extension marketplace packaging (Chrome Web Store, Firefox,
  Edge).
- Provider-page contextual warnings driven by live ConfigTrace state.
- Bundled icon set.
- Cross-browser packaging (Firefox MV3, Safari Web Extension).

Any future work that would change the data-access posture of this
extension must explicitly update this README's **Data & security
boundaries** table.
