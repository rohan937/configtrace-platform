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

To run the extension without publishing it:

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
├── store-listing.md           Chrome Web Store listing copy + justifications
├── privacy-disclosure.md      technical privacy disclosure
├── package-extension.sh       builds dist/ ZIP for Chrome Web Store upload
├── icons/
│   ├── icon.svg               source-of-truth design
│   ├── icon16.png             16×16 toolbar icon
│   ├── icon32.png             32×32 toolbar icon
│   ├── icon48.png             48×48 management page icon
│   ├── icon128.png            128×128 Web Store icon
│   └── generate_icons.py      regenerates the PNGs (stdlib only)
├── screenshots/
│   └── README.md              capture checklist + safety rules
└── src/
    ├── background.js          service worker — seeds default prefs only
    ├── guidance.js            shared catalog + URL-based context detection
    ├── contentScript.js       injects shadow-DOM panel on provider pages
    ├── popup.html             toolbar popup markup
    ├── popup.js               toolbar popup logic
    └── popup.css              toolbar popup styles
```

- **Manifest V3**, service worker, no inline scripts, explicit CSP.
- `guidance.js` is loaded both into the content-script isolated world and
  the popup page. It exposes `CT_GUIDANCE`, `CT_PROVIDERS`, `CT_LINKS`,
  `CT_APP_DEFAULT_BASE`, `CT_DOCS_BASE`, and `ctDetectProviderContext`.
- The injected panel lives in a **closed Shadow DOM** (`mode: "closed"`)
  attached to a single `<div>` appended to `<html>`. The host page cannot
  reach it, and panel CSS cannot leak into the host page.
- The popup uses `chrome.tabs.query({active: true, currentWindow: true})`
  with no `tabs` permission — relying on host permissions for URL access.
- PNG icons are bundled in `icons/`. The 128 px master is drawn from pure
  Python stdlib (see `icons/generate_icons.py`); 48/32/16 are downsampled
  via `sips`.

---

## Chrome Web Store publishing preparation

This extension is prepared for Chrome Web Store submission but is **not
auto-submitted**. The maintainer uploads the ZIP manually via the
Developer Dashboard.

### Build the upload ZIP

```bash
cd browser-extension
./package-extension.sh
```

The script:

- Re-creates `dist/` from scratch on every run.
- Reads the version from `manifest.json` so script + manifest never drift.
- Uses an **allow-list** of files to ship (safer than a deny-list).
- Excludes `.git`, `node_modules`, `dist`, `.DS_Store`, `screenshots/`,
  `store-listing.md`, `privacy-disclosure.md`, `package-extension.sh`,
  `icons/generate_icons.py`, and any `.env*` files.
- Performs a *forbidden-path audit* on the resulting ZIP and aborts if
  anything dangerous slips in.
- Writes `dist/configtrace-provider-console-helper-<VERSION>.zip` and
  prints the path, size, and contents manifest.

### Manual Chrome Web Store upload steps

1. Open the **Chrome Web Store Developer Dashboard**:
   <https://chrome.google.com/webstore/devconsole>.
2. Click **Add new item**.
3. Upload `dist/configtrace-provider-console-helper-<VERSION>.zip`.
4. **Store listing** → paste fields from
   [`store-listing.md`](store-listing.md) (name, short description,
   detailed description, category, language).
5. **Privacy practices** → paste permission justifications and answer
   the privacy practices form using
   [`store-listing.md`](store-listing.md) and
   [`privacy-disclosure.md`](privacy-disclosure.md).
6. **Distribution** → choose *Public* (or *Unlisted* for soft launch).
7. Add screenshots from `screenshots/` (see the
   [shot-list and safety rules](screenshots/README.md)).
8. **Submit for review.** Google review typically takes a few business
   days; respond to any feedback via the Dashboard.

### Required prerequisites before *public* submission

These are **outside** the scope of this milestone — the maintainer
resolves them manually:

- [ ] **Chrome Web Store developer account.** One-time **$5 USD**
      registration fee, two-factor auth recommended.
- [ ] **Privacy policy URL.** Chrome requires a publicly accessible
      privacy policy. Either add `privacy.html` to the marketing site or
      link to `docs/data-access.html`. See *Outstanding work* in
      [`privacy-disclosure.md`](privacy-disclosure.md).
- [ ] **Support email.** Replace the placeholder in
      [`store-listing.md`](store-listing.md) with a real address.
- [ ] **Screenshots captured** per `screenshots/README.md` — using only
      sandbox/demo accounts.
- [ ] **Verified domain / publisher**, if displaying a verified-publisher
      badge is desired (optional).

Review-time gotchas (worth knowing in advance):

- Google reviewers ask about each host permission individually. The
  per-host justifications in [`store-listing.md`](store-listing.md) are
  written to answer those prompts directly.
- The reviewer may request a working test account showing the in-page
  panel on at least one provider; have a sandbox AWS or test-mode Stripe
  ready.

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

## Future work (intentionally **not** in this milestone)

These are tracked for follow-up milestones. They are **not** implemented
here and the prototype contains no scaffolding for them yet:

- Authenticated workspace context (token entry, sign-in, OAuth).
- Fetching recent ConfigTrace risks via the ConfigTrace API.
- Matching a resource visible on the provider page (e.g. a specific
  security-group ID in the URL hash) to a ConfigTrace resource.
- Pre-aggregated, anonymized signal back to ConfigTrace for triage.
- Provider-page contextual warnings driven by live ConfigTrace state.
- Firefox MV3 and Safari Web Extension packaging (Chrome Web Store
  upload preparation is included in M58.24; cross-browser is deferred).

Completed in M58.23 — prototype:

- ✓ Manifest V3 skeleton, popup, in-page panel, guidance catalog.

Completed in M58.24 — Chrome Web Store readiness:

- ✓ Polished manifest (name, short_name, icons, action.default_icon).
- ✓ Bundled icon set (16/32/48/128 PNG + source SVG).
- ✓ Store-listing copy and per-permission justifications.
- ✓ Technical privacy disclosure.
- ✓ Repeatable packaging script with allow-list and forbidden-path audit.
- ✓ Screenshot capture checklist with safety rules.

Any future work that would change the data-access posture of this
extension must explicitly update this README's **Data & security
boundaries** table.
