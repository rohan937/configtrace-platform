# Chrome Web Store Listing — ConfigTrace Provider Console Helper

This document is the source-of-truth copy for the Chrome Web Store
submission of the ConfigTrace browser extension. Paste these fields into
the Chrome Web Store Developer Dashboard during manual upload.

> Do **not** submit automatically. The maintainer manually uploads the ZIP
> built by `package-extension.sh` and pastes these fields into the
> Dashboard.

---

## Extension identity

| Field            | Value                                                       |
| ---------------- | ----------------------------------------------------------- |
| Name             | **ConfigTrace Provider Console Helper**                     |
| Short name       | **ConfigTrace**                                             |
| Version          | **0.1.0**                                                   |
| Manifest version | **3**                                                       |
| Default language | **English (en)**                                            |
| Category         | **Developer Tools** (preferred) — *Productivity* secondary  |

Rationale for category: the extension targets engineers/DevOps/SecOps
working in provider admin consoles. "Developer Tools" matches the audience
more precisely than "Productivity".

---

## Short description (≤ 132 chars)

> Read-only ConfigTrace helper for AWS, GitHub, Stripe, Cloudflare, Vercel, Supabase, Firebase, and Shopify consoles.

(Character count: **120**, under the 132-char limit.)

---

## Detailed description

```
ConfigTrace Provider Console Helper recognizes when you are viewing supported
cloud and SaaS admin consoles and displays read-only guidance that links back
to ConfigTrace.

It helps teams remember which production-critical settings are monitored for
risky drift — including security groups, DNS, webhooks, branch protection,
RLS policies, security rules, deployment settings, and app scopes.

The extension does NOT modify provider settings, does NOT read secret values,
does NOT read customer data, and does NOT send page content to ConfigTrace in
this prototype.

Supported provider consoles:
• AWS — console.aws.amazon.com (Security Groups, IAM, Route 53, S3)
• GitHub — github.com (settings, branch protection, environments, webhooks)
• Stripe — dashboard.stripe.com (webhooks, API keys, settings)
• Cloudflare — dash.cloudflare.com (DNS, WAF, SSL/TLS)
• Vercel — vercel.com (env vars, domains, deploy hooks)
• Supabase — supabase.com/dashboard (RLS, auth, storage)
• Firebase — console.firebase.google.com (Firestore rules, Storage rules,
  Auth, App Check, Remote Config)
• Shopify — admin.shopify.com (apps & scopes, webhooks/notifications,
  store settings)

How it works:
• When you open a supported console, ConfigTrace detects the context using
  only the page URL — no DOM scraping, no form values read.
• A small dismissible panel appears in the bottom-right corner with a short
  guidance note and links back to ConfigTrace (timeline, Needs Review,
  documentation).
• The toolbar popup shows the detected context and one-click links to
  ConfigTrace, the public demo, and the docs.

Privacy:
• The extension requests only the `storage` permission and host permissions
  for the 8 supported provider consoles.
• It does not request `<all_urls>`, `webRequest`, `cookies`, `downloads`,
  `history`, `activeTab`, `tabs`, or `scripting`.
• It does not load remote code or use `eval`.
• It does not send any data to ConfigTrace or any other server.
• See the privacy disclosure shipped with the extension and the public
  data-access policy at https://configtrace.org/docs/data-access.html

Learn more: https://configtrace.org
Public demo:  https://configtrace.org/demo.html
Documentation: https://configtrace.org/docs.html
```

---

## Single purpose statement

> ConfigTrace Provider Console Helper has a single purpose: when the user
> visits a supported cloud/SaaS provider admin console, it recognizes the
> page using URL patterns and displays read-only guidance plus links back
> to ConfigTrace. It performs no other function.

---

## Permission justifications

Paste these into the Dashboard's *Privacy practices → Permission
justification* fields. Use the per-permission text below.

### `storage`

> Stores two local user preferences in `chrome.storage.local`:
> (1) whether the in-page helper panel is enabled, and
> (2) which provider contexts the user has dismissed.
> The extension also stores an optional `app_base_url` override for users
> who run ConfigTrace at a non-default URL.
> No personally identifying or sensitive data is stored.

### Host permission — `https://console.aws.amazon.com/*` and `https://*.console.aws.amazon.com/*`

> Required to run the read-only content script on the AWS Management
> Console so we can recognize Security Groups, IAM, Route 53, and S3
> contexts from the URL and show the matching helper panel. No DOM
> content is read; no AWS resources are modified.

### Host permission — `https://github.com/*`

> Required to run the read-only content script on GitHub repository
> settings pages so we can recognize branch protection, environment
> protection, webhooks, and Actions-secrets contexts from the URL.
> The panel only mounts on `/{owner}/{repo}/settings/...` paths; no DOM
> content is read; no GitHub resources are modified.

### Host permission — `https://dashboard.stripe.com/*`

> Required to recognize Stripe Dashboard contexts (webhooks, API keys,
> settings) from the URL. Stripe payment data, customer data, and key
> values are never read.

### Host permission — `https://dash.cloudflare.com/*`

> Required to recognize Cloudflare DNS, WAF, and SSL/TLS contexts from
> the URL. Visitor traffic, request logs, and Worker code are never read.

### Host permission — `https://vercel.com/*` and `https://*.vercel.com/*`

> Required to recognize Vercel project settings, environment variable
> pages, domains, and deploy-hook contexts from the URL. Environment
> variable values, deployed code, and logs are never read.

### Host permission — `https://supabase.com/dashboard/*`

> Required to recognize Supabase dashboard contexts (RLS policies, auth
> settings, storage policies) from the URL. Database rows, user records,
> and stored file contents are never read.

### Host permission — `https://console.firebase.google.com/*`

> Required to recognize Firebase Console contexts (Firestore rules,
> Storage rules, Auth, App Check, Remote Config) from the URL. Firestore
> documents, Realtime Database data, and stored file contents are never
> read.

### Host permission — `https://admin.shopify.com/*`

> Required to recognize Shopify Admin contexts (apps & scopes, webhooks /
> notifications, store settings) from the URL. Customer records, order
> contents, payment data, inventory, and theme files are never read.

---

## Privacy practices answers

Paste these into the Dashboard's *Privacy practices* form.

| Question                                                | Answer                                                                                                                                       |
| ------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Does this extension collect any of the following data?  | **No** — the extension does not collect or transmit data of any kind in this prototype.                                                       |
| Personally identifiable information                     | Not collected.                                                                                                                                |
| Health information                                      | Not collected.                                                                                                                                |
| Financial / payment information                         | Not collected.                                                                                                                                |
| Authentication information                              | Not collected.                                                                                                                                |
| Personal communications                                 | Not collected.                                                                                                                                |
| Location                                                | Not collected.                                                                                                                                |
| Web history                                             | Not collected. Browsing history is not read or stored.                                                                                        |
| User activity                                           | Not collected. Per-context dismissal flags are stored locally in `chrome.storage.local` and never transmitted.                                |
| Website content                                         | Not collected. The extension reads only the URL of the active tab and does not access DOM, form values, cookies, or page contents.            |

Required affirmations:

- [x] I certify the data is **not** being sold to third parties.
- [x] I certify the data is **not** being used or transferred for
      purposes unrelated to the item's single purpose.
- [x] I certify the data is **not** being used or transferred to determine
      creditworthiness or for lending purposes.

---

## Data-collection statement

> ConfigTrace Provider Console Helper does not collect, transmit, sell, or
> share user data. All state is kept locally in the user's browser via
> `chrome.storage.local`. The extension reads only the URL of the active
> tab and uses URL patterns to display matching guidance. No HTTP requests
> are made by the extension to ConfigTrace or any other server.

---

## Support contact

| Field           | Value                                                  |
| --------------- | ------------------------------------------------------ |
| Support email   | **TBD — placeholder for review** (e.g. `support@configtrace.org`) |
| Support website | `https://configtrace.org/docs.html`                    |
| Privacy policy  | `https://configtrace.org/docs/data-access.html` (technical disclosure) — see *Blockers* below |

> **Blocker:** Chrome Web Store requires a dedicated *privacy policy* URL.
> `docs/data-access.html` is the closest existing public document but is
> not a formal privacy policy. Decision needed before public submission:
> (a) add `privacy.html` to the public marketing site, or
> (b) link directly to `docs/data-access.html` and accept whatever
>     guidance the Chrome reviewer provides.

---

## Screenshot checklist

Chrome Web Store accepts up to 5 screenshots (1280×800 or 640×400 PNG/JPG).
Capture in this order — see `screenshots/README.md` for a detailed shooting
guide and safety rules.

- [ ] **#1** Toolbar popup on a neutral page (shows the "no supported provider" state + settings panel).
- [ ] **#2** AWS Security Groups page with the ConfigTrace helper panel mounted in the bottom-right.
- [ ] **#3** GitHub branch protection settings page with the panel mounted.
- [ ] **#4** Stripe webhooks page with the panel mounted.
- [ ] **#5** Either: Cloudflare DNS, Vercel env vars, Supabase RLS, Firebase rules, or Shopify webhooks — whichever showcases the diversity best.

Optional promotional images (only if doing a featured/promoted listing):
- [ ] Small promo tile (440×280)
- [ ] Marquee promo (1400×560)

---

## Pre-submission publishing checklist

Manual steps the maintainer performs in the Chrome Developer Dashboard.

- [ ] Chrome Web Store developer account exists (one-time $5 USD
      registration fee paid).
- [ ] Two-factor authentication enabled on the developer account.
- [ ] Privacy policy URL ready (see *Support contact* note above).
- [ ] Screenshots captured per the checklist.
- [ ] Run `./package-extension.sh` → confirm
      `dist/configtrace-provider-console-helper-0.1.0.zip` exists.
- [ ] `unzip -l dist/configtrace-provider-console-helper-0.1.0.zip` shows
      only the expected files (no `.git`, `dist/`, `.DS_Store`,
      `screenshots/`, `node_modules/`, env files).
- [ ] Manifest fields (`name`, `short_name`, `description`, `version`,
      `icons`) match this document.
- [ ] Permission justifications pasted from this file.
- [ ] Privacy practices form completed exactly as in this file.
- [ ] Distribution set to "Public" (or "Unlisted" for a soft launch).
- [ ] Visible regions: leave Chrome's default (all regions) unless there
      is a compliance reason to restrict.
- [ ] Submit for review. Google review typically takes a few business days
      and can request changes; respond via the Dashboard.
