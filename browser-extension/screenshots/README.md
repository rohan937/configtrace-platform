# Screenshots for Chrome Web Store submission

This directory holds the screenshots that will accompany the ConfigTrace
Provider Console Helper listing on the Chrome Web Store.

> **Important:** screenshots in this directory are **excluded** from the
> upload ZIP built by `../package-extension.sh`. They live here as a
> staging area for the maintainer to drag into the Chrome Web Store
> Developer Dashboard manually.

---

## Chrome Web Store screenshot rules

- **Format:** PNG or JPEG, 24-bit color (no alpha channel).
- **Dimensions:** **1280 × 800** (preferred) or **640 × 400**.
- **Count:** at least 1, at most **5**.
- **File size:** ≤ 5 MB each.
- Filenames are not user-visible; use the names below to keep order
  predictable in this directory.

---

## Safety rules (must all hold before a screenshot ships)

Before taking each screenshot, confirm:

- [ ] Browser is signed into a **demo / sandbox / personal-test** account.
      Never use a production account, never use a customer account.
- [ ] Provider is showing **dummy data**: a throwaway AWS account, a
      private test repo, a test Stripe account in test mode, a personal
      Cloudflare zone for a domain you own, a personal Vercel/Supabase/
      Firebase/Shopify project.
- [ ] No real customer names, emails, addresses, payment data, or order
      data are visible anywhere in the frame.
- [ ] No real API keys, tokens, secret values, or partial secret values
      are visible. If a secrets list is in the frame, all values must be
      masked (`••••••••`) by the provider's UI; crop or blur if needed.
- [ ] The browser's profile chip / avatar / user email at the top-right
      is cropped or blurred.
- [ ] Other browser extension icons that might leak identifying info are
      cleared from the toolbar before the shot.
- [ ] The ConfigTrace panel itself is clearly visible (not behind a
      provider modal / dropdown / autocomplete).
- [ ] If a tooltip in the panel says "Read-only browser helper. Does not
      change provider settings.", it is visible — this is good for review
      reviewers to see at a glance.

---

## Shot list

Capture in this order. Files go in this directory as `01-*.png` etc.

### #1 — `01-popup-neutral.png`
**Goal:** Show the toolbar popup on a neutral page (no supported provider
detected) so reviewers see the settings UI and link list.
**How:**
1. Open a non-provider page (e.g. `about:blank` or a personal blog).
2. Click the ConfigTrace toolbar icon.
3. Verify the popup shows: brand row · "No supported provider page
   detected" card · 6 link rows · Settings block · footer "Read-only · URL-
   only context detection · no DOM scraping · no provider mutations.".
4. Screenshot at 1280 × 800.

### #2 — `02-aws-security-groups.png`
**Goal:** AWS Security Groups view with the helper panel mounted.
**How:**
1. In a sandbox AWS account, navigate to EC2 → Security Groups.
2. Open at least one row so the AWS UI looks substantive but no IPs or
   account numbers are visible. Mask or crop if necessary.
3. The ConfigTrace panel appears in the bottom-right. Confirm the
   provider chip reads **AWS** and the title is *AWS Security Groups*.
4. Screenshot at 1280 × 800.

### #3 — `03-github-branch-protection.png`
**Goal:** GitHub branch protection settings page with the helper panel
mounted.
**How:**
1. In a test repo you own, go to **Settings → Branches**.
2. Make sure no real collaborator usernames are visible (use a personal
   throwaway repo).
3. ConfigTrace panel chip should read **GitHub**, title *GitHub Branch
   Protection*.
4. Screenshot at 1280 × 800.

### #4 — `04-stripe-webhooks.png`
**Goal:** Stripe webhooks page with the helper panel mounted.
**How:**
1. Use a **test-mode** Stripe account (the orange "Test mode" banner
   should be visible).
2. Navigate to **Developers → Webhooks**.
3. Verify no signing-secret values are visible.
4. ConfigTrace panel chip should read **Stripe**, title *Stripe Webhooks*.
5. Screenshot at 1280 × 800.

### #5 — *(pick one to round out the listing)*
Capture **one** of the following, whichever is easiest with a sandbox
account on hand:

- `05-cloudflare-dns.png` — Cloudflare DNS records for a personal domain.
- `05-vercel-env-vars.png` — Vercel project Settings → Environment
  Variables (no values visible — Vercel masks them by default).
- `05-supabase-rls.png` — Supabase Database → Policies for a test project.
- `05-firebase-rules.png` — Firebase Firestore → Rules for a test project.
- `05-shopify-webhooks.png` — Shopify Settings → Notifications → Webhooks
  on a development store.

---

## After capturing

- Drop the PNGs in this folder.
- Verify dimensions and file size with
  `sips -g pixelWidth -g pixelHeight 01-*.png` (macOS).
- **Do not commit screenshots to the repo** unless you've double-checked
  the safety rules above. Consider git-ignoring this folder if any
  reviewer accidentally pastes a real account screenshot.
- Confirm `../package-extension.sh` still ships a clean ZIP — screenshots
  are explicitly excluded by the allow-list, but verify by running:
  ```
  cd ..
  ./package-extension.sh
  unzip -l dist/configtrace-provider-console-helper-*.zip | grep -i screenshots || echo "(clean)"
  ```

---

## Optional promotional images

These are only required if doing a "Featured" or "Promoted" listing.
They live in this folder too, named `promo-*.png`.

- **Small promo tile:** 440 × 280 PNG/JPEG.
- **Marquee promo:** 1400 × 560 PNG/JPEG.
- **Large promo (deprecated, optional):** 920 × 680.

Keep promotional artwork brand-consistent (dark background, brand blue,
"CT" mark — same look as the extension icon).
