# Dodo Payments — Live Mode cutover runbook

Status as of this document: **Dodo Payments is implemented and tested in
Test Mode only.** `BILLING_PROVIDER` is `stripe` in every deployed
environment. No Dodo Live Mode object (product, API key, webhook,
customer, subscription, or payment) has been created. This runbook exists
so that, once Dodo approves Live Mode access, the rollout can be completed
deterministically by following the stages below — without requiring an
engineering session to re-derive the plan.

This document assumes familiarity with the existing provider-neutral
billing domain (`backend/app/billing/`) and the Stripe/Paddle rollouts that
preceded it. It does not re-explain that architecture.

---

## 0. Prerequisites

Before starting Stage A:

- [ ] Dodo Payments has approved Live Mode access for the ConfigTrace merchant account.
- [ ] You have Owner/Admin access to the Dodo Payments dashboard, Live Mode.
- [ ] You have access to the Render dashboard for the `configtrace-api` service (Environment tab).
- [ ] You have a way to receive one real payment (a card you're willing to charge, or Dodo's documented Live-mode test-card equivalent if one exists — verify in the Dodo dashboard, since this has not been confirmed by this codebase).
- [ ] You have picked ONE non-production-critical workspace to pilot Dodo Live checkout (Stage H) before the global switch.
- [ ] You have read section 6 (Rollback) before starting — know how to undo every stage before you do it.

Dashboard paths referenced throughout (Dodo's dashboard layout is assumed stable but has not been re-verified since this codebase's Test Mode implementation — confirm paths on the day of cutover):

- Dodo Dashboard → **Products** (catalog creation/verification)
- Dodo Dashboard → **Developers → API Keys** (Live API key)
- Dodo Dashboard → **Developers → Webhooks** (Live webhook endpoint + signing secret)
- Render Dashboard → `configtrace-api` service → **Environment**

---

## 1. Live catalog runbook

Dodo has no separate "Price" resource — price is embedded directly on the
product. Create these THREE Live Mode objects, in this order:

### 1.1 ConfigTrace Pro

| Field | Value |
|---|---|
| Name | `ConfigTrace Pro` |
| Price | `$10.00 USD` |
| Billing interval | Monthly (recurring) |
| Tax category | SaaS |
| Add-ons | None |

### 1.2 ConfigTrace Team

| Field | Value |
|---|---|
| Name | `ConfigTrace Team` |
| Price | `$30.00 USD` |
| Billing interval | Monthly (recurring) |
| Tax category | SaaS |
| Includes | Up to 20 billable workspace members (informational — Dodo does not enforce a seat count; ConfigTrace's own billing domain enforces this via `DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID`, see below) |

### 1.3 ConfigTrace Additional Team Member (add-on)

| Field | Value |
|---|---|
| Name | `ConfigTrace Additional Team Member` |
| Price | `$5.00 USD per unit` |
| Type | Recurring add-on |
| Associated product | ConfigTrace Team **only** — do NOT associate with Pro |

### 1.4 Verification checklist (before recording any ID)

For **each** of the three objects above, confirm in the Dodo dashboard:

- [ ] You are in **Live Mode**, not Test Mode (check the dashboard's mode toggle — this is the single most common mistake in this stage).
- [ ] Price and currency are exactly `$10.00 USD` / `$30.00 USD` / `$5.00 USD` — no rounding, no different currency default.
- [ ] Billing interval is **Monthly**, not annual or one-time.
- [ ] Product/add-on status is **Active** (not draft/archived).
- [ ] The add-on is associated with Team only, not Pro, not standalone.
- [ ] No duplicate object exists — search the Live catalog by name before creating; if a duplicate is accidentally created, archive/delete the extra one and re-verify the ID you're about to record still points at the correct, single object.

### 1.5 Record exact IDs

Copy the Live Mode product/add-on IDs into the credential inventory template in section 8 of this document. Do **not** paste them into chat with an AI assistant, a ticket, or Slack — treat them as operationally sensitive even though they are not secrets (see section 2).

---

## 2. Production environment contract

All Dodo variables are set on **Render**, on the `configtrace-api` service only. **No Vercel/frontend variable is needed for Dodo** — the frontend never talks to Dodo directly; `handleDodoCheckout` (see `frontend/src/app/(app)/settings/workspace/billing/page.tsx`) only redirects the browser to a `checkout_url` the backend already created via a server-side Dodo API call, exactly like the existing Stripe path. Do not invent a `NEXT_PUBLIC_DODO_*` variable — none is required.

| Variable | Secret? | Accepted values | Test → Live changes? |
|---|---|---|---|
| `BILLING_PROVIDER` | No | `stripe` \| `paddle` \| `dodo` | **Do not touch until Stage M.** Stays `stripe` through Stage L. |
| `DODO_ENVIRONMENT` | No | `test` / `live` (this codebase's short form) OR `test_mode` / `live_mode` (Dodo's own SDK convention — both are accepted and normalized, see `Settings.dodo_environment_normalized`) | Yes — must become `live` (or `live_mode`) in Stage D. |
| `DODO_API_KEY` | **Yes** | Live Mode API key from Dodo Dashboard → Developers → API Keys | Yes — a completely different value from the Test key. Never reuse the Test key. |
| `DODO_WEBHOOK_SECRET` | **Yes** | Live Mode webhook signing secret, `whsec_`-prefixed, base64 after the prefix (Standard Webhooks format) | Yes — a completely different value from the Test secret; generated fresh when you create the Live webhook endpoint in Stage C. |
| `DODO_PRO_PRODUCT_ID` | No (but treat as sensitive-adjacent — see 1.5) | Live Mode Pro product ID from Stage A | Yes — different ID from the Test Mode product. |
| `DODO_TEAM_PRODUCT_ID` | No | Live Mode Team product ID from Stage A | Yes — different ID from the Test Mode product. |
| `DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID` | No | Live Mode add-on ID from Stage A | Yes — different ID from the Test Mode add-on. |
| `DODO_PILOT_WORKSPACE_ID` | No (plain workspace UUID) | A single workspace UUID, or unset | New for live-cutover preparation — see section 5. Not present during Test Mode implementation. |
| `BILLING_GRACE_PERIOD_DAYS` | No | Integer ≥ 0 | Unchanged — provider-neutral, already set for Stripe/Paddle. |

**Stripe and Paddle variables that must remain, unchanged, through and after the entire Dodo cutover** (removing any of these breaks existing Stripe/Paddle subscriptions, which continue to be managed by their original provider under the stored-provider-wins rule — see `app/billing/provider_routing.py`):

- `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, and every other existing `STRIPE_*` variable already in Render.
- `PADDLE_API_KEY`, `PADDLE_WEBHOOK_SECRET`, `PADDLE_ENVIRONMENT`, and every other existing `PADDLE_*` variable already in Render.
- Any existing billing safety/kill-switch variable already in Render (e.g. the frontend's `NEXT_PUBLIC_BILLING_CHECKOUT_DISABLED` on Vercel, if set) — Dodo does not replace or interact with these; they continue to gate checkout globally regardless of provider.

**Do not invent any other variable.** If a step in this runbook seems to need a new environment variable not listed above, stop and re-derive it from the actual adapter code (`backend/app/billing/adapters/dodo.py`, `backend/app/config.py`) rather than guessing.

---

## 3. Live webhook runbook

Target endpoint: `https://api.configtrace.org/dodo/webhook` (already deployed and live for Test Mode traffic — see `backend/app/routers/dodo_webhook.py`; the route itself does not change for Live Mode, only the secret used to verify it).

### 3.1 Events to subscribe to

Subscribe the Live endpoint to every event this codebase's normalization map (`backend/app/billing/dodo_webhooks.py::_DODO_EVENT_TYPE_MAP`) understands:

```
subscription.active
subscription.renewed
subscription.updated
subscription.plan_changed
subscription.on_hold
subscription.paused
subscription.cancelled
subscription.failed
subscription.expired
subscription.update_payment_method
payment.succeeded
payment.failed
dunning.started
dunning.recovered
```

If Dodo's Live webhook creation UI offers an "all events" option instead of per-event selection, that is also safe to use — every event this codebase does not recognize maps to `WebhookEventType.UNKNOWN` and is acknowledged (HTTP 200) without mutating any subscription state (see `dodo_webhook_service.process_dodo_webhook`).

### 3.2 Create the Live endpoint

1. Dodo Dashboard → **Developers → Webhooks** → confirm you are in **Live Mode**.
2. Add endpoint: `https://api.configtrace.org/dodo/webhook`.
3. Select the event list from 3.1 (or "all events").
4. Save.

### 3.3 Retrieve and store the Live signing secret

1. Dodo will display the Live webhook's signing secret once (`whsec_...`). Copy it immediately — most webhook providers do not show it again.
2. Set it in Render as `DODO_WEBHOOK_SECRET` (Stage C/D). Never paste it into a commit, a test file, a ticket, or chat.

### 3.4 Unsigned reachability test

Before wiring the real secret, confirm the endpoint is publicly reachable and returns the expected 400 for a missing signature:

```bash
curl -i -X POST https://api.configtrace.org/dodo/webhook \
  -H "Content-Type: application/json" \
  -d '{"type":"ping"}'
```

Expected: `HTTP/1.1 400 Bad Request` with body `{"detail":"Missing required webhook signature headers."}`. If you get a connection error or a 5xx, do not proceed — the endpoint itself is broken, independent of Dodo.

### 3.5 Signed test-event verification

Use Dodo's dashboard "Send test event" feature against the Live endpoint (if offered — Dodo's Live dashboard test-event support has not been independently verified by this codebase; check the Webhooks page for a "Test" or "Resend" action). Expected: `HTTP 200 {"status":"ok"}`.

If Dodo has no dashboard test-event feature for Live endpoints, defer full signature verification to Stage G (the first real signed delivery from an actual Live checkout), and use 3.4 to confirm reachability only.

### 3.6 Replay / idempotency verification

Trigger the same event delivery twice (via Dodo's dashboard "Resend" action if available, or by observing Dodo's natural retry if the first delivery is deliberately slow). Expected: the second delivery still returns `HTTP 200`, and `dodo_live_cutover.py webhook-events` (section 7) shows the event's `processing_status` as `duplicate_ignored`, not a second `processed` row — uniqueness is enforced on `(provider, external_event_id)` at the database level (`commercial_webhook_events` table), so this is expected to hold without any additional code changes.

### 3.7 Failure handling

- **HTTP 400** — signature verification failed. Check: is `DODO_WEBHOOK_SECRET` in Render the Live secret (not the Test secret)? Was it pasted with the `whsec_` prefix intact?
- **HTTP 503** — `DODO_WEBHOOK_SECRET` is unset in Render. Confirm Stage D completed.
- **HTTP 200 `{"status":"error"}`** — signature verified but processing failed (see `DodoWebhookProcessingError`). Check Render logs (`Error processing Dodo webhook event: ...`) for the exception. This is safely retryable — Dodo retries up to 8 times over ~10 hours — but should be investigated before it exhausts retries.
- **Database verification** — after any test delivery, run `python scripts/dodo_live_cutover.py webhook-events --provider dodo --limit 5` (see section 7) to confirm the row landed with the expected `event_type` and `processing_status`.
- **Render log inspection** — `logger.info("Dodo webhook processed: %s (%s)", ...)` on success, `logger.warning`/`logger.exception` on failure — search Render's log stream for `Dodo webhook`.

---

## 4. Safe rollout stages (A → N)

Each stage should be completed and verified before moving to the next. None of stages A–G touch `BILLING_PROVIDER` or affect any real customer.

| Stage | Action | Verification |
|---|---|---|
| **A** | Create the Live catalog (section 1): Pro, Team, Additional Team Member. | Section 1.4 checklist passes for all three objects. |
| **B** | Create a Live Dodo API key (Dodo Dashboard → Developers → API Keys, Live Mode). | Key is visible in the dashboard's Live key list; not yet in Render. |
| **C** | Create the Live webhook endpoint (section 3.2) and retrieve its signing secret (section 3.3). | Secret captured; endpoint visible in Dodo's Live webhook list. |
| **D** | Add all Live Dodo variables to Render (`DODO_ENVIRONMENT=live`, `DODO_API_KEY`, `DODO_WEBHOOK_SECRET`, `DODO_PRO_PRODUCT_ID`, `DODO_TEAM_PRODUCT_ID`, `DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID`) **while `BILLING_PROVIDER` remains `stripe`**. Redeploy. | `python scripts/dodo_live_cutover.py env-check` shows all Dodo secrets present and `DODO_ENVIRONMENT` resolves to `live`; `BILLING_PROVIDER` is still `stripe`. |
| **E** | Run the offline readiness checker. | `python scripts/dodo_live_cutover.py readiness` → `all_present=True`, and `not_routing_production_to_dodo` check is `True` (confirms `BILLING_PROVIDER` is still not `dodo`). |
| **F** | Run the read-only Live catalog verification. | `python scripts/dodo_live_cutover.py catalog-verify --live` succeeds, returns the raw product JSON for Pro and Team; manually re-confirm the section 1.4 checklist against the returned data. |
| **G** | Verify signed Live webhook delivery (section 3.5/3.6). | A real or dashboard-triggered signed delivery returns `HTTP 200`; `webhook-events` shows the row; a replay shows `duplicate_ignored`. |
| **H** | Enable Dodo for exactly one designated pilot workspace (section 5) via `DODO_PILOT_WORKSPACE_ID` in Render. `BILLING_PROVIDER` remains `stripe` globally. | `python scripts/dodo_live_cutover.py pilot-override status` shows the override active for that workspace only; a *different* workspace's checkout still returns `provider: "stripe"`. |
| **I** | Complete ONE controlled real Pro checkout as/for the pilot workspace, using a real card. | Checkout redirects to Dodo's real hosted page and completes; `subscription` command (section 7) shows a new row with `provider=dodo`, `plan_id=pro`, `status=active`. |
| **J** | Verify the full lifecycle for that one subscription: transaction recorded, subscription active, entitlement upgraded in-app, customer portal reachable, and a test cancellation processed correctly. | `subscription <pilot-workspace>` shows expected fields at each step; in-app plan-gated features unlock/relock as expected; cancelling via the Dodo customer portal results in `cancel_at_period_end=True` then eventually `status=canceled` after the real period end (or immediately if Dodo's portal supports immediate cancellation — verify against the actual portal UI). |
| **K** | Complete ONE controlled real Team checkout for the pilot workspace (or a second pilot workspace, if you want Pro and Team verified independently). | `subscription` shows `provider=dodo`, `plan_id=team`, `billable_seats=20`, `additional_seat_quantity=0`. |
| **L** | Verify 20/21/25-member billing behavior on that Team subscription: add members up to 20 (no add-on charge expected), add a 21st (add-on quantity should become 1), add up to 25 (add-on quantity should become 5). | `subscription <workspace>` shows `additional_seat_quantity` tracking `max(0, member_count - 20)` at each step; confirm the actual Dodo subscription's add-on quantity matches via the Dodo dashboard (this codebase has not independently verified add-on quantity semantics against a real change-plan call — see `adapters/dodo.py`'s module docstring — so this stage IS that verification). |
| **M** | Switch `BILLING_PROVIDER=dodo` in Render globally. Redeploy. | `env-check` shows `BILLING_PROVIDER=dodo`; a brand-new workspace's checkout now defaults to Dodo without needing the pilot override; existing Stripe/Paddle subscriptions are unaffected (stored-provider-wins). Consider unsetting `DODO_PILOT_WORKSPACE_ID` at this point — it becomes a no-op once the global default is already `dodo` (see `dodo_pilot_override_active`'s "nothing to override" case). |
| **N** | Monitor. Retain the ability to roll back (section 6) for at least one full billing cycle. | `python scripts/dodo_live_cutover.py health-check` run periodically (see section 7.10); no unexplained `stuck-webhooks` or `duplicate-subscriptions` findings. |

---

## 5. One-workspace rollout mechanism

Implemented in this codebase (message: "Prepare Dodo live cutover"). Mechanism: a single Render environment variable, `DODO_PILOT_WORKSPACE_ID` (a plain workspace UUID — not a secret), compared for equality inside `provider_for_checkout()` (`backend/app/billing/provider_routing.py`) **only**.

Why this satisfies every stated requirement:

- **Admin-controlled** — only someone with Render dashboard access can set it; no in-app UI exists to change it (matches this codebase's existing precedent of env-var-only admin controls for billing — there is no DB-backed feature-flag system anywhere in this domain).
- **Auditable** — every checkout created under the override records a `PILOT_OVERRIDE_APPLIED` audit event (`BillingAuditEventType.PILOT_OVERRIDE_APPLIED`) with the plan ID, visible via the existing commercial audit log / `commercial_audit_events` table.
- **Reversible** — unsetting the one variable (or letting it expire) instantly reverts every future checkout for that workspace to whatever `BILLING_PROVIDER` is globally, with zero code deploy.
- **No global switch** — `BILLING_PROVIDER` itself is never touched by this mechanism; `provider_for_checkout` only special-cases the designated workspace ID.
- **No secret values in source** — a workspace UUID is not a credential; it is safe to see in logs, code review, or this document.
- **Existing stored-provider routing remains authoritative** — `provider_for_management` and `provider_for_reconciliation` (the functions governing an *existing* subscription) are completely unmodified by this feature; the override only ever affects `provider_for_checkout`, i.e. what happens on a brand-new checkout.
- **No accidental effect on other workspaces** — the override is a single equality check (`workspace_id == pilot_id`); every other workspace's `provider_for_checkout` call is byte-for-byte the same code path as before this feature existed.
- **Fails closed** — the override is silently inert unless Dodo is fully configured (`settings.is_dodo_configured`); a malformed or unset `DODO_PILOT_WORKSPACE_ID` behaves exactly as if the variable were never introduced.

Applying and removing it:

```bash
# See the exact Render variable to SET for a given workspace (does not mutate anything itself):
python scripts/dodo_live_cutover.py pilot-override print "<workspace name or UUID>" --yes

# Check current status:
python scripts/dodo_live_cutover.py pilot-override status

# See the instruction to UNSET it:
python scripts/dodo_live_cutover.py pilot-override clear --yes
```

This tool never calls Render's API — Render environment variables are only reachable from the Render dashboard/CLI, so applying or removing the override is always a manual Render step. The script's job is to resolve the workspace correctly and print the exact value, removing any chance of transposing digits in a UUID by hand.

Test coverage: `backend/tests/test_commercial_dodo_pilot_override.py` (18 tests) — covers pilot-workspace identification, override-active semantics, that `BILLING_PROVIDER` is never mutated, that existing stored-provider routing is untouched, and that the audit event is recorded exactly once per pilot checkout.

---

## 6. Rollback plan

Rollback is possible at every stage. The further along the rollout, the more manual verification (not code changes) rollback requires.

### 6.1 Returning to Stripe globally (after Stage M)

1. In Render, set `BILLING_PROVIDER=stripe`. Redeploy.
2. This immediately stops routing NEW checkouts to Dodo (`configured_checkout_provider()` now returns `stripe`).
3. **Do not delete or disable the Dodo webhook endpoint.** Any workspace that already has a `provider=dodo` subscription (from Stage I onward) must continue to route webhook processing to Dodo — `provider_for_management`/`provider_for_reconciliation` read the STORED provider, not `BILLING_PROVIDER`, so this happens automatically and requires no further action.
4. If `DODO_PILOT_WORKSPACE_ID` is still set, remove it too (section 6.4) unless you specifically want that one workspace to keep using Dodo for new checkouts while everyone else is back on Stripe.

### 6.2 Disabling new Dodo checkout creation without a global flip

If you only want to stop NEW Dodo checkouts (e.g. pause the pilot) without touching the global default:

- If `BILLING_PROVIDER` was never flipped to `dodo` (still mid-rollout, Stage H–L): remove `DODO_PILOT_WORKSPACE_ID` (section 6.4). This is the only mechanism that can route a checkout to Dodo before Stage M.
- If `BILLING_PROVIDER=dodo` already (post Stage M): there is no partial "disable new checkouts but keep everything else" switch for the global default — use 6.1 (revert to `stripe`) and re-enable per-workspace only via the pilot override if narrower scope is needed.

### 6.3 What must NOT be deleted during rollback

- The Live Dodo webhook endpoint (existing Dodo subscriptions still need their webhook events processed — deleting it silently stops updating their status, which will eventually look like a stuck/expired subscription to the customer).
- Any Dodo environment variable in Render (`DODO_API_KEY`, `DODO_WEBHOOK_SECRET`, catalog IDs) — these are needed for `provider_for_management`/`provider_for_reconciliation` to keep managing any subscription that already exists under Dodo, even after `BILLING_PROVIDER` reverts to `stripe`.
- Any `commercial_subscriptions`, `commercial_webhook_events`, or `commercial_audit_events` row — these are the source of truth for what actually happened and are needed for both support and future reconciliation.

### 6.4 Removing the one-workspace override

```bash
python scripts/dodo_live_cutover.py pilot-override clear --yes
```

Then, in Render, delete the `DODO_PILOT_WORKSPACE_ID` variable (or set it empty) and redeploy. This is fully reversible in the other direction too — re-add it with the same workspace UUID to resume the pilot.

### 6.5 Handling checkout failures during rollback

If a checkout is in flight (customer on Dodo's hosted page) at the moment `BILLING_PROVIDER` flips back to `stripe`:

- The in-flight Dodo checkout session is unaffected — Dodo's hosted page and the resulting webhook delivery both still complete normally, and the resulting `NormalizedSubscription` row is still created with `provider=dodo` (the checkout was created under the provider active at checkout-creation time, not at webhook-delivery time).
- Only the NEXT checkout attempt (a fresh "Upgrade" click) is affected by the reverted `BILLING_PROVIDER`.
- No orphaned or half-created state is possible: `_create_plan_checkout` only records the `PILOT_OVERRIDE_APPLIED` audit event and commits AFTER the provider's `create_checkout` call already succeeded (see `backend/app/routers/billing.py`) — a failed Dodo API call never produces a local DB row at all.

---

## 7. Safe operational commands

`backend/scripts/dodo_live_cutover.py` — a single CLI with subcommands, following this repo's existing `scripts/set_workspace_plan.py` conventions. Run from `/backend` with the venv active and `DATABASE_URL` reachable (see section 9 for how this document's author ran it locally).

Safety properties enforced across every subcommand (see the script's own module docstring and `backend/tests/test_commercial_dodo_live_cutover_script.py` for verification):

- **Never prints a secret.** `DODO_API_KEY`, `DODO_WEBHOOK_SECRET`, and every existing Stripe/Paddle secret are reported as presence-only booleans (`env-check`); `catalog-verify` never logs the API key; error messages from the Dodo client are already sanitized upstream (`dodo_client.py`).
- **Read-only by default.** The only network call anywhere in the script is a single `GET` (inside `catalog-verify`) — no command issues a `POST`/`PATCH` to Dodo, ever.
- **Test-oriented commands refuse Live Mode.** `catalog-verify` refuses to run if the configured `DODO_ENVIRONMENT` resolves to `live` unless you pass `--live` explicitly (and refuses the reverse mismatch too — passing `--live` against a Test-configured environment).
- **No script may switch the global provider automatically.** Nothing in this file reads-then-writes `BILLING_PROVIDER`; nothing sets `DODO_PILOT_WORKSPACE_ID` in Render (Render's API is never called).
- **Every mutating-adjacent operation prints its target before requiring confirmation.** `pilot-override print`/`clear` print the resolved workspace or the variable being targeted before the required `--yes` flag is even checked.

### 7.1 Readiness check

```bash
python scripts/dodo_live_cutover.py readiness
```
Offline (no HTTP), wraps `app.billing.dodo_config.check_dodo_readiness`. Exit code 0 if every field is present and consistent, 1 otherwise.

### 7.2 Masked environment-variable presence check

```bash
python scripts/dodo_live_cutover.py env-check
```
Prints presence (`True`/`False`) for every secret variable, and the real value for every documented non-secret variable (`BILLING_PROVIDER`, `DODO_ENVIRONMENT`, catalog IDs, `DODO_PILOT_WORKSPACE_ID`).

### 7.3 Catalog verification (Test or Live)

```bash
python scripts/dodo_live_cutover.py catalog-verify            # refuses if configured env is live
python scripts/dodo_live_cutover.py catalog-verify --live     # Stage F
```
Read-only `GET /products/{id}` for the configured Pro and Team product IDs. Prints the raw response for manual comparison against the section 1.4 checklist (this codebase has not independently verified Dodo's exact product-response field names for price/currency/status — see `tests/test_commercial_dodo_sandbox_optional.py` — so the script deliberately does not assert on them itself). Also flags if the Pro and Team IDs are identical (duplicate-object detection).

### 7.4 Webhook-event inspection

```bash
python scripts/dodo_live_cutover.py webhook-events --provider dodo --status failed --limit 20
```
Lists recent `commercial_webhook_events` rows (id, event type, processing status, error category, attempt count, received-at). Read-only.

### 7.5 Subscription/provider counts

```bash
python scripts/dodo_live_cutover.py subscription-counts
```
Groups `commercial_subscriptions` by `(provider, status)` — use this before and after Stage M to confirm the population shift looks as expected.

### 7.6 One-workspace provider override (apply / remove)

```bash
python scripts/dodo_live_cutover.py pilot-override status
python scripts/dodo_live_cutover.py pilot-override print "<workspace>" --yes
python scripts/dodo_live_cutover.py pilot-override clear --yes
```
See section 5. Never calls Render; only resolves the workspace and prints the exact instruction.

### 7.7 Normalized-subscription inspection

```bash
python scripts/dodo_live_cutover.py subscription "<workspace name or UUID>"
```
Full non-secret snapshot of one workspace's `NormalizedSubscription` row (provider, plan, status, seats, period, grace period, version).

### 7.8 Duplicate subscription detection

```bash
python scripts/dodo_live_cutover.py duplicate-subscriptions
```
Flags any provider-side subscription or customer reference shared by more than one workspace's row — a data-integrity signal, not an expected outcome under any provider's documented behavior. Exit code 1 if any finding exists.

### 7.9 Stuck webhook detection

```bash
python scripts/dodo_live_cutover.py stuck-webhooks --older-than-minutes 60
```
Lists `commercial_webhook_events` rows still `pending` or `failed` older than the threshold. Exit code 1 if any finding exists.

### 7.10 Post-cutover health check

```bash
python scripts/dodo_live_cutover.py health-check
```
Composite, fully offline (no Dodo API call): readiness + subscription counts + stuck-webhook count + duplicate-subscription count + current `BILLING_PROVIDER`. Exit code 0 only if readiness passes AND there are zero stuck webhooks AND zero duplicate-subscription findings. Safe to run on a schedule post-cutover (Stage N).

---

## 8. Credential and object-ID inventory template

Copy this block into your own secrets manager (never into a committed file) and fill in the placeholders during Stages A–D. **This template, as it appears here, contains no real values — every field is a placeholder.**

```
# Dodo Payments — LIVE MODE inventory. NOT a real credential file.
# Fill in during Stages A-D. Store only in a secrets manager, never in git.

DODO_ENVIRONMENT=live                          # or live_mode, per Dodo's dashboard convention
DODO_API_KEY=<REPLACE_WITH_LIVE_API_KEY>
DODO_WEBHOOK_SECRET=<REPLACE_WITH_LIVE_WEBHOOK_SIGNING_SECRET>   # whsec_...

DODO_PRO_PRODUCT_ID=<REPLACE_WITH_LIVE_PRO_PRODUCT_ID>
DODO_TEAM_PRODUCT_ID=<REPLACE_WITH_LIVE_TEAM_PRODUCT_ID>
DODO_TEAM_ADDITIONAL_SEAT_ADDON_ID=<REPLACE_WITH_LIVE_ADDON_ID>

DODO_PILOT_WORKSPACE_ID=<REPLACE_WITH_PILOT_WORKSPACE_UUID>      # Stage H only; remove after Stage M

# Verification record (fill in as each stage completes):
Stage A completed:  [ ] date: __________  by: __________
Stage B completed:  [ ] date: __________  by: __________
Stage C completed:  [ ] date: __________  by: __________
Stage D completed:  [ ] date: __________  by: __________
Stage E (readiness) result: __________
Stage F (catalog-verify --live) result: __________
Stage G (webhook signed delivery) result: __________
Stage H pilot workspace: __________ (name/UUID)
Stage I first real Pro checkout — transaction ref: __________
Stage J lifecycle verification notes: __________
Stage K first real Team checkout — subscription ref: __________
Stage L seat-count verification notes (20/21/25): __________
Stage M global switch date/time: __________
```

---

## 9. Validation performed for this document's code changes

Run from `/backend` with a real `DATABASE_URL` (Docker Compose Postgres, in this case):

```bash
python -m pytest -q tests/ -k "dodo or commercial or billing or stripe or paddle"
```

Result at the time this document was written: **1337 passed, 6 skipped** (the 6 skips are the pre-existing, deliberately opt-in `RUN_DODO_SANDBOX_TESTS=1` Live/Test smoke tests in `test_commercial_dodo_sandbox_optional.py`, which require real Dodo credentials and are not runnable until Stage A–D are complete).

New test files added as part of this preparation:

- `backend/tests/test_commercial_dodo_pilot_override.py` (18 tests) — the one-workspace mechanism (section 5).
- `backend/tests/test_commercial_dodo_live_cutover_script.py` (28 tests) — every operational command's importable logic (section 7), including the never-print-a-secret and refuse-Live-without-flag properties.

No Stripe or Paddle code path was modified. No Dodo Live Mode API call was made. `BILLING_PROVIDER` was not changed in any environment.
