# Commercial Infrastructure — Stripe Coupling Inventory (message 1)

Scope note (important, discovered during this audit): this repository
contains **two unrelated Stripe surfaces**:

1. **ConfigTrace's own billing** (charging customers for Pro/Team plans) —
   `app/services/billing_service.py`, `app/models/billing.py`,
   `app/routers/billing.py`, `app/routers/stripe_webhook.py`. **This is
   the subject of this inventory and this entire message.**
2. **The Stripe security-monitoring connector** (`app/connectors/stripe.py`,
   `app/services/risk_rules/stripe.py`, `app/services/security_rules/stripe.py`,
   `stripe_schema.py`) — ConfigTrace *monitors a customer's own Stripe
   account* for configuration drift and security findings, exactly like it
   monitors AWS/GitHub/Snowflake/etc. **This is unrelated to ConfigTrace's
   own payment processing and is explicitly OUT OF SCOPE** for this
   Commercial Infrastructure message — it is not modified, and continuing
   to certify/monitor customer Stripe accounts has nothing to do with which
   provider ConfigTrace itself uses to bill its own customers.

Search terms used: `stripe`, `Stripe`, `STRIPE_`, `stripe_customer_id`,
`stripe_subscription_id`, `stripe_price_id`, `stripe_product_id`,
`checkout.session`, `billing portal`, `webhook secret`, `payment status`,
`subscription status`, `plan price`, `Team price`, `$50`, `5000 cents`.
Searched: backend, frontend, migrations, tests, seed data, configuration,
Docker, GitHub Actions, Render/Vercel configuration, documentation, scripts.

**Correction to the task's stated baseline**: the current Team price is
**$40/month flat** (set in M58.25, "early-access pricing"), not $50 — there
is no `$50`/`5000`-cents Team reference anywhere in the current codebase
(confirmed by direct read of `billing_service.py` and grep for `5000`/`$50`).
The new $30-base + $5/seat formula replaces this $40 flat price.

## Columns

Location · Symbol/reference · Layer · Current responsibility ·
Stripe-specific? · Replacement abstraction · M1 action · M2 action ·
Removal milestone · Risk

## Backend — billing domain (own payment processing)

| Location | Symbol/reference | Layer | Current responsibility | Stripe-specific? | Replacement abstraction | M1 action | M2 action | Removal milestone | Risk |
|---|---|---|---|---|---|---|---|---|---|
| `app/models/billing.py` | `WorkspaceBilling.stripe_customer_id` | model | Stores the Stripe Customer ID per workspace | Yes | `BillingProviderReference(provider=stripe, object_type=customer)` | Documented as compatibility field; kept unmodified | Populate `BillingProviderReference` in parallel on write | Post-cutover + rollback window | Low — opaque ID, no PII |
| `app/models/billing.py` | `WorkspaceBilling.stripe_subscription_id` | model | Stores the Stripe Subscription ID per workspace | Yes | `BillingProviderReference(provider=stripe, object_type=subscription)` | Documented as compatibility field; kept unmodified | Populate in parallel; sync into `NormalizedSubscription` | Post-cutover + rollback window | Low |
| `app/models/billing.py` | `WorkspaceBilling.stripe_price_id` | model | Stores the active Stripe Price ID | Yes | Internal `plan_id` + `PriceComponent` mapping | Documented as compatibility field; kept unmodified | Map to `plan_id` via `_plan_for_price` equivalent | Post-cutover + rollback window | Low |
| `app/models/billing.py` | `StripeWebhookEvent` | model | Stripe-only webhook idempotency (event_id unique) | Yes | `BillingWebhookEvent` (provider, external_event_id) | Left unmodified; new `BillingWebhookEvent` table added alongside | Stripe adapter can dual-write or migrate to new table | Post-cutover | Low |
| `app/services/billing_service.py` | `PLAN_LIMITS["team"]["monthly_price_usd"]` (40) | service | Legacy flat Team price used only for docs/trial-day lookup | Yes (legacy Stripe price assumption) | `app/billing/plans.py::TEAM_PLAN` + `app/billing/pricing.py` | Left unchanged (existing Stripe checkout still charges the configured flat Stripe price) — **isolation, not rewrite** | Retire once Paddle multi-item checkout replaces it | M2 cutover | Medium — display/actual-charge mismatch, documented in message1.md limitations |
| `app/services/billing_service.py` | `_stripe_post`, `create_checkout_session`, `create_portal_session`, `verify_stripe_signature`, `handle_webhook_event` | service | All direct Stripe HTTP API calls (raw httpx, no SDK) | Yes | `app.billing.adapters.stripe.StripeBillingAdapter` | Wrapped, not rewritten | Adapter gains real seat-based checkout wiring only if kept post-cutover for compatibility | Post-cutover | Medium — production payment code path |
| `app/services/billing_service.py` | `_allowed_price_ids`, `_plan_for_price`, `_trial_days_for_price` | service | Server-side Stripe price-ID allowlist / plan mapping | Yes | `app/billing/plans.py` provider mappings (future) | Unchanged | Superseded by Paddle price mapping | M2+ | Low |
| `app/config.py` | `STRIPE_SECRET_KEY` | config | Stripe API auth | Yes | N/A (provider-specific secret) | Unchanged; documented | Add `PADDLE_API_KEY` alongside, not replacing | Retirement phase (message-2 report Phase E) | High if leaked — secret |
| `app/config.py` | `STRIPE_WEBHOOK_SECRET` | config | Stripe webhook HMAC verification | Yes | N/A | Unchanged | Add `PADDLE_WEBHOOK_SECRET` alongside | Retirement phase | High if leaked |
| `app/config.py` | `STRIPE_PRICE_PRO_MONTHLY`, `STRIPE_PRICE_TEAM_MONTHLY` (+aliases) | config | Stripe Price IDs for Pro/Team | Yes | `app/billing/plans.py` provider mappings | Unchanged | Superseded by `PADDLE_BASE_PRICE_ID`/`PADDLE_ADDITIONAL_SEAT_PRICE_ID` | Retirement phase | Low |
| `app/routers/billing.py` | `BillingResponse.stripe_customer_id`, `.stripe_subscription_id`, `.stripe_mode`, `.stripe_configured`, `.stripe_events_configured` | router | API response fields exposing Stripe config status (never secrets) | Yes | Provider-neutral response fields (future) | Unchanged; new `pricing-preview` endpoint added alongside | Add `provider`/`paddle_configured` fields | M2 | Low — no secret exposure, already audited |
| `app/routers/stripe_webhook.py` | `POST /stripe/webhook` | router | Public Stripe webhook receiver | Yes | Provider-neutral webhook router (future, per-provider path) | Unchanged; no Paddle webhook route added yet | Add `POST /paddle/webhook` as a new, separate route | M2 | Medium — public endpoint, signature-verified |
| `alembic/versions/006_m52_billing.py` | `workspace_billing.stripe_*` columns | migration | Original billing schema | Yes | N/A (historical) | Left unmodified (never destructively altered) | N/A | Never — historical record | None |
| `alembic/versions/018_m594_abuse_protection.py` | `stripe_webhook_events` table | migration | Original webhook idempotency table | Yes | `commercial_webhook_events` (new, additive) | Left unmodified | N/A | Post-cutover, if ever | None |

## Backend — new provider-neutral domain (message 1 additions)

| Location | Symbol/reference | Layer | Current responsibility | Stripe-specific? | Replacement abstraction | M1 action | M2 action | Removal milestone | Risk |
|---|---|---|---|---|---|---|---|---|---|
| `app/billing/adapters/stripe.py` | `StripeBillingAdapter` | adapter | Wraps existing Stripe flows behind `BillingProviderAdapter` | Yes (implementation), No (interface) | N/A — this IS the abstraction | Created this message | Extended only if needed for compatibility during cutover | Post-cutover + rollback window | Low — read-only wrapper, no new Stripe calls |
| `app/billing/models.py` | `BillingWebhookEvent.provider`, `.external_event_id` | model | Provider-neutral webhook idempotency | No (bounded enum value) | N/A | Created this message | Paddle adapter writes into same table | N/A | None |
| `app/billing/registry.py` | `BILLING_PROVIDER` setting reference | config/registry | Selects active adapter | No (reads a string, bounded by enum) | N/A | Defaults to "stripe" — preserves deployed behavior | M2 changes deployment default to "paddle" | N/A | None |

## Frontend

| Location | Symbol/reference | Layer | Current responsibility | Stripe-specific? | Replacement abstraction | M1 action | M2 action | Removal milestone | Risk |
|---|---|---|---|---|---|---|---|---|---|
| `frontend/src/app/(app)/settings/workspace/billing/page.tsx` | `NEXT_PUBLIC_STRIPE_PRICE_PRO_MONTHLY`, `NEXT_PUBLIC_STRIPE_PRICE_TEAM_MONTHLY` | frontend | Client-side-safe Stripe Price IDs used to build checkout requests | Yes | Future `NEXT_PUBLIC_PADDLE_*` variables (message 2) | Unchanged; Team pricing COPY updated to new formula this message | Add Paddle checkout path alongside | M2+ | Low — public, non-secret price identifiers |
| `frontend/src/app/(app)/settings/workspace/billing/page.tsx` | `PLAN_META.team.monthlyPriceUsd` (was `"$40"`) | frontend | Static Team price display | Yes (was tied to the flat Stripe price) | `app/billing/pricing.py` via `getTeamPricingPreview()` | **Updated this message** to `"$30"` + formula copy; dynamic breakdown fetched from the new pricing-preview endpoint | N/A | N/A | Low |
| `frontend/src/lib/api.ts` | `createCheckoutSession`, `createPortalSession` | frontend | Calls the existing Stripe checkout/portal endpoints | Yes (endpoint names/shape) | Provider-neutral checkout/portal abstraction (backend-side only in M1) | Unchanged | Add Paddle checkout call path | M2 | Low |
| `frontend/src/types/index.ts` | `WorkspaceBilling` type (`stripe_customer_id`, `stripe_subscription_id`) | frontend | TypeScript type mirroring the billing API response | Yes | N/A | Unchanged | Add `provider` field | M2 | None |

## Test-only references (not omitted per spec item 2)

| Location | Symbol/reference | Layer | Current responsibility | Stripe-specific? | M1 action | Risk |
|---|---|---|---|---|---|---|
| `tests/test_milestone52.py` | `WorkspaceBilling` model tests | test | Pins original billing model behavior | Yes | Unchanged; still passes | None |
| `tests/test_milestone58_25.py` | Pro/Team pricing + trial metadata tests | test | Pins the EXISTING (unchanged) flat Pro/Team Stripe checkout flow | Yes | Unchanged; still passes (asserts Team=$40, which remains true for the legacy compatibility path) | None — explicitly allowlisted in `test_commercial_stale_team_price.py` |
| `tests/test_milestone58_26.py` | Portal-only cancellation policy tests | test | Pins existing cancellation-via-portal behavior | Yes | Unchanged | None |
| `tests/test_milestone59_2.py`, `test_milestone59_3.py` | Webhook / billing edge-case tests | test | Pins existing webhook handling | Yes | Unchanged | None |
| `tests/test_commercial_stripe_adapter.py` | New adapter tests | test | Proves adapter wraps existing behavior without external calls | Yes (subject), No (test itself is provider-neutral in spirit) | Created this message | None |

## Deployment / configuration references

| Location | Symbol/reference | Layer | Current responsibility | Stripe-specific? | M1 action | Risk |
|---|---|---|---|---|---|---|
| `.env.example` | (no `STRIPE_*` entries existed before this message) | config example | N/A | N/A | Added `STRIPE_*`/`BILLING_PROVIDER`/`PADDLE_*` placeholder section (empty values only) this message | None — no secrets |
| `render.yaml` | (no Stripe/Paddle references) | infra-as-code | Render service topology only, no env var declarations for Stripe | N/A | Confirmed unchanged; not modified this message | None |
| GitHub Actions (`.github/workflows/`) | (no Stripe references) | CI | Provider-certification workflow only (message 7); no billing secrets used in CI | N/A | Confirmed unchanged | None |
| Docker Compose | (no Stripe references) | local dev | No Stripe env vars declared in `docker-compose.yml` | N/A | Confirmed unchanged | None |

## Out-of-scope Stripe references (security-monitoring connector — different feature)

Listed for completeness per spec item 2 ("do not omit test-only or
deployment-only references"), but explicitly **not** part of this
message's billing-provider work:

`app/connectors/stripe.py`, `app/connectors/stripe_schema.py`,
`app/services/risk_rules/stripe.py`, `app/services/security_rules/stripe.py`,
`app/provider_certification/manifests/stripe.py`, and their ~10 associated
test files (`test_stripe_*_qa.py`, `test_stripe_part1/2_risk_audit.py`,
`test_provider_certification_stripe.py`, `test_milestone35.py`,
`test_milestone60_4_5_stripe_vercel_shopify_rules.py`,
`test_milestone73a/b/e_stripe_*.py`) — these monitor a CUSTOMER's own
Stripe account for security configuration drift, exactly like the AWS or
GitHub connectors monitor those providers. No action taken; frozen under
the Provider Certification Framework's provider-expansion freeze regardless.
