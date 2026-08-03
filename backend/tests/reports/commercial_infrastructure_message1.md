# Commercial Infrastructure — Message 1 (Provider-Neutral Billing Architecture)

## Objective

Build ConfigTrace's provider-neutral commercial architecture, select
Paddle as the replacement billing provider, implement the new Team
pricing model, and isolate all existing Stripe coupling — without
performing the production cutover, calling any Paddle API, or creating
any real Paddle product/price.

## Graphify results / freshness

All four mandatory queries ran successfully. The graph was one commit
stale (built from `037dadea`; `git rev-parse HEAD` was `6fdbd27`, the
Provider Certification Framework completion commit) — `graphify update .`
was run first, then all four queries re-ran against the fresh graph
(`6fdbd278...`). Key findings from the queries, confirmed by direct reads:

- `app/services/billing_service.py` and `app/models/billing.py`
  (`WorkspaceBilling`, `StripeWebhookEvent`) are ConfigTrace's OWN billing
  implementation.
- **Critical scope-boundary finding**: `app/connectors/stripe.py`,
  `app/services/risk_rules/stripe.py`, `app/services/security_rules/stripe.py`
  are a COMPLETELY UNRELATED feature — ConfigTrace monitors a CUSTOMER's
  own Stripe account for security configuration drift, exactly like it
  monitors AWS/GitHub/Snowflake. Conflating these with ConfigTrace's own
  payment processing would have been a serious architectural error; this
  message's entire scope is the latter only.
- A real, indexed test node (`test_milestone58_25.py`) pinned "Team plan
  must be priced at $40/month" — surfacing the actual current price
  BEFORE any direct read confirmed it, which is why this report corrects
  the task's stated "$50" baseline below.

## Current Stripe architecture (before this message)

- `WorkspaceBilling` (one row per workspace): `plan` (free/pro/team),
  `status` (mirrors Stripe subscription status), `stripe_customer_id`,
  `stripe_subscription_id`, `stripe_price_id`, period boundaries,
  `cancel_at_period_end`, `trial_end`.
- `StripeWebhookEvent`: `(event_id UNIQUE, event_type, processed_at)` —
  Stripe-only webhook idempotency (M59.4).
- `billing_service.py`: `PLAN_LIMITS` dict (single source of truth for
  limits + legacy flat pricing), `get_or_create_billing`,
  `assert_can_create_integration`/`assert_can_add_member`,
  `create_checkout_session`/`create_portal_session` (raw `httpx` calls to
  the Stripe REST API — no Stripe SDK dependency), `verify_stripe_signature`
  (manual HMAC-SHA256), `handle_webhook_event` (dispatches 5 event types,
  with idempotency check-then-record).
- `app/routers/billing.py`: `GET/POST /workspaces/{id}/billing[/checkout|/portal]`.
- `app/routers/stripe_webhook.py`: `POST /stripe/webhook` (public, HMAC-verified).
- **Actual current Team price: $40/month flat** (M58.25 "early-access
  pricing"), **not $50** as the task's baseline stated — there is no
  `$50`/`5000`-cents reference anywhere in this codebase. The new
  $30-base + $5/seat formula replaces this $40 flat price.

## Full Stripe coupling inventory

See `commercial_infrastructure_stripe_inventory.md` — every backend,
frontend, migration, test, and deployment reference, with the
provider-neutral replacement abstraction and M1/M2 action for each.

## Provider-neutral architecture (new, this message)

New package `backend/app/billing/`:

| Module | Responsibility |
|---|---|
| `enums.py` | `BillingProvider`, `BillingInterval`, `PlanId`, `ObjectType`, `NormalizedSubscriptionStatus`, `WebhookEventType`, `WebhookProcessingStatus`, `WebhookErrorCategory`, `DesiredSubscriptionReason`, `BillingAuditEventType` — bounded enums, never ad hoc strings. |
| `pricing.py` | `calculate_team_monthly_price()` — the pure, deterministic Team pricing function. |
| `billable_seats.py` | `calculate_billable_member_count()` — the canonical billable-member definition. |
| `plans.py` | Provider-neutral `Plan`/`EntitlementBundle` for `free`/`team`, copied unchanged from existing `PLAN_LIMITS` except Team's pricing strategy. |
| `entitlements.py` | `NormalizedSubscriptionStatus` mapping + `decide_entitlements()` — feature gates read only this, never a raw provider status string. |
| `provider.py` | `BillingProviderAdapter` ABC + provider-neutral request/response dataclasses (never a Stripe SDK type). |
| `registry.py` | `get_billing_provider()` — fail-closed provider selection. |
| `models.py` | 4 new SQLAlchemy tables (additive). |
| `events.py` | `normalize_stripe_event()` — Stripe → provider-neutral webhook event. |
| `idempotency.py` | `(provider, external_event_id)` idempotency + stale-event detection. |
| `audit.py` | Append-only, allowlist-filtered billing audit log. |
| `desired_state.py` | `DesiredSubscriptionState` — desired-state calculation only, never calls a provider. |
| `adapters/stripe.py` | `StripeBillingAdapter` — wraps existing Stripe flows, isolation not rewrite. |
| `adapters/paddle.py` | `PaddleBillingAdapter` — contract only, typed `not_configured`/`unsupported_before_m2` states, zero live calls. |

## Paddle target architecture

Paddle is selected (business decision, not re-litigated). Planned
representation (message 2+): ONE Team base recurring item (quantity 1,
`PADDLE_BASE_PRICE_ID`) + ONE additional-seat recurring item (quantity
`max(0, seats - 20)`, `PADDLE_ADDITIONAL_SEAT_PRICE_ID`) — never one
external price per team size. `PaddleBillingAdapter` implements the exact
same `BillingProviderAdapter` interface as Stripe; every operation
currently raises `PaddleNotConfiguredError` (no price mapping) or
`PaddleUnsupportedBeforeM2Error` (mapping present, no live call
implemented) — never a silent Stripe fallback.

## Team pricing formula

```
monthly_total_cents = 3000 + max(0, billable_member_count - 20) * 500
```

$30 is the flat base for up to 20 billable members — never a per-member
price. Only members strictly above 20 add $5/month each. Always returns
integer minor units.

## Zero-member decision

A workspace can never actually reach 0 billable members: every workspace
requires exactly one owner (`Workspace.created_by_user_id` non-nullable +
owner `WorkspaceMember` created at workspace creation), so 0 billable
members is an invalid workspace-domain state, never a real commercial
state. `calculate_billable_member_count()` raises `WorkspaceHasNoOwnerError`
rather than ever returning 0 for a real workspace.
`calculate_team_monthly_price(0)` still returns the $30 base defensively —
the pricing function itself must never produce a free/negative Team price
even under a hypothetical transient bad input.

## Billable-member definition

Audited `app/models/workspace.py`: only owner/admin/member roles exist;
`WorkspaceMember` rows are hard-deleted on removal (no
deactivated/suspended state exists in this codebase);
`WorkspaceInvite` is a separate table, never counted until acceptance
creates a real `WorkspaceMember` row; no service-account/API-identity
concept exists. Canonical definition:

```
Billable = every real WorkspaceMember row (owner, admin, member alike)
Not billable = pending WorkspaceInvite rows
```

This exactly matches what `billing_service.get_workspace_usage` already
counts for member-limit enforcement — no new concept invented.

## Pricing examples

| Members | Total |
|---|---|
| 1 | $30 |
| 10 | $30 |
| 20 | $30 |
| 21 | $35 |
| 25 | $55 |
| 30 | $80 |
| 50 | $180 |

All 7 examples verified by `test_commercial_pricing.py::TestBoundaryValues`
and the full pricing matrix report.

## Database changes

One additive migration (`alembic/versions/036_commercial_infrastructure_billing.py`,
`mig036`, `down_revision=mig035`): 4 new tables
(`billing_provider_references`, `commercial_subscriptions`,
`commercial_webhook_events`, `commercial_audit_events`). Zero columns
renamed, dropped, or backfilled on `workspace_billing` /
`stripe_webhook_events`. Verified: upgrade → downgrade → re-upgrade all
clean; all 13 pre-existing `workspace_billing` columns confirmed present
and unchanged after the full migration cycle.

## Provider-reference model

`BillingProviderReference(provider, object_type, external_id, workspace_id,
metadata, created_at, updated_at)` — unique on `(provider, object_type,
external_id)`. External IDs are never treated as application authority,
only as a lookup key back to the provider.

## Subscription aggregate

`NormalizedSubscription` (`commercial_subscriptions` table): one row per
workspace's current commercial state — plan, interval, normalized status,
billable seats, base/additional quantities, period boundaries,
cancel-at-period-end, grace-period end, last provider event, `version`
(for future optimistic-concurrency / stale-event protection).

## Entitlement normalization

8 normalized statuses (trialing/active/past_due/grace_period/paused/
canceled/expired/incomplete). `normalize_stripe_status()` is the ONLY
place a raw Stripe status string is translated. `decide_entitlements()`
returns `EntitlementDecision` (paid access, plan, limits, grace-period
end, management availability, reason, source provider, last-sync time) —
feature gates never inspect a provider status string directly.

## Webhook event / idempotency model

`BillingWebhookEvent` (`commercial_webhook_events` table): unique on
`(provider, external_event_id)` — additive alongside the existing
`StripeWebhookEvent` table (left untouched). Raw payloads are never
persisted — only a small, allowlisted `normalized_payload` summary.
`is_stale_subscription_update()` compares event `occurred_at` against the
stored subscription's `updated_at` to reject out-of-order/replayed events.
9 normalized event types (`subscription_created/updated/canceled/paused/
resumed`, `transaction_completed/failed`, `payment_past_due`,
`customer_updated`).

## Stripe compatibility behavior

`StripeBillingAdapter` wraps (never rewrites) `create_checkout_session`,
`create_portal_session`, `verify_stripe_signature` — all pinned functional
by `test_commercial_stripe_adapter.py` with zero real Stripe HTTP calls
(mocked `_stripe_post`). Cancellation remains portal-only (documented
existing product behavior, not invented). Seat-quantity updates are
explicitly `unsupported_before_m2` — the existing flow has no per-seat
Stripe pricing to update.

## Paddle adapter contract

See "Paddle target architecture" above. Zero live Paddle calls anywhere in
this message — verified by `test_commercial_paddle_contract.py` (every
operation either raises a typed exception or returns a typed
`ProviderOperationResult`, never a real API response).

## Stale $50 references removed

There were none to remove ($40 was the real flat price) — but the STALE
concept (a flat, non-seat-based Team price) was removed from the frontend:
`PLAN_META.team.monthlyPriceUsd` changed from `"$40"` to `"$30"` with new
formula copy ("Includes up to 20 members. +$5/month for each additional
member."), and a dynamic per-workspace pricing breakdown is now fetched
from the new `GET /workspaces/{id}/billing/pricing-preview` endpoint.
`test_commercial_stale_team_price.py` proves no stale flat-$40/$50
reference remains in the billing page, while allowlisting the legacy
compatibility value in `billing_service.py` (which intentionally keeps
driving the UNCHANGED existing Stripe checkout flow).

## Frontend pricing changes

- `frontend/src/lib/api.ts`: new `getTeamPricingPreview()` +
  `TeamPricingBreakdown` type.
- `frontend/src/app/(app)/settings/workspace/billing/page.tsx`:
  `PLAN_META.team` updated; new dynamic breakdown panel (billable members,
  included seats, additional seats, base/additional amounts, estimated
  total) rendered for Team-plan workspaces, sourced entirely from the
  backend preview endpoint — never recomputed client-side.

## Deployment inventory

See `commercial_infrastructure_deployment_inventory.md`. Exact planned
variables:

- **Render (backend)**: `BILLING_PROVIDER`, `PADDLE_ENVIRONMENT`,
  `PADDLE_API_KEY`, `PADDLE_WEBHOOK_SECRET`, `PADDLE_BASE_PRICE_ID`,
  `PADDLE_ADDITIONAL_SEAT_PRICE_ID`.
- **Vercel (frontend)**: `NEXT_PUBLIC_PADDLE_ENVIRONMENT`,
  `NEXT_PUBLIC_PADDLE_CLIENT_TOKEN`, and (if message 2's verified design
  needs it) `NEXT_PUBLIC_PADDLE_BASE_PRICE_ID`.

None of these are set in any hosted environment — only settings-schema
support and `.env.example` placeholders (empty values) were added this
message. No existing Vercel or Render value was read, changed, or removed.

## Sandbox/live separation and cutover sequence

See `commercial_infrastructure_paddle_cutover.md` — Phases A (account
readiness) through E (retirement), with an explicit rollback strategy
(`BILLING_PROVIDER=stripe`, a single config change, works at any point
before Phase E's secret removal since message 2+ is required to keep the
Stripe path functional through Phase E).

## Performance / determinism

Not separately budgeted this message (no CI/performance requirement in
this message's spec) — pricing calculation is O(1) and covered by a
201-value bounded-loop property test plus explicit boundary values.

## Tests

11 new test files, **182 tests, all passing**:

| File | Tests |
|---|---|
| `test_commercial_pricing.py` | 36 |
| `test_commercial_billable_seats.py` | 14 |
| `test_commercial_provider_registry.py` | 12 |
| `test_commercial_entitlements.py` | 32 |
| `test_commercial_webhook_events.py` | 17 |
| `test_commercial_webhook_idempotency.py` | 12 |
| `test_commercial_stripe_adapter.py` | 8 |
| `test_commercial_paddle_contract.py` | 18 |
| `test_commercial_deployment_config.py` | 12 |
| `test_commercial_stale_team_price.py` | 8 |
| `test_commercial_message1_reports.py` | 13 |

All 10 required narrow `-k` filters select non-zero, passing tests:
`commercial and pricing`, `commercial and billable_seats`,
`commercial and provider_registry`, `commercial and entitlements`,
`commercial and webhook`, `commercial and stripe_adapter`,
`commercial and paddle`, `commercial and deployment_config`,
`commercial and stale_team_price`, `commercial and reports`.

## Focused regressions

Existing Stripe billing, checkout, portal, webhook, workspace membership,
invitation, and entitlement/plan-limit tests re-run explicitly (exact
files, never a broad filter): `test_milestone52.py`,
`test_milestone58_25.py`, `test_milestone58_26.py`, `test_milestone59_2.py`,
`test_milestone59_3.py` — all pass unchanged, proving the existing Stripe
behavior remains equivalent (the intentional Team-price-DISPLAY change
excepted — `test_milestone58_25.py`'s $40 assertion is about the
UNCHANGED legacy compatibility value, not the new formula, and still
passes).

## Migration validation

`alembic upgrade head` → 4 new tables created; `alembic downgrade mig035`
→ all 4 removed cleanly; `alembic upgrade head` again → clean re-creation.
`workspace_billing`'s 13 pre-existing columns confirmed present and
unchanged throughout.

## Frontend validation

`npx tsc --noEmit` run (frontend files changed this message: `api.ts`,
`billing/page.tsx`).

## External calls made

**Zero external calls.** No Stripe API call, no Paddle API call, no Vercel API call, no
Render API call. All Stripe-adapter tests mock `_stripe_post`; the Paddle
adapter has no live-call code path to invoke.

## Dependencies added

**None.** No Paddle SDK — the adapter contract is expressed entirely with
stdlib `dataclasses`/`abc`, matching this repo's existing pattern of raw
`httpx` calls instead of provider SDKs.

## Message-2 recommendation

Implement the real Paddle sandbox integration per
`commercial_infrastructure_paddle_cutover.md` Phase B: create sandbox
Team base + additional-seat prices, wire `PaddleBillingAdapter`'s real API
calls, implement `POST /paddle/webhook`, and build the Paddle checkout UI
— all while leaving `BILLING_PROVIDER` defaulted to `stripe` in production
until Phase D.

## Safe to push?

Not applicable — pushing was not requested and is explicitly forbidden
this message regardless of gate status.

**Commercial Infrastructure message 1 is complete for its stated scope.**
Do not begin Commercial Infrastructure message 2. Do not push.
