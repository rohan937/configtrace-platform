# Commercial Infrastructure — Deployment Configuration Inventory (message 1)

No hosted environment (Vercel, Render) was modified by this message. This
report documents CURRENT configuration and PLANNED (not-yet-deployed)
Paddle configuration, with no real secret values anywhere in this document
or in the repository.

## Local `.env.example` (repo root)

Added this message — placeholders only, all values empty:

```
BILLING_PROVIDER=stripe

PADDLE_ENVIRONMENT=
PADDLE_API_KEY=
PADDLE_WEBHOOK_SECRET=
PADDLE_BASE_PRICE_ID=
PADDLE_ADDITIONAL_SEAT_PRICE_ID=
```

Existing (already present in `app/config.py`, now also documented in
`.env.example` for completeness — no values):

```
STRIPE_SECRET_KEY=
STRIPE_WEBHOOK_SECRET=
STRIPE_PRICE_PRO_MONTHLY=
STRIPE_PRICE_TEAM_MONTHLY=
```

## Backend / Render (current — Stripe)

| Variable | Purpose | Secret? |
|---|---|---|
| `STRIPE_SECRET_KEY` | Stripe API auth (checkout/portal session creation) | Yes |
| `STRIPE_WEBHOOK_SECRET` | Stripe webhook HMAC signature verification | Yes |
| `STRIPE_PRICE_PRO_MONTHLY` (+ 2 aliases) | Stripe Price ID for Pro plan | No (opaque ID) |
| `STRIPE_PRICE_TEAM_MONTHLY` (+ 2 aliases) | Stripe Price ID for Team plan | No (opaque ID) |
| `FRONTEND_URL` | Builds Stripe Checkout success/cancel URLs | No |

No Stripe Billing Portal configuration is stored as an env var — portal
behavior (allowed actions) is configured directly in the Stripe Dashboard
per `billing_service.create_portal_session`'s docstring.

## Backend / Render (planned — Paddle, message 2+)

Not present in any hosted Render environment as of this message. Names
decided from this repository's existing `STRIPE_*` naming convention:

| Variable | Purpose | Secret? |
|---|---|---|
| `BILLING_PROVIDER` | Selects active adapter: `stripe` \| `paddle` | No |
| `PADDLE_ENVIRONMENT` | `sandbox` \| `live` | No |
| `PADDLE_API_KEY` | Paddle API auth | Yes |
| `PADDLE_WEBHOOK_SECRET` | Paddle webhook/notification signature verification | Yes |
| `PADDLE_BASE_PRICE_ID` | Paddle recurring price ID for the Team base ($30/mo, ≤20 seats) item | No (opaque ID) |
| `PADDLE_ADDITIONAL_SEAT_PRICE_ID` | Paddle recurring price ID for the Team additional-seat ($5/mo) item | No (opaque ID) |

## Frontend / Vercel (current — Stripe)

| Variable | Purpose | Secret? |
|---|---|---|
| `NEXT_PUBLIC_STRIPE_PRICE_PRO_MONTHLY` | Client-side Pro price ID sent to `/billing/checkout` | No (public, client-safe by design) |
| `NEXT_PUBLIC_STRIPE_PRICE_TEAM_MONTHLY` | Client-side Team price ID sent to `/billing/checkout` | No |
| `NEXT_PUBLIC_BILLING_CHECKOUT_DISABLED` | Emergency kill-switch for checkout (unrelated to provider choice) | No |
| `NEXT_PUBLIC_API_BASE_URL` | Backend base URL | No |

## Frontend / Vercel (planned — Paddle, message 2+)

Not present in any hosted Vercel environment as of this message:

| Variable | Purpose | Secret? |
|---|---|---|
| `NEXT_PUBLIC_PADDLE_ENVIRONMENT` | `sandbox` \| `live`, controls Paddle.js initialization mode | No |
| `NEXT_PUBLIC_PADDLE_CLIENT_TOKEN` | Paddle client-side token (frontend-safe by Paddle's own design — analogous to a Stripe publishable key) | No (public by design, but still Paddle-issued and revocable) |
| `NEXT_PUBLIC_PADDLE_BASE_PRICE_ID` | Public base price identifier, only if the verified message-2 frontend checkout design requires client-side price selection (mirrors the existing `NEXT_PUBLIC_STRIPE_PRICE_*` pattern) | No |

No Paddle secret (`PADDLE_API_KEY`, `PADDLE_WEBHOOK_SECRET`) is ever
planned for a `NEXT_PUBLIC_` variable — those remain backend/Render only,
enforced by `test_commercial_deployment_config.py::TestPaddleSecretsBackendOnly`.

## GitHub Actions

No billing-related secret or variable is used in `.github/workflows/`
(confirmed: only the provider-certification workflow exists, message 7).
No change made or planned for CI billing configuration in message 1.

## Docker Compose / local development

No `STRIPE_*` or `PADDLE_*` variable is declared in `docker-compose.yml`
today; local development reads them from `.env` via `app/config.py`'s
`env_file=".env"`. No change made this message.

## Staging / production separation

ConfigTrace currently has a single Render backend service and does not
maintain a separate "staging" Render service distinct from production, per
`render.yaml`. Sandbox-vs-live separation for Paddle is therefore governed
entirely by `PADDLE_ENVIRONMENT` + which set of Paddle credentials
(sandbox vs. live) is loaded into the single production Render service —
see the cutover sequence in
`commercial_infrastructure_paddle_cutover.md` Phase B/C for how this is
staged safely without a dedicated staging environment.
