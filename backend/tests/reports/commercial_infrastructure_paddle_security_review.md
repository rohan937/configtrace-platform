# Commercial Infrastructure — Paddle Security Review (message 2)

## Secrets boundary

| Secret | Location | Never appears in |
|---|---|---|
| `PADDLE_API_KEY` | Render (backend) only | Frontend bundle, logs, API responses, error messages, this report |
| `PADDLE_WEBHOOK_SECRET` | Render (backend) only | Frontend bundle, logs, API responses, error messages, this report |
| `NEXT_PUBLIC_PADDLE_CLIENT_TOKEN` | Vercel (frontend), public by Paddle's own design | N/A — intentionally public, analogous to a Stripe publishable key |

Verified: `app/billing/paddle_client.py`'s `_raise_for_status` never includes
the API key in any raised exception (`test_commercial_paddle_client.py::TestSanitizedErrors`).
`app/billing/paddle_config.py::validate_paddle_configuration` never
includes a secret VALUE in an issue message (`test_commercial_paddle_readiness.py::TestNoSecretInValidationErrors`).
`app/billing/readiness.py::check_production_readiness` reports
presence/absence only (`test_commercial_paddle_readiness.py::TestProductionReadinessReport::test_report_never_includes_secret_value`).

## Webhook body handling

- The raw request body is read via `await request.body()` in
  `app/routers/paddle_webhook.py` BEFORE any JSON parsing — signature
  verification always operates on the exact bytes Paddle sent, never a
  re-serialized representation (proven byte-exact by
  `test_commercial_paddle_signature.py::TestExactRawBodyPreservation`).
- The raw body is never logged — only `event.get("type")`/`event_type`
  (an enum-bounded string) appears in any log statement in
  `paddle_webhook.py` or `paddle_webhook_service.py`.
- `BillingWebhookEvent.normalized_payload` stores only an allowlisted
  summary (`raw_event_name`, `status`) — never the full Paddle payload
  (`app/billing/paddle_webhooks.py::normalize_paddle_event`).

## Signature verification

- Constant-time comparison via `hmac.compare_digest` for every candidate
  `h1` value (secret-rotation-safe: multiple signatures are supported,
  any match succeeds).
- Timestamp tolerance (default 300s, matching the existing Stripe
  tolerance) rejects stale or future-dated deliveries.
- Missing header, malformed header, non-integer timestamp, wrong secret,
  and modified body are all rejected — see
  `test_commercial_paddle_signature.py` (19 tests).

## Management URL host validation

`app/billing/adapters/paddle.py::_validate_management_url` rejects any
Paddle-returned management URL whose host is not
`customer-portal.paddle.com` or `sandbox-customer-portal.paddle.com` —
defense-in-depth against ever redirecting a user to an unexpected domain
even if a future Paddle API response shape changes unexpectedly
(`test_commercial_paddle_management.py::TestUrlHostValidation`).

## No arbitrary client-submitted pricing

`POST /workspaces/{id}/billing/checkout/team` (the only Paddle checkout
route) computes `plan_id`, `billing_interval`, and `billable_seat_count`
entirely server-side from `calculate_billable_member_count` — the
request body accepts NO client-submitted price ID, plan, or seat count.
Success/cancel URLs are built from `settings.effective_frontend_url`
only, never from client input, closing off open-redirect risk.

## Authorization

Every new provider-neutral billing route (`checkout/team`, `subscription`,
`management`, `cancel`, `reconcile`) calls `_require_admin` first — the
same admin/owner-role check every existing billing route already used
(`app/routers/billing.py::_require_admin`, unchanged).

## No production side effects from offline tests

Every backend billing test in this message mocks Paddle HTTP via
`httpx.MockTransport` — zero real network calls. The one module that DOES
make a real call (`app/billing/catalog_verification.py::verify_catalog`)
is invoked ONLY from `test_commercial_paddle_sandbox_optional.py`, which
is skipped by default and requires `RUN_PADDLE_SANDBOX_TESTS=1` plus real
sandbox credentials.

## Known limitation, stated honestly

The signature-verification scheme in `app/billing/paddle_webhooks.py` is
implemented from Paddle's publicly documented webhook signing scheme as
of this message's authoring. It has NOT been verified against a real,
live Paddle sandbox webhook delivery in this message (no sandbox
credentials were available) — see
`test_commercial_paddle_sandbox_optional.py::TestSandboxSignatureRoundTrip`
for the explicit, honest placeholder marking this as pending rather than
falsely claiming it as verified.
