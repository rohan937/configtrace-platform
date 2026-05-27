# Edge / DDoS Hardening Recommendations (M59.4)

This note records what is handled in **app code** versus what must be
handled at the **edge / platform layer** (Cloudflare + Render).  M59.4
implemented every protection that fits cleanly inside the FastAPI
application; everything below is a recommendation for the deployment
configuration.

## What the app currently handles (M59.1 – M59.4)

| Threat | App-layer control |
|---|---|
| Cross-workspace data access (IDOR / confused-deputy) | `workspace_service.require_role`, `_require_membership`, `get_integration_for_*`, `_get_change_and_workspace`, `iac_repository.workspace_id` double-key filters (M59.1) |
| Secret leakage in responses / logs / snapshots / risk reasons | AES-256-GCM at rest; `_mask_url`; response schemas omit credential fields; `_FORBIDDEN_CRED_FIELDS` static audits (M59.2) |
| Webhook authenticity | Stripe HMAC on raw body + 5-min timestamp window; Slack HMAC + 5-min replay window; GitHub App HMAC state bound to `user_id` (M59.3) |
| Dangerous-action gating | PR-creation 10-gate flow (exact phrase, admin role, repo↔workspace, IaC confidence, safe paths, draft-only) (M59.3) |
| Webhook URL SSRF (literal IP + DNS rebinding) | `_validate_url` + `_assert_hostname_resolves_public` against `_PRIVATE_NETWORKS` and `is_loopback/link_local/multicast/reserved/private` (M59.4) |
| Stripe webhook replay / Stripe retry duplication | `stripe_webhook_events` table with unique `event_id`; `handle_webhook_event` short-circuits duplicates (M59.4) |
| Manual sync spam | `POST /syncs` calls `has_in_flight_sync` and returns 409 (M59.4) |
| Test-notification spam | Workspace-wide 60-second cooldown shared across the four `/test` endpoints (M59.4) |

## What must be handled at the edge / platform (Cloudflare + Render)

App code cannot prevent volumetric DDoS, distributed credential-stuffing,
TLS-layer attacks, or large-scale scraping.  These belong at the edge:

### Cloudflare (recommended in front of `app.configtrace.org` and `api.configtrace.org`)

* **Proxy enabled** (orange-cloud) on the apex and `api.` records so
  Cloudflare terminates TLS and absorbs L3/L4 floods.
* **Managed WAF rule sets** active: OWASP Core, Cloudflare Specials,
  Bot Management (if licensed).
* **Rate-limit rules**:
  * `/stripe/webhook` — allow Stripe's published egress range (or skip
    the rule for those IPs); rate-limit all other sources to ~5 req/min
    so a misconfigured client cannot churn invalid signatures.
  * `/slack/oauth/callback` and `/slack/actions` — ~30 req/min per IP.
  * Authenticated API mutation routes (`POST /workspaces/{id}/billing/*`,
    `POST /changes/{id}/github-pr`, `POST /workspaces/{id}/iac/*/scan`,
    `POST /syncs`) — ~60 req/min per Clerk-user header.
  * Test-notification endpoints — already cooled at app layer; an edge
    rule at ~5 req/min per workspace provides defense-in-depth against
    distributed admin-credential abuse.
* **Cache rules**: `/health`, static assets, `/openapi.json`, `/docs`
  cached for 60 s.
* **Origin lockdown**: Cloudflare-only Authenticated Origin Pulls on
  Render so the origin only accepts requests from Cloudflare.
* **Bot challenge**: Managed Challenge for `/api/*` except known
  webhook source IPs (Stripe, Slack, GitHub).

### Render (or platform equivalent)

* **Auto-scaling** with a sane max instance count to prevent runaway
  cost on a successful flood.
* **Concurrent request limit** per instance so a single slow client
  cannot exhaust uvicorn worker slots.
* **Health-check timeout** generous enough that a transient cold start
  does not trigger redeploys during traffic spikes.

## Known limitations

* DNS-rebinding protection in `_validate_url` runs once at URL save time;
  a hostname that mutates its DNS records *after* validation is not
  re-checked at delivery time.  Acceptable tradeoff because the
  delivery still goes over HTTPS and the resolver re-checks happen on
  every connection.
* Webhook event-id dedupe is per-database (one Stripe customer ID across
  multiple Render environments would not share the dedupe table).
  Acceptable for the single-environment deployment ConfigTrace
  currently targets.
* Test-notification cooldown is per-workspace shared across channels
  (Slack / push / webhook / digest).  Channel-granular cooldown is a
  future enhancement if abuse patterns warrant it.

---

*Generated alongside the M59.4 implementation.  See `tests/test_milestone59_4.py`
and `tests/test_milestone59_3.py::TestDocumentedGaps` for the pinned
behavior of each control.*
