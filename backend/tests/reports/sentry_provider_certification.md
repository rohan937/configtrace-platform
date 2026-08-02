# Sentry Provider Certification (Sentry Message 8 of 8 — Public Launch, FINAL Provider-Expansion Milestone)

Final launch certification for the Sentry provider — the last of the 8
planned Sentry implementation milestones, and the last planned
provider-expansion milestone overall. Moves Sentry from
internal/planned/non-connectable/non-Live to publicly visible,
connectable, credential-validated, partial-coverage-aware,
production-certified, Live.

## 1. Identity

| Field | Value |
|---|---|
| Canonical provider ID | `sentry` |
| Display name | Sentry |
| Category | `observability` (frontend `ProviderCategory`) |
| Public/Live status | Live — connectable, in `PROVIDER_IDS` and `CONNECTABLE_PROVIDER_IDS` (frontend), `PROVIDER_CAPABILITIES` not `PROVIDER_CAPABILITIES_PARTIAL` (backend) |
| Stable organization identity | `SentryConnector.compute_organization_id(raw_id)` → `id:<raw organization id>`, derived from Sentry's own immutable organization `id` field, never from the user-supplied `organization_slug` credential |

## 2. Authentication

- **Model**: Sentry organization auth token (organization-owned internal integration token recommended) presented as `Authorization: Bearer <token>` against the fixed `https://sentry.io` API origin. No personal token as preferred, no interactive OAuth, no username/password, no CLI, no DSN auth, no browser login is advertised or implemented.
- **Scope model** (confirmed docs.sentry.io/api/auth/, docs.sentry.io/organization/integrations/integration-platform/internal-integration/): internal integrations are organization-owned, support up to 20 tokens, never auto-expire, are manually revocable via Settings → Developer Settings — the basis for recommending an organization-owned internal integration token over a personal token, which is tied to an individual user and inherits that user's own permissions.
- **Confirmed token scopes used by this connector**: `org:read` (organization detail, projects, teams), `member:read` (org members), `alerts:read` (metric alert rules), `org:integrations` (integrations, repositories), `project:releases` (releases). No write scope is ever requested or required.
- **Regional hosts** (confirmed docs.sentry.io/organization/data-storage-location/): US region → `us.sentry.io`, EU/Frankfurt region → `de.sentry.io`; `sentry.io` alone serves non-region-specific account/org data. This launch keeps the connector's existing hardcoded `https://sentry.io` trusted origin unchanged — no multi-region support, no custom base URL, no arbitrary regional host — to avoid expanding SSRF surface. EU-region organizations are a known, explicitly documented limitation (see §16).
- **Deployment support**: Sentry SaaS (sentry.io) only. Self-hosted Sentry is explicitly out of scope and not implemented.

## 3. Credential fields

`sentry_organization_slug` / `sentry_auth_token` — exact existing schema field names (unchanged from message 1). Frontend labels: "Sentry Organization Slug", "Sentry Auth Token" (password input, masked, never redisplayed).

## 4. Least-privilege / setup guidance

Setup guide (form + trustNote + provider card) recommends: organization-owned internal integration token with read-only scopes, created via Settings → Developer Settings → New Internal Integration. Never recommends a personal access token. Core vs Extended coverage split (see `sentry_access_requirement_matrix.md`) is derived from the actual 7 probed capability families, not invented.

## 5. Credential validation

`SentryConnector.probe_coverage()` (new this message) runs exactly two bounded things: the organization-detail request (`GET /organizations/{slug}/`, message 1) and the 7 bounded capability probes (message 1's `_CAPABILITY_PROBES`) — never a full organization inventory. Computes `COVERAGE_FULL` / `COVERAGE_PARTIAL` / `COVERAGE_INVALID` via `compute_coverage_state()` (new `sentry_schema.py` helper): Invalid only when zero of the 3 Core families (`projects`, `teams`, `members`) are readable; Full when all 7 probed families are readable; Partial otherwise. Returns sanitized grouped diagnostics via `format_capability_diagnostics()` — 6 human-readable groups, never a raw request URL or low-level status code.

`_create_sentry_integration()` calls `probe_coverage()` synchronously before any DB write; `COVERAGE_INVALID` raises `ConnectorError` and the router returns 400 — no seemingly-healthy integration is ever created from rejected/insufficient credentials. `reconnect_credentials_sentry()` follows the identical pattern.

## 6. Full / Partial / Invalid semantics

- **Full**: all 7 probed capability families available (`projects`, `teams`, `members`, `metric_alerts`, `integrations`, `repositories`, `releases`).
- **Partial**: all 3 Core families (`projects`, `teams`, `members`) available but at least one Extended family (`metric_alerts`, `integrations`, `repositories`, `releases`) is denied — a narrowly-scoped token legitimately may lack `alerts:read`/`org:integrations`/`project:releases`. Accepted; useful monitoring still results.
- **Invalid**: zero Core families are readable, OR the organization-detail request itself fails (malformed slug, rejected/revoked token, unreachable organization). Rejected at creation/reconnect with a sanitized message.

Certified via `test_sentry_integration_creation.py` (`TestValidConnection`, `TestPartialConnection`, `TestInvalidConnection`, `TestExtendedFamilyDeniedNotInvalid`) and `test_sentry_provider_depth_qa.py` §F.

## 7. Capability diagnostics

Grouped into 6 safe labels (`Projects and teams`, `Members and access`, `Alert rules`, `Integrations`, `Repositories`, `Releases`), each `Available` / `Permission denied` / `Unavailable` — never the 7 individual low-level probe request paths.

## 8. Reconnect behavior

`reconnect_credentials_sentry()` (new this message, mirrors `reconnect_credentials_snowflake`/`reconnect_credentials_okta`):
- Same organization + new token → accepted (after `probe_coverage()` re-validation).
- Same organization (same stable `organization_id`) + renamed slug → accepted — comparison uses the STABLE `organization_id` derived from Sentry's own immutable organization `id`, never the raw `organization_slug` credential, so a legitimate rename never falsely mismatches.
- Different organization (`existing_organization_id != new_organization_id`) → rejected with `ConnectorError`, directing the user to create a new integration instead.
- Invalid/revoked token → rejected via the same `probe_coverage()` → `COVERAGE_INVALID` path, sanitized error, no credential material echoed.
- Partial permissions → accepted; diagnostics updated in `resource_metadata`.
- Old token is fully overwritten (never retained alongside the new one) — a fresh `SentryConnector()`/`httpx.Client` is built from only the new credentials each time, so no prior session/organization/capability/cache state leaks forward.
- Reconnect works before any sync has ever run (no dependency on prior sync-run state); it never creates a `SyncRun` row itself.

Certified via `test_sentry_integration_creation.py::TestReconnect` (11 cases), `test_sentry_reconnect.py` (11 focused cases: organization-identity mismatch, no-state-reuse, token-rotation identity, reconnect-before-first-sync), and `test_sentry_provider_depth_qa.py::TestCredentialRoundTrip`.

## 9. Organization mismatch / slug-rename / rotation protection

Because `SentryConnector.compute_organization_id()` derives identity purely from Sentry's own immutable organization `id` — never the raw `organization_slug` string — a reconnect after a legitimate organization rename (same underlying organization, new slug) is compared on the STABLE derived value and is never falsely rejected. A genuinely different underlying organization always produces a different `organization_id` and is always rejected, even if it happens to reuse the same slug string. Sentry's `probe_coverage()` establishes the real `organization_id` synchronously at creation time (message 8), so there is no "pre-first-sync placeholder" ambiguity window for Sentry reconnects.

## 10. Initial baseline / partial baseline

First-sync behavior (message 7's false-removal suppression architecture, re-verified unaffected this message): a first sync with no prior state produces only additions, never fabricated historical Changes (`TestFirstSyncBehavior` in `test_sentry_partial_sync.py`). A partial first sync (e.g. `integrations`/`repositories`/`releases` denied while `projects`/`teams`/`members` succeed) is accepted as Partial; readable families baseline normally, unavailable families are marked incomplete via `family_completeness`/per-team/per-project completeness fields (message 7), and later permission expansion or reduction never produces false removals or mass deletions.

## 11. Frontend

- **Provider card**: `/integrations` — status Live, concise copy covering organization access/projects/teams/members/alert routing/integrations/repositories/release configuration/effective access; explicitly does not advertise issue/event ingestion, stack traces, breadcrumbs, session replay, performance spans, profiles, DSNs, source code, commit content, or release/deployment history.
- **Setup form**: `SentryIntegrationForm.tsx` (new) — 2 fields (organization slug, auth token), token masked (`type="password"`), never redisplayed after success, no localStorage, no token in URL, setup guidance (4-step internal-integration flow), least-privilege warning recommending an organization-owned internal integration token over a personal token, Core/Extended scope guidance, Partial-coverage explanation, SaaS-only statement.
- **Reconnect**: `ReconnectIntegrationModal.tsx` extended with a `sentry_auth_token` field mapping (previously the modal only special-cased Cloudflare/Vercel/GitHub and would have silently sent the wrong payload key for Sentry).
- **Integration detail**: safe context only (organization slug/name, stable organization identifier, last sync, sync status, Full/Partial coverage, monitored record/Finding/Change counts, grouped diagnostics) — never auth token, Authorization header, raw request URL, DSN, email, webhook URL, repository credential, raw ownership text, or event payload (unchanged architecture — the generic integration-detail surface already enforces this for every provider).

## 12. Record count / Finding count

- **18 record types** (unchanged since message 5): `sentry_organization`, `sentry_api_capability`, `sentry_project`, `sentry_team`, `sentry_member`, `sentry_team_membership`, `sentry_project_team_assignment`, `sentry_metric_alert_rule`, `sentry_metric_alert_trigger`, `sentry_issue_alert_rule`, `sentry_alert_action`, `sentry_organization_integration`, `sentry_repository`, `sentry_code_mapping`, `sentry_ownership_rule`, `sentry_privileged_member`, `sentry_privileged_team`, `sentry_routing_context` — all 18 tracked in `diff_service.py`, all 18 classified in `risk_rules/sentry.py` (re-verified this message via `test_sentry_provider_depth_qa.py::TestRecordTypeInventory`).
- **20 Security Findings** (unchanged since message 6): full registry/evaluator/confidence/pack/coverage/frontend-catalog parity re-verified this message (`TestSecurityFindingParity`, 4 cases).

## 13. Reliability re-certification

No connector fetch()/collection/diff/classifier code was modified this message — message 7's reliability certification (63 change-classification tests, 26 parity tests, 19 partial-sync tests, 16 HTTP-reliability tests, 4 scale-reliability tests; 174-row change-classification matrix; 260-row reliability matrix) remains valid unchanged. This message only adds: `probe_coverage()` (a thin wrapper reusing the exact same organization-identity request + `_probe_capabilities()` primitives already certified), the `compute_coverage_state()`/`format_capability_diagnostics()` pure functions, and the creation/reconnect service-layer wiring.

## 14. Sensitive-data / CLI-independence / dependency audit

- **Auth token never persisted** outside encrypted credential storage: never in normalized snapshot, provider metadata, Finding, Change, diagnostic output, frontend response, logs, or reports — re-verified via `test_sentry_provider_depth_qa.py` §D and `test_sentry_integration_creation.py::TestSensitiveCredentialsNeverLeak` (3 cases: create response, get response, encrypted-column-is-not-plaintext).
- **No mutating HTTP call is ever constructed**: verified by grepping for `client.post(`/`client.put(`/`client.patch(`/`client.delete(` in `sentry.py` and finding none — the connector only ever issues `GET` requests.
- **No CLI/subprocess dependency**: no `subprocess`, `os.system`, `Popen`, `shell=True` anywhere in the connector.
- **No Sentry SDK / telemetry coupling**: the connector never imports `sentry_sdk`, never calls `sentry_sdk.init()`, and never reads the global `SENTRY_DSN`/`SENTRY_AUTH_TOKEN` environment variables used by ConfigTrace's own operational telemetry — customer credentials are read exclusively from the per-integration encrypted credential store, fully separate from ConfigTrace's own Sentry SDK configuration (if any). Reconnect never mutates any global SDK state.
- **Production dependencies unchanged**: `httpx` only — no `sentry-sdk` package, no Sentry CLI, no browser automation, no new OS package, no new global env var for customer connections.

## 15. Database / deployment audit

Integration credential/resource storage (`encrypted_credentials`, `credential_iv`, `resource_metadata` JSON column) is the same generic, already-migrated schema every other provider uses. `Integration.provider` is stored as free-form `text`, not a constrained enum/CHECK — adding `"sentry"` as a value required no migration. No new column, no new enum, no `CHECK` constraint was required for this message's `resource_metadata` additions (`organization_id`, `coverage`, `diagnostics` are just new JSON keys within the existing free-form column).

## 16. Known limitations (explicit, launch-critical to state)

Sentry SaaS (sentry.io) only — no self-hosted Sentry, no custom base URL, no arbitrary regional host (EU/`de.sentry.io` organizations are not supported — the connector's trusted origin is hardcoded to `https://sentry.io`). No issue or event ingestion of any kind — no stack traces, no breadcrumbs, no session replay, no performance spans/profiles, no DSNs, no source code, no commit content, no release/deployment history ingestion. Webhook delivery-content ingestion is deferred (Sentry's webhook-configuration detail lives behind a private/undocumented API not part of the public REST API surface this connector uses). Release-threshold configuration ingestion is deferred (experimental API). Sentry App installation posture (distinct from internal-integration tokens) is deferred. Ownership-rule resolution is limited to the rules Sentry's public `ownership/` endpoint returns as text, not a fully resolved per-file owner graph. Effective-access derivation depends on Sentry's own public role/team-membership semantics as returned by the API — it is not an independent privilege model. Some families (`metric_alerts`, `integrations`, `repositories`, `releases`) may remain Partial indefinitely for an intentionally narrow-scoped monitoring token — this is expected, not a defect.

## 17. Certification

| Gate | Result |
|---|---|
| Provider identity (ID/label/category consistent backend+frontend) | PASS |
| Authentication model matches current docs, no unimplemented modes advertised | PASS |
| Credential fields match existing schema exactly | PASS |
| Least-privilege guidance recommends internal integration token, never a personal token | PASS |
| Access-requirement matrix (30+ rows) covers every real connector endpoint, no write scopes listed | PASS |
| Synchronous credential validation before persistence (`probe_coverage`) | PASS |
| Full/Partial/Invalid semantics correct, no over-rejection on Extended-family denial | PASS |
| Capability diagnostics grouped and safe | PASS |
| Reconnect: same-organization rotation accepted, renamed-slug accepted, different-organization rejected, old token never reused | PASS |
| Initial/partial baseline: no fabricated history, no false removals | PASS |
| Frontend card/form/reconnect-modal/setup/SaaS-only wording | PASS |
| 18 record types / 20 Findings unchanged and re-verified | PASS |
| Message-7 reliability certification still valid (no fetch/diff/classifier code touched) | PASS |
| Sensitive-data / CLI-independence / telemetry-separation / dependency audit | PASS |
| Database migration audit (none required) | PASS |
| Full Sentry test suite passing | PASS |
| Cross-provider regression | PASS |
| Frontend TypeScript (`tsc --noEmit`) | PASS |

**CERTIFICATION: PASS.**

## 18. Documentation verification log (topics researched this message and message 1)

1. Auth tokens — [Auth Tokens](https://docs.sentry.io/api/auth/) — confirmed `Authorization: Bearer <token>` header format.
2. Internal integrations — [Internal Integrations](https://docs.sentry.io/organization/integrations/integration-platform/internal-integration/) — confirmed organization-owned, up to 20 tokens, never auto-expire, manually revocable — basis for the "recommend organization-owned integration token over personal token" guidance.
3. Scopes — confirmed `org:read`, `member:read`, `alerts:read`, `org:integrations`, `project:releases` cover every endpoint this connector calls; no write scope is ever required.
4. Regional data storage — [Data Storage Location](https://docs.sentry.io/organization/data-storage-location/) — confirmed US (`us.sentry.io`) vs EU/Frankfurt (`de.sentry.io`) region hosts; `sentry.io` serves non-region-specific account data. Decision: no multi-region support added this launch (documented limitation, §16) to avoid expanding SSRF surface.
5. Rate limits — general API rate-limit behavior confirmed via `429`/`Retry-After` handling already certified in message 7's HTTP-reliability suite; unchanged this message.

**Sentry provider expansion is complete. Provider expansion is now frozen. Do not begin another provider.**
