# Okta Provider Certification (Message 8 of 8 — Public Launch)

This is the final certification report for the Okta provider expansion arc
(messages 1-8). It certifies Okta as a publicly visible, connectable,
production-certified ConfigTrace provider.

## 1. Provider identity

| Field | Value |
|---|---|
| Provider ID | `okta` |
| Display name | `Okta` |
| Category | `identity` (frontend) / `auth` (backend capability matrix) |
| Status | Live — in `PROVIDER_IDS` and `CONNECTABLE_PROVIDER_IDS` (frontend), in `PROVIDER_CAPABILITIES` (backend, not the partial list) |
| Capability-matrix maturity | `partial` (drift + Security Findings; no activity-ingestion stack — see §7) |

## 2. Authentication

- **Credential type**: Okta org base URL (`org_url`) + API token (`api_token`, SSWS scheme). No OAuth service-app mode (documented future enhancement), no separate token-scoping mechanism.
- **API-token permission model**: Okta classic API tokens inherit the exact permissions of the administrator account that generated them — there is no independent scoping mechanism the way OAuth service-app scopes provide. ConfigTrace never requests broader access than that account already has, and cannot see more than a least-privileged read-only admin role exposes. Guidance (setup guide, form, and card trustNote) explicitly tells users to generate the token from a dedicated account assigned the built-in **Read-Only Administrator** role (or a custom admin role with equivalent read access to Users, Groups, Applications, Authentication Policies, and Administrator Role assignments) — never to generate it from a Super Admin account unless no narrower role is available. This is the least-privileged built-in Okta role that can read all 12 monitored API families.
- **Validation**: `OktaConnector.validate_credentials()` calls the narrowest official endpoint, `GET /api/v1/org` (Okta's Org Setting API), which simultaneously proves the token is accepted and the org is reachable, without requiring any broader read permission. Called synchronously at integration-creation time (message 8 change — previously deferred to first sync, matching Kubernetes' message-9 precedent).
- **Full/Partial/Invalid semantics**:
  - **Invalid**: malformed `org_url`, 401 (token rejected), unreachable org, TLS failure — all raise before an integration row is written. Also: zero of the 12 monitored families readable at diagnostics time (`build_okta_permission_diagnostics()` reports `"invalid"`).
  - **Full**: every one of the 12 monitored API families reports `"complete"`.
  - **Partial**: the org is reachable and at least one family is readable, but one or more families is denied/unavailable/partially collected — e.g. a least-privileged (non-Super-Admin) role commonly cannot see custom admin roles. This is NOT rejected at creation time; it is a first-sync-time diagnostic only, matching Kubernetes' precedent of deferring full-family probing to the first sync.

## 3. Coverage

- **Record types**: 16 (organization, API capability probes, user, group, group membership, application, application user/group assignment, policy, policy rule, authenticator, admin role, user/group admin-role assignment, privileged identity, privileged group — established across messages 1-5).
- **Security Findings**: 30 rules (`security_rules/okta.py`) — Critical 3 / High 9 / Medium 15 / Low 3, fully registered in the evaluator/registry/confidence/pack/coverage layers (message 6).
- **Change classification**: exhaustive QA pass complete (message 7) — 4 real bugs found and fixed (scope-categorization asymmetry, Everyone-group `None`-vs-`False` defaulting, pagination truncation masking, non-deterministic record ordering).
- **Monitored API families** (12, permission-matrix basis for `build_okta_permission_diagnostics()`): users, groups, group memberships, applications, application user assignments, application group assignments, authentication/password policies, policy rules, authenticators, custom admin roles, user admin-role assignments, group admin-role assignments.

## 4. Reliability

- Partial-permission and partial-sync false-removal protection (`family_completeness`, `_okta_removal_suppressed()`, per-parent completeness fields — message 7).
- Bounded 429 retry with backoff (injectable `_sleep_fn`).
- Link-header pagination with truncation detection (message-7 fix — a rejected cross-origin `Link` header or a mid-pagination failure now correctly reports `FAMILY_PARTIAL` instead of silently looking complete).
- Stable tenant identity: `compute_tenant_id()` keyed on the immutable Okta org `id` field (falls back to normalized hostname); reused by both `fetch()` and the new `reconnect_credentials_okta()` for tenant-mismatch detection.
- `build_okta_permission_diagnostics()` / `format_okta_permission_diagnostics_text()` (message 8, modeled on Kubernetes' `build_permission_diagnostics()`) — redacted, user-facing Full/Partial/Invalid coverage reporting across the 12 families.

## 5. Sensitive-data boundary

- `api_token`: encrypted at rest (AES-256-GCM via `encrypt_credentials`), never returned in any API response (`IntegrationResponse` has no credential field), never logged, never copied into `resource_metadata` (only the non-secret `org_url` is stored there at creation time).
- Passwords, password hashes, recovery answers, MFA secrets, OTP seeds, session/refresh/access tokens, private keys, raw authentication factors, raw System Log payloads: never fetched (permanent, documented boundary since message 1).
- Reconnect (`reconnect_credentials_okta()`): the new token is never logged; a genuinely different-tenant token is rejected with a message that never echoes the token value.
- 3 safety greps (secrets pattern, CLI/subprocess dependency, incident-claim language) run against all Okta launch files: clean.

## 6. Reconnect / token rotation

- `reconnect_credentials_okta()` (new this message) validates the new credentials against the live org, then resolves the new tenant's identity via `compute_tenant_id()` and compares it against the identity already recorded on the integration's `okta_organization` resource.
- **Same-tenant rotation**: a new token for the SAME tenant (`org/<tenant_id>` matches) is accepted, the encrypted credentials are replaced, and `status` is reset from `error`/`needs_reconnect` to `active` if applicable.
- **Different-tenant rejection**: a token that resolves to a genuinely different tenant raises `ConnectorError` and the existing credentials are left unchanged — never silently overwritten.
- **Pre-first-sync guard**: the org resource's `provider_resource_id` is a creation-time placeholder (`str(integration.id)`) until the first sync populates the real `"org/<tenant_id>"` identity. Reconnect only enforces the tenant-mismatch check once a real identity has been recorded — otherwise every reconnect attempted before the first sync would spuriously look like a tenant mismatch. This is a deliberate refinement over a naive copy of the Kubernetes pattern (see `test_okta_provider_depth_qa.py::TestCredentialRoundTrip::test_reconnect_rejects_different_tenant`).
- Router wiring: `POST /integrations/{id}/reconnect` dispatches to `reconnect_credentials_okta()` via a new `elif integration.provider == "okta"` branch, following the same exception-mapping pattern (`AuthenticationError`→400, `ConnectorError`→400, `NetworkError`→502) as every other bespoke-reconnect provider.

## 7. Frontend

- **Card**: `providers.ts` `okta` entry — description, `monitoredSurfaces`, and `trustNote` copy rewritten to remove all "(planned)"/"foundation stage" language, describe the 12 monitored families accurately, and explicitly disclaim System Log threat detection, session monitoring, device telemetry, per-user effective-MFA evaluation, password-breach intelligence, and runtime attack detection (none of these are implemented) — pinned by `test_okta_provider_depth_qa.py::TestFrontendLaunchState`.
- **Form**: `OktaIntegrationForm.tsx` (new this message) — org URL + password-style API-token field (never re-displayed after success, only "API token configured" is shown), inline least-privileged-role guidance matching the real Okta token-inheritance model.
- **Setup guide**: `ProviderSetupGuide` `okta` branch in `integrations/page.tsx` (new this message) — dedicated read-only admin account guidance, token-generation steps, org-URL/token-paste step.
- **Detail page**: `ProviderOverview` `okta` branch (new this message) — org hostname, display name, last snapshot, monitored-category list; never renders the API token or raw API errors.
- **Findings/Changes**: provider filter, detail views, severity, evidence, remediation copy all resolve through the existing generic (non-provider-specific) UI — no Okta-specific gaps found, since `okta` is now present in `PROVIDER_IDS`.

## 8. Known limitations (intentional, documented — not gaps)

- Okta activity/System Log ingestion, activity signals, risk × activity correlations, demo seed/clear, case reporting, evidence timeline/graph: **not built** for this provider — Okta's security stack is Security Findings only (drift + static rules), the same dual-stack scope as Kubernetes. This is why capability-matrix maturity stays `"partial"` even though the provider is fully launched.
- OAuth 2.0 service-app (client_credentials with a private key / DPoP) authentication: **not implemented** — API-token auth is officially supported by Okta for this "trusted backend service reads org configuration" use case and remains the correct minimal secure starting point; OAuth is a documented future enhancement, not a launch blocker.
- Raw System Log payloads, passwords, password hashes, recovery answers, MFA secrets, OTP seeds, session/refresh/access tokens, private keys: **permanently unsupported** (architectural decision from message 1, reaffirmed every message since).
- Custom admin roles / resource-set edge cases may be unreadable under a least-privileged (non-Super-Admin) token — reported as `"denied"`/`"unavailable"` in coverage diagnostics, never treated as invalid.
- Frontend reconnect UI (`ReconnectIntegrationModal`) does not yet support Okta's two-field (org URL + API token) credential shape — this is a **pre-existing gap shared by most non-original-8 providers** (Kubernetes, AWS, Firebase, Supabase, Shopify, GitLab, Jira, etc. have the same limitation), not something introduced or left incomplete by this message. The backend `reconnect_credentials_okta()` + router branch are fully implemented and tested at the API layer. Flagged as a separate follow-up task, not a launch blocker.

## 9. Certification status

**PASS.**

All launch gates pass:
- Synchronous create-time validation added (`_create_okta_integration()` now calls `validate_credentials()` before writing any row), matching the Kubernetes message-9 precedent and giving the Invalid launch-certification state immediate feedback.
- Reconnect path added (`reconnect_credentials_okta()`, router branch, schema fields) with same-tenant-identity preservation and cross-tenant-mismatch rejection.
- `build_okta_permission_diagnostics()` / `format_okta_permission_diagnostics_text()` implemented for Full/Partial/Invalid coverage reporting across the 12 monitored API families.
- Capability matrix moved to the public/complete list (`PROVIDER_CAPABILITIES`, 10 providers total), `drift_review_workflow` flipped to `True`, notes rewritten to reflect launched state.
- `security_coverage_service.PROVIDERS` / `PROVIDER_SURFACES` now include `okta`.
- Frontend `providers.ts` moved `okta` to `PROVIDER_IDS` + `CONNECTABLE_PROVIDER_IDS`, card copy rewritten to remove stale "(planned)"/"foundation stage" wording and describe real coverage/limits.
- `OktaIntegrationForm.tsx` built and wired into the integration creation flow and setup guide.
- Integration detail page given a real Okta overview panel.
- Exactly 30 Security Finding rules confirmed (no drift) across evaluator/registry/confidence/coverage layers.
- Sensitive-data boundary re-verified (3 safety greps clean; no CLI/subprocess dependency).
- No database migration required (`Integration.provider` is a plain `Text` column, no ENUM/CheckConstraint).
- Zero new production environment variables.
- 1025 Okta-related tests pass (`find tests -maxdepth 1 -iname '*okta*'`), up from the message-7 baseline of 971.
- All 6 required narrow filters (`okta and provider_depth`, `okta and integration`, `okta and credential`, `okta and reconnect`, `okta and security_finding`, `okta and change`) select non-zero tests and all pass.
- Cross-provider regression tests (capability matrix, coverage service, reconnect dispatch for all providers, full `-k okta` sweep) pass with no unrelated regressions.
- Frontend `tsc --noEmit` passes with zero errors; `next build` compiles successfully and passes type-checking (the only failure is a pre-existing sandbox limitation — no real Clerk publishable key for static-page prerendering on `/integrations` and `/security/signals` — unrelated to and unaffected by this message's changes, identical to the Kubernetes launch's documented limitation).

**Okta provider expansion is complete.**
