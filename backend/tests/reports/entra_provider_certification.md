# Microsoft Entra ID Provider Certification (Message 8 of 8 — Public Launch)

## Identity

- **Canonical ID**: `entra`
- **Display name**: Microsoft Entra ID
- **Category**: `identity` (frontend), `auth` (backend capability taxonomy) — audited for consistency; both layers already used these values for Okta, so no UI contradiction exists.
- **Live status**: **Live** — `entra` is now in `PROVIDER_IDS` and `CONNECTABLE_PROVIDER_IDS` (`frontend/src/lib/providers.ts`), `PROVIDER_CAPABILITIES` (not `_PARTIAL`), and `security_coverage_service.PROVIDERS`.

## Authentication

- OAuth 2.0 client-credentials grant, app-only, against `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` with `scope=https://graph.microsoft.com/.default` — verified against current official Microsoft Learn documentation ["Get access without a user"](https://learn.microsoft.com/en-us/graph/auth-v2-service), no discrepancy with the existing connector.
- Credentials: `tenant_id` (GUID, rejects `common`/`organizations`/`consumers`), `client_id` (GUID), `client_secret`. Frontend fields: "Microsoft Entra tenant ID" / "Application (client) ID" / "Client secret", matching the task's exact requested labels/helper text.
- Microsoft commercial/global cloud only — `login.microsoftonline.com` / `graph.microsoft.com` are the only trusted hosts; GCC High, DoD, and China (21Vianet) are explicitly documented as unsupported in the card trust-note and capability-matrix notes.
- Full permission model: see `backend/tests/reports/entra_graph_permission_matrix.md`, verified against 8 distinct current Microsoft Learn pages fetched live on 2026-07-29. No discrepancy found between the already-implemented connector and current official documentation.
- Never advertises: delegated login, device code, Azure CLI, PowerShell, managed identity, or certificate auth. Certificate-based auth remains a documented future enhancement only (connector docstring, unchanged from message 1).

## Coverage

- **19 emitted record types**: `entra_organization`, `entra_user`, `entra_group`, `entra_group_membership`, `entra_application`, `entra_service_principal`, `entra_application_user_assignment`, `entra_application_group_assignment`, `entra_service_principal_app_role_assignment`, `entra_oauth2_permission_grant`, `entra_conditional_access_policy`, `entra_authentication_strength`, `entra_authentication_method`, `entra_directory_role`, `entra_directory_role_assignment`, `entra_privileged_identity`, `entra_privileged_group`, `entra_privileged_service_principal`, `entra_api_capability`.
- **45 Security Findings** — exact count re-verified this message (`test_entra_has_exactly_45_rules`), severity distribution unchanged from message 6: **Critical 9, High 18, Medium 16, Low 2**.
- **Change coverage**: identity lifecycle, applications/service principals/assignments, Conditional Access/authentication policy, and privileged-identity/consent all have dedicated `risk_rules/entra.py` classifiers (messages 2-7), including the message-7 parity fixes.

## Reliability (carried forward from message 7, re-verified this message)

- Partial-sync / false-removal suppression: `_entra_removal_suppressed()` (tenant-wide + per-parent for group memberships and SP assignments) — 35 dedicated tests, all passing.
- Pagination/retry: bounded 429/5xx retry, `@odata.nextLink` trusted-origin constraint, capability-probe `_sleep_fn` threading (message-7 bug fix) — 26 dedicated tests.
- Token-cache binding: `_TokenCache.credential_key = (tenant_id, client_id)` — re-verified this message with a new behavioral regression test (`test_token_cache_does_not_leak_across_reconnect_to_new_client`) proving two different client credentials on one reused connector instance never share a cached token.
- Idempotency/determinism/scale: 20 dedicated scale tests, deterministic ordering via final `records.sort()`.

## Sensitive data

- `client_secret` is never logged, never returned in any API response, never copied into `resource_metadata`, and is stored only via the existing `encrypt_credentials()`/`decrypt_credentials()` mechanism shared by every other provider — no Entra-specific encryption was invented.
- Access tokens are connector-instance-memory-only (`_TokenCache`), never persisted to the database, never entered into the integration credential JSON.
- Verified via source-scan tests (`test_connector_never_logs_or_raises_with_raw_secret`, `test_org_resource_metadata_never_contains_client_secret`, `test_reconnect_entra_never_logs_new_secret`) and a live behavioral test (`test_client_secret_not_logged_by_validate_credentials`) that mocks a real token-endpoint response and asserts the secret never appears in captured log output.
- Safety greps across every file this message touched found zero forbidden secret/token leakage patterns and zero unsupported incident-claim language (see final report for exact grep commands/output).

## Frontend

- **Card**: `entra` in `PROVIDER_IDS`/`CONNECTABLE_PROVIDER_IDS`; card copy rewritten to drop all "(planned)"/"architecture-foundation stage" wording and describe the actual live monitored surfaces.
- **Setup form**: `EntraIntegrationForm.tsx` — Tenant ID / Application (client) ID / Client secret fields (secret is `type="password"`, never re-echoed after success, cleared from state immediately on success), inline least-privilege setup guidance (app registration → API permissions → admin consent → client secret → copy tenant/client IDs), matching the task's exact requested flow and field labels.
- **Validation UX**: synchronous validate-on-create via `EntraConnector.validate_credentials()`; sanitized errors only (`AuthenticationError`/`ConnectorError`/`NetworkError` → 400/400/502, never a raw Graph body).
- **Coverage diagnostics**: `build_entra_permission_diagnostics()` / `format_entra_permission_diagnostics_text()` (new this message, mirroring Okta's `build_okta_permission_diagnostics()`) group the 12 backend families into Full/Partial/Invalid coverage with human-readable per-family status labels — never raw endpoint names, tokens, or Graph error bodies.
- **Findings/Changes UI**: no Entra-specific frontend rendering path exists — Findings/Changes render generically off `provider`/`record_type`/`severity` fields already common to every provider; Entra's 45 rules and Change classifiers were already wired at messages 6-7 and require no additional frontend code.
- Reconnect UI: `ReconnectIntegrationModal.tsx` does not yet support Entra's 3-field (tenant/client/secret) credential shape — this is the **same pre-existing gap shared by Okta, Kubernetes, AWS, Firebase, Supabase, Shopify, GitLab, Jira, etc.** (documented at Okta's own message 8), not something introduced or left incomplete by this message. The backend `reconnect_credentials_entra()` + router branch + schema fields are fully implemented and tested at the API layer. Flagged as a follow-up, not a launch blocker.

## Deployment

- **Database migration**: none required. `Integration.provider` is a plain `Text` column (`nullable=False`, no CHECK constraint, no enum) — confirmed by direct model inspection.
- **Dependencies**: none added. The connector uses the backend's existing `httpx` client only — no Microsoft Graph SDK, no MSAL, no Azure CLI, no PowerShell, no browser automation. Confirmed via `test_no_cli_or_subprocess_dependency` and `test_no_graph_sdk_or_msal_dependency`.
- **Environment variables**: none added. Credentials are per-integration, encrypted at rest via the existing `ENCRYPTION_KEY`-based mechanism — no new global secret.
- **CLI independence**: confirmed — zero matches for `subprocess`/`os.system`/`az login`/`Connect-MgGraph`/`powershell`/`pwsh`/`shell=True` in `entra.py`.

## Known limitations (explicitly accepted at launch)

- No runtime sign-in-event ingestion and no Identity Protection risk-event ingestion — configuration/posture snapshots only.
- No per-user authentication-method enumeration (tenant-wide `authenticationMethodsPolicy` configuration only).
- No exact effective Conditional Access evaluation for a specific sign-in — policy configuration only, not a policy simulator.
- No nested/transitive group membership flattening — direct memberships only (documented since message 2).
- **PIM eligible-role schedules are NOT modeled.** `entra_directory_role_assignment` is collected via `GET /roleManagement/directory/roleAssignments`, which returns only **active** role assignments — it does not capture PIM eligible assignments, activation schedules, or activation history. Privileged-identity/group/service-principal derivation and all related Security Findings are therefore based on active assignment state only; this is not claimed to be exhaustive privileged-access coverage in tenants using PIM eligible (as opposed to active/permanent) assignments.
- No certificate-based ConfigTrace authentication — client secret only (certificate auth remains a documented future enhancement).
- Commercial/global Microsoft cloud only — no GCC, GCC High, DoD, or China (21Vianet) support.
- No runtime token/session telemetry of any kind.
- Reconnect UI (`ReconnectIntegrationModal.tsx`) does not yet support Entra's multi-field credential shape — backend-only for now (see Frontend section above), matching the pattern already accepted for most non-original-8 providers.

None of these limitations block launch — they mirror the same class of accepted, clearly documented gaps under which Okta and Kubernetes already launched.

## Certification

**PASS**
