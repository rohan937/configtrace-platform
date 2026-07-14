# Azure Detection QA Matrix

Exhaustive end-to-end validation of the Azure provider (connector → diff
tracking → risk classification → security findings → registries →
frontend catalog), following the same methodology established for
SendGrid, Twilio, Terraform Cloud, GitLab, Jira, Linear, PagerDuty,
Datadog, Clerk, Auth0, and Google Cloud in prior QA passes.

## Graphify usage

Ran successfully via the full path (`/Users/rohan/.local/bin/graphify`)
for all 4 required queries — no errors. The graph confirmed
`AzureConnector` (backend/app/connectors/azure.py:302) and
`security_rules/azure.py` (M77B+M77C) exist and are indexed, and surfaced
the M77A–M77H test file arc (`test_milestone77a_azure_drift_provider_foundation.py`
through `test_milestone77i_azure_cross_cloud_ux_polish.py`). Critically,
**no node for `risk_rules/azure.py` or `classify_azure_change()` appeared
in any of the 4 queries** — the same missing-module signal seen in every
prior provider this session, confirmed directly afterward via `grep`.
Query results were otherwise mostly generic cross-provider boilerplate
(every connector class, unrelated milestone test files), so this pass
proceeded via direct, targeted file reads for all substantive analysis.

## Summary

Azure's connector (`app/connectors/azure.py`), schema
(`azure_schema.py`), and security rules (`security_rules/azure.py`, 20
rules across 7 of its 9 record types) were already mature (built across
M77A–M77D). **Registries and the frontend catalog were already in
perfect parity (20/20, zero severity mismatches)** — no fixes needed
there. The two recurring root-cause bugs from every prior provider pass
were both present here too, with the same "already-claimed-true
capability matrix" twist seen in Auth0 and Google Cloud's passes:

1. **`risk_rules/azure.py` did not exist at all.** `risk_service.py` had
   no `azure_` dispatch branch, so **every Azure configuration change
   silently fell through to the Cloudflare DNS classifier**.

2. **Diff/drift tracking gap.** Azure had **zero entries** in
   `diff_service.py`'s per-provider tracked-fields dispatch, so every
   Azure record type fell through to the Cloudflare DNS default tuple.
   `compute_diff` could never detect a modified field on an existing
   Azure record.

3. **The twist (same pattern as Auth0/Google Cloud)**: `provider_capability_matrix_service.py`'s
   Azure entry already claims `drift_diff=True` and
   `drift_risk_classification=True`. This pass's fixes make those
   pre-existing claims true for the Change-classification layer for the
   first time.

This is the **second provider in this session's series with list-valued
tracked fields** (after Google Cloud's firewall rule lists). The
None-vs-empty-list bug found and fixed in Google Cloud's *follow-up
classification-QA pass* was applied **proactively from the start** here
for Azure's NSG `rules_summary` field — `_as_dict_list_or_none()` and the
"evaluate current state only when baseline is unknown" pattern were built
into the module from day one, with a dedicated regression test
(`test_nsg_rules_summary_unknown_baseline_does_not_claim_added`) locking
it in immediately rather than requiring a second pass to discover it.

Building on the false-positive severity bug found and fixed in
PagerDuty's classification-QA pass, and the `(n_old or 0)`
unknown-treated-as-zero bug found and fixed in Google Cloud's
classification-QA pass, `_int_or_none()` is used for every count-based
field, applied proactively from the start (no count-threshold rules
exist in Azure's 20-rule set that require a "many X" style comparison —
Azure's Findings are almost entirely boolean/category-string posture
checks, not count thresholds, unlike GCP's service-account-key-count or
Auth0's callback-count rules).

No new Security Finding rules were added — the existing 20 rules already
cover the large majority of what this pass identified as security-
relevant. Two genuine **Finding-layer coverage gaps** were found
(category S below: `azure_storage_account.supports_https_traffic_only`
and `azure_app_service.client_cert_enabled` are both fetched, normalized,
and now diff-tracked, but have no dedicated Security Finding) —
documented, not fixed, per the established precedent (Auth0, Google
Cloud) of deferring new-Finding decisions to a dedicated follow-up
classification-QA pass rather than adding rules during detection QA. The
Change classifier still applies sensible severities to these two
already-fetched fields, mirroring the task's own stated HTTPS/client-cert
conventions and the analogous sibling `azure_app_service_https_disabled`
rule (high) for the storage-account HTTPS case.

## Connector extraction review

| Record type | Source endpoint | Sensitive values excluded? | Fail-soft on error? | Stable record IDs? |
|---|---|---|---|---|
| `azure_subscription` | ARM `subscriptions.get` (2022-12-01) | Yes — no owner/ancestry principals stored | Yes — wrapped in the connector's top-level `fetch()` try/except | Yes — `subscription_id` |
| `azure_resource_group` | ARM `resourceGroups.list` (2021-04-01) | Yes — tag VALUES excluded (only key names) | Yes | Yes — subscription + name-derived |
| `azure_network_security_group` | ARM `networkSecurityGroups.list` (2023-05-01) | Yes — packet/log-profile data never accessed; rules capped at 50, each reduced to 9 safe fields | Yes | Yes — resource-ID-derived |
| `azure_storage_account` | ARM `storageAccounts.list` (2023-01-01) | Yes — no storage keys, SAS tokens, or connection strings ever fetched | Yes | Yes — resource-ID-derived |
| `azure_key_vault` | ARM `vaults.list` (2023-02-01) | Yes — no secret names/values/certs/principal IDs; `access_policy_count` is a count only | Yes | Yes — resource-ID-derived |
| `azure_role_assignment` | ARM `roleAssignments.listForSubscription` (2022-04-01) | Yes — `principalId` (object ID) intentionally excluded; only `principalType` (category string) kept; role name resolved from a static built-in-role GUID map, no extra API call | Yes | Yes — assignment-ID-derived |
| `azure_app_service` | ARM `sites.list` (2023-01-01) + per-site config sub-request (fail-soft) | Yes — app setting/connection-string names and values never stored, only counts | Yes — per-site config fetch wrapped in its own try/except, fields default to `None` on failure | Yes — resource-ID-derived |
| `azure_sql_server` | ARM `servers.list` (2021-11-01) + per-server firewall-rules sub-request (fail-soft) | Yes — administrator login/password never stored; firewall rules reduced to a count + one safe boolean (`has_allow_azure_services_rule`) | Yes — per-server firewall fetch wrapped in its own try/except | Yes — resource-ID-derived |
| `azure_aks_cluster` | ARM `managedClusters.list` (2023-10-01) | Yes — kubeconfig, credentials, certs, node/pod data are never accessible from the management-plane list API | Yes | Yes — resource-ID-derived |

**Confirmed via code inspection** (connector module docstring + normalizer
bodies + the module-level "PRIVACY / SECURITY" comment block):
- No **client secrets** are stored — the service-principal `client_secret`
  is used only within `_get_token()`'s scope to acquire a bearer token,
  never stored as an instance attribute, never logged, never returned in
  a record.
- No **certificates/private keys** are stored — Key Vault and AKS
  normalizers never read certificate/key material fields at all.
- No **connection strings** are stored — App Service's
  `connectionStrings` sub-request result is reduced to
  `connection_string_count` only; the names/values are read transiently
  and discarded.
- No **storage account keys** are stored — the connector never calls the
  `listKeys` endpoint at all.
- No **Key Vault secret values** are stored — the connector only calls
  `vaults.list` (management-plane metadata), never the data-plane secrets
  API.
- No **SQL data** is stored — only `servers.list` and firewall-rule
  metadata are fetched; no database-content or query endpoint is called.
- No **blob/object contents** are stored — no Storage data-plane
  (blob/queue/table) endpoint is called.
- No **logs/events payload contents** are stored — the M77D Activity Log
  path (`list_activity_events`) strips `caller`, `claims`,
  `authorization`, `properties`, `httpRequest`, `description`, and
  `tenantId` from every event before returning it, and applies a
  client-side allowlist restricting results to management/control-plane
  write/delete operations only.
- No **customer data** is stored — none of the 9 record types touch a
  user-facing/customer-facing data plane.
- Only **safe configuration metadata, booleans, counts, IDs, and posture
  fields** are stored, confirmed field-by-field against each normalizer.

**Record ID stability note**: all 9 record types use Azure-native
resource-ID-derived or subscription/name-derived identifiers — no
positional-index or hash-based identifiers are used anywhere in this
connector.

## Diff/change tracking review

**Before this pass**: 0 of 9 record types had a tracked-fields entry —
all Azure modified-field changes silently fell through to the Cloudflare
DNS default tuple and were never detected, **despite the capability
matrix already claiming `drift_diff=True`.**

**After this pass**: all 9 record types are tracked with every
security-relevant field verified present, including every one of the
task's high-priority fields: `role_definition_name` (RBAC role name),
`principal_type` (principal category), `allow_blob_public_access`,
`public_network_access` (storage/Key Vault/SQL/App Service/AKS),
`shared_access_key_enabled`, `supports_https_traffic_only`/
`minimum_tls_version` (storage), `rules_summary` (NSG source/port/
protocol/access/direction), `purge_protection_enabled`/
`soft_delete_enabled`/`enable_rbac_authorization` (Key Vault),
`https_only`/`client_cert_enabled` (App Service), `firewall_rule_count`/
`has_allow_azure_services_rule` (SQL), `private_cluster_enabled`/
`local_account_disabled`/`api_server_authorized_ip_range_count` (AKS).

No fields were found that are tracked but no longer emitted by the
connector — the tracked tuples were built directly from each
normalizer's actual return dict.

**Not modeled** (task explicitly asked about these, confirming absence
rather than inventing them): SQL auditing/threat-detection fields (no
such API is called — only firewall aggregate count + the
"Allow Azure services" boolean exist); AKS workload identity federation
(no `workloadIdentityConfig`-equivalent field exists in this connector's
AKS schema — only `azure_rbac_enabled`, not workload identity); diagnostic
settings / Log Analytics sink configuration as a standalone drift record
type (the M77D Activity Log path ingests *activity events*, a separate
system, not a drift-tracked "diagnostic settings" configuration record);
App Registrations / Service Principals (explicitly deferred — requires
the Microsoft Graph API, a different auth scope from the ARM connector
used here).

## Test matrix

| Test case | Normalized record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes/fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A1. RBAC privileged role (Owner) granted | `azure_role_assignment` | `role_definition_name` | `"Reader"` → `"Owner"` | Change (high) + Finding (high/medium dynamic, `azure_role_assignment_broad_privilege`) | Change never generated before fix | high | high (after fix) | matches the Finding's subscription-scope (worst-case) branch | new `test_role_assignment_owner_granted_is_high` | **FIXED** | Change-only approximation: the Finding's severity also depends on `scope_type` (subscription=high, resource_group=medium), which a single-field Change on `role_definition_name` can't confirm — kept at the worst case, consistent with every other combined-condition approximation in this session |
| A2. RBAC privileged role removed | `azure_role_assignment` | `role_definition_name` | `"Owner"` → `"Reader"` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a | new `test_role_assignment_owner_removed_is_low` | **FIXED** | Role assignments are effectively immutable in Azure (a role change is normally a delete+create surfaced as separate added/removed events on a new assignment_id) — this branch exists defensively for the rarer "modified" case |
| B. Broad principal access added/removed | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Azure RBAC has no "public"/"anonymous" sentinel principal equivalent to GCP's `allUsers`/Auth0's public IAM member — every role assignment requires a specific principal object ID. Not invented |
| C1. Storage blob public access enabled | `azure_storage_account` | `allow_blob_public_access` | `False` → `True` | Change (high) + Finding (high, `azure_storage_public_blob_access`) | Change never generated before fix | high | high (after fix) | `azure_storage_public_blob_access` (high) — matches | new `test_storage_public_blob_access_enabled_is_high` | **FIXED** | — |
| C2. Storage blob public access disabled | `azure_storage_account` | `allow_blob_public_access` | `True` → `False` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a | new `test_storage_public_blob_access_disabled_is_low` | **FIXED** | — |
| D. Storage container public access level | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | `azure_storage_account` models the account-level `allow_blob_public_access` toggle only; per-container public-access-level (Blob/Container/Off) is not fetched — no per-container endpoint is called. Not invented |
| E1. Storage shared key access enabled | `azure_storage_account` | `shared_access_key_enabled` | `False` → `True` | Change (medium) + Finding (medium, `azure_storage_shared_key_enabled`) | Change never generated before fix | medium | medium (after fix) | `azure_storage_shared_key_enabled` (medium) — matches | new `test_storage_shared_key_access_enabled_is_medium` | **FIXED** | — |
| E2. Storage shared key access disabled | `azure_storage_account` | `shared_access_key_enabled` | `True` → `False` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a | covered by tracked-field sweep | **FIXED** | — |
| F1. Storage minimum TLS weakened | `azure_storage_account` | `minimum_tls_version` | `"TLS1_2"` → `"TLS1_0"` | Change (medium) + Finding (medium, `azure_storage_weak_tls`) | Change never generated before fix | medium | medium (after fix) | `azure_storage_weak_tls` (medium) — matches | covered by tracked-field sweep | **FIXED** | — |
| F2. Storage HTTPS-only disabled (Finding gap) | `azure_storage_account` | `supports_https_traffic_only` | `True` → `False` | Change (high, per task convention) | Change never generated before fix | high | high (after fix) | none — no dedicated Finding at this record type (see category S) | new `test_storage_https_only_disabled_is_high` | **FIXED (Change-only, documented gap)** | `azure_app_service_https_disabled` (high) evaluates the analogous `https_only` field on `azure_app_service`, not `azure_storage_account`; the storage-account-level `supports_https_traffic_only` field is fetched and normalized but has no dedicated Finding — documented, not invented |
| G. Uniform/public container access if modeled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Same as D — no container-level public-access endpoint is called |
| G1. NSG public SSH ingress added | `azure_network_security_group` | `rules_summary` | `[] → [ssh_rule]` | Change (high) + Finding (high, `azure_nsg_public_admin_ingress`) | Change never generated before fix | high | high (after fix) | `azure_nsg_public_admin_ingress` (high for SSH) — matches | new `test_nsg_public_ssh_rule_added_is_high` | **FIXED** | — |
| G2. NSG public RDP ingress added | `azure_network_security_group` | `rules_summary` | `[] → [rdp_rule]` | Change (critical) + Finding (critical, `azure_nsg_public_admin_ingress`) | Change never generated before fix | critical | critical (after fix) | `azure_nsg_public_admin_ingress` (critical for RDP) — matches | new `test_nsg_public_rdp_rule_added_is_critical` | **FIXED** | — |
| G3. NSG broad all-ports ingress added | `azure_network_security_group` | `rules_summary` | `[] → [broad_rule]` | Change (critical) + Finding (critical, `azure_nsg_public_broad_ingress`) | Change never generated before fix | critical | critical (after fix) | `azure_nsg_public_broad_ingress` (critical) — matches | new `test_nsg_broad_all_ports_rule_added_is_critical` | **FIXED** | — |
| G4. NSG benign port rule added | `azure_network_security_group` | `rules_summary` | `[] → [https_rule]` | Change (low) | Change never generated before fix | low | low (after fix) | n/a | new `test_nsg_benign_rule_added_is_low` | **FIXED** | — |
| G5. NSG public rule removed | `azure_network_security_group` | `rules_summary` | `[ssh_rule] → []` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a | new `test_nsg_public_rule_removed_is_low` | **FIXED** | — |
| G6. NSG rules_summary unknown baseline | `azure_network_security_group` | `rules_summary` | `None` → `[rdp_rule]` | Change (critical, current-state-only wording) | Change never generated before fix | critical | critical (after fix) | matches — mirrors the Finding's own current-state-only admin-port check | new `test_nsg_rules_summary_unknown_baseline_does_not_claim_added` | **FIXED (proactive)** | Applied the None-vs-empty-list lesson from Google Cloud's classification-QA pass from the start — no wording falsely claims a rule was "added" when the baseline is unknown |
| H. NSG SSH/RDP/admin port opened/closed | (covered above, G1–G5) | | | | | | | | | | Task category H is the same surface as G for this connector (Azure models ingress rules as a single `rules_summary` list, not separate "port opened"/"broad ingress" record types like some other providers) |
| I1. SQL public network access enabled | `azure_sql_server` | `public_network_access` | `"Disabled"` → `"Enabled"` | Change (medium) + Finding (high/medium dynamic, `azure_sql_public_network_access`) | Change never generated before fix | medium | medium (after fix) | matches the Finding's base (no-Allow-Azure-services) branch | new `test_sql_server_public_network_access_enabled_is_medium` | **FIXED** | Finding severity bumps to `high` when `has_allow_azure_services_rule` is ALSO true — a single-field Change can't confirm that sibling, kept at the conservative base case |
| I2. SQL public network access disabled | `azure_sql_server` | `public_network_access` | `"Enabled"` → `"Disabled"` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a | covered by tracked-field sweep | **FIXED** | — |
| J. SQL firewall broad range added/removed | `azure_sql_server` | `firewall_rule_count`, `has_allow_azure_services_rule` | count/bool change | Change (low, generic) | Change never generated before fix | low | low (after fix) | n/a — only an aggregate count + one boolean flag exist; no per-rule range inspection (e.g. a `0.0.0.0`–`255.255.255.255` fully-open range) is modeled | covered by tracked-field sweep | **PARTIAL (aggregate only)** | This connector has no per-firewall-rule record type or range data — only `firewall_rule_count` and the "Allow Azure services" pseudo-rule boolean. Not invented |
| K1. SQL TLS weakened | `azure_sql_server` | `minimum_tls_version` | `"1.2"` → `"1.0"` | Change (medium) + Finding (medium, `azure_sql_weak_tls`) | Change never generated before fix | medium | medium (after fix) | `azure_sql_weak_tls` (medium) — matches | covered by tracked-field sweep | **FIXED** | — |
| K2. SQL auditing/threat detection | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | No Azure SQL Auditing or Advanced Threat Protection API is called by this connector. Not invented |
| L1. Key Vault public network access enabled | `azure_key_vault` | `public_network_access` | `"Disabled"` → `"Enabled"` | Change (medium) + Finding (high/medium dynamic, `azure_key_vault_public_network_access`) | Change never generated before fix | medium | medium (after fix) | matches the Finding's base branch | covered by tracked-field sweep | **FIXED** | Same combined-condition approximation pattern as storage/SQL public network access |
| M1. Key Vault purge protection disabled | `azure_key_vault` | `purge_protection_enabled` | `True` → `False` | Change (medium) + Finding (high/medium dynamic, `azure_key_vault_purge_protection_disabled`) | Change never generated before fix | medium | medium (after fix) | matches the Finding's base (soft-delete-still-on) branch | new `test_key_vault_purge_protection_disabled_is_medium` | **FIXED** | Finding bumps to `high` when `soft_delete_enabled` is ALSO false — single-field Change can't confirm, kept conservative |
| M2. Key Vault soft delete disabled | `azure_key_vault` | `soft_delete_enabled` | `True` → `False` | Change (medium) + Finding (medium, `azure_key_vault_soft_delete_disabled`) | Change never generated before fix | medium | medium (after fix) | `azure_key_vault_soft_delete_disabled` (medium) — matches | new `test_key_vault_soft_delete_disabled_is_medium` | **FIXED** | — |
| N1. App Service HTTPS-only disabled | `azure_app_service` | `https_only` | `True` → `False` | Change (high) + Finding (high, `azure_app_service_https_disabled`) | Change never generated before fix | high | high (after fix) | `azure_app_service_https_disabled` (high) — matches | new `test_app_service_https_only_disabled_is_high` | **FIXED** | — |
| N2. App Service client cert requirement disabled (Finding gap) | `azure_app_service` | `client_cert_enabled` | `True` → `False` | Change (medium, per task convention) | Change never generated before fix | medium | medium (after fix) | none — no dedicated Finding at this field (see category S) | covered by tracked-field sweep | **FIXED (Change-only, documented gap)** | `client_cert_enabled` is fetched and normalized but has no dedicated Finding — documented, not invented |
| N3. App Service FTP/public network access weakened | `azure_app_service` | `ftps_state`, `public_network_access` | weakened | Change (medium each) + Finding (medium each, `azure_app_service_ftp_enabled`/`_public_network_access`) | Change never generated before fix | medium (each) | medium (each) (after fix) | both match | covered by tracked-field sweep | **FIXED** | — |
| O1. AKS local accounts enabled | `azure_aks_cluster` | `local_account_disabled` | `True` → `False` | Change (medium) + Finding (medium, `azure_aks_local_accounts_enabled`) | Change never generated before fix | medium | medium (after fix) | `azure_aks_local_accounts_enabled` (medium) — matches | new `test_aks_local_accounts_enabled_is_medium` | **FIXED** | — |
| O2. AKS private cluster disabled (public API) | `azure_aks_cluster` | `private_cluster_enabled` | `True` → `False` | Change (medium) + Finding (high, `azure_aks_public_api_access`, requires `api_server_authorized_ip_range_count==0` too) | Change never generated before fix | medium | medium (after fix) | Change-only approximation — see design note | covered by tracked-field sweep | **FIXED** | A public API server combined with configured authorized IP ranges is a common, safe configuration — kept at `medium` rather than the Finding's `high` ceiling to avoid over-alerting, the same reasoning already established for Auth0's `grant_client_credentials_enabled` and Google Cloud's `gke_public_control_plane` |
| O3. AKS network policy removed | `azure_aks_cluster` | `network_policy` | `"azure"` → `"none"` | Change (medium) + Finding (medium, `azure_aks_network_policy_missing`) | Change never generated before fix | medium | medium (after fix) | `azure_aks_network_policy_missing` (medium) — matches | new `test_aks_network_policy_removed_is_medium` | **FIXED** | — |
| O4. AKS workload identity | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | No `workloadIdentityConfig`-equivalent field exists in this connector's AKS schema (only `azure_rbac_enabled`, a distinct feature). Not invented |
| P. Diagnostic logging/sink posture changed | n/a | n/a | n/a | n/a | not modeled as a drift record | n/a | n/a | n/a | n/a | **N/A** | n/a | Activity Log *ingestion* exists (M77D `list_activity_events`, a separate Activity system), but no drift-tracked "diagnostic settings" configuration record type/endpoint exists in the 9 M77A/M77C surfaces. Not invented |
| Q. Unknown/missing fields never produce high/critical findings | all 9 record types | any | `None`/missing | no high/critical finding/classification | Confirmed — every Finding check in `security_rules/azure.py` uses explicit boolean/category-string equality (`is False`/`is True`), and every new Change classifier branch falls to `low` on unparseable/missing values via `_is_falsy_explicit`/`_is_truthy`/`_int_or_none()`'s explicit `None` check, applied proactively from the start | none | none | all | new `test_every_tracked_field_classifies_without_error_or_invalid_severity`, `test_unknown_transitions_never_produce_high_or_critical` | PASS | — |
| R. 403/404 fail-soft on optional endpoints | App Service per-site config, SQL per-server firewall rules (soft-failure sub-requests) | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed — every surface in `fetch()` is wrapped in its own `try/except Exception` block that logs a warning and continues; App Service's site-config and SQL's firewall-rules sub-requests default their derived fields to `None`/unset on failure rather than aborting the whole record | n/a | n/a | n/a | existing `test_fetch_fail_soft_when_one_surface_unavailable` (M77A) | PASS | — |
| S. Records with normalized fields but no security rule | `azure_subscription` (all fields), `azure_resource_group` (all fields), `azure_storage_account.supports_https_traffic_only`, `azure_app_service.client_cert_enabled` | n/a | n/a | correctly documented gaps | Confirmed — `security_rules/azure.py`'s own docstring explicitly states subscription/resource-group have "no actionable posture surface available"; `supports_https_traffic_only` and `client_cert_enabled` are fetched/normalized/tracked but the `evaluate()` dispatcher's per-type functions never read either field | n/a | n/a | n/a — two record types intentionally undocumented at the Finding layer (pre-existing design), two individual fields are genuine gaps (candidates for a future classification-QA pass, not fixed here per established precedent) | new `TestAzureDiffTrackedFields`/`TestAzureRiskClassifier` coverage | PASS (documented, not a gap to fix in this pass) | Mirrors Auth0's `connection.mfa_enabled`/`resource_server.signing_alg` and Google Cloud's `shielded_nodes_enabled` — this session's established pattern of deferring new-Finding decisions to a follow-up classification-QA pass |
| T. Security rules with no reachable normalized record | — | — | — | — | None found — all 20 rules dispatch from `evaluate()` against one of the 7 record types that actually have Findings, and all 7 are emitted by the connector | n/a | n/a | all | existing `test_azure_provider_depth_qa.py` / `test_milestone77h_azure_provider_depth_qa.py` coverage | PASS | Zero dead/unreachable rules |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | 20/20 rule keys present everywhere with matching severities | Verified via exact set diff: `security_rules/azure.py` (20) vs. `security_rule_registry.py` (20), `security_rule_pack.py` (20, all severities cross-checked, zero mismatches after excluding regex false-positives from dynamic-severity rules — every dynamic rule correctly stores its worst-case headline), `security_rule_confidence.py` (20), `security_coverage_service.py` (20 rule-key→record-type mappings, no extras once record-type-string false positives are excluded), and `securityRuleCatalog.ts` (20) | n/a | n/a | all | ad hoc scripted diff + manual re-verification for dynamic-severity rules | PASS | Zero mismatches — no fix needed (matching Linear's/PagerDuty's/Datadog's/Clerk's equivalent passes, unlike Jira's, which found 10 severity mismatches and 6 catalog gaps) |
| Diff-tracked fields present for all 9 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 9 record types tracked (before fix)** → **9 of 9 tracked (after fix)** | n/a | n/a | n/a | new `TestAzureDiffTrackedFields` (5 tests) | **FIXED** | Root-cause fix — see Summary #2 |
| Risk classification module exists and is wired | all | all tracked fields | n/a | every Change gets an Azure-specific classification, not the Cloudflare DNS fallback | **module did not exist (before fix)** → **9 classifiers + dispatch wired (after fix)** | n/a | n/a | n/a | new `TestAzureRiskClassifier` (24 tests, including a dispatch-level regression test, a dict-shaped mock-bug-prevention test, and dedicated NSG list-diffing tests across critical/high/low/unknown-baseline cases) | **FIXED** | Summary #1/#3 — the largest fix in this pass, and the one that makes the pre-existing `drift_risk_classification=True` capability-matrix claim actually true |

## Design notes

### Why the NSG `rules_summary` unknown-baseline case reaches the same severity as a confirmed "added" transition

Unlike Google Cloud's `source_ranges_summary` (where an unknown baseline
deliberately stays conservative at `low`, since a bare public range alone
isn't yet the full risky combination), Azure's `rules_summary` entries
carry the FULL rule shape (direction, access, source, destination port)
in a single list item — so a rule matching `_is_risky_public_rule()`
*is itself* sufficient evidence for the Finding's own current-state
check (`_eval_nsg` evaluates exactly this same per-rule shape,
independent of history). Evaluating current-state-only when the baseline
is unknown therefore correctly reaches the same severity a Finding would
assign to that same snapshot — mirroring the reasoning already
established for Google Cloud's IAM `role_names` unknown-baseline case
(also current-state-sufficient), not GCP's `source_ranges_summary` case
(which needs a second field).

### Why combined-condition Findings (storage/Key Vault/SQL public network access, Key Vault purge protection, AKS public API access) stay at their base-case severity, not the worst case

Five Findings in this rule set require a combination of fields a
single-field Change classifier cannot see simultaneously:
`azure_storage_public_network_access` and
`azure_key_vault_public_network_access` (both bump from medium to high
when `network_default_action` is ALSO `"Allow"`),
`azure_sql_public_network_access` (bumps when
`has_allow_azure_services_rule` is ALSO true),
`azure_key_vault_purge_protection_disabled` (bumps when
`soft_delete_enabled` is ALSO false), and
`azure_aks_public_api_access` (only fires at all when
`api_server_authorized_ip_range_count` is ALSO 0). Following the
established convention from Auth0's and Google Cloud's classification-QA
passes, this pass classifies each at the **base-case** severity rather
than guessing the worse combination, since the risky combination is
often not the common/expected configuration (e.g. many storage accounts
and Key Vaults legitimately have public network access enabled but a
`Deny`-by-default network rule set with explicit allow entries — the
`medium` case, not the `high` case).

## Tracked-fields vs. classifier-branch comparison

Verified programmatically: parsed `_AZURE_TRACKED_FIELDS_BY_TYPE` from
`diff_service.py` and every `if fp == "..."` / `if fp in (...)` branch
from each of the 9 `_classify_*_change` functions in
`risk_rules/azure.py`.

**Result**: zero tracked fields fall through accidentally, and zero
dead/unreachable classifier branches across all 9 record types — every
branch corresponds to a real tracked field, and every tracked field is
handled by either a field-specific branch or an explicit generic group
(including `azure_subscription` and `azure_resource_group`, whose fields
are all intentionally generic-`low` but still explicitly named rather
than falling through a bare catch-all, applying the lesson learned from
the exact fall-through bugs found in Clerk's and Auth0's classification-
QA passes proactively from the start).

**Classifier branches referring to fields not emitted by the
connector/schema:** none found — every branch was cross-checked against
both `_AZURE_TRACKED_FIELDS_BY_TYPE` and the connector's actual
normalizer return dicts.

**Classifier branches referring to stale field names:** none — this is a
newly-built module (this session), so there was no legacy field-name
drift to inherit.

**Fields with similar names that could be confused:** `public_network_access`
appears on storage/Key Vault/SQL/App Service/AKS records — each branch
names its own record type explicitly in the emitted wording ("Azure
storage public-access posture" / "Azure Key Vault protection posture" /
"Azure SQL network posture" / "Azure App Service public network access"),
so the five remain distinguishable in the reason text.
`minimum_tls_version` (storage/SQL) vs. `min_tls_version` (App Service) —
two *different* field names for the same concept, correctly handled by
separate branches in separate classifier functions, no cross-contamination.
`local_account_disabled` (AKS) uses an inverted-boolean name (disabled=True
means accounts are OFF, i.e. safe) — the classifier's wording explicitly
says "local accounts were enabled"/"disabled" rather than echoing the raw
field name, avoiding the double-negative confusion risk.

## Verification: no `int(value or 0)`-style coercion remains

```
grep -n "int(.*or 0)\|_int_pair\|(n_old or 0)" backend/app/services/risk_rules/azure.py
```
→ no matches. `_int_or_none()` is defined and available for any
count-based field, though Azure's 20-rule set has no "many X" count-
threshold Findings requiring it directly (unlike GCP's service-account-
key-count or Auth0's callback-count rules) — applied proactively for
future-proofing.

## Mock-shape (`old_value`/`prev_value`/`previous_value`/`prior_value`) verification

```
grep -n "old_value\|previous_value\|prior_value\|prev_value" backend/app/services/risk_rules/azure.py
```
→ all matches are `_get(change, "prev_value")` — production code was
written clean from the start, no `old_value`/`previous_value`/
`prior_value` usage found.

```
grep -rn "old_value\|previous_value\|prior_value" backend/tests/test_milestone77a_azure_drift_provider_foundation.py
```
→ one match, a docstring comment in the new
`test_classifier_reads_real_compute_diff_dict_shape_not_a_mock` test
naming the bug class being guarded against, not an actual field usage.

## Fixes made

1. **`backend/app/services/risk_rules/azure.py`** (new file) — 9
   record-type classifiers (`_classify_subscription_change` through
   `_classify_aks_cluster_change`) plus the `classify_azure_change`
   dispatcher. Built with `_int_or_none()` and the
   None-vs-empty-list-safe `_as_dict_list_or_none()` from the start
   (proactively applying both the PagerDuty and Google Cloud
   classification-QA lessons), plus dedicated NSG rule-list-diffing
   helpers (`_is_risky_public_rule`, `_added_rules`, `_expand_ports`,
   `_is_broad_destination_port`) mirrored from
   `security_rules/azure.py`.
2. **`backend/app/services/risk_service.py`** — added the `azure_`
   prefix dispatch branch to `classify_change`, routing Azure changes to
   the new module instead of the Cloudflare DNS fallback; updated the
   module docstring's dispatch list.
3. **`backend/app/services/diff_service.py`** — added
   `_AZURE_TRACKED_FIELDS_BY_TYPE` (all 9 record types) and wired the
   `azure_` prefix into `_tracked_fields_for`. Updated the function's
   docstring.
4. **`backend/tests/test_milestone77a_azure_drift_provider_foundation.py`**
   — added `TestAzureDiffTrackedFields` (5 tests) and
   `TestAzureRiskClassifier` (24 tests, including a dispatch-level
   regression test, a dict-shaped mock-bug-prevention test, and
   dedicated NSG list-diffing tests across critical/high/low/unknown-
   baseline cases); added a dedicated forbidden-wording test for the new
   `risk_rules/azure.py` module, matching this file's existing per-module
   test pattern.
5. **`backend/tests/reports/azure_detection_matrix.md`** — this report.

No changes were made to `security_rules/azure.py`, the four backend
registries, or the frontend catalog — all were already correct and in
perfect 20/20 parity with zero severity mismatches.

## Not fixed in this pass (explicitly out of scope)

- **Broad public principal (category B)** — no Azure RBAC equivalent to
  GCP's `allUsers`/Auth0's public IAM member exists; not invented.
- **Storage/container-level public access (category D/G)** — only the
  account-level `allow_blob_public_access` toggle is fetched; no
  per-container endpoint is called.
- **SQL firewall broad-range detection (category J)** — only an
  aggregate count and the "Allow Azure services" boolean exist; no
  per-rule IP-range data is modeled.
- **SQL auditing/threat detection (category K)** — no such API is
  called by this connector.
- **AKS workload identity (category O)** — no
  `workloadIdentityConfig`-equivalent field exists in this connector's
  AKS schema.
- **Diagnostic logging/sink posture as a drift record (category P)** —
  Activity Log *ingestion* exists as a separate M77D system, but no
  drift-tracked "diagnostic settings" record type exists.
- **`azure_storage_account.supports_https_traffic_only` and
  `azure_app_service.client_cert_enabled` Security Findings** (category
  S) — both fields are fetched and now diff-tracked with sensible Change
  severities, but no new Security Finding rule was added for either, per
  established precedent deferring new-rule decisions to a follow-up
  classification-QA pass.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone77a_azure_drift_provider_foundation.py -q
# 139 passed

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "azure"
# 668 passed, 16668 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*azure* -q
# 666 passed
```

No frontend files were touched in this pass — registries and the
frontend catalog were already in perfect 20/20 parity — so
`npx tsc --noEmit` was not run.
