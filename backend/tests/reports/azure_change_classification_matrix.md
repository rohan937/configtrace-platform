# Azure change-classification QA report

Follow-up to `azure_detection_matrix.md` (commit `051fb06`). This pass audits
`app/services/risk_rules/azure.py` (change classification) against
`app/services/security_rules/azure.py` (Security Findings), stress-tests the
NSG list-diff logic, and resolves the two Change-only gaps documented in the
detection pass.

## Summary

1. **Tracked-fields-vs-classifier audit: clean.** Every field in
   `_AZURE_TRACKED_FIELDS_BY_TYPE` (9 record types, diff_service.py) has either
   a specific classification branch or an intentional generic-low fallthrough
   in `risk_rules/azure.py`. Zero accidentally-dropped fields, zero dead
   branches referring to fields the connector doesn't emit.
2. **Mock-shape audit: clean.** No `old_value`/`previous_value`/`prior_value`
   usage anywhere in `risk_rules/azure.py` or the Azure test files (the one
   textual hit is a regression-test docstring *naming* the bug class, not
   using the wrong field). A dedicated test builds a plain dict shaped exactly
   like real `compute_diff` output and asserts correct classification.
3. **Unknown-to-zero / list-None-vs-empty audit: clean.** Zero `(x or 0)`
   coercions anywhere in the module (confirmed by both manual review and a
   new `test_no_unknown_to_zero_coercion_pattern_in_source` regression test).
   `_int_or_none()` exists and is correctly implemented but is not currently
   invoked — Azure's 20 (now 21) Findings are boolean/category-string posture
   checks with no count-threshold rule, so there is nothing to call it on yet;
   it remains as intentional future-proofing, not dead-code cleanup.
   `_as_dict_list_or_none()` correctly preserves the None-vs-empty distinction
   for NSG `rules_summary` (verified below).
4. **Severity parity with Security Findings: aligned.** All specific
   classifier branches match their corresponding Finding's severity, using
   the established "combined-condition Finding → base-case Change severity"
   pattern for the 5 rules that require a second field the Change can't see
   (`azure_storage_public_network_access`/`azure_key_vault_public_network_access`/
   `azure_sql_public_network_access` → medium base; `azure_key_vault_purge_protection_disabled`
   → medium base; `azure_aks_private_cluster_enabled`→false → medium, not the
   Finding's high ceiling). `azure_role_assignment_broad_privilege`'s
   `role_definition_name` field is the one exception, kept at the Finding's
   worst case (high) because role assignments are effectively immutable in
   Azure (documented design note, unchanged from the detection pass).
5. **NSG list-diff logic: stress-tested and safe.** 9 new tests added
   covering `Internet`/`::/0` source literals, database ports beyond SSH/RDP
   (3306), destination port ranges expressed as a range string containing an
   admin port, removal of a broad-source rule (must not be high/critical),
   pure reordering of two benign rules (must not create false risk),
   malformed rule dicts missing keys (must not raise, must not overstate),
   Outbound direction (never flagged), and Deny access (never flagged). All
   pass.
6. **New Security Finding added:** `azure_storage_https_only_disabled` (high),
   a direct single-field analog of the existing `azure_app_service_https_disabled`
   rule, for `azure_storage_account.supports_https_traffic_only`. Registered
   across all 4 backend registries, the correlation-rules dict, the frontend
   catalog, and covered by 5 new Finding-level tests (positive/negative/unknown/
   registry-parity/Change-severity-parity).
7. **`client_cert_enabled` kept Change-only (not converted to a Finding).**
   Unlike HTTPS-only (which has a clear "usually on, this is a regression"
   story), client-certificate / mTLS auth is an opt-in App Service hardening
   feature with no sibling pattern anywhere in the 20-rule set — most
   correctly configured App Services never enable it, so a Finding would fire
   on the overwhelming majority of records with near-zero signal. Documented
   in the module comment; Change classification (medium on disable) is
   retained as-is.
8. **No misclassifications found.** No severity was too high, too low, or
   using generic/default wording where a specific classification was needed.

## Tracked-fields vs classifier-branch comparison

| Record type | Tracked fields | Specific branch | Generic-low fallthrough |
|---|---|---|---|
| azure_subscription | display_name, state, tenant_id, authorization_source | none (no Finding surface) | all 4 |
| azure_resource_group | location, provisioning_state, tag_keys | none (no Finding surface) | all 3 |
| azure_network_security_group | nsg_name, resource_group, location, rule_count, inbound_allow_rule_count, public_inbound_rule_count, rules_summary | rules_summary | other 6 |
| azure_storage_account | account_name, resource_group, location, kind, sku_name, allow_blob_public_access, public_network_access, minimum_tls_version, supports_https_traffic_only, shared_access_key_enabled, network_default_action | allow_blob_public_access, public_network_access, minimum_tls_version, supports_https_traffic_only, shared_access_key_enabled | other 6 |
| azure_key_vault | vault_name, resource_group, location, enable_rbac_authorization, public_network_access, soft_delete_enabled, purge_protection_enabled, access_policy_count, network_default_action | public_network_access, purge_protection_enabled, soft_delete_enabled, enable_rbac_authorization | other 5 |
| azure_role_assignment | scope_type, resource_group, role_definition_id, role_definition_name, principal_type, condition_present, created_on, updated_on | role_definition_name | other 7 |
| azure_app_service | app_name, resource_group, location, kind, https_only, public_network_access, client_cert_enabled, ftps_state, min_tls_version, auth_enabled, app_settings_count, connection_string_count | https_only, public_network_access, client_cert_enabled, ftps_state, min_tls_version | other 7 |
| azure_sql_server | server_name, resource_group, location, public_network_access, minimum_tls_version, azure_ad_only_authentication, firewall_rule_count, has_allow_azure_services_rule | public_network_access, minimum_tls_version | other 6 |
| azure_aks_cluster | cluster_name, resource_group, location, private_cluster_enabled, local_account_disabled, azure_rbac_enabled, network_plugin, network_policy, public_network_access, api_server_authorized_ip_range_count, authorized_ip_ranges_configured | private_cluster_enabled, local_account_disabled, network_policy | other 8 |

Result: **zero fields fall through unintentionally**; every generic-low
fallthrough is a metadata-only field with no Finding surface (name, location,
resource_group, counts with no threshold rule, etc).

## Classification matrix (representative cases)

| Case | Record type | Field | Old | New | Detected? | Current risk | Expected risk | Finding parity | Status |
|---|---|---|---|---|---|---|---|---|---|
| A1 | azure_role_assignment | role_definition_name | Reader | Owner | yes | high | high | matches (worst-case, documented exception) | PASS |
| A2 | azure_role_assignment | role_definition_name | Owner | Reader | yes | low | low (improvement) | N/A (Findings are current-state only) | PASS |
| A3 | azure_role_assignment | role_definition_name | Reader | (unknown) | yes | low | low | n/a | PASS |
| B1 | azure_storage_account | allow_blob_public_access | False | True | yes | high | high | azure_storage_public_blob_access (high) | PASS |
| B2 | azure_storage_account | public_network_access | Disabled | Enabled | yes | medium | medium (base case) | azure_storage_public_network_access (medium/high dynamic) | PASS |
| B3 | azure_storage_account | shared_access_key_enabled | False | True | yes | medium | medium | azure_storage_shared_key_enabled (medium) | PASS |
| B4 | azure_storage_account | supports_https_traffic_only | True | False | yes | high | high | **azure_storage_https_only_disabled (high) — added this pass** | PASS |
| B5 | azure_storage_account | minimum_tls_version | TLS1_2 | TLS1_0 | yes | medium | medium | azure_storage_weak_tls (medium) | PASS |
| B6 | azure_storage_account | allow_blob_public_access | True | (unknown) | yes | low | low (no overstatement) | n/a | PASS |
| D1 | azure_network_security_group | rules_summary | [] | [+SSH/*] | yes | high | high | azure_nsg_public_admin_ingress (high, SSH) | PASS |
| D2 | azure_network_security_group | rules_summary | [] | [+RDP/0.0.0.0/0] | yes | critical | critical | azure_nsg_public_admin_ingress (critical, RDP) | PASS |
| D3 | azure_network_security_group | rules_summary | [] | [+all-ports/Internet] | yes | critical | critical | azure_nsg_public_broad_ingress (critical) | PASS |
| D4 | azure_network_security_group | rules_summary | [] | [+MySQL 3306/0.0.0.0/0] | yes | critical | critical | azure_nsg_public_admin_ingress (critical, DB port) | PASS |
| D5 | azure_network_security_group | rules_summary | [+SSH/*] | [] | yes | low | low (improvement) | n/a | PASS |
| D6 | azure_network_security_group | rules_summary | (unknown) | [+RDP/0.0.0.0/0] | yes | critical | critical (current-state-only, no "added" claim) | n/a | PASS |
| D7 | azure_network_security_group | rules_summary | [rule_a, rule_b] | [rule_b, rule_a] (reordered) | yes | low | low (no false risk from reordering) | n/a | PASS |
| D8 | azure_network_security_group | rules_summary | [] | [malformed dict missing keys] | yes | low | low (no false high on malformed shape) | n/a | PASS |
| D9 | azure_network_security_group | rules_summary | [] | [Outbound Allow */*] | yes | low | low (Outbound never flagged) | n/a | PASS |
| D10 | azure_network_security_group | rules_summary | [] | [Inbound Deny */*] | yes | low | low (Deny never flagged) | n/a | PASS |
| F1 | azure_key_vault | purge_protection_enabled | True | False | yes | medium | medium (base case) | azure_key_vault_purge_protection_disabled (medium/high dynamic) | PASS |
| F2 | azure_key_vault | soft_delete_enabled | True | False | yes | medium | medium | azure_key_vault_soft_delete_disabled (medium) | PASS |
| F3 | azure_key_vault | public_network_access | Disabled | Enabled | yes | medium | medium (base case) | azure_key_vault_public_network_access (medium/high dynamic) | PASS |
| G1 | azure_app_service | https_only | True | False | yes | high | high | azure_app_service_https_disabled (high) | PASS |
| G2 | azure_app_service | client_cert_enabled | True | False | yes | medium | medium | Change-only (reviewed, documented — see item 7) | PASS |
| G3 | azure_app_service | ftps_state | Disabled | AllAllowed | yes | medium | medium | azure_app_service_ftp_enabled (medium) | PASS |
| E1 | azure_sql_server | public_network_access | Disabled | Enabled | yes | medium | medium (base case) | azure_sql_public_network_access (medium/high dynamic) | PASS |
| H1 | azure_aks_cluster | private_cluster_enabled | True | False | yes | medium | medium (base case, not Finding's high ceiling) | azure_aks_public_api_access (high, combined-condition) | PASS |
| H2 | azure_aks_cluster | local_account_disabled | True | False | yes | medium | medium | azure_aks_local_accounts_enabled (medium) | PASS |
| H3 | azure_aks_cluster | network_policy | azure | none | yes | medium | medium | azure_aks_network_policy_missing (medium) | PASS |
| K1 | (6 record types) | various | (value) | None/missing | yes | low, never high/critical | low | n/a | PASS |
| L1 | (all) | (all) | — | — | — | — | — | no forbidden wording anywhere | PASS |

Totals: 30 representative cases in this table, all PASS. Combined with the
existing 155 unit tests in `test_milestone77a_azure_drift_provider_foundation.py`
(139 baseline + 16 new this pass) and the 5 new Finding-level tests, no FAIL
or unresolved GAP remains. The one open item (G2, `client_cert_enabled`) is
resolved as an intentional design decision, not a gap.

## Design notes (carried over + new)

- NSG `rules_summary` unknown-baseline reaches the *same* severity as a
  confirmed "added" transition (current-state-only evaluation), because each
  rule dict carries the full risk signal (direction+access+source+dest-port)
  in one list entry — unlike a field that needs a second field to know the
  port.
- Five combined-condition Findings are approximated at base-case severity on
  the Change side (not the Finding's worst case) because the risky
  combination is not the common/expected configuration.
- `azure_role_assignment_broad_privilege`'s `role_definition_name` field is
  the one exception, kept at worst-case (high), because role assignments are
  effectively immutable in Azure — a "modified" event on this field is a rare
  defensive case, not the expected create/delete pattern.
- `supports_https_traffic_only` (storage) now has a backing Finding —
  it is a direct, low-effort single-field analog of the already-shipped
  `azure_app_service_https_disabled` rule, and HTTPS-only is Azure's own
  new-storage-account default, giving it a clear "usually on, this is a
  regression" story.
- `client_cert_enabled` (App Service) intentionally remains Change-only —
  it's an opt-in hardening feature with no sibling Finding pattern and no
  "usually on" baseline, so a Finding would be noisy with near-zero signal.

## Fixes made this pass

1. Added Security Finding `azure_storage_https_only_disabled` (high) in
   `security_rules/azure.py`, registered in `security_rule_registry.py`,
   `security_rule_pack.py`, `security_rule_confidence.py`,
   `security_coverage_service.py`, `security_signal_correlation_service.py`
   (`AZURE_CORRELATION_RULES`), and `frontend/src/lib/securityRuleCatalog.ts`.
2. Updated `risk_rules/azure.py`'s `supports_https_traffic_only` branch
   comment to reflect the new Finding backing (severity unchanged — was
   already correctly "high").
3. Updated `risk_rules/azure.py`'s `client_cert_enabled` branch comment to
   document the reviewed decision to keep it Change-only.
4. Updated hardcoded rule-count/rule-set assertions from 20→21 (or added the
   new key to the expected set) in `test_azure_provider_depth_qa.py`,
   `test_milestone77c_azure_security_expansion.py`,
   `test_milestone77f_azure_correlations.py`, `test_milestone77g_azure_demo_qa.py`,
   `test_milestone77h_azure_provider_depth_qa.py`.
5. Added a `supports_https_traffic_only: False` field to the storage-account
   synthetic risky record in `test_azure_provider_depth_qa.py`'s
   `_all_azure_findings()` fixture so the new rule fires in the
   "every rule fires" coverage test.
6. Added 16 new tests to `test_milestone77a_azure_drift_provider_foundation.py`:
   9 NSG list-diff stress tests, 5 Finding-level tests for the new rule, and
   2 count/threshold-safety regression tests.

No severity values, wording, or dispatch logic were changed beyond the new
rule and its two comment updates — the classifier was already correctly
built defensively in the detection-QA pass.

## Validation run

- `docker compose exec api pytest tests/test_milestone77a_azure_drift_provider_foundation.py -q` → **155 passed** (was 139; +16 new tests, 0 regressions).
- `docker compose exec api pytest -k "azure and risk" -q` → **25 passed**, 17311 deselected.
- `docker compose exec api pytest -k "azure and diff" -q` → **11 passed**, 17325 deselected.
- `docker compose exec api pytest -k "azure" -q` → **646 passed**, 37 skipped, 1 failed (pre-existing, unrelated — see below), 16668 deselected.
- `docker compose exec api pytest tests/test_azure_provider_depth_qa.py tests/test_milestone77c_azure_security_expansion.py tests/test_milestone77f_azure_correlations.py tests/test_milestone77g_azure_demo_qa.py tests/test_milestone77h_azure_provider_depth_qa.py tests/test_milestone77i_azure_cross_cloud_ux_polish.py -q` → **257 passed**, 35 skipped, 1 failed (same pre-existing issue).
- `npx tsc --noEmit` (frontend, run because `securityRuleCatalog.ts` changed) → **clean, no errors**.

**One pre-existing, unrelated failure**: `test_azure_provider_depth_qa.py::TestAzureCopySafety::test_network_attack_surface_softened` fails with
`FileNotFoundError: /backend/app/services/security_rules/azure.py` inside the
`docker compose exec api` environment. Verified via `git stash` that this
fails identically on the pre-change commit (`051fb06`) — the test's
`REPO_ROOT = Path(__file__).resolve().parents[2]` assumes a
`.../ConfigTrace/backend/tests/...` layout, but this container mounts the
backend app directly at `/app`, so the path resolves to a nonexistent
`/backend/...`. Not a regression from this pass; out of scope to fix (a
Docker Compose test-runner path assumption, unrelated to Azure classification
logic).

## Safety greps (scoped to touched files)

No unsafe phrase (`compromise confirmed`, `data leaked`, `breach detected`,
`storage exposed`, `key vault exposed`, `customer data exposed`, etc.) appears
in any code or copy path across the touched files. All grep hits are forbidden
-phrase test constants (lists of strings a test asserts are *absent*) or
docstring/comment prose describing what the copy must *not* claim.
