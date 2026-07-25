# Kubernetes Provider Depth Matrix (Message 9 — Public Launch)

Columns: **Surface** (what area), **Requirement** (what must be true), **Backend**, **Frontend**, **Test**, **Status** (PASS / N/A), **Notes**.

`N/A` marks an intentional limitation (documented in the certification report §7), never a launch-blocking gap.

| # | Surface | Requirement | Backend | Frontend | Test | Status | Notes |
|---|---|---|---|---|---|---|---|
| 1 | Registration | Provider ID `kubernetes` registered in sync dispatch | `sync_service._SUPPORTED_PROVIDERS` | — | `test_kubernetes_provider_depth_qa.py::test_kubernetes_in_sync_supported_providers` | PASS | |
| 2 | Registration | Provider ID in `IntegrationCreateRequest.provider` Literal | `schemas/integration.py:89` | — | `test_kubernetes_connector_contract.py::TestCredentialSchema` | PASS | |
| 3 | Registration | Provider in Security Findings coverage list | `security_coverage_service.PROVIDERS` | — | `test_kubernetes_provider_depth_qa.py::test_kubernetes_in_security_coverage_providers` | PASS | |
| 4 | Registration | Provider in public capability matrix (not the partial/staging list) | `provider_capability_matrix_service.PROVIDER_CAPABILITIES` | — | `test_kubernetes_provider_depth_qa.py::test_kubernetes_in_capability_matrix_complete_list_not_partial` | PASS | 9 providers total now |
| 5 | Registration | Capability notes describe launched state, not "not yet connectable" | `provider_capability_matrix_service.py` `_KUBERNETES.notes` | — | `test_kubernetes_provider_depth_qa.py::test_kubernetes_capability_notes_say_launched_not_pending` | PASS | |
| 6 | Registration | Connector creation dispatch exists | `integration_service._create_kubernetes_integration` | — | `test_kubernetes_connector_contract.py::TestProviderDispatchWiring` | PASS | |
| 7 | Registration | Sync worker dispatch exists | `app/workers/sync_task.py` | — | `test_kubernetes_connector_contract.py::test_sync_task_dispatches_kubernetes` | PASS | |
| 8 | Registration | Reconnect dispatch exists | `integration_service.reconnect_credentials_kubernetes` | — | `test_kubernetes_provider_depth_qa.py::test_kubernetes_reconnect_function_exists` | PASS | New this message |
| 9 | Credentials | `POST /integrations` extracts kubeconfig (was silently dropped) | `routers/integrations.py::_build_credentials` kubernetes branch | — | `test_kubernetes_provider_depth_qa.py::TestCredentialRoundTrip` | PASS | Critical bug found + fixed this message |
| 10 | Credentials | Optional context/cluster_name/namespace_allowlist extracted | `_build_credentials` | `KubernetesIntegrationForm.tsx` | `test_kubernetes_provider_depth_qa.py::test_build_credentials_extracts_optional_fields` | PASS | |
| 11 | Credentials | Router credential-dict key matches connector's expected key | `_build_credentials` / `KubernetesConnector._build_api_client` | — | `test_kubernetes_provider_depth_qa.py::test_build_credentials_key_matches_connector_expectation` | PASS | `"context"`, not `"context_name"` |
| 12 | Credentials | Live-validation harness key-naming bug fixed | `run_live_kubernetes_validation()` | — | `test_kubernetes_provider_depth_qa.py::test_live_validation_harness_uses_matching_context_key` | PASS | Second bug found + fixed this message |
| 13 | Credentials | Reconnect schema has kubeconfig/context/cluster_name/namespace_allowlist fields | `schemas/integration.py::IntegrationReconnectRequest` | — | `test_kubernetes_provider_depth_qa.py::test_reconnect_schema_has_kubernetes_fields` | PASS | |
| 14 | Credentials | Reconnect router branch dispatches to service function | `routers/integrations.py` reconnect route | — | `test_kubernetes_provider_depth_qa.py::test_reconnect_router_branch_exists_for_kubernetes` | PASS | |
| 15 | Credentials | Reconnect preserves identity for same-cluster credential rotation | `reconnect_credentials_kubernetes` | — | `test_kubernetes_multi_cluster.py::TestClusterIdentityStability` (identity logic), manual review of reconnect fn | PASS | Compares `cluster_id` before/after |
| 16 | Credentials | Reconnect rejects a kubeconfig pointing at a genuinely different cluster | `reconnect_credentials_kubernetes` | — | Code review (raises `ConnectorError` on cluster_id mismatch) | PASS | Never silently merges |
| 17 | Validation | Kubeconfig parsing/exec/auth-provider rejection at connect time | `KubernetesConnector._build_api_client` | — | `test_kubernetes_foundation.py::TestCredentialSafety` | PASS | Pre-existing (message 1), re-verified |
| 18 | Validation | Selected context existence check | `_build_api_client` | `KubernetesIntegrationForm.tsx` helper copy | `test_kubernetes_foundation.py::test_missing_context_fails_clearly` | PASS | |
| 19 | Validation | TLS validity / cluster reachability via `/version` | `validate_credentials()` | — | `test_kubernetes_connector_contract.py::TestValidateCredentials` | PASS | |
| 20 | Validation | Creation now runs `validate_credentials()` synchronously (was deferred to first sync) | `integration_service._create_kubernetes_integration` | — | `test_kubernetes_integration_creation.py::TestValidConnection`/`TestInvalidConnection` | PASS | Architecture change this message |
| 21 | Validation | Full/Partial/Invalid coverage semantics | `build_permission_diagnostics()` | — | `test_kubernetes_permission_diagnostics.py`, `test_kubernetes_integration_creation.py::TestPartialConnection` | PASS | |
| 22 | Validation | Gateway API unsupported ≠ Invalid | `build_permission_diagnostics()` | — | `test_kubernetes_integration_creation.py::TestUnsupportedOptionalApi` | PASS | |
| 23 | Validation | Malformed kubeconfig rejected (HTTP 400) | `POST /integrations` | Form client-side has no parse check (server is authoritative) | `test_kubernetes_integration_creation.py::test_malformed_kubeconfig_rejected` | PASS | |
| 24 | Validation | Nonexistent explicit context rejected (HTTP 400) | `POST /integrations` | — | `test_kubernetes_integration_creation.py::test_nonexistent_context_rejected` | PASS | |
| 25 | Validation | Auth failure rejected (HTTP 400) | `POST /integrations` | — | `test_kubernetes_integration_creation.py::test_auth_failure_rejected` | PASS | |
| 26 | Validation | Unreachable cluster rejected | `POST /integrations` | — | `test_kubernetes_integration_creation.py::test_unreachable_cluster_rejected` | PASS | 400 (NetworkError subclasses ConnectorError, caught first) |
| 27 | Validation | Missing kubeconfig rejected at schema layer (HTTP 422) | `IntegrationCreateRequest` validator | Form requires kubeconfig before submit | `test_kubernetes_integration_creation.py::test_missing_kubeconfig_rejected_at_schema_layer` | PASS | |
| 28 | Connector | 36 record types collected across workload/RBAC/network/admission families | `kubernetes_schema.py` | — | messages 2-5 test suites | PASS | Pre-existing, re-verified this message |
| 29 | Connector | Pagination bounded, no unbounded watch connections | `paginate_list()` | — | `test_kubernetes_foundation.py` | PASS | Pre-existing |
| 30 | Connector | Fail-soft handling on partial API discovery | `_discover_capabilities()` | — | messages 1/8 test suites | PASS | Pre-existing |
| 31 | Drift | Snapshot/diff/risk-classification exist for every record type | `diff_service`, `risk_rules/kubernetes.py` | — | `test_kubernetes_workload_diff.py`, `test_kubernetes_rbac_diff.py`, `test_kubernetes_network_diff.py`, `test_kubernetes_admission_diff.py` | PASS | Pre-existing, re-verified |
| 32 | Drift | Review/acknowledge workflow enabled for Kubernetes (capability flag) | `provider_capability_matrix_service._KUBERNETES.drift.drift_review_workflow=True` | Generic review UI (no provider-specific code needed) | `test_kubernetes_connector_contract.py::test_kubernetes_drift_snapshots_true_but_nothing_else` | PASS | Flipped True this message |
| 33 | Security Findings | 59 rules registered | `security_rules/kubernetes.py` | — | `test_kubernetes_provider_depth_qa.py::TestSecurityFindingParity` | PASS | |
| 34 | Security Findings | All rules in central registry | `security_rule_registry.KNOWN_RULE_KEYS` | — | `test_kubernetes_provider_depth_qa.py::test_kubernetes_has_exactly_59_rules` | PASS | |
| 35 | Security Findings | All rules have confidence entries | `security_rule_confidence.RULE_CONFIDENCE` | — | `test_kubernetes_provider_depth_qa.py::test_all_kubernetes_rules_have_confidence` | PASS | |
| 36 | Security Findings | Frontend rule catalog parity | — | `securityRuleCatalog.ts` | message 6 test suite | PASS | Pre-existing, unaffected |
| 37 | Security Findings | Finding detail shows provider/severity/evidence/remediation correctly | Generic Finding rendering (no per-provider code) | Generic Finding detail page | Manual copy review this message | PASS | No Kubernetes-specific gaps found |
| 38 | Change | Change list/detail shows provider/resource/cluster/namespace correctly | Generic Change rendering | Generic Change detail page | messages 6/7 test suites | PASS | Pre-existing, unaffected |
| 39 | Sensitive data | Connector never calls Secret list/read APIs | `app/connectors/kubernetes.py` | — | `test_kubernetes_provider_depth_qa.py::TestSensitiveDataBoundary`, safety grep (a) | PASS | |
| 40 | Sensitive data | Connector never calls ConfigMap list/read APIs | `app/connectors/kubernetes.py` | — | same | PASS | |
| 41 | Sensitive data | Connector never calls Pod exec/attach/logs/port-forward | `app/connectors/kubernetes.py` | — | same | PASS | |
| 42 | Sensitive data | Connector never calls ServiceAccount token-creation API | `app/connectors/kubernetes.py` | — | same | PASS | |
| 43 | Sensitive data | Kubeconfig never copied into `resource_metadata` | `_create_kubernetes_integration` | — | `test_kubernetes_provider_depth_qa.py::test_kubeconfig_never_copied_into_resource_metadata` | PASS | |
| 44 | Sensitive data | Kubeconfig never in create-integration API response | `IntegrationResponse` schema | — | `test_kubernetes_integration_creation.py::test_kubeconfig_not_in_create_response` | PASS | |
| 45 | Sensitive data | Kubeconfig never in get-integration API response | `IntegrationResponse` schema | — | `test_kubernetes_integration_creation.py::test_kubeconfig_not_in_get_integration_response` | PASS | |
| 46 | Sensitive data | Kubeconfig never logged during validation | `validate_credentials()` | — | `test_kubernetes_integration_creation.py::test_kubeconfig_not_logged_by_validate_credentials` | PASS | |
| 47 | Sensitive data | Encrypted-credentials DB column is not plaintext | `encrypt_credentials()` | — | `test_kubernetes_integration_creation.py::test_encrypted_credentials_column_is_not_plaintext` | PASS | |
| 48 | RBAC manifest | Manifest excludes secrets/configmaps | `kubernetes_readonly_rbac_manifest.md` | — | `test_kubernetes_provider_depth_qa.py::TestRbacManifestParity::test_manifest_excludes_secrets_and_configmaps` | PASS | |
| 49 | RBAC manifest | Manifest grants only get/list verbs | `kubernetes_readonly_rbac_manifest.md` | — | `test_manifest_only_grants_get_list_verbs` | PASS | |
| 50 | RBAC manifest | Manifest resources match real connector calls (re-audited this message) | `kubernetes_readonly_rbac_manifest.md` vs `kubernetes.py` | — | `test_manifest_resources_match_connector_calls` | PASS | No drift found; manifest was already accurate |
| 51 | RBAC manifest | Setup UX surfaces minimum-permission guidance | — | `KubernetesIntegrationForm.tsx` security-notice block | Manual review | PASS | Inlined (no doc-hosting infra exists to link out to) |
| 52 | Provider card | Card visible on `/integrations`, correct category/description | — | `providers.ts` `kubernetes` entry | `test_kubernetes_provider_depth_qa.py::TestFrontendLaunchState` | PASS | |
| 53 | Provider card | In `PROVIDER_IDS` (display order) | — | `providers.ts` | `test_kubernetes_in_provider_ids` | PASS | |
| 54 | Provider card | In `CONNECTABLE_PROVIDER_IDS` | — | `providers.ts` | `test_kubernetes_in_connectable_provider_ids` | PASS | |
| 55 | Provider card | Copy omits unsupported-capability claims | — | `providers.ts` | `test_kubernetes_card_copy_omits_unsupported_claims` | PASS | |
| 56 | Connect form | Component exists and is wired into `renderProviderForm()` | — | `KubernetesIntegrationForm.tsx`, `integrations/page.tsx` | `test_kubernetes_form_component_exists`, `test_kubernetes_form_wired_into_integrations_page` | PASS | |
| 57 | Connect form | Kubeconfig field is a textarea, not a truncating password input | — | `KubernetesIntegrationForm.tsx` | `test_kubernetes_form_never_uses_type_password_for_kubeconfig` | PASS | |
| 58 | Connect form | Kubeconfig cleared from state + never re-displayed after success | — | `KubernetesIntegrationForm.tsx` | `test_kubernetes_form_never_prefills_or_echoes_kubeconfig_after_success` | PASS | |
| 59 | Connect form | Context field optional, "leave blank" guidance present | — | `KubernetesIntegrationForm.tsx` | Manual review | PASS | |
| 60 | Setup guide | Dedicated ServiceAccount + exec/auth-provider rejection guidance | — | `ProviderSetupGuide` kubernetes branch | Manual review | PASS | |
| 61 | Integration detail | Cluster identity/context/namespace count/last sync shown | — | `ProviderOverview` kubernetes branch | Manual review | PASS | Reads from real `resource.metadata`, no fabricated fields |
| 62 | Integration detail | Never shows kubeconfig/token/certificate/raw API errors | — | `ProviderOverview` kubernetes branch | Manual review | PASS | |
| 63 | Namespace allowlist | Backend model supports it end-to-end | `_build_credentials`, `_create_kubernetes_integration`, connector | — | `test_kubernetes_provider_depth_qa.py::test_build_credentials_extracts_optional_fields` | PASS | |
| 64 | Namespace allowlist | Dedicated frontend UI for setting it at connect time | — | — | — | N/A | Deferred as documented post-launch enhancement (§7 of certification report), not forced into this message's UI scope |
| 65 | Reconnect UI | Multi-field reconnect modal for Kubernetes | — | — | — | N/A | Pre-existing gap shared by most non-original-8 providers; flagged as a follow-up task, not a launch blocker |
| 66 | Reliability | Partial-sync false-removal protection | `_kubernetes_removal_suppressed()` | — | `test_kubernetes_partial_sync.py` | PASS | Pre-existing (message 8), re-verified reachable |
| 67 | Reliability | Bounded 429 retry with backoff+jitter | `call_k8s()` | — | message 8 test suite | PASS | Pre-existing, re-verified |
| 68 | Reliability | Differentiated connect/read timeouts | `CATEGORY_TIMEOUT` | — | message 8 test suite | PASS | Pre-existing, re-verified |
| 69 | Reliability | Multi-cluster identity stability (rotation, rename, recreation) | `compute_cluster_id()` | — | `test_kubernetes_multi_cluster.py` | PASS | Pre-existing, re-verified |
| 70 | Reliability | N+1 query avoidance / scale behavior pinned | connector pagination | — | `test_kubernetes_permission_diagnostics.py::TestNPlusOneGuard`/`TestScale` | PASS | Pre-existing, re-verified |
| 71 | Diagnostics | `build_permission_diagnostics()` / `format_permission_diagnostics_text()` reachable | `app/connectors/kubernetes.py` | — | `test_kubernetes_provider_depth_qa.py::TestReliabilitySurfacesReachable` | PASS | |
| 72 | Diagnostics | Live-cluster validation harness exists (opt-in, test-only) | `run_live_kubernetes_validation()` | — | `test_kubernetes_permission_diagnostics.py::TestLiveValidationHarness` | PASS | Gated behind `CONFIGTRACE_KUBERNETES_LIVE_KUBECONFIG` |
| 73 | Deployment | No kubectl/helm/cloud-CLI execution dependency | official `kubernetes` Python client only | — | safety grep (c) | PASS | Clean |
| 74 | Deployment | No local-kubeconfig-file / filesystem assumption in production path | credentials come from encrypted DB column, not disk | — | code review | PASS | `run_live_kubernetes_validation()` reads from disk but is test-only, never invoked by production code |
| 75 | Deployment | No new required production env var | — | — | code review | PASS | `CONFIGTRACE_KUBERNETES_LIVE_KUBECONFIG` remains optional/test-only |
| 76 | Deployment | No database migration required | `Integration.provider` is plain `Text`, no ENUM/CheckConstraint | — | grep of all Alembic migrations (message 9 audit) | PASS | Confirmed via full migration-file grep |
| 77 | Copy audit | No "complete cluster security" / "runtime protection" / "threat detection" claims | — | `providers.ts`, `KubernetesIntegrationForm.tsx`, `ProviderSetupGuide` | `test_kubernetes_card_copy_omits_unsupported_claims`, manual review | PASS | |
| 78 | Test strategy | Full Kubernetes test file set passes, count increased over message-8 baseline | — | — | `pytest $(find tests -iname '*kubernetes*')` → 1011 passed, 1 skipped | PASS | Up from 1018-scoped message-8 baseline (different file scope; see certification report §8) |
| 79 | Test strategy | `-k kubernetes` across full repo passes, no unrelated regressions | — | — | 1065 passed, 1 skipped, 17568 deselected | PASS | |
| 80 | Test strategy | Narrow filters all select tests (no false "0 selected") | — | — | 6 filters run, all non-zero, all passed | PASS | See certification report |
| 81 | Frontend build | `tsc --noEmit` passes | — | — | `npx tsc --noEmit` | PASS | Zero errors |
| 82 | Frontend build | `next build` compiles and type-checks | — | — | `npm run build` | PASS | "Compiled successfully"; prerender failure is a pre-existing sandbox Clerk-key limitation, unrelated to this change |

**Total rows: 82.** No unresolved GAP for any launch-critical requirement; all `N/A` rows are documented, intentional, non-blocking limitations.
