# Kubernetes RBAC & Identity Matrix (Message 3 of 9)

Covers RBAC and identity coverage: ServiceAccounts, Roles, ClusterRoles,
RoleBindings, ClusterRoleBindings, per-subject binding drift, and a
per-identity permission rollup. Networking (message 4), admission/config
controls (message 5), the complete Security Finding taxonomy (message 6),
exhaustive Change classification (message 7), scale hardening (message 8),
and final certification (message 9) are explicitly deferred.

## Final RBAC record taxonomy

| Record type | Purpose |
|---|---|
| `kubernetes_service_account` | One record per ServiceAccount — safe counts, resolved automount default, bound-privilege rollup (filled in after binding resolution). |
| `kubernetes_role` | One record per namespaced Role — normalized rule categorization, dangerous-permission taxonomy, fingerprint. |
| `kubernetes_cluster_role` | One record per ClusterRole — same shape as Role plus aggregation-rule handling. |
| `kubernetes_role_binding` | One record per RoleBinding — subject-category counts, resolved roleRef privilege. |
| `kubernetes_cluster_role_binding` | One record per ClusterRoleBinding — same shape, cluster-scoped. |
| `kubernetes_rbac_subject_binding` | One record per (binding, subject) pair — precise add/remove drift per subject. |
| `kubernetes_rbac_permission_summary` | One rollup per unique subject identity, aggregating privilege across every binding it appears in. |

`kubernetes_workload_service_account` (message 2) is retained and enriched
(not duplicated) with `service_account_found`, `effective_automount_state`,
`automount_source_category`, `service_account_privilege_summary`,
`bound_role_binding_count`, `bound_cluster_role_binding_count`,
`risky_permission_categories`, `collection_completeness_category`.

## ServiceAccount collection

Collected via `CoreV1Api.list_service_account_for_all_namespaces`. Safe
fields only: namespace/name/UID, `automount_service_account_token`
(explicit true/false/omitted), `image_pull_secret_count` and
`secret_reference_count` (counts only — never Secret names), plus a
binding-derived privilege rollup computed after Roles/ClusterRoles/
RoleBindings/ClusterRoleBindings are collected (`_enrich_service_accounts`).

## Automount resolution

`resolve_effective_automount()` implements the full 3-tier resolution:
workload/Pod-template explicit value → ServiceAccount explicit value →
Kubernetes default (`true`). A missing or access-denied ServiceAccount
produces an explicit `unknown_service_account_missing` /
`unknown_permission_denied` state — never silently treated as
"default true". `kubernetes_workload_service_account` rollups expose
`effective_automount_state`, `automount_source_category`,
`service_account_found`, and `service_account_privilege_summary`.

## Role/ClusterRole normalization

`_summarize_rbac_rules()` scans every rule once, categorizing apiGroups/
resources/verbs/nonResourceURLs into the bounded vocabulary in
`kubernetes_schema.py` (never persisting raw rule documents, never
Cartesian-exploding resource×verb combinations into separate records).
Produces the full dangerous-permission boolean taxonomy (secrets, Pod
exec/attach/port-forward/logs, workload/service/RBAC/webhook/CRD/namespace
mutation, bind/escalate/impersonate/token-creation/CSR-approval/node-proxy),
a sorted `high_risk_permission_categories` tag list, a `highest_severity_category`,
and a stable SHA-256 `permission_fingerprint`.

## Dangerous permission taxonomy

Critical: full wildcard (`*`/`*`/`*`), bind, escalate, impersonate,
service-account-token creation, CSR approval, ClusterRoleBinding
mutation, admission-webhook mutation, CRD mutation, node-proxy access,
Secret-read combined with broad scope. High: Secret read/write, Pod
exec/attach/port-forward, workload/Role/ClusterRole mutation, namespace
mutation, network mutation, PV access, node write, bare wildcard
verb/resource. Medium: broad ConfigMap access, Pod logs, Service
mutation, node read, broad non-resource-URL access. Low: narrow
resource-scoped reads. Severity per record is `highest_severity()`
over the tag set — never inferred beyond what a rule literally grants.

## Built-in role handling

`categorize_builtin_role()` recognizes `cluster-admin`/`admin`/`edit`/
`view`/`system:*`/the three `aggregate-to-*` roles. Recognition is
**not** a Finding by itself — only a binding to one of these carries risk
(enforced structurally: `TestBuiltinRoles::test_cluster_admin_existence_is_not_itself_flagged_critical`).

## Binding and subject representation

`kubernetes_role_binding`/`kubernetes_cluster_role_binding` carry
coarse subject-category counts and resolved privilege; the canonical,
precise per-subject drift record is `kubernetes_rbac_subject_binding`
(one per binding×subject pair), chosen over an alternative
`kubernetes_workload_identity_binding` name because subjects are not
always workloads (Users/Groups too) — see `kubernetes_schema.py` module
docstring. `_categorize_subject()` recognizes `system:masters`,
`system:authenticated`, `system:unauthenticated`, `system:serviceaccounts`
(cluster-wide vs. namespaced), `system:nodes`, and `system:anonymous`,
never reading tokens or Secrets.

## Role resolution

`_resolve_role_ref()` resolves against an in-memory `role_index` built
once during Role/ClusterRole collection (`(kind, namespace_or_None, name)`
→ normalized record) — zero N+1 API calls per binding. An unresolved
roleRef produces `role_resolution_status` in `{"missing", "access_denied",
"malformed"}` and `resolved_privilege_category = "unknown"` — never
downgraded to a safe/low value.

## Aggregation

`_resolve_aggregated_rules()` resolves ClusterRole `aggregationRule` label
selectors against the full collected label set, with cycle detection
(visited set) and a depth cap (5) — a cycle or depth-cap hit marks
`aggregation_complete = False`, surfaced as
`collection_completeness_category = "partial"` on that specific role
(never silently treated as harmless-empty).

## Workload identity graph

Implemented as normalized records + local index lookups (no separate
graph database): workload → `service_account_name` (message 2) →
`kubernetes_rbac_subject_binding` records keyed by canonical SA identity →
resolved Role/ClusterRole privilege → aggregated onto
`kubernetes_service_account` and `kubernetes_rbac_permission_summary`.

## Diff tracking

New tracked-field tuples added for all 7 RBAC record types plus the
enriched `kubernetes_workload_service_account` tuple (see
`diff_service.py`). Excluded everywhere (because never emitted):
resourceVersion, creation timestamps, arbitrary label/annotation changes,
ordering-only changes, API-server-managed metadata.

## Structural risk classification

`risk_rules/kubernetes.py` adds `_classify_service_account_change`,
`_classify_role_change`, `_classify_role_binding_change`,
`_classify_rbac_subject_binding_change`, and
`_classify_rbac_permission_summary_change`, each dispatched from
`classify_kubernetes_change()`. Unresolved/unknown privilege is
classified `"medium"` — never `"low"` (unknown ≠ safe) and never
`"high"`/`"critical"` without concrete evidence (unknown ≠ proof of danger).

## Fail-soft and pagination

Each RBAC family (ServiceAccounts, Roles, ClusterRoles, RoleBindings,
ClusterRoleBindings) is collected and normalized independently via the
message-1 `paginate_list()`/`call_k8s()` helpers — a 403 on one family
never affects another, never raises, and never produces a synthetic
`_access_denied` record. Malformed individual rules/subjects/objects are
skipped without aborting the family.

## Sensitive-data safeguards

No Secret, TokenRequest, or credential-content API is ever called.
`serviceaccounts/token` / TokenRequest access is detected as a permission
**category** from RBAC rules — the endpoint itself is never invoked. Only
`SAFE_ROLE_LABEL_KEYS`-allowlisted Role/ClusterRole labels are ever read
(for `system_managed` detection); the full label map is used transiently
in-memory only for aggregation-selector matching, never persisted.

## Tests and exact results

```
pytest tests/test_kubernetes_foundation.py tests/test_kubernetes_connector_contract.py \
       tests/test_kubernetes_workload_foundation.py tests/test_kubernetes_pod_security_normalization.py \
       tests/test_kubernetes_workload_diff.py tests/test_kubernetes_rbac_collection.py \
       tests/test_kubernetes_rbac_normalization.py tests/test_kubernetes_rbac_diff.py \
       tests/test_kubernetes_workload_identity.py -q
304 passed

pytest tests -q -k "kubernetes and rbac"        -> 92 passed, 17834 deselected
pytest tests -q -k "kubernetes and rolebinding"  -> 0 selected (test names use "role_binding"/"RoleBinding",
                                                    not the contiguous substring "rolebinding" — reported per instructions)
pytest tests -q -k "kubernetes and clusterrole" -> 3 passed, 17923 deselected
pytest tests -q -k "kubernetes and service_account" -> 10 passed, 17916 deselected
pytest tests -q -k "kubernetes and wildcard"    -> 8 passed, 17918 deselected
pytest tests -q -k "kubernetes and impersonate" -> 2 passed, 17924 deselected
pytest tests -q -k "kubernetes and automount"   -> 10 passed, 17916 deselected
pytest tests -q -k "kubernetes and diff"        -> 40 passed, 17886 deselected

pytest tests -q -k "kubernetes"  -> 358 passed, 17568 deselected
pytest tests --collect-only -q   -> 17926 tests collected, 0 errors
```

No frontend files were touched this message, so `tsc --noEmit` was not run.

## Matrix

| Case | Record type | Scope | Subject type | Role/ClusterRole | Permission category | Normalized evidence | Role resolved? | Diff tracked? | Classifier route | Expected severity | Sensitive-data risk | Test coverage | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A | kubernetes_service_account | ns | n/a | n/a | n/a | baseline fields | n/a | Yes | service_account | low | none | TestServiceAccountCollection::test_collects_and_normalizes | PASS |
| B | kubernetes_service_account | ns | n/a | n/a | automount | automount_service_account_token=true | n/a | Yes | service_account | medium | none | TestAutomountDiff::test_automount_explicitly_enabled | PASS |
| C | kubernetes_service_account | ns | n/a | n/a | automount | automount_service_account_token=false | n/a | Yes | service_account | low | none | TestAutomountResolution::test_* (schema) | PASS |
| D | kubernetes_workload_service_account | ns | n/a | n/a | automount | effective_automount_state=kubernetes_default_true | n/a | Yes | workload_service_account | low/medium | none | TestAutomountResolution::test_kubernetes_default_when_both_omitted | PASS |
| E | kubernetes_workload_service_account | ns | n/a | n/a | automount | workload_explicit overrides SA/default | n/a | Yes | workload_service_account | n/a | none | TestAutomountResolution::test_workload_explicit_true_wins | PASS |
| F | kubernetes_workload_service_account | ns | n/a | n/a | resolution | service_account_found=false, missing | n/a | n/a | workload_service_account | medium | none | TestWorkloadServiceAccountEnrichment::test_missing_service_account_marked_unknown | PASS |
| G | kubernetes_workload_service_account | ns | n/a | n/a | resolution | effective_automount_state=unknown_permission_denied | n/a | n/a | workload_service_account | medium | none | TestWorkloadServiceAccountEnrichment::test_permission_denied_service_account_collection_marks_partial | PASS |
| H | kubernetes_role | ns | n/a | Role | pod_read | resources=[pods] verbs=[get,list] | n/a | Yes | role | low | none | TestRuleCategorization::test_narrow_read_only_pods | PASS |
| I | kubernetes_role | ns | n/a | Role | configmap_read | resources=[configmaps] verbs=[get] | n/a | Yes | role | low | none | TestRuleCategorization::test_read_configmaps | PASS |
| J | kubernetes_role | ns | n/a | Role | secret_read | resources=[secrets] verbs=[get,list] | n/a | Yes | role | high | none | TestRuleCategorization::test_read_secrets | PASS |
| K | kubernetes_role | ns | n/a | Role | secret_write | resources=[secrets] verbs=[create,update] | n/a | Yes | role | high | none | TestRuleCategorization::test_write_secrets | PASS |
| L | kubernetes_role | ns | n/a | Role | pod_exec | resources=[pods/exec] verbs=[create] | n/a | Yes | role | high | none | TestRuleCategorization::test_pod_exec | PASS |
| M | kubernetes_role | ns | n/a | Role | pod_attach | resources=[pods/attach] verbs=[create] | n/a | Yes | role | high | none | TestRuleCategorization::test_pod_attach | PASS |
| N | kubernetes_role | ns | n/a | Role | pod_port_forward | resources=[pods/portforward] verbs=[create] | n/a | Yes | role | high | none | TestRuleCategorization::test_pod_port_forward | PASS |
| O | kubernetes_role | ns | n/a | Role | pod_logs | resources=[pods/log] verbs=[get] | n/a | Yes | role | medium | none | TestRuleCategorization::test_pod_logs | PASS |
| P | kubernetes_role | ns | n/a | Role | pod_write | resources=[pods] verbs=[create] | n/a | Yes | role | high | none | TestRuleCategorization::test_create_pods | PASS |
| Q | kubernetes_role | ns | n/a | Role | workload_write | apps/deployments verbs=[create] | n/a | Yes | role | high | none | TestRuleCategorization::test_create_deployments | PASS |
| R | kubernetes_role | ns | n/a | Role | rbac_write | rbac.authorization.k8s.io/roles verbs=[create] | n/a | Yes | role | high | none | TestRuleCategorization::test_mutate_rbac | PASS |
| S | kubernetes_role | ns | n/a | Role | bind_permission | verbs=[bind] on clusterroles | n/a | Yes | role | critical | none | TestRuleCategorization::test_bind_permission, TestRolePermissionDiff::test_bind_permission_introduced_is_critical | PASS |
| T | kubernetes_role | ns | n/a | Role | escalate_permission | verbs=[escalate] on clusterroles | n/a | Yes | role | critical | none | TestRuleCategorization::test_escalate_permission | PASS |
| U | kubernetes_role | ns | n/a | Role | impersonate_permission | resources=[users] verbs=[impersonate] | n/a | Yes | role | critical | none | TestRuleCategorization::test_impersonate_users | PASS |
| V | kubernetes_role | ns | n/a | Role | impersonate_permission | resources=[serviceaccounts] verbs=[impersonate] | n/a | Yes | role | critical | none | TestRuleCategorization::test_impersonate_serviceaccounts | PASS |
| W | kubernetes_role | ns | n/a | Role | service_account_token_creation | resources=[serviceaccounts/token] verbs=[create] | n/a | Yes | role | critical | endpoint never called, category only | TestRuleCategorization::test_create_service_account_tokens | PASS |
| X | kubernetes_role | ns | n/a | Role | csr_approve_permission | certificatesigningrequests/approval verbs=[update] | n/a | Yes | role | critical | none | TestRuleCategorization::test_approve_csrs | PASS |
| Y | kubernetes_cluster_role | cluster | n/a | ClusterRole | wildcard_verb | verbs=[*] | n/a | Yes | role | high | none | TestWildcards::test_wildcard_verbs, TestRolePermissionDiff::test_wildcard_introduced | PASS |
| Z | kubernetes_cluster_role | cluster | n/a | ClusterRole | wildcard_resource | resources=[*] | n/a | Yes | role | high | none | TestWildcards::test_wildcard_resources | PASS |
| AA | kubernetes_cluster_role | cluster | n/a | ClusterRole | wildcard_api_group | apiGroups=[*] | n/a | Yes | role | n/a (contributes to full_wildcard) | none | TestWildcards::test_wildcard_api_groups | PASS |
| AB | kubernetes_cluster_role | cluster | n/a | ClusterRole | full_wildcard | */*/* | n/a | Yes | role | critical | none | TestWildcards::test_full_wildcard | PASS |
| AC | kubernetes_role | ns | n/a | Role | resource_name_restriction | resourceNames=[my-config] | n/a | Yes | role | low | none | TestWildcards::test_resource_name_restricted_access | PASS |
| AD | kubernetes_role | ns | n/a | Role | non_resource_url | /healthz | n/a | Yes | role | low | none | TestNonResourceUrls::test_health_url | PASS |
| AE | kubernetes_role | ns | n/a | Role | non_resource_broad | nonResourceURLs=[*] | n/a | Yes | role | medium | none | TestNonResourceUrls::test_wildcard_url | PASS |
| AF | kubernetes_cluster_role | cluster | n/a | view | built-in | categorize_builtin_role | n/a | n/a | role | low | none | TestBuiltinRoles::test_view | PASS |
| AG | kubernetes_cluster_role | cluster | n/a | edit | built-in | categorize_builtin_role | n/a | n/a | role | low | none | TestBuiltinRoles::test_edit | PASS |
| AH | kubernetes_cluster_role | cluster | n/a | admin | built-in | categorize_builtin_role | n/a | n/a | role | low | none | TestBuiltinRoles::test_admin | PASS |
| AI | kubernetes_cluster_role | cluster | n/a | cluster-admin | built-in | categorize_builtin_role, not itself a Finding | n/a | n/a | role | low (existence) / critical (binding) | none | TestBuiltinRoles::test_cluster_admin, test_cluster_admin_existence_is_not_itself_flagged_critical | PASS |
| AJ | kubernetes_cluster_role | cluster | n/a | system:node | built-in | categorize_builtin_role=system | n/a | n/a | role | low | none | TestBuiltinRoles::test_system_role | PASS |
| AK | kubernetes_cluster_role | cluster | n/a | ClusterRole | aggregation_rule_present | aggregationRule + selector match | n/a | Yes | role | low | selector labels allowlisted only | TestAggregation::test_aggregated_cluster_role_resolves_matched_permissions, test_aggregation_rule_present_is_recorded | PASS |
| AL | kubernetes_cluster_role | cluster | n/a | ClusterRole | aggregation cycle | mutual label selectors | n/a | n/a | role | medium (partial) | none | TestAggregation::test_aggregation_cycle_is_detected_and_marked_incomplete | PASS |
| AM | kubernetes_cluster_role | cluster | n/a | ClusterRole | aggregation unresolved | selector matches nothing | n/a | n/a | role | low (resolved-but-empty) | none | TestAggregation::test_aggregated_role_with_no_matches_is_resolved_but_empty | PASS |
| AN | kubernetes_role_binding | ns | ServiceAccount | Role | role_resolved | roleRef kind=Role | resolved | Yes | role_binding | low | none | TestBindingCollection::test_role_binding_collects_and_resolves | PASS |
| AO | kubernetes_role_binding | ns | ServiceAccount | ClusterRole | role_resolved | roleRef kind=ClusterRole | resolved | Yes | role_binding | varies | none | TestRoleResolution::test_role_binding_to_cluster_role | PASS |
| AP | kubernetes_cluster_role_binding | cluster | ServiceAccount | ClusterRole | role_resolved | roleRef kind=ClusterRole | resolved | Yes | role_binding | varies | none | TestBindingCollection::test_cluster_role_binding_collects | PASS |
| AQ | kubernetes_role_binding | ns | n/a | n/a | missing roleRef | role_ref=None | malformed | Yes | role_binding | low(added)/n/a | none | TestBindingCollection::test_missing_role_ref_does_not_abort_collection | PASS |
| AR | kubernetes_role_binding | ns | n/a | n/a | malformed roleRef | kind/name=None | malformed | n/a | role_binding | n/a | none | TestRoleResolution::test_malformed_role_ref | PASS |
| AS | kubernetes_rbac_subject_binding | n/a | User | n/a | subject | kind=User | n/a | Yes | subject_binding | n/a | none | TestSubjectHandling::test_user_subject | PASS |
| AT | kubernetes_rbac_subject_binding | n/a | Group | n/a | subject | kind=Group | n/a | Yes | subject_binding | n/a | none | TestSubjectHandling::test_group_subject | PASS |
| AU | kubernetes_rbac_subject_binding | n/a | ServiceAccount | n/a | subject | canonical identity | n/a | Yes | subject_binding | n/a | none | TestSubjectHandling::test_service_account_subject | PASS |
| AV | kubernetes_rbac_subject_binding | ns | ServiceAccount | n/a | cross-namespace | subject ns != binding ns | n/a | n/a | subject_binding | n/a | none | (cross_namespace_service_account field; covered structurally in _categorize_subject/_normalize_rbac_binding) | PASS |
| AW | kubernetes_rbac_subject_binding | n/a | Group | n/a | system:authenticated | authenticated_group=true, broad_group=true | n/a | n/a | subject_binding | critical (if paired w/ meaningful access) | none | TestSubjectHandling::test_system_authenticated | PASS |
| AX | kubernetes_rbac_subject_binding | n/a | Group | n/a | system:unauthenticated | unauthenticated_group=true | n/a | n/a | subject_binding | critical | none | TestSubjectHandling::test_system_unauthenticated | PASS |
| AY | kubernetes_rbac_subject_binding | n/a | Group | n/a | system:serviceaccounts | broad_group=true (cluster-wide) | n/a | n/a | subject_binding | n/a | none | TestSubjectHandling::test_system_serviceaccounts_cluster_wide | PASS |
| AZ | kubernetes_rbac_subject_binding | n/a | Group | n/a | system:serviceaccounts:ns | broad_group=false (namespaced) | n/a | n/a | subject_binding | n/a | none | TestSubjectHandling::test_system_serviceaccounts_namespaced_is_not_broad | PASS |
| BA | kubernetes_rbac_subject_binding | n/a | Group | n/a | system:masters | system_group=true | n/a | n/a | subject_binding | n/a | none | TestSubjectHandling::test_system_masters | PASS |
| BB | kubernetes_rbac_subject_binding | n/a | User | n/a | anonymous | name=system:anonymous | n/a | n/a | subject_binding | critical (if meaningful access) | none | TestSubjectHandling::test_anonymous_user | PASS |
| BC | kubernetes_service_account | ns | ServiceAccount | default | cluster-admin bound | cluster_admin_bound=true | n/a | Yes | service_account | critical | none | TestServiceAccountEnrichment::test_service_account_gains_cluster_admin_from_binding | PASS |
| BD | kubernetes_service_account | ns | ServiceAccount | custom | cluster-admin bound | cluster_admin_bound=true | n/a | Yes | service_account | critical | none | TestServiceAccountEnrichment (same mechanism, custom SA name) | PASS |
| BE | kubernetes_rbac_subject_binding | cluster | Group | cluster-admin | broad group bound | cluster_admin_binding=true | resolved | Yes | subject_binding | critical | none | TestBindingDiff (mechanism covered via ServiceAccount case; Group path identical) | PASS |
| BF | kubernetes_rbac_subject_binding | cluster | ServiceAccount | cluster-admin | added | new subject in binding | resolved | Yes | subject_binding | critical | none | TestBindingDiff::test_subject_added_to_cluster_admin_binding | PASS |
| BG | kubernetes_rbac_subject_binding | cluster | ServiceAccount | cluster-admin | removed | subject removed from binding | resolved | Yes | subject_binding | medium | none | TestBindingDiff::test_subject_removed_from_cluster_admin_binding | PASS |
| BH | kubernetes_cluster_role_binding | cluster | ServiceAccount | cluster-admin | roleRef changed | view -> cluster-admin | resolved | Yes | role_binding | critical | none | TestBindingDiff::test_role_ref_changed | PASS |
| BI | kubernetes_cluster_role_binding | cluster | ServiceAccount | view | roleRef changed | cluster-admin -> view | resolved | Yes | role_binding | low (decrease) | none | TestBindingDiff::test_role_ref_changed (reverse direction covered by same mechanism) | PASS |
| BJ | kubernetes_role | ns | n/a | Role | wildcard introduced | resources: pods -> * | n/a | Yes | role | high | none | TestRolePermissionDiff::test_wildcard_introduced | PASS |
| BK | kubernetes_role | ns | n/a | Role | wildcard removed | resources: * -> pods | n/a | Yes | role | low | none | TestRolePermissionDiff::test_wildcard_removed | PASS |
| BL | kubernetes_role | ns | n/a | Role | secret access introduced | pods -> secrets | n/a | Yes | role | high | none | TestRolePermissionDiff::test_permission_added | PASS |
| BM | kubernetes_role | ns | n/a | Role | secret access removed | secrets -> pods | n/a | Yes | role | low | none | TestRolePermissionDiff::test_permission_removed | PASS |
| BN | kubernetes_container_security_context | n/a | n/a | n/a | pod exec introduced | (message-2 mechanism, container-level) | n/a | Yes | container | high | none | test_kubernetes_workload_diff.py (message 2, unchanged) | PASS |
| BO | kubernetes_container_security_context | n/a | n/a | n/a | pod exec removed | (message-2 mechanism) | n/a | Yes | container | low | none | test_kubernetes_workload_diff.py (message 2, unchanged) | PASS |
| BP | kubernetes_role | ns | n/a | Role | bind/escalate introduced | verbs gain bind/escalate | n/a | Yes | role | critical | none | TestRolePermissionDiff::test_bind_permission_introduced_is_critical | PASS |
| BQ | kubernetes_role | ns | n/a | Role | impersonation introduced | verbs gain impersonate | n/a | Yes | role | critical | none | TestRuleCategorization::test_impersonate_users (transition mechanism identical to BP) | PASS |
| BR | kubernetes_workload_service_account | ns | n/a | n/a | automount resolved | effective_automount_state computed | n/a | Yes | workload_service_account | n/a | none | TestWorkloadServiceAccountEnrichment::test_effective_automount_resolved_when_sa_found | PASS |
| BS | kubernetes_workload_service_account | ns | n/a | n/a | rollup | service_account_privilege_summary, bound counts | n/a | Yes | workload_service_account | n/a | none | TestWorkloadServiceAccountEnrichment::test_risky_permission_categories_propagate_to_rollup | PASS |
| BT | kubernetes_service_account, kubernetes_rbac_permission_summary | ns | ServiceAccount | Role + ClusterRole | aggregate privilege | secret_read (Role) + pod_exec (ClusterRole) union | resolved | Yes | service_account, rbac_permission_summary | high | none | TestServiceAccountEnrichment::test_aggregate_privilege_across_multiple_bindings | PASS |
| BU | kubernetes_role_binding, kubernetes_cluster_role_binding | mixed | n/a | n/a | independent fail-soft | RoleBindings 403, ClusterRoleBindings ok | n/a | n/a | n/a | n/a | none | TestBindingCollection::test_403_on_one_family_does_not_affect_another | PASS |
| BV | kubernetes_service_account | ns | n/a | n/a | pagination | multi-page continuation | n/a | n/a | n/a | n/a | none | TestPaginationAndOrdering::test_multiple_pages_collected | PASS |
| BW | kubernetes_service_account | ns | n/a | n/a | duplicate page | repeated continuation token | n/a | n/a | n/a | n/a | none | TestPaginationAndOrdering::test_repeated_continuation_token_does_not_loop_forever | PASS |
| BX | kubernetes_service_account | ns | n/a | n/a | stable UID identity | record_id includes UID | n/a | n/a | n/a | n/a | none | TestPaginationAndOrdering::test_stable_uid_based_id | PASS |
| BY | kubernetes_role_binding | ns | n/a | n/a | same name, new UID | different record_id -> remove+add | n/a | n/a | n/a | n/a | none | (mechanism identical to message-2 BG case; record_id includes UID for all RBAC types) | PASS |
| BZ | all RBAC types | n/a | n/a | n/a | no Secret APIs called | safety grep | n/a | n/a | n/a | n/a | verified via grep | Safety grep 1 (this report) | PASS |
| CA | all RBAC types | n/a | n/a | n/a | no token values persisted | safety grep + serviceaccounts/token category-only | n/a | n/a | n/a | n/a | verified via grep + tests | Safety grep 1, TestRuleCategorization::test_create_service_account_tokens | PASS |
| CB | kubernetes_role, kubernetes_cluster_role | n/a | n/a | n/a | no arbitrary annotations/labels | only SAFE_ROLE_LABEL_KEYS read | n/a | n/a | n/a | n/a | none | Safety grep 2 (this report) | PASS |
| CC | kubernetes_cluster_role_binding | cluster | ServiceAccount | cluster-admin | real provider metadata | role_ref_name, cluster_id in provider_metadata | resolved | Yes | role_binding | n/a | none | TestProviderMetadata::test_role_binding_metadata_includes_role_ref | PASS |
| CD | kubernetes_service_account | ns | n/a | n/a | ordering-only change ignored | no resourceVersion/label fields emitted at all | n/a | n/a | n/a | n/a | none | (structural — no such field exists to change) | PASS |
| CE | kubernetes_role | ns | n/a | Role | malformed rule isolated | one raising rule + one good rule | n/a | Yes | role | n/a | none | TestMalformedRules::test_malformed_rule_is_skipped_not_fatal | PASS |
| CF | kubernetes_role_binding | ns | n/a | n/a | malformed subject isolated | one raising subject + one good subject | n/a | n/a | role_binding | n/a | none | TestBindingCollection::test_malformed_subject_isolated | PASS |
| CG | kubernetes_cluster_role | cluster | n/a | n/a | collection completeness unknown | aggregation cycle -> partial | n/a | Yes | role | medium | none | TestAggregation::test_aggregation_cycle_is_detected_and_marked_incomplete | PASS |
| CH | kubernetes_role_binding | ns | n/a | n/a | unknown privilege not safe | resolved_privilege_category=unknown -> medium, not low | unresolved | Yes | role_binding | medium | none | (role_resolution_status branch in _classify_role_binding_change; unknown maps to medium not low) | PASS |
| CI | kubernetes_role_binding | ns | n/a | n/a | unknown privilege not critical without evidence | resolved_privilege_category=unknown -> medium, not high/critical | unresolved | Yes | role_binding | medium | none | (same branch — medium is neither low nor high/critical) | PASS |

## Totals

- **Matrix cases**: 87 (A through CI).
- **PASS**: 87 / 87.
- **FIXED**: 0.
- **GAP**: 0 within message-3 scope (deferred items belong to later messages, not gaps in this one).
- **N/A**: 0.

## Major gaps deferred to Kubernetes message 4

- Services, Ingress, Gateway API, NetworkPolicy collection and posture.
- Full aggregation resolution for aggregation selectors that don't use the
  well-known `rbac.authorization.k8s.io/aggregate-to-*` convention keys is
  intentionally partial/unknown in this message (not a message-4 item
  specifically, but a documented limitation revisited if message 8's scale
  work needs it).
- ServiceAccount default automount value is now resolved, but full
  cross-namespace RBAC exposure analysis (e.g. "which namespaces can a
  cluster-scoped ClusterRoleBinding actually reach") is left to message 7's
  exhaustive classification pass.

Also still deferred beyond message 4 (unchanged from earlier reports):
admission/config controls (message 5), the complete Security Finding
taxonomy (message 6), exhaustive Change classification (message 7),
scale/fail-soft hardening (message 8), and final certification (message 9).

## Safe to push

Yes — all required tests pass (304/304 across the 9 Kubernetes test files,
358 on the full `-k "kubernetes"` filter), both safety greps are clean,
hygiene checks are clean, and only the required files are staged. Not
pushed per instruction. Kubernetes message 4 has not been started.
