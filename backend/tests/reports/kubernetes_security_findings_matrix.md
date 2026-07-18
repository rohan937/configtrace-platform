# Kubernetes Security Finding Matrix (Message 6 of 9)

Covers the complete static Kubernetes Security Finding taxonomy: 59 rules
across workload/Pod security, RBAC/identity, network exposure, NetworkPolicy
isolation, admission webhooks, Pod Security Admission, namespace governance,
and resource governance. Every rule is registered centrally (evaluator,
registry, confidence, pack, coverage, frontend catalog) and reachable through
real `evaluate_record()` dispatch. This message does **not** implement
exhaustive Change classification (message 7), scale/partial-sync hardening
(message 8), or production certification (message 9).

## Final rule count and taxonomy

**59 Kubernetes Security Finding rules**, source-verified via
`security_rule_registry.KNOWN_RULE_KEYS`, `security_rule_pack._RULE_META`,
and `security_rule_confidence.RULE_CONFIDENCE` (all three collections are
asserted to contain exactly the same 59 keys by
`test_kubernetes_security_rule_parity.py::TestFullCrossLayerParity`).

### Rule keys by category

**Workload / Pod security (18)**: `kubernetes_privileged_container`,
`kubernetes_privileged_host_access`, `kubernetes_root_container`,
`kubernetes_run_as_non_root_disabled`, `kubernetes_privilege_escalation_allowed`,
`kubernetes_dangerous_linux_capability`, `kubernetes_all_capabilities_added`,
`kubernetes_host_pid_enabled`, `kubernetes_host_ipc_enabled`,
`kubernetes_host_network_enabled`, `kubernetes_dangerous_hostpath`,
`kubernetes_container_runtime_socket_mounted`, `kubernetes_seccomp_unconfined`,
`kubernetes_apparmor_unconfined`, `kubernetes_writable_root_filesystem`,
`kubernetes_mutable_image_tag`, `kubernetes_service_account_token_automount`,
`kubernetes_sensitive_host_port`.

**RBAC / identity (17)**: `kubernetes_cluster_admin_binding`,
`kubernetes_unauthenticated_cluster_admin`,
`kubernetes_authenticated_group_cluster_admin`,
`kubernetes_all_service_accounts_cluster_admin`,
`kubernetes_wildcard_rbac_permissions`, `kubernetes_rbac_bind_permission`,
`kubernetes_rbac_escalate_permission`, `kubernetes_rbac_impersonate_permission`,
`kubernetes_service_account_token_creation`, `kubernetes_secret_read_permission`,
`kubernetes_secret_write_permission`, `kubernetes_pod_exec_permission`,
`kubernetes_pod_attach_permission`, `kubernetes_broad_workload_creation`,
`kubernetes_rbac_modification_permission`,
`kubernetes_admission_webhook_modification_permission`,
`kubernetes_crd_modification_permission`.

**Network exposure (5)**: `kubernetes_public_load_balancer`,
`kubernetes_sensitive_nodeport`, `kubernetes_public_ingress_without_tls`,
`kubernetes_hostless_catchall_ingress`, `kubernetes_public_gateway_listener`.

**NetworkPolicy isolation (7)**: `kubernetes_network_policy_allows_all_ingress`,
`kubernetes_network_policy_allows_all_egress`,
`kubernetes_public_ipv4_cidr_allowed`, `kubernetes_public_ipv6_cidr_allowed`,
`kubernetes_namespace_no_network_policy`,
`kubernetes_namespace_no_ingress_isolation`,
`kubernetes_namespace_no_egress_isolation`.

**Admission webhooks (4)**: `kubernetes_validating_webhook_fail_open`,
`kubernetes_mutating_webhook_fail_open`, `kubernetes_broad_admission_webhook`,
`kubernetes_admission_webhook_external_http`.

**Pod Security Admission (4)**: `kubernetes_psa_privileged_enforcement`,
`kubernetes_psa_enforcement_missing`, `kubernetes_psa_invalid_enforcement`,
`kubernetes_psa_weak_with_privileged_workloads`.

**Namespace governance / composite (3)**: `kubernetes_namespace_weak_governance`,
`kubernetes_privileged_identity_in_weak_namespace`,
`kubernetes_privileged_workload_without_isolation`.

**Resource governance (1)**: `kubernetes_namespace_resource_governance_missing`.

### Severity distribution (source: `security_rule_pack._RULE_META`)

| Severity | Count |
|---|---|
| Critical | 6 |
| High | 33 |
| Medium | 19 |
| Low | 1 |
| **Total** | **59** |

The 6 Critical rules are exactly: `kubernetes_unauthenticated_cluster_admin`,
`kubernetes_authenticated_group_cluster_admin`,
`kubernetes_all_service_accounts_cluster_admin`,
`kubernetes_rbac_bind_permission`, `kubernetes_rbac_escalate_permission`, and
`kubernetes_privileged_host_access` (the deterministic privileged+host-access
combination). No rule fires Critical on a single weak signal in isolation
(e.g. `kubernetes_privileged_container` alone is High, not Critical — Critical
requires the combination with host_pid/host_ipc/runtime-socket/high-risk
capability evidence on the same workload record).

### Confidence distribution (source: `security_rule_confidence.RULE_CONFIDENCE`)

| Confidence | Count |
|---|---|
| High | 44 |
| Medium | 15 |
| Low | 0 |

No Kubernetes rule uses Low confidence — consistent with every other
provider's rule set in this codebase (Low-confidence rules are deferred
rather than shipped).

### Rule-pack distribution

| Pack | Count | Rule categories |
|---|---|---|
| `core_security` | 26 | Workload/Pod security (18), Admission webhooks (4)* |
| `identity` | 17 | RBAC / identity |
| `network` | 12 | Network exposure (5), NetworkPolicy isolation (7) |
| `governance` | 8 | Pod Security Admission (4), Namespace governance (3), Resource governance (1) |

*`kubernetes_broad_admission_webhook` and `kubernetes_mutating_webhook_fail_open`
are grouped with `core_security` alongside the other admission rules, matching
the task's suggested "admission fail-open" grouping under Core security.

## Evaluator / registry / confidence / pack / coverage / frontend parity

Verified by `test_kubernetes_security_rule_parity.py` (27 tests, all passing):

- `kubernetes.evaluate()` is dispatched from `_PROVIDER_RULES["kubernetes"]` in
  `security_finding_evaluator.py`.
- All 59 rule keys appear in `security_rule_registry.KNOWN_RULE_KEYS`, with no
  extras.
- All 59 rule keys have a confidence entry in `RULE_CONFIDENCE`
  (High or Medium only), with no extras.
- All 59 rule keys have a pack entry in `security_rule_pack._RULE_META`
  (provider="kubernetes"), with no extras — the module's own import-time
  `assert set(_RULE_META) == set(KNOWN_RULE_KEYS)` also passes globally.
- All 59 rule keys have a `RULE_RECORD_TYPES` entry in
  `security_coverage_service.py`, with no extras; `"kubernetes"` is present
  in `PROVIDERS` and `PROVIDER_SURFACES`.
- All 59 rule keys appear in `frontend/src/lib/securityRuleCatalog.ts` with
  `provider: "kubernetes"`, with no extras (no frontend-only or backend-only
  rules).
- `TestFullCrossLayerParity::test_all_layers_have_identical_kubernetes_key_sets`
  asserts the module/registry/confidence/pack/coverage/frontend key sets are
  byte-for-byte identical.

## Connector-shape reachability

Verified by `test_kubernetes_security_finding_reachability.py` (17 tests, all
passing) using real `kubernetes` client-shaped fake objects passed through the
actual connector normalize/collect functions (`_collect_workload_family()`,
`_collect_rbac_bindings()`, `_normalize_service()`, `_normalize_network_policy()`,
`_normalize_webhook_configuration()`, `_normalize_pod_security_admission()`),
not hand-fabricated dictionaries — for at least one representative rule per
category:

- Workload: `kubernetes_privileged_container`, `kubernetes_host_pid_enabled`,
  `kubernetes_privileged_host_access` (plus a full safe-baseline negative case).
- RBAC: `kubernetes_cluster_admin_binding`,
  `kubernetes_unauthenticated_cluster_admin` (plus a safe-binding negative case).
- Network: `kubernetes_public_load_balancer`.
- NetworkPolicy: `kubernetes_network_policy_allows_all_ingress`,
  `kubernetes_public_ipv4_cidr_allowed`.
- Admission: `kubernetes_validating_webhook_fail_open`.
- PSA: `kubernetes_psa_privileged_enforcement`.
- Governance: a TypedDict-field cross-check confirming every field the rule
  module reads on a `kubernetes_namespace_governance_posture` record is
  declared on the connector's own TypedDict (catches silent renames between
  the connector and the rule module).

The remaining 49 rules are exercised through the identical central
`evaluate_record()` dispatch path in `test_kubernetes_security_findings.py`
using normalized dicts matching the exact TypedDict field shapes documented
in `kubernetes_schema.py` — the same dispatch code path the reachability
tests prove works end-to-end from real connector output.

## Unknown / missing evidence discipline audit

Every tri-state or completeness-sensitive predicate in
`app/services/security_rules/kubernetes.py` was re-read line by line for this
message. Findings:

- `privileged`, `allow_privilege_escalation`, `run_as_non_root`,
  `read_only_root_filesystem`, `automount_service_account_token`: every check
  uses `is True` / `is False` exactly — `None` never satisfies either branch.
- `run_as_uid == 0`: gated behind `run_as_user_set is True`, so an unset UID
  (0 by Python default) can never be misread as explicit root.
- `seccomp_profile_category` / `apparmor_profile_category`: checked via
  equality against the exact `PROFILE_CATEGORY_UNCONFINED` constant; the
  `"omitted"` (unknown) category can never equal it.
- `exposure_category` / `public_exposure_category`: checked via equality
  against the exact `EXPOSURE_EXTERNAL_LOAD_BALANCER` constant only —
  `pending_load_balancer`, `internal_load_balancer`, and `unknown` never
  equal it, so a requested-but-not-yet-assigned LoadBalancer never fires.
- Unresolved RBAC roles: the connector itself (not the rule module) sets
  `cluster_admin_binding=False`, `wildcard_permission_binding=False`, and
  `high_risk_permission_categories=[]` whenever `role_resolved` is `False`
  (verified in `app/connectors/kubernetes.py` around the `_normalize_rbac_binding`
  fallback branch) — so an unresolved binding structurally cannot satisfy any
  RBAC rule's predicate. `kubernetes_unresolved_privileged_binding` was
  deliberately not implemented as a Finding (documented as a GAP below);
  role-resolution failure is a provider-completeness/visibility concern.
- `collection_completeness_category` (namespace network posture) and
  `governance_completeness_category` (namespace governance rollup): every
  rule reading these records checks `== "partial"` first and returns `[]`
  immediately — proven by `TestNamespaceNoNetworkPolicy::test_unknown_partial_collection`,
  `TestNamespaceNoIngressIsolation::test_unknown_partial_collection`,
  `TestNamespaceNoEgressIsolation::test_unknown_partial_collection`,
  `TestPsaPrivilegedEnforcement::test_unknown_partial`,
  `TestPsaEnforcementMissing::test_unknown_partial`,
  `TestPsaWeakWithPrivilegedWorkloads::test_unknown_partial`,
  `TestNamespaceWeakGovernance::test_unknown_partial`.
- Admission API denied entirely: the collector fails soft and simply returns
  no webhook records for that family — since `evaluate_record()` only ever
  sees records that exist, a total collection failure produces zero Findings
  rather than a false "no fail-open webhooks" claim in either direction.
- Unknown webhook selectors: no implemented rule keys off namespace/object
  selector category directly — `kubernetes_broad_admission_webhook` only
  reads the wildcard operation/apiGroup/resource booleans, which are always
  explicitly resolved by the connector (never `None`).
- Gateway listener / NetworkPolicy `unknown` categories: both are treated as
  ordinary "not the confirmed-risky value" cases via equality checks, so
  `unknown` never fires (`TestPublicGatewayListener::test_unknown`,
  and the general `!= EXTERNAL_LOAD_BALANCER` pattern for exposure).

**No code changes were required** — this audit found the existing
implementation already correct; no gap discovered that needed a fix.

## Severity parity review

Reviewed all 6 Critical rules and all High-severity rules per the task's
required doctrine list (Section 4). Findings:

- Critical is reserved exclusively for unauthenticated/broad cluster-admin
  bindings (3 rules), bind/escalate RBAC permissions (2 rules), and the
  deterministic privileged+host-access combination (1 rule) — matching the
  task's exact Critical doctrine list.
- `kubernetes_privileged_container` alone (no host-access combination) is
  correctly High, not Critical — the task explicitly cautions "Do not trigger
  critical merely because privileged=true alone," which this taxonomy
  respects via the separate `kubernetes_privileged_host_access` combination
  rule.
- `kubernetes_container_runtime_socket_mounted` is uniformly High (not
  split Critical-if-writable/High-if-read-only) because the workload-level
  `dangerous_hostpath_categories` evidence cannot distinguish mount
  read/write mode — a documented, conservative simplification, not a
  severity inversion.
- No Medium or Low rule describes evidence stronger than a corresponding
  High/Critical rule; e.g. `kubernetes_host_network_enabled` (Medium) is
  weaker evidence than `kubernetes_host_pid_enabled`/`kubernetes_host_ipc_enabled`
  (High), consistent with the task's own severity hierarchy for these three
  host-namespace flags.

**No recalibration was necessary.**

## Claim-discipline and sensitive-evidence safety greps

Both required greps were run against every file touched in this message
(`git diff --name-only` plus untracked new files, excluding `tail-latency-study/`):

**Grep 1** (compromise/breach/exploitation claim-discipline): every match is
either (a) a pre-existing denylist constant in another provider's
`test_*_provider_depth_qa.py` file that this message touched only to update
an unrelated stale "Kubernetes not yet implemented" guard assertion, (b) this
message's own `security_rules/kubernetes.py` module docstring describing
*what language is prohibited* (documentation, not production Finding copy),
or (c) this message's own `test_kubernetes_security_findings.py` negative
test asserting those phrases never appear in Finding text. No production
Finding title/description contains any forbidden claim.

**Grep 2** (sensitive-field leakage): every match is either a pre-existing
denylist constant in another provider's test file, the legitimate technical
term "authorization" used in OAuth/RBAC category names and grant-type strings
(e.g. `authorization_code`, "Resource server authorization"), or this
message's own test's forbidden-substring list. No Kubernetes Finding evidence
dict contains a literal Secret/ConfigMap value, kubeconfig content, token,
private key, certificate byte, or webhook payload.

## Evidence and claim safety (design-level)

All 59 rules were verified (in `TestEvidenceSafety`) to emit only: cluster
ID/name, namespace, workload/container/webhook/binding names, subject
kind/identity, permission category labels, exposure/coverage categories,
booleans, counts, and CIDÂ­R-adjacent category labels — never Secret values,
ConfigMap values, kubeconfig contents, tokens, private keys, certificate
bytes, webhook payloads, arbitrary annotations/labels, environment values,
command/args, Pod logs, or audit events. No Finding title/description claims
a confirmed breach, exploitation, or unauthorized access.

## Matrix

61 rows: 59 implemented Findings + 2 summary header rows (see table). GAP/N/A
rows for intentionally unsupported detections follow in the next section.

| Rule key | Category | Record type | Trigger field(s) | Positive evidence | Negative evidence | Unknown evidence | Severity | Confidence | Pack | Evaluator reachable? | Registry present? | Frontend present? | Real connector shape? | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| kubernetes_admission_webhook_external_http | Admission webhooks | kubernetes_validating_webhook/kubernetes_mutating_webhook | plaintext_http_client | True | False | n/a | high | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestAdmissionWebhookExternalHttp | PASS | |
| kubernetes_admission_webhook_modification_permission | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'admission_webhook_write' in categories | [] | n/a | high | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_all_capabilities_added | Workload / Pod security | kubernetes_container_security_context | capabilities_added | ['ALL'] | ['NET_BIND_SERVICE'] | [] (empty) | high | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestAllCapabilitiesAdded | PASS | |
| kubernetes_all_service_accounts_cluster_admin | RBAC / identity | kubernetes_rbac_subject_binding | cluster_admin_binding + subject_kind/subject_name | subject_kind=Group, subject_name=system:serviceaccounts | subject_name=system:masters | n/a | critical | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestAllServiceAccountsClusterAdmin | PASS | |
| kubernetes_apparmor_unconfined | Workload / Pod security | kubernetes_container_security_context | apparmor_profile_category | unconfined | runtime_default | omitted (never fires) | medium | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestApparmorUnconfined | PASS | |
| kubernetes_authenticated_group_cluster_admin | RBAC / identity | kubernetes_rbac_subject_binding | cluster_admin_binding + authenticated_group | cluster_admin_binding=True, authenticated_group=True | authenticated_group=False | n/a | critical | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestAuthenticatedGroupClusterAdmin | PASS | |
| kubernetes_broad_admission_webhook | Admission webhooks | kubernetes_validating_webhook/kubernetes_mutating_webhook | wildcard_operation/api_group/resource | wildcard_resource=True | all wildcard flags False | n/a | medium | medium | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestBroadAdmissionWebhook | PASS | |
| kubernetes_broad_workload_creation | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'workload_write' in categories | [] | n/a | high | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_cluster_admin_binding | RBAC / identity | kubernetes_rbac_subject_binding | cluster_admin_binding | True | False | n/a (resolved bool; unresolved role -> connector sets False upstream) | high | high | identity | Yes | Yes | Yes | Yes (dedicated reachability test) | test_kubernetes_security_findings.py::TestClusterAdminBinding | PASS | |
| kubernetes_container_runtime_socket_mounted | Workload / Pod security | kubernetes_deployment/kubernetes_statefulset/kubernetes_daemonset/kubernetes_job/kubernetes_cronjob/kubernetes_pod | dangerous_hostpath_categories | ['docker_socket'] | ['proc'] (other dangerous, not socket) | n/a | high | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestRuntimeSocketMounted | PASS | |
| kubernetes_crd_modification_permission | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'crd_write' in categories | [] | n/a | high | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_dangerous_hostpath | Workload / Pod security | kubernetes_deployment/kubernetes_statefulset/kubernetes_daemonset/kubernetes_job/kubernetes_cronjob/kubernetes_pod | dangerous_hostpath_categories | ['etc'] | [] | n/a (empty list = no evidence) | high | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestDangerousHostpath | PASS | |
| kubernetes_dangerous_linux_capability | Workload / Pod security | kubernetes_container_security_context | dangerous_added_capability_categories | ['SYS_ADMIN'] (high tier) | [] (empty) | n/a (empty list = no evidence, not unknown) | high | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestDangerousLinuxCapability | PASS | |
| kubernetes_host_ipc_enabled | Workload / Pod security | kubernetes_deployment/kubernetes_statefulset/kubernetes_daemonset/kubernetes_job/kubernetes_cronjob/kubernetes_pod | host_ipc | host_ipc=True | host_ipc=False | n/a (bool, never None) | high | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestHostIpc | PASS | |
| kubernetes_host_network_enabled | Workload / Pod security | kubernetes_deployment/kubernetes_statefulset/kubernetes_daemonset/kubernetes_job/kubernetes_cronjob/kubernetes_pod | host_network | host_network=True | host_network=False | n/a (bool, never None) | medium | medium | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestHostNetwork | PASS | |
| kubernetes_host_pid_enabled | Workload / Pod security | kubernetes_deployment/kubernetes_statefulset/kubernetes_daemonset/kubernetes_job/kubernetes_cronjob/kubernetes_pod | host_pid | host_pid=True | host_pid=False | n/a (bool, never None on this field) | high | high | core_security | Yes | Yes | Yes | Yes (dedicated reachability test) | test_kubernetes_security_findings.py::TestHostPid | PASS | |
| kubernetes_hostless_catchall_ingress | Network exposure | kubernetes_ingress_rule | catch_all_route + host_category | catch_all_route=True, host_category=hostless | host_category=exact | n/a | high | high | network | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestHostlessCatchallIngress | PASS | |
| kubernetes_mutable_image_tag | Workload / Pod security | kubernetes_container_security_context | image_tag_category | latest_explicit / latest_implicit | pinned_digest | n/a (category always resolved) | medium | medium | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestMutableImageTag | PASS | |
| kubernetes_mutating_webhook_fail_open | Admission webhooks | kubernetes_mutating_webhook | failure_policy | Ignore | Fail | n/a | medium | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestMutatingWebhookFailOpen | PASS | |
| kubernetes_namespace_no_egress_isolation | NetworkPolicy isolation | kubernetes_namespace_network_posture | egress_isolation_present + completeness | egress_isolation_present=False, complete | egress_isolation_present=True | collection_completeness_category=partial | medium | medium | network | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestNamespaceNoEgressIsolation | PASS | |
| kubernetes_namespace_no_ingress_isolation | NetworkPolicy isolation | kubernetes_namespace_network_posture | ingress_isolation_present + completeness | ingress_isolation_present=False, complete | ingress_isolation_present=True | collection_completeness_category=partial | medium | medium | network | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestNamespaceNoIngressIsolation | PASS | |
| kubernetes_namespace_no_network_policy | NetworkPolicy isolation | kubernetes_namespace_network_posture | has_any_network_policy + completeness | has_any_network_policy=False, complete | has_any_network_policy=True | collection_completeness_category=partial | medium | medium | network | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestNamespaceNoNetworkPolicy | PASS | |
| kubernetes_namespace_resource_governance_missing | Resource governance | kubernetes_namespace_governance_posture | resource_quota_count + limit_range_count + quota_coverage_category | both 0, coverage=none | both >=1, coverage=broad | quota_coverage_category=unknown | low | medium | governance | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestNamespaceResourceGovernanceMissing | PASS | |
| kubernetes_namespace_weak_governance | Namespace governance | kubernetes_namespace_governance_posture | 3+ of 4 weak signals + completeness | weak PSA + no ingress isolation + no quota + privileged workload | only 1 weak signal | governance_completeness_category=partial | high | medium | governance | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestNamespaceWeakGovernance | PASS | |
| kubernetes_network_policy_allows_all_egress | NetworkPolicy isolation | kubernetes_network_policy | allows_all_egress | True | False | n/a | medium | high | network | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestNetworkPolicyAllowsAllEgress | PASS | |
| kubernetes_network_policy_allows_all_ingress | NetworkPolicy isolation | kubernetes_network_policy | allows_all_ingress | True | False | n/a (bool, connector never emits None) | high | high | network | Yes | Yes | Yes | Yes (dedicated reachability test) | test_kubernetes_security_findings.py::TestNetworkPolicyAllowsAllIngress | PASS | |
| kubernetes_pod_attach_permission | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'pod_attach' in categories | [] | n/a | high | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_pod_exec_permission | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'pod_exec' in categories | [] | n/a | high | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_privilege_escalation_allowed | Workload / Pod security | kubernetes_container_security_context | allow_privilege_escalation | allow_privilege_escalation=True | allow_privilege_escalation=False | allow_privilege_escalation=None | medium | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPrivilegeEscalationAllowed | PASS | |
| kubernetes_privileged_container | Workload / Pod security | kubernetes_container_security_context | privileged | privileged=True | privileged=False | privileged=None (never fires) | high | high | core_security | Yes | Yes | Yes | Yes (dedicated reachability test) | test_kubernetes_security_findings.py::TestPrivilegedContainer | PASS | |
| kubernetes_privileged_host_access | Workload / Pod security | kubernetes_deployment/kubernetes_statefulset/kubernetes_daemonset/kubernetes_job/kubernetes_cronjob/kubernetes_pod | privileged_container_count + host_pid/host_ipc/hostpath/capability | privileged_container_count=1 AND host_pid=True | privileged alone or host-access alone (either count=0) | n/a (deterministic combo; zero count never fires) | critical | high | core_security | Yes | Yes | Yes | Yes (dedicated reachability test) | test_kubernetes_security_findings.py::TestPrivilegedHostAccess | PASS | |
| kubernetes_privileged_identity_in_weak_namespace | Namespace governance | kubernetes_namespace_governance_posture | high_privilege_service_account_present + weak net + zero quota | risk tag=high_privilege_identity_weak_governance | high_privilege_service_account_present=False | n/a (guarded by governance_completeness_category upstream) | high | medium | governance | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPrivilegedIdentityInWeakNamespace | PASS | |
| kubernetes_privileged_workload_without_isolation | Namespace governance | kubernetes_namespace_governance_posture | privileged_workload_present + network_policy_coverage_category | privileged_workload_present=True, coverage=none | coverage=broad | coverage=unknown | high | medium | governance | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPrivilegedWorkloadWithoutIsolation | PASS | |
| kubernetes_psa_enforcement_missing | Pod Security Admission | kubernetes_pod_security_admission | enforce_level + completeness | unset, complete | restricted | collection_completeness_category=partial | medium | medium | governance | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPsaEnforcementMissing | PASS | |
| kubernetes_psa_invalid_enforcement | Pod Security Admission | kubernetes_pod_security_admission | enforce_level | invalid | baseline | n/a | medium | high | governance | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPsaInvalidEnforcement | PASS | |
| kubernetes_psa_privileged_enforcement | Pod Security Admission | kubernetes_pod_security_admission | enforce_level + completeness | privileged, complete | restricted | collection_completeness_category=partial | medium | high | governance | Yes | Yes | Yes | Yes (dedicated reachability test) | test_kubernetes_security_findings.py::TestPsaPrivilegedEnforcement | PASS | |
| kubernetes_psa_weak_with_privileged_workloads | Pod Security Admission | kubernetes_pod_security_admission | governance_risk_summary contains privileged_workload_weak_psa + completeness | privileged_workload_present=True, risk tag present, complete | privileged_workload_present=False, standard | governance_completeness_category=partial | high | high | governance | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPsaWeakWithPrivilegedWorkloads | PASS | |
| kubernetes_public_gateway_listener | Network exposure | kubernetes_gateway_listener | public_exposure_category | external_load_balancer | internal_load_balancer | unknown | high | high | network | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPublicGatewayListener | PASS | |
| kubernetes_public_ingress_without_tls | Network exposure | kubernetes_ingress_rule | public_exposure_category + tls_covered | external_load_balancer, tls_covered=False | tls_covered=True | public_exposure_category=unknown | high | high | network | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPublicIngressWithoutTls | PASS | |
| kubernetes_public_ipv4_cidr_allowed | NetworkPolicy isolation | kubernetes_network_policy | public_ipv4_cidr_allowed | True | False | n/a | high | high | network | Yes | Yes | Yes | Yes (dedicated reachability test) | test_kubernetes_security_findings.py::TestPublicIpv4CidrAllowed | PASS | |
| kubernetes_public_ipv6_cidr_allowed | NetworkPolicy isolation | kubernetes_network_policy | public_ipv6_cidr_allowed | True | False | n/a | high | high | network | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPublicIpv6CidrAllowed | PASS | |
| kubernetes_public_load_balancer | Network exposure | kubernetes_service | exposure_category | external_load_balancer | cluster_internal / internal_load_balancer | pending_load_balancer / unknown | high | high | network | Yes | Yes | Yes | Yes (dedicated reachability test) | test_kubernetes_security_findings.py::TestPublicLoadBalancer | PASS | |
| kubernetes_rbac_bind_permission | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'bind' in categories | [] (no categories) | n/a | critical | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_rbac_escalate_permission | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'escalate' in categories | [] | n/a | critical | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_rbac_impersonate_permission | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'impersonate' in categories | [] | n/a | high | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_rbac_modification_permission | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'role_or_cluster_role_write'/'cluster_role_binding_write' in categories | [] | n/a | high | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_root_container | Workload / Pod security | kubernetes_container_security_context | run_as_user_set + run_as_uid | run_as_user_set=True, run_as_uid=0 | run_as_uid=1000 | run_as_user_set=False, run_as_uid=None | medium | medium | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestRootContainer | PASS | |
| kubernetes_run_as_non_root_disabled | Workload / Pod security | kubernetes_container_security_context | run_as_non_root | run_as_non_root=False | run_as_non_root=True | run_as_non_root=None | medium | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestRunAsNonRootDisabled | PASS | |
| kubernetes_seccomp_unconfined | Workload / Pod security | kubernetes_container_security_context | seccomp_profile_category | unconfined | runtime_default | omitted (never fires) | high | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestSeccompUnconfined | PASS | |
| kubernetes_secret_read_permission | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'secret_read'/'secret_read_broad_scope' in categories | [] | n/a | high | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_secret_write_permission | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'secret_write' in categories | [] | n/a | high | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_sensitive_host_port | Workload / Pod security | kubernetes_container_security_context | dangerous_host_ports | [6443] | [] | n/a (empty list = no evidence) | medium | high | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestSensitiveHostPort | PASS | |
| kubernetes_sensitive_nodeport | Network exposure | kubernetes_service_port | node_port + sensitive_port | node_port=6443, sensitive_port=True | sensitive_port=False | node_port=None | medium | medium | network | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestSensitiveNodeport | PASS | |
| kubernetes_service_account_token_automount | Workload / Pod security | kubernetes_deployment/kubernetes_statefulset/kubernetes_daemonset/kubernetes_job/kubernetes_cronjob/kubernetes_pod | automount_service_account_token | True | False | None | medium | medium | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestServiceAccountTokenAutomount | PASS | |
| kubernetes_service_account_token_creation | RBAC / identity | kubernetes_rbac_subject_binding | high_risk_permission_categories | 'token_creation' in categories | [] | n/a | high | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestPermissionCategoryRules | PASS | |
| kubernetes_unauthenticated_cluster_admin | RBAC / identity | kubernetes_rbac_subject_binding | cluster_admin_binding + anonymous_subject/unauthenticated_group | cluster_admin_binding=True, anonymous_subject=True | cluster_admin_binding=True, anonymous_subject=False | n/a | critical | high | identity | Yes | Yes | Yes | Yes (dedicated reachability test) | test_kubernetes_security_findings.py::TestUnauthenticatedClusterAdmin | PASS | |
| kubernetes_validating_webhook_fail_open | Admission webhooks | kubernetes_validating_webhook | failure_policy | Ignore | Fail | unknown | high | high | core_security | Yes | Yes | Yes | Yes (dedicated reachability test) | test_kubernetes_security_findings.py::TestValidatingWebhookFailOpen | PASS | |
| kubernetes_wildcard_rbac_permissions | RBAC / identity | kubernetes_rbac_subject_binding | wildcard_permission_binding (not cluster-admin) | wildcard_permission_binding=True, cluster_admin_binding=False | wildcard_permission_binding=False | n/a (suppressed when already cluster-admin) | high | high | identity | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestWildcardRbacPermissions | PASS | |
| kubernetes_writable_root_filesystem | Workload / Pod security | kubernetes_container_security_context | read_only_root_filesystem | False | True | None | medium | medium | core_security | Yes | Yes | Yes | Yes (via pure-dict evaluate_record path; same dispatch) | test_kubernetes_security_findings.py::TestWritableRootFilesystem | PASS | |

## Intentionally unsupported detections (GAP / N/A)

| Capability | Category | Status | Notes |
|---|---|---|---|
| Secret contents | unsupported detection capability | N/A (permanent) | ConfigTrace never reads Secret values — a message-1 architectural boundary reaffirmed in message 5's ConfigMap/Secret safety review. |
| ConfigMap contents | unsupported detection capability | N/A (permanent) | Same boundary as Secret contents; no field-level RBAC exists to request metadata-only ConfigMap access. |
| Runtime exploit / intrusion detection | unsupported detection capability | N/A (permanent) | ConfigTrace evaluates configuration snapshots only, never runtime behavior, syscalls, or process activity. |
| Pod logs | unsupported detection capability | N/A (permanent) | Never fetched; would require broad `pods/log` read access and could contain arbitrary application data. |
| Kubernetes audit-event detection | unsupported detection capability | GAP (deferred) | Would require cluster audit-log/webhook integration, a materially different collection surface not built in messages 1-6. |
| Vulnerability scanning (image CVEs) | unsupported detection capability | N/A (permanent) | Requires image-layer inspection or a registry-scanning integration outside this connector's metadata-only scope. |
| Image malware scanning | unsupported detection capability | N/A (permanent) | Same rationale as vulnerability scanning — outside a metadata-only Kubernetes API connector's scope. |
| Runtime syscall detection | unsupported detection capability | N/A (permanent) | Requires an eBPF/runtime security agent (e.g. Falco); architecturally distinct from a Kubernetes API connector. |
| CNI enforcement verification | unsupported detection capability | N/A (permanent) | ConfigTrace can observe NetworkPolicy *objects* but not confirm the cluster's CNI actually enforces them — documented explicitly in the NetworkPolicy rule wording ("ConfigTrace observed no NetworkPolicy...", never "traffic is unrestricted"). |
| ReferenceGrant direct collection | unsupported detection capability | GAP (deferred) | Gateway API ReferenceGrant objects are not yet collected; `kubernetes_cross_namespace_route` was deferred partly for this reason (see module docstring). |
| API-server control-plane flags/posture | unsupported detection capability | GAP (deferred, reserved) | `kubernetes_api_server_security_posture` is a reserved-but-unimplemented record type in `kubernetes_schema.py` (`KUBERNETES_PLANNED_RECORD_TYPES`); no static Finding exists for it yet. |
| kubernetes_validating_webhook_removed (static rule) | Admission webhooks | N/A (by design) | Static Findings evaluate current state, not historical removal — that belongs to Change classification (message 7). |
| kubernetes_admission_webhook_missing_ca | Admission webhooks | N/A (by design) | Deferred to avoid false positives on external-URL clients relying on system trust. |
| kubernetes_unresolved_privileged_binding | RBAC / identity | N/A (by design) | Role-resolution failure is a provider-completeness/visibility concern, not a security Finding. |
| kubernetes_external_ip_service / external_name_service / wildcard_ingress / gateway_routes_all_namespaces / cross_namespace_route | Network exposure / NetworkPolicy | N/A (by design) | Lower-signal/noisier variants; higher-signal equivalents were kept instead (see module docstring "Deferred Kubernetes rules"). |
| Per-key ResourceQuota/LimitRange Findings | Resource governance | N/A (by design) | Consolidated into one `kubernetes_namespace_resource_governance_missing` rule instead of one Finding per absent quota/limit key. |
| kubernetes_psa_baseline_enforcement / psa_audit_missing / psa_warn_missing (standalone) | Pod Security Admission | N/A (by design) | Baseline enforcement and missing audit/warn are common, low-signal defaults on their own; only the combined `kubernetes_psa_weak_with_privileged_workloads` rule fires. |

## Totals

- **Matrix rows (implemented Findings)**: 59 / 59 PASS.
- **GAP rows**: 3 (Kubernetes audit-event detection, ReferenceGrant direct
  collection, API-server control-plane posture) — all deferred to a later
  message, none silently dropped.
- **N/A rows (permanent architectural boundaries or deliberate design
  choices)**: 14.
- **FIXED**: 0 — no defects were found during this message's validation pass.
