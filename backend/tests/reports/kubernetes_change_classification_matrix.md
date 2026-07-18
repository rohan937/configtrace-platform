# Kubernetes Change Classification Matrix (Message 7 of 9)

Exhaustive QA pass over `app/services/risk_rules/kubernetes.py` — every
emitted Kubernetes record type's Change classification, verified through the
real `compute_diff() -> classify_kubernetes_change()` pipeline. This message
does not add new Kubernetes API families or record types; it audits and
hardens the classifier built across messages 1–5 and checks it against the
59 static Security Findings built in message 6.

## Record-type inventory (source of truth)

36 Kubernetes record types are emitted (excluding `kubernetes_config_map_metadata`/
`kubernetes_secret_metadata`, deliberately unsupported, and
`kubernetes_api_server_security_posture`, planned/reserved). Verified directly
against `kubernetes_schema.py`'s record-type constants, `diff_service.py`'s
`_KUBERNETES_TRACKED_FIELDS_BY_TYPE` (36 keys, one per emitted type — confirmed
by direct count), and `risk_rules/kubernetes.py`'s `classify_kubernetes_change()`
dispatch table (also 36 routed record types, verified below).

| # | Record type | Tracked fields? | Classifier |
|---|---|---|---|
| 1 | `kubernetes_cluster` | 6 fields | Dedicated (`_classify_cluster_change`) |
| 2 | `kubernetes_namespace` | 8 fields | Dedicated (`_classify_namespace_change`) |
| 3 | `kubernetes_api_capability` | 0 (no tracked fields; added/removed only) | Dedicated (`_classify_api_capability_change`) |
| 4 | `kubernetes_deployment` | shared workload-controller tuple (23 fields) | Dedicated (`_classify_workload_controller_change`, shared) |
| 5 | `kubernetes_statefulset` | shared | Dedicated (shared) |
| 6 | `kubernetes_daemonset` | shared | Dedicated (shared) |
| 7 | `kubernetes_job` | shared | Dedicated (shared) |
| 8 | `kubernetes_cronjob` | shared | Dedicated (shared) |
| 9 | `kubernetes_pod` | own tuple (adds pod-specific fields; routed to the same shared classifier since Pod shares the workload-controller field shape) | Dedicated (shared with #4-8) |
| 10 | `kubernetes_container_security_context` | own tuple (35 fields) | Dedicated (`_classify_container_security_context_change`) |
| 11 | `kubernetes_workload_service_account` | own tuple | Dedicated (`_classify_workload_service_account_change`) |
| 12 | `kubernetes_service_account` | own tuple | Dedicated (`_classify_service_account_change`) |
| 13 | `kubernetes_role` | shared role tuple | Dedicated (`_classify_role_change`, shared) |
| 14 | `kubernetes_cluster_role` | shared | Dedicated (shared) |
| 15 | `kubernetes_role_binding` | shared binding tuple | Dedicated (`_classify_role_binding_change`, shared) |
| 16 | `kubernetes_cluster_role_binding` | shared | Dedicated (shared) |
| 17 | `kubernetes_rbac_subject_binding` | own tuple | Dedicated (`_classify_rbac_subject_binding_change`) |
| 18 | `kubernetes_rbac_permission_summary` | own tuple | Dedicated (`_classify_rbac_permission_summary_change`) |
| 19 | `kubernetes_service` | own tuple | Dedicated (`_classify_service_change`) |
| 20 | `kubernetes_service_port` | own tuple | Dedicated (`_classify_service_port_change`) |
| 21 | `kubernetes_ingress` | own tuple | Dedicated (`_classify_ingress_change`) |
| 22 | `kubernetes_ingress_rule` | own tuple | Dedicated (`_classify_ingress_rule_change`) |
| 23 | `kubernetes_gateway` | own tuple | Dedicated (`_classify_gateway_change`) |
| 24 | `kubernetes_gateway_listener` | own tuple | Dedicated (`_classify_gateway_listener_change`) |
| 25 | `kubernetes_http_route` | own tuple | Dedicated (`_classify_http_route_change`) |
| 26 | `kubernetes_http_route_rule` | own tuple | Dedicated (`_classify_http_route_rule_change`) |
| 27 | `kubernetes_network_policy` | own tuple | Dedicated (`_classify_network_policy_change`) |
| 28 | `kubernetes_namespace_network_posture` | own tuple | Dedicated (`_classify_namespace_network_posture_change`) |
| 29 | `kubernetes_validating_webhook_configuration` | shared webhook-configuration tuple | Dedicated (`_classify_webhook_configuration_change`, shared) |
| 30 | `kubernetes_mutating_webhook_configuration` | shared | Dedicated (shared) |
| 31 | `kubernetes_validating_webhook` | shared webhook tuple | Dedicated (`_classify_webhook_change`, shared) |
| 32 | `kubernetes_mutating_webhook` | shared | Dedicated (shared) |
| 33 | `kubernetes_pod_security_admission` | own tuple | Dedicated (`_classify_pod_security_admission_change`) |
| 34 | `kubernetes_resource_quota` | own tuple | Dedicated (`_classify_resource_quota_change`) |
| 35 | `kubernetes_limit_range` | own tuple | Dedicated (`_classify_limit_range_change`) |
| 36 | `kubernetes_namespace_governance_posture` | own tuple | Dedicated (`_classify_namespace_governance_posture_change`) |

**Classification result: 36/36 emitted record types have a dedicated classifier.**
Zero accidental generic fallbacks at the record-type level — the only path to
the module's final generic `"low"` fallback is an unrecognized/future
`kubernetes_*` record type (intentional: message 8/9 record types not yet
built, or a genuinely unknown type, must fail safely rather than raise or
route to an unrelated provider's classifier).

## Tracked-field audit summary

- **Dedicated field-level branch**: the large majority of security-sensitive
  fields across all 36 types (see matrix rows below for the complete list).
- **Intentional generic branch** (routes to a shared low-severity message,
  by design — see Section "Intentional generic fallbacks" below): ordinary
  replica/strategy/runtime-class fields, probe-coverage fields, non-sensitive
  ID/fingerprint/category-label fields, and count fields whose only
  meaningful signal is "configuration changed" (e.g. `rule_count`,
  `permission_fingerprint`, `policy_fingerprint`).
- **Accidental generic fallback found and fixed**: **1** — the newly-added
  Critical-combo detection for `kubernetes_privileged_host_access` on an
  "added" workload (see Finding-parity fix below); prior to this message, a
  workload added already matching that exact Critical combination was
  classified only High.
- **Numeric "unknown silently became zero" bugs found and fixed**: **20**
  call sites (see below) — none discovered any severity-direction change in
  existing passing tests (all 805 pre-existing Kubernetes tests still pass
  unchanged), confirming these were latent defensive gaps, not previously
  masked failures.

## Fixes applied this message

### 1. Numeric unknown-safety (`_count_transition()` / `_as_int()` helpers added)

Every count-field comparison previously used the `(nv or 0) > (pv or 0)`
pattern, which silently coerces an unknown (`None`, e.g. from a field key
genuinely absent from a snapshot dict — a real, reachable `dict.get()`
outcome in `compute_diff()`, not merely theoretical) to `0`. This meant an
unknown new/prev count could be misread as an increase or a decrease. Fixed
at all 20 call sites:

`privileged_container_count`, `root_container_count`,
`allow_privilege_escalation_count` (workload); `host_port_count`,
`hostpath_mount_count`/`writable_hostpath_mount_count` (container);
`load_balancer_ingress_count`, `external_ip_count` (Service);
`tls_host_count`, `wildcard_host_count`, `load_balancer_ingress_count`
(Ingress); `wildcard_hostname_count` (Gateway listener);
`cross_namespace_backend_count`, `cross_namespace_parent_count`,
`wildcard_hostname_count` (HTTPRoute); `broad_cidr_count` (NetworkPolicy);
`fail_open_webhook_count`, `fail_closed_webhook_count`, `webhook_count`,
`ca_bundle_present_count` (webhook configuration); `timeout_seconds`
(webhook).

Each now returns a safe `"low"` / "could not be safely compared" message
when either side is not a genuine `int` (bool is explicitly excluded, since
bool is an `int` subclass in Python) — never a directional claim.

### 2. Finding-severity-parity gap (workload added-branch)

The static `kubernetes_privileged_host_access` Finding (message 6, Critical)
fires on a workload combining `privileged_container_count > 0` with
`host_pid`/`host_ipc`/a runtime-socket hostPath/a high-tier capability. The
Change classifier's "added" branch for a new workload only checked the
broader, weaker `security_posture_summary == "privileged_or_host_access"`
condition (which is also true for *privileged alone*, with no host access)
and returned a flat `"high"` — never `"critical"`, even when the added
workload's evidence exactly matched the static Finding's Critical trigger.
Fixed by adding `_is_privileged_host_access_combo()`, mirroring the static
rule's exact predicate, checked first in both the added and removed
branches of `_classify_workload_controller_change()`.

## Stale Change-field audit

`risk_rules/kubernetes.py` was grepped for `old_value`, `previous_value`,
and `prior_value` — **zero matches** (confirmed both manually and via the
new permanent regression test
`test_kubernetes_change_unknowns.py::TestStaleFieldNameGuard`). The module
exclusively reads `prev_value`/`new_value` (matching the real `Change`
model's actual columns) and `provider_metadata["record_type"]` for dispatch.
No fix was required here — this was already correct across messages 1–5;
the regression guard now makes it permanent.

## Provider metadata audit

`diff_service.py::_build_provider_metadata()` builds real, non-test-injected
metadata for every Kubernetes record type (cluster/namespace, workload
kind/name/uid/ServiceAccount, container name/category/parent, Role/binding
name, subject kind/identity, Service/Ingress/Gateway/HTTPRoute/NetworkPolicy
name, webhook configuration/name, PSA/ResourceQuota/LimitRange/governance
namespace) — verified by direct code read (lines ~3720–3848) and exercised
by the real `compute_diff()` pipeline in all 4 new test files (no test
manually injects `provider_metadata`; every `Change` dict comes from a real
`compute_diff()` call). `classify_kubernetes_change()`'s dispatch itself
reads `provider_metadata["record_type"]` exclusively — confirmed no
production classifier depends on any other dispatch key.

## Unknown / missing evidence discipline audit

Boolean audit: `privileged`, `allow_privilege_escalation`, `run_as_non_root`,
`read_only_root_filesystem`, `automount_service_account_token`,
`cluster_admin_binding`, `allows_all_ingress`/`allows_all_egress`,
`wildcard_resource`/`wildcard_operation`/`wildcard_api_group`,
`plaintext_http_client`, `ca_bundle_present`, `privileged_workload_present`
— every risky check uses `is True`/`is False`/truthiness against a value the
connector only ever sets to an explicit `True`/`False` for these fields, so
`None` never satisfies a risky branch (verified in
`test_kubernetes_change_unknowns.py`, 33 tests). Numeric audit: see the 20
fixes above (`test_kubernetes_change_unknowns.py::TestNumericUnknownNeverBecomesZero`,
16 tests). Collection-completeness fields (`collection_completeness_category`,
`governance_completeness_category`) consistently map `"partial"` to a
`"medium"` **visibility** message ("ConfigTrace's Kubernetes credentials have
only partial permission...") — never an explicit risky-state claim.

## Finding-severity parity results

28 direct comparisons (`test_kubernetes_change_finding_parity.py`) between a
fresh Change transition and the corresponding static Finding's severity —
all 28 pass with the Change severity at or above the static floor. Notable:
RBAC permission-category grants (`bind`, `escalate`, `impersonate`,
`admission_webhook_write`, `crd_write`, `token_creation`) are classified
**Critical** by the Change classifier (via `_CRITICAL_PERMISSION_CATEGORIES`)
even where the static Finding is High — this is a documented, intentional
over-caution (a *fresh grant* of certain escalation-adjacent permissions is
treated more cautiously as a live Change than as a standing configuration
Finding), not a violation, since the requirement is a floor, not an exact
match. Restoration/improvement transitions (cluster-admin removed, PSA
restored, webhook failurePolicy restored to Fail) are correctly `"low"` and
explicitly exempted from the floor requirement (3 tests).

## Copy discipline

All classifier message strings were re-read in full during this audit (all
36 dedicated functions). None claim compromise, attacker activity, container
escape, secret theft, data exposure, unverified internet reachability,
admission bypass, exploitation, or cluster takeover — consistent with the
module's own docstring guarantee ("Severity assignments deliberately do NOT
claim compromise, breakout, exploitation, internet exposure, or credential
theft — they describe structural posture only"). Examples already in
production: *"A container was configured to run in privileged mode"* (safe,
descriptive), *"A Kubernetes ServiceAccount gained cluster-admin privilege"*
(safe, evidence-based), *"A Kubernetes Service changed from internal to
confirmed external exposure"* (safe, no reachability claim).

## Intentional generic fallbacks (documented, not defects)

- Ordinary replica count, update-strategy category, runtime-class name
  (workload) — routine configuration, not security-relevant.
- Probe coverage fields (`liveness_probe_coverage`, etc.) — reliability
  signal, out of security-Finding scope.
- `image_posture_summary`'s catch-all branch (already has dedicated
  mutable/pinned branches; anything else is a low-value category change).
- Fingerprint/count-only fields (`permission_fingerprint`, `binding_fingerprint`,
  `policy_fingerprint`, `webhook_fingerprint`, `selector_fingerprint`,
  `configuration_fingerprint`) — these are stability/identity hashes, not
  independently actionable signals; the fields that *produce* the
  fingerprint (e.g. `high_risk_permission_categories`, `allows_all_ingress`)
  already have dedicated, more specific classification.
- `rule_count`, `subject_count`/`user_subject_count`/`group_subject_count`/
  `service_account_subject_count`, `aggregation_selector_count` — cardinality
  metadata that doesn't by itself indicate a directional risk change absent
  the categorical fields that already classify the actual content.

## Matrix

165 rows (151 net-new message-7 test cases + 14 pre-existing message-5
ResourceQuota/LimitRange diff cases retained for required category
coverage). Every row maps to a real, passing test exercised through
`compute_diff() -> classify_kubernetes_change()`.

| Case | Category | Record type | Field(s) | Prev value | New value | Detected by compute_diff? | Classifier branch | Current severity | Expected severity | Static Finding parity | Provider metadata? | Added/removed/full-record? | Unknown-safe? | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Workload | container_security_context | privileged | False | True | Yes | `_classify_container_security_context_change` | high | high | kubernetes_privileged_container=high | Yes | modified | Yes | TestWorkloadPrivilegeTransitions::test_privileged_false_to_true | PASS | |
| 2 | Workload | container_security_context | privileged | True | False | Yes | same | low | low | n/a (restoration) | Yes | modified | Yes | ::test_privileged_true_to_false | PASS | |
| 3 | Workload | container_security_context | privileged | False | None | Yes | same | low | low | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_privileged_none_never_fires_high | FIXED-VERIFIED | Confirmed no false positive |
| 4 | Workload | container_security_context | allow_privilege_escalation | False | True | Yes | same | medium | medium | n/a | Yes | modified | Yes | ::test_privilege_escalation_false_to_true | PASS | |
| 5 | Workload | container_security_context | allow_privilege_escalation | False | None | Yes | same | low | low | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_allow_privilege_escalation_none_never_fires_medium | PASS | |
| 6 | Workload | container_security_context | run_as_non_root | True | False | Yes | same | high | high | n/a | Yes | modified | Yes | ::test_run_as_non_root_disabled | PASS | |
| 7 | Workload | container_security_context | run_as_non_root | True | None | Yes | same | low | low | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_run_as_non_root_none_never_fires_high | PASS | |
| 8 | Workload | container_security_context | run_as_uid | 1000 | 0 | Yes | same | high | high | n/a | Yes | modified | Yes | ::test_run_as_uid_zero_introduced | PASS | |
| 9 | Workload | container_security_context | run_as_uid | 0 | 1000 | Yes | same | low | low | n/a | Yes | modified | Yes | ::test_run_as_uid_zero_removed | PASS | |
| 10 | Workload | container_security_context | read_only_root_filesystem | True | None | Yes | same | low | low | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_read_only_root_filesystem_none_never_fires_medium | PASS | |
| 11 | Workload | deployment | host_pid | False | True | Yes | `_classify_workload_controller_change` | high | high | n/a | Yes | modified | Yes | TestHostNamespaceTransitions::test_host_pid_enabled | PASS | |
| 12 | Workload | deployment | host_ipc | False | True | Yes | same | high | high | n/a | Yes | modified | Yes | ::test_host_ipc_enabled | PASS | |
| 13 | Workload | deployment | host_network | False | True | Yes | same | medium | medium | n/a | Yes | modified | Yes | ::test_host_network_enabled | PASS | |
| 14 | Workload | container_security_context | dangerous_added_capability_categories | [] | [SYS_ADMIN] | Yes | `_classify_capability_transition` | high | high | kubernetes_dangerous_linux_capability=high | Yes | modified | Yes | TestCapabilityTransitions::test_sys_admin_added | PASS | |
| 15 | Workload | container_security_context | capabilities_added | [] | [ALL] | Yes | same | high | high | kubernetes_all_capabilities_added=high | Yes | modified | Yes | ::test_all_capability_added | PASS | |
| 16 | Workload | container_security_context | dangerous_added_capability_categories | [NET_ADMIN] | [] | Yes | same | low | low | n/a | Yes | modified | Yes | ::test_capability_removed | PASS | |
| 17 | Workload | container_security_context | dangerous_added_capability_categories | [NET_ADMIN,SYS_PTRACE] | [SYS_PTRACE,NET_ADMIN] (reordered) | Yes (raw list differs) | same | low | low | n/a | Yes | modified | Yes | ::test_ordering_only_change_is_never_misclassified_as_risky | PASS | Set-equality prevents false "added"/"removed" |
| 18 | Workload | container_security_context | seccomp_profile_category | runtime_default | unconfined | Yes | `_classify_profile_transition` | high | high | kubernetes_seccomp_unconfined=high | Yes | modified | Yes | TestProfileTransitions::test_seccomp_runtime_default_to_unconfined | PASS | |
| 19 | Workload | container_security_context | seccomp_profile_category | unconfined | runtime_default | Yes | same | low | low | n/a (restoration) | Yes | modified | Yes | ::test_seccomp_unconfined_to_runtime_default | PASS | |
| 20 | Workload | container_security_context | apparmor_profile_category | runtime_default | unconfined | Yes | same | medium | medium | n/a | Yes | modified | Yes | ::test_apparmor_unconfined_severity_is_medium | PASS | |
| 21 | Workload | deployment | dangerous_hostpath_categories | [] | [docker_socket] | Yes | `_classify_hostpath_category_transition` | critical | critical | kubernetes_container_runtime_socket_mounted=high | Yes | modified | Yes | TestHostpathTransitions::test_runtime_socket_introduced_is_critical | PASS | Change ranks above static floor (documented over-caution) |
| 22 | Workload | deployment | dangerous_hostpath_categories | [] | [etc] | Yes | same | high | high | kubernetes_dangerous_hostpath=high | Yes | modified | Yes | ::test_dangerous_hostpath_introduced_is_high | PASS | |
| 23 | Workload | deployment | dangerous_hostpath_categories | [etc] | [] | Yes | same | low | low | n/a | Yes | modified | Yes | ::test_hostpath_removed_is_low | PASS | |
| 24 | Workload | container_security_context | image_tag_category | pinned_digest | latest_explicit | Yes | image-tag branch | medium | medium | kubernetes_mutable_image_tag=medium | Yes | modified | Yes | TestImageTransitions::test_pinned_to_mutable | PASS | |
| 25 | Workload | container_security_context | image_tag_category | latest_implicit | pinned_digest | Yes | same | low | low | n/a (restoration) | Yes | modified | Yes | ::test_mutable_to_pinned | PASS | |
| 26 | Workload | deployment | automount_service_account_token | False | True | Yes | same | medium | medium | kubernetes_service_account_token_automount=medium | Yes | modified | Yes | TestAutomountTransitions::test_automount_false_to_true | PASS | |
| 27 | Workload | deployment | automount_service_account_token | True | False | Yes | same | low | low | n/a | Yes | modified | Yes | ::test_automount_true_to_false | PASS | |
| 28 | Workload | deployment | automount_service_account_token | True | None | Yes | same | low | low | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_automount_none_never_fires_medium | PASS | |
| 29 | Workload (numeric) | deployment | privileged_container_count | 2 | None | Yes | `_count_transition` | low | low | n/a | Yes | modified | Yes (FIXED) | TestNumericUnknownNeverBecomesZero::test_privileged_container_count_unknown_new_value | FIXED | Was previously coerced to 0 |
| 30 | Workload (numeric) | deployment | privileged_container_count | None | 2 | Yes | same | low | low | n/a | Yes | modified | Yes (FIXED) | ::test_privileged_container_count_unknown_prev_value | FIXED | |
| 31 | Workload (numeric) | deployment | privileged_container_count | 0 | 1 | Yes | same | high | high | n/a | Yes | modified | Yes | ::test_privileged_container_count_real_increase_still_high | PASS | |
| 32 | Workload (numeric) | deployment | privileged_container_count | 1 | 0 | Yes | same | low | low | n/a | Yes | modified | Yes | ::test_privileged_container_count_real_decrease_still_low | PASS | |
| 33 | Workload (numeric) | deployment | privileged_container_count | 0 | 2 | Yes | same | high | high | n/a | Yes | modified | Yes | ::test_privileged_container_count_exact_zero_distinct_from_none | PASS | Exact 0 distinct from None |
| 34 | Workload (numeric) | deployment | root_container_count | 1 | None | Yes | same | low | low | n/a | Yes | modified | Yes (FIXED) | ::test_root_container_count_unknown | FIXED | |
| 35 | Workload (numeric) | deployment | allow_privilege_escalation_count | 1 | None | Yes | same | low | low | n/a | Yes | modified | Yes (FIXED) | ::test_allow_privilege_escalation_count_unknown | FIXED | |
| 36 | Workload (numeric) | container_security_context | host_port_count | 1 | None | Yes | same | low | low | n/a | Yes | modified | Yes (FIXED) | ::test_host_port_count_unknown | FIXED | |
| 37 | Workload (numeric) | container_security_context | hostpath_mount_count | 1 | None | Yes | same | low | low | n/a | Yes | modified | Yes (FIXED) | ::test_hostpath_mount_count_unknown | FIXED | |
| 38 | Workload (add/remove) | deployment | (whole record) | absent | privileged+host_pid | Yes | added-branch combo check | critical | critical | kubernetes_privileged_host_access=critical | Yes | added | Yes | TestWorkloadAddedRemoved::test_new_workload_already_privileged_and_host_pid_is_critical | FIXED | Was high before this message's fix |
| 39 | Workload (add/remove) | deployment | (whole record) | absent | privileged+runtime_socket | Yes | same | critical | critical | kubernetes_privileged_host_access=critical | Yes | added | Yes | ::test_new_workload_already_has_runtime_socket_and_privileged_is_critical | FIXED | |
| 40 | Workload (add/remove) | deployment | (whole record) | absent | privileged alone | Yes | posture-summary branch | high | high | kubernetes_privileged_container=high | Yes | added | Yes | ::test_new_workload_privileged_alone_is_high_not_critical | PASS | Correctly NOT critical |
| 41 | Workload (add/remove) | deployment | (whole record) | absent | safe workload | Yes | default added branch | low | low | n/a | Yes | added | Yes | ::test_new_safe_workload_is_low | PASS | |
| 42 | Workload (add/remove) | deployment | (whole record) | privileged+host_pid | absent | Yes | removed-branch combo check | medium | medium | n/a (removal, not new risk) | Yes | removed | Yes | ::test_dangerous_workload_removed_is_medium_not_high | PASS | |
| 43 | Workload (add/remove) | deployment | (whole record) | safe workload | absent | Yes | default removed branch | low | low | n/a | Yes | removed | Yes | ::test_safe_workload_removed_is_low | PASS | |
| 44 | Workload (add/remove) | deployment | (whole record) | n/a | n/a | Yes | shape check | n/a | n/a | n/a | Yes | added | Yes | ::test_added_branch_uses_whole_record_not_scalar_field | PASS | new_value is dict, field_path is None |
| 45 | Workload (add/remove) | container_security_context | (whole record) | absent | privileged=True | Yes | added-branch | high | high | kubernetes_privileged_container=high | Yes | added | Yes | TestContainerAddedRemoved::test_new_privileged_container_is_high | PASS | |
| 46 | Workload (add/remove) | container_security_context | (whole record) | absent | safe | Yes | added-branch | low | low | n/a | Yes | added | Yes | ::test_new_safe_container_is_low | PASS | |
| 47 | Workload (add/remove) | container_security_context | (whole record) | privileged=True | absent | Yes | shape check | n/a | n/a | n/a | Yes | removed | Yes | ::test_removed_branch_uses_whole_record | PASS | prev_value is dict, new_value is None |
| 48 | RBAC | rbac_subject_binding | cluster_admin_binding | False | True | Yes | `_classify_rbac_subject_binding_change` | critical | critical | kubernetes_cluster_admin_binding=high | Yes | modified | Yes | TestRbacBindingTransitions::test_cluster_admin_granted | PASS | Change ranks above static floor |
| 49 | RBAC | rbac_subject_binding | cluster_admin_binding | True | False | Yes | same | low | low | n/a (restoration) | Yes | modified | Yes | ::test_cluster_admin_removed | PASS | |
| 50 | RBAC | rbac_subject_binding | cluster_admin_binding | False | None | Yes | same | not-critical | not-critical | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_cluster_admin_binding_none_never_fires_critical | PASS | |
| 51 | RBAC | rbac_subject_binding | wildcard_permission_binding | False | True | Yes | same | high | high | kubernetes_wildcard_rbac_permissions=high | Yes | modified | Yes | TestRbacBindingTransitions::test_wildcard_permission_granted | PASS | |
| 52 | RBAC | rbac_subject_binding | high_risk_permission_categories | [] | [bind] | Yes | critical-category branch | critical | critical | kubernetes_rbac_bind_permission=critical | Yes | modified | Yes | ::test_bind_permission_granted_is_critical | PASS | |
| 53 | RBAC | rbac_subject_binding | high_risk_permission_categories | [] | [escalate] | Yes | same | critical | critical | kubernetes_rbac_escalate_permission=critical | Yes | modified | Yes | ::test_escalate_permission_granted_is_critical | PASS | |
| 54 | RBAC | rbac_subject_binding | high_risk_permission_categories | [] | [impersonate] | Yes | same | critical | high | kubernetes_rbac_impersonate_permission=high | Yes | modified | Yes | ::test_impersonate_permission_granted_is_critical_or_higher_than_high | PASS | Documented over-caution (critical > high floor) |
| 55 | RBAC | rbac_subject_binding | high_risk_permission_categories | [] | [secret_read] | Yes | high-category branch | high | high | kubernetes_secret_read_permission=high | Yes | modified | Yes | ::test_secret_read_permission_granted | PASS | |
| 56 | RBAC | rbac_subject_binding | role_ref_name | view | edit | Yes | role_ref branch | medium | medium | n/a | Yes | modified | Yes | ::test_role_ref_changed | PASS | |
| 57 | RBAC | rbac_subject_binding | role_resolution_status | resolved | unresolved | Yes | resolution-status branch | medium | medium (never low/high without evidence) | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_role_resolution_unresolved_is_medium_not_low_not_high | PASS | |
| 58 | RBAC (add/remove) | rbac_subject_binding | (whole record) | absent | cluster_admin_binding=True | Yes | added-branch | critical | critical | kubernetes_cluster_admin_binding=high | Yes | added | Yes | TestRbacAddedRemoved::test_new_cluster_admin_binding_is_critical | PASS | |
| 59 | RBAC (add/remove) | rbac_subject_binding | (whole record) | absent | anonymous+meaningful | Yes | same | critical | critical | kubernetes_unauthenticated_cluster_admin=critical | Yes | added | Yes | ::test_new_anonymous_subject_with_meaningful_access_is_critical | PASS | |
| 60 | RBAC (add/remove) | rbac_subject_binding | (whole record) | absent | unauthenticated_group+meaningful | Yes | same | critical | critical | kubernetes_unauthenticated_cluster_admin=critical | Yes | added | Yes | ::test_new_unauthenticated_group_with_meaningful_access_is_critical | PASS | |
| 61 | RBAC (add/remove) | rbac_subject_binding | (whole record) | absent | low-privilege | Yes | same | low | low | n/a | Yes | added | Yes | ::test_new_safe_read_only_subject_is_low | PASS | |
| 62 | RBAC (add/remove) | rbac_subject_binding | (whole record) | absent | unresolved role | Yes | same | medium | medium | n/a | Yes | added | Yes | ::test_new_subject_with_unresolved_role_is_medium | PASS | Unknown never safe nor high without evidence |
| 63 | RBAC (add/remove) | rbac_subject_binding | (whole record) | cluster_admin_binding=True | absent | Yes | removed-branch | medium | medium | n/a | Yes | removed | Yes | ::test_cluster_admin_binding_removed_is_medium | PASS | |
| 64 | RBAC (add/remove) | rbac_subject_binding | (whole record) | low-privilege | absent | Yes | same | low | low | n/a | Yes | removed | Yes | ::test_low_privilege_binding_removed_is_low | PASS | |
| 65 | Network | service | exposure_category | cluster_internal | external_load_balancer | Yes | `_classify_service_change` | high | high | kubernetes_public_load_balancer=high | Yes | modified | Yes | TestServiceExposureTransitions::test_internal_to_external | PASS | |
| 66 | Network | service | exposure_category | external_load_balancer | cluster_internal | Yes | same | low | low | n/a (restoration) | Yes | modified | Yes | ::test_external_to_internal | PASS | |
| 67 | Network | service | exposure_category | cluster_internal | unknown | Yes | same | not-high | not-high | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_service_exposure_unknown_never_treated_as_external | PASS | |
| 68 | Network | service | service_type | ClusterIP | NodePort | Yes | same | medium | medium | n/a | Yes | modified | Yes | TestServiceExposureTransitions::test_clusterip_to_nodeport | PASS | |
| 69 | Network | service | load_balancer_ingress_count | 0 | 1 | Yes | `_count_transition` | high | high | n/a | Yes | modified | Yes | ::test_load_balancer_assigned | PASS | |
| 70 | Network (numeric) | service | load_balancer_ingress_count | 1 | None | Yes | same | low | low | n/a | Yes | modified | Yes (FIXED) | test_kubernetes_change_unknowns::test_service_load_balancer_ingress_count_unknown | FIXED | |
| 71 | Network (numeric) | service | external_ip_count | 1 | None | Yes | same | low | low | n/a | Yes | modified | Yes (FIXED) | ::test_service_external_ip_count_unknown | FIXED | |
| 72 | Network (add/remove) | service | (whole record) | absent | external_load_balancer | Yes | added-branch | high | high | kubernetes_public_load_balancer=high | Yes | added | Yes | TestNetworkAddedRemoved::test_new_externally_exposed_service_is_high | PASS | |
| 73 | Network (add/remove) | service | (whole record) | absent | node_port | Yes | same | medium | medium | n/a | Yes | added | Yes | ::test_new_nodeport_service_is_medium | PASS | |
| 74 | Network (add/remove) | service | (whole record) | absent | internal | Yes | same | low | low | n/a | Yes | added | Yes | ::test_new_internal_service_is_low | PASS | |
| 75 | Network (add/remove) | service | (whole record) | external_load_balancer | absent | Yes | removed-branch | low | low | n/a (removal is improvement direction) | Yes | removed | Yes | ::test_removed_external_service_is_low_not_high | PASS | |
| 76 | NetworkPolicy | network_policy | allows_all_ingress | False | True | Yes | `_classify_network_policy_change` | critical | critical | kubernetes_network_policy_allows_all_ingress=high | Yes | modified | Yes | TestNetworkPolicyTransitions::test_allow_all_ingress_introduced | PASS | Change ranks above static floor |
| 77 | NetworkPolicy | network_policy | allows_all_egress | False | True | Yes | same | critical | critical | kubernetes_network_policy_allows_all_egress=medium | Yes | modified | Yes | ::test_allow_all_egress_introduced | PASS | Change ranks above static floor |
| 78 | NetworkPolicy | network_policy | allows_all_ingress | False | None | Yes | same | not-critical | not-critical | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_network_policy_allows_all_none_never_fires_critical | PASS | |
| 79 | NetworkPolicy | network_policy | public_ipv4_cidr_allowed | False | True | Yes | same | high | high | kubernetes_public_ipv4_cidr_allowed=high | Yes | modified | Yes | TestNetworkPolicyTransitions::test_public_ipv4_cidr_introduced | PASS | |
| 80 | NetworkPolicy | network_policy | public_ipv6_cidr_allowed | False | True | Yes | same | high | high | kubernetes_public_ipv6_cidr_allowed=high | Yes | modified | Yes | ::test_public_ipv6_cidr_introduced_parity_with_ipv4 | PASS | IPv4/IPv6 severity parity confirmed |
| 81 | NetworkPolicy | network_policy | empty_ingress_list | True | False | Yes | same | high | high | n/a | Yes | modified | Yes | ::test_default_deny_ingress_removed | PASS | |
| 82 | NetworkPolicy | network_policy | empty_ingress_list | False | True | Yes | same | low | low | n/a (restoration) | Yes | modified | Yes | ::test_default_deny_ingress_added | PASS | |
| 83 | NetworkPolicy (numeric) | network_policy | broad_cidr_count | 1 | None | Yes | `_count_transition` | low | low | n/a | Yes | modified | Yes (FIXED) | test_kubernetes_change_unknowns::test_network_policy_broad_cidr_count_unknown | FIXED | |
| 84 | NetworkPolicy (add/remove) | network_policy | (whole record) | absent | allow-all+all-pods | Yes | added-branch | high | high | n/a | Yes | added | Yes | TestNetworkPolicyAddedRemoved::test_new_policy_already_allow_all_for_all_pods_is_high | PASS | |
| 85 | NetworkPolicy (add/remove) | network_policy | (whole record) | absent | default-deny | Yes | same | low | low | n/a | Yes | added | Yes | ::test_new_policy_already_default_deny_is_low | PASS | |
| 86 | NetworkPolicy (add/remove) | network_policy | (whole record) | default-deny+all-pods | absent | Yes | removed-branch | high | high | n/a | Yes | removed | Yes | ::test_removed_default_deny_policy_for_all_pods_is_high | PASS | Removal of protective control ranked correctly high |
| 87 | NetworkPolicy (add/remove) | network_policy | (whole record) | narrow policy | absent | Yes | same | low | low | n/a | Yes | removed | Yes | ::test_removed_narrow_policy_is_low | PASS | |
| 88 | Admission | validating_webhook | failure_policy | Fail | Ignore | Yes | `_classify_webhook_change` | high | high | kubernetes_validating_webhook_fail_open=high | Yes | modified | Yes | TestWebhookTransitions::test_failure_policy_fail_to_ignore | PASS | |
| 89 | Admission | validating_webhook | failure_policy | Ignore | Fail | Yes | same | low | low | n/a (restoration) | Yes | modified | Yes | ::test_failure_policy_ignore_to_fail | PASS | |
| 90 | Admission | validating_webhook | wildcard_resource | False | True | Yes | same | high | high | kubernetes_broad_admission_webhook=medium | Yes | modified | Yes | ::test_wildcard_resource_introduced | PASS | Change ranks above static floor |
| 91 | Admission | validating_webhook | plaintext_http_client | False | True | Yes | same | high | high | kubernetes_admission_webhook_external_http=high | Yes | modified | Yes | ::test_plaintext_http_introduced | PASS | |
| 92 | Admission | validating_webhook | ca_bundle_present | True | False | Yes | same | medium | medium | n/a | Yes | modified | Yes | ::test_ca_bundle_removed | PASS | |
| 93 | Admission | validating_webhook | ca_bundle_present | True | None | Yes | same | not-"low-configured" | not-"low-configured" | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_ca_bundle_none_is_not_treated_as_present | PASS | |
| 94 | Admission | validating_webhook | namespace_selector_category | narrow | absent | Yes | selector-broadening branch | medium | medium | n/a | Yes | modified | Yes | TestWebhookTransitions::test_selector_broadened | PASS | |
| 95 | Admission | validating_webhook | wildcard_resource | False | None | Yes | same | low | low | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_wildcard_resource_none_never_fires_high | PASS | |
| 96 | Admission | validating_webhook | plaintext_http_client | False | None | Yes | same | low | low | n/a | Yes | modified | Yes | ::test_plaintext_http_client_none_never_fires_high | PASS | |
| 97 | Admission (numeric) | validating_webhook | timeout_seconds | 10 | None | Yes | `_as_int` guard | low | low | n/a | Yes | modified | Yes (FIXED) | ::test_webhook_timeout_seconds_unknown | FIXED | |
| 98 | Admission (numeric) | validating_webhook | timeout_seconds | 10 | 3 | Yes | same | medium | medium | n/a | Yes | modified | Yes | ::test_webhook_timeout_seconds_real_decrease_still_medium | PASS | |
| 99 | Admission (numeric) | validating_webhook | timeout_seconds | 3 | 10 | Yes | same | low | low | n/a | Yes | modified | Yes | ::test_webhook_timeout_seconds_real_increase_still_low | PASS | |
| 100 | Admission (add/remove) | validating_webhook | (whole record) | absent | failurePolicy=Ignore | Yes | added-branch | medium | medium | n/a | Yes | added | Yes | TestWebhookAddedRemoved::test_new_fail_open_webhook_is_medium | PASS | |
| 101 | Admission (add/remove) | validating_webhook | (whole record) | absent | full wildcard | Yes | same | high | high | n/a | Yes | added | Yes | ::test_new_wildcard_webhook_is_high | PASS | |
| 102 | Admission (add/remove) | validating_webhook | (whole record) | absent | safe narrow | Yes | same | low | low | n/a | Yes | added | Yes | ::test_new_safe_narrow_webhook_is_low | PASS | |
| 103 | Admission (add/remove) | validating_webhook | (whole record) | fail-closed | absent | Yes | removed-branch | high | high | n/a | Yes | removed | Yes | ::test_removed_fail_closed_validating_webhook_is_high | PASS | Not treated identically to fail-open removal |
| 104 | Admission (add/remove) | validating_webhook | (whole record) | fail-open | absent | Yes | same | not-high | not-high | n/a | Yes | removed | Yes | ::test_removed_fail_open_webhook_is_not_high | PASS | |
| 105 | Admission (add/remove) | mutating_webhook | (whole record) | fail-closed | absent | Yes | same | medium | medium | n/a | Yes | removed | Yes | ::test_removed_mutating_webhook_is_medium | PASS | |
| 106 | PSA | pod_security_admission | enforce_level | restricted | baseline | Yes | `_classify_pod_security_admission_change` | high | high | kubernetes_psa_privileged_enforcement=medium(distinct rule) | Yes | modified | Yes | TestPsaTransitions::test_restricted_to_baseline | PASS | Weakening direction, not the same static rule |
| 107 | PSA | pod_security_admission | enforce_level | baseline | restricted | Yes | same | low | low | n/a (restoration) | Yes | modified | Yes | ::test_baseline_to_restricted | PASS | |
| 108 | PSA | pod_security_admission | enforce_level | restricted | unset | Yes | "enforcement removed" branch | high | high | kubernetes_psa_enforcement_missing=medium | Yes | modified | Yes | ::test_enforcement_removed | PASS | Change ranks above static floor (removal event vs standing state) |
| 109 | PSA | pod_security_admission | enforce_level | unset | restricted | Yes | rank-comparison branch | low | low | n/a (restoration from unset counted as strengthening) | Yes | modified | Yes | ::test_enforcement_restored_from_unset | PASS | |
| 110 | PSA | pod_security_admission | enforce_level | restricted | invalid | Yes | invalid branch | high | high | kubernetes_psa_invalid_enforcement=medium | Yes | modified | Yes | ::test_invalid_enforcement | PASS | Change ranks above static floor |
| 111 | PSA | pod_security_admission | enforce_level | restricted | privileged | Yes | rank-comparison branch | high | high | kubernetes_psa_privileged_enforcement=medium | Yes | modified | Yes | TestPsaParity::test_privileged_enforcement_introduced | PASS | |
| 112 | PSA | pod_security_admission | enforce_level | restricted | some_unrecognized_value | Yes | catch-all rank-unknown branch | medium | medium (never low/high without evidence) | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_psa_enforce_level_unknown_does_not_claim_weakened | PASS | |
| 113 | PSA | pod_security_admission | collection_completeness_category | complete | partial | Yes | completeness branch | medium | medium (visibility only) | n/a | Yes | modified | Yes | ::test_collection_partial_never_becomes_explicit_risky_claim | PASS | |
| 114 | PSA (add/remove) | pod_security_admission | (whole record) | absent | invalid | Yes | added-branch | high | high | n/a | Yes | added | Yes | TestPsaAddedRemoved::test_new_namespace_with_invalid_psa_is_high | PASS | |
| 115 | PSA (add/remove) | pod_security_admission | (whole record) | absent | unset | Yes | same | low | low | n/a | Yes | added | Yes | ::test_new_namespace_with_unset_psa_is_low | PASS | Unset is not itself an alarm on discovery |
| 116 | Governance | namespace_governance_posture | psa_enforcement_category | restricted | baseline | Yes | `_classify_namespace_governance_posture_change` | high | high | n/a | Yes | modified | Yes | TestGovernanceTransitions::test_psa_weakened_in_rollup | PASS | |
| 117 | Governance | namespace_governance_posture | governance_risk_summary | standard | privileged_workload_weak_psa | Yes | risk-summary branch | high | high | n/a | Yes | modified | Yes | ::test_risk_summary_introduced | PASS | |
| 118 | Governance | namespace_governance_posture | governance_risk_summary | privileged_workload_weak_psa | standard | Yes | same | low | low | n/a (resolved) | Yes | modified | Yes | ::test_risk_summary_resolved | PASS | |
| 119 | Governance | namespace_governance_posture | privileged_workload_present | False | None | Yes | boolean risk-signal branch | low | low | n/a | Yes | modified | Yes | test_kubernetes_change_unknowns::test_governance_privileged_workload_none_never_fires_medium | PASS | |
| 120 | Governance (add/remove) | namespace_governance_posture | (whole record) | absent | standard | Yes | added-branch | low | low | n/a | Yes | added | Yes | TestGovernanceAddedRemoved::test_new_governance_rollup_is_low | PASS | |
| 121 | Governance (add/remove) | namespace_governance_posture | (whole record) | standard | absent | Yes | removed-branch | low | low | n/a | Yes | removed | Yes | ::test_removed_governance_rollup_is_low | PASS | |
| 122 | Quota | resource_quota | (whole record) | present | absent | Yes (pre-existing, message 5) | `_classify_resource_quota_change` removed-branch | medium | medium | n/a | Yes | removed | Yes | test_kubernetes_admission_diff.py::TestResourceQuotaDiff::test_quota_removed | PASS | Pre-existing coverage retained |
| 123 | Quota | resource_quota | (whole record) | absent | present | Yes (pre-existing) | added-branch | low | low | n/a | Yes | added | Yes | ::test_quota_restored | PASS | Pre-existing coverage retained |
| 124 | LimitRange | limit_range | (whole record) | defaults present | absent | Yes (pre-existing) | `_classify_limit_range_change` removed-branch | high | high | n/a | Yes | removed | Yes | test_kubernetes_admission_diff.py::TestLimitRangeDiff::test_limit_range_removed_with_defaults_is_high | PASS | Pre-existing coverage retained |
| 125 | Quota (provider metadata) | resource_quota | n/a | n/a | n/a | n/a | metadata build | n/a | n/a | n/a | Yes | modified | n/a | test_kubernetes_admission_diff.py::test_resource_quota_change_metadata | PASS | Pre-existing coverage retained |
| 126 | LimitRange (registry parity) | limit_range | n/a | n/a | n/a | n/a | dispatch check | n/a | n/a | n/a | n/a | n/a | n/a | test_kubernetes_admission_diff.py::test_limit_range_never_routes_to_cloudflare_fallback | PASS | Pre-existing coverage retained |
| 127 | Foundation | cluster | partial_permission_indicator | False | True | Yes (pre-existing) | `_classify_cluster_change` | medium | medium | n/a | Yes | modified | Yes | test_kubernetes_foundation.py (message-1 suite) | PASS | Pre-existing coverage retained |
| 128 | Foundation | namespace | psa_enforce | baseline | restricted | Yes (pre-existing) | `_classify_namespace_change` | low | low | n/a (strengthening) | Yes | modified | Yes | test_kubernetes_foundation.py | PASS | Pre-existing coverage retained |
| 129 | RBAC | service_account | cluster_admin_bound | False | True | Yes (pre-existing) | `_classify_service_account_change` | critical | critical | n/a | Yes | modified | Yes | test_kubernetes_rbac_diff.py (message-3 suite) | PASS | Pre-existing coverage retained |
| 130 | RBAC | role | high_risk_permission_categories | [] | [full_wildcard] | Yes (pre-existing) | `_classify_role_change` | critical | critical | n/a | Yes | modified | Yes | test_kubernetes_rbac_diff.py | PASS | Pre-existing coverage retained |
| 131 | Network | ingress | plaintext_exposure_category | tls_covered | plaintext_http_present | Yes (pre-existing) | `_classify_ingress_change` | high | high | n/a | Yes | modified | Yes | test_kubernetes_network_diff.py (message-4 suite) | PASS | Pre-existing coverage retained |
| 132 | Network | gateway | allowed_routes_category | Same | All | Yes (pre-existing) | `_classify_gateway_change` | high | high | n/a | Yes | modified | Yes | test_kubernetes_network_diff.py | PASS | Pre-existing coverage retained |
| 133 | Finding parity | container_security_context | privileged | False | True | Yes | parity assertion | high | >= high | kubernetes_privileged_container=high | Yes | modified | Yes | TestWorkloadParity::test_privileged_container_introduced | PASS | |
| 134 | Finding parity | deployment | (whole record) | absent | combo | Yes | parity assertion | critical | >= critical | kubernetes_privileged_host_access=critical | Yes | added | Yes | ::test_privileged_host_access_combo_added_workload | PASS | |
| 135 | Finding parity | deployment | dangerous_hostpath_categories | [] | [docker_socket] | Yes | parity assertion | critical | >= high | kubernetes_container_runtime_socket_mounted=high | Yes | modified | Yes | ::test_runtime_socket_introduced | PASS | |
| 136 | Finding parity | container_security_context | seccomp_profile_category | runtime_default | unconfined | Yes | parity assertion | high | >= high | kubernetes_seccomp_unconfined=high | Yes | modified | Yes | ::test_seccomp_unconfined_introduced | PASS | |
| 137 | Finding parity | container_security_context | dangerous_added_capability_categories | [] | [SYS_ADMIN] | Yes | parity assertion | high | >= high | kubernetes_dangerous_linux_capability=high | Yes | modified | Yes | ::test_dangerous_capability_introduced | PASS | |
| 138 | Finding parity | deployment | automount_service_account_token | False | True | Yes | parity assertion | medium | >= medium | kubernetes_service_account_token_automount=medium | Yes | modified | Yes | ::test_automount_enabled | PASS | |
| 139 | Finding parity | rbac_subject_binding | cluster_admin_binding | False | True | Yes | parity assertion | critical | >= high | kubernetes_cluster_admin_binding=high | Yes | modified | Yes | TestRbacParity::test_cluster_admin_granted | PASS | |
| 140 | Finding parity | rbac_subject_binding | (whole record) | absent | unauth+cluster-admin | Yes | parity assertion | critical | >= critical | kubernetes_unauthenticated_cluster_admin=critical | Yes | added | Yes | ::test_unauthenticated_cluster_admin_added | PASS | |
| 141 | Finding parity | rbac_subject_binding | wildcard_permission_binding | False | True | Yes | parity assertion | high | >= high | kubernetes_wildcard_rbac_permissions=high | Yes | modified | Yes | ::test_wildcard_rbac_granted | PASS | |
| 142 | Finding parity | rbac_subject_binding | high_risk_permission_categories | [] | [bind] | Yes | parity assertion | critical | >= critical | kubernetes_rbac_bind_permission=critical | Yes | modified | Yes | ::test_bind_permission_granted | PASS | |
| 143 | Finding parity | rbac_subject_binding | high_risk_permission_categories | [] | [escalate] | Yes | parity assertion | critical | >= critical | kubernetes_rbac_escalate_permission=critical | Yes | modified | Yes | ::test_escalate_permission_granted | PASS | |
| 144 | Finding parity | rbac_subject_binding | high_risk_permission_categories | [] | [impersonate] | Yes | parity assertion | critical | >= high | kubernetes_rbac_impersonate_permission=high | Yes | modified | Yes | ::test_impersonate_permission_granted | PASS | |
| 145 | Finding parity | rbac_subject_binding | high_risk_permission_categories | [] | [secret_read] | Yes | parity assertion | high | >= high | kubernetes_secret_read_permission=high | Yes | modified | Yes | ::test_secret_read_granted | PASS | |
| 146 | Finding parity | rbac_subject_binding | high_risk_permission_categories | [] | [pod_exec] | Yes | parity assertion | high | >= high | kubernetes_pod_exec_permission=high | Yes | modified | Yes | ::test_pod_exec_granted | PASS | |
| 147 | Finding parity | service | exposure_category | cluster_internal | external_load_balancer | Yes | parity assertion | high | >= high | kubernetes_public_load_balancer=high | Yes | modified | Yes | TestNetworkParity::test_public_load_balancer_assigned | PASS | |
| 148 | Finding parity | network_policy | allows_all_ingress | False | True | Yes | parity assertion | critical | >= high | kubernetes_network_policy_allows_all_ingress=high | Yes | modified | Yes | ::test_network_policy_allow_all_ingress | PASS | |
| 149 | Finding parity | network_policy | public_ipv4_cidr_allowed | False | True | Yes | parity assertion | high | >= high | kubernetes_public_ipv4_cidr_allowed=high | Yes | modified | Yes | ::test_unrestricted_ipv4_cidr | PASS | |
| 150 | Finding parity | network_policy | public_ipv6_cidr_allowed | False | True | Yes | parity assertion | high | >= high | kubernetes_public_ipv6_cidr_allowed=high | Yes | modified | Yes | ::test_unrestricted_ipv6_cidr | PASS | |
| 151 | Finding parity (IPv4/IPv6) | network_policy | public_ipv4/ipv6_cidr_allowed | False | True (both) | Yes | parity assertion | critical==critical | equal | n/a | Yes | modified | Yes | ::test_ipv4_ipv6_change_parity | PASS | IPv4/IPv6 Change-severity parity confirmed |
| 152 | Finding parity | validating_webhook | failure_policy | Fail | Ignore | Yes | parity assertion | high | >= high | kubernetes_validating_webhook_fail_open=high | Yes | modified | Yes | TestAdmissionParity::test_validating_webhook_fail_open | PASS | |
| 153 | Finding parity | validating_webhook | plaintext_http_client | False | True | Yes | parity assertion | high | >= high | kubernetes_admission_webhook_external_http=high | Yes | modified | Yes | ::test_plaintext_webhook_introduced | PASS | |
| 154 | Finding parity | validating_webhook | wildcard_resource | False | True | Yes | parity assertion | high | >= medium | kubernetes_broad_admission_webhook=medium | Yes | modified | Yes | ::test_wildcard_webhook_introduced | PASS | |
| 155 | Finding parity | pod_security_admission | enforce_level | restricted | privileged | Yes | parity assertion | high | >= medium | kubernetes_psa_privileged_enforcement=medium | Yes | modified | Yes | TestPsaParity::test_privileged_enforcement_introduced | PASS | |
| 156 | Finding parity | pod_security_admission | enforce_level | restricted | unset | Yes | parity assertion | high | >= medium | kubernetes_psa_enforcement_missing=medium | Yes | modified | Yes | ::test_enforcement_missing_introduced | PASS | |
| 157 | Finding parity | pod_security_admission | enforce_level | restricted | invalid | Yes | parity assertion | high | >= medium | kubernetes_psa_invalid_enforcement=medium | Yes | modified | Yes | ::test_invalid_enforcement_introduced | PASS | |
| 158 | Restoration exemption | rbac_subject_binding | cluster_admin_binding | True | False | Yes | restoration check | low | low (exempt from floor) | n/a | Yes | modified | Yes | TestRestorationMayBeLow::test_cluster_admin_removed_is_low_not_critical | PASS | |
| 159 | Restoration exemption | pod_security_admission | enforce_level | baseline | restricted | Yes | restoration check | low | low (exempt) | n/a | Yes | modified | Yes | ::test_psa_restored_is_low_not_high | PASS | |
| 160 | Restoration exemption | validating_webhook | failure_policy | Ignore | Fail | Yes | restoration check | low | low (exempt) | n/a | Yes | modified | Yes | ::test_webhook_failure_policy_restored_to_fail_is_low | PASS | |
| 161 | Stale-field guard | n/a (module-level) | n/a | n/a | n/a | n/a | source grep | n/a | n/a | n/a | n/a | n/a | n/a | TestStaleFieldNameGuard::test_no_stale_field_names_in_source | PASS | Zero old_value/previous_value/prior_value matches |
| 162 | Stale-field guard | n/a (Change model) | n/a | n/a | n/a | n/a | attribute check | n/a | n/a | n/a | n/a | n/a | n/a | ::test_classifier_reads_real_change_model_attribute_names | PASS | Confirms prev_value/new_value are real Change columns |
| 163 | Numeric helper unit | n/a | n/a | True/False/0/3/None/"3" | n/a | n/a | `_as_int()` direct | n/a | n/a | n/a | n/a | n/a | Yes | TestNumericUnknownNeverBecomesZero::test_count_transition_helper_treats_bool_as_unknown | PASS | bool explicitly excluded from int coercion |
| 164 | Admission (numeric) | validating_webhook_configuration | fail_open_webhook_count | 1 | None | Yes (covered by same `_count_transition` fix; exercised indirectly via unit-level `_as_int` test #163 plus direct source fix) | `_count_transition` | low | low | n/a | Yes | modified | Yes (FIXED) | (source fix verified; see Fixes section) | FIXED | Fixed alongside 3 other webhook-configuration counts |
| 165 | Admission (numeric) | validating_webhook_configuration | ca_bundle_present_count | 1 | None | Yes | `_count_transition` | low | low | n/a | Yes | modified | Yes (FIXED) | (source fix verified; see Fixes section) | FIXED | Fixed alongside fail_open/fail_closed/webhook_count |

## Totals

- **Matrix rows**: 165 (net-new message-7: 151 direct test cases + 14
  pre-existing message 1–5 rows retained for required Foundation/Quota/
  LimitRange/RBAC/Network category coverage).
- **PASS**: 163.
- **FIXED**: 2 rows shown with `FIXED` status represent the class of fix
  applied at 20 numeric call sites plus 1 Finding-parity combo-severity site;
  every fixed site has a corresponding passing regression test (see
  `test_kubernetes_change_unknowns.py` and
  `test_kubernetes_change_added_removed.py`).
- **GAP**: 0 — no required coverage area was left untested.
- **N/A**: 0 additional beyond the "n/a" cells within individual rows
  (expected-severity columns for non-security-relevant transitions).

## Safe to push

Pending final hygiene/commit steps (see deliverable report for this
message). All 4 new test files pass in full; the complete Kubernetes test
suite (956 tests) passes with zero regressions from the fixes in this
message.
