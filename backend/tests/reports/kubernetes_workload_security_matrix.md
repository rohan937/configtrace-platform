# Kubernetes Workload & Pod-Security Matrix (Message 2 of 9)

Covers workload inventory and Pod-security posture collection: Deployments,
StatefulSets, DaemonSets, Jobs, CronJobs, standalone Pods, and per-container
security-context records. RBAC, networking, admission/config controls, the
complete Security Finding taxonomy, exhaustive Change classification, scale
hardening, and final certification are explicitly deferred to messages 3–9.

## Record taxonomy (final, message 2)

| Record type | Emitted for | Scope |
|---|---|---|
| `kubernetes_deployment` | Deployments | Declarative + aggregated posture |
| `kubernetes_statefulset` | StatefulSets | Declarative + aggregated posture |
| `kubernetes_daemonset` | DaemonSets | Declarative + aggregated posture |
| `kubernetes_job` | Jobs | Declarative + aggregated posture |
| `kubernetes_cronjob` | CronJobs | Declarative + aggregated posture (via jobTemplate) |
| `kubernetes_pod` | **Standalone Pods only** (no ownerReferences) | Declarative + separated runtime-only fields |
| `kubernetes_container_security_context` | One per container (application/init/ephemeral), for every workload family above | Per-container precision |
| `kubernetes_workload_service_account` | One rollup per (namespace, service_account_name) referenced by ≥1 collected workload | Automount-posture counts only |

**Pod-emission policy**: controller-owned Pods are never emitted as
individual `kubernetes_pod` records — their posture is captured once,
precisely, from the owning controller's Pod template. This avoids
duplicating identical template posture N times per replica and avoids
turning an ordinary rolling update into N spurious create/delete Changes.

## Explicit / effective / unknown semantics

Every tri-state security field is `True`/`False`/`None`. `None` always means
"not explicitly set" — never a confirmed secure or risky state.
`hostNetwork`/`hostPID`/`hostIPC` are the one exception, stored as concrete
booleans, since Kubernetes documents their default as `false` (not
"unknown"). `automountServiceAccountToken`, `runAsNonRoot`, `runAsUser`,
seccomp/AppArmor profile category, and read-only-root-filesystem have no
safe universal default and are always `None` when omitted.

## Matrix

| Case | Resource kind | Record type | Source field | Normalized field | Explicit/Effective/Unknown | Collected? | Diff tracked? | Classifier route | Expected severity | Sensitive-data risk | Test coverage | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A | Deployment | kubernetes_deployment | spec.template | (baseline) | n/a | Yes | Yes | classify_kubernetes_change → controller | low | none | test_kubernetes_workload_foundation.py::TestPerFamilyCollection | PASS |
| B | StatefulSet | kubernetes_statefulset | spec.template | (baseline) | n/a | Yes | Yes | controller | low | none | TestPerFamilyCollection | PASS |
| C | DaemonSet | kubernetes_daemonset | spec.template | (baseline) | n/a | Yes | Yes | controller | low | none | TestPerFamilyCollection | PASS |
| D | Job | kubernetes_job | spec.template | (baseline) | n/a | Yes | Yes | controller | low | none | TestPerFamilyCollection | PASS |
| E | CronJob | kubernetes_cronjob | spec.jobTemplate.spec.template | (baseline) | n/a | Yes | Yes | controller | low | none | TestPerFamilyCollection | PASS |
| F | Pod | kubernetes_pod | metadata.ownerReferences (empty) | mirror_pod / declarative fields | n/a | Yes | Yes (declarative only) | controller (shared fn) | low | none | TestPodEmissionPolicy::test_standalone_pod_is_emitted | PASS |
| G | Pod | (none — represented via controller) | metadata.ownerReferences (non-empty) | n/a | n/a | No (by design) | n/a | n/a | n/a | none | TestPodEmissionPolicy::test_controller_owned_pod_is_not_emitted | PASS |
| H | Deployment/container (application) | kubernetes_container_security_context | securityContext.privileged | privileged | Explicit | Yes | Yes | container | high | none | TestPrivilegedAcrossCategories::test_privileged_application_container | PASS |
| I | Deployment/container (init) | kubernetes_container_security_context | initContainers[].securityContext.privileged | privileged, container_category=init | Explicit | Yes | Yes | container | high | none | TestPrivilegedAcrossCategories::test_privileged_init_container | PASS |
| J | Deployment/container (ephemeral) | kubernetes_container_security_context | ephemeralContainers[].securityContext.privileged | privileged, container_category=ephemeral | Explicit | Yes | Yes | container | high | none | TestPrivilegedAcrossCategories::test_privileged_ephemeral_container | PASS |
| K | container | kubernetes_container_security_context | securityContext.allowPrivilegeEscalation | allow_privilege_escalation | Explicit | Yes | Yes | container | medium | none | TestRootAndPrivilegeEscalation::test_allow_privilege_escalation_true | PASS |
| L | container | kubernetes_container_security_context | securityContext.runAsNonRoot=false | run_as_non_root | Explicit | Yes | Yes | container | high | none | TestRootAndPrivilegeEscalation::test_explicit_run_as_non_root_false | PASS |
| M | container | kubernetes_container_security_context | securityContext.runAsUser=0 | run_as_uid, run_as_user_set | Explicit | Yes | Yes | container | high | none (UID is not sensitive) | TestRootAndPrivilegeEscalation::test_explicit_uid_zero | PASS |
| N | container | kubernetes_container_security_context | securityContext.runAsUser omitted | run_as_uid=None, run_as_user_set=False | Unknown | Yes | Yes | container | low (no claim) | none | TestRootAndPrivilegeEscalation::test_unknown_run_as_user_is_none_not_a_claim | PASS |
| O | Deployment | kubernetes_deployment | spec.template.spec.hostNetwork | host_network | Explicit (default-false documented) | Yes | Yes | controller | medium | none | TestHostNamespaceAccess::test_host_network | PASS |
| P | Deployment | kubernetes_deployment | spec.template.spec.hostPID | host_pid | Explicit (default-false documented) | Yes | Yes | controller | high | none | TestHostNamespaceAccess::test_host_pid | PASS |
| Q | Deployment | kubernetes_deployment | spec.template.spec.hostIPC | host_ipc | Explicit (default-false documented) | Yes | Yes | controller | high | none | TestHostNamespaceAccess::test_host_ipc | PASS |
| R | Pod | kubernetes_pod | spec.shareProcessNamespace | share_process_namespace | Explicit/Unknown | Yes | Yes | controller (shared fn) | medium | none | TestHostNamespaceAccess::test_share_process_namespace_on_standalone_pod | PASS |
| S | hostPath volume | kubernetes_deployment / container | volumes[].hostPath.path="/" | dangerous_hostpath_categories=root_filesystem | Categorized (path never stored) | Yes | Yes | controller | high (critical if socket) | path never persisted | TestHostPathCategorization::test_root_mounted | PASS |
| T | hostPath volume | kubernetes_container_security_context | path="/var/run/docker.sock" | docker_socket category | Categorized | Yes | Yes | controller/container | critical | path never persisted | TestHostPathCategorization::test_docker_socket, TestHostPathChanges::test_writable_docker_socket_mount_is_critical | PASS |
| U | hostPath volume | kubernetes_container_security_context | path="/run/containerd/..." | containerd_socket category | Categorized | Yes | Yes | controller/container | critical | path never persisted | TestHostPathCategorization::test_containerd_socket | PASS |
| V | hostPath volume | kubernetes_container_security_context | path="/var/lib/kubelet/..." | kubelet_dir category | Categorized | Yes | Yes | controller/container | high | path never persisted | TestHostPathCategorization::test_kubelet_dir | PASS |
| W | hostPath mount | kubernetes_container_security_context | volumeMounts[].readOnly=false | writable_hostpath_mount_count | Explicit | Yes | Yes | container | medium/high | none | TestHostPathCategorization::test_writable_hostpath_mount_counted | PASS |
| X | volumeMount | kubernetes_container_security_context | volumeMounts[].mountPropagation="Bidirectional" | bidirectional_mount_propagation_present | Explicit | Yes | Yes | container | medium | none | TestHostPathCategorization::test_bidirectional_mount_propagation | PASS |
| Y | container | kubernetes_container_security_context | securityContext.capabilities.add=[SYS_ADMIN] | capabilities_added, dangerous_added_capability_categories | Explicit | Yes | Yes | container | high | none | TestCapabilities::test_sys_admin_added | PASS |
| Z | container | kubernetes_container_security_context | capabilities.add=[NET_ADMIN] | dangerous_added_capability_categories | Explicit | Yes | Yes | container | medium | none | TestCapabilities::test_net_admin_added | PASS |
| AA | container | kubernetes_container_security_context | capabilities.add=[SYS_PTRACE] | dangerous_added_capability_categories | Explicit | Yes | Yes | container | medium | none | TestCapabilities::test_sys_ptrace_added | PASS |
| AB | container | kubernetes_container_security_context | capabilities.add=[ALL] | capabilities_added=[ALL] | Explicit | Yes | Yes | container | high | none | TestCapabilities::test_all_capability_added | PASS |
| AC | container | kubernetes_container_security_context | capabilities.drop=[ALL] | capabilities_dropped=[ALL] | Explicit | Yes | Yes | container | low | none | TestCapabilities::test_all_capabilities_dropped, TestCapabilityChanges::test_all_capability_dropped_is_low_severity | PASS |
| AD | container | kubernetes_container_security_context | seccompProfile.type=RuntimeDefault | seccomp_profile_category=runtime_default | Explicit | Yes | Yes | container | low | none | TestSeccomp::test_runtime_default | PASS |
| AE | container | kubernetes_container_security_context | seccompProfile.type=Unconfined | seccomp_profile_category=unconfined | Explicit | Yes | Yes | container | high | none | TestSeccomp::test_unconfined, TestSeccompChanges::test_seccomp_changed_to_unconfined | PASS |
| AF | container | kubernetes_container_security_context | seccompProfile omitted | seccomp_profile_category=omitted | Unknown | Yes | Yes | container | low (no claim) | none | TestSeccomp::test_omitted_is_not_a_claim_of_protection | PASS |
| AG | container | kubernetes_container_security_context | securityContext.appArmorProfile.type=RuntimeDefault | apparmor_profile_category=runtime_default | Explicit (structured, 1.30+) | Yes | Yes | container | low | none | TestAppArmor::test_structured_runtime_default | PASS |
| AH | Pod annotation | kubernetes_container_security_context | container.apparmor.security.beta.kubernetes.io/<name>=unconfined | apparmor_profile_category=unconfined | Explicit (legacy annotation) | Yes | Yes | container | medium | only this one well-known key ever read | TestAppArmor::test_legacy_annotation_unconfined, test_no_other_annotation_is_ever_read | PASS |
| AI | container | kubernetes_container_security_context | securityContext.readOnlyRootFilesystem=true | read_only_root_filesystem=true | Explicit | Yes | Yes | container | low | none | TestRootFilesystem::test_read_only_true | PASS |
| AJ | container | kubernetes_container_security_context | readOnlyRootFilesystem=false | read_only_root_filesystem=false | Explicit | Yes | Yes | container | medium | none | TestRootFilesystem::test_writable | PASS |
| AK | Deployment | kubernetes_deployment | spec.template.spec.automountServiceAccountToken=true | automount_service_account_token=true | Explicit | Yes | Yes | controller | medium | none | TestAutomount::test_explicit_automount, TestServiceAccountAutomountChanges | PASS |
| AL | Deployment | kubernetes_deployment | automountServiceAccountToken omitted | automount_service_account_token=None | Unknown/inherited | Yes | Yes | controller | low (no claim) | none | TestAutomount::test_inherited_automount_is_none_not_false | PASS |
| AM | container | kubernetes_container_security_context | image="nginx@sha256:..." | image_tag_category=pinned_digest | Categorized | Yes | Yes | container | low | none | TestImageCategorization::test_pinned_by_digest | PASS |
| AN | container | kubernetes_container_security_context | image="nginx:1.25.3" | image_tag_category=explicit_tag | Categorized | Yes | Yes | container | low | none | TestImageCategorization::test_explicit_immutable_tag | PASS |
| AO | container | kubernetes_container_security_context | image="nginx:latest" | image_tag_category=latest_explicit | Categorized | Yes | Yes | container | medium | none | TestImageCategorization::test_latest_explicit, TestImagePostureChanges | PASS |
| AP | container | kubernetes_container_security_context | image="nginx" (no tag) | image_tag_category=latest_implicit | Categorized | Yes | Yes | container | medium | none | TestImageCategorization::test_implicit_latest | PASS |
| AQ | container | kubernetes_container_security_context | imagePullPolicy=Always | image_pull_policy | Explicit | Yes | Yes (informational) | container | low | none | TestImageCategorization::test_pull_policy_always | PASS |
| AR | container | kubernetes_container_security_context | resources.requests (no cpu) | cpu_request_present=false | Explicit absence | Yes | Yes | container | low | none | TestResourceControls::test_no_cpu_request | PASS |
| AS | container | kubernetes_container_security_context | resources.requests (no memory) | memory_request_present=false | Explicit absence | Yes | Yes | container | low | none | TestResourceControls::test_no_memory_request | PASS |
| AT | container | kubernetes_container_security_context | resources.limits (no cpu) | cpu_limit_present=false | Explicit absence | Yes | Yes | container | medium (via any_resource_limit_present) | none | TestResourceControls::test_no_cpu_limit | PASS |
| AU | container | kubernetes_container_security_context | resources.limits (no memory) | memory_limit_present=false | Explicit absence | Yes | Yes | container | medium | none | TestResourceControls::test_no_memory_limit, TestResourceControlChanges | PASS |
| AV | container | kubernetes_container_security_context | livenessProbe present | liveness_probe_present=true | Explicit | Yes | Yes | container | low | probe payload never persisted | TestProbes::test_liveness_probe_presence | PASS |
| AW | container | kubernetes_container_security_context | readinessProbe present | readiness_probe_present=true | Explicit | Yes | Yes | container | low | probe payload never persisted | TestProbes::test_readiness_probe_presence | PASS |
| AX | container | kubernetes_container_security_context | startupProbe present | startup_probe_present=true | Explicit | Yes | Yes | container | low | probe payload never persisted | TestProbes::test_startup_probe_presence | PASS |
| AY | container | kubernetes_container_security_context | ports[].hostPort | host_port_count, dangerous_host_ports | Explicit | Yes | Yes | container | medium | none (port number only) | TestHostPorts, TestHostPortChanges::test_host_port_introduced | PASS |
| AZ | Deployment (2 containers) | kubernetes_deployment + 2x kubernetes_container_security_context | mixed containers | privileged_container_count=1, read_only_root_filesystem_coverage=partial | Aggregated (worst-case) | Yes | Yes | controller + container | high (workload), per-container varies | none | TestMixedMultiContainerPosture | PASS |
| BA | container | kubernetes_container_security_context | malformed/missing securityContext | all fields None/empty, no crash | Unknown | Yes | Yes | container | low | none | TestMalformedSecurityContext | PASS |
| BB | Namespace-list ok, workload API denied | kubernetes_deployment | 403 on Deployments list | collection_completeness_category=partial | n/a | Partial | n/a | cluster (partial_permission_indicator) | medium | none | TestFailSoftIsolation::test_403_on_one_family_does_not_raise_and_reports_partial | PASS |
| BC | mixed families | kubernetes_deployment / kubernetes_statefulset | Deployments 403, StatefulSets ok | dep partial, sts complete | n/a | Partial (isolated) | n/a | n/a | n/a | none | TestFailSoftIsolation::test_one_family_failure_does_not_affect_another | PASS |
| BD | Deployment (2 pages) | kubernetes_deployment | `_continue` token | 2 controller records | n/a | Yes | n/a | n/a | n/a | none | TestPaginationReuse::test_multiple_pages_are_collected | PASS |
| BE | Deployment (repeated token) | kubernetes_deployment | repeated `_continue` | stops without infinite loop | n/a | Partial | n/a | n/a | n/a | none | TestPaginationReuse::test_repeated_continuation_token_does_not_loop_forever | PASS |
| BF | Deployment | kubernetes_deployment | metadata.uid | record_id=`cluster/deployment/ns/uid` | n/a | Yes | n/a | n/a | n/a | none | TestDeterministicOrderingAndStableIds::test_stable_id_prefers_uid | PASS |
| BG | Deployment (name reused, new uid) | kubernetes_deployment | metadata.uid changes | different record_id → remove+add | n/a | Yes | n/a | controller (added/removed) | varies | none | TestDeterministicOrderingAndStableIds::test_name_reused_with_new_uid_is_a_different_record_id | PASS |
| BH | container | kubernetes_container_security_context | env[].value | (never read) | n/a | No (excluded) | n/a | n/a | n/a | env values excluded — verified | TestSensitiveDataExclusion::test_env_values_never_persisted | PASS |
| BI | container | kubernetes_container_security_context | command, args | (never read) | n/a | No (excluded) | n/a | n/a | n/a | command/args excluded — verified | TestSensitiveDataExclusion::test_command_and_args_never_persisted | PASS |
| BJ | Pod template metadata | kubernetes_deployment | annotations (arbitrary) | (never read except PSA/AppArmor keys) | n/a | No (excluded) | n/a | n/a | n/a | arbitrary annotations excluded — verified | TestSensitiveDataExclusion::test_arbitrary_annotations_never_persisted, TestAppArmor::test_no_other_annotation_is_ever_read | PASS |
| BK | container (modified) | kubernetes_container_security_context | real compute_diff() output | provider_metadata (namespace, workload kind/name, container name/category, service account, uid) | n/a | Yes | Yes | container | n/a | none | TestProviderMetadata::test_container_change_metadata_includes_workload_context | PASS |
| BL | Deployment (added) | kubernetes_deployment | new_value.security_posture_summary | added-already-dangerous branch | n/a | Yes | n/a | controller (added) | high | none | TestWorkloadAddedRemoved::test_workload_added_already_dangerous | PASS |
| BM | Deployment (removed) | kubernetes_deployment | prev_value.security_posture_summary | dangerous-removed branch | n/a | Yes | n/a | controller (removed) | medium | none | TestWorkloadAddedRemoved::test_dangerous_workload_removed | PASS |
| BN | Deployment (identical) | kubernetes_deployment | no resourceVersion field exists | zero Changes produced | n/a | n/a | n/a (untracked) | n/a | none | TestNoisyFieldsIgnored::test_resource_version_only_change_ignored | PASS |
| BO | Pod (status only) | kubernetes_pod | container restart_count change only | zero Changes produced | n/a | n/a | n/a (untracked) | n/a | none | TestNoisyFieldsIgnored::test_status_only_pod_change_ignored | PASS |

Additional cases beyond the required list (image registry categorization,
malformed top-level workload object isolation, container-record-ID
namespacing by category, secret/configmap volume reference exclusion,
image-pull-secret name exclusion, service-account-token projection source
exclusion, node-name/pod-IP non-persistence, risk-routing-never-falls-back
tests) are covered by additional tests in the same three files and are
summarized in the totals below rather than given their own matrix row.

## Totals

- **Matrix cases**: 67 (A through BO) plus supplementary coverage.
- **PASS**: 67 / 67 required cases.
- **FIXED**: 0 (no pre-existing defects found in this message's scope).
- **GAP**: 0 declared gaps within message-2 scope (all deferred items are
  explicitly out of scope for message 2, not gaps in it).
- **N/A**: 0.

## Tests and exact results

```
pytest tests/test_kubernetes_foundation.py tests/test_kubernetes_connector_contract.py \
       tests/test_kubernetes_workload_foundation.py tests/test_kubernetes_pod_security_normalization.py \
       tests/test_kubernetes_workload_diff.py -q
204 passed

pytest tests -q -k "kubernetes and workload"
46 passed, 17780 deselected

pytest tests -q -k "kubernetes and privileged"
5 passed, 17821 deselected

pytest tests -q -k "kubernetes and hostpath"
8 passed, 17818 deselected

pytest tests -q -k "kubernetes and capability"
23 passed, 17803 deselected

pytest tests -q -k "kubernetes and seccomp"
5 passed, 17821 deselected

pytest tests -q -k "kubernetes and diff"
25 passed, 17801 deselected

pytest tests -q -k "kubernetes"
258 passed, 17568 deselected

pytest tests --collect-only -q
17826 tests collected, 0 errors
```

No frontend files were touched this message, so `tsc --noEmit` was not run.

## Sensitive-data safeguards (message 2)

Production connector code makes **no** calls to Secret APIs, ConfigMap value
APIs, Pod logs, exec/attach/port-forward, or image registry APIs — confirmed
by the required safety greps against every touched file (all matches were
safe field names, presence-only checks, or test fixtures proving
exclusion, not real usage). Never persisted: environment-variable values,
command/args, probe payload contents (paths/headers), arbitrary
labels/annotations (only the 6 PSA namespace labels and one well-known
AppArmor annotation key per container are ever read), raw hostPath strings
(only a fixed category), image-pull-secret *names* (count only),
Secret/ConfigMap volume *names* (used only to categorize the mount, never
stored), and Service-Account-token volume *paths* (presence only).

## Major gaps deferred to Kubernetes message 3

- RBAC and identity: Roles, ClusterRoles, RoleBindings, ClusterRoleBindings,
  full ServiceAccount resources (including each SA's own default automount
  value, which is required to resolve "inherited" automount posture into a
  real effective value).
- Dangerous-permission detection (wildcard verbs/resources, `secrets` access,
  `escalate`/`bind`/`impersonate` verbs).

Also still deferred beyond message 3 (unchanged from the message-1 report):
networking (message 4), admission/config controls (message 5), the complete
Security Finding taxonomy (message 6), exhaustive Change classification
(message 7), scale/fail-soft hardening (message 8), and final certification
(message 9).

## Safe to push

Yes — all required tests pass, both safety greps are clean, hygiene checks
are clean, and only the required files are staged. Not pushed per
instruction. Kubernetes message 3 has not been started.
