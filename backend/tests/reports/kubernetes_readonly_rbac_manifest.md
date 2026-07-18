# Kubernetes Minimum Read-Only RBAC Manifest (Message 8 of 9)

This is the minimum recommended `ClusterRole` for ConfigTrace's Kubernetes
integration, generated from the exact API calls `app/connectors/kubernetes.py`
makes (verified directly against the connector source — every method call
below has a corresponding line in the connector). It is **documentation
only**: ConfigTrace never applies this manifest automatically to a cluster.
An operator must review and `kubectl apply` it themselves.

## Design rules

- **Only `get`/`list` verbs.** ConfigTrace's connector never uses `watch` —
  every collection is a bounded, paginated `list` call (see `paginate_list()`
  / `_paginate_custom_objects()`); there is no long-lived watch connection
  anywhere in the codebase, so `watch` is deliberately **not** included.
- **No write verbs, ever.** No `create`/`update`/`patch`/`delete`.
- **No `secrets` or `configmaps`.** Both are permanently, deliberately
  unsupported (see `kubernetes_schema.py`'s module docstring and message 5's
  safety review) — this manifest grants **zero** access to either resource
  type, on purpose, not as an oversight.
- **No `pods/exec`, `pods/attach`, `pods/log`, `pods/portforward`,
  `serviceaccounts/token`.** ConfigTrace never executes into a Pod, attaches
  to a container console, reads Pod logs, port-forwards, or mints
  ServiceAccount tokens — the connector reads Pod *specs*, not Pod
  *contents* or *actions*.
- **No `impersonate`/`bind`/`escalate`.** ConfigTrace's own credential is
  never granted (nor does it need) any RBAC-escalation-adjacent permission.

## Coverage mapping (verified against connector source)

| API group | Resources | Verbs | Connector call(s) |
|---|---|---|---|
| `""` (core) | `namespaces` | get, list | `core_v1.read_namespace`, `core_v1.list_namespace` |
| `""` (core) | `pods` | list | `core_v1.list_pod_for_all_namespaces` |
| `""` (core) | `services` | list | `core_v1.list_service_for_all_namespaces` |
| `""` (core) | `serviceaccounts` | list | `core_v1.list_service_account_for_all_namespaces` |
| `""` (core) | `resourcequotas` | list | `core_v1.list_resource_quota_for_all_namespaces` |
| `""` (core) | `limitranges` | list | `core_v1.list_limit_range_for_all_namespaces` |
| `apps` | `deployments` | list | `apps_v1.list_deployment_for_all_namespaces` |
| `apps` | `statefulsets` | list | `apps_v1.list_stateful_set_for_all_namespaces` |
| `apps` | `daemonsets` | list | `apps_v1.list_daemon_set_for_all_namespaces` |
| `batch` | `jobs` | list | `batch_v1.list_job_for_all_namespaces` |
| `batch` | `cronjobs` | list | `batch_v1.list_cron_job_for_all_namespaces` |
| `rbac.authorization.k8s.io` | `roles` | list | `rbac_v1.list_role_for_all_namespaces` |
| `rbac.authorization.k8s.io` | `clusterroles` | list | `rbac_v1.list_cluster_role` |
| `rbac.authorization.k8s.io` | `rolebindings` | list | `rbac_v1.list_role_binding_for_all_namespaces` |
| `rbac.authorization.k8s.io` | `clusterrolebindings` | list | `rbac_v1.list_cluster_role_binding` |
| `networking.k8s.io` | `ingresses` | list | `networking_v1.list_ingress_for_all_namespaces` |
| `networking.k8s.io` | `networkpolicies` | list | `networking_v1.list_network_policy_for_all_namespaces` |
| `admissionregistration.k8s.io` | `validatingwebhookconfigurations` | list | `admissionregistration_v1.list_validating_webhook_configuration` |
| `admissionregistration.k8s.io` | `mutatingwebhookconfigurations` | list | `admissionregistration_v1.list_mutating_webhook_configuration` |
| `gateway.networking.k8s.io` (CRD, if installed) | `gateways` | get, list | `custom_objects_api.list_cluster_custom_object(group="gateway.networking.k8s.io", version="v1", plural="gateways")` |
| `gateway.networking.k8s.io` (CRD, if installed) | `httproutes` | get, list | same, `plural="httproutes"` |
| `` (discovery) | API group/version discovery | get | `_discover_capabilities()` — a curated, bounded set of group/version probes, never the full discovery document |
| n/a | Kubernetes server version | get | `VersionApi().get_code()` (unauthenticated-adjacent, but included for completeness) |

The Gateway API rules use `resources: ["gateways", "httproutes"]` under the
`gateway.networking.k8s.io` API group. If the CRDs are not installed on a
given cluster, Kubernetes RBAC simply has no effect on a nonexistent
resource type — granting the rule is harmless on clusters without Gateway
API installed, and `_family_completeness_status()` correctly reports
`"unsupported"` (not `"partial"`) in that case.

## Manifest

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: configtrace-readonly
  labels:
    app.kubernetes.io/managed-by: configtrace-operator-reviewed
rules:
  # Core workloads/resources
  - apiGroups: [""]
    resources:
      - namespaces
      - pods
      - services
      - serviceaccounts
      - resourcequotas
      - limitranges
    verbs: ["get", "list"]

  # apps
  - apiGroups: ["apps"]
    resources:
      - deployments
      - statefulsets
      - daemonsets
    verbs: ["get", "list"]

  # batch
  - apiGroups: ["batch"]
    resources:
      - jobs
      - cronjobs
    verbs: ["get", "list"]

  # RBAC
  - apiGroups: ["rbac.authorization.k8s.io"]
    resources:
      - roles
      - clusterroles
      - rolebindings
      - clusterrolebindings
    verbs: ["get", "list"]

  # Networking
  - apiGroups: ["networking.k8s.io"]
    resources:
      - ingresses
      - networkpolicies
    verbs: ["get", "list"]

  # Admission control
  - apiGroups: ["admissionregistration.k8s.io"]
    resources:
      - validatingwebhookconfigurations
      - mutatingwebhookconfigurations
    verbs: ["get", "list"]

  # Gateway API (CRDs) — harmless no-op if not installed on this cluster
  - apiGroups: ["gateway.networking.k8s.io"]
    resources:
      - gateways
      - httproutes
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: configtrace-readonly-binding
subjects:
  - kind: ServiceAccount
    name: configtrace-reader
    namespace: configtrace-system   # adjust to wherever the credential is issued from
roleRef:
  kind: ClusterRole
  name: configtrace-readonly
  apiGroup: rbac.authorization.k8s.io
```

## Explicitly excluded (by design, not oversight)

- `secrets`, `configmaps` — any verb, any API group.
- `pods/exec`, `pods/attach`, `pods/log`, `pods/portforward`.
- `serviceaccounts/token` (token creation).
- Any `create`/`update`/`patch`/`delete`/`deletecollection` verb, anywhere.
- `impersonate`, `bind`, `escalate` special verbs on any resource.
- `watch` on any resource (the connector never opens a watch connection).
- `customresourcedefinitions` themselves (only the Gateway API CRD's own
  *instances* — `gateways`/`httproutes` — are read, never CRD definitions).
- `nodes`, `nodes/proxy`, `persistentvolumes`, `events`, `endpointslices` —
  collected by no current family; not included until a future message adds
  them.

If a cluster operator grants only a subset of the above (e.g. omits RBAC
read access), the connector degrades gracefully per this message's
false-removal-prevention work — the corresponding family is marked
`"partial"`/`"denied"` and its previously-known records are never reported
as deleted merely because the credential can no longer read them.
