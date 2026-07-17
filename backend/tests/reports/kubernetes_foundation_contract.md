# Kubernetes Provider — Foundation Contract (Message 1 of 9)

This report documents the architecture, safety contract, and test results for the
Kubernetes provider's **foundation stage only**: provider capability contract,
cluster identity, namespace scope, API discovery, pagination, fail-soft handling,
and the initial low-risk record set (`kubernetes_cluster`, `kubernetes_namespace`,
`kubernetes_api_capability`).

Workloads, RBAC, network exposure, admission/config controls, Security Findings,
change classification depth, and scale hardening are explicitly **deferred** to
Kubernetes messages 2–9 (see "Capability status" table below).

## Architecture summary

The Kubernetes connector follows ConfigTrace's established `BaseConnector`
contract (`fetch(credentials) -> list[dict]`, `validate_credentials(credentials)
-> bool`) and is registered through the same dispatch points used by every other
provider: `sync_task.py`, `sync_service.py`'s supported-providers list,
`integration_service.py`'s create-integration dispatch, `risk_service.py`'s
change classifier dispatch, and `diff_service.py`'s tracked-fields dispatch.

Reference providers used as direct templates:
- **Jira** (`_create_jira_integration`) — schema-level credential validation
  only at integration-create time; live API validation deferred to first sync.
  Mirrored exactly for `_create_kubernetes_integration`.
- **Azure / Google Cloud** — precedent for a cloud-style provider with a
  discovery/capability-inventory phase preceding resource collection.
- **Terraform Cloud** — precedent for `maturity="planned"` in the provider
  capability matrix and a "foundation only, no live monitoring surfaces yet"
  frontend posture.

## Auth model

**Supported:** kubeconfig YAML content (`credentials["kubeconfig"]`) + an
optional explicit `context` name. Static bearer-token and client-certificate/key
auth entries embedded in the kubeconfig are accepted (these are handled entirely
by the official `kubernetes` client library once past our own pre-check).

**Rejected:** any resolved user entry containing an `exec` or `auth-provider`
key. Rejection happens via `yaml.safe_load()` + `_resolve_context()` +
`assert_context_auth_is_supported()` **before** the kubeconfig is ever handed to
`kubernetes.config.load_kube_config_from_dict()` — this is a structural
guarantee, not a runtime check, that ConfigTrace never has the opportunity to
invoke an arbitrary `ExecProvider` binary supplied via user-uploaded
kubeconfig content. Covered by
`TestCredentialSafety::test_exec_plugin_is_rejected` and
`test_auth_provider_plugin_is_rejected`.

**Deferred / N/A for message 1:** cloud-provider-native IAM auth plugins (EKS
IAM authenticator, GKE gcloud auth-plugin, AKS Azure AD) are a subset of the
rejected `exec`/`auth-provider` case today; a deliberate, explicit mechanism for
supporting them may be added in a later message but is out of scope now.

Credential content (kubeconfig, tokens, client keys/certs) is never persisted
outside the encrypted `credentials` column, never copied into
`resource_metadata`, and never appears in error messages
(`TestCredentialSafety::test_error_messages_never_leak_credential_content`).

## Client strategy

Official `kubernetes` Python client, pinned to `kubernetes==30.1.0`
(`backend/requirements.txt`). Config is loaded per-request via
`config.load_kube_config_from_dict(..., persist_config=False)` — no config is
ever written to disk. `ApiClient` instances are created fresh per `fetch()`/
`validate_credentials()` call and explicitly cleaned up via
`api_client.rest_client.pool_manager.clear()` in a `finally` block. All calls
set an explicit 30s timeout (`_REQUEST_TIMEOUT_SECONDS`). The connector is
synchronous, matching every other ConfigTrace connector.

## Cluster identity

`compute_cluster_id(*, api_server_host, kube_system_uid)`:
- If the `kube-system` namespace UID is readable, identity is `f"uid:{uid}"`.
- Otherwise, identity falls back to `f"host:{sha256(normalized_host)[:32]}"`,
  where `normalize_api_server_host()` strips scheme/port/credentials/query
  strings before hashing.
- Context name is **display-only** (`display_cluster_name` /
  `context_name` on the record) and is never part of identity — confirmed via
  `TestClusterIdentity::test_context_name_is_display_only_not_identity`.

## Namespace scope

Default scope is **all namespaces** in the cluster. An optional
`namespace_allowlist` (schema field) restricts collection to the given names.
`kube-system`/`kube-public`/`kube-node-lease` are **not** auto-excluded — the
task explicitly calls out that a compromised/misconfigured system namespace is
itself a signal worth surfacing. Namespace listing uses `paginate_list()`
against `CoreV1Api.list_namespace`.

## Record types

**Implemented in message 1** (`KUBERNETES_FOUNDATION_RECORD_TYPES`):
- `kubernetes_cluster` — identity, version (`kubernetes_version`,
  `kubernetes_major_minor`), platform, TLS-verification flag, partial-permission
  indicator, collection-completeness category.
- `kubernetes_namespace` — name, UID, phase, terminating flag, and only the
  6 well-known Pod Security Admission label keys
  (`pod-security.kubernetes.io/{enforce,enforce-version,audit,audit-version,
  warn,warn-version}`). No other labels or any annotations are read or stored.
- `kubernetes_api_capability` — one record per discovered (or explicitly
  unavailable) API resource family, used for capability inventory only; no
  drift tracking on this type yet.

**Reserved now, implemented in later messages** (`KUBERNETES_PLANNED_RECORD_TYPES`,
26 constants in `kubernetes_schema.py`) — workload types (message 2), RBAC
types (message 3), network types (message 4), admission/config types
(message 5), and further posture types for messages 6–8. Reserving the names
now avoids a later rename/migration.

## Sensitive-data policy

Message 1 does **not** call any Secret or ConfigMap API, not even for metadata.
This is a prominent, explicit contract stated in the `kubernetes.py` module
docstring and enforced by source-inspection tests
(`TestSafeNormalization::test_no_forbidden_kubernetes_api_calls_in_source`,
`TestFailSoft`/`TestDiscovery` fixtures never reference Secret/ConfigMap read
methods). Never collected, this message or ever without a future explicit
redesign: Secret values, ConfigMap values, service-account tokens, kubeconfig
contents, bearer tokens, client private keys, client certs beyond safe
metadata/fingerprint, registry pull secrets, TLS private keys, env-var values,
mounted secret contents, Pod logs, exec output, application logs, risky command
args, raw admission-review payloads, raw audit events, raw annotation maps,
arbitrary label maps, image pull credentials, cloud-provider credentials, node
bootstrap credentials, Secrets API bodies beyond metadata, admission webhook
cert bundles, projected SA token contents.

**Secret-metadata RBAC limitation (documented prominently):** Kubernetes RBAC
cannot grant "read Secret metadata but not values" — `get`/`list`/`watch` on
`secrets` always exposes `.data`/`.stringData`. Because of this, the documented
minimum read-only permission contract **excludes Secret API access entirely**
from the default ClusterRole, for all messages, not just message 1.

## Fail-soft behavior

`call_k8s()` wraps every API call and classifies outcomes into: success,
`auth_failed` (401), `permission_denied` (403), `not_found` (404),
`continuation_expired` (410), `throttled` (429), `server_error` (5xx),
`connection_error`, `tls_error`, `malformed_response`, and `api_unavailable`
(for discovery). A foundational failure (auth) fails `validate_credentials`
outright. A permission-denied on an optional resource (e.g. one discovery
group) does not fail the whole `fetch()` — it emits an "unavailable" capability
record and sets `partial_permission=True` on the cluster record, never a
synthetic `_access_denied` record and never fabricated posture. One resource
family's failure never suppresses unrelated records already collected.
Covered by `TestFailSoft` (12 tests).

## Pagination

`paginate_list()` supports `limit`/`_continue`, restarts once (not looped) on
HTTP 410 continuation-token expiry, tracks `seen_tokens` to stop on a repeated
token, caps at `_MAX_PAGES=50` and marks `truncated_by_page_cap=True` rather
than looping forever, and returns a `PageDiagnostics` object so partial-failure
status survives into the final record set instead of silently truncating.
Covered by `TestPagination` (11 tests: single/multi/empty page, repeated
token, 410-restart-once, 410-twice-stops, permission-failure-keeps-partial-items,
malformed-metadata-stops-safely, page-cap, configurable page size,
no-duplicate-items).

## API discovery

`_discover_capabilities()` probes 8 API groups (core, apps, RBAC, networking,
policy, batch, admissionregistration, and Gateway API via a raw
`ApiClient.call_api()` probe since Gateway API has no typed client class). Only
safe capability records (resource name, namespaced flag, verbs, group/version)
are ever persisted — the full discovery document is never stored. Each group is
independently fail-soft: an unavailable optional group is recorded as
"unsupported", not "empty". The connector never assumes `networking.k8s.io/v1`,
Gateway API CRDs, `policy/v1`, PSP, admissionregistration APIs, or metrics APIs
are present — every one of these is probed, not assumed.

## Supported-version policy

Officially supported versions are whatever the pinned `kubernetes==30.1.0`
client supports; older/unreachable API servers fail safely via
`validate_credentials`. `normalize_kubernetes_version()` strips build-metadata
(`+...`) and pre-release (`-...`) suffixes from `GitVersion` before storing
`kubernetes_version`/`kubernetes_major_minor`. No hard-coded version gating —
discovery drives capability, not a version table.

## Distribution neutrality

No EKS/GKE/AKS-specific API calls or field assumptions in message 1. Only
`platform` categorization of the API server host
(`categorize_api_server_host`: private IP / public IP / localhost / DNS
hostname) is recorded — genuine distribution detection (e.g. cloud-provider
annotations) is deferred.

## Minimum read-only permission contract

Message 1 requires only: `get /version`, `get`/`list` on `namespaces`
(cluster-scoped), and API discovery endpoints (`get` on each group's discovery
document). A future read-only `ClusterRole` covering later messages' resource
families is documented for message 2+ but **not implemented** with write
permissions now, and **explicitly excludes all Secret API access** per the
RBAC limitation above.

## Frontend availability

`frontend/src/lib/providers.ts` adds a `kubernetes` entry to `PROVIDERS` (for
internal/back-office reference and the capability matrix) but **deliberately
excludes** it from `PROVIDER_IDS` and `CONNECTABLE_PROVIDER_IDS`, so Kubernetes
is not user-connectable and not shown as "Live" yet. The entry's `trustNote`
states plainly that this is an architecture-foundation stage and workload/RBAC/
network/admission monitoring are planned, not live. The provider capability
matrix marks `maturity="planned"` with all `SecurityCapabilities` and
`drift_diff`/`drift_risk_classification`/`drift_review_workflow`/
`drift_remediation_preview` set to `False`; only `drift_snapshots=True`.

## GAPs deferred to messages 2–9

- Message 2: Workloads (Deployments, StatefulSets, DaemonSets, Pods) and Pod
  security posture (privileged containers, hostPath mounts, capabilities).
- Message 3: RBAC (Roles, ClusterRoles, RoleBindings, ClusterRoleBindings,
  ServiceAccounts, dangerous-permission detection).
- Message 4: Network exposure (Services, Ingresses, NetworkPolicies, Gateway
  API routes).
- Message 5: Admission control and cluster-wide config (admission webhooks,
  PodSecurityPolicy/PSA cluster defaults, API server security posture).
- Message 6: Kubernetes-specific Security Findings.
- Message 7: Deeper change classification / risk rules for workload+RBAC+
  network record types.
- Message 8: Scale and fail-soft hardening (very large clusters, sharded
  collection, rate-limit backoff tuning).
- Message 9: Final certification (`kubernetes_provider_depth_qa`-style test
  suite) and frontend promotion to "Live"/connectable.

## Capability status

| Capability area | Message | Status |
|---|---|---|
| Cluster foundation | 1 | Implemented |
| Namespace posture | 1 | Foundation only |
| Workload security | 2 | Deferred |
| RBAC | 3 | Deferred |
| Network exposure | 4 | Deferred |
| Admission / config controls | 5 | Deferred |
| Security Findings | 6 | Deferred |
| Change classification | 7 | Deferred |
| Scale / fail-soft hardening | 8 | Deferred |
| Final certification | 9 | Deferred |

## Tests

- `backend/tests/test_kubernetes_foundation.py` — 71 tests, all passing.
  Covers credential safety, cluster identity, namespace normalization,
  pagination, fail-soft classification, version normalization, API discovery,
  and safe-normalization source scans.
- `backend/tests/test_kubernetes_connector_contract.py` — 30 tests, all
  passing. Covers `validate_credentials`, provider dispatch wiring (sync task,
  sync service, integration service — including a real-DB test confirming no
  kubeconfig/token leakage into `Resource.resource_metadata` or the API
  response), credential schema validation, diff/risk dispatch (confirms
  Kubernetes changes are routed to `classify_kubernetes_change`, not the
  Cloudflare fallback), capability matrix entries, and frontend catalog state.

Exact results:
```
pytest tests/test_kubernetes_foundation.py tests/test_kubernetes_connector_contract.py -q
101 passed

pytest tests -q -k "kubernetes"
155 passed, 17568 deselected

pytest tests -q -k "expansion_framework or capability_matrix or kubernetes"
629 passed, 4 skipped, 17090 deselected

pytest tests --collect-only -q
17723 tests collected
```

A pre-existing, unrelated failure (`test_milestone82_pre_provider_integration_card_parity.py`,
3 tests) was identified during a broader spot-check and confirmed via
`git stash`/`git stash pop` to exist at baseline before any Kubernetes work —
it asserts a stale hardcoded 13-provider connectable set that never accounted
for pagerduty/linear/jira/gitlab/terraform_cloud's earlier additions. Left
untouched as out-of-scope for this message.
