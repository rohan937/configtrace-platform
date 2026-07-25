# Kubernetes Provider Certification (Message 9 of 9 — Public Launch)

This is the final certification report for the Kubernetes provider expansion
arc (messages 1-9). It certifies Kubernetes as a publicly visible,
connectable, production-certified ConfigTrace provider.

## 1. Provider identity

| Field | Value |
|---|---|
| Provider ID | `kubernetes` |
| Display name | `Kubernetes` |
| Category | `cloud` |
| Status | Live — in `PROVIDER_IDS` and `CONNECTABLE_PROVIDER_IDS` (frontend), in `PROVIDER_CAPABILITIES` (backend, not the partial list) |
| Capability-matrix maturity | `partial` (drift + Security Findings; no activity-ingestion stack — see §6) |

## 2. Authentication

- **Credential type**: kubeconfig YAML content + optional context name, cluster display name, and namespace allowlist. No separate bearer-token field, no cluster-admin requirement, no cloud IAM settings.
- **Validation**: `KubernetesConnector.validate_credentials()` parses the kubeconfig, resolves the context (explicit or current-context), and confirms the API server answers `/version`. Called synchronously at integration-creation time (message 9 change — previously deferred to first sync).
- **Rejected auth mechanisms**: `exec` and `auth-provider` kubeconfig entries are rejected at connection time with a `ConnectorError` — ConfigTrace never executes an external auth plugin. Pinned by `TestExecAuthRejection`/`TestAuthProviderRejection` in `test_kubernetes_foundation.py`.
- **Full/Partial/Invalid semantics**:
  - **Invalid**: malformed kubeconfig, nonexistent explicit context, auth failure (401), unreachable cluster, TLS failure — all raise before an integration row is written.
  - **Full/Partial**: determined per-family at fetch time via `family_completeness` on the `kubernetes_cluster` record, surfaced through `build_permission_diagnostics()`. Gateway API being uninstalled reports `"unsupported"`, never `"invalid"`. A single denied family does not block sync — see `_kubernetes_removal_suppressed()` (message 8) for false-removal protection.

## 3. Coverage

- **Record types**: 36 (cluster, namespace, workload/pod security posture, RBAC, network, admission/policy families — established across messages 1-5).
- **Security Findings**: 59 rules (`security_rules/kubernetes.py`) — Critical 6 / High 33 / Medium 19 / Low 1, fully registered in the evaluator/registry/confidence/pack/coverage layers (message 6).
- **Change classification**: exhaustive QA pass complete (message 7) — 20 numeric "unknown-as-zero" bugs and 1 Finding-severity-parity gap fixed.
- **Monitored API families**: workload/Pod security, RBAC/identity, Services/Ingress/Gateway API/NetworkPolicy, admission webhooks, Pod Security Admission, ResourceQuota/LimitRange.

## 4. Reliability

- Partial-permission and partial-sync false-removal protection (`family_completeness`, `configured_namespace_allowlist`, `_kubernetes_removal_suppressed()` — message 8).
- Bounded 429 retry with backoff+jitter (injectable `_sleep_fn`).
- Differentiated connect(10s)/read(30s) timeouts, `CATEGORY_TIMEOUT` classification.
- Multi-cluster identity safety: `compute_cluster_id()` keyed on kube-system UID (falls back to normalized API server host); context rename and credential rotation for the same cluster preserve identity; a genuinely recreated cluster (new UID) is never cross-diffed against the old cluster's records — pinned in `test_kubernetes_multi_cluster.py`.
- Scale: N+1-query-avoidance and large-page-count behavior pinned in `test_kubernetes_permission_diagnostics.py::TestNPlusOneGuard` / `TestScale`.

## 5. Sensitive-data boundary

- Secret and ConfigMap contents: **never accessed** — zero `list`/`get` calls on either resource type anywhere in `app/connectors/kubernetes.py` (grepped; see §8).
- Pod exec/attach/logs/port-forward, ServiceAccount token creation: **never called**.
- Credentials: encrypted at rest (AES-256-GCM via `encrypt_credentials`), never returned in any API response (`IntegrationResponse` has no kubeconfig/credential field), never logged, never copied into `resource_metadata` (only user-supplied `cluster_name`/`context` display labels are stored there).
- `run_live_kubernetes_validation()`'s `context_name` → credentials-dict key mismatch (it built `credentials["context_name"]` while the connector reads `credentials.get("context")`, silently dropping the override) was found and fixed during this message's router audit — see `test_kubernetes_provider_depth_qa.py::TestCredentialRoundTrip::test_live_validation_harness_uses_matching_context_key`.

## 6. Frontend

- **Card**: `providers.ts` `kubernetes` entry — description, `monitoredSurfaces`, and `trustNote` copy audited to remove all "(planned)"/"foundation stage" language and unsupported-capability claims (no Secret/ConfigMap/runtime-detection/vulnerability-scanning/audit-log-monitoring/malware claims — pinned by `test_kubernetes_provider_depth_qa.py::TestFrontendLaunchState`).
- **Form**: `KubernetesIntegrationForm.tsx` — kubeconfig textarea (never a single-line password field, since kubeconfig is multiline), optional context field with "Leave blank to use the kubeconfig's current context" copy, inline minimum-RBAC guidance, "Kubeconfig configured" success message that never re-displays the kubeconfig.
- **Setup guide**: `ProviderSetupGuide` branch in `integrations/page.tsx` — dedicated-ServiceAccount guidance, exec/auth-provider rejection note, kubeconfig-paste step.
- **Detail page**: `ProviderOverview` Kubernetes branch — cluster name, context, visible-namespace count, last snapshot, monitored-category list; never renders kubeconfig/token/certificate/raw API errors.
- **Findings/Changes**: provider filter, detail views, severity, evidence, remediation copy all resolve through the existing generic (non-provider-specific) UI — no Kubernetes-specific gaps found; verified via the existing message-6/7 test suites plus a description/copy re-audit this message.

## 7. Known limitations (intentional, documented — not gaps)

- Kubernetes audit-event ingestion, activity signals, risk × activity correlations, demo seed/clear, case reporting, evidence timeline/graph: **not built** for this provider — Kubernetes' security stack is Security Findings only (drift + static rules), not the full dual-stack GitHub/AWS-style architecture. This is why capability-matrix maturity stays `"partial"` even though the provider is fully launched.
- Secret/ConfigMap content scanning: **permanently unsupported** (architectural decision from message 1, reaffirmed every message since).
- Runtime/syscall monitoring, vulnerability/malware scanning, Kubernetes audit-log monitoring: **not implemented, not planned** — out of scope for a configuration-drift/security-posture product.
- Gateway API resources (`gateways`/`httproutes`): supported only when the CRDs are installed; reported `"unsupported"` (not `"invalid"`) otherwise.
- ReferenceGrant, API-server flags, node-level configuration: not collected by any current family.
- Frontend reconnect UI (`ReconnectIntegrationModal`) does not yet support Kubernetes' multi-field (kubeconfig + context) credential shape — this is a **pre-existing gap shared by most non-original-8 providers** (AWS, Firebase, Supabase, Shopify, GitLab, Jira, etc. have the same limitation), not something introduced or left incomplete by this message. The backend `reconnect_credentials_kubernetes()` + router branch are fully implemented and tested at the API layer. Flagged as a separate follow-up task, not a launch blocker.
- Namespace-allowlist frontend UX: the backend credential model supports `namespace_allowlist` end-to-end (schema, router, connector), but no dedicated frontend UI was added for it in this message (the field can be omitted; all visible namespaces are collected by default). Documented as a post-launch UX enhancement rather than forced in under this message's scope, per the instruction not to invent a large new UI subsystem.

## 8. Certification status

**PASS.**

All launch gates pass:
- Credential path fixed and wired end-to-end (`_build_credentials()` kubernetes branch — previously silently dropped kubeconfig on the real `POST /integrations` path; this was the most critical bug found and fixed this message).
- Reconnect path added (`reconnect_credentials_kubernetes()`, router branch, schema fields) with same-cluster-identity preservation and cross-cluster-mismatch rejection.
- Synchronous create-time validation added (Invalid-state detection matches every other provider).
- Capability matrix moved to the public/complete list (`PROVIDER_CAPABILITIES`, 9 providers total), notes rewritten to reflect launched state.
- Frontend `providers.ts` moved to `PROVIDER_IDS` + `CONNECTABLE_PROVIDER_IDS`, card copy rewritten.
- `KubernetesIntegrationForm.tsx` built and wired into the integration creation flow and setup guide.
- Integration detail page given a real Kubernetes overview panel.
- RBAC-manifest parity re-verified against every connector call.
- Sensitive-data boundary re-verified (3 safety greps clean).
- No database migration required (`Integration.provider` is a plain `Text` column, no ENUM/CheckConstraint).
- No kubectl/helm/cloud-CLI execution dependency anywhere (grepped clean).
- 1065 Kubernetes-related tests pass across the full repo (`-k kubernetes`), 1 skipped (a documented live-cluster-only test gated behind an opt-in env var), up from the message-8 baseline.
- Frontend `tsc --noEmit` passes with zero errors; `next build` compiles successfully and passes type-checking (the only failure is a pre-existing sandbox limitation — no real Clerk publishable key for static-page prerendering — unrelated to and unaffected by this message's changes).

**Kubernetes provider expansion is complete.**
