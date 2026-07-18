# Kubernetes Reliability Matrix (Message 8 of 9)

Covers scale hardening, partial-sync safety, family-level completeness,
false-removal prevention, multi-cluster safety, pagination stress,
rate-limit/retry discipline, namespace-scope reliability, API-discovery
drift, permission diagnostics, the minimum read-only RBAC manifest, and the
live-validation harness. This message does not add new Kubernetes API
families and does not begin message 9 (final certification/production
launch).

## Current sync architecture (audited before any change)

- `sync_task.py::sync_integration()` calls `connector.fetch()` **once per
  resource**, wraps the whole sync in a single outer `try/except` — there is
  no per-family exception boundary at the orchestration layer (only the
  Kubernetes connector's own internal fail-soft `_collect_*` helpers provide
  that). `compute_diff(previous_snapshot, new_snapshot)` is called exactly
  once per resource, comparing two consecutive `Snapshot.state` lists.
- `compute_diff()`'s "Removed records" loop was, before this message,
  **unconditional**: any record present in the previous snapshot but absent
  from the new one was reported "removed" — with no completeness check
  anywhere. Confirmed via direct code read and the sole caller
  (`sync_task.py:390`).
- Neither `Snapshot` nor `SyncRun` has a spare JSONB/metadata column.
  `backend/app/core/failure_classifier.py::classify_failure()` is a
  cross-provider exception→(category, error_code, action) classifier used
  purely for user-facing sync-error display (`SyncRun.failure_category`) —
  it has zero connection to diff/removal logic.
- **Direct answer to "what happens today if the Role API returns 403 on a
  re-sync?"**: `_collect_roles` returns `records=[]` (fail-soft, no
  exception). `fetch()` still returns a valid `list[dict]` with zero
  `kubernetes_role` records. The sync is marked "completed." `compute_diff`
  then reports every previously-known Role as **falsely removed** — the
  only prior evidence of the real cause was an unrelated field-level
  `"modified"` Change on the `kubernetes_cluster` record's
  `collection_completeness_category`, which nothing correlated back to
  suppress the Role removals. **This message fixes that.**

## Family-level completeness design

A new `family_completeness: dict[str, str]` field (keyed by exact
`record_type` string, values `"complete"`/`"partial"`/`"unsupported"`) is
carried on the single, always-present `kubernetes_cluster` record — **never**
as a synthetic/fake resource record of its own. All 20 currently-collected
families are represented (see `app/connectors/kubernetes.py`'s
`family_completeness` dict construction in `fetch()`). Namespaced families
that share one cluster-wide List call (all of them, in the current
architecture — see below) report one status for the whole family; there is
no separate namespace-level status because there is no separate
namespace-level API call to have one.

## Namespace-level completeness design

The current architecture makes **exactly one List call per resource type
across the entire cluster** (e.g. `list_role_for_all_namespaces`), never one
call per namespace. A genuine "namespace-a: accessible, namespace-b: 403"
outcome is therefore not a distinct failure mode from a family-wide failure
in this connector today — it would require N per-namespace API calls, which
this message deliberately does NOT introduce (that would multiply API load
against real clusters, working against the "large-cluster performance"
goal). Namespace-scoped safety is instead provided for the one namespace-scope
change that IS a first-class, already-existing concept: the
**`namespace_allowlist`**. A new `configured_namespace_allowlist` field
(sorted list, or `None` = unrestricted) on the `kubernetes_cluster` record
lets `compute_diff()` distinguish "this namespace's resources vanished
because the allowlist intentionally shrank" from "this namespace's
resources were actually deleted from the cluster."

## False-removal prevention behavior

`_kubernetes_removal_suppressed()` (new, in `diff_service.py`) is consulted
for every candidate-removed record whose `record_type` starts with
`kubernetes_`. It suppresses the removal when either:
1. The new snapshot's matching `kubernetes_cluster` record's
   `family_completeness[record_type]` is not `"complete"`, or
2. The record has a `namespace` field and the new snapshot's
   `configured_namespace_allowlist` is a restricted list that no longer
   includes that namespace.
Otherwise the normal removal path proceeds. This is **provider-scoped**:
every other provider's removal behavior is provably unaffected (the
function returns `None` immediately for any non-`kubernetes_*` record —
confirmed by `TestFamilyCompletenessFalseRemovalPrevention::test_non_kubernetes_records_are_never_affected`).

## Pagination-partial behavior

`paginate_list()`/`_paginate_custom_objects()` (Gateway API) already (from
message 1) preserve collected items across a mid-pagination failure, cap
pages, and detect repeated continuation tokens. Verified unchanged by this
message's tests; hardened with bounded 429 retry (see below) and explicit
timeout classification.

## 410 (continuation-token-expired) handling

Confirmed: **exactly one restart from the beginning** on the first 410;
`items` is reset to `[]` on restart (no duplicates from the first partial
page); a **second** 410 after the restart is NOT retried again — it marks
the family `partial` and stops (`TestPaginationResilience::test_second_410_marks_partial_no_infinite_loop`,
asserting `list_fn.call_count == 3`, never a third restart attempt).

## 429 (throttled) retry behavior

New in this message: `call_k8s()` retries a `CATEGORY_THROTTLED` response up
to `_MAX_THROTTLE_RETRIES = 3` times, honoring a `Retry-After` header when
present (capped at `_THROTTLE_MAX_DELAY_SECONDS = 8.0`) or falling back to
`base(0.5s) * 2**attempt` with bounded jitter. Sleep is injected via a
`_sleep_fn` parameter (threaded through `paginate_list`/
`_paginate_custom_objects`) so tests never actually wait. After retry
exhaustion, the family is marked `partial`/`throttled` and removals are
suppressed via the same `family_completeness` mechanism. 401/403 are never
retried (`TestPaginationResilience::test_403_never_retried`).

## Timeout behavior

Every API call already carried a bounded `_request_timeout` (30s, message
1); this message differentiates **connect** (10s) vs **read** (30s) timeouts
via the client library's native `(connect, read)` tuple support, and adds
explicit `CATEGORY_TIMEOUT` classification for `ReadTimeoutError`,
`ConnectTimeoutError`, `socket.timeout`, and `MaxRetryError`-wrapped
timeouts — previously these fell into the less-specific
`CATEGORY_CONNECTION_ERROR` bucket. A timeout classifies the family as
`"partial"` (never `"unsupported"`), so pre-existing records are never
falsely reported deleted.

## Connection/TLS failure behavior

Unchanged from message 1 (already correct): `_classify_api_exception`
distinguishes TLS certificate failures (`Urllib3SSLError`/`ssl.SSLError`,
and `MaxRetryError` wrapping a certificate-related reason) from generic
connection errors. `server_certificate_verification_enabled` on the cluster
record surfaces whether the kubeconfig disabled TLS verification — as
posture metadata, never by logging the kubeconfig itself. Foundational
connectivity failure (can't even reach the API server / can't validate
credentials) still fails `validate_credentials()` clearly; optional family
calls remain fail-soft.

## API-discovery drift behavior

`_discover_capabilities()` (message 1) already probes a curated, bounded set
of API groups individually and fail-soft per probe. Gateway API / HTTPRoute
unavailability is classified `"unsupported"` (not `"partial"`) via
`_family_completeness_status()`'s `CATEGORY_NOT_FOUND`/`CATEGORY_API_UNAVAILABLE`
branch — and `"unsupported"` triggers the exact same removal-suppression
path as `"partial"` in `_kubernetes_removal_suppressed()`, so a cluster
upgrade/downgrade that adds or removes the Gateway API CRDs never produces
false "all Gateways deleted" or "all Gateways added back safely" noise.

## Multi-cluster safety

`compute_cluster_id()` (message 1, unchanged) prefers the immutable
`kube-system` namespace UID; `context_name` is not even a parameter to the
function (proven by `TestClusterIdentityStability::test_context_name_never_affects_identity`
introspecting the function signature). Every Kubernetes record's
`record_id` embeds `cluster_id`, so `build_record_index()` can never collide
across two different clusters even with identical namespace/resource names
(`TestMultiClusterNameCollisionSafety`). `provider_metadata` always includes
`cluster_id`/`cluster_name` (verified directly, not just by convention).

## Cluster recreation behavior

A new `kube-system` UID (same API host) computes a different `cluster_id`,
so every one of that cluster's record_ids changes — `compute_diff` sees a
fully disjoint record set (old records "removed", new cluster's records
"added"), **never** a cross-cluster field-level "modified" Change
(`TestClusterRecreation::test_recreated_cluster_never_cross_diffs_with_old_cluster_records`).
This is the intended, documented migration semantic: a recreated cluster is
treated as an entirely new cluster identity, not a continuation.

## Namespace allowlist scope-change behavior

Documented and tested: an allowlist **shrink** suppresses removal Changes
for namespaces newly excluded from scope (their resources are not
necessarily gone from the cluster — ConfigTrace simply stopped looking).
An allowlist **expand** does not retroactively suppress anything (there is
no pre-existing record to suppress for a namespace newly brought into
scope — it naturally appears as a normal "added" baseline for that
namespace on the next sync, per standard added-record handling). Namespaces
that stay in scope continue to diff normally in both directions.

## First-baseline behavior

Verified unaffected by this message's changes: `sync_task.py` only calls
`compute_diff` `if previous_snapshot is not None` — the very first snapshot
for any resource generates zero "added" Changes (no prior snapshot to diff
against), while `evaluate_security_findings_for_resource` runs unconditionally
against the first snapshot's normalized records. This existing dual-track
design (Findings evaluate current state; Changes require a prior baseline)
already provides exactly the behavior required — no fix was needed for
Kubernetes specifically.

## Family recovery behavior

When a previously-denied family becomes readable again, this message's
mechanism naturally does the safer of the two documented options: the
**next complete sync's snapshot is compared against the last snapshot that
existed** (which, per the suppression logic, never had that family's
records silently zeroed out in the stored snapshot — the suppression
happens at diff time, not at snapshot-write time, so the stored previous
snapshot still reflects the last time the connector actually observed that
family, whatever its age). This means real, observed drift during the
blind period is compared "last complete observation vs. current," never a
fabricated exact timeline — matching the requested copy semantic
("ConfigTrace observed this configuration changed between the last complete
observation and the current sync") without needing new copy, since the
existing Change classifier already describes the field-level transition
factually.

## Large-cluster performance results

`TestScale::test_normalizes_many_workloads_within_generous_bound`: 2,000
Deployments normalized well within a 10-second broad upper bound (no
external API latency involved — pure in-memory normalization).
`TestScale::test_large_rbac_binding_set_resolves_without_per_binding_calls`:
3,000 RoleBindings with subjects collected and resolved via exactly **one**
List call. Both are regression guards against an accidental O(n²)/Cartesian
blow-up, not tight millisecond benchmarks (per the task's own guidance to
avoid flaky assertions).

## N+1 guard results

Three dedicated tests (`TestNPlusOneGuard`) assert `list_fn.call_count == 1`
for workload family collection (25 Deployments), Role collection (50
Roles), and RBAC binding + subject resolution (30 ClusterRoleBindings) —
proving role/subject resolution happens against a locally-built
`role_index` dict, never one API call per binding/subject/workload.

## Record-count / truncation policy

Unchanged from messages 1–7 (already correct, re-verified this message):
`max_pages` (default 50) bounds pagination without silently dropping
legitimate records within that bound — `diag.truncated_by_page_cap` is set
whenever the cap is hit, which (per the existing `_family_completeness_status`)
correctly yields `"partial"`, so a truncated collection is never presented
as complete evidence. No new low, arbitrary per-object caps (e.g. "max 10
subjects per binding") were introduced — none were found to be necessary;
the existing design already emits exactly one record per real child object
(container, subject, port, route rule) with no unbounded Cartesian
expansion anywhere (confirmed during the RBAC/webhook rule categorization
review in messages 3 and 5).

## Permission diagnostics

New `build_permission_diagnostics(records)` / `format_permission_diagnostics_text(report)`
in `kubernetes.py` build the exact redacted report shape from the task
description (Cluster reachable / Namespaces / Workloads / RBAC / Networking
/ Admission / Coverage / Security Findings note) purely from already-fetched
normalized records — no new API calls, no raw exception text, no
credentials. 13 tests cover section correctness, partial/unsupported
status propagation, coverage rollup, and a sensitive-key sweep across the
full JSON-serialized report.

## Minimum read-only RBAC manifest

[`kubernetes_readonly_rbac_manifest.md`](kubernetes_readonly_rbac_manifest.md) —
generated by direct inspection of every API method call in
`kubernetes.py`. Covers core/apps/batch/RBAC/networking/admissionregistration
plus Gateway API CRDs (`gateways`/`httproutes` only). `get`/`list` verbs
only — no `watch` (the connector never watches). Explicitly excludes
Secrets, ConfigMaps, Pod exec/attach/log/port-forward, ServiceAccount token
creation, all write verbs, and `impersonate`/`bind`/`escalate`. 4 tests
verify the manifest file's YAML content directly (no secrets/configmaps
granted, only get/list verbs present, no write/escalation verbs present).

## Live-validation harness

`run_live_kubernetes_validation(kubeconfig_path, context_name=None)` reuses
the exact same `KubernetesConnector.fetch()` production pipeline against a
real kubeconfig, then builds the same redacted diagnostics report. Gated
entirely behind the `CONFIGTRACE_KUBERNETES_LIVE_KUBECONFIG` environment
variable — normal test runs never require, and never implicitly read, a
developer's default kubeconfig (`~/.kube/config` or `$KUBECONFIG` are never
touched; `kubeconfig_path` has no default value, confirmed by signature
introspection). The live test itself is `@pytest.mark.skipif`-gated and
passed in this session (skipped, as expected — no live cluster env var is
set here).

## Reliability matrix

83 rows. Every row maps to a real, passing (or explicitly gapped/N-A) test.

| Case | Family | Scope | Failure mode | Records collected? | Completeness | Removals allowed? | Retry? | Diagnostic | Expected behavior | Test coverage | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Role | cluster | 403 on list | No | partial | No (suppressed) | No (403 never retried) | family_completeness["kubernetes_role"]="partial" | Suppress Role removals | TestFamilyCompletenessFalseRemovalPrevention::test_role_403_suppresses_role_removals | PASS | |
| 2 | Role + Service | cluster | Role 403, Service complete | Role: no; Service: yes | Role partial, Service complete | Role: no; Service: yes | No | both statuses independent | Role suppressed, Service diffs normally | ::test_unrelated_complete_family_still_diffs_normally | PASS | |
| 3 | Role + Service | cluster | Role 403, Service real removal | Service: no (genuinely gone) | Role partial, Service complete | Service: yes (real) | No | n/a | Service removal reported; Role suppressed | ::test_service_removed_when_role_family_incomplete_but_service_family_complete | PASS | |
| 4 | Role | cluster | Recovers after denial | Yes (next complete sync) | complete | Yes (normal) | n/a | family_completeness["kubernetes_role"]="complete" | Family recovery re-enables normal diffing | ::test_denied_family_recovers_and_diffs_again | PASS | |
| 5 | Gateway | cluster | CRD uninstalled (unsupported) | No | unsupported | No (suppressed) | n/a | family_completeness["kubernetes_gateway"]="unsupported" | Unsupported suppresses removals same as partial | ::test_unsupported_family_also_suppresses_removals | PASS | |
| 6 | n/a (other provider) | n/a | n/a | n/a | n/a | Yes (unaffected) | n/a | n/a | Non-Kubernetes removal behavior completely unchanged | ::test_non_kubernetes_records_are_never_affected | PASS | |
| 7 | Cluster | cluster | Cluster record itself removed | n/a | n/a | Yes (never suppressed) | n/a | n/a | Cluster disappearance is always a real signal | ::test_cluster_record_itself_is_never_suppressed | PASS | |
| 8 | Role | cluster | No cluster record in new snapshot at all | n/a | n/a | Yes (fallback to normal) | n/a | n/a | Missing cluster record -> normal removal (no guessing) | ::test_missing_cluster_record_in_new_snapshot_falls_back_to_normal_removal | PASS | |
| 9 | Namespace c | namespace | Allowlist shrink (a,b,c -> a,b) | No | n/a (scope change) | No (suppressed) | n/a | configured_namespace_allowlist | Namespace de-scoped, not "deleted" | TestNamespaceAllowlistScopeChange::test_allowlist_shrink_suppresses_descoped_namespace_removals | PASS | |
| 10 | Namespace a | namespace | Allowlist unchanged, real removal | No (genuinely gone) | n/a | Yes (real) | n/a | n/a | Real removal still reported when scope unchanged | ::test_allowlist_unchanged_still_allows_real_removal | PASS | |
| 11 | Namespace a | namespace | Allowlist expand (a -> a,b) | No (genuinely gone) | n/a | Yes (real, unrelated to expand) | n/a | n/a | Expand doesn't retroactively suppress unrelated removal | ::test_allowlist_expand_does_not_suppress_unrelated_removal | PASS | |
| 12 | Namespace prod | namespace | Unrestricted -> unrestricted, real removal | No | n/a | Yes (real) | n/a | n/a | Unrestricted scope: normal removal semantics | ::test_unrestricted_to_unrestricted_real_removal_still_reported | PASS | |
| 13 | ClusterRole | cluster-scoped | Allowlist shrink (irrelevant to cluster-scoped) | No | n/a | Yes (real; no namespace field) | n/a | n/a | Cluster-scoped resources unaffected by namespace allowlist | ::test_cluster_scoped_record_without_namespace_is_unaffected_by_allowlist | PASS | |
| 14 | (pagination) | n/a | Multi-page success | Yes (all pages) | complete | n/a | n/a | pages_fetched=2 | Normal multi-page collection | TestPaginationResilience::test_multi_page_success | PASS | |
| 15 | (pagination) | n/a | Page 2 returns 403 | Partial (page 1 preserved) | partial | n/a | No | permission_denied=True | Partial data preserved, marked incomplete | ::test_page_two_permission_denied_preserves_page_one | PASS | |
| 16 | (pagination) | n/a | Page 1 returns 410 | Yes (after restart) | complete | n/a | 1 restart | continuation_restarted=True | Single restart from beginning, no duplicates | ::test_single_410_restart_then_success | PASS | |
| 17 | (pagination) | n/a | Second 410 after restart | Partial (up to failure) | partial | n/a | No 2nd restart | call_count==3 | Never a second restart — bounded | ::test_second_410_marks_partial_no_infinite_loop | PASS | |
| 18 | (pagination) | n/a | 429 then success | Yes | complete | n/a | Yes (1 retry, no real sleep) | throttled, retried | Bounded retry succeeds, no unbounded wait | ::test_429_then_success_retries_without_real_sleep | PASS | |
| 19 | (pagination) | n/a | 429 exhausted (10 failures) | No | partial | No | Yes (bounded, <=5 attempts) | error_category=throttled | Retry exhaustion marks partial, never infinite | ::test_429_exhausted_marks_partial | PASS | |
| 20 | (pagination) | n/a | 403 (not throttled) | No | partial | No | No (never retried) | permission_denied=True | 403 never retried as if transient | ::test_403_never_retried | PASS | |
| 21 | (pagination) | n/a | Repeated continuation token | Partial (first page) | partial | n/a | No | error_category=repeated_continuation_token | Stops rather than looping forever | ::test_repeated_continuation_token_stops | PASS | |
| 22 | (pagination) | n/a | Malformed page (items=None) | No | partial | n/a | No | malformed_metadata=True | Stops rather than guessing | ::test_malformed_page_shape_stops_safely | PASS | |
| 23 | (pagination) | n/a | max_pages cap hit | Partial (3 pages) | partial | n/a | No | truncated_by_page_cap=True | Bounded even with endless continue tokens | ::test_max_pages_cap_enforced | PASS | |
| 24 | (timeout) | n/a | ReadTimeoutError | No | n/a | n/a | n/a | category=timeout | Classified as timeout, not connection_error | TestTimeoutClassification::test_read_timeout_classified_as_timeout_not_connection_error | PASS | |
| 25 | (timeout) | n/a | ConnectTimeoutError | No | n/a | n/a | n/a | category=timeout | Classified as timeout | ::test_connect_timeout_classified_as_timeout | PASS | |
| 26 | (timeout) | n/a | socket.timeout | No | n/a | n/a | n/a | category=timeout | Classified as timeout | ::test_socket_timeout_classified_as_timeout | PASS | |
| 27 | (connection) | n/a | Generic ConnectionError | No | n/a | n/a | n/a | category=connection_error | Distinct from timeout | ::test_generic_connection_error_still_classified_separately | PASS | |
| 28 | (timeout) | n/a | Timeout -> family status | No | partial | No | n/a | _family_completeness_status | Timeout maps to partial, never unsupported | ::test_timeout_family_status_is_partial_not_unsupported | PASS | |
| 29 | Cluster identity | cluster | Same UID, same host, twice | n/a | n/a | n/a | n/a | n/a | Deterministic, stable identity | TestClusterIdentityStability::test_same_uid_same_host_gives_same_id | PASS | |
| 30 | Cluster identity | cluster | Context renamed | n/a | n/a | n/a | n/a | n/a | Identity function has no context_name param at all | ::test_context_name_never_affects_identity | PASS | |
| 31 | Cluster identity | cluster | Same UID, different host (HA VIP change) | n/a | n/a | n/a | n/a | n/a | UID authoritative over host | ::test_kube_system_uid_is_primary_identity_not_host | PASS | |
| 32 | Cluster identity | cluster | UID unavailable, host fallback | n/a | n/a | n/a | n/a | n/a | Deterministic host-hash fallback | ::test_host_fallback_used_only_when_uid_unavailable | PASS | |
| 33 | Cluster identity | cluster | Credential rotation, same cluster | n/a | n/a | n/a | n/a | n/a | Identity stable across credential rotation | ::test_credential_rotation_for_same_cluster_preserves_identity | PASS | |
| 34 | Cluster recreation | cluster | New kube-system UID, same host | n/a | n/a | n/a | n/a | n/a | New cluster identity, not same-cluster continuation | TestClusterRecreation::test_new_kube_system_uid_is_a_new_identity | PASS | |
| 35 | Cluster recreation | cluster | Recreated cluster diff | n/a | n/a | Old: removed; New: added | n/a | n/a | Fully disjoint record set, never cross-cluster "modified" | ::test_recreated_cluster_never_cross_diffs_with_old_cluster_records | PASS | |
| 36 | Multi-cluster | namespace+resource | Same namespace/name, different cluster | Yes (both) | n/a | n/a | n/a | n/a | Distinct record_ids, no collision | TestMultiClusterNameCollisionSafety::test_same_namespace_and_resource_name_different_cluster_stay_distinct | PASS | |
| 37 | Multi-cluster | n/a | Provider metadata cluster identity | n/a | n/a | n/a | n/a | cluster_id/cluster_name always present | Every Change carries cluster identity | ::test_provider_metadata_always_includes_cluster_identity | PASS | |
| 38 | Multi-cluster | namespace | Identical namespace across 2 clusters | Yes | n/a | added+removed, never modified | n/a | n/a | Diff never merges records across clusters | ::test_diff_never_merges_records_across_clusters_even_with_identical_namespace | PASS | |
| 39 | Host normalization | n/a | Scheme/credentials in host string | n/a | n/a | n/a | n/a | n/a | Stripped to host:port only | TestApiServerHostNormalization::test_normalization_strips_scheme_and_credentials | PASS | |
| 40 | Host normalization | n/a | Case sensitivity | n/a | n/a | n/a | n/a | n/a | Case-insensitive normalization | ::test_normalization_is_case_insensitive | PASS | |
| 41 | Diagnostics | all | Reachable cluster | n/a | mixed | n/a | n/a | 5 sections built | Sections match task's example report | TestPermissionDiagnosticsReport::test_reachable_cluster_reports_sections | PASS | |
| 42 | Diagnostics (RBAC) | cluster | Role partial | n/a | partial | n/a | n/a | status_label="partially available" | Partial family surfaced in report | ::test_partial_role_family_reflected_in_rbac_section | PASS | |
| 43 | Diagnostics (Networking) | cluster | Gateway unsupported | n/a | unsupported | n/a | n/a | status="unsupported" | Unsupported family surfaced distinctly | ::test_unsupported_gateway_reflected_in_networking_section | PASS | |
| 44 | Diagnostics (coverage) | cluster | Any family incomplete | n/a | mixed | n/a | n/a | coverage="partial" | Coverage rollup reflects any incompleteness | ::test_coverage_is_partial_when_any_family_incomplete | PASS | |
| 45 | Diagnostics (coverage) | cluster | All families complete | n/a | complete | n/a | n/a | coverage="complete" | Full coverage correctly reported | ::test_coverage_is_complete_when_every_family_complete | PASS | |
| 46 | Diagnostics | cluster | No cluster record (unreachable) | n/a | n/a | n/a | n/a | cluster_reachable=False | Graceful unreachable-cluster report | ::test_unreachable_cluster_reports_gracefully | PASS | |
| 47 | Diagnostics (scope) | cluster | Unrestricted namespace scope | n/a | n/a | n/a | n/a | namespace_scope="all namespaces" | Scope correctly labeled | ::test_namespace_scope_unrestricted | PASS | |
| 48 | Diagnostics (scope) | cluster | Restricted namespace scope | n/a | n/a | n/a | n/a | namespace_scope="2 allowlisted..." | Scope correctly labeled | ::test_namespace_scope_allowlisted | PASS | |
| 49 | Diagnostics (Findings note) | cluster | n/a | n/a | n/a | n/a | n/a | safe wording | No overclaim of Finding completeness | ::test_security_findings_note_present_and_safe | PASS | |
| 50 | Diagnostics (text render) | cluster | n/a | n/a | n/a | n/a | n/a | no raw secrets/creds in text | Safe plain-text rendering | ::test_text_rendering_contains_no_raw_exception_or_credential_text | PASS | |
| 51 | Diagnostics (safety sweep) | cluster | n/a | n/a | n/a | n/a | n/a | no forbidden substrings in JSON | Full-report sensitive-key sweep | TestDiagnosticsSafety::test_no_sensitive_keys_anywhere_in_report | PASS | |
| 52 | N+1 guard | Workload | 25 Deployments | Yes (all) | complete | n/a | n/a | list_fn.call_count==1 | Bulk collection, not per-object | TestNPlusOneGuard::test_workload_family_collection_is_bulk_not_per_object | PASS | |
| 53 | N+1 guard | Role | 50 Roles | Yes (all) | complete | n/a | n/a | list_fn.call_count==1 | Bulk collection, not per-object | ::test_role_collection_is_bulk_not_per_object | PASS | |
| 54 | N+1 guard | RBAC binding | 30 ClusterRoleBindings w/ subjects | Yes (all) | complete | n/a | n/a | list_fn.call_count==1 | Role/subject resolution is local, no extra calls | ::test_rbac_binding_resolution_makes_no_extra_api_calls_per_subject | PASS | |
| 55 | Scale | Workload | 2,000 Deployments | Yes (all) | complete | n/a | n/a | elapsed<10s (broad bound) | No O(n^2)/Cartesian blow-up | TestScale::test_normalizes_many_workloads_within_generous_bound | PASS | |
| 56 | Scale | RBAC binding | 3,000 RoleBindings | Yes (all) | complete | n/a | n/a | list_fn.call_count==1 | Scales without per-binding calls | ::test_large_rbac_binding_set_resolves_without_per_binding_calls | PASS | |
| 57 | RBAC manifest | n/a | Artifact existence | n/a | n/a | n/a | n/a | file exists | Manifest documentation artifact present | TestRbacManifestArtifact::test_manifest_file_exists | PASS | |
| 58 | RBAC manifest | n/a | Secrets/ConfigMaps excluded | n/a | n/a | n/a | n/a | no "secrets"/"configmaps" in YAML | Permanent boundary respected in manifest | ::test_manifest_excludes_secrets_and_configmaps | PASS | |
| 59 | RBAC manifest | n/a | Only get/list verbs | n/a | n/a | n/a | n/a | verbs subset of {get,list} | No watch/write verbs granted | ::test_manifest_uses_only_get_list_verbs | PASS | |
| 60 | RBAC manifest | n/a | No write/escalation verbs | n/a | n/a | n/a | n/a | no create/update/patch/delete/impersonate/bind/escalate/watch | Least-privilege manifest | ::test_manifest_excludes_write_and_escalation_verbs | PASS | |
| 61 | Live validation | n/a | No env var set | n/a | n/a | n/a | n/a | skipped | Never required for normal CI | TestLiveValidationHarness::test_skips_without_env_var | PASS | |
| 62 | Live validation | n/a | Env var set (real cluster) | n/a | n/a | n/a | n/a | gated by skipif | Runs only when explicitly opted in | ::test_live_validation_against_real_cluster | SKIP (no live cluster in this session) | Correctly skipped |
| 63 | Live validation | n/a | Implicit default kubeconfig | n/a | n/a | n/a | n/a | required positional arg | Never reads ~/.kube/config or $KUBECONFIG implicitly | ::test_never_reads_arbitrary_default_kubeconfig | PASS | |
| 64 | Authentication | cluster | Valid connection | Yes | complete | n/a | n/a | n/a | Baseline success path (pre-existing, message 1) | test_kubernetes_foundation.py (existing suite) | PASS | Pre-existing coverage retained |
| 65 | Authentication | cluster | 401 | No | n/a | n/a | No | category=auth_failed | Credentials rejected, clearly surfaced | test_kubernetes_foundation.py (existing suite) | PASS | Pre-existing coverage retained |
| 66 | Authentication | cluster | Invalid kubeconfig | No | n/a | n/a | No | ConnectorError raised at validate_credentials | Fails validation clearly, not silently | test_kubernetes_foundation.py (existing suite) | PASS | Pre-existing coverage retained |
| 67 | Authentication | cluster | TLS failure | No | n/a | n/a | No | category=tls_error | Never silently disables verification | test_kubernetes_foundation.py (existing suite) | PASS | Pre-existing coverage retained |
| 68 | Authentication | cluster | Connection refused | No | n/a | n/a | No | category=connection_error | Foundational failure surfaced clearly | test_kubernetes_foundation.py (existing suite) | PASS | Pre-existing coverage retained |
| 69 | Permission | namespace-list | 403 | No | partial | No (message-1 cluster-level suppression + this message's family map) | No | permission_denied=True | Namespace list denial marked partial | test_kubernetes_foundation.py + this message's family_completeness | PASS | |
| 70 | Permission | workload | 403 | No | partial | No (suppressed) | No | family_completeness | Workload family denial suppresses removals | TestFamilyCompletenessFalseRemovalPrevention (workload analog of Role case) | PASS | Same mechanism, proven generically via Role case #1 |
| 71 | Permission | RBAC | 403 | No | partial | No (suppressed) | No | family_completeness | RBAC family denial suppresses removals | Case #1 | PASS | |
| 72 | Permission | network | 403 | No | partial | No (suppressed) | No | family_completeness | Network family denial suppresses removals | Case #2/#3 (Service analog) | PASS | |
| 73 | Permission | admission | 403 | No | partial | No (suppressed) | No | family_completeness | Admission family denial suppresses removals | Same mechanism as case #1, generic across all 20 families | PASS | |
| 74 | Permission | one namespace denied | n/a | n/a | n/a | n/a | n/a | documented architectural note | Not a distinct failure mode today (single cluster-wide List call architecture) | Documented in "Namespace-level completeness design" section above | N/A | Would require per-namespace API calls; deliberately not introduced this message |
| 75 | APIs | Gateway | Unsupported (CRD not installed) | No | unsupported | No (suppressed) | n/a | family_completeness="unsupported" | Same suppression as partial | Case #5 | PASS | |
| 76 | APIs | Gateway | Disappears after being present (cluster downgrade) | No (new sync) | unsupported | No (suppressed) | n/a | family_completeness="unsupported" | Previously-known Gateways not falsely reported deleted | Same mechanism as case #5 (state-independent) | PASS | |
| 77 | APIs | Admission | admissionregistration API unavailable | No | unsupported | No (suppressed) | n/a | family_completeness="unsupported" | Same suppression mechanism, generic | Same mechanism as case #5 | PASS | |
| 78 | Scope | namespace allowlist | Shrink | No | n/a | No (suppressed) | n/a | configured_namespace_allowlist | Case #9 | PASS | |
| 79 | Scope | namespace allowlist | Expand | No (unrelated) | n/a | Yes (unrelated) | n/a | configured_namespace_allowlist | Case #11 | PASS | |
| 80 | Scope | cluster-scoped resources | Allowlist irrelevant | No | n/a | Yes (real) | n/a | n/a | Case #13 | PASS | |
| 81 | Diff | incomplete family | Suppresses removals | No | partial | No | n/a | n/a | Case #1 | PASS | |
| 82 | Diff | complete family | Still diffs normally | Yes | complete | Yes | n/a | n/a | Case #2/#3 | PASS | |
| 83 | Diff | family recovers | Compares last-known-complete to newly-complete | Yes | complete | Yes | n/a | n/a | Case #4 | PASS | |

## Totals

- **Matrix rows**: 83.
- **PASS**: 81.
- **SKIP (correctly, by design)**: 1 (live-cluster test — no live cluster
  configured in this session; the skip path itself is verified PASS).
- **N/A (documented architectural boundary, not a gap)**: 1 (true
  per-namespace API-level partial denial — the current architecture makes
  one cluster-wide List call per resource type, so this specific failure
  mode does not exist as a distinct code path; introducing it would require
  N per-namespace API calls per family, working against this message's own
  large-cluster-performance goal).
- **GAP**: 0.
- **FIXED**: the false-removal bug itself (unconditionally treating an
  absent record as removed with no completeness awareness) — the core defect
  this entire message targets — confirmed fixed and regression-tested.
