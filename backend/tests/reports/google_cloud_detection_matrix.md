# Google Cloud Detection QA Matrix

Exhaustive end-to-end validation of the Google Cloud provider (connector →
diff tracking → risk classification → security findings → registries →
frontend catalog), following the same methodology established for
SendGrid, Twilio, Terraform Cloud, GitLab, Jira, Linear, PagerDuty,
Datadog, Clerk, and Auth0 in prior QA passes.

## Summary

Google Cloud's connector (`app/connectors/google_cloud.py`), schema
(`google_cloud_schema.py`), and security rules
(`security_rules/google_cloud.py`, 22 rules across 8 of its 10 record
types) were already mature (built across M78A/M78C). **Registries and
the frontend catalog were already in 22/22 rule-key parity** — but this
pass found and fixed **one real severity inconsistency** (see Fix #0
below). The two recurring root-cause bugs from every prior provider pass
were both present here too, with the same twist seen in Auth0's pass:

1. **`risk_rules/google_cloud.py` did not exist at all.** `risk_service.py`
   had no `google_cloud_` dispatch branch, so **every Google Cloud
   configuration change silently fell through to the Cloudflare DNS
   classifier**.

2. **Diff/drift tracking gap.** Google Cloud had **zero entries** in
   `diff_service.py`'s per-provider tracked-fields dispatch, so every
   Google Cloud record type fell through to the Cloudflare DNS default
   tuple. `compute_diff` could never detect a modified field on an
   existing Google Cloud record.

3. **The twist (same pattern as Auth0)**: `provider_capability_matrix_service.py`'s
   Google Cloud entry already claims `drift_diff=True` and
   `drift_risk_classification=True` (and even `drift_review_workflow=True`).
   This pass's fixes make those pre-existing claims true for the Change-
   classification layer for the first time.

**Fix #0 — severity-convention inconsistency found via registry/frontend
audit**: `google_cloud_firewall_rule_no_targets` is a dynamic-severity
rule (`"high" if broad/admin ingress also present else "medium"`), and
every OTHER dynamic-severity Google Cloud rule stores its **worst-case**
value as the pack.py/frontend headline severity with a `severityNote`
documenting the lesser case (e.g. `firewall_public_admin_ingress`:
headline `"critical"`, note *"high for SSH"*). This one rule was the sole
exception — it stored the **base/lesser** case (`"medium"`) as headline
with a note about the bump to `"high"`, inverted from the established
convention. **Fixed**: `security_rule_pack.py` and
`securityRuleCatalog.ts` now both store `"high"` as the headline
severity for this rule, matching every other dynamic-severity rule's
convention. `security_rule_confidence.py`'s entry is a *confidence* value
(unrelated axis) and needed no change. No test asserted the old `"medium"`
headline value, so this fix required no test updates — confirmed via
grep before making the change.

Building on the false-positive severity bug found and fixed in
PagerDuty's classification-QA pass and the crossing-only threshold bug
found and fixed in Datadog's classification-QA pass, the new
`risk_rules/google_cloud.py` module was written **defensively from the
start**: every count-based branch uses `_int_or_none()` (not a bare
`int(val or 0)` coercion), and the service-account key count threshold
uses "any increase over the threshold," not a crossing-only check.

No new Security Finding rules were added — all 22 existing rules already
cover every field this pass identified as security-relevant, and this
provider is the first in this session's series to model firewall-rule
list fields (`source_ranges_summary`, `allowed_summary`) as diff-tracked
values; the Change classifier diffs these lists directly (detecting
newly-added public source ranges and newly-added admin/broad port
entries) to satisfy the task's explicit categories I and J.

## Connector extraction review

| Record type | Source endpoint | Sensitive values excluded? | Fail-soft on error? | Stable record IDs? |
|---|---|---|---|---|
| `google_cloud_project` | Cloud Resource Manager v3 `projects.get` | Yes — label VALUES excluded (only key names), parent ID excluded (only parent type) | Yes — wrapped in the connector's top-level `fetch()` try/except | Yes — `project_id` |
| `google_cloud_iam_policy_summary` | Cloud Resource Manager `getIamPolicy` | Yes — principal identifiers (member emails/IDs), `etag`, and CEL condition expressions are NEVER stored; only role names + bucketed member-type counts | Yes — dedicated try/except around the IAM policy fetch | Yes — `f"gcp_iam_policy_{project_id}"` |
| `google_cloud_vpc_network` | Compute v1 `networks.list` | Yes — subnet/peering lists reduced to counts | Yes | Yes — selfLink-derived |
| `google_cloud_firewall_rule` | Compute v1 `firewalls.list` | Yes — target service-account emails reduced to a count; source/destination ranges and allowed/denied lists capped at 20 entries | Yes | Yes — selfLink-derived |
| `google_cloud_storage_bucket` | Storage v1 `buckets.list` | Yes — no object names/contents/signed URLs/ACL grantee identities ever accessed | Yes | Yes — bucket name-derived |
| `google_cloud_sql_instance` | Cloud SQL Admin v1beta4 `instances.list` | Yes — no database names/users/passwords/connection strings/row data | Yes | Yes — `project_id` + `instance_name` |
| `google_cloud_run_service` | Cloud Run Admin v2 `services.list` + per-service `getIamPolicy` (fail-soft) | Yes — env var names/values, secret names/values, container image URIs never stored; only counts | Yes — per-service invoker-policy fetch wrapped in its own `except Exception: pass` | Yes — `project_id`/`region`/`service_name`-derived |
| `google_cloud_gke_cluster` | Container v1 `clusters.list` | Yes — no kubeconfig/certs/node names/pod specs/workload data/secrets | Yes | Yes — selfLink-derived |
| `google_cloud_service_account_key_summary` | IAM Admin v1 `serviceAccounts.list` + per-SA `keys.list` (fail-soft, capped at 50 SAs) | Yes — SA emails used only as API path parameters, never stored; key IDs/material/OAuth tokens never stored; only aggregate counts | Yes — per-SA key fetch wrapped in `except Exception: pass` | Yes — `f"gcp_sa_key_summary_{project_id}"` (project-level aggregate) |
| `google_cloud_secret_manager_summary` | Secret Manager v1 `secrets.list` | Yes — secret names/values/labels never stored; only counts and replication-policy distribution | Yes — the whole fetch is wrapped in its own try/except with an explicit comment about the surface requiring `secretmanager.secrets.list` permission | Yes — `f"gcp_secret_mgr_summary_{project_id}"` (project-level aggregate) |

**Confirmed via code inspection** (connector module docstring + normalizer
bodies + the module-level "PRIVACY / SECURITY" comment block):
- No **service-account private keys** are stored — `_normalize_service_account_key_summary`
  reads `keyType`/`validAfterTime`/`disabled` only, never the key material
  or key ID.
- No **credentials or tokens** are stored — `service_account_json`,
  the minted OAuth access token, and the JWT assertion are used only
  within the token-acquisition/request scope and never written to a
  record or logged.
- No **object contents** are stored — the Storage bucket normalizer never
  calls an objects.* endpoint at all.
- No **SQL data** is stored — the Cloud SQL Admin API surface used here
  (`instances.list`) never returns row/query data; the connector doesn't
  call any data-plane SQL endpoint.
- No **logs/events payload contents** are stored — the M78D audit-log
  ingestion path (`list_activity_events`, not reviewed in depth by this
  detection-QA pass since it's a separate M78D/E/F system) uses a strict
  control-plane `methodName` allowlist and reuses the same safe drift
  normalizers rather than storing raw log entries.
- No **customer data** is stored — none of the 10 record types touch a
  user-facing/customer-facing data plane.
- No **full secrets/connection strings** are stored — Secret Manager
  summary is aggregate counts only; Cloud SQL connection strings are
  never constructed or read.
- Only **safe configuration metadata, booleans, counts, IDs, and posture
  fields** are stored, confirmed field-by-field against each normalizer
  above.

**Record ID stability note**: `google_cloud_service_account_key_summary`
and `google_cloud_secret_manager_summary` are **project-level aggregates**
(one record per project, not one per resource) — this is an intentional
design choice (per-SA-key and per-secret detail would require storing
identifying information the schema explicitly forbids), not a stability
gap.

## Diff/change tracking review

**Before this pass**: 0 of 10 record types had a tracked-fields entry —
all Google Cloud modified-field changes silently fell through to the
Cloudflare DNS default tuple and were never detected, **despite the
capability matrix already claiming `drift_diff=True`.**

**After this pass**: all 10 record types are tracked with every
security-relevant field verified present, including every one of the
task's high-priority fields: `role_names` (IAM binding role),
`allusers_binding_present`/`allauthenticatedusers_binding_present`,
`broad_role_count`, `source_ranges_summary`/`allowed_summary` (firewall
ports/ranges), `public_access_prevention`/`uniform_bucket_level_access_enabled`
(bucket public access posture), `versioning_enabled`/
`retention_policy_locked` (bucket retention/versioning),
`public_ip_enabled`/`require_ssl`/`ssl_mode`/`backup_enabled`/
`deletion_protection_enabled` (Cloud SQL), `user_managed_key_count`/
`old_user_managed_key_count` (service-account keys), `public_endpoint_enabled`/
`master_authorized_networks_count`/`workload_identity_enabled` (GKE).

No fields were found that are tracked but no longer emitted by the
connector — the tracked tuples were built directly from each normalizer's
actual return dict (this schema file has no `TypedDict`s, unlike Auth0/
Clerk, so tracked fields were cross-referenced against the connector's
normalizer source directly rather than schema type annotations).

**Not modeled** (task explicitly asked about these, confirming absence
rather than inventing them): KMS keys as a standalone record type (only
a boolean `encryption_default_kms_key_present` presence flag on the
bucket record — no KMS key rotation/protection-level/state fields exist
anywhere in the connector); BigQuery datasets (no BigQuery API is called
at all); per-service-account `disabled` status as an individual record
(only the aggregate `disabled_service_account_count` on the project-level
key summary); organization/folder policy metadata (no Organization
Policy API call exists).

## Test matrix

| Test case | Normalized record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes/fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. IAM broad principal added | `google_cloud_iam_policy_summary` | `allusers_binding_present` | `False → True` | Change (high) + Finding (high, `google_cloud_iam_public_member`) | Change never generated before fix | high | high (after fix) | `google_cloud_iam_public_member` (high) — matches | new `test_iam_public_member_added_is_high` | **FIXED** | — |
| A2. IAM broad principal removed | `google_cloud_iam_policy_summary` | `allusers_binding_present` | `True → False` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a | new `test_iam_public_member_removed_is_low` | **FIXED** | — |
| B. IAM primitive owner/editor role added | `google_cloud_iam_policy_summary` | `role_names` | `[] → [..., "roles/owner"]` | Change (high) + Finding (high, `google_cloud_iam_broad_privileged_role`) | Change never generated before fix | high | high (after fix) | `google_cloud_iam_broad_privileged_role` (high) — matches | new `test_iam_high_severity_broad_role_added_is_high` | **FIXED** | Change classifier diffs the `role_names` list directly (added-vs-removed set comparison) — the only list-valued field in this record type |
| B2. IAM primitive role removed | `google_cloud_iam_policy_summary` | `role_names` | `["roles/owner"] → []` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a | new `test_iam_broad_role_removed_is_low` | **FIXED** | — |
| C. IAM privileged role count increased (medium-severity role) | `google_cloud_iam_policy_summary` | `role_names` | `[] → ["roles/iam.serviceAccountAdmin"]` | Change (medium) + Finding (medium, `google_cloud_iam_broad_privileged_role`) | Change never generated before fix | medium | medium (after fix) | `google_cloud_iam_broad_privileged_role` (medium branch) — matches | new `test_iam_medium_severity_broad_role_added_is_medium` | **FIXED** | Same rule key as B, different severity bucket depending on which role matched — mirrored exactly |
| D. Service account disabled/enabled | n/a (aggregate only) | `disabled_service_account_count` | count change | Change (low, generic) | Change never generated before fix | low | low (after fix) | n/a — no per-SA `disabled` record exists, only the project-level aggregate count | covered by tracked-field sweep | **PARTIAL (aggregate only)** | This connector has no per-service-account record type; only the aggregate `disabled_service_account_count` on `google_cloud_service_account_key_summary` exists. Not invented — documented as a scope limitation |
| E. Service account key count increased | `google_cloud_service_account_key_summary` | `user_managed_key_count` | `1 → 2` | Change (medium) + Finding (medium, `google_cloud_service_account_user_managed_keys`) | Change never generated before fix | medium | medium (after fix) | `google_cloud_service_account_user_managed_keys` (medium branch) — matches | new `test_sa_key_count_increase_below_five_is_medium` | **FIXED** | — |
| E2. Service account key count reaches high threshold | `google_cloud_service_account_key_summary` | `user_managed_key_count` | `3 → 5` | Change (high) + Finding (high, count>=5 branch) | Change never generated before fix | high | high (after fix) | `google_cloud_service_account_user_managed_keys` (high branch) — matches | new `test_sa_key_count_reaches_five_is_high` | **FIXED** | — |
| E3. Service account key count decreased | `google_cloud_service_account_key_summary` | `user_managed_key_count` | `5 → 3` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a | new `test_sa_key_count_decrease_is_low` | **FIXED** | — |
| F. Bucket public access enabled/disabled | `google_cloud_storage_bucket` | `public_access_prevention` | `"enforced" → "inherited"` | Change (medium) + Finding (medium/high dynamic, `google_cloud_storage_public_access_prevention_disabled`) | Change never generated before fix | medium | medium (after fix) | matches the Finding's base-case (medium) branch | new `test_bucket_public_access_prevention_disabled_is_medium` | **FIXED** | Finding severity bumps to high when `uniform_bucket_level_access_enabled` is ALSO false — a single-field Change can't see that sibling, so this defaults to the base-case `medium`, matching the Run/GKE precedent of not over-alerting on an unconfirmed combination |
| G. Uniform bucket-level access enabled/disabled | `google_cloud_storage_bucket` | `uniform_bucket_level_access_enabled` | `True → False` | Change (medium) + Finding (medium, `google_cloud_storage_uniform_access_disabled`) | Change never generated before fix | medium | medium (after fix) | `google_cloud_storage_uniform_access_disabled` (medium) — matches | new `test_bucket_uniform_access_disabled_is_medium` | **FIXED** | — |
| H. Bucket retention/versioning posture changed | `google_cloud_storage_bucket` | `versioning_enabled`, `retention_policy_locked` | `True → False` (each) | Change (low / medium) + Finding (low `google_cloud_storage_versioning_disabled` / medium-or-low dynamic `google_cloud_storage_retention_not_locked`) | Change never generated before fix | low / medium | low / medium (after fix) | both match | covered by tracked-field sweep | **FIXED** | — |
| I. Firewall 0.0.0.0/0 ingress added | `google_cloud_firewall_rule` | `source_ranges_summary` | `["10.0.0.0/8"] → ["10.0.0.0/8", "0.0.0.0/0"]` | Change (high) + Finding (critical/high dynamic, depends on concurrent port entries — `google_cloud_firewall_public_broad_ingress`/`_admin_ingress`) | Change never generated before fix | high | high (after fix) | Change-only approximation — see design note | new `test_firewall_public_source_range_added_is_high` | **FIXED** | The Findings require the COMBINATION of a public range AND a specific allowed-port entry (evaluated together on the same record); the Change classifier fires on the public-range addition alone at a conservative `high` (not `critical`), since it cannot confirm which port entries are concurrently allowed |
| I2. Firewall 0.0.0.0/0 ingress removed | `google_cloud_firewall_rule` | `source_ranges_summary` | `["10.0.0.0/8", "0.0.0.0/0"] → ["10.0.0.0/8"]` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a | new `test_firewall_public_source_range_removed_is_low` | **FIXED** | — |
| J. Firewall SSH/RDP/admin port opened | `google_cloud_firewall_rule` | `allowed_summary` | new entry `{"protocol":"tcp","ports":["3389"]}` / `["22"]` / `{"protocol":"all"}` | Change (critical/critical/critical) + Finding (critical/high/critical, `google_cloud_firewall_public_admin_ingress`/`_broad_ingress`) | Change never generated before fix | critical (RDP/broad) / high (SSH) | critical (RDP/broad) / high (SSH) (after fix) | both rule keys match | new `test_firewall_rdp_port_entry_added_is_critical`, `test_firewall_ssh_port_entry_added_is_high`, `test_firewall_broad_port_entry_added_is_critical` | **FIXED** | Change classifier diffs `allowed_summary` (a list of dicts) directly, mirroring `security_rules/google_cloud.py`'s `_expand_ports`/`_is_broad_port_entry` helpers, to detect newly-added admin/broad port entries with matching severity |
| J2. Firewall benign port opened | `google_cloud_firewall_rule` | `allowed_summary` | new entry `{"protocol":"tcp","ports":["443"]}` | Change (low) | Change never generated before fix | low | low (after fix) | n/a | new `test_firewall_benign_port_entry_added_is_low` | **FIXED** | Confirms the port-diffing logic doesn't over-fire on non-admin, non-broad entries |
| J3. Firewall rule loses its explicit targets | `google_cloud_firewall_rule` | `target_tag_count` | `2 → 0` | Change (medium) + Finding (medium/high dynamic, `google_cloud_firewall_rule_no_targets`) | Change never generated before fix | medium | medium (after fix) | matches base-case branch | new `test_firewall_no_targets_gained_is_medium` | **FIXED** | Same combined-condition limitation as F/I — Change classifier can't confirm the concurrent broad/admin ingress that would elevate this to `high` |
| K. Cloud SQL public IP enabled | `google_cloud_sql_instance` | `public_ip_enabled` | `False → True` | Change (high) + Finding (high/medium dynamic, `google_cloud_sql_public_network_access`) | Change never generated before fix | high | high (after fix) | matches the Finding's higher (authorized-networks-present) branch | new `test_sql_public_ip_enabled_is_high` | **FIXED** | — |
| L. Cloud SQL SSL/backups/deletion protection changed | `google_cloud_sql_instance` | `require_ssl`, `ssl_mode`, `backup_enabled`, `deletion_protection_enabled` | `True → False` (each) | Change (medium each) + Finding (medium each, `google_cloud_sql_weak_tls`/`_backups_disabled`/`_deletion_protection_disabled`) | Change never generated before fix | medium (each) | medium (each) (after fix) | all match | new `test_sql_backups_disabled_is_medium` + covered by tracked-field sweep for the other three | **FIXED** | — |
| M. KMS key state/rotation/protection changed | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | No KMS key record type or endpoint exists — only a boolean `encryption_default_kms_key_present` presence flag on the storage bucket record. Not invented per task instructions |
| N. BigQuery dataset public access changed | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | No BigQuery API is called by this connector. Not invented |
| O. GKE public endpoint / authorized networks changed | `google_cloud_gke_cluster` | `public_endpoint_enabled` | `False → True` | Change (medium) + Finding (high/n-a dynamic, `google_cloud_gke_public_control_plane`, requires `master_authorized_networks_count==0` too) | Change never generated before fix | medium | medium (after fix) | Change-only approximation — see design note | new (covered by tracked-field sweep; explicit test on `legacy_abac_enabled`/`workload_identity_enabled` siblings) | **FIXED** | Deliberately kept at `medium` rather than the Finding's `high` ceiling: a public endpoint combined with configured authorized networks is a common, safe GKE configuration, so defaulting to `high` would over-alert — same reasoning as the Auth0 `grant_client_credentials_enabled` fix from the prior classification-QA pass |
| O2. GKE legacy ABAC / Workload Identity changed | `google_cloud_gke_cluster` | `legacy_abac_enabled`, `workload_identity_enabled` | `False → True` / `True → False` | Change (high / medium) + Finding (high `google_cloud_gke_legacy_abac_enabled` / medium `google_cloud_gke_workload_identity_disabled`) | Change never generated before fix | high / medium | high / medium (after fix) | both match | new `test_gke_legacy_abac_enabled_is_high`, `test_gke_workload_identity_disabled_is_medium` | **FIXED** | — |
| P. Audit logging/sink posture changed | n/a | n/a | n/a | n/a | not modeled at the drift-record level | n/a | n/a | n/a | n/a | **N/A** | n/a | Audit-log *ingestion* exists (M78D `list_activity_events`, a separate Activity system), but no drift-tracked "logging sink configuration" record type/endpoint exists in the 10 M78A/M78C surfaces. Not invented |
| Q. Unknown/missing fields never produce high/critical findings | all 10 record types | any | `None`/missing | no high/critical finding/classification | Confirmed — every Finding check in `security_rules/google_cloud.py` uses explicit boolean/category-string equality (`is False`/`is True`), and every new Change classifier branch falls to `low` on unparseable/missing values via `_is_falsy_explicit`/`_is_truthy`/`_int_or_none()`'s explicit `None` check | none | none | all | new `test_every_tracked_field_classifies_without_error_or_invalid_severity`, `test_unknown_transitions_never_produce_high_or_critical`, `test_count_unknown_not_treated_as_zero` | PASS | — |
| R. 403/404 fail-soft on optional endpoints | Cloud Run invoker-policy fetch, GKE, service-account keys, Secret Manager (soft-failure surfaces) | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed — every surface in `fetch()` is wrapped in its own `try/except Exception` block that logs a warning and continues; the Run service's per-service invoker-policy fetch has an additional inner `except Exception: pass` | n/a | n/a | n/a | existing `test_milestone78a`/`test_milestone78c` connector tests | PASS | — |
| S. Records with normalized fields but no security rule | `google_cloud_project` (all fields), `google_cloud_vpc_network` (all fields) | n/a | n/a | correctly documented gap | Confirmed — `security_rules/google_cloud.py`'s own docstring explicitly states these two record types have "no actionable posture surface at M78B"; the `evaluate()` dispatcher returns `[]` for both | n/a | n/a | n/a — intentionally undocumented at the Finding layer, now explicitly classified generic-low at the Change layer | new project/vpc_network branches in `risk_rules/google_cloud.py` | PASS (documented, not a gap to fix) | Two full record types with zero Findings — the largest "no rule" surface of any provider in this session, but explicitly pre-documented by the module's own author, not an oversight |
| T. Security rules with no reachable normalized record | — | — | — | — | None found — all 22 rules dispatch from `evaluate()` against one of the 8 record types that actually have Findings, and all 8 are emitted by the connector | n/a | n/a | all | existing `test_google_cloud_provider_depth_qa.py` / `test_milestone78h_...` coverage | PASS | Zero dead/unreachable rules |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | 22/22 rule keys present everywhere with matching severities | Verified via exact set diff: `security_rules/google_cloud.py` (22) vs. `security_rule_registry.py` (22), `security_rule_pack.py` (22, all severities cross-checked programmatically against source, **1 mismatch found and fixed** — see Fix #0), `security_rule_confidence.py` (22), `security_coverage_service.py` (22 rule-key→record-type mappings, no extras once record-type-string false positives are excluded), and `securityRuleCatalog.ts` (22) | n/a | n/a | all | ad hoc scripted diff in this pass | **FIXED (1 severity mismatch)** | `google_cloud_firewall_rule_no_targets` stored the base-case severity as headline instead of the worst-case, inverted from every other dynamic-severity rule's convention — fixed in `security_rule_pack.py` and `securityRuleCatalog.ts` |
| Diff-tracked fields present for all 10 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 10 record types tracked (before fix)** → **10 of 10 tracked (after fix)** | n/a | n/a | n/a | new `TestGoogleCloudDiffTrackedFields` (5 tests) | **FIXED** | Root-cause fix — see Summary #2 |
| Risk classification module exists and is wired | all | all tracked fields | n/a | every Change gets a Google-Cloud-specific classification, not the Cloudflare DNS fallback | **module did not exist (before fix)** → **10 classifiers + dispatch wired (after fix)** | n/a | n/a | n/a | new `TestGoogleCloudRiskClassifier` (26 tests, including a dispatch-level regression test, a dict-shaped mock-bug-prevention test, a proactive count-unknown-not-zero test, and dedicated list-diffing tests for firewall source ranges/allowed ports) | **FIXED** | Summary #1/#3 — the largest fix in this pass, and the one that makes the pre-existing `drift_risk_classification=True` capability-matrix claim actually true |

## Design notes

### Why the firewall/bucket/GKE combined-condition Findings are approximated conservatively, not at the worst-case severity

Three Findings in this rule set require a **combination** of fields a
single-field Change classifier cannot see simultaneously:
- `google_cloud_storage_public_access_prevention_disabled` (medium base,
  high when `uniform_bucket_level_access_enabled` is ALSO false)
- `google_cloud_firewall_rule_no_targets` (medium base, high when the
  same rule is ALSO a broad/admin public ingress)
- `google_cloud_gke_public_control_plane` (only fires at all when
  `master_authorized_networks_count` is ALSO 0/None)

Unlike the registry/frontend headline-severity convention (which
correctly stores the *Finding's own* worst case, since a Finding
evaluates the full record at once), the *Change* classifier only ever
sees one field's transition. For `public_access_prevention` and
`firewall_rule_no_targets`, this pass classifies at the **base-case**
severity (`medium`) rather than guessing the worse combination — the
same reasoning already established in Auth0's classification-QA pass for
`grant_client_credentials_enabled` (downgraded from an unconditional
`medium` to `low` because the risky combination is not the common case).
For `gke_public_control_plane` and Cloud Run's `ingress` field, this
pass similarly keeps the severity at the base/typical case rather than
the Finding's ceiling, to avoid over-alerting on the common, safe
configuration (an authorized-networks-restricted public GKE endpoint; an
all-ingress Cloud Run service still gated by IAM invoker policy).

The one place this pass deliberately does escalate more aggressively is
firewall port/range detection (categories I/J): a **newly-added** public
source range or admin/broad port entry is classified at `high`/`critical`
even without confirming the other half of the combination, because
adding a public range or an admin port is itself the primary, standalone
risk signal the task's categories I and J explicitly ask this pass to
detect — and, unlike the three cases above, there is no common/expected
configuration where adding `0.0.0.0/0` or an RDP/SSH port entry is safe
by default.

### Why `google_cloud_project` and `google_cloud_vpc_network` have zero Security Findings

`security_rules/google_cloud.py`'s own module docstring explicitly states:
*"google_cloud_project / google_cloud_vpc_network rules — no actionable
posture surface at M78B (project metadata is informational; VPC network
posture is captured via the firewall-rule surface)."* This is a
pre-existing, intentional design decision from M78B, not a gap this pass
found — both record types are still fully diff-tracked (all fields
generic-`low`), so changes to them are still visible in the Changes
timeline, just without an elevated-severity Finding.

## Tracked-fields vs. classifier-branch comparison

Verified programmatically: parsed `_GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE`
from `diff_service.py` and every `if fp == "..."` / `if fp in (...)`
branch from each of the 10 `_classify_*_change` functions in
`risk_rules/google_cloud.py`, then diffed the two sets per record type.

**Result**: zero tracked fields fall through accidentally, and zero
dead/unreachable classifier branches — every branch corresponds to a
real tracked field, and every tracked field is handled by either a
field-specific branch or an explicit generic group (including
`google_cloud_project`, `google_cloud_vpc_network`, and
`google_cloud_secret_manager_summary`, whose fields are all
intentionally generic-`low` but still explicitly named rather than
falling through a bare catch-all).

**Classifier branches referring to fields not emitted by the
connector/schema:** none found — every branch was cross-checked against
both `_GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE` and the connector's actual
normalizer return dicts (this schema has no `TypedDict`s to cross-check
against, unlike Auth0/Clerk).

**Classifier branches referring to stale field names:** none — this is a
newly-built module (this session), so there was no legacy field-name
drift to inherit.

**Fields with similar names that could be confused:** `public_access_prevention`
(bucket, a category string) vs. `public_ip_enabled` (Cloud SQL, a
boolean) vs. `public_invoker_allowed` (Cloud Run, a boolean) vs.
`public_endpoint_enabled` (GKE, a boolean) all encode "is this publicly
reachable" for four different surfaces — each branch names its own
record type and field explicitly in the emitted wording ("bucket
public-access posture" / "Cloud SQL network posture" / "Cloud Run ...
public invocation" / "GKE cluster public endpoint posture"), so the four
remain distinguishable in the reason text despite the shared "public"
theme.

## Verification: no `int(value or 0)`-style coercion remains

```
grep -n "int(.*or 0)\|_int_pair" backend/app/services/risk_rules/google_cloud.py
```
→ no matches. The one count-threshold field
(`user_managed_key_count`, plus `old_user_managed_key_count`/
`oldest_key_age_days`) uses `_int_or_none()` throughout.

## Verification: threshold-increase-while-already-over-threshold handled correctly (no Datadog-style bug)

`user_managed_key_count` uses direct comparison (`n_new > (n_old or 0)`)
against the fixed `_MANY_KEY_COUNT_THRESHOLD = 4` (the Finding's own
`>=5` cutoff), firing `medium` on **any** increase and `high` once the
count itself exceeds the threshold — confirmed via
`test_sa_key_count_reaches_five_is_high` (3→5, crosses to high),
`test_sa_key_count_increase_below_five_is_medium` (1→2, increase but
still under threshold), and `test_sa_key_count_decrease_is_low` (5→3,
decrease while still over threshold correctly rated as improvement, not
elevated). No PagerDuty-style or Datadog-style regression found — the
module was written defensively from the start.

## Mock-shape (`old_value`/`prev_value`/`previous_value`/`prior_value`) verification

```
grep -n "old_value\|previous_value\|prior_value\|prev_value" backend/app/services/risk_rules/google_cloud.py
```
→ all matches are `_get(change, "prev_value")` — production code was
written clean from the start, no `old_value`/`previous_value`/
`prior_value` usage found.

```
grep -rn "old_value\|previous_value\|prior_value" backend/tests/test_milestone78a_google_cloud_drift_provider_foundation.py
```
→ no matches at all (unlike Clerk/Auth0, no docstring comment in this
file references the bug class by name, but the dedicated
`test_classifier_reads_real_compute_diff_dict_shape_not_a_mock` test
still builds a plain dict shaped exactly like real `compute_diff` output,
guarding against the same bug class).

## Fixes made

1. **`backend/app/services/risk_rules/google_cloud.py`** (new file) — 10
   record-type classifiers (`_classify_project_change` through
   `_classify_secret_manager_summary_change`) plus the
   `classify_google_cloud_change` dispatcher. Built with `_int_or_none()`
   from the start, and with dedicated list-diffing helpers
   (`_added_entries`, `_expand_ports`, `_is_broad_port_entry`, mirrored
   from `security_rules/google_cloud.py`) to detect newly-added public
   source ranges and admin/broad firewall port entries — the first
   provider in this session's series to need list-valued field diffing
   rather than pure scalar comparisons.
2. **`backend/app/services/risk_service.py`** — added the `google_cloud_`
   prefix dispatch branch to `classify_change`, routing Google Cloud
   changes to the new module instead of the Cloudflare DNS fallback;
   updated the module docstring's dispatch list.
3. **`backend/app/services/diff_service.py`** — added
   `_GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE` (all 10 record types) and wired
   the `google_cloud_` prefix into `_tracked_fields_for`. Updated the
   function's docstring.
4. **`backend/app/services/security_rule_pack.py`** — fixed
   `google_cloud_firewall_rule_no_targets`'s headline severity from
   `"medium"` to `"high"`, matching every other dynamic-severity Google
   Cloud rule's worst-case-headline convention (Fix #0).
5. **`frontend/src/lib/securityRuleCatalog.ts`** — matching severity fix
   (`"medium"` → `"high"`) and updated `severityNote` wording for the
   same rule.
6. **`backend/tests/test_milestone78a_google_cloud_drift_provider_foundation.py`**
   — added `TestGoogleCloudDiffTrackedFields` (5 tests) and
   `TestGoogleCloudRiskClassifier` (26 tests, including a dispatch-level
   regression test, a dict-shaped mock-bug-prevention test, a proactive
   count-unknown-not-zero test, and dedicated tests for the firewall
   list-diffing logic across critical/high/low port-entry cases); added
   `app.services.risk_rules.google_cloud` to the forbidden-wording
   module scan parametrization.
7. **`backend/tests/reports/google_cloud_detection_matrix.md`** — this
   report.

No changes were made to `security_rules/google_cloud.py`'s rule logic,
`security_rule_registry.py`, `security_rule_confidence.py`, or
`security_coverage_service.py` — all were already correct.

## Not fixed in this pass (explicitly out of scope)

- **KMS key state/rotation/protection** (task category M) — no KMS key
  record type or endpoint exists; only a boolean presence flag on the
  bucket record. Not invented.
- **BigQuery dataset public access** (task category N) — no BigQuery API
  is called by this connector. Not invented.
- **Audit logging/sink posture as a drift-tracked record** (task category
  P) — audit-log *activity ingestion* exists as a separate M78D system,
  but no drift-tracked "logging sink" configuration record type exists.
  Not invented.
- **Per-service-account `disabled` status as an individual record** (task
  category D) — only the project-level aggregate
  `disabled_service_account_count` exists; no per-SA record type is
  modeled. Not invented.
- **Organization/folder/project policy metadata** — no Organization
  Policy API call exists in this connector. Not invented.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone78a_google_cloud_drift_provider_foundation.py -q
# 153 passed

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "google_cloud"
# 756 passed, 1 skipped, 16531 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*google_cloud* -q
# 750 passed, 1 skipped
```

Frontend catalog changed in this pass (one severity fix), so
`npx tsc --noEmit` was run from `frontend/` — no errors.
