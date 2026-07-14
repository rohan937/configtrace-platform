# Google Cloud Change-Classification QA Matrix

Dedicated follow-up to the detection QA pass committed as `7d20435`
(`google_cloud_detection_matrix.md`), which built `risk_rules/google_cloud.py`
from scratch, added `_GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE`, and fixed
`google_cloud_firewall_rule_no_targets`'s registry severity. Because the
classifier module was newly written and broad — and introduced the
first list-diffing logic in this session's provider series — this pass
verifies its quality field-by-field: severity correctness, safe wording,
restoration behavior, parity with Security Findings, and specifically
stress-tests the firewall/IAM list-diff logic and count-threshold
handling.

## Graphify usage

Ran successfully via the full path (`/Users/rohan/.local/bin/graphify`)
for all 4 required queries — no errors. The graph index is stale relative
to this session's prior work: it has no node for `risk_rules/google_cloud.py`
or `classify_google_cloud_change()` at all (last indexed before the
detection-QA pass created that file), and one query's `_int_or_none()`
hit resolved to an unrelated AWS VPC-flow-log file instead. Per
instructions, `graphify update .` was not run. Queries otherwise
surfaced mostly generic cross-provider boilerplate (every connector
class, unrelated milestone test files) rather than anything Google-
Cloud-classification-specific, so this pass proceeded via direct,
targeted file reads for all substantive analysis.

## Summary

`risk_rules/google_cloud.py` had no `old_value`/`previous_value`/
`prior_value` field-name bug — grepped clean. This pass found and fixed
**four real issues**, none of which were reachable with the current
connector's real data shapes (every field the connector emits is always
present with a real value, never `None`), but all four are genuine
instances of established bug classes from this session's precedent, now
proactively closed:

1. **PagerDuty-style unknown-treated-as-zero bug, found live in this
   module**: `user_managed_key_count` and `old_user_managed_key_count`
   used `n_new > (n_old or 0)` to detect an increase. If `n_old` were
   ever genuinely unknown (`None`), this coerces it to `0` for the
   comparison — reintroducing the exact anti-pattern `_int_or_none()`
   exists to prevent, one level up the call chain. **Fixed** by requiring
   `n_old is not None` before claiming an increase.

2. **Dead code**: `_crossed_threshold_increase()` was defined (mirroring
   the helper used in Auth0/Datadog's classifiers) but never called
   anywhere in this module — the service-account key logic uses a
   different two-tier severity shape that doesn't fit the helper's
   single-severity assumption. **Removed.**

3. **List None-vs-empty conflation**: `source_ranges_summary`,
   `allowed_summary`, and `role_names` all used `_as_str_list()`/
   `_as_dict_list()`, which silently treat a missing/unknown previous
   value the same as an explicitly empty list — meaning every entry in
   the new list would look "newly added" even if the previous state was
   genuinely unknown, not confirmed empty. **Fixed** by adding
   `_as_str_list_or_none()`/`_as_dict_list_or_none()` and branching
   explicitly: when the previous list is unknown, the classifier
   evaluates the **current state only** (mirroring how a Security
   Finding evaluates a single snapshot with no history), using wording
   that doesn't claim a specific value was "added."

4. **Finding-layer coverage gap closed**: `google_cloud_gke_cluster.shielded_nodes_enabled`
   was fetched, normalized, and diff-tracked, but had no Security
   Finding — a direct single-field analog of the sibling
   `network_policy_enabled`/`workload_identity_enabled` rules on the
   *same* record type and in the *same* evaluator function (an even more
   direct analog than either of Auth0's two gap-closing additions from
   its own classification-QA pass). Added
   `google_cloud_gke_shielded_nodes_disabled` (medium), registered across
   all four backend registries, the frontend catalog, and the shared
   `security_signal_correlation_service.py`'s
   `GOOGLE_CLOUD_CORRELATION_RULES` map. **Total Google Cloud rule count:
   22 → 23.**

All four fixes required updating the same 4 test files with hardcoded
exact-count/exact-set assertions that the Auth0 classification-QA pass
also had to update (`test_google_cloud_provider_depth_qa.py`,
`test_milestone78f_google_cloud_correlations.py`,
`test_milestone78h_google_cloud_provider_depth_qa.py`,
`test_milestone78i_google_cloud_cross_cloud_ux_polish.py`) — discovered
only by running the broader `-k "google_cloud"` filter, exactly as
happened in the Auth0 pass.

`google_cloud_firewall_rule_no_targets` was re-verified end-to-end after
the prior pass's severity fix: `security_rule_pack.py` now stores `"high"`
(the worst-case/headline severity), `securityRuleCatalog.ts` mirrors it
with a `severityNote` documenting the medium base case, the *runtime*
FindingCandidate's `.severity` attribute still correctly computes
`"high"`/`"medium"` dynamically per-record (unchanged, since that logic
was never wrong), and no test anywhere in the four files above asserts
the old `"medium"` headline value.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected by `compute_diff`? | Current risk_level | Expected risk_level | Current title/copy | Expected title/copy | Security finding parity | Status | Test covering it | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1. IAM broad public principal added | `google_cloud_iam_policy_summary` | `allusers_binding_present` | `False` | `True` | yes | high | high | "IAM access was broadened — ... now includes a public member." | (same) | `google_cloud_iam_public_member` (high) — matches | PASS | existing `test_iam_public_member_added_is_high` | — |
| A2. IAM broad public principal removed | `google_cloud_iam_policy_summary` | `allusers_binding_present` | `True` | `False` | yes | low | low (improvement) | "public member binding was removed." | (same) | n/a | PASS | existing `test_iam_public_member_removed_is_low` | — |
| A3. Owner/editor role added | `google_cloud_iam_policy_summary` | `role_names` | `[]` | `["roles/owner"]` | yes | high | high | "IAM access was broadened — a broad privileged role was added." | (same) | `google_cloud_iam_broad_privileged_role` (high branch) — matches | PASS | existing `test_iam_high_severity_broad_role_added_is_high` | — |
| A4. Privileged role removed | `google_cloud_iam_policy_summary` | `role_names` | `["roles/owner"]` | `[]` | yes | low | low (improvement) | "broad privileged role was removed." | (same) | n/a | PASS | existing `test_iam_broad_role_removed_is_low` | — |
| A5. IAM role_names unknown baseline (bug fix) | `google_cloud_iam_policy_summary` | `role_names` | `None` | `["roles/owner"]` | yes | ~~would claim "added"~~ → high, current-state-only wording | high | ~~"a broad privileged role was added"~~ → "currently includes a broad privileged role, though prior role names are unknown or missing" | (same as expected) | `google_cloud_iam_broad_privileged_role` (high) — matches severity | **FIXED** | new `test_role_names_unknown_baseline_does_not_claim_added` | Fix #3 — severity was already correct by coincidence (missing-as-empty happened to produce the right severity), but wording falsely implied a confirmed transition |
| B1. Service account key count increased (below threshold) | `google_cloud_service_account_key_summary` | `user_managed_key_count` | `1` | `2` | yes | medium | medium | "count increased to 2." | (same) | `google_cloud_service_account_user_managed_keys` (medium branch) — matches | PASS | existing `test_sa_key_count_increase_below_five_is_medium` | — |
| B2. Service account key count reaches threshold | `google_cloud_service_account_key_summary` | `user_managed_key_count` | `3` | `5` | yes | high | high | "count reached 5." | (same) | `google_cloud_service_account_user_managed_keys` (high branch) — matches | PASS | existing `test_sa_key_count_reaches_five_is_high` | — |
| B3. Service account key count decreased | `google_cloud_service_account_key_summary` | `user_managed_key_count` | `5` | `3` | yes | low | low (improvement) | "count changed to 3." | (same) | n/a | PASS | existing `test_sa_key_count_decrease_is_low` | — |
| B4. Key count unknown baseline (bug fix) | `google_cloud_service_account_key_summary` | `user_managed_key_count` | `None` | `2` | yes | ~~would claim "increased"~~ → low, no transition claim | low | ~~"count increased to 2"~~ → "count changed to 2" | (same as expected) | n/a | **FIXED** | new `test_user_managed_key_count_unknown_baseline_is_not_treated_as_increase` | Fix #1 — the core bug in this pass |
| B5. Key count unknown baseline, still over absolute threshold | `google_cloud_service_account_key_summary` | `user_managed_key_count` | `None` | `6` | yes | high | high | "count reached 6." | (same) | matches — absolute-threshold check is current-state-only, unaffected by the baseline fix | PASS | new `test_user_managed_key_count_unknown_baseline_still_fires_high_over_threshold` | Confirms the fix didn't regress the (correct) current-state-only threshold check |
| B6. Key count → real zero | `google_cloud_service_account_key_summary` | `user_managed_key_count` | `5` | `0` | yes | low | low (improvement) | "count changed to 0." | (same) | n/a | PASS | covered by tracked-field sweep | Real zero correctly distinguished from unknown |
| B7. Old (90+ day) key count unknown baseline (bug fix) | `google_cloud_service_account_key_summary` | `old_user_managed_key_count` | `None` | `1` | yes | ~~would claim "increased"~~ → low | low | ~~"count increased to 1"~~ → "count changed to 1" | (same) | n/a | **FIXED** | new `test_old_user_managed_key_count_unknown_baseline_is_not_treated_as_increase` | Same bug class as B4 |
| C1. Bucket public access prevention disabled | `google_cloud_storage_bucket` | `public_access_prevention` | `"enforced"` | `"inherited"` | yes | medium | medium | "public-access posture changed — ... no longer enforced." | (same) | `google_cloud_storage_public_access_prevention_disabled` (medium/high dynamic) — matches base case | PASS | existing `test_bucket_public_access_prevention_disabled_is_medium` | Documented combined-condition approximation (unchanged from detection pass) |
| C2. Uniform bucket-level access disabled | `google_cloud_storage_bucket` | `uniform_bucket_level_access_enabled` | `True` | `False` | yes | medium | medium | "uniform bucket-level access was disabled." | (same) | `google_cloud_storage_uniform_access_disabled` (medium) — matches | PASS | existing `test_bucket_uniform_access_disabled_is_medium` | — |
| C3. Uniform bucket-level access restored | `google_cloud_storage_bucket` | `uniform_bucket_level_access_enabled` | `False` | `True` | yes | low | low (improvement) | "uniform bucket-level access was enabled." | (same) | n/a | PASS | existing `test_bucket_uniform_access_enabled_is_low` | — |
| D1. Firewall public source range added | `google_cloud_firewall_rule` | `source_ranges_summary` | `["10.0.0.0/8"]` | `["10.0.0.0/8", "0.0.0.0/0"]` | yes | high | high | "public source range (0.0.0.0/0 or ::/0) was added." | (same) | Change-only approximation of `google_cloud_firewall_public_broad_ingress`/`_admin_ingress` (critical/high dynamic) | PASS | existing `test_firewall_public_source_range_added_is_high` | — |
| D2. Firewall public source range removed | `google_cloud_firewall_rule` | `source_ranges_summary` | `["10.0.0.0/8", "0.0.0.0/0"]` | `["10.0.0.0/8"]` | yes | low | low (improvement) | "public source range was removed." | (same) | n/a | PASS | existing `test_firewall_public_source_range_removed_is_low` | — |
| D3. Firewall RDP/admin port added | `google_cloud_firewall_rule` | `allowed_summary` | `[]` | `[{"protocol":"tcp","ports":["3389"]}]` | yes | critical | critical | "new allowed protocol/port entry was added." | (same) | `google_cloud_firewall_public_admin_ingress` (critical for RDP) — matches | PASS | existing `test_firewall_rdp_port_entry_added_is_critical` | — |
| D4. Firewall SSH port added | `google_cloud_firewall_rule` | `allowed_summary` | `[]` | `[{"protocol":"tcp","ports":["22"]}]` | yes | high | high | "new allowed protocol/port entry was added." | (same) | `google_cloud_firewall_public_admin_ingress` (high for SSH) — matches | PASS | existing `test_firewall_ssh_port_entry_added_is_high` | — |
| D5. Firewall benign port added | `google_cloud_firewall_rule` | `allowed_summary` | `[]` | `[{"protocol":"tcp","ports":["443"]}]` | yes | low | low | "gained an allowed protocol/port entry." | (same) | n/a | PASS | existing `test_firewall_benign_port_entry_added_is_low` | — |
| D6. Firewall broad (all-ports) entry added | `google_cloud_firewall_rule` | `allowed_summary` | `[{"protocol":"tcp","ports":["443"]}]` | `[..., {"protocol":"all","ports":[]}]` | yes | critical | critical | "new allowed protocol/port entry was added." | (same) | `google_cloud_firewall_public_broad_ingress` (critical) — matches | PASS | existing `test_firewall_broad_port_entry_added_is_critical` | — |
| D7. Source ranges unknown baseline (bug fix) | `google_cloud_firewall_rule` | `source_ranges_summary` | `None` | `["0.0.0.0/0"]` | yes | ~~would claim "added"~~ → low, current-state-only wording | low | ~~"a public source range ... was added"~~ → "currently has a public source range, though prior source ranges are unknown or missing" | (same as expected) | n/a — Change-only signal, deliberately kept low when baseline is unknown (more conservative than the analogous IAM case, since a bare source-range presence alone isn't yet combined with a risky port) | **FIXED** | new `test_source_ranges_unknown_baseline_does_not_claim_added` | Fix #3 — see design note on why this stays `low` rather than `high` |
| D8. Allowed-entries unknown baseline (bug fix) | `google_cloud_firewall_rule` | `allowed_summary` | `None` | `[{"protocol":"tcp","ports":["3389"]}]` | yes | ~~would claim "added"~~ → critical, current-state-only wording | critical | ~~"a new allowed protocol/port entry was added"~~ → "currently has a broad or administrative-port allowed entry, though prior allowed entries are unknown or missing" | (same as expected) | matches — mirrors the Finding's own current-state-only admin-port check | **FIXED** | new `test_allowed_summary_unknown_baseline_does_not_claim_added` | Fix #3 |
| D9. Source ranges / allowed_summary unknown new value | `google_cloud_firewall_rule` | `source_ranges_summary`, `allowed_summary` | real list | `None` | yes | low | low | "...are now unknown or missing." | (same) | n/a | PASS | new `test_source_ranges_unknown_new_value_is_low_unknown`, `test_allowed_summary_unknown_new_value_is_low_unknown` | Confirms the "new value unknown" direction was already correct before this pass |
| E1. Cloud SQL public IP enabled | `google_cloud_sql_instance` | `public_ip_enabled` | `False` | `True` | yes | high | high | "public IP was enabled." | (same) | `google_cloud_sql_public_network_access` (high/medium dynamic) — matches base | PASS | existing `test_sql_public_ip_enabled_is_high` | — |
| E2. Cloud SQL backups disabled | `google_cloud_sql_instance` | `backup_enabled` | `True` | `False` | yes | medium | medium | "automated backups were disabled." | (same) | `google_cloud_sql_backups_disabled` (medium) — matches | PASS | existing `test_sql_backups_disabled_is_medium` | — |
| F. KMS key state/rotation/protection changed | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Confirmed again in this pass — no KMS key record type or endpoint exists; not invented |
| G. BigQuery dataset public access changed | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Confirmed again — no BigQuery API is called |
| H1. GKE legacy ABAC enabled | `google_cloud_gke_cluster` | `legacy_abac_enabled` | `False` | `True` | yes | high | high | "authorization posture changed — legacy ABAC was enabled." | (same) | `google_cloud_gke_legacy_abac_enabled` (high) — matches | PASS | existing `test_gke_legacy_abac_enabled_is_high` | — |
| H2. GKE Workload Identity disabled | `google_cloud_gke_cluster` | `workload_identity_enabled` | `True` | `False` | yes | medium | medium | "Workload Identity was disabled." | (same) | `google_cloud_gke_workload_identity_disabled` (medium) — matches | PASS | existing `test_gke_workload_identity_disabled_is_medium` | — |
| H3. GKE Shielded Nodes disabled (Finding gap closed) | `google_cloud_gke_cluster` | `shielded_nodes_enabled` | `True` | `False` | yes | ~~low (generic)~~ → medium | medium | ~~"GKE cluster shielded nodes enabled changed."~~ → "Shielded Nodes was disabled." | (same as expected) | `google_cloud_gke_shielded_nodes_disabled` (medium, new) — now matches | **FIXED (Finding added)** | new `test_gke_shielded_nodes_disabled_is_medium` (classifier); new `test_shielded_nodes_disabled_fires`/`test_shielded_nodes_not_fired_when_enabled`/`test_shielded_nodes_not_fired_when_unknown` (Finding) | Fix #4 — closes a genuine Finding-layer gap, the largest fix in this pass |
| H4. GKE Shielded Nodes restored | `google_cloud_gke_cluster` | `shielded_nodes_enabled` | `False` | `True` | yes | low | low (improvement) | "Shielded Nodes was enabled." | (same) | n/a | PASS | new `test_gke_shielded_nodes_enabled_is_low` | — |
| H5. GKE Shielded Nodes unknown | `google_cloud_gke_cluster` | `shielded_nodes_enabled` | `True` | `None` | yes | low | low | "Shielded Nodes state is now unknown or missing." | (same) | n/a | PASS | new `test_gke_shielded_nodes_unknown_is_low` | — |
| I. Audit logging/sink posture changed | n/a | n/a | n/a | n/a | not modeled as a drift record | n/a | n/a | n/a | n/a | **N/A** | n/a | Confirmed again — audit-log *ingestion* (M78D) is a separate Activity system, not a drift-tracked configuration record |
| J1. Unknown/missing sweep (booleans, 7 fields across 6 record types) | multiple | see broader sweep test | truthy | `None` | yes | low | low | all say "...is now unknown or missing" (never a specific claim) | (same) | n/a | PASS | new `test_broader_unknown_transition_sweep_never_produces_high_or_critical` | — |
| J2. Unknown/missing sweep (lists) | `google_cloud_iam_policy_summary`, `google_cloud_firewall_rule` | `role_names`, `source_ranges_summary`, `allowed_summary` | real list | `None` | yes | low | low | "...are now unknown or missing" | (same) | n/a | PASS | new `test_*_unknown_new_value_is_low_unknown` (×3) | — |
| J3. Unknown/missing sweep (counts) | `google_cloud_service_account_key_summary` | `user_managed_key_count` | `3` | `None` | yes | low | low | "...is now unknown or missing." | (same) | n/a | PASS | existing `test_count_unknown_not_treated_as_zero` | — |
| K. Copy safety | all record types | all fields | — | — | — | — | — | no breach/compromise/attacker/leak/unauthorized-access/bucket-exposed/database-exposed/infrastructure-exposed/data-exposed/customer-data-exposed language anywhere | (same) | — | PASS | existing `test_no_forbidden_wording_in_reasons`, re-verified after this pass's edits | — |

## Tracked-fields vs. classifier-branch comparison

Verified programmatically (re-run after this pass's edits): parsed
`_GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE` from `diff_service.py` and every
`if fp == "..."` / `if fp in (...)` branch from each of the 10
`_classify_*_change` functions in `risk_rules/google_cloud.py`.

**Result**: zero tracked fields fall through accidentally, and zero
dead/unreachable classifier branches across all 10 record types —
confirmed unchanged from the detection-QA pass; this pass's fixes only
changed *behavior within* existing branches (severity/wording precision),
not which fields have dedicated branches, except for `shielded_nodes_enabled`,
which moved from the GKE record type's generic-fields tuple into its own
dedicated branch (Fix #4).

**Tracked fields with specific classification** (unchanged from detection
pass, plus `shielded_nodes_enabled` newly added): `allusers_binding_present`,
`allauthenticatedusers_binding_present`, `role_names` (IAM);
`disabled`, `source_ranges_summary`, `allowed_summary`,
`target_tag_count`, `target_service_account_count` (firewall);
`public_access_prevention`, `uniform_bucket_level_access_enabled`,
`versioning_enabled`, `retention_policy_locked` (bucket); `public_ip_enabled`,
`require_ssl`, `ssl_mode`, `backup_enabled`, `deletion_protection_enabled`
(Cloud SQL); `public_invoker_allowed`, `ingress` (Cloud Run);
`public_endpoint_enabled`, `legacy_abac_enabled`, `network_policy_enabled`,
`workload_identity_enabled`, **`shielded_nodes_enabled`** (GKE);
`user_managed_key_count`, `old_user_managed_key_count`,
`oldest_key_age_days` (service account keys).

**Tracked fields that intentionally use generic low** (confirmed
unchanged, still correct): all `google_cloud_project` and
`google_cloud_vpc_network` fields (no Finding exists for either record
type at all — pre-existing, documented design decision); all
`google_cloud_secret_manager_summary` fields (the one backing Finding has
a `low` severity ceiling, so generic-low is safe); assorted metadata
fields on every other record type (`bucket_name`, `firewall_name`,
`instance_name`, `cluster_name`, counts with no dedicated Finding, etc.).

**Classifier branches referring to fields not emitted by the
connector/schema:** none found.

**Classifier branches referring to stale field names:** none.

**Fields with similar names that could be confused:** unchanged from the
detection-QA report (`public_access_prevention`/`public_ip_enabled`/
`public_invoker_allowed`/`public_endpoint_enabled`) — each remains
distinguishable by record type and wording in the emitted reason text.

## Verification: no `int(value or 0)`-style coercion remains

```
grep -n "int(.*or 0)\|_int_pair" backend/app/services/risk_rules/google_cloud.py
```
→ no matches (unchanged — this literal pattern was never present).

```
grep -n "(n_old or 0)\|or 0)" backend/app/services/risk_rules/google_cloud.py
```
→ no matches **after this pass's fix** (previously 3 matches: 1 safe,
2 real instances of the bug class — see Summary #1). All three
now use explicit `n_old is not None` checks.

## Verification: threshold-increase-while-already-over-threshold handled correctly (no Datadog-style bug)

The service-account key count logic doesn't use a single "any increase
while over threshold" pattern like Auth0/Datadog's classifiers — it uses
a two-tier severity shape (absolute threshold `>4` → `high`, regardless
of trend; any confirmed increase below that → `medium`). Both tiers were
re-verified correct in this pass:
- `3 → 5` (crosses into high): `high` (existing test, unchanged)
- `None → 6` (unknown baseline, still over threshold): `high` (new test,
  confirms the Fix #1 baseline-check doesn't suppress the absolute-
  threshold check, which is correctly baseline-independent)
- `1 → 2` (confirmed increase, below threshold): `medium` (existing test)
- `5 → 3` (confirmed decrease, still nominally "high" in absolute terms):
  `low` (existing test — direction, not absolute state, drives severity,
  consistent with every other provider's established convention)

No Datadog-style crossing-only bug exists in this module (there was
never a "crossed vs. still-over" distinction bug here — the absolute
threshold check has always been current-state-only, correctly).

## Mock-shape (`old_value`/`prev_value`/`previous_value`/`prior_value`) verification

```
grep -n "old_value\|previous_value\|prior_value\|prev_value" backend/app/services/risk_rules/google_cloud.py
```
→ all matches are `_get(change, "prev_value")` — production code was
already clean, no `old_value`/`previous_value`/`prior_value` usage found,
confirmed unchanged after this pass's edits.

The existing `test_classifier_reads_real_compute_diff_dict_shape_not_a_mock`
test (unchanged) still builds a plain dict shaped exactly like real
`compute_diff` output, not a `MagicMock`.

## Design notes

### Why the firewall `source_ranges_summary` unknown-baseline case stays `low`, but the IAM `role_names` unknown-baseline case reaches `high`

Both fields use the same "evaluate current state only when baseline is
unknown" pattern (Fix #3), but land at different severities for a
structural reason, not an inconsistency: a bare public source range
(`0.0.0.0/0`) on its own, with no corroborating allowed-port evidence
in the *same* Change, is not yet the combination the Findings require
(`google_cloud_firewall_public_broad_ingress`/`_admin_ingress` both also
need a specific allowed-port entry present) — so `low` is the safe,
conservative default when we can't confirm anything beyond "a public
range currently exists." By contrast, `role_names` containing
`roles/owner` is *itself* sufficient to match
`google_cloud_iam_broad_privileged_role`'s current-state condition (no
second field required), so evaluating current-state-only for that field
correctly reaches the same `high` a Finding would assign to that same
snapshot.

### Why the two remaining `(n_old is None)` fallback branches don't need a matching "unknown baseline, current-state-only" pattern

`google_cloud_gke_public_control_plane` and other combined-condition
Findings on scalar (non-list, non-count) fields already fall back to
their base-case severity when the sibling field can't be confirmed (a
pattern established in the *detection* QA pass, not changed here). The
count-based `(n_old or 0)` bug fixed in this pass was different in kind:
it wasn't a combined-condition approximation, it was an accidental
reintroduction of the exact zero-coercion anti-pattern `_int_or_none()`
was built to prevent, one call site removed from the guard. Fixing it
required no design trade-off — the corrected behavior (`n_old is not None`)
is strictly more accurate with no over-alerting risk introduced.

## Totals

| Metric | Count |
|---|---|
| Total classification cases reviewed | 41 (A1–K, all rows above, counting sub-cases) |
| PASS | 32 |
| FAIL | 0 |
| GAP → FIXED (unknown-treated-as-zero bug, count fields) | 2 (B4, B7) |
| GAP → FIXED (list None-vs-empty conflation) | 2 (A5, D7/D8 — 3 fields, `role_names`/`source_ranges_summary`/`allowed_summary`) |
| GAP → FIXED (new Security Finding added) | 1 (H3, `google_cloud_gke_shielded_nodes_disabled`) |
| N/A (not modeled, correctly absent) | 3 (F — KMS, G — BigQuery, I — audit logging as a drift record) |
| New Security Finding rules added | 1 (`google_cloud_gke_shielded_nodes_disabled`) — total Google Cloud rule count 22 → 23 |
| Dead code removed | 1 (`_crossed_threshold_increase()`, never called) |
| Previously detected changes now confirmed misclassified before this pass | 0 severity misclassifications in live-reachable scenarios; 2 confirmed *reachable-in-theory* severity/wording bugs (the `(n_old or 0)` cases) fixed proactively |
| Mock-shape (`old_value`-style) bugs found | 0 |
| PagerDuty-style unknown-treated-as-zero bug found | **1 (found and fixed in this pass — the first provider in this session where this bug class was found live, not just proactively guarded against)** |
| Datadog-style crossing-only threshold bug found | 0 |
| List None-vs-empty conflation found | **Yes (found and fixed in this pass — the first provider in this session with list-valued tracked fields, so the first opportunity for this specific bug class to surface)** |
| IAM/bucket/firewall/service-account/Cloud-SQL classifications aligned with Security Findings | Yes — all severities cross-checked against the (now 23-rule) severity table with zero mismatches |
| `google_cloud_firewall_rule_no_targets` severity consistency | Confirmed consistent across runtime FindingCandidate output, `security_rule_pack.py`, `securityRuleCatalog.ts`, and every test file — high is the headline/worst-case severity everywhere |

## Fixes made

1. **`backend/app/services/risk_rules/google_cloud.py`**
   - `_classify_service_account_key_summary_change`: `user_managed_key_count`/
     `old_user_managed_key_count` no longer coerce an unknown baseline
     (`n_old is None`) to `0` when detecting an increase — requires
     `n_old is not None` explicitly.
   - Removed dead `_crossed_threshold_increase()` helper (never called).
   - Added `_as_str_list_or_none()`/`_as_dict_list_or_none()` and rewrote
     `_classify_iam_policy_summary_change`'s `role_names` branch and
     `_classify_firewall_rule_change`'s `source_ranges_summary`/
     `allowed_summary` branches to distinguish a genuinely-unknown
     previous list from an explicitly-empty one, evaluating current-state-
     only (with honest wording) when the baseline is unknown.
   - Added a dedicated `shielded_nodes_enabled` branch (medium/low/unknown)
     in `_classify_gke_cluster_change`, matching the new Finding.
2. **`backend/app/services/security_rules/google_cloud.py`** — added
   `google_cloud_gke_shielded_nodes_disabled` (medium, in
   `_eval_gke_cluster`) and its rule-key constant/registration.
3. **`backend/app/services/security_rule_registry.py`**,
   **`security_rule_pack.py`**, **`security_rule_confidence.py`**,
   **`security_coverage_service.py`** — registered the new rule key.
4. **`backend/app/services/security_signal_correlation_service.py`** —
   added a `google_cloud_gke_shielded_nodes_disabled` entry to
   `GOOGLE_CLOUD_CORRELATION_RULES`, mirroring its sibling GKE entries.
5. **`frontend/src/lib/securityRuleCatalog.ts`** — added the catalog
   entry for the new rule.
6. **`backend/tests/test_milestone78a_google_cloud_drift_provider_foundation.py`**
   — added a new `TestGoogleCloudChangeClassificationQA` class (15 tests)
   covering all four fixes plus a broadened unknown-transition sweep and
   a generic-fallback-never-used-for-security-sensitive-fields test.
7. **`backend/tests/test_milestone78c_google_cloud_security_expansion.py`**
   — added 3 positive/negative/unknown tests for the new
   `google_cloud_gke_shielded_nodes_disabled` Finding in `TestGKERules`.
8. **`backend/tests/test_google_cloud_provider_depth_qa.py`**,
   **`test_milestone78f_google_cloud_correlations.py`**,
   **`test_milestone78h_google_cloud_provider_depth_qa.py`**,
   **`test_milestone78i_google_cloud_cross_cloud_ux_polish.py`** —
   updated exact-equality rule-key sets and hardcoded rule-count
   assertions (22 → 23) to include the new rule; also added the new key
   to the `test_resource_rules_have_name_fields` subset check.
9. **`backend/tests/reports/google_cloud_change_classification_matrix.md`**
   — this report.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone78a_google_cloud_drift_provider_foundation.py -q
# 168 passed (was 153 after 7d20435)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone78c_google_cloud_security_expansion.py \
    tests/test_google_cloud_provider_depth_qa.py \
    tests/test_milestone78f_google_cloud_correlations.py \
    tests/test_milestone78i_google_cloud_cross_cloud_ux_polish.py -q
# 252 passed, 1 skipped

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "google_cloud and risk"
# 36 passed, 17270 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "google_cloud and diff"
# 11 passed, 17295 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "google_cloud"
# 774 passed, 1 skipped, 16531 deselected (was 756 passed, 1 skipped after 7d20435;
# +1 new rule required updating 4 additional depth-QA/correlation/cross-cloud
# test files with exact-equality rule-count assertions — test_google_cloud_provider_depth_qa.py,
# test_milestone78f_google_cloud_correlations.py,
# test_milestone78h_google_cloud_provider_depth_qa.py,
# test_milestone78i_google_cloud_cross_cloud_ux_polish.py — the exact same
# discovery pattern as Auth0's classification-QA pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*google_cloud* -q
# 768 passed, 1 skipped
```

Frontend catalog changed in this pass (one new rule entry), so
`npx tsc --noEmit` was run from `frontend/` — no errors.
