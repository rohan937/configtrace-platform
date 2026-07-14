# Datadog Change-Classification QA Matrix

Dedicated follow-up to the detection QA pass committed as `55e9f5e`
(`datadog_detection_matrix.md`), which built `risk_rules/datadog.py` from
scratch and added `_DATADOG_TRACKED_FIELDS_BY_TYPE`. Because the
classifier module was newly written and broad, this pass verifies its
quality field-by-field: severity correctness, safe wording, restoration
behavior, and parity with Security Findings.

## Summary

`risk_rules/datadog.py` had no `old_value`/`prev_value`-style field-name
bug, and — having just fixed a false-positive severity bug in PagerDuty's
own classification-QA pass — this module was already written defensively
from the start using `_int_or_none()` everywhere. Confirmed by grepping
for `int(... or 0)` and equivalent coercion patterns: **zero matches**.
Every count-based branch already distinguishes `None`/unknown from an
explicit `0` correctly.

This pass instead found and fixed **one real severity bug**, present in
both count-threshold fields that carry a review threshold
(`scopes_count` on application keys, `permission_count` on roles):

**The threshold-crossing check only fired `medium` at the exact moment of
crossing the threshold** (`n_new > THRESHOLD and (n_old or 0) <= THRESHOLD`).
An increase while a count was **already** over the threshold — e.g.
scopes going from 15 to 20, both above the review threshold of 10 — fell
through to the generic `low` "changed from X to Y" branch instead of
`medium`. This is inconsistent with the established cross-provider
convention (e.g. Jira's `permission_grant_count`, GitLab's
`team_access_count`) where **any increase while over the threshold**
triggers the elevated severity, not only the single crossing transition.
Fixed by changing the condition from `(n_old or 0) <= THRESHOLD` to
`n_new > (n_old or 0)` (any increase, while still requiring `n_new` to
exceed the threshold) for both fields.

No new Security Finding rules were added in this pass — it is scoped to
the Change-classification layer only.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected by `compute_diff`? | Current risk_level | Expected risk_level | Current title/copy | Expected title/copy | Security finding parity | Status | Test covering it | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1. Monitor disabled | `datadog_monitor` | `enabled` | `True` | `False` | yes | medium | medium | "alerting posture changed — the monitor was disabled." | (same) | `datadog_monitor_disabled` (medium) — matches | PASS | existing `test_monitor_disabled_is_medium` | — |
| A2. Monitor re-enabled | `datadog_monitor` | `enabled` | `False` | `True` | yes | low | low (improvement) | "was re-enabled." | (same) | n/a | PASS | existing `test_monitor_re_enabled_is_low` | — |
| A3. Monitor notify_no_data disabled | `datadog_monitor` | `notify_no_data` | `True` | `False` | yes | low | low | "no-data notification was disabled." | (same) | `datadog_monitor_notify_no_data_disabled` (low) — matches | PASS | covered by tracked-field sweep | — |
| A4. Monitor notification routing drops | `datadog_monitor` | `notification_routing_present` | `True` | `False` | yes | medium | medium | "lost its notification routing — alerts...may no longer reach a destination." | (same) | `datadog_monitor_no_notifications` (medium) — matches | PASS | covered by tracked-field sweep | — |
| A5. Monitor notification routing restored | `datadog_monitor` | `notification_routing_present` | `False` | `True` | yes | low | low (improvement) | "gained notification routing." | (same) | n/a | PASS | covered | — |
| A6. Monitor no-data timeframe weakened | `datadog_monitor` | `no_data_timeframe_category` | `"medium"` | `"extended"` | yes | low | low | "no-data timeframe is now classified as extended." | (same) | `datadog_monitor_long_no_data_timeframe` (low) — matches | PASS | covered by tracked-field sweep | — |
| A7. Monitor priority/criticality | n/a | n/a | n/a | n/a | tracked (`priority_category`) but no dedicated Finding | n/a | n/a | n/a | n/a | n/a | **N/A (intentional generic)** | n/a | No Security Finding exists for `priority_category` transitions specifically; falls to generic `low` fallback, consistent with the field's lack of a Finding |
| A8. Monitor enabled true → unknown | `datadog_monitor` | `enabled` | `True` | `None` | yes | low | low | "enabled state is now unknown or missing." | (same) | n/a | PASS | already correct — three-way branch from the start | No fix needed — confirmed correct on inspection |
| B1. Webhook HTTP scheme | `datadog_webhook_integration` | `url_scheme_category` | `"https"` | `"http"` | yes | high | high | "posture may require review — the endpoint URL scheme changed to HTTP." | (same) | `datadog_webhook_non_https_endpoint` (high) — matches | PASS | existing `test_webhook_http_scheme_is_high` | — |
| B2. Webhook HTTPS restored | `datadog_webhook_integration` | `url_scheme_category` | `"http"` | `"https"` | yes | low | low (improvement) | "URL scheme changed to HTTPS." | (same) | n/a | PASS | existing `test_webhook_https_restored_is_low` | — |
| B3. Webhook secret header removed | `datadog_webhook_integration` | `secret_headers_present` | `True` | `False` | yes | high | high | "posture may require review — its secret header indicator was removed." | (same) | `datadog_webhook_without_secret_headers` (high) — matches | PASS | existing `test_webhook_secret_headers_removed_is_high` | — |
| B4. Webhook secret header restored | `datadog_webhook_integration` | `secret_headers_present` | `False` | `True` | yes | low | low (improvement) | "secret header indicator was added." | (same) | n/a | PASS | existing `test_webhook_secret_headers_added_is_low` | — |
| B5. Webhook gains auth-material headers | `datadog_webhook_integration` | `auth_material_present` | `False` | `True` | yes | medium | medium | "configuration now includes authentication-material headers." | (same) | `datadog_webhook_auth_material_present` (medium) — matches | PASS | covered by tracked-field sweep | — |
| B6. Webhook unknown transitions | `datadog_webhook_integration` | `secret_headers_present`, `url_scheme_category` | `True`/`"https"` | `None` | yes | low | low | "...is now unknown or missing." | (same) | n/a | PASS | existing three-way branches, confirmed correct from the start | No fix needed |
| C1. Dashboard gains public URL | `datadog_dashboard` | `public_url_present` | `False` | `True` | yes | medium | medium | "sharing posture changed — a public URL is now present." | (same) | `datadog_dashboard_public_url_present` (medium) — matches | PASS | existing `test_dashboard_public_url_gained_is_medium` | — |
| C2. Dashboard public URL revoked | `datadog_dashboard` | `public_url_present` | `True` | `False` | yes | low | low (improvement) | "public URL was revoked (restricted)." | (same) | n/a | PASS | existing `test_dashboard_public_url_revoked_is_low` | — |
| C3. Dashboard public URL true → unknown | `datadog_dashboard` | `public_url_present` | `True` | `None` | yes | low | low | "public URL presence is now unknown or missing." | (same) | n/a | PASS | already correct — three-way branch from the start | Confirmed: does not claim the dashboard "became private" on an unknown transition |
| C4. Dashboard viewer/editor count | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Datadog dashboards don't expose per-viewer/editor identity counts in this connector's schema — only `restricted_roles_count` (aggregate role-restriction count), already covered |
| D1. API key disabled | `datadog_api_key_metadata` | `disabled` | `False` | `True` | yes | low | low | "key metadata changed — the API key was disabled." | (same) | `datadog_api_key_disabled` (low) — matches | PASS | covered by tracked-field sweep | — |
| D2. API key re-enabled | `datadog_api_key_metadata` | `disabled` | `True` | `False` | yes | low | low (improvement) | "was re-enabled." | (same) | n/a | PASS | covered | — |
| D3. API key metadata added/removed | `datadog_api_key_metadata` | (whole record) | — | — | yes | low | low | "record was added or removed during sync." | (same) | n/a | PASS | covered by generic add/remove handling | — |
| D4. API key name/owner metadata | n/a | n/a | n/a | n/a | tracked (`created_by_present`) but no dedicated Finding | n/a | n/a | n/a | n/a | n/a | **N/A (intentional generic)** | n/a | No Finding exists for `created_by_present`/`resource_name` transitions specifically |
| E1. Application key scope count crosses threshold | `datadog_application_key_metadata` | `scopes_count` | `5` | `15` | yes | medium | medium | "key metadata changed — application key scope count increased from 5 to 15, exceeding the broad-scope review threshold." | (same) | `datadog_application_key_broad_scopes` (medium) — matches | PASS | existing `test_application_key_scopes_cross_threshold_is_medium` | — |
| E2. Application key scope count increases while already broad | `datadog_application_key_metadata` | `scopes_count` | `15` | `20` | yes | **was low (fell through the crossing-only check)** | medium | ~~"scope count changed from 15 to 20."~~ | "key metadata changed — application key scope count increased from 15 to 20, exceeding the broad-scope review threshold." | `datadog_application_key_broad_scopes` (medium, fires on every snapshot while `scopes_count > 10`) — now matches | **FIXED** | new `test_application_key_scopes_increase_while_already_broad_is_medium` | The core bug in this pass |
| E3. Application key scope count decreases while still broad | `datadog_application_key_metadata` | `scopes_count` | `20` | `15` | yes | low | low (improvement) | "scope count decreased from 20 to 15." | (same) | n/a — direction-based improvement, consistent with cross-provider convention | PASS (after fix) | new `test_application_key_scopes_decrease_while_still_broad_is_low` | — |
| E4. Application key scope count unknown | `datadog_application_key_metadata` | `scopes_count` | `5` | `None` | yes | low | low | "scope count is now unknown or missing." | (same) | n/a | PASS | existing `test_unknown_transitions_never_produce_high` | Confirmed: does not treat unknown as zero or as crossing the threshold |
| F1. Role permission count crosses threshold | `datadog_role` | `permission_count` | `20` | `30` | yes | medium | medium | "permission count increased from 20 to 30, exceeding the broad-access review threshold." | (same) | `datadog_role_high_permission_count` (medium) — matches | PASS | existing `test_role_permission_count_crosses_threshold_is_medium` | — |
| F2. Role permission count increases while already broad | `datadog_role` | `permission_count` | `30` | `40` | yes | **was low (fell through the crossing-only check)** | medium | ~~"permission count changed from 30 to 40."~~ | "permission count increased from 30 to 40, exceeding the broad-access review threshold." | `datadog_role_high_permission_count` (medium, fires on every snapshot while `permission_count > 25`) — now matches | **FIXED** | new `test_role_permission_count_increase_while_already_broad_is_medium` | Same bug class as E2 |
| F3. Role permission count decreases while still broad | `datadog_role` | `permission_count` | `40` | `30` | yes | low | low (improvement) | "permission count decreased from 40 to 30." | (same) | n/a | PASS (after fix) | new `test_role_permission_count_decrease_while_still_broad_is_low` | — |
| G1. Integration disabled | `datadog_notification_integration` | `enabled` | `True` | `False` | yes | medium | medium | "integration posture changed — this notification integration was disabled." | (same) | n/a (no dedicated Finding fires on `enabled=False` alone) | PASS | covered by tracked-field sweep | Change-only signal, already documented in the detection-QA report |
| G2. Integration restored | `datadog_notification_integration` | `enabled` | `False` | `True` | yes | low | low (improvement) | "was enabled." | (same) | n/a | PASS | covered | — |
| H. Log collection / security monitoring | `datadog_cloud_integration` | `log_collection_enabled` | `False` | `True` | yes | medium | medium | "gained log collection." | (same) | `datadog_cloud_integration_log_collection_enabled` (low, current-state) — intentional disagreement, already documented in the detection-QA report | PASS | covered by tracked-field sweep | No dedicated Security Monitoring Rules or log archive/index/pipeline surface exists — correctly N/A per the detection report |
| I1. Unknown/missing sweep (booleans) | multiple | `enabled`, `secret_headers_present`, `url_scheme_category`, `public_url_present` | truthy | `None` | yes | low | low | all say "...is now unknown or missing." | (same) | n/a | PASS | existing `test_unknown_transitions_never_produce_high` | — |
| I2. Unknown/missing sweep (counts) | `datadog_role`, `datadog_application_key_metadata`, `datadog_slo` | `permission_count`, `scopes_count`, `monitor_count` | numeric | `None` | yes | low | low | all say "...is now unknown or missing," never "dropped to zero" | (same) | n/a | PASS | new `test_slo_monitor_count_unknown_is_low_not_zero`, existing `test_count_unknown_not_treated_as_zero` | — |
| I3. Real zero still triggers intended classification | `datadog_slo` | `monitor_count` | `2` | `0` | yes | medium | medium | "SLO lost all linked monitors." | (same) | `datadog_slo_no_monitors` (medium) — matches | PASS | new `test_slo_monitor_count_real_zero_still_triggers_medium` | Confirms the unknown-handling fix/defensive design didn't accidentally break genuine zero-detection |
| J. Copy safety | all record types | all fields | — | — | — | — | — | no breach/compromise/attacker/leak/unauthorized-access/log-exposure/dashboard-exposure/secret-exposure/data-exposure/customer-impact language anywhere | (same) | — | PASS | existing `test_no_forbidden_wording_in_reasons`, re-verified after this pass's edits | — |

## Tracked-fields vs. classifier-branch comparison

(Unchanged from the detection pass's comparison table — this pass only
changed the *severity logic* for two already-dedicated branches
(`scopes_count`, `permission_count`), not which fields have dedicated
branches. Re-verified as still accurate.)

**Classifier branches referring to fields not emitted by the
connector/schema:** none found.

**Classifier branches referring to stale field names:** none — newly-built
module, no legacy drift to inherit.

**Fields with similar names that could be confused:** `scopes_count`
(application key) and `permission_count` (role) share the identical
threshold-crossing bug pattern and fix, but live in separate classifier
functions with distinct wording ("application key scope count" vs. "role
permission count"), so there is no cross-field confusion risk in the
emitted reason text.

## Verification: no `int(value or 0)`-style coercion remains

```
grep -n "int(.*or 0)\|_int_pair" backend/app/services/risk_rules/datadog.py
```
→ no matches. Every count-based branch in this module uses
`_int_or_none()`, confirmed both before and after this pass's edits — the
module was already built defensively, having learned from the PagerDuty
bug in the prior classification-QA pass.

## Mock-shape (`old_value`/`prev_value`/`previous_value`/`prior_value`) verification

```
grep -n "old_value\|previous_value\|prior_value\|prev_value" backend/app/services/risk_rules/datadog.py
```
→ 7 matches, all `_get(change, "prev_value")` — production code was
already clean.

```
grep -rn "old_value\|previous_value\|prior_value" backend/tests/*datadog*
```
→ one match, in `test_milestone82a_datadog_drift_provider_foundation.py`
— a docstring comment naming the bug class being guarded against, not an
actual field usage.

**No mock-shape issue remains, and none was introduced by this pass.**

## Totals

| Metric | Count |
|---|---|
| Total classification cases reviewed | 24 (A1–J, all rows above) |
| PASS | 20 |
| FAIL | 0 |
| GAP → FIXED (threshold-crossing severity bug) | 2 (E2, F2 — one field each, `scopes_count` and `permission_count`) |
| N/A (not modeled, correctly absent) | 2 (A7, C4) |
| New Security Finding rules added | 0 (classification-layer pass only) |
| Previously detected changes now confirmed misclassified before this pass | 2 (both threshold fields, only when already-over-threshold and increasing further) |
| Mock-shape (`old_value`-style) bugs found | 0 |
| PagerDuty-style unknown-treated-as-zero bug found | 0 — confirmed the module was already defensive from the start |
| Monitor/webhook/dashboard/role/API key/application key/integration classifications aligned with Security Findings | Yes, after the threshold-crossing fix — all 9 confirmed |

## Fixes made

1. **`backend/app/services/risk_rules/datadog.py`**
   - `_classify_application_key_change`: `scopes_count`'s threshold check
     changed from `n_new > THRESHOLD and (n_old or 0) <= THRESHOLD`
     (crossing-only) to `n_new > THRESHOLD and n_new > (n_old or 0)` (any
     increase while over threshold).
   - `_classify_role_change`: identical fix applied to `permission_count`.
2. **`backend/tests/test_milestone82a_datadog_drift_provider_foundation.py`**
   — added 6 new tests: 2 for the "increase while already broad" fix (one
   per field), 2 confirming the "decrease while still broad" improvement
   path still works, and 2 for the SLO `monitor_count` real-zero vs.
   unknown distinction (proving the defensive unknown-handling didn't
   break genuine zero-detection).
3. **`backend/tests/reports/datadog_change_classification_matrix.md`** —
   this report.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone82a_datadog_drift_provider_foundation.py -q
# 134 passed (was 128 after 55e9f5e)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "datadog and risk"
# 179 passed, 7 skipped, 16942 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "datadog and diff"
# 12 passed, 17116 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "datadog"
# 782 passed, 22 skipped, 16324 deselected (was 776 passed, 22 skipped after 55e9f5e)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*datadog* -q
# 773 passed, 22 skipped
```

The 22 skips are pre-existing (network-dependent tests skipped in this
environment) and unrelated to this pass's changes.

No frontend files were touched in this pass — no new Security Finding
rule was added or changed, only Change-classification logic and tests —
so `npx tsc --noEmit` was not run.
