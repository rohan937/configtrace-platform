# Terraform Cloud Detection QA Matrix

Exhaustive validation pass over the Terraform Cloud provider (connector →
diff tracking → risk classification → security findings → registries →
frontend catalog), following the same methodology as
`sendgrid_detection_matrix.md`, `sendgrid_change_classification_matrix.md`,
and `twilio_detection_matrix.md`.

## Summary

Terraform Cloud started this QA pass from a **much more mature baseline**
than SendGrid or Twilio did: `risk_rules/terraform_cloud.py` already
existed (unlike SendGrid/Twilio, which needed the module built from
scratch in prior QA passes), and `security_rules/terraform_cloud.py` (36
rules across 10 record types) was already in perfect registry/pack/
confidence/coverage/frontend-catalog parity before this pass began.

Two real, previously-undetected bugs were found and fixed:

1. **Diff/drift tracking gap** (same shape as the SendGrid/Twilio bug fixed
   in `4bd31f4` / `87635c0`). Terraform Cloud had **zero entries** in
   `diff_service.py`'s per-provider tracked-fields dispatch, so every
   Terraform Cloud record type fell through to the Cloudflare-DNS default
   tuple. `compute_diff` could therefore never detect a *modified* field on
   an existing Terraform Cloud record — only add/remove of a whole record.
   Fixed by adding `_TERRAFORM_CLOUD_TRACKED_FIELDS_BY_TYPE` (all 10 record
   types) and wiring the `terraform_cloud_` prefix into
   `_tracked_fields_for`.

2. **A more severe, distinct bug: every directional classifier in
   `risk_rules/terraform_cloud.py` read a nonexistent `old_value` field
   instead of the real `prev_value` field** that `compute_diff`/the
   `Change` ORM model actually use. This is NOT the same bug as #1 — it
   exists independently of whether `compute_diff` ever generates the
   Change. Because `_get(change, "old_value")` always returned `None` in
   real usage, **every "increase vs. decrease" and "transitioned from X"
   comparison in the entire module was broken**: `sensitive_variable_count`
   decreasing (the single most safety-critical classification — "sensitive
   variable re-classified as non-sensitive") could never be distinguished
   from increasing; `execution_mode_category` transitioning specifically
   *from* `"remote"` could never be detected (the "remote → local/agent is
   `high`" rule could never fire — it always fell to the generic `medium`
   branch); `admin_access_count`/`write_access_count`/`team_access_count`
   increases were structurally indistinguishable from decreases.

   **Why existing tests never caught this:** the test helper
   (`_make_change` in `test_milestone88a_...py`) set
   `change.old_value = old_value` — the *same wrong field name* as the
   buggy code. Test and code agreed with each other while both disagreeing
   with reality (a real `Change` object/dict uses `prev_value`). This is a
   textbook "matched-bug" false-positive: 100% test pass rate with zero
   real-world correctness.

   Fixed by changing all 5 occurrences of `_get(change, "old_value")` to
   `_get(change, "prev_value")` in `risk_rules/terraform_cloud.py`, and
   updating the test helper to set `change.prev_value` instead of
   `change.old_value`. Added a dedicated regression test
   (`test_classifier_reads_real_compute_diff_dict_shape_not_a_mock`) that
   builds a plain dict shaped exactly like `compute_diff`'s real output
   (not a `MagicMock`) to permanently guard against this exact class of
   bug recurring.

A third, minor gap was found and fixed: `plan_access_count` and
`custom_permission_count` (both tracked, both real schema fields) had no
dedicated classification — they fell through to the generic `low` default
instead of the task's expected `medium` for a broadened grant. Added
explicit handling for both.

- **Connector**: 10 record types, all fail-soft on optional sub-resources
  (variables, notifications, team-access, run-triggers, projects, variable
  sets, policy sets — verified via `_fetch_fail_soft`'s explicit
  `except (ConnectorError, AuthenticationError, RateLimitError,
  NetworkError): return []`). Only the workspace list and organization
  fetch are semi-required (organization fetch returns `None` gracefully;
  workspace-list failures propagate, matching the "one required anchor
  surface" convention used by every other provider connector in this
  codebase). Confirmed: no state file content, no variable values, no
  secrets, no auth tokens are ever stored — every identifier is a
  SHA-256-derived opaque ID, every enum is bucketed into a safe
  "category" (`execution_mode_category`, `terraform_version_category`,
  `enforcement_level_category`, etc.) rather than storing the raw string.
- **Security findings**: 36 rules, already in 100% parity across all four
  backend registries and the frontend catalog before this pass (verified by
  exact set diff — zero fixes needed here).
- **Risk classification for Changes**: existed before this pass, but was
  silently broken for every directional comparison (bug #2 above). Now
  fixed and verified with a real-shape regression test.

## Test matrix

| Test case | Normalized record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes / fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. Workspace auto-apply enabled/disabled | `terraform_cloud_workspace` | `auto_apply` | `False → True` | Change (high) + Finding (high) | Change never generated before fix (bug #1); Finding fired but Change was invisible | high | high | `terraform_cloud_workspace_auto_apply_enabled` | `test_classify_auto_apply_enabled_is_high`, new `test_auto_apply_change_produces_drift_change` | **FIXED** | Diff-tracking gap (#1) fixed |
| B. Workspace execution mode changed | `terraform_cloud_workspace` | `execution_mode_category` | `"remote" → "local"` | Change (high) | **Misclassified as medium before fix** (bug #2 — `prev_value` unreadable, so the remote-specific `high` branch could never match) | high | high (after fix) | n/a (Change-only; no dedicated Finding for this specific transition) | new `test_classifier_reads_real_compute_diff_dict_shape_not_a_mock` | **FIXED (was misclassified)** | The most concrete proof of bug #2 — this transition specifically requires reading `prev_value == "remote"` |
| C. Workspace VCS connected/disconnected | `terraform_cloud_workspace` | `vcs_connected` | `True → False` | Change (medium) | Change never generated before fix (#1) | medium | medium | `terraform_cloud_workspace_vcs_connection_missing` | existing `test_milestone88a` coverage (via FORBIDDEN-wording sweep) | **FIXED** | — |
| D. Global remote state/state sharing enabled/disabled | `terraform_cloud_workspace` | `global_remote_state` | `False → True` | Change (high) + Finding (high) | Change never generated before fix (#1) | high | high | `terraform_cloud_workspace_global_remote_state_enabled` | `test_classify_global_remote_state_enabled_is_high` | **FIXED** | — |
| E. Workspace variable sensitive true/false | `terraform_cloud_workspace`, `terraform_cloud_workspace_variable_summary` | `sensitive_variable_count` | `5 → 2` (decrease) | Change (high) | **Misclassified as "low, increased" before fix** (bug #2 — `n_old` always read as 0, so a real decrease was indistinguishable from an increase and always took the "increased" branch) | high | high (after fix) | n/a (Change-only signal; the current-state Finding `terraform_cloud_workspace_non_sensitive_variables_present` is a separate, intentionally lower-severity signal — see design note below) | `test_classify_sensitive_variable_count_decreased_is_high`, `test_classifier_reads_real_compute_diff_dict_shape_not_a_mock` | **FIXED (was misclassified)** | This was the single most safety-critical broken classification in the module |
| F. Environment variable marked non-sensitive / risky metadata | `terraform_cloud_workspace`, `terraform_cloud_workspace_variable_summary` | `unprotected_non_sensitive_count` | increase | Change (medium) + Finding | Change never generated before fix (#1) | medium | medium | `terraform_cloud_workspace_environment_variables_non_sensitive` | existing coverage in `test_milestone88c_terraform_cloud_workspace_variable_policy_risk_expansion.py` | **FIXED** | Risky metadata is by-name-category only (env vs. terraform), never by variable name — matches "do not invent" |
| G. Terraform variable HCL flag changed | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | The connector aggregates variable *counts* only (by sensitivity/category) — no per-variable HCL flag is fetched or normalized anywhere in the schema. Not invented per task instructions |
| H. Team access broadened/restricted | `terraform_cloud_team_access_summary` | `admin_access_count`, `write_access_count`, `team_access_count` | increase | Change (high for admin/write, medium for total) + Finding | Change never generated before fix (#1); directional logic also broken by bug #2 | high (admin/write), medium (total) | high / medium (after fix) | `terraform_cloud_team_admin_access`, `terraform_cloud_team_write_access` | `test_classify_admin_access_increased_is_high`, `test_classify_write_access_increased_is_high`, new `test_admin_access_count_change_produces_drift_change` | **FIXED** | — |
| I. Apply/admin access broadened | `terraform_cloud_team_access_summary` | `admin_access_count`, `write_access_count` | increase | Change (high) | Same as H | high | high | `terraform_cloud_team_admin_access` | see H | **FIXED** | Terraform Cloud's "write" access level maps to apply-capable; both admin and write are classified `high` on increase |
| J. Plan access broadened | `terraform_cloud_team_access_summary` | `plan_access_count` | `0 → 2` | Change (medium) | **Gap found**: field is tracked and normalized but had no dedicated classification rule — fell through to the generic `low` "field changed" fallback | medium | medium (after fix) | `terraform_cloud_team_plan_access` (Finding, pre-existing); Change classifier previously had no matching rule | new `test_classify_plan_access_increased_is_medium`, `test_classify_plan_access_decreased_is_low` | **FIXED** | Also added `custom_permission_count` (medium on increase) alongside, for the same reason — see `test_classify_custom_permission_increased_is_medium` |
| K. Policy set enforcement weakened/strengthened | `terraform_cloud_policy_set` | `enforcement_level_category` | `"mandatory" → "advisory"` | Change (high) | **Misclassified before fix** (bug #2 — `old_s` always `""`, so the `mandatory`-specific `high` branch could never match; fell to generic `medium`/`low`) | high | high (after fix) | `terraform_cloud_policy_set_advisory_enforcement` | existing `test_classify_policy_enforcement_weakened_mandatory_to_advisory_is_high` (now genuinely exercised) | **FIXED (was misclassified)** | Same root cause as B — confirms bug #2 affected multiple record types, not just workspace |
| L. Run task enabled/disabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | Terraform Cloud Run Tasks (a distinct API resource from run *triggers*) are not fetched by the connector. No existing evidence to build a rule from; would require a new endpoint call (`/workspaces/{id}/run-tasks`) — out of scope per "do not invent unsupported capabilities" |
| M. Run trigger added/removed | `terraform_cloud_run_trigger` | whole record | added | Change (medium) + Finding (medium) | Detected correctly (add/remove never depended on tracked fields or the `prev_value` bug) | medium | medium | `terraform_cloud_run_trigger_enabled` | existing `test_milestone88a`/`test_milestone88c` coverage | PASS | Unaffected by either bug — was already correct |
| N. Unknown/missing fields never trigger high findings | all 10 record types | any field | field absent (`None`) | no high finding | Confirmed — every Finding check requires an explicit boolean/category match; every Change classifier falls to `low` on unparseable/missing values (`try/except (TypeError, ValueError)` guards throughout) | none | none | all | existing FORBIDDEN-wording sweep test (110 field/record_type combinations) | PASS | — |
| O. 403/404 fail-soft on optional endpoints | variables, notifications, team-access, run-triggers, projects, variable sets, policy sets | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed via `_fetch_fail_soft`'s explicit catch of `ConnectorError`/`AuthenticationError`/`RateLimitError`/`NetworkError`, returning `[]` | n/a | n/a | n/a | existing `test_milestone88a` connector tests | PASS | — |
| P. Records with normalized fields but no security rule | `terraform_cloud_project` (`workspace_count`, `team_access_count`) | n/a | n/a | correctly no finding | Confirmed — `evaluate()` has an explicit comment "`terraform_cloud_project`: no rules at M88B/M88C" and the Change classifier likewise falls to a generic low-severity message for this record type | n/a | n/a | n/a | n/a | PASS | Deliberate, documented design choice — project-level aggregate counts are low-signal on their own |
| Q. Security rules with no reachable normalized record | — | — | — | — | None found — all 36 rules dispatch from `evaluate()` against one of the 9 rule-bearing record types | n/a | n/a | all | existing `test_terraform_cloud_provider_depth_qa.py` / `test_milestone88h_...py` reachability tests | PASS | Zero dead/unreachable rules |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | all 36 rule keys present everywhere with matching severities | Verified via exact set diff: `security_rules/terraform_cloud.py` (36) vs. all four backend registries (36 each) and `securityRuleCatalog.ts` (36) | n/a | n/a | all | existing depth-QA test suites | PASS | Zero mismatches — already correct before this pass, no fix needed |
| Diff-tracked fields present for all 10 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 10 record types tracked (before fix)** → **10 of 10 tracked (after fix)** | n/a | n/a | n/a | new `TestTerraformCloudDiffTrackedFields` (5 tests) | **FIXED** | Bug #1 |

## Design note: why `sensitive_variable_count` has two different severities

The Security Finding `terraform_cloud_workspace_non_sensitive_variables_present`
(medium) and the Change classifier's `sensitive_variable_count` decrease
(high) are **intentionally different signals, not a parity bug**:

- The **Finding** evaluates a single snapshot in isolation: "this workspace
  currently has some non-sensitive variables." That's a normal, common
  state — most workspaces have some non-secret variables — so `medium` is
  appropriate.
- The **Change classifier** evaluates a *transition*: "the count of
  sensitive variables just went down." That can only mean a variable was
  either deleted or had its sensitivity flag flipped off — a materially
  different, higher-signal event that the Finding layer structurally cannot
  observe (it never sees the prior state). `high` is appropriate here.

This is the same pattern already established for GitHub (`insecure_ssl`)
and SendGrid (`event_webhook_signed`) in prior QA passes: current-state
Findings and Change-transition classifiers answer different questions and
are allowed to disagree on severity by design.

## Totals

| Metric | Count |
|---|---|
| Total Terraform Cloud test cases reviewed | 17 (rows A–Q) |
| PASS (already correct, no fix needed) | 6 (M, N, O, P, Q, registry parity) |
| FAIL | 0 |
| FIXED — previously undetected (diff-tracking gap only) | 4 (A, C, D, F) |
| FIXED — previously misclassified (field-name bug) | 3 (B, E, K) |
| FIXED — genuine classification gap (missing rule) | 1 (J) |
| FIXED — broadened access, both bugs combined | 1 (H/I, counted once) |
| N/A (not modeled, correctly absent per API/connector reality) | 2 (G, L) |

## Fixes made

1. **`backend/app/services/diff_service.py`** — added
   `_TERRAFORM_CLOUD_TRACKED_FIELDS_BY_TYPE` (all 10 record types, every
   non-identity field) and wired the `terraform_cloud_` prefix into
   `_tracked_fields_for`. Updated the function's docstring.
2. **`backend/app/services/risk_rules/terraform_cloud.py`** — fixed all 5
   occurrences of `_get(change, "old_value")` → `_get(change, "prev_value")`
   (the field-name bug, #2 above). Added explicit `plan_access_count`
   (medium on increase) and `custom_permission_count` (medium on increase)
   classification branches that previously fell through to the generic
   `low` fallback.
3. **`backend/tests/test_milestone88a_terraform_cloud_drift_provider_foundation.py`**
   — fixed the `_make_change` test helper to set `change.prev_value`
   instead of `change.old_value` (so it matches a real `Change`). Added:
   `TestTerraformCloudDiffTrackedFields` (5 tests: entry-completeness,
   no-fallthrough check, 2 `compute_diff` regression tests, 1
   no-spurious-change sanity test);
   `test_classifier_reads_real_compute_diff_dict_shape_not_a_mock` (proves
   the classifier reads a real plain-dict shape, not a mock, for two of the
   previously-broken transitions);
   `test_classify_plan_access_increased_is_medium`,
   `test_classify_plan_access_decreased_is_low`,
   `test_classify_custom_permission_increased_is_medium` (the new rule
   coverage from fix #2 above).
4. **`backend/tests/reports/terraform_cloud_detection_matrix.md`** — this
   report.

## Not fixed in this pass (explicitly out of scope)

- **Terraform variable HCL flag** (item G) — not fetched; the connector
  only aggregates variable counts by sensitivity/category, never per-
  variable attributes.
- **Run Tasks** (item L) — a distinct Terraform Cloud API resource from
  Run *Triggers* (which the connector already covers); no endpoint is
  fetched. Would require a new `/workspaces/{id}/run-tasks` connector call
  — a new capability, not a QA-pass fix, per "do not invent unsupported
  capabilities."
- **GitLab's parallel diff-tracking gap** — while investigating the
  `_tracked_fields_for` dispatch chain, confirmed GitLab (`gitlab_*` record
  types) has the exact same missing-entry gap that Terraform Cloud,
  SendGrid, and Twilio each had before their respective QA passes. Left
  untouched — GitLab is a different provider, out of scope for this task,
  and deserves its own dedicated QA pass rather than an incidental fix
  here.

## Validation run (narrow, foreground only)

```
DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone88a_terraform_cloud_drift_provider_foundation.py -q
# 75 passed (was 66 before this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "terraform_cloud"
# 690 passed, 16258 deselected (was 681 passed before this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_terraform_cloud_provider_depth_qa.py \
    tests/test_milestone88b_terraform_cloud_core_security_foundation.py \
    tests/test_milestone88c_terraform_cloud_workspace_variable_policy_risk_expansion.py \
    tests/test_milestone88h_terraform_cloud_provider_depth_qa.py -q
# 275 passed
```

No frontend files were touched in this pass (no new Security Finding rule
was added — only classification-logic and diff-tracking fixes), so
`npx tsc --noEmit` was not run.
