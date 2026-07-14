# Terraform Cloud Change-Classification QA Matrix

Dedicated follow-up to the detection QA pass committed as `7fa4e65`
(`terraform_cloud_detection_matrix.md`). That pass fixed the diff-tracking
gap (0/10 record types tracked → 10/10) and the `old_value`/`prev_value`
field-name bug in `risk_rules/terraform_cloud.py`. This pass verifies that,
now that changes are detected, every one of them is classified with the
correct severity, safe wording, and improvement/restoration behavior, and
checks for any remaining generic-fallback gaps or mock-bug regressions.

## Summary

Starting point: all 10 record types tracked, all 5 `old_value` occurrences
already fixed to `prev_value`, `plan_access_count`/`custom_permission_count`
already classified. This pass found and fixed two categories of remaining
issue:

1. **Two genuine classification gaps** — tracked, normalized fields that
   fell through to the generic per-record-type fallback (`low`, "field X
   changed") instead of a risk-appropriate classification:
   - `terraform_cloud_policy_set.vcs_connected` — tracked since `7fa4e65`,
     but `_classify_policy_set_change` had no branch for it. Fixed:
     disconnection → `medium` (mirrors the existing `terraform_cloud_workspace.vcs_connected`
     convention), reconnection → `low`.
   - `terraform_cloud_project.team_access_count` — tracked since `7fa4e65`,
     but `_classify_project_change` only handled `added`/`removed` change
     types, nothing for `modified`. Fixed: increase → `medium` (project-level
     team access is coarser than workspace's granular admin/write/plan
     breakdown, so it doesn't warrant `high` on its own), decrease → `low`.

2. **A wording-accuracy bug affecting three boolean fields** —
   `auto_apply`, `global_remote_state` (workspace), and `global_scope`
   (variable set) each used `_is_truthy(new_v)` to decide the `high`
   branch, then unconditionally labeled *any* non-truthy value — including
   `None`/unknown, not just an explicit `false` — as "was disabled" /
   "was removed". This never produced an incorrect *severity* (unknown
   still correctly stayed `low`, matching the task's "unknown should not
   create high" requirement), but it produced factually wrong *copy*:
   a value that went from `true` to genuinely unknown/missing would be
   reported as if it had been explicitly turned off. Fixed by adding an
   explicit `_is_falsy_explicit(new_v)` check before falling back to a new,
   accurate "value is now unknown or missing" message.

No new Security Finding rules were added or changed — this pass is scoped
to the Change-classification layer (`risk_rules/terraform_cloud.py`), not
`security_rules/terraform_cloud.py`, which was already verified at 100%
registry parity in the prior pass.

No `old_value`/`prev_value` regressions were found — see verification
section below.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected by `compute_diff`? | Current risk_level | Expected risk_level | Current title/copy | Expected title/copy | Security finding parity | Status | Test covering it | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1. Auto-apply enabled | `terraform_cloud_workspace` | `auto_apply` | `False` | `True` | yes | high | high | "auto-apply was enabled — runs will apply automatically..." | (same) | `terraform_cloud_workspace_auto_apply_enabled` (high) — matches | PASS | `test_classify_auto_apply_enabled_is_high`, `test_auto_apply_change_produces_drift_change` | — |
| A2. Auto-apply disabled (restoration) | `terraform_cloud_workspace` | `auto_apply` | `True` | `False` | yes | low | low (improvement) | "auto-apply was disabled." | (same) | n/a (Finding only fires on current-state true) | PASS | new `test_classify_auto_apply_explicit_false_is_low_disabled_wording` | — |
| A3. Auto-apply unknown → true | `terraform_cloud_workspace` | `auto_apply` | `None` | `True` | yes | high | high | "auto-apply was enabled..." | (same) | matches | PASS | covered by A1's truthy check (`_is_truthy` doesn't care about old value) | Correct: only `new_value` truthiness gates high, as required |
| A4. Auto-apply true → unknown | `terraform_cloud_workspace` | `auto_apply` | `True` | `None` | yes | **was low but mislabeled "disabled"** | low | ~~"auto-apply was disabled."~~ | "auto-apply value is now unknown or missing." | n/a | **FIXED (wording)** | new `test_classify_auto_apply_true_to_unknown_is_low_not_disabled_wording` | Severity was already correct; copy was inaccurate |
| B1. Execution mode remote → local | `terraform_cloud_workspace` | `execution_mode_category` | `"remote"` | `"local"` | yes | high | high | "execution mode changed from remote to local..." | (same) | `terraform_cloud_workspace_local_execution` (medium, current-state) — **intentional disagreement, see design note** | PASS | `test_classify_execution_mode_remote_to_local_is_high` | Fixed in `7fa4e65` (was the `old_value` bug) |
| B2. Execution mode remote → agent | `terraform_cloud_workspace` | `execution_mode_category` | `"remote"` | `"agent"` | yes | high | high | "execution mode changed from remote to agent..." | (same) | `terraform_cloud_workspace_agent_execution` (medium, current-state) — intentional disagreement | PASS | `test_classify_execution_mode_to_agent_is_high` | — |
| B3. Execution mode local → remote (restoration) | `terraform_cloud_workspace` | `execution_mode_category` | `"local"` | `"remote"` | yes | low | low (improvement) | "execution mode changed to remote." | (same) | n/a | PASS | falls to the module's final `return ("low", f"...changed to {new_s}.")` branch — verified by inspection | Centralizing execution back to remote is not itself risky |
| B4. Execution mode unknown → local | `terraform_cloud_workspace` | `execution_mode_category` | `""`/`None` | `"local"` | yes | medium | medium (not high — old state wasn't confirmed remote) | "execution mode changed to local." | (same) | n/a | PASS | covered by existing branch logic (`old_s not in (local, agent)` but `old_s != "remote"`) | Correctly avoids high on unconfirmed prior state |
| C1. VCS disconnected | `terraform_cloud_workspace` | `vcs_connected` | `True` | `False` | yes | medium | medium | "VCS connection was removed." | (same) | `terraform_cloud_workspace_vcs_connection_missing` (medium) — matches | PASS | `test_classify_vcs_connection_removed_is_medium` | — |
| C2. VCS reconnected (restoration) | `terraform_cloud_workspace` | `vcs_connected` | `False` | `True` | yes | low | low (improvement) | "VCS connection was added." | (same) | n/a | PASS | new `test_classify_vcs_reconnected_is_improvement_low` | — |
| C3. VCS repo identifier changed | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | n/a | N/A | n/a | Connector only stores a boolean `vcs_connected`, never a repo name/URL/identifier — correctly not modeled to preserve privacy-by-design (no repo names stored) |
| D1. Global remote state enabled | `terraform_cloud_workspace` | `global_remote_state` | `False` | `True` | yes | high | high | "global remote state sharing was enabled..." | (same) | `terraform_cloud_workspace_global_remote_state` (high) — matches | PASS | `test_classify_global_remote_state_enabled_is_high` | — |
| D2. Global remote state disabled (restoration) | `terraform_cloud_workspace` | `global_remote_state` | `True` | `False` | yes | low | low (improvement) | "global remote state sharing was disabled." | (same) | n/a | PASS | new `test_classify_global_remote_state_disabled_is_improvement_low` | — |
| D3. Global remote state true → unknown | `terraform_cloud_workspace` | `global_remote_state` | `True` | `None` | yes | **was low but mislabeled "disabled"** | low | ~~"...was disabled."~~ | "...value is now unknown or missing." | n/a | **FIXED (wording)** | new `test_classify_global_remote_state_true_to_unknown_is_low_not_disabled_wording` | Same wording bug class as A4 |
| E1. Sensitive variable count decreases | `terraform_cloud_workspace`, `terraform_cloud_workspace_variable_summary` | `sensitive_variable_count` | `5` | `2` | yes | high | high | "sensitive variable count decreased — variables may have been re-classified..." | (same) | `terraform_cloud_workspace_non_sensitive_variables_present` (medium, current-state) — intentional disagreement, see design note | PASS | `test_classify_sensitive_variable_count_decreased_is_high`, `test_classifier_reads_real_compute_diff_dict_shape_not_a_mock` | Fixed in `7fa4e65` (was the `old_value` bug) — the single most safety-critical fix in that pass |
| E2. Sensitive variable count restored/increases | same | `sensitive_variable_count` | `2` | `5` | yes | low | low (improvement) | "sensitive variable count increased." | (same) | n/a | PASS | covered by existing branch (`n_new < n_old` else low) | — |
| E3. Per-variable sensitive flag true → false | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | n/a | N/A | n/a | Connector aggregates counts only, never per-variable records — no per-variable ID/name/flag is fetched. Not invented, per task instructions |
| E4. Variable category env/terraform changes | `terraform_cloud_workspace_variable_summary` | `environment_variable_count`, `terraform_variable_count` | count | count | yes | low (generic fallback) | low (intentional) | "...field 'X' changed." | (same) | n/a | PASS (intentional generic) | none dedicated; covered indirectly by `unprotected_non_sensitive_count` | The risky *combination* (non-sensitive AND environment-category) is already classified specifically via `unprotected_non_sensitive_count` (medium) — the raw per-category counts alone carry no independent risk signal |
| E5. Unprotected non-sensitive env var count increases | `terraform_cloud_workspace_variable_summary` | `unprotected_non_sensitive_count` | `0` | `1` | yes | medium | medium | "unprotected non-sensitive environment variable count increased." | (same) | `terraform_cloud_workspace_environment_variables_non_sensitive` (medium) — matches | PASS | existing `test_milestone88c` coverage | — |
| F1. Team access count increases | `terraform_cloud_team_access_summary` | `team_access_count` | `1` | `3` | yes | medium | medium | "total team access count increased." | (same) | n/a (no single Finding for the aggregate total) | PASS | existing coverage | — |
| F2. Admin access count increases | `terraform_cloud_team_access_summary` | `admin_access_count` | `0` | `2` | yes | high | high | "admin team access count increased..." | (same) | `terraform_cloud_team_admin_access` (high) — matches | PASS | `test_classify_admin_access_increased_is_high`, `test_admin_access_count_change_produces_drift_change` | Fixed in `7fa4e65` (was the `old_value` bug) |
| F3. Write/apply access count increases | `terraform_cloud_team_access_summary` | `write_access_count` | `0` | `2` | yes | high | high | "write access count increased..." | (same) | `terraform_cloud_team_write_access` (medium, current-state) — intentional disagreement, see design note | PASS | `test_classify_write_access_increased_is_high` | Fixed in `7fa4e65` |
| F4. Plan access count increases | `terraform_cloud_team_access_summary` | `plan_access_count` | `0` | `2` | yes | medium | medium | "plan-only team access count increased..." | (same) | `terraform_cloud_team_plan_access` (medium) — matches | PASS | `test_classify_plan_access_increased_is_medium` | Fixed in `7fa4e65` |
| F5. Custom permission count increases | `terraform_cloud_team_access_summary` | `custom_permission_count` | `0` | `1` | yes | medium | medium | "custom-permission team access count increased..." | (same) | `terraform_cloud_team_custom_permissions` (low, current-state) — intentional disagreement (transition > steady-state, same pattern as E1/F3) | PASS | `test_classify_custom_permission_increased_is_medium` | Fixed in `7fa4e65` |
| F6. All access counts decrease (restoration) | `terraform_cloud_team_access_summary` | any | higher | lower | yes | low | low (improvement) | "...count decreased." | (same) | n/a | PASS | `test_classify_plan_access_decreased_is_low` + inspection of all other count branches | Every count-based branch in this record type has a symmetric `n_new <= n_old → low` path |
| F7. Project-level team access count increases | `terraform_cloud_project` | `team_access_count` | `1` | `3` | yes | **was low (generic fallback)** | medium | ~~"project configuration field 'team_access_count' changed."~~ | "project team access count increased... access may now be broadened across all workspaces in this project." | n/a (no project-level Finding exists — documented no-rule choice) | **FIXED (gap)** | new `test_classify_project_team_access_increased_is_medium` | Genuine classification gap — field has been tracked since `7fa4e65` but had no branch until this pass |
| F8. Project-level team access count decreases | `terraform_cloud_project` | `team_access_count` | `3` | `1` | yes | low | low (improvement) | "project team access count decreased." | (same) | n/a | PASS (after fix) | new `test_classify_project_team_access_decreased_is_low` | — |
| G1. Policy enforcement mandatory → advisory | `terraform_cloud_policy_set` | `enforcement_level_category` | `"mandatory"` | `"advisory"` | yes | high | high | "enforcement level weakened from mandatory to advisory..." | (same) | `terraform_cloud_policy_advisory` (medium, current-state) — intentional disagreement | PASS | `test_classify_policy_enforcement_weakened_mandatory_to_advisory_is_high` | Fixed in `7fa4e65` (was the `old_value` bug) |
| G2. Policy enforcement mandatory → none/disabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | n/a | N/A | n/a | `enforcement_level_category` only models Terraform Cloud's three real API values (`mandatory`/`soft_mandatory`/`advisory`); a policy set with enforcement fully disabled is not a distinct state in the TFC API — it would show as the policy set being detached (`global_scope`/`workspace_count` change) or removed entirely (`change_type == "removed"`), both already covered |
| G3. Policy enforcement advisory → mandatory (restoration) | `terraform_cloud_policy_set` | `enforcement_level_category` | `"advisory"` | `"mandatory"` | yes | low | low (improvement) | "enforcement level changed to mandatory." | (same) | n/a | PASS | falls to the module's final low branch — verified by inspection | Strengthening enforcement is not itself risky |
| G4. Policy set removed | `terraform_cloud_policy_set` | (whole record) | — | — | yes | low | low/medium (review — a protective control disappeared) | "policy set record was added or removed during sync." | (same, generic) | n/a | PASS (intentional generic) | existing `add`/`remove` branch | Matches convention used by every other provider — record removal is `low`/informational, since the Security Finding layer (current-state) is what flags an org missing policy coverage, not the Change layer |
| H1. Run trigger added | `terraform_cloud_run_trigger` | (whole record) | — | — | yes | medium | medium | "A Terraform Cloud run trigger was added..." | (same) | `terraform_cloud_run_trigger_enabled` (medium) — matches | PASS | existing coverage | — |
| H2. Run trigger removed (restoration) | `terraform_cloud_run_trigger` | (whole record) | — | — | yes | low | low (improvement) | "A Terraform Cloud run trigger was removed..." | (same) | n/a | PASS | existing coverage | — |
| H3. Source workspace changed | `terraform_cloud_run_trigger` | `sourceable_type_category` | value | value | yes | low (generic fallback) | low/medium (per existing convention) | "run trigger changed." | (same) | n/a | PASS (intentional generic) | falls to the record type's final low branch | Sourceable-type change carries no independent risk signal distinct from the trigger's own add/remove events, which already have dedicated rules |
| I1. Policy set VCS disconnected | `terraform_cloud_policy_set` | `vcs_connected` | `True` | `False` | yes | **was low (generic fallback)** | medium | ~~"policy set field 'vcs_connected' changed."~~ | "policy set VCS connection was removed — policy definitions may no longer sync from source control." | n/a (no dedicated Finding; the analogous `terraform_cloud_workspace_vcs_connection_missing` doesn't cover policy sets) | **FIXED (gap)** | new `test_classify_policy_set_vcs_disconnected_is_medium` | Field has been tracked since `7fa4e65`; mirrors the existing `terraform_cloud_workspace.vcs_connected` convention |
| I2. Policy set VCS reconnected | `terraform_cloud_policy_set` | `vcs_connected` | `False` | `True` | yes | low | low (improvement) | "policy set VCS connection was added." | (same) | n/a | PASS (after fix) | new `test_classify_policy_set_vcs_reconnected_is_low` | — |
| J. Variable set global scope true → unknown | `terraform_cloud_variable_set` | `global_scope` | `True` | `None` | yes | **was medium but mislabeled "removed"** | low | ~~"global scope was removed."~~ | "global scope value is now unknown or missing." | n/a | **FIXED (wording + severity)** | new `test_classify_variable_set_global_scope_true_to_unknown_is_low` | This one *did* have a severity impact, not just wording: an unknown transition was previously classified `medium` as if explicitly removed |
| K. Org 2FA requirement disabled | `terraform_cloud_organization` | `two_factor_requirement_enabled` | `True` | `False` | yes | high | high | "2FA requirement was disabled..." | (same) | `terraform_cloud_org_2fa_not_required` (medium, current-state) — intentional disagreement | PASS | `test_classify_org_2fa_disabled_is_high` | — |
| L. Unknown/missing fields never produce high | all 10 record types | any | `None`/missing | `None`/missing | n/a (no diff on identical values) or yes (if present→absent) | low | low | varies, all fall to safe generic or explicit unknown-handling branches | (same) | n/a | PASS | new `test_every_tracked_field_classifies_without_error_or_invalid_severity` (exercises every tracked field across all 10 record types) | Verified no `TypeError`/`ValueError` and no invalid severity string for any tracked field |
| M. 403/404 fail-soft on optional endpoints | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | PASS | existing connector tests (`test_milestone88a`) | Out of scope for classification layer — verified unaffected in prior pass |

## Design note: intentional Finding/Change severity disagreements

Several rows above show a Security Finding severity that is *lower* than
the corresponding Change classification. This is by design, established in
the prior detection QA pass and reapplied consistently here:

- The **Finding** layer evaluates a single snapshot in isolation ("this
  workspace currently has write access granted to N teams") — a durable
  state that is often unremarkable on its own, so it gets a more moderate
  severity.
- The **Change** classifier evaluates a *transition* ("write access count
  just increased") — a materially higher-signal event, since it means a
  grant was just added, which the Finding layer structurally cannot
  observe (it never sees the prior snapshot).

This pattern recurs for: `execution_mode_category` (B1/B2),
`sensitive_variable_count` (E1), `write_access_count` (F3),
`custom_permission_count` (F5), `enforcement_level_category` (G1), and
`two_factor_requirement_enabled` (K). All six were spot-checked against
their corresponding `security_rules/terraform_cloud.py` rule severities in
this pass and confirmed to be intentional, not accidental drift.

## Tracked-fields vs. classifier-branch comparison

| Record type | Tracked fields with dedicated classification | Tracked fields using generic fallback (intentional) | Tracked fields that fell through accidentally (fixed this pass) |
|---|---|---|---|
| `terraform_cloud_organization` | `two_factor_requirement_enabled`, `sso_enabled`, `cost_estimation_enabled`, `collaborator_auth_policy_category` | `workspace_count`, `project_count`, `policy_set_count`, `variable_set_count`, `team_count_category` — pure structural counts with no independent directional risk signal (org-level policy/variable-set enforcement is already tracked precisely at the individual `terraform_cloud_policy_set`/`terraform_cloud_variable_set` record level) | none |
| `terraform_cloud_workspace` | `auto_apply`, `global_remote_state`, `vcs_connected`, `execution_mode_category`, `queue_all_runs`, `speculative_enabled`, `run_trigger_count`, `team_access_count`, `variable_count`, `sensitive_variable_count`, `terraform_version_category` | `file_triggers_enabled`, `working_directory_present`, `trigger_prefix_count`, `non_sensitive_variable_count`, `environment_variable_count`, `terraform_variable_count`, `notification_count`, `current_state_version_present`, `latest_run_status_category` — either purely structural/cosmetic, or the risky combination is already captured by a more specific sibling field (e.g. `unprotected_non_sensitive_count` on the variable-summary record type) | none |
| `terraform_cloud_project` | `team_access_count` | — | **`team_access_count` (this pass)** |
| `terraform_cloud_variable_set` | `global_scope`, `sensitive_variable_count`, `workspace_count` | `project_count`, `variable_count`, `non_sensitive_variable_count`, `environment_variable_count`, `terraform_variable_count` — same rationale as workspace | none |
| `terraform_cloud_workspace_variable_summary` | `sensitive_variable_count`, `unprotected_non_sensitive_count` | `variable_count`, `non_sensitive_variable_count`, `environment_variable_count`, `terraform_variable_count` — same rationale | none |
| `terraform_cloud_policy_set` | `global_scope`, `enforcement_level_category`, `policy_count`, `workspace_count` | `project_count` — structural count, redundant with `workspace_count` | **`vcs_connected` (this pass)** |
| `terraform_cloud_notification_configuration` | `webhook_url_scheme_category`, `token_present`, `enabled`, `destination_type_category`, `trigger_count` | `webhook_url_present` — a flip from `true`→`false` on this field is subsumed by the `enabled` field's own explicit branch, and has no independent risk signal | none |
| `terraform_cloud_team_access_summary` | `team_access_count`, `admin_access_count`, `write_access_count`/`apply_access_count`, `plan_access_count`, `custom_permission_count`, `read_access_count` | — (full coverage) | none (fixed in `7fa4e65`) |
| `terraform_cloud_run_trigger` | (add/remove via `change_type`) | `sourceable_type_category` — no independent risk signal beyond add/remove | none |
| `terraform_cloud_state_version_summary` | `state_version_present` | `state_version_count_category` — a count bucket with no directional risk implication | none |

**Classifier branches referring to fields not emitted by the connector/schema:**
none found. Every `fp ==` check in `risk_rules/terraform_cloud.py` was
cross-referenced against `terraform_cloud_schema.py`'s `TypedDict`
definitions; all matched field names exist in the schema, including
`apply_access_count` (accepted as an alias check alongside
`write_access_count` for forward compatibility, though the schema only
emits `write_access_count` today — this is a defensive alias, not a stale
reference, and is harmless since it can never match a real record).

**Classifier branches referring to old/stale field names:** none — this
was the exact bug fixed in `7fa4e65` (`old_value` → `prev_value`); no
further stale names were found in this pass.

## `old_value`/`prev_value` regression verification

```
grep -n "old_value\|prev_value" backend/app/services/risk_rules/terraform_cloud.py
```
→ 5 matches, all `_get(change, "prev_value")` — production code is clean.

```
grep -rn "old_value" backend/tests/*terraform_cloud*
```
→ only `test_milestone88a_terraform_cloud_drift_provider_foundation.py`,
and only as the `_make_change(..., old_value=...)` **parameter name**
(which is correctly mapped internally to `change.prev_value` — see the
helper's docstring, itself written during the `7fa4e65` fix to explain why
this exact mismatch class is dangerous). No other Terraform Cloud test
file references `old_value` at all.

Confirmed present and passing:
- A dict-shaped (non-`MagicMock`) regression test exists:
  `test_classifier_reads_real_compute_diff_dict_shape_not_a_mock`.
- The `_make_change` mock helper sets `change.prev_value`, matching real
  `compute_diff`/`Change` output.
- No test in the Terraform Cloud suite hides a field-name mismatch behind
  a mock that agrees with buggy production code.

**No old_value/prev_value issue remains.**

## Totals

| Metric | Count |
|---|---|
| Total classification cases reviewed | 33 (A1–M, all rows above) |
| PASS (already correct) | 23 |
| FAIL | 0 |
| GAP → FIXED (missing classification branch) | 2 (F7/F8 project team access, I1/I2 policy set VCS — counted as 2 field-level gaps across 4 table rows) |
| FIXED (wording-only, severity was already correct) | 2 (A4 auto_apply, D3 global_remote_state) |
| FIXED (wording + severity) | 1 (J variable_set.global_scope unknown transition) |
| N/A (not modeled, correctly absent) | 3 (C3 VCS repo identifier, E3 per-variable sensitive flag, G2 enforcement fully disabled) |
| New Security Finding rules added | 0 (classification-layer pass only) |
| Previously detected changes now confirmed misclassified before this pass | 3 (A4, D3, J — all in the truthy/unknown wording family) |
| Previously undetected changes | 0 (all tracked fields already classify; the 2 gaps fell through to the generic fallback, which does classify — just not risk-appropriately) |

## Fixes made

1. **`backend/app/services/risk_rules/terraform_cloud.py`**
   - `_classify_workspace_change`: `auto_apply` and `global_remote_state`
     now use `_is_falsy_explicit` to distinguish an explicit disable from
     an unknown/missing transition, with accurate wording for the latter.
   - `_classify_variable_set_change`: `global_scope` given the same
     explicit/unknown distinction (this one also changes severity: unknown
     was previously miscategorized as the explicit-removal `medium` case).
   - `_classify_policy_set_change`: added a `vcs_connected` branch
     (medium on disconnect, low on reconnect/unknown) — previously fell
     through to the generic fallback.
   - `_classify_project_change`: added a `team_access_count` branch
     (medium on increase, low on decrease/unknown) — previously only
     handled `added`/`removed` change types.
2. **`backend/tests/test_milestone88a_terraform_cloud_drift_provider_foundation.py`**
   — added 12 new tests: wording/severity coverage for the 3 fixed
   unknown-transition cases, restoration/improvement coverage for
   `global_remote_state`/`vcs_connected`, the 2 new gap-fix classifications
   (both directions each), and a sync test
   (`test_every_tracked_field_classifies_without_error_or_invalid_severity`)
   that exercises every tracked field of every record type through the
   classifier to catch future `TypeError`/`KeyError`/invalid-severity
   regressions without needing to enumerate every field explicitly.
3. **`backend/tests/reports/terraform_cloud_change_classification_matrix.md`**
   — this report.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone88a_terraform_cloud_drift_provider_foundation.py -q
# 86 passed (was 75 after 7fa4e65; +11 net new in this pass — 12 added,
# 1 accounted for by a pre-existing test already covering an overlapping case)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "terraform_cloud and risk"
# 164 passed, 16795 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "terraform_cloud and diff"
# 13 passed, 16946 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "terraform_cloud"
# 701 passed, 16258 deselected (was 690 after 7fa4e65)
```

No frontend files were touched in this pass — no new Security Finding rule
was added, only Change-classification logic and tests — so
`npx tsc --noEmit` was not run.
