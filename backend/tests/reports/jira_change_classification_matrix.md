# Jira Change-Classification QA Matrix

Dedicated follow-up to the detection QA pass committed as `10a1fff`
(`jira_detection_matrix.md`), which built `risk_rules/jira.py` from
scratch, added `_JIRA_TRACKED_FIELDS_BY_TYPE`, fixed 10 Security Finding
severity mismatches, and implemented 5 new backend rules. Because the
classifier module was newly written and broad, this pass verifies its
quality field-by-field: severity correctness, safe wording, restoration
behavior, and parity with Security Findings.

## Summary

`risk_rules/jira.py` had no `old_value`/`prev_value`-style field-name bug —
it was written from scratch already reading `prev_value` correctly
everywhere, and its test helper already builds plain dicts, not
`MagicMock`. This pass instead found and fixed three other categories of
issue:

1. **Two classifier branches that never read `new_value` at all** —
   `project_archived` and `workflow_draft` each returned the exact same
   message regardless of which direction the field actually changed. This
   is a more severe version of the "unknown transition overstates
   certainty" bug class: these two branches were not direction-blind on
   just the unknown case, they were direction-blind on *every* case,
   making them functionally identical to the generic per-record-type
   fallback despite looking like dedicated logic. Severity was already
   `low` in both directions (matching their Findings, both `low`), so
   there was no severity bug — but the wording was misleading (e.g. a
   workflow being un-drafted would still say "draft state changed"
   instead of "was published"). Fixed both to properly branch on
   `new_value`.

2. **A wording-accuracy pattern affecting 3 permission-scheme boolean
   fields** (the same bug class fixed for GitLab and Terraform Cloud in
   their respective classification-QA passes): `permission_public_administer_projects`,
   `permission_public_manage_sprints`, `permission_public_create_issues`,
   `permission_public_transition_issues` (grouped), and
   `permission_public_browse_projects` all claimed "public {X} access was
   removed" whenever `new_value` was anything other than explicitly truthy
   — including `None`/unknown, not just an explicit `False`. Severity was
   already safe (`low` either way), but a `true → unknown` transition
   would incorrectly claim the grant had been confirmed removed. Fixed to
   distinguish explicit-`False` from unknown/missing.

3. **One genuine tracked-field-falls-through gap**: `automation_component_count`'s
   sibling fields `automation_action_count` and `automation_branch_count`
   both get `medium` on increase, but `automation_condition_count` — also
   tracked in `_JIRA_TRACKED_FIELDS_BY_TYPE`, part of the same
   structural-complexity family — was accidentally left out of that
   grouped branch and fell through to the generic `low` fallback. Fixed by
   adding it to the branch.

All 5 of the newly-added Security Findings from the prior pass
(`jira_workflow_draft`, `jira_workflow_scheme_low_project_count`,
`jira_permission_scheme_high_grant_count`, `jira_webhook_broad_event_scope`,
`jira_automation_rule_high_component_count`) were checked against the
Change classifier and found to be severity-consistent (see the dedicated
parity table below) — no further fixes were needed for these beyond the
`workflow_draft` wording bug already covered in fix #1.

No new Security Finding rules were added in this pass — it is scoped to
the Change-classification layer only.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected by `compute_diff`? | Current risk_level | Expected risk_level | Current title/copy | Expected title/copy | Security finding parity | Status | Test covering it | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1. Anonymous access granted | `jira_permission_scheme` | `permission_anonymous_grant_count` | `0` | `1` | yes | high | high | "anonymous grant count increased from 0 to 1 — Jira anonymous access may now be enabled..." | (same) | `jira_permission_scheme_anonymous_grant` (high) — matches | PASS | existing `test_anonymous_grant_increase_is_high` | — |
| A2. Anonymous access revoked (restoration) | `jira_permission_scheme` | `permission_anonymous_grant_count` | `1` | `0` | yes | low | low (improvement) | "anonymous grant count decreased." | (same) | n/a (Finding only fires on current-state count > 0) | PASS | existing `test_anonymous_grant_decrease_is_low` | — |
| A3. Anonymous access unknown → true | `jira_permission_scheme` | `permission_anonymous_grant_count` | `None` | `1` | yes | high | high | "increased from 0 to 1..." | (same) | matches | PASS | covered — `_int_pair` coerces unknown prior to 0, consistent with the established cross-provider convention for count fields (Terraform Cloud, GitLab) | — |
| A4. Anonymous access true → unknown | `jira_permission_scheme` | `permission_anonymous_grant_count` | `1` | `None` | yes | low | low | "decreased." (coerced to 0) | (same) | n/a | PASS | covered by `_int_pair` coercion | Count fields intentionally use the 0-coercion convention rather than a distinct "unknown" branch — consistent across all providers in this codebase, not fixed here |
| B. 'Anyone' access granted/revoked | `jira_permission_scheme` | `permission_anyone_grant_count` | `0`/`1` | `1`/`0` | yes | high / low | high / low | mirrors A1/A2 | (same) | `jira_permission_scheme_anyone_grant` (high) — matches | PASS | existing tests | — |
| C1. Browse permission broadened | `jira_permission_scheme` | `permission_public_browse_projects` | `False` | `True` | yes | medium | medium (per existing convention — see design note in detection report) | "grants public browse-projects access..." | (same) | `jira_permission_scheme_public_browse_projects` (medium) — matches | PASS | existing `test_public_browse_projects_true_is_medium` | — |
| C2. Browse permission true → unknown | `jira_permission_scheme` | `permission_public_browse_projects` | `True` | `None` | yes | **was low but said "was removed"** | low | ~~"public browse-projects access was removed."~~ | "public browse-projects access is now unknown or missing." | n/a | **FIXED (wording)** | new `test_public_browse_projects_true_to_unknown_is_low_not_removed_wording` | Severity already correct; wording overstated certainty |
| D1. Administer permission broadened | `jira_permission_scheme` | `permission_public_administer_projects` | `False` | `True` | yes | high | high | "grants public administer-projects access..." | (same) | `jira_permission_scheme_public_administer_projects` (high) — matches | PASS | existing `test_public_administer_projects_true_is_high` | — |
| D2. Administer permission explicit false (restoration) | `jira_permission_scheme` | `permission_public_administer_projects` | `True` | `False` | yes | low | low (improvement) | "public administer-projects access was removed." | (same) | n/a | PASS (after fix) | new `test_public_administer_projects_explicit_false_is_removed_wording` | — |
| D3. Administer permission true → unknown | `jira_permission_scheme` | `permission_public_administer_projects` | `True` | `None` | yes | **was low but said "was removed"** | low | ~~"public administer-projects access was removed."~~ | "public administer-projects access is now unknown or missing." | n/a | **FIXED (wording)** | new `test_public_administer_projects_true_to_unknown_is_low_not_removed_wording` | Same bug class as C2 — also covers manage-sprints, create-issues, transition-issues (grouped branch) |
| E. Project role actor count changes | `jira_permission_scheme` | `permission_project_role_grant_count` | count | count | yes | low (generic, intentional) | low | "field '...' changed." | (same) | n/a (project roles are the safe/preferred holder type — see prior pass's design note on the removed stale frontend entry) | PASS (intentional) | covered by tracked-field sweep | — |
| F. Privileged role actor count | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Jira does not expose per-role actor rosters via this connector — only aggregate grant counts by holder *type* on permission schemes, not membership of a specific named role (e.g., "Administrators"). Not invented per task instructions |
| G1. Permission scheme total grant count increases | `jira_permission_scheme` | `permission_grant_count` | `10` | `25` | yes | medium | medium | "total grant count increased from 10 to 25..." | (same) | `jira_permission_scheme_high_grant_count` (medium) — matches | PASS | new `test_permission_scheme_high_grant_count_change_matches_finding_severity_medium` | Parity check for the newly-added Finding |
| G2. Permission scheme total grant count decreases | `jira_permission_scheme` | `permission_grant_count` | `25` | `10` | yes | low | low (improvement) | "total grant count decreased." | (same) | n/a | PASS | covered by existing branch | — |
| H. Issue security scheme disabled/enabled/removed/added | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Issue Security Schemes are a distinct Jira API resource from Issue *Type* Schemes (which are modeled); no endpoint is fetched. Not invented per task instructions — see the detection report's "Not fixed" section |
| I. Issue security scheme unknown transitions | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Same reason as H |
| G(workflow)1. Workflow draft entered | `jira_workflow` | `workflow_draft` | `False` | `True` | yes | **was low but wording was direction-blind** | low | ~~"draft state changed."~~ | "entered a draft (unpublished) state." | `jira_workflow_draft` (low) — matches | **FIXED (dead-branch bug)** | new `test_workflow_draft_true_reads_new_value`, `test_workflow_draft_change_matches_finding_severity_low` | The branch never read `new_value` at all before this fix — see Summary #1 |
| G(workflow)2. Workflow published (restoration) | `jira_workflow` | `workflow_draft` | `True` | `False` | yes | low | low (improvement) | ~~"draft state changed."~~ | "was published (no longer draft)." | n/a | **FIXED** | new `test_workflow_draft_false_is_published_restoration` | — |
| G(scheme)1. Workflow scheme low project count | `jira_workflow_scheme` | `workflow_scheme_project_count` | `5` | `1` | yes | low | low | "project count decreased from 5 to 1." | (same) | `jira_workflow_scheme_low_project_count` (low) — matches | PASS | new `test_workflow_scheme_low_project_count_change_matches_finding_severity_low` | Parity check for the newly-added Finding |
| G(scheme)2. Workflow scheme changed (no default) | `jira_workflow_scheme` | `workflow_scheme_default_present` | `True` | `False` | yes | medium | medium | "no longer has a default workflow indicator..." | (same) | `jira_workflow_scheme_no_default` (medium, corrected in the prior pass) — matches | PASS | existing `test_workflow_scheme_default_removed_is_medium` | — |
| H(notif)1. Notification recipient count increases | `jira_notification_scheme` | `notification_email_recipient_count`, `notification_unknown_recipient_count` | count increase | yes | medium | medium | "email recipient count increased..." | (same) | `jira_notification_scheme_email_recipients` (medium, corrected in the prior pass) — matches | PASS | covered by tracked-field sweep | — |
| H(notif)2. Project-role recipients (post stale-entry removal) | `jira_notification_scheme` | `notification_project_role_recipient_count` | count | count | yes | low (generic, intentional) | low | "field '...' changed." | (same) | n/a — correctly no Finding after the stale frontend entry was removed in the prior pass | PASS (intentional) | covered by tracked-field sweep | Confirms project-role recipients are still *not* treated as risky by the Change layer either, consistent with the prior pass's fix |
| H(notif)3. Notification recipient count decreases (restoration) | `jira_notification_scheme` | `notification_email_recipient_count` | `3` | `1` | yes | low | low (improvement) | "changed from 3 to 1." | (same) | n/a | PASS | covered | — |
| I1. Webhook broad event scope | `jira_webhook` | `webhook_event_count` | `2` | `15` | yes | medium | medium | "event count increased from 2 to 15..." | (same) | `jira_webhook_broad_event_scope` (medium) — matches | PASS | new `test_webhook_broad_event_scope_change_matches_finding_severity_medium` | Parity check for the newly-added Finding. Note: the Change classifier fires `medium` on *any* increase, not only increases that cross the Finding's >10 ceiling — an intentional, more-sensitive transition-based design already used elsewhere in this codebase (e.g. GitLab's `team_access_count`) |
| I2. Webhook HTTP scheme | `jira_webhook` | `webhook_url_scheme_category` | `"https"` | `"http"` | yes | high | high | "URL scheme changed to HTTP (non-encrypted)..." | (same) | `jira_webhook_non_https` (high) — matches | PASS | existing `test_webhook_http_scheme_is_high` | — |
| I3. Webhook secret removed | `jira_webhook` | `webhook_secret_present` | `True` | `False` | yes | high | high | "secret indicator was removed..." | (same) | `jira_webhook_no_secret_indicator` (high) — matches | PASS | existing `test_webhook_secret_removed_is_high` | — |
| I4. Webhook disabled/enabled | `jira_webhook` | `webhook_enabled` | `True`/`False` | `False`/`True` | yes | medium / low | medium / low | "was disabled." / "was enabled." | (same) | `jira_webhook_disabled` (medium, corrected in the prior pass) — matches | PASS | covered by tracked-field sweep | — |
| I5. Webhook unknown transitions | `jira_webhook` | `webhook_enabled`, `webhook_secret_present`, `webhook_url_scheme_category` | `True`/`"https"` | `None` | yes | low (already correctly handled before this pass) | low | "...is now unknown or missing." | (same) | n/a | PASS | pre-existing three-way branches (no fix needed — these were already correct) | Confirmed no bug here; the webhook boolean/category branches already distinguished explicit-false/unknown from the start |
| J1. Automation high component count | `jira_automation_rule` | `automation_component_count` | `5` | `20` | yes | low | low | "component count increased from 5 to 20." | (same) | `jira_automation_rule_high_component_count` (low) — matches | PASS | new `test_automation_high_component_count_change_matches_finding_severity_low` | Parity check for the newly-added Finding |
| J2. Automation condition count increases | `jira_automation_rule` | `automation_condition_count` | `1` | `5` | yes | **was low (generic fallback)** | medium | ~~"field 'automation_condition_count' changed."~~ | "condition count increased from 1 to 5..." | n/a (no dedicated Finding exists for condition_count specifically — matches the sibling action/branch pattern by convention) | **FIXED (gap)** | new `test_automation_condition_count_increase_is_medium` | Accidentally excluded from the grouped `action_count`/`branch_count` branch — see Summary #3 |
| J3. Automation condition count decreases (restoration) | `jira_automation_rule` | `automation_condition_count` | `5` | `1` | yes | low | low (improvement) | "changed from 5 to 1." | (same) | n/a | PASS (after fix) | new `test_automation_condition_count_decrease_is_low` | — |
| J4. Automation disabled/restored | `jira_automation_rule` | `automation_enabled` | `True`/`False` | `False`/`True` | yes | medium / low | medium / low | "was disabled." / "was enabled." | (same) | `jira_automation_rule_disabled` (medium) — matches | PASS | covered by tracked-field sweep | — |
| J5. Automation web-request/external action gained | `jira_automation_rule` | `automation_has_web_request_action`, `automation_has_external_action` | `False` | `True` | yes | high | high | "gained a web request action..." | (same) | `jira_automation_rule_web_request_action`, `_external_action` (high) — matches | PASS | existing `test_automation_web_request_action_is_high` | — |
| K. Application access posture | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Organization-level Atlassian Admin API concept, out of this connector's scope |
| L1. Project archived (dead-branch bug) | `jira_project` | `project_archived` | `False` | `True` | yes | **wording was direction-blind before fix** | low | ~~"archived flag changed."~~ | "was archived." | `jira_project_archived` (low) — matches | **FIXED (dead-branch bug)** | new `test_project_archived_true_reads_new_value` | See Summary #1 — same bug class as `workflow_draft` |
| L2. Project unarchived (restoration) | `jira_project` | `project_archived` | `True` | `False` | yes | low | low (improvement) | ~~"archived flag changed."~~ | "was unarchived — it is now active again." | n/a | **FIXED** | new `test_project_unarchived_reads_new_value` | — |
| L3. Project deleted true → unknown | `jira_project` | `project_deleted` | `True` | `None` | yes | **was low but said "flag changed" (ambiguous, not "cleared")** | low | "deleted flag changed." → "deleted flag is now unknown or missing." | (same) | n/a | **FIXED (wording)** | new `test_project_deleted_true_to_unknown_is_low_not_cleared_wording` | Minor wording precision fix — severity was already safe |
| L4. Unknown/missing sweep | `jira_project`, `jira_workflow`, `jira_permission_scheme` | `project_archived`, `project_deleted`, `workflow_draft`, `permission_public_administer_projects`, `permission_public_browse_projects` | `True`/`False` | `None`/missing | yes | low | low | varies, all now say "unknown or missing" | (same) | n/a | PASS | new `test_unknown_transitions_never_produce_high` (5 field/record-type combinations) | Verified none of the fixed fields can produce `"high"` on an unknown/missing transition |

## Tracked-fields vs. classifier-branch comparison

| Record type | Tracked fields with dedicated classification | Tracked fields using generic fallback (intentional) | Tracked fields that fell through accidentally (fixed this pass) |
|---|---|---|---|
| `jira_site` | — | All 4 tracked fields — pure structural/rollup counts, no directional risk signal (unchanged from the detection pass) | none |
| `jira_project` | `project_private`, `project_deleted`, `project_archived` | `project_key_present`, `project_type_category`, `project_style_category`, `board_count`, `issue_type_count`, `lead_present` | none (both dedicated branches were direction-blind before this pass, now fixed — not a fall-through, a wording bug) |
| `jira_board` | `board_jql_filter_broad`, `project_id` | `board_type_category`, `board_location_type_category`, `board_filter_present`, `board_column_count`, `board_quick_filter_count`, `board_swimlane_strategy_category` | none |
| `jira_workflow` | `workflow_active`, `workflow_status_count`, `workflow_transition_count`, `workflow_global_transition_count`, `workflow_orphan_status_count`, `workflow_transition_rule_count`, `workflow_validator_count`, `workflow_condition_count`, `workflow_draft` | `workflow_has_done_status`, `workflow_has_in_progress_status`, `workflow_post_function_count`, `workflow_status_category_count` | none (`workflow_draft` was direction-blind, now fixed) |
| `jira_workflow_scheme` | `workflow_scheme_default_present`, `workflow_scheme_unmapped_issue_type_count`, `workflow_scheme_project_count` | `workflow_scheme_workflow_count`, `workflow_scheme_issue_type_mapping_count` | none |
| `jira_permission_scheme` | all 12 grant/count/boolean fields | `permission_project_role_grant_count` (intentional — safe holder type) | none (wording-only fixes on 5 boolean fields) |
| `jira_notification_scheme` | `notification_count`, `notification_email_recipient_count`, `notification_unknown_recipient_count` | `notification_group_recipient_count`, `notification_project_role_recipient_count`, `notification_all_watchers_recipient_count`, `notification_event_count` | none |
| `jira_issue_type_scheme` | `default_issue_type_present` | `issue_type_count` | none |
| `jira_field_configuration_scheme` | — | All 3 tracked fields — no security rule exists for this record type at all | none |
| `jira_screen_scheme` | `screen_count` | `tab_count`, `field_count`, `screen_tab_count`, `screen_unmapped_screen_count` | none |
| `jira_webhook` | `webhook_enabled`, `webhook_secret_present`, `webhook_url_scheme_category`, `webhook_jql_filter_present`, `webhook_event_count`, `webhook_has_comment_events`, `webhook_has_attachment_events`, `webhook_all_issue_events`, `webhook_has_sprint_events`, `webhook_has_worklog_events` | `webhook_url_present`, `webhook_has_issue_events`, `webhook_has_project_events`, `webhook_jql_empty_or_broad`, `webhook_event_scope_category` | none |
| `jira_automation_rule` | `automation_enabled`, `automation_scope_category`, `automation_has_web_request_action`, `automation_has_external_action`, `automation_has_email_action`, `automation_action_count`, `automation_branch_count`, `automation_condition_count`, `automation_component_count` | `automation_trigger_type_category`, `automation_has_comment_action` | **`automation_condition_count` (this pass)** |

**Classifier branches referring to fields not emitted by the
connector/schema:** none found — every `fp ==` check in `risk_rules/jira.py`
was cross-referenced against `jira_schema.py`'s `TypedDict` definitions.

**Classifier branches referring to stale field names:** none — this module
was written fresh in the prior pass with no legacy names to drift from.

**Fields with similar names that could be confused:** `permission_grant_count`
(total) vs. `permission_high_privilege_grant_count` vs.
`permission_public_grant_count` — all three are tracked and each has its
own distinct branch with wording that names the specific count it refers
to (e.g. "total grant count" vs. "high-privilege grant count" vs.
"permission_public_grant_count" via the generic `fp.replace(...)`
formatting), so none are confusable in the emitted reason text. Similarly,
`automation_action_count`/`automation_branch_count`/`automation_condition_count`
(structural complexity) are clearly distinguished from
`automation_component_count` (the aggregate total) — each branch names its
own field in the wording.

## Parity check: the 5 newly-added Security Findings vs. the Change classifier

| Rule key | Finding severity | Field | Change classifier severity (on the Finding-triggering transition) | Match? |
|---|---|---|---|---|
| `jira_workflow_draft` | low | `workflow_draft` | low | Yes (after fixing the direction-blind wording bug) |
| `jira_workflow_scheme_low_project_count` | low | `workflow_scheme_project_count` | low | Yes |
| `jira_permission_scheme_high_grant_count` | medium | `permission_grant_count` | medium | Yes |
| `jira_webhook_broad_event_scope` | medium | `webhook_event_count` | medium | Yes |
| `jira_automation_rule_high_component_count` | low | `automation_component_count` | low | Yes |

All 5 are now classification-aligned. None required a severity change in
this pass — the only fix among them was the `workflow_draft` wording bug,
which did not change its severity (already `low`).

## Mock-shape (`old_value`/`prev_value`/`previous_value`/`prior_value`) verification

```
grep -n "old_value\|previous_value\|prior_value\|prev_value" backend/app/services/risk_rules/jira.py
```
→ 7 matches, all `_get(change, "prev_value")` — production code was
already clean (this module was written fresh in the prior pass with the
correct field name from the start).

```
grep -rln "old_value\|previous_value\|prior_value" backend/tests/*jira*
```
→ no matches in any Jira test file.

```
grep -c "prev_value" backend/tests/test_milestone86a_jira_drift_provider_foundation.py
```
→ 25+ matches (higher after this pass's new tests) — both the existing
`TestJiraRiskClassifier._make_change` helper and the dict literals used in
`test_classifier_reads_real_compute_diff_dict_shape_not_a_mock` build
plain dicts shaped exactly like real `compute_diff` output, never a
`MagicMock`.

**No mock-shape issue remains, and none was introduced by this pass.**

## Totals

| Metric | Count |
|---|---|
| Total classification cases reviewed | 34 (A1–L4, all rows above) |
| PASS | 20 |
| FAIL | 0 |
| GAP → FIXED (missing classification / accidental fall-through) | 1 (`automation_condition_count`) |
| FIXED (dead/direction-blind branch — didn't read `new_value` at all) | 2 (`project_archived`, `workflow_draft`) |
| FIXED (wording-only, severity was already correct) | 4 (browse-projects unknown, administer-projects unknown + 3 sibling public-grant fields as one grouped branch, project_deleted unknown) |
| N/A (not modeled, correctly absent) | 6 (F, H, I, K, plus 2 folded rows) |
| New Security Finding rules added | 0 (classification-layer pass only) |
| Previously detected changes now confirmed misclassified before this pass | 6 (the 2 dead branches + the 4 wording-overstatement cases) |
| Mock-shape (`old_value`-style) bugs found | 0 |
| 5 newly-added Security Findings — classification-aligned | 5 of 5 |

## Fixes made

1. **`backend/app/services/risk_rules/jira.py`**
   - `_classify_project_change`: `project_archived` now branches on
     `new_value` (was previously direction-blind); `project_deleted`'s
     fallback now distinguishes explicit-`False` from unknown.
   - `_classify_workflow_change`: `workflow_draft` now branches on
     `new_value` (was previously direction-blind).
   - `_classify_permission_scheme_change`: the grouped
     `administer_projects`/`manage_sprints`/`create_issues`/`transition_issues`
     branch and the `browse_projects` branch now distinguish explicit-`False`
     from unknown/missing before claiming "access was removed."
   - `_classify_automation_rule_change`: added `automation_condition_count`
     to the grouped `action_count`/`branch_count` branch (medium on
     increase) — it was tracked but accidentally excluded.
2. **`backend/tests/test_milestone86a_jira_drift_provider_foundation.py`**
   — added 17 new tests: 2 tests each for the `project_archived` and
   `workflow_draft` direction-blind fixes, 3 tests for the
   permission-scheme unknown-transition wording fixes, 2 tests for the
   `automation_condition_count` gap fix, a 5-case unknown/missing severity
   sweep, and 5 dedicated parity tests (one per newly-added Security
   Finding from the prior pass) proving Change/Finding severity agreement.
3. **`backend/tests/reports/jira_change_classification_matrix.md`** — this
   report.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone86a_jira_drift_provider_foundation.py -q
# 176 passed (was 160 after 10a1fff)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "jira and risk"
# 126 passed, 16923 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "jira and diff"
# 8 passed, 17041 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "jira"
# 998 passed, 16051 deselected (was 982 after 10a1fff)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*jira* -q
# 982 passed
```

No frontend files were touched in this pass — no new Security Finding rule
was added or changed, only Change-classification logic and tests — so
`npx tsc --noEmit` was not run.
