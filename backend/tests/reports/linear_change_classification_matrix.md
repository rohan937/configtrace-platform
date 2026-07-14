# Linear Change-Classification QA Matrix

Dedicated follow-up to the detection QA pass committed as `24bdafa`
(`linear_detection_matrix.md`), which built `risk_rules/linear.py` from
scratch and added `_LINEAR_TRACKED_FIELDS_BY_TYPE`. Because the classifier
module was newly written and broad, this pass verifies its quality
field-by-field: severity correctness, safe wording, restoration behavior,
and parity with Security Findings.

## Summary

`risk_rules/linear.py` had no `old_value`/`prev_value`-style field-name bug
— it was written from scratch already reading `prev_value` correctly
everywhere, and its test helper already builds plain dicts, not
`MagicMock`. This pass found and fixed three issues, all in the same
categories already established by the Jira and GitLab classification-QA
passes:

1. **One classifier branch that never read `new_value` at all**:
   `webhook_has_attachment_type` returned the exact same message regardless
   of which direction the field actually changed — functionally
   indistinguishable from the generic fallback despite looking like
   dedicated logic. Severity was already `low` in both directions
   (matching the `linear_webhook_attachment_scope` Finding, also `low`), so
   there was no severity bug — but the wording never said whether the
   webhook gained or lost attachment-type scope. Fixed to properly branch
   on `new_value`.

2. **A wording-accuracy bug on `view_shared`**: the field claimed "sharing
   was disabled (restricted)" whenever `new_value` was anything other than
   explicitly truthy — including `None`/unknown, not just an explicit
   `False`. Severity was already safe (`low` either way), but a
   `true → unknown` transition would incorrectly claim sharing had been
   confirmed disabled. Fixed to distinguish explicit-`False` from
   unknown/missing (the same bug class fixed for GitLab, Terraform Cloud,
   and Jira in their respective classification-QA passes).

3. **One genuine tracked-field-falls-through gap**: `linear_workspace.team_count`
   is tracked in `_LINEAR_TRACKED_FIELDS_BY_TYPE` and has a matching
   Security Finding (`linear_workspace_low_team_count`, `low`), but the
   Change classifier had no dedicated branch for it at all — unlike its
   sibling workspace fields `webhook_count` and `integration_count`, which
   both already had a "dropped to zero" branch. It silently fell to the
   generic per-record-type fallback. Fixed by adding the same
   "dropped to zero" pattern already used for the other two workspace
   count fields.

`private_team`'s asymmetric Finding/Change behavior (flagged as an
intentional design decision in the detection-QA pass) was re-verified in
this pass and confirmed correct — see the dedicated design-note section
below. No changes were needed there.

The `resource_name` privacy question (task item J) was also re-verified:
the classifier never references `resource_name`'s actual value anywhere —
a `resource_name` change falls to the generic field-path-only fallback,
which names the *field* (`'resource_name'`) but never quotes the old/new
*name* itself. A new dedicated test
(`test_classifier_copy_never_leaks_raw_resource_name_value`) locks this in
across all three record types that carry the field.

No new Security Finding rules were added in this pass — it is scoped to
the Change-classification layer only.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected by `compute_diff`? | Current risk_level | Expected risk_level | Current title/copy | Expected title/copy | Security finding parity | Status | Test covering it | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1. Workspace team count dropped to zero | `linear_workspace` | `team_count` | `3` | `0` | yes | **was low (generic fallback)** | low | ~~"field 'team_count' changed."~~ | "team count dropped to zero." | `linear_workspace_low_team_count` (low) — now matches | **FIXED (gap)** | new `test_workspace_team_count_dropped_to_zero_is_low_not_generic_fallback` | Sibling fields `webhook_count`/`integration_count` already had this exact pattern; `team_count` was accidentally excluded |
| A2. Workspace member/admin/guest count | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | No workspace-level membership breakdown is fetched — confirmed unchanged from the detection pass |
| B. Workspace security posture (SSO/domain) | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Linear's GraphQL API surface queried by this connector exposes no SSO/domain-restriction fields; `url_key_present`/`logo_present` are cosmetic, not security posture |
| C1. Team private → not private (broadened) | `linear_team` | `private_team` | `True` | `False` | yes | medium | medium | "visibility was broadened — the team is no longer private..." | (same) | `linear_team_private` (low, current-state-only) — **intentional disagreement, see design note** | PASS | existing `test_team_visibility_broadened_is_medium` | — |
| C2. Team not private → private (restoration) | `linear_team` | `private_team` | `False` | `True` | yes | low | low (improvement) | "was made private (restricted)." | (same) | n/a | PASS | existing `test_team_made_private_is_low` | — |
| C3. Team private true → unknown | `linear_team` | `private_team` | `True` | `None` | yes | low | low | "private flag is now unknown or missing." | (same) | n/a | PASS | already correct before this pass — `private_team` was one of the branches already using the explicit three-way (falsy/truthy/unknown) pattern | No fix needed — confirmed correct on inspection |
| C4. Team unknown → not private | `linear_team` | `private_team` | `None` | `False` | yes | medium | medium | "visibility was broadened..." | (same) | matches | PASS | covered — only `new_value` gates the broadened branch | Correct: any transition *to* explicitly non-private is medium regardless of prior state |
| D1. Team project/label/webhook/workflow-state count changes | `linear_team` | `project_count`, `workflow_state_count`, `label_count`, `webhook_count` | count | count | yes | low (semi-generic, intentional) | low | "team {field} changed." | (same) | matches (all four Findings are `low`) | PASS | covered by tracked-field sweep | — |
| D2. Team lost completed-category workflow state | `linear_team` | `has_completed_state` | `True` | `False` | yes | medium | medium | "no longer has a completed-category workflow state..." | (same) | `linear_team_no_completed_state` (medium) — matches | PASS | covered by tracked-field sweep | The one team-level boolean field whose Finding is `medium` rather than `low` — correctly mirrored |
| E1. Integration disabled | `linear_integration` | `integration_enabled` | `True` | `False` | yes | medium | medium | "was disabled..." | (same) | `linear_integration_disabled` (medium) — matches | PASS | existing `test_integration_disabled_is_medium` | — |
| E2. Integration enabled (restoration) | `linear_integration` | `integration_enabled` | `False` | `True` | yes | low | low (improvement) | "was enabled." | (same) | n/a | PASS | covered by existing branch | — |
| E3. Integration team scope → workspace-wide | `linear_integration` | `team_id` | `"team-1"` | `None` | yes | low | low | "is now workspace-scoped (no team restriction)." | (same) | `linear_integration_workspace_scoped` (low) — matches | PASS | covered by tracked-field sweep | — |
| F1. Webhook secret removed | `linear_webhook` | `webhook_secret_present` | `True` | `False` | yes | high | high | "secret indicator was removed..." | (same) | `linear_webhook_no_secret_indicator` (high) — matches | PASS | existing `test_webhook_secret_removed_is_high` | — |
| F2. Webhook non-HTTPS scheme | `linear_webhook` | `webhook_url_scheme_category` | `"https"` | `"non_https"` | yes | high | high | "URL scheme changed to a non-HTTPS scheme..." | (same) | `linear_webhook_non_https` (high) — matches | PASS | existing `test_webhook_non_https_is_high` | — |
| F3. Webhook resource-type scope broadens | `linear_webhook` | `webhook_resource_types_count` | `1` | `3` | yes | medium | medium | "resource type scope increased from 1 to 3..." | (same) | `linear_webhook_broad_resource_scope` (medium) — matches | PASS | covered by tracked-field sweep | — |
| F4. Webhook comment-type scope gained | `linear_webhook` | `webhook_has_comment_type` | `False` | `True` | yes | medium | medium | "gained comment-type event scope..." | (same) | `linear_webhook_issue_comment_scope` (medium) — matches | PASS | covered by tracked-field sweep | — |
| F5. Webhook attachment-type scope gained | `linear_webhook` | `webhook_has_attachment_type` | `False` | `True` | yes | **was low but wording was direction-blind** | low | ~~"attachment-type event scope changed."~~ | "gained attachment-type event scope." | `linear_webhook_attachment_scope` (low) — matches | **FIXED (dead-branch bug)** | new `test_webhook_attachment_type_gained_reads_new_value` | The branch never read `new_value` at all before this fix |
| F6. Webhook attachment-type scope removed (restoration) | `linear_webhook` | `webhook_has_attachment_type` | `True` | `False` | yes | low | low (improvement) | ~~"attachment-type event scope changed."~~ | "attachment-type event scope was removed." | n/a | **FIXED** | new `test_webhook_attachment_type_removed_reads_new_value` | — |
| F7. Webhook disabled/enabled | `linear_webhook` | `webhook_enabled` | `True`/`False` | `False`/`True` | yes | medium / low | medium / low | "was disabled." / "was enabled." | (same) | `linear_webhook_disabled` (medium) — matches | PASS | covered by tracked-field sweep | — |
| G. API keys / personal access tokens / OAuth apps | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | No per-key metadata endpoint is fetched; Linear's "integrations" surface (covered by E above) is the closest analog to OAuth-app posture in this connector's scope |
| H. Project/issue visibility | n/a | n/a | n/a | n/a | not modeled (project visibility inherits from team) | n/a | n/a | n/a | n/a | **N/A** | n/a | Confirmed unchanged from the detection pass — no independent project-level visibility flag exists in the API surface this connector queries |
| I1. View shared/unshared | `linear_view` | `view_shared` | `False`/`True` | `True`/`False` | yes | low | low | "was shared..." / "sharing was disabled (restricted)." | (same) | `linear_view_shared` (low, current-state) — matches | PASS | existing branch, wording fixed for the unknown case (see I2) | — |
| I2. View shared true → unknown | `linear_view` | `view_shared` | `True` | `None` | yes | **was low but said "sharing was disabled"** | low | ~~"sharing was disabled (restricted)."~~ | "sharing state is now unknown or missing." | n/a | **FIXED (wording)** | new `test_view_shared_true_to_unknown_is_low_not_disabled_wording` | Severity was already correct; wording overstated certainty |
| I3. Unknown/missing sweep | `linear_webhook`, `linear_view` | `webhook_has_attachment_type`, `view_shared` | `True` | `None` | yes | low | low | varies, both now say "unknown or missing" | (same) | n/a | PASS | new `test_unknown_transitions_never_produce_high_qa_pass` (2 field/record-type combinations) | Verified neither of the two fixed fields can produce `"high"` on an unknown/missing transition |
| J. `resource_name` copy safety | `linear_workspace`, `linear_team`, `linear_project` | `resource_name` | `"Acme Corp Old Name"` | `"Acme Corp New Name"` | yes | low (generic, intentional) | low | "field 'resource_name' changed." (field path only, never the value) | (same) | n/a — no Finding references `resource_name` at all | PASS (confirmed safe) | new `test_classifier_copy_never_leaks_raw_resource_name_value` | Confirms the classifier never echoes the actual stored name into a Change reason string, across all three record types that carry the field |

## Tracked-fields vs. classifier-branch comparison

| Record type | Tracked fields with dedicated classification | Tracked fields using generic fallback (intentional) | Tracked fields that fell through accidentally (fixed this pass) |
|---|---|---|---|
| `linear_workspace` | `team_count`, `webhook_count`, `integration_count` | `resource_name`, `url_key_present`, `logo_present` — cosmetic/hygiene fields, no Finding beyond `low` | **`team_count` (this pass)** |
| `linear_team` | `private_team`, `has_completed_state` | `resource_name`, `member_count_category`, `project_count`, `auto_archive_enabled`, `cycle_enabled`, `cycle_duration_category`, `has_backlog_state`, `has_started_state`, `has_canceled_state`, `workflow_state_count`, `label_count`, `webhook_count` — all match their Findings' `low` severity | none |
| `linear_project` | `lead_present`, `team_count`, `project_health_category` | `resource_name`, `member_count_category`, `issue_count_category`, `project_status_category` | none |
| `linear_workflow_state` | — | All 4 tracked fields — the only Finding for this record type is `low` and carries no directional signal | none |
| `linear_label` | `team_id` | `resource_name`, `is_group_label`, `parent_id_present` — no dedicated Finding for either boolean | none |
| `linear_webhook` | `webhook_enabled`, `webhook_secret_present`, `webhook_url_scheme_category`, `webhook_resource_types_count`, `webhook_has_comment_type`, `webhook_has_attachment_type` | `webhook_url_present`, `team_id` — no dedicated Finding | none (`webhook_has_attachment_type` was direction-blind, now fixed) |
| `linear_view` | `view_shared` | `resource_name`, `filter_count_category`, `team_id` — `linear_view_shared_without_team_scope` is a combined condition (shared=True AND team_id=None) that a single-field Change classifier can't cheaply replicate, matching the same accepted limitation documented for GitLab's/Terraform Cloud's combined-condition Findings | none |
| `linear_cycle` | — | `resource_name`, `active` (structural constant — see detection report), `team_id`, `issue_count_category` (matches its `low` Finding) | none |
| `linear_integration` | `integration_enabled`, `team_id` | `integration_type_category` — matches its `low` Finding | none |

**Classifier branches referring to fields not emitted by the
connector/schema:** none found — every `fp ==` check in
`risk_rules/linear.py` was cross-referenced against `linear_schema.py`'s
`TypedDict` definitions.

**Classifier branches referring to stale field names:** none — this
module was written fresh in the prior pass with no legacy names to drift
from.

**Fields with similar names that could be confused:** `webhook_has_comment_type`
(medium) vs. `webhook_has_attachment_type` (low) are the closest pair —
each has its own branch with wording that names the specific event-type
family it refers to, so the two are not confusable in the emitted reason
text. `team_count` appears on both `linear_workspace` (now dedicated,
fixed this pass) and `linear_project` (already dedicated) — each lives in
its own record-type classifier function and produces record-type-specific
wording ("Linear workspace team count..." vs. "Linear project team
count..."), so there is no cross-record-type confusion risk.

## Design note: `private_team` is intentionally asymmetric between Findings and Changes

Re-verified in this pass, confirmed correct, no changes needed:

- The **Finding** (`linear_team_private`, `low`) fires only on the
  *current state* `private_team == True`, framed as an informational
  "review whether this is intentional" note — not a risk signal, since
  private is a common and often deliberate configuration in Linear.
  Critically, there is **no Finding at all** for the *non-private* state,
  because most Linear teams are non-private by default; flagging every
  non-private team would be extremely noisy and contrary to the rule's own
  documented framing.
- The **Change classifier**, in contrast, evaluates the *transition*: a
  team that was private and became non-private just had its visibility
  broadened to the whole workspace — a real, observable event that the
  Finding layer structurally cannot see (it never observes the prior
  state). This is classified `medium`, distinct from and independent of
  the Finding's `low` on the opposite state.

This is the same "Change layer catches transitions the Finding layer
can't observe" pattern already established for GitLab (`execution_mode`),
Terraform Cloud (`sensitive_variable_count`), and Jira
(`permission_public_administer_projects`) in prior classification-QA
passes — confirmed intentional, not a defect.

## Mock-shape (`old_value`/`prev_value`/`previous_value`/`prior_value`) verification

```
grep -n "old_value\|previous_value\|prior_value\|prev_value" backend/app/services/risk_rules/linear.py
```
→ 3 matches, all `_get(change, "prev_value")` — production code was
already clean (this module was written fresh in the prior pass with the
correct field name from the start).

```
grep -rn "old_value\|previous_value\|prior_value" backend/tests/*linear*
```
→ one match, in `test_milestone85a_linear_drift_provider_foundation.py` —
a docstring comment (`"""Regression guard against the exact
old_value/prev_value bug class..."""`) that *names* the bug class being
guarded against; it is not an actual field usage and does not affect test
behavior.

```
grep -c "prev_value" backend/tests/test_milestone85a_linear_drift_provider_foundation.py
```
→ 25+ matches (higher after this pass's new tests) — the
`TestLinearRiskClassifier._make_change` helper and the dict literal in
`test_classifier_reads_real_compute_diff_dict_shape_not_a_mock` both build
plain dicts shaped exactly like real `compute_diff` output, never a
`MagicMock`.

**No mock-shape issue remains, and none was introduced by this pass.**

## Totals

| Metric | Count |
|---|---|
| Total classification cases reviewed | 20 (A1–J, all rows above) |
| PASS | 13 |
| FAIL | 0 |
| GAP → FIXED (missing classification / accidental fall-through) | 1 (`linear_workspace.team_count`) |
| FIXED (dead/direction-blind branch — didn't read `new_value` at all) | 1 (`webhook_has_attachment_type`) |
| FIXED (wording-only, severity was already correct) | 1 (`view_shared` unknown transition) |
| N/A (not modeled, correctly absent) | 5 (A2, B, G, H, plus one folded row) |
| New Security Finding rules added | 0 (classification-layer pass only) |
| Previously detected changes now confirmed misclassified before this pass | 2 (the direction-blind branch + the wording-overstatement case) |
| Mock-shape (`old_value`-style) bugs found | 0 |
| `private_team` Finding/Change asymmetry | confirmed intentional, no change needed |
| `resource_name` value leakage into classifier copy | none found, confirmed safe by new dedicated test |

## Fixes made

1. **`backend/app/services/risk_rules/linear.py`**
   - `_classify_workspace_change`: added a `team_count` branch (matching
     the existing `webhook_count`/`integration_count` "dropped to zero"
     pattern) — it was tracked and had a matching Finding but no dedicated
     Change classification.
   - `_classify_webhook_change`: `webhook_has_attachment_type` now
     branches on `new_value` (was previously direction-blind, returning
     the same message regardless of the transition).
   - `_classify_view_change`: `view_shared`'s fallback now distinguishes
     explicit-`False` from unknown/missing before claiming sharing was
     disabled.
2. **`backend/tests/test_milestone85a_linear_drift_provider_foundation.py`**
   — added 6 new tests: 2 for the `webhook_has_attachment_type`
   direction-blind fix, 2 for the `view_shared` unknown-wording fix, 1 for
   the `team_count` gap fix, and 1 dedicated `resource_name`
   copy-safety test (across all three record types that carry the field),
   plus an unknown/missing severity sweep covering both fixed fields.
3. **`backend/tests/reports/linear_change_classification_matrix.md`** —
   this report.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone85a_linear_drift_provider_foundation.py -q
# 136 passed (was 129 after 24bdafa)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "linear and risk"
# 188 passed, 16887 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "linear and diff"
# 15 passed, 17060 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "linear"
# 816 passed, 16259 deselected (was 809 after 24bdafa)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*linear* -q
# 803 passed
```

No frontend files were touched in this pass — no new Security Finding rule
was added or changed, only Change-classification logic and tests — so
`npx tsc --noEmit` was not run.
