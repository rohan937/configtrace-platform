# GitLab Change-Classification QA Matrix

Dedicated follow-up to the detection QA pass committed as `28412a7`
(`gitlab_detection_matrix.md`). That pass fixed the diff-tracking gap
(0/9 record types tracked → 9/9) and a connector normalization bug
(`gitlab_project.approval_rule_count` was populated from
`approvals_required` instead of the real rule count). This pass verifies
that, now that changes are detected, every one of them is classified with
the correct severity, safe wording, and improvement/restoration behavior,
and checks for remaining generic-fallback gaps, dead classifier branches,
or mock-shape regressions.

## Summary

Unlike Terraform Cloud's equivalent follow-up pass, `risk_rules/gitlab.py`
had **no `old_value`/`prev_value`-style field-name bug** — every
directional comparison already read `prev_value` correctly, and the test
helper already built plain dicts shaped like real `compute_diff` output
(not `MagicMock`). This pass instead found and fixed three other categories
of issue:

1. **A wording-accuracy pattern affecting 7 boolean/categorical fields.**
   Many boolean fields were gated as `if new_v is False (explicit): X; else: Y`
   (or the truthy-gated mirror). The explicit-value branch was always
   severity-safe, but the `else` branch fired on **both** the true opposite
   value **and** an unknown/missing value (`None`), and unconditionally
   claimed the opposite state had been explicitly set. For example,
   `allow_force_push` transitioning from `True` to `None` (unknown) was
   reported as "force push was disabled (hardened)" — factually wrong,
   though the severity (`low`) was already safe. Fixed for:
   `visibility_category` (project and group — the `else` branch also
   wrongly said "changed to a more restrictive setting" even when the new
   value was `"unknown"`, not `"private"`), `allow_force_push`,
   `ssl_verification_enabled`, `secret_token_present`, `url_scheme`,
   `membership_lock` (group).

2. **Four genuine classification gaps** — tracked, normalized fields that
   fell through to the generic per-record-type fallback instead of a
   risk-appropriate classification:
   - `gitlab_project.container_registry_enabled` — tracked since `28412a7`,
     no classifier branch. Fixed: `medium` on enable (matches the
     existing `gitlab_project_container_registry_enabled_public` Finding
     severity), `low` on disable.
   - `gitlab_group.shared_runners_setting_category` — tracked, no branch.
     Fixed: `medium` when the new category is `"enabled"`, `low` otherwise.
   - `gitlab_runner_summary.shared_runner_enabled` — tracked, no branch,
     despite an existing Finding (`gitlab_runner_shared_enabled`, medium)
     for the same current-state condition. Fixed: `medium` on enable,
     `low` on disable.
   - `gitlab_merge_request_approval_summary.approval_rule_count` — tracked
     since `28412a7`, no branch (this is the exact field named in the
     task's category C). Fixed: `medium` on decrease, `low` on increase.
   - `gitlab_merge_request_approval_summary.author_approval_allowed` —
     tracked, no branch. Fixed: `medium` when authors are newly allowed to
     approve their own MRs, `low` when disabled.

3. **A dead/unreachable classifier branch** (task item 10): the MR
   approval summary classifier (`_classify_mr_approval_change`) had a
   branch checking `field_path == "code_owner_approval_required"` — but
   `code_owner_approval_required` is **not a field of
   `GitLabMRApprovalSummaryRecord`** (confirmed against
   `gitlab_schema.py`); it only exists on `GitLabBranchProtectionRecord`.
   `compute_diff` can never emit a Change with this field_path for this
   record_type, since `_GITLAB_TRACKED_FIELDS_BY_TYPE["gitlab_merge_request_approval_summary"]`
   doesn't include it. This branch could never fire in production — it
   was dead code carried over, likely copy-pasted from the branch
   protection classifier. Removed and replaced with the two genuinely
   reachable branches above (`approval_rule_count`,
   `author_approval_allowed`).

No new Security Finding rules were added or changed — this pass is scoped
to the Change-classification layer only.

**`approval_rule_count` vs. `approvals_required`**: after this pass, both
fields are classified with clearly distinct wording ("approval rule
count" vs. "required approvals") and neither classifier branch references
the other field's name, closing the exact confusion risk the task's
question 11 asked about. See the dedicated test
`test_mr_approval_rule_count_and_approvals_required_are_not_confused`.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected by `compute_diff`? | Current risk_level | Expected risk_level | Current title/copy | Expected title/copy | Security finding parity | Status | Test covering it | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1. Project private/internal → public | `gitlab_project` | `visibility_category` | `"private"` | `"public"` | yes | high | high | "visibility changed to public..." | (same) | `gitlab_project_public_visibility` (high) — matches | PASS | `test_project_public_visibility_is_high` | — |
| A2. Project public → private (restoration) | `gitlab_project` | `visibility_category` | `"public"` | `"private"` | yes | low | low (improvement) | "visibility changed to private (restricted)." | (same) | n/a | PASS (after fix) | new `test_project_visibility_to_private_says_private_not_generic` | Previously said "changed to a more restrictive setting" (generic, ambiguous) |
| A3. Project public → internal (restoration) | `gitlab_project` | `visibility_category` | `"public"` | `"internal"` | yes | medium | medium | "visibility changed to internal..." | (same) | n/a | PASS | existing branch | Internal is treated as its own tier, correctly not conflated with private |
| A4. Project unknown → public | `gitlab_project` | `visibility_category` | `None`/unset | `"public"` | yes | high | high | "visibility changed to public..." | (same) | matches | PASS | covered — only `new_v` gates the high branch | Correct: any transition *to* public is high regardless of prior state |
| A5. Project public → unknown | `gitlab_project` | `visibility_category` | `"public"` | `"unknown"`/`None` | yes | **was low but said "more restrictive"** | low | ~~"changed to a more restrictive setting."~~ | "visibility category is now unknown or missing." | n/a | **FIXED (wording)** | new `test_project_visibility_public_to_unknown_is_low_not_more_restrictive` | Severity was already correct; wording overstated certainty of hardening |
| A6. Group private/internal → public | `gitlab_group` | `visibility_category` | `"private"` | `"public"` | yes | high | high | "visibility changed to public..." | (same) | `gitlab_group_public_visibility` (high) — matches | PASS | `test_group_public_visibility_is_high` | — |
| A7. Group public → unknown | `gitlab_group` | `visibility_category` | `"public"` | `"unknown"`/`None` | yes | **was low but said "more restrictive"** | low | ~~"changed to a more restrictive setting."~~ | "visibility category is now unknown or missing." | n/a | **FIXED (wording)** | new `test_group_visibility_public_to_unknown_is_low_not_more_restrictive` | Same bug class as A5 |
| B1. Branch protection removed | `gitlab_branch_protection` | (whole record) | — | — | yes | high | high | "branch protection rule was removed..." | (same) | n/a (Finding is current-state only) | PASS | `test_branch_protection_removed_is_high` | — |
| B2. Branch protection added (restoration) | `gitlab_branch_protection` | (whole record) | — | — | yes | low | low (improvement) | "new branch protection rule was added." | (same) | n/a | PASS | existing branch | — |
| B3. Force push enabled | `gitlab_branch_protection` | `allow_force_push` | `False` | `True` | yes | high | high | "force push was enabled..." | (same) | `gitlab_branch_force_push_enabled` (high) — matches | PASS | `test_force_push_enabled_is_high` | — |
| B4. Force push disabled (restoration) | `gitlab_branch_protection` | `allow_force_push` | `True` | `False` | yes | low | low (improvement) | "force push was disabled (hardened)." | (same) | n/a | PASS | new `test_force_push_true_to_false_is_low_hardened_wording` | — |
| B5. Force push true → unknown | `gitlab_branch_protection` | `allow_force_push` | `True` | `None` | yes | **was low but said "hardened"** | low | ~~"force push was disabled (hardened)."~~ | "force push setting is now unknown or missing." | n/a | **FIXED (wording)** | new `test_force_push_true_to_unknown_is_low_not_hardened_wording` | Severity was already correct; wording claimed hardening that wasn't confirmed |
| B6. Push access broadened | `gitlab_branch_protection` | `push_access_level_category` | `"maintainer"` | `"developer"` | yes | medium | medium | "push access level changed to 'developer'..." | (same) | `gitlab_branch_push_access_broad` (medium) — matches | PASS | existing branch | — |
| B7. Merge access broadened | `gitlab_branch_protection` | `merge_access_level_category` | `"maintainer"` | `"developer"` | yes | medium | medium | "merge access level changed to 'developer'..." | (same) | `gitlab_branch_merge_access_broad` (medium) — matches | PASS | existing branch | — |
| B8. Unprotect access levels | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | n/a | **N/A** | n/a | The connector only extracts push/merge access levels and counts; `unprotect_access_levels` is not fetched. Not invented per task instructions |
| C1. Approvals required decreases | `gitlab_merge_request_approval_summary` | `approvals_required` | `2` | `0` | yes | medium | medium | "required approvals decreased from 2 to 0..." | (same) | `gitlab_merge_request_approval_not_required` (medium) — matches | PASS | `test_approval_reduction_is_medium` | — |
| C2. Approvals required increases (restoration) | `gitlab_merge_request_approval_summary` | `approvals_required` | `0` | `2` | yes | low | low (improvement) | "required approvals changed from 0 to 2." | (same) | n/a | PASS | covered by existing branch | — |
| C3. Approval rule count decreases | `gitlab_merge_request_approval_summary` | `approval_rule_count` | `3` | `1` | yes | **was low (generic fallback)** | medium | ~~"MR approval summary field 'approval_rule_count' changed."~~ | "MR approval rule count decreased from 3 to 1..." | n/a (no dedicated Finding uses this field directly; used only as evidence context in sibling findings) | **FIXED (gap)** | new `test_mr_approval_rule_count_decreased_is_medium` | Genuine gap — explicitly named in task category C |
| C4. Approval rule count increases (restoration) | `gitlab_merge_request_approval_summary` | `approval_rule_count` | `1` | `3` | yes | low | low (improvement) | "MR approval rule count changed from 1 to 3." | (same) | n/a | PASS (after fix) | new `test_mr_approval_rule_count_increased_is_low` | — |
| C5. `approval_rule_count` vs. `approvals_required` distinctness | `gitlab_merge_request_approval_summary` | both | `2` | `0` (same numbers, different field) | yes | medium (both) | medium (both), but with distinct wording | previously N/A for rule count (generic fallback) | "approval rule count decreased..." vs. "required approvals decreased..." — must not share wording or reference the other field's name | n/a | **FIXED** | new `test_mr_approval_rule_count_and_approvals_required_are_not_confused` | Directly answers task question 11 |
| C6. Approval rules removed (whole-record) | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | n/a | **N/A** | n/a | Approval rules are summarized as a count on `gitlab_merge_request_approval_summary`, not emitted as individual addable/removable records — a count decrease is the correctly-modeled proxy for this (see C3) |
| C7. Author self-approval allowed | `gitlab_merge_request_approval_summary` | `author_approval_allowed` | `False` | `True` | yes | **was low (generic fallback)** | medium | ~~"field 'author_approval_allowed' changed."~~ | "MR authors are now allowed to approve their own merge requests..." | n/a (used only as evidence context in the `gitlab_merge_request_approval_not_required` Finding) | **FIXED (gap)** | new `test_author_approval_allowed_true_is_medium` | — |
| C8. Author self-approval disabled (restoration) | `gitlab_merge_request_approval_summary` | `author_approval_allowed` | `True` | `False` | yes | low | low (improvement) | "author self-approval was disabled." | (same) | n/a | PASS (after fix) | new `test_author_approval_allowed_false_is_low` | — |
| C9. `code_owner_approval_required` on MR summary (dead field) | `gitlab_merge_request_approval_summary` | `code_owner_approval_required` | n/a | n/a | **no — this field does not exist on this record type; `compute_diff` can never emit it here** | low (generic fallback, confirmed intentional after fix) | low (generic fallback is correct — this field_path is unreachable for this record_type) | previously a dead "medium, code owner approval requirement..." branch that could never execute | generic fallback message | n/a | **FIXED (dead branch removed)** | new `test_mr_summary_code_owner_approval_required_is_dead_field_falls_generic` | Task item 10 — this was the one truly unreachable classifier branch found in the whole module |
| C10. `code_owner_approval_required` on branch protection (real field) | `gitlab_branch_protection` | `code_owner_approval_required` | `True` | `False` | yes | medium | medium | "code owner approval requirement was disabled..." | (same) | `gitlab_branch_code_owner_approval_missing` (medium) — matches | PASS | `test_code_owner_approval_disabled_is_medium` | Untouched — this is the correct record type for this field |
| D1. CI variable protected true → false (count decrease) | `gitlab_ci_variable_summary` | `protected_variable_count` | `2` | `1` | yes | medium | medium | "protected variable count decreased from 2 to 1..." | (same) | `gitlab_ci_variables_unprotected` (medium, current-state: 0 protected) — related but distinct condition | PASS | existing branch | — |
| D2. CI variable masked true → false (count decrease) | `gitlab_ci_variable_summary` | `masked_variable_count` | `2` | `1` | yes | medium | medium | "masked variable count decreased from 2 to 1..." | (same) | `gitlab_ci_variables_unmasked` (medium, current-state: 0 masked) — related but distinct condition | PASS | existing branch | — |
| D3. CI variable hidden true/false | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | n/a | **N/A** | n/a | GitLab's "hidden" variable flag is not extracted by the connector's variable summary normalizer — only `protected`/`masked`/`environment_scope` booleans are read per-variable before being reduced to counts |
| D4. Unprotected+unmasked increase | `gitlab_ci_variable_summary` | `unprotected_unmasked_count` | `0` | `3` | yes | high | high | "unprotected/unmasked CI variable count increased..." | (same) | `gitlab_ci_unprotected_unmasked_variables` (high) — matches | PASS | `test_unprotected_unmasked_ci_increase_is_high` | — |
| D5. Environment scope broadened | `gitlab_ci_variable_summary` | `environment_scoped_count` | count | count | yes | low (generic fallback, intentional) | low | "field 'environment_scoped_count' changed." | (same) | n/a | PASS (intentional generic) | none dedicated | Increasing environment-scoped variables is a *hardening* signal (scoping limits exposure), not a broadening one — correctly not flagged as risk-worthy |
| E1. Deploy key write access enabled | `gitlab_deploy_key_summary` | `write_enabled_count` | `0` | `2` | yes | high | high | "write-enabled count increased from 0 to 2..." | (same) | `gitlab_deploy_key_write_enabled` (high) — matches | PASS | `test_deploy_key_write_increase_is_high` | — |
| E2. Deploy key write access disabled (restoration) | `gitlab_deploy_key_summary` | `write_enabled_count` | `2` | `0` | yes | low | low (improvement) | "write-enabled count changed from 2 to 0." | (same) | n/a | PASS | covered by existing branch | — |
| E3. Deploy key added | `gitlab_deploy_key_summary` | `deploy_key_count` | `0` | `1` | yes | medium | medium | "deploy key count increased from 0 to 1..." | (same) | n/a | PASS | existing branch | — |
| E4. Deploy key enabled/removed metadata | `gitlab_deploy_key_summary` | `read_only_count`, `enabled_count` | count | count | yes | low (generic fallback, intentional) | low | "field '...' changed." | (same) | n/a | PASS (intentional generic) | none dedicated | `write_enabled_count`'s own branch already captures the security-relevant signal; these residual counts carry no independent directional risk |
| F1. Webhook SSL verification disabled | `gitlab_webhook` | `ssl_verification_enabled` | `True` | `False` | yes | high | high | "SSL verification was disabled..." | (same) | `gitlab_webhook_ssl_verification_disabled` (high) — matches | PASS | `test_webhook_ssl_disabled_is_high` | — |
| F2. Webhook SSL verification restored | `gitlab_webhook` | `ssl_verification_enabled` | `False` | `True` | yes | low | low (improvement) | "SSL verification was enabled." | (same) | n/a | PASS (after fix) | covered — explicit-true branch now separated from unknown | — |
| F3. Webhook SSL true → unknown | `gitlab_webhook` | `ssl_verification_enabled` | `True` | `None` | yes | **was low but said "was enabled"** | low | ~~"SSL verification was enabled."~~ | "SSL verification setting is now unknown or missing." | n/a | **FIXED (wording)** | new `test_webhook_ssl_true_to_unknown_is_low_not_enabled_wording` | — |
| F4. Webhook HTTP scheme observed | `gitlab_webhook` | `url_scheme` | `"https"` | `"http"` | yes | high | high | "URL scheme changed to HTTP (non-encrypted)..." | (same) | `gitlab_webhook_http_scheme` (high) — matches | PASS | existing branch | — |
| F5. Webhook HTTPS restored | `gitlab_webhook` | `url_scheme` | `"http"` | `"https"` | yes | low | low (improvement) | "URL scheme changed to HTTPS." | (same) | n/a | PASS (after fix) | new `test_webhook_url_scheme_https_still_says_https` | — |
| F6. Webhook scheme → other/unknown | `gitlab_webhook` | `url_scheme` | `"https"` | `"other"` | yes | **was low but said "changed to HTTPS"** | low | ~~"URL scheme changed to HTTPS."~~ | "URL scheme is now unknown or missing." | n/a | **FIXED (wording)** | new `test_webhook_url_scheme_other_is_low_not_https_wording` | This was factually backwards — scheme "other" was reported as if it were HTTPS |
| F7. Webhook secret/token removed | `gitlab_webhook` | `secret_token_present` | `True` | `False` | yes | high | high | "secret token was removed..." | (same) | `gitlab_webhook_secret_missing` (high) — matches | PASS | `test_webhook_secret_removed_is_high` | — |
| F8. Webhook secret true → unknown | `gitlab_webhook` | `secret_token_present` | `True` | `None` | yes | **was low but said "was added"** | low | ~~"secret token was added."~~ | "secret token presence is now unknown or missing." | n/a | **FIXED (wording)** | new `test_webhook_secret_true_to_unknown_is_low_not_added_wording` | — |
| F9. Webhook target/host category changed | `gitlab_webhook` | `url_host_category` | `"internal"` | `"external"` | yes | low (generic fallback, intentional) | low/medium review | "field 'url_host_category' changed." | (same) | n/a | PASS (intentional generic) | none dedicated | No confident directional risk signal — an internal-to-external host category change isn't inherently worse than the reverse in this connector's model; flagged for future consideration but not fixed in this pass (low confidence, not explicitly required) |
| F10. Webhook enabled/disabled | n/a | n/a | n/a | n/a | tracked but the field is a structural constant | n/a | n/a | n/a | n/a | n/a | **PASS (documented no-op)** | n/a | The connector's `enabled` field is always `True` by construction (GitLab's Hooks API has no active/disabled flag) — this field can never actually change value, so no classifier branch is meaningful here; documented in the connector's own inline comment |
| G1. Shared runners enabled (project) | `gitlab_project` | `shared_runners_enabled` | `False` | `True` | yes | medium | medium | "shared runners were enabled..." | (same) | `gitlab_project_shared_runners_enabled` (medium) — matches | PASS | existing branch | — |
| G2. Shared runners enabled (group) | `gitlab_group` | `shared_runners_setting_category` | `"disabled_locked"` | `"enabled"` | yes | **was low (generic fallback)** | medium | ~~"group configuration field 'shared_runners_setting_category' changed."~~ | "shared runners setting was enabled..." | n/a (no group-level Finding exists for this; only the project-level rule does) | **FIXED (gap)** | new `test_group_shared_runners_setting_enabled_is_medium` | — |
| G3. Shared runners enabled (runner summary) | `gitlab_runner_summary` | `shared_runner_enabled` | `False` | `True` | yes | **was low (generic fallback)** | medium | ~~"runner summary field 'shared_runner_enabled' changed."~~ | "shared runners are now enabled for this project or group..." | `gitlab_runner_shared_enabled` (medium) — now matches | **FIXED (gap)** | new `test_runner_summary_shared_runner_enabled_is_medium` | This is the clearest Finding/Change severity mismatch found — the Finding already existed at medium but the Change classifier had no branch at all |
| G4. Container registry enabled | `gitlab_project` | `container_registry_enabled` | `False` | `True` | yes | **was low (generic fallback)** | medium | ~~"project configuration field 'container_registry_enabled' changed."~~ | "container registry was enabled..." | `gitlab_project_container_registry_enabled_public` (medium, current-state: public + enabled) — now aligned | **FIXED (gap)** | new `test_container_registry_enabled_is_medium` | — |
| G5. Untagged runner count / protected runners | n/a | n/a | n/a | n/a | tracked but no dedicated branch (intentional) | low (generic) | low | "field 'untagged_runner_count' changed." | (same) | `gitlab_runner_untagged` (medium, current-state) exists but no Change classifier branch added | PASS (intentional generic, lower priority than G1-G4) | none dedicated | Left as generic in this pass — lower-confidence directional signal than the four fixed above; flagged for a future pass if desired |
| G6. Security scanning / SAST | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | n/a | **N/A** | n/a | No SAST/dependency-scanning endpoint is fetched by the connector |
| H. Project/group/member access counts | n/a | n/a | n/a | n/a | not modeled beyond `member_count_category` (a bucketed string, not a precise count) | n/a | n/a | n/a | n/a | n/a | **N/A** | n/a | The connector never fetches per-member access-level data (privacy-by-design — no user identities are stored); `member_count_category` itself is a coarse bucket with no admin/maintainer breakdown, so no specific "privileged access broadened" signal can be derived without inventing a new capability |
| I. Unknown/missing sweep | all record types | all newly-fixed fields | `None`/missing | `None`/missing | n/a or yes | low | low | varies, all safe generic-unknown wording | (same) | n/a | PASS | new `test_unknown_transitions_never_produce_high` (8 field/record-type combinations in one sweep) | Verified none of the fields touched in this pass can produce `"high"` on an unknown/missing transition |

## Tracked-fields vs. classifier-branch comparison

| Record type | Tracked fields with dedicated classification | Tracked fields using generic fallback (intentional) | Tracked fields that fell through accidentally (fixed this pass) |
|---|---|---|---|
| `gitlab_instance` | `two_factor_requirement_enabled`, `sign_up_enabled`, `visibility_restriction_category`, `shared_runners_enabled` | `version_present`, `revision_present`, `enterprise`, `project_count`, `group_count` — pure structural/one-time-set fields with no directional risk signal | none |
| `gitlab_project` | `visibility_category`, `archived`, `protected_branch_count`, `deploy_key_count`, `webhook_count`, `shared_runners_enabled`, `container_registry_enabled`, `wiki_enabled`/`snippets_enabled`/`packages_enabled` (metadata-only, always low) | `default_branch_present`, `merge_requests_enabled`, `issues_enabled`, `ci_variable_count`, `approval_rule_count` (project-level rollup — the detailed `gitlab_ci_variable_summary`/`gitlab_merge_request_approval_summary` records already carry the real classified signal) | **`container_registry_enabled` (this pass)** |
| `gitlab_group` | `visibility_category`, `two_factor_requirement_enabled`, `membership_lock`, `shared_runners_setting_category` | `project_count`, `subgroup_count`, `member_count_category` — structural counts | **`shared_runners_setting_category` (this pass)** |
| `gitlab_branch_protection` | `allow_force_push`, `code_owner_approval_required`, `push_access_level_category`, `merge_access_level_category`, `allowed_to_push_count`, `allowed_to_merge_count` | `pattern_category` — a rename/categorization with no directional risk signal by itself | none |
| `gitlab_webhook` | `ssl_verification_enabled`, `secret_token_present`, `url_scheme`, `event_count`, `push_events`/`merge_requests_events`/`pipeline_events`/`job_events` | `enabled` (structural constant — never actually changes), `url_host_category` (no confident directional signal, see F9) | none |
| `gitlab_ci_variable_summary` | `variable_count`, `protected_variable_count`, `masked_variable_count`, `unprotected_unmasked_count` | `environment_scoped_count` (increasing this is a hardening signal, not a risk one) | none |
| `gitlab_deploy_key_summary` | `write_enabled_count`, `deploy_key_count` | `read_only_count`, `enabled_count` (redundant with `write_enabled_count`'s own branch) | none |
| `gitlab_runner_summary` | `locked_runner_count`, `paused_runner_count` (both directions intentionally low — pausing a runner is not risky either way), `shared_runner_enabled` | `runner_count`, `tagged_runner_count`, `untagged_runner_count` — see G5; lower-confidence than the fixed fields, left generic this pass | **`shared_runner_enabled` (this pass)** |
| `gitlab_merge_request_approval_summary` | `approvals_required`, `disable_overriding_approvers_per_merge_request`, `reset_approvals_on_push`, `approval_rule_count`, `author_approval_allowed` | — (full coverage after this pass) | **`approval_rule_count`, `author_approval_allowed` (this pass)** |

**Classifier branches referring to fields not emitted by the connector/schema for that record type:**
one found and fixed — `code_owner_approval_required` inside
`_classify_mr_approval_change` (see Summary #3 and matrix row C9). No
other stale/mismatched field-name references were found; every other
`fp ==` check was cross-referenced against `gitlab_schema.py`'s
`TypedDict` definitions for its containing record type and confirmed
correct.

**Classifier branches referring to old/stale field names:** none — GitLab
never had the `old_value`/`prev_value` bug that Terraform Cloud's first
pass found, so there was no stale-name class of bug to look for beyond the
one dead-field case above.

## Mock-shape (`old_value`/`prev_value`/`previous_value`/`prior_value`) verification

```
grep -n "old_value\|previous_value\|prior_value\|prev_value" backend/app/services/risk_rules/gitlab.py
```
→ 5 matches, all `_get(change, "prev_value")` — production code is clean
and was already clean before this pass.

```
grep -rln "old_value\|previous_value\|prior_value" backend/tests/*gitlab*
```
→ no matches in any GitLab test file.

```
grep -c "prev_value" backend/tests/test_milestone87a_gitlab_drift_provider_foundation.py
```
→ 14+ matches (now higher after this pass's new tests) — the existing
`TestDriftRiskClassifier._make_change` helper (and the new
`TestGitLabChangeClassificationQA._make_change` helper added in this
pass) both build **plain dicts** shaped exactly like real `compute_diff`
output (`provider_metadata`, `field_path`, `change_type`, `prev_value`,
`new_value`) — neither uses `MagicMock`, so there is no possibility of a
mock silently agreeing with a wrong field name.

**No mock-shape issue remains, and none was introduced by this pass.**

## Totals

| Metric | Count |
|---|---|
| Total classification cases reviewed | 39 (A1–I, all rows above) |
| PASS | 20 |
| FAIL | 0 |
| GAP → FIXED (missing classification branch) | 5 (C3/C4, C7/C8, G2, G3, G4 — 5 distinct fields across 8 table rows) |
| FIXED (wording-only, severity was already correct) | 7 (A5, A7, B5, F3, F6, F8, plus the dead-branch removal C9) |
| N/A (not modeled, correctly absent) | 6 (B8, D3, F10 documented no-op, G6, H, plus C6 folded into C3) |
| Intentional generic (left as-is, lower priority) | 3 (D5, E4, F9, G5 — 4 field groups) |
| New Security Finding rules added | 0 (classification-layer pass only) |
| Dead/unreachable classifier branches found and removed | 1 (`code_owner_approval_required` under `gitlab_merge_request_approval_summary`) |
| Mock-shape (`old_value`-style) bugs found | 0 |
| `approval_rule_count`/`approvals_required` confusion risk | resolved — distinct wording, cross-verified by dedicated test |

## Fixes made

1. **`backend/app/services/risk_rules/gitlab.py`**
   - `_classify_project_change`: `visibility_category`'s fallback now
     distinguishes explicit `"private"` from unknown/other; added a
     `container_registry_enabled` branch (medium on enable).
   - `_classify_group_change`: `visibility_category` given the same
     private/unknown distinction; `membership_lock`'s fallback now
     distinguishes explicit-true from unknown; added a
     `shared_runners_setting_category` branch (medium when `"enabled"`).
   - `_classify_branch_protection_change`: `allow_force_push`'s fallback
     now distinguishes explicit-false ("hardened") from unknown.
   - `_classify_webhook_change`: `ssl_verification_enabled`,
     `secret_token_present`, and `url_scheme` fallbacks now distinguish
     the genuine opposite/HTTPS value from unknown/other.
   - `_classify_runner_change`: added a `shared_runner_enabled` branch
     (medium on enable) — this now matches the pre-existing
     `gitlab_runner_shared_enabled` Finding severity, closing the clearest
     Finding/Change disagreement found in this pass.
   - `_classify_mr_approval_change`: removed the dead
     `code_owner_approval_required` branch (unreachable for this record
     type); added `approval_rule_count` (medium on decrease) and
     `author_approval_allowed` (medium when self-approval newly allowed)
     branches; `disable_overriding_approvers_per_merge_request` and
     `reset_approvals_on_push` fallbacks now distinguish explicit-true
     from unknown.
2. **`backend/tests/test_milestone87a_gitlab_drift_provider_foundation.py`**
   — added `TestGitLabChangeClassificationQA` (21 new tests): wording
   coverage for the 6 fixed unknown-transition cases, the 5 new gap-fix
   classifications (both directions each where applicable), the dead-field
   regression test, the `approval_rule_count`/`approvals_required`
   distinctness test, and an 8-case unknown/missing severity sweep.
3. **`backend/tests/reports/gitlab_change_classification_matrix.md`** —
   this report.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone87a_gitlab_drift_provider_foundation.py -q
# 137 passed (was 116 after 28412a7)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "gitlab and risk"
# 196 passed, 16772 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "gitlab and diff"
# 8 passed, 16960 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "gitlab"
# 714 passed, 16275 deselected (was 693 after 28412a7)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*gitlab* -q
# 701 passed
```

No frontend files were touched in this pass — no new Security Finding rule
was added, only Change-classification logic and tests — so
`npx tsc --noEmit` was not run.
