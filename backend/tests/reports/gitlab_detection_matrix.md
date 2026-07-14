# GitLab Detection QA Matrix

Exhaustive end-to-end validation of the GitLab provider (connector → diff
tracking → risk classification → security findings → registries → frontend
catalog), following the same methodology established for SendGrid, Twilio,
and Terraform Cloud in prior QA passes
(`sendgrid_detection_matrix.md`, `twilio_detection_matrix.md`,
`terraform_cloud_detection_matrix.md`).

## Summary

GitLab's connector (`app/connectors/gitlab.py`), schema
(`gitlab_schema.py`), and security rules (`security_rules/gitlab.py`, 25
rules across 8 rule-bearing record types) were already mature and well
documented — including explicit code comments listing two rules that were
intentionally *not* implemented because the connector doesn't emit the
fields they'd need (`gitlab_runner_unprotected_runners`,
`gitlab_deploy_key_stale_or_expired`). Registries and the frontend catalog
were already in perfect parity (25/25 rule keys, matching severities) —
zero fixes needed there.

Two real bugs were found and fixed:

1. **Diff/drift tracking gap (the recurring root-cause bug across this
   codebase's provider QA passes)**. GitLab had **zero entries** in
   `diff_service.py`'s per-provider tracked-fields dispatch, exactly like
   SendGrid, Twilio, and Terraform Cloud before their respective fixes.
   Every GitLab record type fell through to the Cloudflare DNS default
   tuple (`record_type`, `name`, `content`, `ttl`, `proxied`, `priority`,
   `comment`) — none of which exist on any GitLab record — so
   `compute_diff` could **never detect a modified field on an existing
   GitLab record**. Only whole-record add/remove events were ever
   detected. This meant every one of `risk_rules/gitlab.py`'s directional
   classifiers (public visibility, force push, SSL verification, deploy
   key write access, etc.) was completely unreachable in production, even
   though the classifier logic itself was correct. Fixed by adding
   `_GITLAB_TRACKED_FIELDS_BY_TYPE` (all 9 record types) and wiring the
   `gitlab_` prefix into `_tracked_fields_for`.

2. **Connector normalization bug**: `gitlab_project.approval_rule_count`
   was populated from `approvals_required` (the number of approvals
   required to merge — a small integer like 1 or 2) instead of the actual
   count of approval rule objects, which `_normalize_mr_approval_summary`
   already computed correctly for the sibling
   `gitlab_merge_request_approval_summary` record. The two records
   reported different, semantically incompatible numbers under the same
   field name. Fixed by extracting the correct computation into a shared
   `_mr_approval_rule_count()` helper used by both call sites.

`risk_rules/gitlab.py` was otherwise found to be **already correct**: every
directional comparison already reads `prev_value` (not `old_value` — the
bug class found and fixed in Terraform Cloud's first QA pass never existed
here), and the test helper (`TestDriftRiskClassifier._make_change`) already
builds plain dicts shaped like real `compute_diff` output rather than
`MagicMock` objects, so there was no hidden mock-agreement bug to find.

## Connector extraction review

| Record type | Source endpoint(s) | Sensitive values excluded? | Fail-soft on 403/404? | Stable record IDs? |
|---|---|---|---|---|
| `gitlab_instance` | `GET version`, `GET application/settings` (both via `_safe_get`) | Yes — no license/admin secrets | Yes — `_safe_get` returns `None` | Yes — constant `"gitlab_instance"` |
| `gitlab_project` | `GET projects` (`membership=true`) | Yes — no name/path/URL | N/A (required anchor surface, propagates on failure like every other provider's primary surface) | Yes — `_opaque_id(project_id)` (SHA-256) |
| `gitlab_group` | `GET groups` | Yes — no name/path | N/A (anchor surface) | Yes — `_opaque_id(group_id)` |
| `gitlab_branch_protection` | `GET projects/:id/protected_branches` | Yes — pattern *category* only, never the branch name | Yes — `_safe_list` | Yes — opaque hash of `project_id:pattern_category:hash(name)` |
| `gitlab_webhook` | `GET projects/:id/hooks`, `GET groups/:id/hooks` | Yes — URL scheme + host category only, never the URL; secret/token presence only, never the value | Yes — `_safe_list` | Yes — `_opaque_id(owner:hook_id)` |
| `gitlab_ci_variable_summary` | `GET projects/:id/variables`, `GET groups/:id/variables` | Yes — counts only, names/values never touched | Yes — `_safe_list` | Yes — `_opaque_id(ci_var:owner)` |
| `gitlab_deploy_key_summary` | `GET projects/:id/deploy_keys` | Yes — counts only, never title/fingerprint/material | Yes — `_safe_list` | Yes — `_opaque_id(deploy_key:project)` |
| `gitlab_runner_summary` | `GET projects/:id/runners` | Yes — counts only, never token/IP/description | Yes — `_safe_list` | Yes — `_opaque_id(runner:owner)` |
| `gitlab_merge_request_approval_summary` | `GET projects/:id/approvals` (`_safe_get`) | Yes — counts/booleans only, never approver identities | Yes — `_safe_get` returns `None` | Yes — `_opaque_id(mr_approval:project)` |

**Confirmed via code inspection** (connector module docstring + normalizer
bodies):
- No Terraform/CI variable **values** are stored — only counts derived
  from `protected`/`masked`/`environment_scope` booleans on each raw
  variable dict, discarded immediately after counting.
- No webhook **secret/token values** are stored — only
  `bool(raw.get("token") or raw.get("secret_token"))`.
- No deploy key **material** is stored beyond safe counts
  (`write_enabled_count`/`read_only_count`/`enabled_count`).
- No **repository code or commit contents** are ever fetched — the
  connector has no code/commits/tree endpoint calls at all.
- No **private URLs with tokens** are stored — webhook URLs are reduced to
  `url_scheme`/`url_host_category` via `urlparse`, and the PAT is used only
  in the `PRIVATE-TOKEN` request header, never copied into any record or
  logged (`logger.info` only logs a record count and base URL).

## Diff/change tracking review

**Before this pass**: 0 of 9 record types had a tracked-fields entry — all
GitLab modified-field changes silently fell through to the Cloudflare DNS
default tuple and were never detected.

**After this pass**: all 9 record types are tracked with every
security-relevant field verified present, including all the task's
high-priority fields: `visibility_category`, `allow_force_push`,
`push_access_level_category`/`merge_access_level_category`,
`approvals_required`, `protected_variable_count`/`masked_variable_count`,
`write_enabled_count`, `enabled` (webhook), `url_scheme`,
`ssl_verification_enabled`. (`push_access_levels`/`merge_access_levels`
raw arrays and `unprotect_access_levels` are not modeled beyond the
category + count fields already tracked — see "Not modeled" section.)

No fields were found that are tracked but no longer emitted by the
connector, or emitted but silently dropped before tracking — the tracked
tuples were built directly from `gitlab_schema.py`'s `TypedDict`
definitions, which match the connector's normalizer output field-for-field.

## Test matrix

| Test case | Normalized record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes/fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. Project private/internal → public | `gitlab_project` | `visibility_category` | `"private"`/`"internal"` → `"public"` | Change (high) + Finding (high) | Change never generated before fix (diff-tracking gap) | high | high (after fix) | `gitlab_project_public_visibility` | `test_project_public_visibility_is_high`, new `test_project_visibility_change_produces_drift_change` | **FIXED** | — |
| B. Project public → private/internal (restoration) | `gitlab_project` | `visibility_category` | `"public"` → `"private"` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a (Finding only fires on current-state public) | `test_private_visibility_is_low` | **FIXED** | — |
| C. Branch protection disabled/weakened | `gitlab_branch_protection` | (whole record removed) or `push_access_level_category`/`merge_access_level_category` broadened | record removed, or access level → `developer`/`reporter`/`guest` | Change (high on removal, medium on access broadening) + Finding (medium, broad access) | Removal already detected (add/remove doesn't depend on tracked fields); access-level *modification* never detected before fix | high (removal) / medium (access broadened) | high / medium (after fix) | (removal: none — generic); `gitlab_branch_push_access_broad`, `gitlab_branch_merge_access_broad` | `test_branch_protection_removed_is_high`; access-level modification newly reachable via the fix | **FIXED (access-level modification only; removal already worked)** | — |
| D. Branch protection strengthened | `gitlab_branch_protection` | `push_access_level_category`/`merge_access_level_category` | `developer` → `maintainer`/`owner` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a | covered by existing branch (`new_v not in _broad_access_levels` → low) | **FIXED** | — |
| E. Force push enabled/disabled on protected branch | `gitlab_branch_protection` | `allow_force_push` | `False` → `True` (and reverse) | Change (high enable / low disable-hardened) + Finding (high) | Change never generated before fix | high / low | high / low (after fix) | `gitlab_branch_force_push_enabled` | `test_force_push_enabled_is_high`, new `test_allow_force_push_change_produces_drift_change` | **FIXED** | — |
| F. MR approvals reduced/disabled | `gitlab_merge_request_approval_summary` | `approvals_required` | `2` → `0` | Change (medium) + Finding (medium, approvals not required) | Change never generated before fix | medium | medium (after fix) | `gitlab_merge_request_approval_not_required` | `test_approval_reduction_is_medium` | **FIXED** | — |
| G. MR approvals strengthened | `gitlab_merge_request_approval_summary` | `approvals_required` | `0` → `2` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a | covered by existing branch (`new_n >= old_n` → low) | **FIXED** | — |
| H. CI/CD variable protected true/false | `gitlab_ci_variable_summary` | `protected_variable_count` | count decreases | Change (medium) + Finding (medium, `gitlab_ci_variables_unprotected`) | Change never generated before fix | medium | medium (after fix) | `gitlab_ci_variables_unprotected` | covered by existing branch; newly reachable via the fix | **FIXED** | — |
| I. CI/CD variable masked true/false | `gitlab_ci_variable_summary` | `masked_variable_count` | count decreases | Change (medium) + Finding (medium, `gitlab_ci_variables_unmasked`) | Change never generated before fix | medium | medium (after fix) | `gitlab_ci_variables_unmasked` | covered by existing branch; newly reachable via the fix | **FIXED** | — |
| J. Deploy key write access enabled/disabled | `gitlab_deploy_key_summary` | `write_enabled_count` | `0` → `2` (and reverse) | Change (high enable) + Finding (high, `gitlab_deploy_key_write_enabled`) | Change never generated before fix | high | high (after fix) | `gitlab_deploy_key_write_enabled` | `test_deploy_key_write_increase_is_high` | **FIXED** | — |
| K. Webhook SSL verification enabled/disabled | `gitlab_webhook` | `ssl_verification_enabled` | `True` → `False` | Change (high) + Finding (high, `gitlab_webhook_ssl_verification_disabled`) | Change never generated before fix | high | high (after fix) | `gitlab_webhook_ssl_verification_disabled` | `test_webhook_ssl_disabled_is_high` | **FIXED** | — |
| L. Webhook HTTP/HTTPS scheme | `gitlab_webhook` | `url_scheme` | `"https"` → `"http"` | Change (high) + Finding (high, `gitlab_webhook_http_scheme`) | Change never generated before fix | high | high (after fix) | `gitlab_webhook_http_scheme` | covered by existing branch (`new_v == "http"` → high); newly reachable via the fix | **FIXED** | — |
| M. Webhook secret/token/signing posture | `gitlab_webhook` | `secret_token_present` | `True` → `False` | Change (high) + Finding (high, `gitlab_webhook_secret_missing`) | Change never generated before fix | high | high (after fix) | `gitlab_webhook_secret_missing` | `test_webhook_secret_removed_is_high` | **FIXED** | — |
| N. Pipeline/security scanning setting weakened | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | The connector has no pipeline-settings or SAST/dependency-scanning endpoint call at all (no `ci/lint`, `projects/:id/pipeline_schedules`, or security-scanning API is fetched). Not invented, per task instructions — no existing evidence to build this from |
| O. Unknown/missing fields never produce high findings | all 9 record types | any | `None`/missing | no high finding/classification | Confirmed — every Finding check uses `is True`/`is False`/explicit `in (...)` membership tests (never bare truthiness), and every Change classifier falls to `low` on unparseable/missing values via `try/except (ValueError, TypeError)` guards | none | none | all | new `test_every_tracked_field_classifies_without_error_or_invalid_severity` (exercises every tracked field of every record type) | PASS | — |
| P. 403/404 fail-soft on optional endpoints | branch protection, webhooks, variables, deploy keys, runners, MR approvals | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed via `_safe_list`/`_safe_get` explicitly catching `ConnectorError`/`NetworkError` (re-raising only `AuthenticationError`), returning `[]`/`None` | n/a | n/a | n/a | existing `test_milestone87a` connector tests (`TestConnector`) | PASS | — |
| Q. Records with normalized fields but no security rule | `gitlab_instance` (fully); `merge_requests_enabled`, `issues_enabled`, `default_branch_present`, `archived`, and all `*_count` fields on rule-bearing types | n/a | n/a | correctly no finding | Confirmed — `gitlab_instance` has an explicit "no rules at M87B/M87C" comment in `evaluate()`; the count/boolean fields above have no dedicated Finding because the risk signal they'd represent is already covered by their own summary record's dedicated rules (e.g. `ci_variable_count` is redundant with `gitlab_ci_variable_summary`'s own `protected`/`masked`/`unprotected_unmasked` rules) | n/a | n/a | n/a | n/a | PASS (intentional, documented) | — |
| R. Security rules with no reachable normalized record | — | — | — | — | None found — all 25 rules dispatch from `evaluate()` against one of the 8 rule-bearing record types the connector actually emits. Two *candidate* rules (`gitlab_runner_unprotected_runners`, `gitlab_deploy_key_stale_or_expired`) were considered and explicitly documented as **not implemented** (not merely unreachable) because the connector doesn't emit the fields they'd need | n/a | n/a | all | existing `test_gitlab_provider_depth_qa.py` / `test_milestone87h_gitlab_provider_depth_qa.py` reachability tests | PASS | Zero dead/unreachable rules |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | 25/25 rule keys present everywhere with matching severities | Verified via exact set diff: `security_rules/gitlab.py` (25) vs. `security_rule_registry.py` (25), `security_rule_pack.py` (25, severities cross-checked and all matched), `security_rule_confidence.py` (25), and `securityRuleCatalog.ts` (25) | n/a | n/a | all | none pre-existing; verified via ad hoc scripted diff in this pass | PASS | Zero mismatches — no fix needed |
| Diff-tracked fields present for all 9 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 9 record types tracked (before fix)** → **9 of 9 tracked (after fix)** | n/a | n/a | n/a | new `TestGitLabDiffTrackedFields` (6 tests) | **FIXED** | Root-cause fix — see Summary #1 |
| Connector `approval_rule_count` correctness | `gitlab_project`, `gitlab_merge_request_approval_summary` | `approval_rule_count` | project record previously derived this from `approvals_required` instead of the rule count | both records report the same, correctly-derived rule count | **was mismatched** (project used `approvals_required`, MR summary used the real rule count) → now derived identically via shared `_mr_approval_rule_count()` | n/a (normalization correctness, not a risk classification) | n/a | n/a | new `TestGitLabConnectorApprovalRuleCountBugfix` (3 tests) | **FIXED** | See Summary #2 |

## Not modeled (correctly absent, not invented)

- **`unprotect_access_levels`** — GitLab's protected-branch API also
  exposes who may *unprotect* a branch entirely; the connector currently
  only captures push/merge access levels and counts. Not invented per task
  instructions — the connector would need a new field extraction, which is
  a capability addition, not a QA-pass fix.
- **Pipeline/CI settings, SAST/dependency scanning** — no endpoint fetched
  at all (category N above).
- **Project/group member access levels** (individual member→role
  mappings) — the connector only aggregates `member_count_category` at
  the group level; no per-member access-level data is fetched, which is
  consistent with the project's privacy-by-design convention of never
  storing user identities.
- **Container/package registry contents** — only the boolean
  enabled/disabled flags are modeled (already covered by categories in the
  test matrix); registry contents (image lists, package lists) are never
  fetched.

## Fixes made

1. **`backend/app/services/diff_service.py`** — added
   `_GITLAB_TRACKED_FIELDS_BY_TYPE` (all 9 record types, every non-identity
   field) and wired the `gitlab_` prefix into `_tracked_fields_for`.
   Updated the function's docstring.
2. **`backend/app/connectors/gitlab.py`** — extracted a shared
   `_mr_approval_rule_count()` helper and used it both in
   `_normalize_mr_approval_summary` and in `fetch()`'s construction of the
   project record, fixing the `approval_rule_count`/`approvals_required`
   field-mismatch bug.
3. **`backend/tests/test_milestone87a_gitlab_drift_provider_foundation.py`**
   — added `TestGitLabDiffTrackedFields` (6 tests: entry-completeness,
   no-fallthrough-to-Cloudflare-default check, 2 `compute_diff` regression
   tests for visibility and force-push, a no-spurious-change sanity test,
   and a full tracked-field-sweep classifier sync test) and
   `TestGitLabConnectorApprovalRuleCountBugfix` (3 tests proving the helper
   counts rules correctly, handles `None`, and that both records now
   agree).
4. **`backend/tests/reports/gitlab_detection_matrix.md`** — this report.

No changes were made to `risk_rules/gitlab.py`, `security_rules/gitlab.py`,
the four backend registries, or the frontend catalog — all were already
correct.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone87a_gitlab_drift_provider_foundation.py -q
# 116 passed (was 107 before this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "gitlab"
# 693 passed, 16275 deselected (was 684 before this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_gitlab_provider_depth_qa.py \
    tests/test_milestone87b_gitlab_core_security_foundation.py \
    tests/test_milestone87c_gitlab_branch_webhook_ci_risk_expansion.py \
    tests/test_milestone87h_gitlab_provider_depth_qa.py -q
# 324 passed
```

No frontend files were touched in this pass (no new Security Finding rule
was added or changed — only diff-tracking and connector-normalization
fixes), so `npx tsc --noEmit` was not run.
