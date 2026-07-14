# Jira Detection QA Matrix

Exhaustive end-to-end validation of the Jira provider (connector → diff
tracking → risk classification → security findings → registries → frontend
catalog), following the same methodology established for SendGrid, Twilio,
Terraform Cloud, and GitLab in prior QA passes.

## Summary

Jira's connector (`app/connectors/jira.py`) and schema
(`jira_schema.py`) were already mature: 12 record types, extensive
fail-soft handling, and a very well-documented security-rules module
(`security_rules/jira.py`, 76 rules pre-pass). This pass found and fixed
four distinct categories of issue — two of them the largest fixes in this
QA series so far:

1. **`risk_rules/jira.py` did not exist at all** (the same "missing
   classifier module" gap found for SendGrid and Twilio in earlier passes).
   `risk_service.py` had no `jira_` dispatch branch, so **every Jira
   configuration change silently fell through to the Cloudflare DNS
   classifier** — the exact wrong-provider fallback this QA series
   repeatedly finds and fixes. Built the module from scratch (12
   record-type classifiers, ~50 field-level branches) and wired the
   dispatch into `risk_service.py`.

2. **Diff/drift tracking gap** (the other recurring root-cause bug in this
   series). Jira had **zero entries** in `diff_service.py`'s per-provider
   tracked-fields dispatch, so every Jira record type fell through to the
   Cloudflare DNS default tuple (`name`, `content`, `ttl`, `proxied`,
   `priority`, `comment` — none of which exist on any Jira record).
   `compute_diff` could never detect a modified field on an existing Jira
   record. Fixed by adding `_JIRA_TRACKED_FIELDS_BY_TYPE` (all 12 record
   types) and wiring the `jira_` prefix into `_tracked_fields_for`.

3. **10 Security Finding severity mismatches** between the actual runtime
   severity emitted by `security_rules/jira.py`'s `_fc()` calls and the
   rule's declared "headline severity" in `security_rule_pack.py` (which is
   supposed to mirror the frontend catalog, per that module's own
   docstring). Cross-checking all three sources (runtime code, pack, and
   frontend catalog) showed the **frontend and pack agreed with each other
   in all 10 cases** — only the runtime `severity=` argument in
   `security_rules/jira.py` disagreed. This means real `FindingCandidate`
   objects were carrying a severity inconsistent with what the rest of the
   system (registries + frontend UI) declares as that rule's correct
   severity. Fixed by correcting the 10 runtime `severity=` values to match
   the pack/frontend consensus (see table below).

4. **6 frontend catalog entries with no backend implementation** — the
   frontend `securityRuleCatalog.ts` had fully-specified entries (title,
   `whatItChecks`, evidence, remediation, false-positive guard) for 6 rule
   keys that did not exist anywhere in `security_rules/jira.py`. For 5 of
   them, the connector already fetches and normalizes the exact field the
   frontend spec names, so the correct fix was to **implement the missing
   backend rule** to match the pre-existing frontend spec. For the 6th
   (`jira_notification_scheme_project_role_recipients`), implementing it
   as specified would have **contradicted this codebase's own established
   convention** — the existing "healthy scheme" test fixture explicitly
   uses project-role recipients as the safe/preferred baseline (matching
   the `email_recipients` rule's own remediation text: "prefer groups or
   project roles over individual email recipients"). That frontend entry
   was removed as stale rather than implemented, since implementing it
   would flag the codebase's own recommended practice as a finding.

## Connector extraction review

| Record type | Source endpoint | Sensitive values excluded? | Fail-soft on 403/404? | Stable record IDs? |
|---|---|---|---|---|
| `jira_site` | `GET serverInfo`, `GET application/settings` | Yes — no base URL, server title, or health-check messages | N/A (required anchor surface — auth errors propagate, matching every other provider's primary surface) | Yes — constant `"site"` |
| `jira_project` | `GET project/search` | Yes — no key, name, lead identity, avatar URL, or description | N/A (anchor surface) | Yes — truncated numeric project ID |
| `jira_board` | `GET agile/1.0/board` | Yes — no board name, filter JQL, column names, quick-filter names, or swimlane query text | Yes — `except ConnectorError: return []` | Yes — truncated numeric board ID |
| `jira_workflow` | `GET workflow/search` | Yes — no workflow name, description, rule expressions, or configs | Yes | Yes — `entityId` |
| `jira_workflow_scheme` | `GET workflowscheme` | Yes — no scheme name/description or named mappings | Yes | Yes — truncated scheme ID |
| `jira_permission_scheme` | `GET permissionscheme` | Yes — no grant holder identities (users/groups/roles), scheme name, or description | Yes | Yes — truncated scheme ID |
| `jira_notification_scheme` | `GET notificationscheme` | Yes — no recipient identities (users/groups/emails), scheme name, or description | Yes | Yes — truncated scheme ID |
| `jira_issue_type_scheme` | `GET issuetypescheme` | Yes — no scheme name/description | Yes | Yes — truncated scheme ID |
| `jira_field_configuration_scheme` | `GET fieldconfigurationscheme` | Yes — no scheme name/description | Yes | Yes — truncated scheme ID |
| `jira_screen_scheme` | `GET screenscheme` | Yes — no scheme name/description or named screens | Yes | Yes — truncated scheme ID |
| `jira_webhook` | `GET webhook` | Yes — no delivery URL or secret value; only scheme category + presence booleans | Yes | Yes — truncated webhook ID |
| `jira_automation_rule` | `GET cb-automation/1.0/rule` | Yes — no rule name, description, component logic, or actor identities | Yes | Yes — truncated rule ID |

**Confirmed via code inspection** (connector module docstring + normalizer
bodies + a full read of every `_normalize_*` function):
- No **issue contents** are stored — the connector has no issue-search or
  issue-detail endpoint call at all.
- No **comments/descriptions** are stored — `has_description` fields are
  booleans (presence only), never the text itself.
- No **API token values** are stored — the token is used only in
  `httpx.Client(...).get(..., auth=(email, api_token))` and never copied
  into any record, logged, or returned from `validate_credentials()`.
- No **webhook secrets** are stored — `webhook_secret_present` is
  `bool(raw.get("secret") or raw.get("secretToken") or raw.get("signingSecret"))`,
  never the value.
- No **private user PII** is stored beyond safe metadata — `lead_present`
  is a boolean, never a lead's name/email/account ID.
- No **full webhook URLs** are stored — `_url_scheme_category()` reduces
  every URL to `"https"`/`"http"`/`"other"`/`"absent"` before any record is
  built; the raw `url` local variable is discarded after that call.
- No **project data/content** beyond configuration metadata — every
  project field is a boolean, count, or bounded category enum.

## Diff/change tracking review

**Before this pass**: 0 of 12 record types had a tracked-fields entry — all
Jira modified-field changes silently fell through to the Cloudflare DNS
default tuple and were never detected.

**After this pass**: all 12 record types are tracked with every
security-relevant field verified present, including all the task's
high-priority fields: `permission_anonymous_grant_count`,
`permission_anyone_grant_count`,
`permission_public_browse_projects`/`permission_public_administer_projects`,
`workflow_scheme_default_present`, project role/actor counts (project-role
grant count; Jira does not model per-actor group/user rosters — see "Not
modeled" section), `webhook_enabled`, `webhook_url_scheme_category`,
`webhook_secret_present`.

No fields were found that are tracked but no longer emitted by the
connector — the tracked tuples were built directly from `jira_schema.py`'s
`TypedDict` definitions cross-referenced against the connector's actual
normalizer output.

## Test matrix

| Test case | Normalized record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes/fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. Anonymous/public access enabled | `jira_permission_scheme` | `permission_anonymous_grant_count`, `permission_anyone_grant_count` | `0 → 1` | Change (high) + Finding (high) | Change never generated before fix (both bugs #1 and #2) | high | high (after fix) | `jira_permission_scheme_anonymous_grant`, `jira_permission_scheme_anyone_grant` | new `test_anonymous_grant_increase_is_high`, `test_permission_scheme_anonymous_grant_change_produces_drift_change` | **FIXED** | — |
| B. Anonymous/public access disabled | `jira_permission_scheme` | `permission_anonymous_grant_count`, `permission_anyone_grant_count` | `1 → 0` | Change (low, improvement) | Change never generated before fix | low | low (after fix) | n/a (Finding only fires on current-state grant > 0) | new `test_anonymous_grant_decrease_is_low` | **FIXED** | — |
| C. Browse project permission broadened | `jira_permission_scheme` | `permission_public_browse_projects` | `False → True` | Change (medium, per existing Finding convention — see design note) + Finding (medium) | Change never generated before fix | medium | medium (after fix) | `jira_permission_scheme_public_browse_projects` | new `test_public_browse_projects_true_is_medium` | **FIXED** | Task's generic guidance suggests "high"; this pass followed the project's existing Finding severity (medium) per task instruction to adjust to existing convention |
| D. Administer project permission broadened | `jira_permission_scheme` | `permission_public_administer_projects` | `False → True` | Change (high) + Finding (high) | Change never generated before fix | high | high (after fix) | `jira_permission_scheme_public_administer_projects` | new `test_public_administer_projects_true_is_high` | **FIXED** | — |
| E. Project role actor count increased/decreased | `jira_permission_scheme` | `permission_project_role_grant_count` | count change | Change (low, generic — project-role grants are the safe/preferred holder type) | Change never generated before fix | low | low (after fix) | n/a (no Finding — project roles are the recommended pattern, not a risk signal) | covered by `test_every_tracked_field_classifies_without_error_or_invalid_severity` | **FIXED (detection)** | Jira does not expose a separate "project role actors" record — role-holder grant counts live on the permission scheme record itself |
| F. Privileged project role actor count increased/decreased | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | The Jira REST API's `/project/{id}/role/{id}` actor-roster endpoint is not fetched — the connector only counts *grants naming a project-role holder type* on permission schemes (`permission_project_role_grant_count`), not the membership of any specific role (e.g., "Administrators" vs. "Developers"). Not invented per task instructions |
| G. Permission scheme changed | `jira_permission_scheme` | `permission_grant_count`, `permission_high_privilege_grant_count`, `permission_unknown_holder_count`, `permission_public_grant_count` | count increases | Change (medium) + Finding (medium) | Change never generated before fix | medium | medium (after fix) | `jira_permission_scheme_high_grant_count` (new), `jira_permission_scheme_high_privilege_grants`, `jira_permission_scheme_unknown_holder`, `jira_permission_scheme_high_public_grant_count` | covered by tracked-field sweep test | **FIXED** | `jira_permission_scheme_high_grant_count` is a new rule (gap #4) |
| H. Issue security scheme removed/disabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Jira's Issue Security Scheme is a distinct API resource (`/issuesecurityschemes`) from the Issue *Type* Scheme (`/issuetypescheme`), which the connector already covers. The connector does not fetch issue security schemes at all — not invented per task instructions. Do not confuse this with `jira_issue_type_scheme`, which is modeled and covered (see J.) |
| I. Issue security scheme added/enabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Same reason as H |
| J. Workflow scheme changed | `jira_workflow_scheme` | `workflow_scheme_default_present`, `workflow_scheme_unmapped_issue_type_count` | `True → False` / count increase | Change (medium) + Finding (medium) | Change never generated before fix | medium | medium (after fix) | `jira_workflow_scheme_no_default`, `jira_workflow_scheme_unmapped_issue_types` | new `test_workflow_scheme_default_removed_is_medium` | **FIXED** | `jira_workflow_scheme_no_default` severity was also corrected low→medium (bug #3) |
| K. Notification scheme changed | `jira_notification_scheme` | `notification_count`, `notification_email_recipient_count` | count change | Change (medium) + Finding (medium) | Change never generated before fix | medium | medium (after fix) | `jira_notification_scheme_no_notifications`, `jira_notification_scheme_email_recipients` | covered by tracked-field sweep test | **FIXED** | Both Finding severities also corrected low→medium (bug #3) |
| L. Webhook HTTP/HTTPS scheme | `jira_webhook` | `webhook_url_scheme_category` | `"https" → "http"` | Change (high) + Finding (high) | Change never generated before fix | high | high (after fix) | `jira_webhook_non_https` | new `test_webhook_http_scheme_is_high`, `test_webhook_https_restored_is_low` | **FIXED** | — |
| M. Webhook secret/signing/SSL posture | `jira_webhook` | `webhook_secret_present` | `True → False` | Change (high) + Finding (high) | Change never generated before fix | high | high (after fix) | `jira_webhook_no_secret_indicator` | new `test_webhook_secret_removed_is_high` | **FIXED** | Jira Cloud webhooks have no separate SSL-verification toggle exposed by the REST API (unlike GitLab/Terraform Cloud) — only secret presence and URL scheme are modeled, matching what the connector can actually observe |
| N. Application access posture changed | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Jira/Atlassian "application access" (product access grants like Jira Software vs. Jira Service Management) is an organization-level Atlassian Admin API concept not fetched by this connector — distinct from anything already in scope. Not invented per task instructions |
| O. Unknown/missing fields never produce high findings | all 12 record types | any | `None`/missing | no high finding/classification | Confirmed — every Finding check in `security_rules/jira.py` uses `is True`/`is False`/explicit category-string equality (never bare truthiness), and every new Change classifier branch falls to `low` on unparseable/missing values via `_int_pair`'s `try/except` guard or an explicit "unknown or missing" branch | none | none | all | new `test_every_tracked_field_classifies_without_error_or_invalid_severity` (exercises every tracked field across all 12 record types) | PASS | — |
| P. 403/404 fail-soft on optional endpoints | boards, workflows, workflow schemes, permission schemes, notification schemes, issue type schemes, field config schemes, screen schemes, webhooks, automation rules | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed — every optional fetcher wraps its call in `except ConnectorError: return []` (site and projects are the only required/anchor surfaces, matching every other provider's convention) | n/a | n/a | n/a | existing `test_milestone86a` connector tests | PASS | — |
| Q. Records with normalized fields but no security rule | `jira_field_configuration_scheme` (no rules at all — evaluator exists but returns `[]`); assorted count/category fields on rule-bearing types (e.g. `jira_project.board_count`, `jira_workflow.workflow_status_category_count`) | n/a | n/a | correctly no finding | Confirmed intentional — `field_configuration_count`/`required_field_count`/`hidden_field_count` are frequently `None` (the connector only populates them when the API echoes mappings, to avoid false-positive "no configurations" findings on schemes whose members weren't expanded), and no dedicated rule was ever added for this record type | n/a | n/a | n/a | existing `test_jira_provider_depth_qa.py` coverage | PASS (intentional, documented) | — |
| R. Security rules with no reachable normalized record | — | — | — | — | None found — all 81 rules dispatch from `evaluate()` against one of the 11 rule-bearing record types the connector actually emits (verified by the existing `test_no_live_jira_record_type_is_dead` and `test_every_live_jira_rule_fires_for_some_risky_record` regression tests, both passing after this pass's fixes) | n/a | n/a | all | existing depth-QA reachability tests | PASS | Zero dead/unreachable rules after the `jira_workflow_scheme_low_project_count` reachability-sweep fix (see Fixes made) |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | 81/81 rule keys present everywhere, matching severities | Verified via exact set diff: `security_rules/jira.py` (81, after removing false-positive `record_id` fallback strings from the raw grep) vs. `security_rule_registry.py` (81), `security_rule_pack.py` (81, all severities cross-checked), `security_rule_confidence.py` (81), and `securityRuleCatalog.ts` (81) | n/a | n/a | all | new tests plus existing `test_jira_provider_depth_qa.py` GROUP A tests | **FIXED (severity mismatches) + FIXED (missing rules) + FIXED (stale entry removed)** | See bugs #3 and #4 |
| Diff-tracked fields present for all 12 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 12 record types tracked (before fix)** → **12 of 12 tracked (after fix)** | n/a | n/a | n/a | new `TestJiraDiffTrackedFields` (5 tests) | **FIXED** | Bug #2 |
| Risk classification module exists and is wired | all | all tracked fields | n/a | every Change gets a Jira-specific classification, not the Cloudflare DNS fallback | **module did not exist (before fix)** → **12 classifiers + dispatch wired (after fix)** | n/a | n/a | n/a | new `TestJiraRiskClassifier` (14 tests, including a dispatch-level regression test through `risk_service.classify_change`) | **FIXED** | Bug #1 — the largest fix in this pass |

## Design note: why `permission_public_browse_projects` is `medium`, not `high`

The task's generic guidance suggests "browse permission broadened to
anonymous/public/broad groups: high." This pass followed the *existing*
project convention instead (per the task's own instruction to adjust to
existing conventions where they differ): `security_rules/jira.py` already
classifies public browse-projects access as `medium`
(`jira_permission_scheme_public_browse_projects`), reserving `high` for
permissions with a more direct write/administrative impact (administer
projects, manage sprints, create issues, transition issues) and for the
`anonymous`/`anyone` *holder-type* grants regardless of which permission
they cover. Browsing is read-only visibility, which this codebase already
treats as one tier below the four write/administrative public-grant rules.
The new `risk_rules/jira.py` Change classifier mirrors this exactly, so
Finding and Change severities agree for this field.

## Tracked-fields vs. classifier-branch comparison

| Record type | Tracked fields with dedicated classification | Tracked fields using generic fallback (intentional) |
|---|---|---|
| `jira_site` | — | All tracked fields (`site_url_present`, `project_count`, `webhook_count`, `automation_rule_count`) — pure structural/rollup counts with no independent directional risk signal; the underlying risk (e.g., zero projects/webhooks/automation rules) is already captured by current-state Findings, not a transition |
| `jira_project` | `project_private`, `project_deleted` | `project_archived`, `project_simplified`, `project_key_present`, `project_type_category`, `project_style_category`, `board_count`, `issue_type_count`, `lead_present` — feature/lifecycle metadata with no clear directional risk signal |
| `jira_board` | `board_jql_filter_broad`, `project_id` | `board_type_category`, `board_location_type_category`, `board_filter_present`, `board_column_count`, `board_quick_filter_count`, `board_swimlane_strategy_category` — structural/categorical fields already covered by their own current-state Findings where relevant |
| `jira_workflow` | `workflow_active`, `workflow_status_count`, `workflow_transition_count`, `workflow_global_transition_count`, `workflow_orphan_status_count`, `workflow_transition_rule_count`, `workflow_validator_count`, `workflow_condition_count` | `workflow_has_done_status`, `workflow_has_in_progress_status`, `workflow_post_function_count`, `workflow_status_category_count`, `workflow_draft` — hygiene-flavored fields where the current-state Finding (already low severity) is the primary signal, not the transition |
| `jira_workflow_scheme` | `workflow_scheme_default_present`, `workflow_scheme_unmapped_issue_type_count`, `workflow_scheme_project_count` | `workflow_scheme_workflow_count`, `workflow_scheme_issue_type_mapping_count` — low-signal counts |
| `jira_permission_scheme` | `permission_anonymous_grant_count`, `permission_anyone_grant_count`, `permission_logged_in_grant_count`, `permission_public_browse_projects`, `permission_public_administer_projects`, `permission_public_manage_sprints`, `permission_public_create_issues`, `permission_public_transition_issues`, `permission_unknown_holder_count`, `permission_high_privilege_grant_count`, `permission_public_grant_count`, `permission_grant_count` | `permission_project_role_grant_count` — the safe/preferred holder type, correctly never flagged (see bug #4 design note) |
| `jira_notification_scheme` | `notification_count`, `notification_email_recipient_count`, `notification_unknown_recipient_count` | `notification_group_recipient_count`, `notification_project_role_recipient_count`, `notification_event_count` — low-signal or (for project-role recipients) intentionally-safe fields |
| `jira_issue_type_scheme` | `default_issue_type_present` | `issue_type_count` |
| `jira_field_configuration_scheme` | — | All tracked fields — no security rule exists for this record type at all (documented, intentional; see Q above) |
| `jira_screen_scheme` | `screen_count` | `tab_count`, `field_count`, `screen_tab_count`, `screen_unmapped_screen_count` |
| `jira_webhook` | `webhook_enabled`, `webhook_secret_present`, `webhook_url_scheme_category`, `webhook_jql_filter_present`, `webhook_event_count`, `webhook_has_comment_events`, `webhook_has_attachment_events`, `webhook_all_issue_events` | `webhook_url_present`, `webhook_has_issue_events`, `webhook_has_project_events`, `webhook_has_sprint_events`, `webhook_has_worklog_events`, `webhook_jql_empty_or_broad`, `webhook_event_scope_category` — either redundant with a more specific sibling field or explicitly not modeled as a separate rule (per the module's own "intentionally NOT added" comment for JQL breadth) |
| `jira_automation_rule` | `automation_enabled`, `automation_scope_category`, `automation_has_web_request_action`, `automation_has_external_action`, `automation_has_email_action`, `automation_action_count`, `automation_branch_count`, `automation_component_count` | `automation_trigger_type_category`, `automation_has_comment_action` — low-severity hygiene fields already matching their Finding's low severity via the generic fallback |

**Classifier branches referring to fields not emitted by the
connector/schema:** none found in the new `risk_rules/jira.py` — every
`fp ==` check was written directly against `jira_schema.py`'s `TypedDict`
definitions and cross-verified against the connector's actual normalizer
output before being added.

**Classifier branches referring to old/stale field names:** none — this is
a newly-built module, so there was no legacy field-name drift to inherit.

## Mock-shape (`old_value`/`prev_value`) verification

Since `risk_rules/jira.py` did not exist before this pass, there was no
pre-existing mock-shape bug to find. The module was written to read
`prev_value` directly from the start (matching `compute_diff`'s real
output), and a dedicated regression test
(`test_classifier_reads_real_compute_diff_dict_shape_not_a_mock`) builds a
plain dict shaped exactly like real `compute_diff` output — not a
`MagicMock` — to guard against this exact bug class recurring, consistent
with the precedent established after Terraform Cloud's first QA pass.

## Fixes made

1. **`backend/app/services/risk_rules/jira.py`** (new file) — 12
   record-type classifiers (`_classify_site_change` through
   `_classify_automation_rule_change`) plus the `classify_jira_change`
   dispatcher, covering every field in the new tracked-fields table with
   either a specific branch or an intentional, documented generic fallback.
2. **`backend/app/services/risk_service.py`** — added the `jira_` prefix
   dispatch branch to `classify_change`, routing Jira changes to the new
   module instead of the Cloudflare DNS fallback.
3. **`backend/app/services/diff_service.py`** — added
   `_JIRA_TRACKED_FIELDS_BY_TYPE` (all 12 record types) and wired the
   `jira_` prefix into `_tracked_fields_for`. Updated the function's
   docstring.
4. **`backend/app/services/security_rules/jira.py`** — corrected 10
   Security Finding severities that disagreed with `security_rule_pack.py`
   and the frontend catalog (both of which already agreed with each
   other): `jira_board_unknown_location_type` low→medium,
   `jira_workflow_no_statuses` low→medium,
   `jira_workflow_excessive_global_transitions` medium→low,
   `jira_workflow_inactive` low→medium,
   `jira_workflow_scheme_no_default` low→medium,
   `jira_notification_scheme_no_notifications` low→medium,
   `jira_notification_scheme_email_recipients` low→medium,
   `jira_webhook_disabled` low→medium, `jira_webhook_no_events`
   low→medium, `jira_webhook_no_jql_filter` medium→low. Also implemented 5
   new rules that the frontend catalog already specified but the backend
   never had: `jira_workflow_draft`,
   `jira_workflow_scheme_low_project_count`,
   `jira_permission_scheme_high_grant_count`,
   `jira_webhook_broad_event_scope`,
   `jira_automation_rule_high_component_count`.
5. **`backend/app/services/security_rule_registry.py`**,
   **`security_rule_pack.py`**, **`security_rule_confidence.py`**,
   **`security_coverage_service.py`** — registered the 5 new rule keys to
   restore 81/81 parity.
6. **`frontend/src/lib/securityRuleCatalog.ts`** — removed the stale
   `jira_notification_scheme_project_role_recipients` entry (see bug #4 —
   implementing it would have contradicted the codebase's own established
   "project roles are the safe/preferred recipient type" convention).
7. **Test files** — added `TestJiraDiffTrackedFields` (5 tests) and
   `TestJiraRiskClassifier` (14 tests) to
   `test_milestone86a_jira_drift_provider_foundation.py`; updated 3 stale
   hardcoded rule-count assertions (76→81) across
   `test_jira_provider_depth_qa.py`, `test_milestone86h_jira_provider_depth_qa.py`,
   and `test_milestone86i_jira_cross_cloud_ux_polish.py`; added one
   explicit reachability-sweep record for
   `jira_workflow_scheme_low_project_count` in
   `test_jira_provider_depth_qa.py`'s `_all_jira_findings()` helper (its
   narrow `0 < count < floor` firing window can't be hit by the existing
   generic 0/999 extreme-value sweep, the same pattern already used there
   for the three category-keyed rules).
8. **`backend/tests/reports/jira_detection_matrix.md`** — this report.

## Not fixed in this pass (explicitly out of scope)

- **Issue Security Schemes** (task categories H/I) — a distinct Jira API
  resource from Issue *Type* Schemes (which are modeled); no endpoint is
  fetched. Would require a new connector capability, not a QA-pass fix.
- **Privileged project role actor rosters** (task category F) — the
  connector counts permission-scheme grants by holder type, not actual
  role membership per project. Would require new
  `/project/{id}/role/{id}` endpoint calls.
- **Application access posture** (task category N) — an
  organization-level Atlassian Admin API concept, out of this connector's
  current scope.
- **Jira Cloud webhook SSL verification toggle** — unlike GitLab/Terraform
  Cloud, the Jira Cloud REST API does not expose a separate SSL-verification
  setting for webhooks; only secret presence and URL scheme are observable
  and are already covered (task category M).

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone86a_jira_drift_provider_foundation.py -q
# 160 passed (was 121 before this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone86b_jira_core_security_foundation.py \
    tests/test_milestone86c_jira_workflow_webhook_risk_expansion.py -q
# 144 passed

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "jira"
# 982 passed, 16051 deselected (was 932 passed before any fixes in this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*jira* -q
# 966 passed

cd /Users/rohan/Downloads/ConfigTrace/frontend
npx tsc --noEmit
# clean, no output — frontend catalog entry removal is type-safe
```

## Frontend

`frontend/src/lib/securityRuleCatalog.ts` was changed (one stale entry
removed), so `npx tsc --noEmit` was run and passed clean with no errors.
