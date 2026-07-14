# Linear Detection QA Matrix

Exhaustive end-to-end validation of the Linear provider (connector → diff
tracking → risk classification → security findings → registries → frontend
catalog), following the same methodology established for SendGrid, Twilio,
Terraform Cloud, GitLab, and Jira in prior QA passes.

## Summary

Linear's connector (`app/connectors/linear.py`), schema
(`linear_schema.py`), and security rules (`security_rules/linear.py`, 39
rules across all 9 record types) were already mature. Unlike Jira's
equivalent pass, **registries and the frontend catalog were already in
perfect parity (39/39, zero severity mismatches)** — no fixes needed
there. The recurring root-cause bugs from every prior provider pass were
both present here, and both are the primary fixes in this pass:

1. **`risk_rules/linear.py` did not exist at all.** `risk_service.py` had
   no `linear_` dispatch branch, so **every Linear configuration change
   silently fell through to the Cloudflare DNS classifier**. Built the
   module from scratch (9 record-type classifiers) and wired the dispatch.

2. **Diff/drift tracking gap.** Linear had **zero entries** in
   `diff_service.py`'s per-provider tracked-fields dispatch, so every
   Linear record type fell through to the Cloudflare DNS default tuple
   (`name`, `content`, `ttl`, `proxied`, `priority`, `comment` — none of
   which exist on any Linear record). `compute_diff` could never detect a
   modified field on an existing Linear record. Fixed by adding
   `_LINEAR_TRACKED_FIELDS_BY_TYPE` (all 9 record types) and wiring the
   `linear_` prefix into `_tracked_fields_for`.

**A design gap was also identified but deliberately not "fixed" as a new
Security Finding** (see the design note below): Linear's `private_team`
field only has a Finding for the *private* state (a low-severity,
informational "review whether this is intentional" note) — there is no
Finding at all for a team being *not* private. This is intentional, not an
oversight: since most Linear teams are non-private by default, flagging
every non-private team would be extremely noisy and inconsistent with
this rule's own documented framing ("private is a common and often
intentional configuration"). However, the *transition* from private to
non-private is still a meaningful visibility-broadening signal, so the new
Change classifier flags it at `medium` — the same "Change layer catches
transitions the Finding layer structurally cannot" pattern established for
GitLab/Terraform Cloud/Jira in prior passes.

## Connector extraction review

| Record type | Source (GraphQL query) | Sensitive values excluded? | Fail-soft on error? | Stable record IDs? |
|---|---|---|---|---|
| `linear_workspace` | `organization { id name urlKey logoUrl teams }` | Partial — see privacy note below | N/A (required anchor surface, propagates on failure like every other provider's primary surface) | Yes — organization `id` |
| `linear_team` | `teams(first: 100) { nodes { ... } }` | Partial — see privacy note | N/A (anchor surface) | Yes — team `id` |
| `linear_project` | `projects(first: 100) { nodes { ... } }` | Partial — see privacy note | N/A (anchor surface) | Yes — project `id` |
| `linear_workflow_state` | `workflowStates(first: 200) { nodes { ... } }` | Partial — see privacy note | Yes — `fetch()` wraps this in `try/except: skip` for activity ingestion; the main `fetch()` path treats it as best-effort alongside other optional surfaces | Yes — state `id` |
| `linear_label` | `issueLabels(first: 200) { nodes { ... } }` | Partial — see privacy note | Yes | Yes — label `id` |
| `linear_webhook` | `webhooks(first: 100) { nodes { ... } }` | Yes — URL and secret are read only to derive `webhook_url_scheme_category`/`*_present` booleans, then explicitly `del`eted before the record is built | Yes | Yes — webhook `id` |
| `linear_view` | `customViews(first: 100) { nodes { ... } }` | Partial — see privacy note | Yes | Yes — view `id` |
| `linear_cycle` | `cycles(first: 100, filter: {isActive: {eq: true}})` | Partial — see privacy note | Yes | Yes — cycle `id` |
| `linear_integration` | `integrations(first: 100) { nodes { ... } }` | Yes — only `service` (category string), `enabled`, and `team.id` are read | Yes — `_fetch_integrations` explicitly catches `ConnectorError`/`NetworkError`/`RateLimitError` and returns `[]`, since integrations may not be available on all plans/API-key scopes | Yes — integration `id` |

### Privacy note: `resource_name` is stored (a deliberate, documented design difference from GitLab/Jira/Terraform Cloud)

Unlike every other provider connector reviewed in this QA series — which
explicitly never store project/team/repo/workspace **names** — the Linear
connector's `_normalize_workspace`, `_normalize_team`, `_normalize_project`,
`_normalize_workflow_state`, `_normalize_label`, `_normalize_view`, and
`_normalize_cycle` functions all store the resource's raw `name` field
(truncated to 100 chars) as `"resource_name"` in the normalized record.
This is confirmed **intentional, not an oversight**:

- The `LinearWorkspaceRecord`/`LinearTeamRecord`/etc. `TypedDict`
  definitions in `linear_schema.py` declare `resource_name: str` as a
  required (non-`Optional`) field.
- `test_milestone85a_linear_drift_provider_foundation.py`'s own
  `_FORBIDDEN_RECORD_FIELDS` set (used by 6+ "no forbidden fields" tests
  across every record type) does **not** include `"name"` or
  `"resource_name"` — it lists `api_key`, `token`, `oauth_token`, `secret`,
  `webhook_secret`, `authorization`, `email`, `user_email`, `phone`,
  `webhook_url`, `delivery_url`, `issue_title`, `issue_description`,
  `comment`, `payload`, `headers`. Every one of these forbidden-field
  tests already passes with `resource_name` present in every record.
- This is consistent across the entire M85A–M85I Linear milestone arc (9
  test files), not an isolated gap.

This is flagged here for visibility because it's a genuine
cross-provider inconsistency worth the team's awareness — GitLab's and
Jira's connector docstrings explicitly state "project names... are never
stored," while Linear's connector stores workspace/team/project/workflow
state/label/view/cycle names by design. **This QA pass did not change this
behavior**: removing it would be a security-architecture decision, not a
detection-QA fix, would touch 9 already-passing milestone test files that
assert names are captured, and is outside this task's scope ("do not
invent unsupported capabilities" cuts both ways — this pass also
shouldn't silently remove an established, tested capability without
explicit direction). Recommend a follow-up conversation with the team to
decide whether this is intentional product behavior (e.g., because Linear
workspace/team/project names are considered non-sensitive display labels)
or should be brought in line with the stricter GitLab/Jira convention.

**Confirmed via code inspection** (connector class docstring + normalizer
bodies + `list_activity_events` docstring):
- No **issue titles, descriptions, or comment bodies** are stored — the
  connector has no issue-detail or comment endpoint call at all.
- No **API key values** are stored — `_query()`'s `api_key` parameter is
  used only in the `Authorization` header and never copied into a record,
  logged, or returned from `validate_credentials()`.
- No **webhook secrets** are stored — `_normalize_webhook` reads
  `raw.get("secret")` only to compute `bool(secret)`, then executes `del
  secret` before returning the record.
- No **full webhook URLs** are stored — same pattern: `url` is reduced to
  `_url_scheme_category(url)` and `bool(url)`, then `del url`.
- No **user PII** (emails, names, account IDs) is stored — member/lead
  fields are reduced to presence booleans (`lead_present`) or bucketed
  counts (`member_count_category`), never identities.
- No **audit/activity payloads** are stored — the connector's own
  docstring explicitly notes that Linear's real audit API includes actor
  emails, IPs, and user agents, and that ConfigTrace deliberately
  synthesizes safe activity events from the same drift surfaces instead of
  ingesting that audit feed.

## Diff/change tracking review

**Before this pass**: 0 of 9 record types had a tracked-fields entry — all
Linear modified-field changes silently fell through to the Cloudflare DNS
default tuple and were never detected.

**After this pass**: all 9 record types are tracked with every
security-relevant field verified present, including all the task's
high-priority fields: `private_team`/`team_visibility_category`,
`member_count_category` (team and project level), `webhook_enabled`,
`webhook_secret_present`, `webhook_url_scheme_category`,
`integration_enabled`, `team_id` (scope) on label/webhook/view/cycle/
integration records.

No fields were found that are tracked but no longer emitted by the
connector — the tracked tuples were built directly from
`linear_schema.py`'s `TypedDict` definitions, cross-referenced against the
connector's actual normalizer output.

## Test matrix

| Test case | Normalized record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes/fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. Workspace/member count changed | `linear_workspace` | `team_count`, `webhook_count`, `integration_count` | count change | Change (low) + Finding (low) | Change never generated before fix (diff-tracking gap) | low | low (after fix) | `linear_workspace_low_team_count`, `linear_workspace_no_webhooks`, `linear_workspace_no_integrations` | new `TestLinearDiffTrackedFields` sweep | **FIXED** | Linear has no workspace-level "member count" — the only workspace-level counts are teams/webhooks/integrations. Per-workspace member/admin/guest counts are not exposed by this connector — see item B/C |
| B. Admin/owner count | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Linear's GraphQL API does not expose a workspace-wide admin/owner role breakdown through any endpoint this connector queries; only `viewer { id }` (for credential validation, not stored) touches user-level data at all. Not invented per task instructions |
| C. Guest/external member count | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Same reason as B — no guest/external-member endpoint is fetched. Linear's team/project `member_count_category` fields are aggregate bucketed counts with no internal/external/guest breakdown |
| D. Team visibility/access broadened/restricted | `linear_team` | `private_team` | `True → False` (broadened) / `False → True` (restricted) | Change (medium broadened / low improvement) + Finding (low, informational, current-state-only) | Change never generated before fix | medium / low | medium / low (after fix) | `linear_team_private` (low, current-state) — **intentional Finding/Change disagreement, see design note** | new `test_team_visibility_broadened_is_medium`, `test_team_made_private_is_low`, `test_team_private_change_produces_drift_change` | **FIXED** | See Summary's design note — the Finding only flags the private *state* (low, informational); the Change classifier flags the *transition to non-private* at medium, since that's the actual broadening event |
| E. Integration enabled/disabled | `linear_integration` | `integration_enabled` | `True → False` | Change (medium) + Finding (medium) | Change never generated before fix | medium | medium (after fix) | `linear_integration_disabled` (medium) — matches | new `test_integration_disabled_is_medium` | **FIXED** | — |
| F. Integration broad access/scope posture | `linear_integration` | `team_id` | team-scoped → workspace-scoped (`None`) | Change (low) + Finding (low, `linear_integration_workspace_scoped`) | Change never generated before fix | low | low (after fix) | `linear_integration_workspace_scoped` (low) — matches | covered by tracked-field sweep | **FIXED** | Linear's integration model doesn't expose a broader "scope"/permission-grant concept beyond team-vs-workspace association — matches the connector's actual evidence |
| G. Webhook enabled/disabled | `linear_webhook` | `webhook_enabled` | `True → False` | Change (medium) + Finding (medium) | Change never generated before fix | medium | medium (after fix) | `linear_webhook_disabled` (medium) — matches | covered by tracked-field sweep | **FIXED** | — |
| H. Webhook signing/secret posture | `linear_webhook` | `webhook_secret_present` | `True → False` | Change (high) + Finding (high) | Change never generated before fix | high | high (after fix) | `linear_webhook_no_secret_indicator` (high) — matches | new `test_webhook_secret_removed_is_high`, `test_webhook_secret_present_change_produces_drift_change` | **FIXED** | — |
| I. Webhook HTTP/HTTPS scheme | `linear_webhook` | `webhook_url_scheme_category` | `"https" → "non_https"` | Change (high) + Finding (high) | Change never generated before fix | high | high (after fix) | `linear_webhook_non_https` (high) — matches | new `test_webhook_non_https_is_high`, `test_webhook_https_restored_is_low` | **FIXED** | Linear's connector categorizes scheme as `"https"`/`"non_https"`/`"absent"` (coarser than GitLab/Jira's `"https"`/`"http"`/`"other"`/`"absent"`, since the GraphQL API doesn't expose non-HTTP-non-HTTPS schemes distinctly) — the classifier matches this actual category set |
| J. API key/token metadata posture | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Linear's API uses a single opaque personal API key per connection (validated via `viewer { id }`); there is no per-key metadata endpoint (creation date, scopes, last-used) that this connector fetches. Not invented per task instructions |
| K. OAuth/app access posture | n/a | n/a | n/a | n/a | not modeled beyond `linear_integration` | n/a | n/a | n/a | n/a | **PASS (covered by E/F)** | n/a | Linear's "integrations" surface (Slack, GitHub, etc.) is the closest analog to "OAuth/app access" in this connector's scope, and is already covered by categories E/F above. A separate OAuth-application-registry endpoint (distinct from configured integrations) is not fetched |
| L. Project/team/issue visibility changed | `linear_team`, `linear_project` | `private_team`, `project_status_category` | see D above; project status has no visibility concept, only workflow status | Change (medium/low) + Finding | covered by D for team visibility; project has no separate visibility field — Linear projects don't have a public/private flag independent of their teams' visibility | n/a for project-level visibility (not modeled — inherits from team) | n/a | n/a | see D | **PASS (folded into D)** | Linear does not expose per-project visibility independent of team visibility in this connector's schema |
| M. Unknown/missing fields never produce high findings | all 9 record types | any | `None`/missing | no high finding/classification | Confirmed — every Finding check in `security_rules/linear.py` uses `is True`/`is False`/explicit category-string equality, and every new Change classifier branch falls to `low` on unparseable/missing values via `_int_pair`'s `try/except` guard or an explicit "unknown or missing" branch | none | none | all | new `test_every_tracked_field_classifies_without_error_or_invalid_severity`, `test_unknown_transitions_never_produce_high` (5 field/record-type combinations) | PASS | — |
| N. 403/404 fail-soft on optional endpoints | `linear_integration` (explicitly documented as plan/scope-gated) | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed — `_fetch_integrations` wraps its query in `except (ConnectorError, NetworkError, RateLimitError): return []`; `list_activity_events` wraps `workflow_states`/`labels`/`views`/`cycles` fetches in bare `try/except Exception: skip` for the activity path specifically | n/a | n/a | n/a | existing `test_milestone85a` connector tests | PASS | — |
| O. Records with normalized fields but no security rule | none found — every one of the 9 record types has at least one rule, and every tracked field either has a dedicated rule or a documented reason for using the generic fallback (see comparison table below) | n/a | n/a | correctly no gaps | Confirmed — cross-referenced every tracked field against `security_rules/linear.py`'s eval functions | n/a | n/a | n/a | existing `test_linear_provider_depth_qa.py` coverage | PASS | — |
| P. Security rules with no reachable normalized record | — | — | — | — | None found — all 39 rules dispatch from `evaluate()` against one of the 9 record types the connector actually emits | n/a | n/a | all | existing depth-QA reachability tests (all still passing after this pass) | PASS | Zero dead/unreachable rules |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | 39/39 rule keys present everywhere with matching severities | Verified via exact set diff (excluding the 9 `record_id` fallback string false-positives): `security_rules/linear.py` (39) vs. `security_rule_registry.py` (39), `security_rule_pack.py` (39, all severities cross-checked programmatically, zero mismatches), `security_rule_confidence.py` (39), and `securityRuleCatalog.ts` (39) | n/a | n/a | all | none pre-existing; verified via ad hoc scripted diff in this pass | PASS | Zero mismatches — no fix needed (unlike Jira's equivalent pass, which found 10 severity mismatches and 6 catalog gaps) |
| Diff-tracked fields present for all 9 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 9 record types tracked (before fix)** → **9 of 9 tracked (after fix)** | n/a | n/a | n/a | new `TestLinearDiffTrackedFields` (5 tests) | **FIXED** | Root-cause fix — see Summary #2 |
| Risk classification module exists and is wired | all | all tracked fields | n/a | every Change gets a Linear-specific classification, not the Cloudflare DNS fallback | **module did not exist (before fix)** → **9 classifiers + dispatch wired (after fix)** | n/a | n/a | n/a | new `TestLinearRiskClassifier` (13 tests, including a dispatch-level regression test through `risk_service.classify_change`) | **FIXED** | Summary #1 — the largest fix in this pass |

## Tracked-fields vs. classifier-branch comparison

| Record type | Tracked fields with dedicated classification | Tracked fields using generic fallback (intentional) |
|---|---|---|
| `linear_workspace` | `webhook_count`, `integration_count` | `resource_name`, `url_key_present`, `logo_present`, `team_count` — matches their Findings' `low` severity via the generic fallback (all four are structural/hygiene signals, no directional risk beyond "count dropped," which the workspace's own dedicated branches for webhook/integration counts already model as the pattern) |
| `linear_team` | `private_team`, `has_completed_state` | `resource_name`, `member_count_category`, `project_count`, `auto_archive_enabled`, `cycle_enabled`, `cycle_duration_category`, `has_backlog_state`, `has_started_state`, `has_canceled_state`, `workflow_state_count`, `label_count`, `webhook_count` — all match their Findings' `low` severity; `has_completed_state` is the one exception (its Finding is `medium`, since losing the ability to mark issues "done" is a more disruptive workflow gap than missing backlog/started/canceled categories) |
| `linear_project` | `lead_present`, `team_count`, `project_health_category` | `resource_name`, `member_count_category`, `issue_count_category`, `project_status_category` — match their Findings' `low` severity |
| `linear_workflow_state` | — | All tracked fields — the only Finding for this record type (`unknown_type`) is `low`, and none of the fields carry a directional risk signal |
| `linear_label` | `team_id` | `resource_name`, `is_group_label`, `parent_id_present` — no dedicated Finding for these two booleans |
| `linear_webhook` | `webhook_enabled`, `webhook_secret_present`, `webhook_url_scheme_category`, `webhook_resource_types_count`, `webhook_has_comment_type` | `webhook_url_present`, `webhook_has_attachment_type`, `team_id` — `webhook_has_attachment_type`'s Finding is `low` (matches the generic fallback exactly); `webhook_url_present` and `team_id` have no dedicated Finding |
| `linear_view` | `view_shared` | `resource_name`, `filter_count_category`, `team_id` — `linear_view_shared_without_team_scope` is a *combined* condition (shared=True AND team_id=None) that a single-field Change classifier can't cheaply replicate; this mirrors the same accepted limitation documented for GitLab's and Terraform Cloud's combined-condition Findings in prior passes |
| `linear_cycle` | — | `resource_name`, `active` (a structural constant — the connector only ever fetches `isActive: {eq: true}` cycles, so this field is always `True` and can never actually change, matching the exact "constant field" pattern already documented for GitLab's webhook `enabled` field), `team_id`, `issue_count_category` (matches its Finding's `low` severity) |
| `linear_integration` | `integration_enabled`, `team_id` | `integration_type_category` — matches its Finding's `low` severity |

**Classifier branches referring to fields not emitted by the
connector/schema:** none found — every `fp ==` check in
`risk_rules/linear.py` was written directly against `linear_schema.py`'s
`TypedDict` definitions and cross-verified against the connector's actual
normalizer output.

**Classifier branches referring to old/stale field names:** none — this
is a newly-built module, so there was no legacy field-name drift to
inherit (matching the precedent set by Jira's equivalent newly-built
module, which also had no `old_value`/`prev_value` bug).

## Mock-shape (`old_value`/`prev_value`) verification

Since `risk_rules/linear.py` did not exist before this pass, there was no
pre-existing mock-shape bug to find. The module was written to read
`prev_value` directly from the start (matching `compute_diff`'s real
output), and a dedicated regression test
(`test_classifier_reads_real_compute_diff_dict_shape_not_a_mock`) builds a
plain dict shaped exactly like real `compute_diff` output — not a
`MagicMock` — to guard against this exact bug class recurring.

## Fixes made

1. **`backend/app/services/risk_rules/linear.py`** (new file) — 9
   record-type classifiers (`_classify_workspace_change` through
   `_classify_integration_change`) plus the `classify_linear_change`
   dispatcher.
2. **`backend/app/services/risk_service.py`** — added the `linear_` prefix
   dispatch branch to `classify_change`, routing Linear changes to the new
   module instead of the Cloudflare DNS fallback.
3. **`backend/app/services/diff_service.py`** — added
   `_LINEAR_TRACKED_FIELDS_BY_TYPE` (all 9 record types) and wired the
   `linear_` prefix into `_tracked_fields_for`. Updated the function's
   docstring.
4. **`backend/tests/test_milestone85a_linear_drift_provider_foundation.py`**
   — added `TestLinearDiffTrackedFields` (5 tests) and
   `TestLinearRiskClassifier` (13 tests, including a dispatch-level
   regression test and a dict-shaped mock-bug-prevention test).
5. **`backend/tests/reports/linear_detection_matrix.md`** — this report.

No changes were made to `security_rules/linear.py`, the four backend
registries, or the frontend catalog — all were already correct and in
perfect 39/39 parity with zero severity mismatches, unlike Jira's
equivalent pass which required 10 severity fixes and 5 new rules.

## Not fixed in this pass (explicitly out of scope)

- **`resource_name` storage** — see the privacy note above. This is a
  pre-existing, deliberately-tested design decision, not a bug introduced
  or found by this pass; flagged for team awareness, not changed.
- **Workspace-level member/admin/guest counts** (task categories A/B/C) —
  no endpoint is fetched for organization-wide membership breakdowns.
- **Per-project visibility** (task category L) — Linear projects inherit
  visibility from their teams; no independent project-level visibility
  flag exists in the API surface this connector queries.
- **API key/token metadata** (task category J) — no per-key metadata
  endpoint is fetched.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone85a_linear_drift_provider_foundation.py -q
# 129 passed (was 100 before this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "linear"
# 809 passed, 16259 deselected (was 790 before any fixes in this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*linear* -q
# 796 passed
```

No frontend files were touched in this pass (registries and the frontend
catalog already had perfect parity with zero severity mismatches — no new
Security Finding rule was added or changed), so `npx tsc --noEmit` was not
run.
