# Sentry Reliability Certification (Sentry Message 7 of 8)

## Inventory

- 18 record types confirmed present, all tracked and classified: `sentry_organization`, `sentry_api_capability`, `sentry_project`, `sentry_team`, `sentry_member`, `sentry_team_membership`, `sentry_project_team_assignment`, `sentry_metric_alert_rule`, `sentry_metric_alert_trigger`, `sentry_issue_alert_rule`, `sentry_alert_action`, `sentry_organization_integration`, `sentry_repository`, `sentry_code_mapping`, `sentry_ownership_rule`, `sentry_privileged_member`, `sentry_privileged_team`, `sentry_routing_context`.
- 20 Security Findings confirmed present (Critical 1 / High 8 / Medium 8 / Low 3), unchanged from message 6 — no new rules were added this message (no genuine message-6 defect was found in the rule taxonomy itself).
- Tracked/classified coverage: every record type has a dedicated `_classify_*_change` branch in `risk_rules/sentry.py`'s dispatcher; the fallback (`"low", "A Sentry configuration field changed."`) is unreachable for any of the 18 known types and exists only as a safety net for a future, not-yet-implemented type.

## Change classification

- Added/removed posture audited across all 18 types (see `sentry_change_classification_matrix.md`, 174 rows).
- **2 genuine bugs found and fixed**:
  1. `sentry_metric_alert_rule`/`sentry_issue_alert_rule` "added, enabled + zero actions" was classified Medium — below the `sentry_metric_alert_unrouted`/`sentry_issue_alert_unrouted` static Finding severity (High). Fixed to High.
  2. `sentry_routing_context` "added" never checked `integration_status_category == "disabled"`, and its confirmed-missing-target case was Medium instead of High (inconsistent with the identical "modified" transition, which was already High). Fixed both to High when `context_enabled` is true.
- **1 additional differentiation added** (not a severity floor violation, but noise reduction per task section 12): metric/issue alert rule **removal** now distinguishes an already-unrouted/disabled rule (Low — no active coverage was lost) from a genuinely enabled+routed rule (Medium — real coverage loss).
- 2 pre-existing message-3 tests (`test_added_enabled_zero_actions_is_medium`) were updated to pin the corrected High severity.

## Owner parity decision

**DECISION: Option B.** The static `sentry_active_organization_owner` Finding remains **Critical**; the `member->owner` privilege-tier transition Change remains **High**. This asymmetry was fixed in message 5's own worked severity examples before message 6's Finding taxonomy existed, and it mirrors the identical, already-shipped pattern for every other provider in this codebase (Okta's `okta_super_admin_assigned` Finding is Critical while no Okta Change ever classifies at Critical; Snowflake's `snowflake_user_accountadmin` Finding is Critical while the corresponding Change is High). Certified permanently in `test_sentry_change_parity.py::TestOwnerParityDecision` (3 tests).

## Finding-vs-Change parity

25 explicit parity tests in `test_sentry_change_parity.py` (all passing) certify: for every static Finding with a direct transition, `Change severity >= Finding severity`, with the owner asymmetry as the one documented, tested exception.

## Completeness

- **Family-level**: all 15 collection families + 3 derived families independently tracked via `sentry_organization.family_completeness`.
- **Per-team**: new `sentry_team.membership_collection_status` field (previously computed but discarded as `_status_by_team`) — localizes team-membership-walk failures to the one failed team.
- **Per-project**: new `sentry_project.issue_alert_collection_status` and `sentry_project.ownership_collection_status` fields (previously computed but discarded) — localize per-project walk failures.
- **Nested action detail**: alert-action removals are suppressed via the owning family's completeness (`alert_actions` for metric-type; `issue_alert_rules`/`alert_actions` combined for issue-type — deliberately coarse for issue-type actions, matching Snowflake's own documented "safe rather than precise" tradeoff, to avoid an O(n) per-removed-action scan at the 150,000-action scale target).
- **Derived records**: `sentry_privileged_member`/`sentry_privileged_team`/`sentry_routing_context` removals are suppressed whenever ANY upstream derivation-input family is incomplete.

## False removals

- Organization-wide, per-team, per-project, and derived-record false-removal suppression all verified via the REAL `compute_diff()` pipeline in `test_sentry_partial_sync.py` (19 tests) — this was previously **entirely unimplemented** for Sentry (`_sentry_removal_suppressed` did not exist; Sentry was not in the `compute_diff()` OR-chain at all). This is the single most significant fix in this message.
- Unrelated complete families continue to diff and report real removals normally (verified explicitly).
- The organization record's own disappearance is never suppressed (a real signal).

## Recovery after partial sync

Verified: complete -> partial -> partial -> complete. Partial syncs never fabricate removals. The re-baseline-on-next-complete-sync behavior is exactly compute_diff()'s existing, unmodified semantics (comparison against the literal previous snapshot's stored state) — documented explicitly rather than assumed.

## First-sync behavior

Verified: a first baseline containing owner/pending-invitation/unrouted-alert/disabled-integration/missing-ownership-target risky posture produces `added` Changes (Security Findings fire independently, with no fabricated history) — 3 explicit tests.

## Pagination

No connector changes required — message 1's pagination implementation (`paginate_sentry`/`_parse_link_header`) was already fully correct and comprehensively tested (10 tests covering single/multi-page, repeated-cursor, malformed Link, untrusted next-URL, later-page 403/429, max-page exhaustion, dedup). Re-certified via cross-provider-regression-style reuse rather than reimplementation.

## Trusted-origin behavior

Already fully enforced at message 1 (exact-origin comparison, never path/query-based). This message adds 7 additional attack-variant tests (lookalike subdomain, lookalike prefix, HTTP scheme, userinfo host-confusion, unrelated host, path/query-never-override) — all correctly rejected except the legitimate `sentry.io` origin.

## Retry/rate-limit behavior

**1 genuine bug found and fixed**: `_classify_response` had no branch for unrecognized 4xx statuses (e.g. 400 Bad Request) — they fell through to `CATEGORY_SERVER_ERROR` and were **retried as if transient**. Added `CATEGORY_CLIENT_ERROR` for any 4xx outside 401/403/404/429, which is never retried. 429/5xx retry behavior (bounded, exponential backoff with jitter, `Retry-After`/`X-Sentry-Rate-Limit-Reset` honored) was already correct and is unchanged.

## Token/organization isolation

Verified via real two-connector-instance `fetch()` calls: two organizations never share records; tokens never appear in any output record; token rotation preserves stable organization identity; organization-slug rename preserves stable organization identity and child-record IDs.

## Call-count formula

```
1  (organization identity)
+ 2 x 6  (projects/teams/members/alert-rules/integrations/repos: 1 capability probe + 1 real collection each)
+ 1  (releases: probe only, never really collected)
+ O(teams)  (team-membership walk, 1 call per team)
+ O(projects)  (issue-alert-rule walk, 1 call per project)
+ O(projects)  (ownership-rule walk, 1 call per project)
+ 1  (code-mappings, single org-wide call)
```

Verified exactly against a live respx-mocked `fetch()` call (3 teams, 2 projects -> 22 total calls, matching the formula precisely) in `test_sentry_scale_reliability.py::TestCallCountFormula`.

## Duplicate-query audit

No avoidable duplicate calls found. The only calls issued twice per family (projects/teams/members/alert-rules/integrations/repos) are the message-1 capability probe (intentional early-availability signal) followed by the real collection call — this is pre-existing, intentional architecture from message 1, not a new defect, and is documented rather than "fixed" (changing it would be a message-1-4 architecture change out of this message's scope).

## Scale

- Effective-access derivation over 3,000 members / 500 teams / 1,000 projects completes in well under 5 seconds, confirming no members-x-projects cross product.
- Derivation uses ID-map (`dict`) lookups throughout — `member_index`, `team_index`, `assignments_by_team` — never linear scans over the full record set (verified by code review and by the runtime bound above).
- Larger per-family scale targets (25k projects, 100k members, 250k memberships, 150k alert actions, 100k ownership rules) are bounded by the same collection caps already exhaustively tested in messages 2-4's own dedicated collection test suites; message 7 adds connector-level (full `fetch()`) scale certification on top, not a duplicate of those per-family tests.

## Safety

- **GET-only**: confirmed via grep — zero `.post(`/`.put(`/`.patch(`/`.delete(` calls anywhere in `sentry.py`/`sentry_schema.py`.
- **Credential isolation**: confirmed (see Token/organization isolation above).
- **Token/error redaction**: confirmed — 401/403/500 error messages never include the token, `Authorization` header, or raw response body content.
- **Event-data boundary**: confirmed via grep — no `/issues/`, `/events/`, `/releases/`-body, `/deploys/`, `/commits/`, replay, or profile data ever fetched; the only "releases"/"replays" string matches are the pre-existing capability-probe endpoint name and an unrelated dataset-category taxonomy value.

## Certification

**PASS** — every launch-critical backend gate above passes: 654 Sentry tests green (up from the 526 baseline), all 6 narrow filters non-zero, all cross-provider regressions clean, safety greps clean, GET-only confirmed, no secret/token/event-data leakage anywhere in the touched surface.
