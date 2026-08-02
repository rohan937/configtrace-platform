# Sentry Access Requirement Matrix (Sentry Message 8 of 8 — Public Launch)

Authoritative setup/permission matrix derived directly from the actual
endpoint call sites in `app/connectors/sentry.py` — never a speculative
list of endpoints the connector does not call. Every `GET` request the
connector can issue appears below exactly once (the message-1 capability
probe and the real-collection call to the same path are listed as one
row where they are literally the same request; where the probe and the
real collection differ — e.g. probe hits page 1 of `/organizations/{slug}/projects/`
while real collection paginates through all pages — they are listed
together with both call sites noted).

**Core vs Extended**: Core families (`projects`, `teams`, `members`) are
the minimum needed for meaningful monitoring and are covered by
`org:read`/`member:read` alone. Extended families
(`metric_alerts`, `integrations`, `repositories`, `releases`) may
require additional token scopes a narrowly-scoped monitoring token
legitimately may not have — if unavailable, the integration still
connects with **Partial** coverage rather than being rejected.

**No write scope is ever requested.** Every row below is satisfied by a
read-only scope; the connector never issues `POST`/`PUT`/`PATCH`/`DELETE`.

| # | ConfigTrace family | HTTP endpoint | Required scope | Core/Extended | Failure behavior | Coverage status if denied | Official documentation | Verified |
|---|---|---|---|---|---|---|---|---|
| 1 | Organization identity | `GET /organizations/{slug}/` | `org:read` | Core (mandatory) | Raises `ConnectorError`/`AuthenticationError` — creation/reconnect rejected entirely (Invalid) | N/A — this call must succeed for ANY coverage state | [Organizations API](https://docs.sentry.io/api/organizations/) | docs |
| 2 | Projects (capability probe) | `GET /organizations/{slug}/projects/` (page 1 only, no pagination) | `org:read` | Core | Probe fails soft → family marked unavailable/denied | `projects` capability = denied/unavailable | [List an Organization's Projects](https://docs.sentry.io/api/organizations/list-an-organizations-projects/) | docs |
| 3 | Projects (real collection) | `GET /organizations/{slug}/projects/` (paginated via `Link` header) | `org:read` | Core | `_collect_projects` marks `projects` family denied/unavailable; other families unaffected | `sentry_organization.family_completeness["projects"]` = denied/unavailable | [List an Organization's Projects](https://docs.sentry.io/api/organizations/list-an-organizations-projects/) | docs |
| 4 | Teams (capability probe) | `GET /organizations/{slug}/teams/` (page 1 only) | `org:read` | Core | Probe fails soft | `teams` capability = denied/unavailable | [List an Organization's Teams](https://docs.sentry.io/api/teams/list-an-organizations-teams/) | docs |
| 5 | Teams (real collection) | `GET /organizations/{slug}/teams/` (paginated) | `org:read` | Core | Family fails soft | `teams` = denied/unavailable | [List an Organization's Teams](https://docs.sentry.io/api/teams/list-an-organizations-teams/) | docs |
| 6 | Members (capability probe) | `GET /organizations/{slug}/members/` (page 1 only) | `member:read` | Core | Probe fails soft | `members` capability = denied/unavailable | [List an Organization's Members](https://docs.sentry.io/api/organizations/list-an-organizations-members/) | docs |
| 7 | Members (real collection) | `GET /organizations/{slug}/members/` (paginated) | `member:read` | Core | Family fails soft | `members` = denied/unavailable | [List an Organization's Members](https://docs.sentry.io/api/organizations/list-an-organizations-members/) | docs |
| 8 | Team memberships (real collection) | `GET /teams/{slug}/{team_slug}/members/` | `team:read` (implied by `org:read` for the organization owner; team-scoped visibility otherwise) | Core | Per-team fails soft (message 7 `membership_collection_status`) | `sentry_team.membership_collection_status` = denied | [List a Team's Members](https://docs.sentry.io/api/teams/list-a-teams-members/) | docs |
| 9 | Metric alert rules (capability probe) | `GET /organizations/{slug}/alert-rules/` (page 1 only) | `alerts:read` | **Extended** | Probe fails soft | `metric_alerts` capability = denied/unavailable | [List an Organization's Metric Alert Rules](https://docs.sentry.io/api/alerts/list-an-organizations-metric-alert-rules/) | docs |
| 10 | Metric alert rules (real collection) | `GET /organizations/{slug}/alert-rules/` (paginated) | `alerts:read` | **Extended** | Family fails soft | `metric_alerts` = denied/unavailable; Partial coverage, not Invalid | [List an Organization's Metric Alert Rules](https://docs.sentry.io/api/alerts/list-an-organizations-metric-alert-rules/) | docs |
| 11 | Issue alert rules (real collection) | `GET /projects/{slug}/{project_slug}/rules/` | `alerts:read` (issue-alert rules are project-scoped; same scope family as metric alerts) | **Extended** | Per-project fails soft (message 7 `issue_alert_collection_status`) | `sentry_project.issue_alert_collection_status` = denied | [List a Project's Rules](https://docs.sentry.io/api/alerts/list-a-projects-rules/) | docs |
| 12 | Organization integrations (capability probe) | `GET /organizations/{slug}/integrations/` (page 1 only) | `org:integrations` | **Extended** | Probe fails soft | `integrations` capability = denied/unavailable | [List Organization Integrations](https://docs.sentry.io/api/integrations/list-an-organizations-integrations/) | docs |
| 13 | Organization integrations (real collection) | `GET /organizations/{slug}/integrations/` (paginated) | `org:integrations` | **Extended** | Family fails soft | `integrations` = denied/unavailable; Partial coverage, not Invalid | [List Organization Integrations](https://docs.sentry.io/api/integrations/list-an-organizations-integrations/) | docs |
| 14 | Repositories (capability probe) | `GET /organizations/{slug}/repos/` (page 1 only) | `org:integrations` | **Extended** | Probe fails soft | `repositories` capability = denied/unavailable | [List an Organization's Repositories](https://docs.sentry.io/api/organizations/list-an-organizations-repositories/) | docs |
| 15 | Repositories (real collection) | `GET /organizations/{slug}/repos/` (paginated) | `org:integrations` | **Extended** | Family fails soft | `repositories` = denied/unavailable | [List an Organization's Repositories](https://docs.sentry.io/api/organizations/list-an-organizations-repositories/) | docs |
| 16 | Code mappings (real collection) | `GET /organizations/{slug}/code-mappings/` | `org:integrations` | **Extended** | Family fails soft (best-effort; feeds `sentry_code_mapping` only) | `sentry_code_mapping` collection incomplete, non-blocking | [Code Mappings](https://docs.sentry.io/product/integrations/source-code-mgmt/) (feature docs; no dedicated public API-reference page for this exact endpoint) | partial |
| 17 | Releases (capability probe) | `GET /organizations/{slug}/releases/` (page 1 only) | `project:releases` | **Extended** | Probe fails soft | `releases` capability = denied/unavailable | [List an Organization's Releases](https://docs.sentry.io/api/releases/list-an-organizations-releases/) | docs |
| 18 | Ownership rules (real collection) | `GET /projects/{slug}/{project_slug}/ownership/` | `org:read` (project-scoped ownership text; no dedicated write-adjacent scope required for read) | **Extended** | Per-project fails soft (message 7 `ownership_collection_status`) | `sentry_project.ownership_collection_status` = denied | [Get Ownership Rules for a Project](https://docs.sentry.io/api/projects/get-ownership-rules-for-a-project/) | docs |
| 19 | Effective access — privileged members | Derived locally from members + team-membership data already collected (no additional HTTP call) | Same as rows 6-8 | Core (derived) | Derivation runs on whatever member/team data was successfully collected; incomplete inputs propagate as incomplete derived records, never a fabricated "not privileged" result | Depends on rows 6-8 completeness | N/A — local derivation, not a Sentry endpoint | n/a |
| 20 | Effective access — privileged teams | Derived locally from team + team-membership + project-assignment data already collected (no additional HTTP call) | Same as rows 4-5, 8 | Core (derived) | Same as row 19 | Depends on rows 4-5, 8 completeness | N/A — local derivation | n/a |
| 21 | Routing context (metric alerts) | Derived locally from metric alert rules + members + teams + integrations already collected (no additional HTTP call) | Same as rows 9-10 | Extended (derived) | Same as row 19 | Depends on rows 9-10 completeness | N/A — local derivation | n/a |
| 22 | Routing context (issue alerts) | Derived locally from issue alert rules + members + teams + integrations already collected (no additional HTTP call) | Same as row 11 | Extended (derived) | Same as row 19 | Depends on row 11 completeness | N/A — local derivation | n/a |
| 23 | Routing context (ownership rules) | Derived locally from ownership rules + members + teams already collected (no additional HTTP call) | Same as row 18 | Extended (derived) | Same as row 19 | Depends on row 18 completeness | N/A — local derivation | n/a |
| 24 | Pagination (all list endpoints) | `Link` response header, `rel="next"`, followed until `results="false"` | Same scope as the endpoint being paginated | N/A | Malformed/missing `Link` header treated as "no next page" — never an infinite loop or crash | No dedicated coverage state; a truncated page still yields whatever was read | [Pagination](https://docs.sentry.io/api/pagination/) | docs |
| 25 | Rate limiting | `429` response with `Retry-After` header, honored with bounded retry (message 7 hardening) | N/A (applies regardless of scope) | N/A | Bounded retry then fails soft per-family, never an unbounded retry loop | Family marked denied/unavailable if retries exhausted | [Rate Limits](https://docs.sentry.io/api/ratelimits/) | docs |
| 26 | Server errors (5xx) | Any endpoint above, `5xx` response | N/A | N/A | Bounded retry (`_MAX_SERVER_ERROR_RETRIES`), then fails soft per-family — never retried as a 4xx client error (message 7 `CATEGORY_CLIENT_ERROR` fix) | Family marked denied/unavailable if retries exhausted | N/A — general HTTP semantics | n/a |
| 27 | Authentication failure (401) | Any endpoint above, `401` response | N/A | N/A | Not retried — raises `AuthenticationError` immediately | Invalid at creation/reconnect; per-family denied during a sync | [Auth Tokens](https://docs.sentry.io/api/auth/) | docs |
| 28 | Authorization failure (403) | Any endpoint above, `403` response | N/A | N/A | Not retried — treated as a scope-denial, family marked denied | Family = denied (contributes to Partial, not Invalid, unless it is a Core family and it's the only family) | [Auth Tokens](https://docs.sentry.io/api/auth/) | docs |
| 29 | Not found (404) | Any endpoint above, `404` response | N/A | N/A | Not retried (message 7 `CATEGORY_CLIENT_ERROR` fix — previously fell through to a retried server-error category) | Family/record marked denied/unavailable, no retry storm | N/A — general HTTP semantics | n/a |
| 30 | Trusted origin enforcement | All requests are constrained to the fixed `https://sentry.io` origin; no redirect-following to an arbitrary host | N/A | N/A | Any attempt to reach a non-trusted origin is rejected before the request is sent | N/A — connector-level SSRF guard, not a Sentry-side behavior | N/A — ConfigTrace-side hardening, not a Sentry API contract | n/a |
| 31 | Organization slug format validation | Local validation of `organization_slug` against Sentry's slug character rules before any HTTP call | N/A | N/A | Malformed slug rejected with `ConnectorError` before any network call — creation/reconnect return 400 | N/A — pre-flight validation | [Organizations API](https://docs.sentry.io/api/organizations/) (slug format is documented as part of organization identification) | partial |
| 32 | Regional host (EU/`de.sentry.io`) | Not called — out of scope | N/A | N/A | N/A — EU-region organizations cannot be connected at all in this launch | N/A | [Data Storage Location](https://docs.sentry.io/organization/data-storage-location/) | docs |

**Total: 32 rows**, exceeding the required minimum of 30. Every real
connector endpoint (rows 1-18), every derived/local computation (rows
19-23), every reliability/protocol behavior (rows 24-30), and both
documented pre-flight/scope limitations (rows 31-32) are covered. No row
lists a write scope.
