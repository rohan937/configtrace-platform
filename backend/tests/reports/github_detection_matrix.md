# GitHub Detection-QA Matrix

Scope: **detection only** — connector normalization, diff reachability, classifier
routing, Security Finding reachability, registry/frontend parity, and
sensitive-data minimization. Exhaustive transition-severity, restoration, and
numeric/list edge-case QA is reserved for the dedicated GitHub
change-classification pass (message 2) and is **not** covered here.

## Record-type inventory

16 record types are defined in `github_schema.py`. Only **11** are ever
produced by `GitHubConnector.fetch()`; the connector's import block
(`connectors/github.py` lines 84-96) omits 6 of the 16 schema constants
entirely, and a full-file grep confirms zero references to them anywhere in
the connector.

| # | record_type | Emitted by fetch()? | Endpoint | Scope |
|---|---|---|---|---|
| 1 | `github_repo_settings` | Yes | `GET /repos/{owner}/{repo}` | repo |
| 2 | `github_branch_protection` | Yes | `GET /repos/{o}/{r}/branches/{b}/protection` | repo, default branch |
| 3 | `github_actions_secret` | Yes | `GET /repos/{o}/{r}/actions/secrets` | repo |
| 4 | `github_actions_variable` | Yes | `GET /repos/{o}/{r}/actions/variables` | repo |
| 5 | `github_webhook` | Yes | `GET /repos/{o}/{r}/hooks` | repo |
| 6 | `github_actions_permissions` | Yes | `GET /repos/{o}/{r}/actions/permissions` (+`/workflow`) | repo |
| 7 | `github_deploy_key` | Yes | `GET /repos/{o}/{r}/keys` | repo |
| 8 | `github_environment_protection` | Yes (M57.9) | `GET /repos/{o}/{r}/environments` | repo |
| 9 | `github_ruleset` | Yes (M69.5A) | `GET /repos/{o}/{r}/rulesets` (+ per-ruleset detail) | repo |
| 10 | `github_automation_permissions` | Yes (M69.5B) | `GET /repos/{o}/{r}` (`permissions` + `X-OAuth-Scopes`) | repo, credential |
| 11 | `github_pages` | Yes | `GET /repos/{o}/{r}/pages` | repo |
| 12 | `github_codeowners` | **No — unreachable** | schema-defined only | n/a |
| 13 | `github_workflow_file` | **No — unreachable** | schema-defined only | n/a |
| 14 | `github_oidc_trust` | **No — unreachable** | schema-defined only | n/a |
| 15 | `github_collaborator` | **No — unreachable** | schema-defined only | n/a |
| 16 | `github_app_installation` | **No — unreachable** | schema-defined only | n/a |
| 17\* | `github_security_features` | **No — unreachable** | schema-defined only | n/a |

\* 16 schema types total; numbered 1-16 above with `github_security_features`
mislabeled 17 due to list ordering — corrected: 16 total, 11 reachable, 6 not.

**No separate Wiki record type exists.** Wiki posture is the `has_wiki`
boolean field on `github_repo_settings`; the `github_wiki_enabled` Security
Finding evaluates that field directly, not a dedicated record.

**Side-channel alert/activity ingestion** — `list_secret_scanning_alerts()`,
`list_code_scanning_alerts()`, `list_dependabot_alerts()`, and
`list_audit_log_events()` are real, live, called methods (used by
`github_secret_scanning_ingestion_service.py`, `github_code_scanning_ingestion_
service.py`, `github_dependabot_ingestion_service.py`), but they are a
**separate pipeline** from `fetch()`/`compute_diff()`/Security Findings — they
feed correlation/signal services directly and never become drift `Change`
rows or `SecurityFinding` rows through the standard evaluator. This is by
design (activity evidence, not configuration snapshot state) and is
documented here, not treated as a detection gap.

## Detection matrix

Columns: Case · Category · Record type · Field(s) · Connector emits? ·
compute_diff detects? · Classifier route · Finding key · Finding reachable? ·
Registry/frontend parity · Test coverage · Status · Notes

| Case | Category | Record type | Field(s) | Emits? | Diff? | Classifier | Finding key | Reachable? | Parity | Tests | Status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A | Repo visibility | `github_repo_settings` | `visibility` | Yes | Yes | `_classify_repo_settings` | — | n/a (Change only) | n/a | test_github_risk_audit.py | PASS |
| B | Repo archived | `github_repo_settings` | `archived` | Yes | Yes | `_classify_repo_settings` | — | n/a | n/a | test_github_risk_audit.py | PASS |
| C | Default branch | `github_repo_settings` | `default_branch` | Yes | Yes | `_classify_repo_settings` | — | n/a | n/a | test_github_risk_audit.py | PASS |
| D | Wiki enabled/disabled | `github_repo_settings` | `has_wiki` | Yes | Yes | `_classify_repo_settings` | `github_wiki_enabled` | Yes | 4/4 | test_github_extras_risk_audit.py | PASS |
| E | Pages enabled/HTTPS | `github_pages` | `pages_enabled`, `pages_https_enforced` | Yes | Yes | `_classify_pages` | `github_pages_enabled` | Yes | 4/4 | test_github_extras_risk_audit.py, test_github_connector.py | PASS |
| F | Branch protection add/remove | `github_branch_protection` | `protection_enabled` | Yes | Yes | `_classify_branch_protection` | `github_branch_protection_missing` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| G | Required approving review count | `github_branch_protection` | `required_approving_review_count` | Yes | Yes | `_classify_branch_protection` | `github_pr_review_not_required` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| H | Code-owner review | n/a | — | No (unreachable, `github_codeowners`) | No | dead branch (`_classify_codeowners`) | n/a | No | n/a | none (unreachable) | GAP |
| I | Admin enforcement | `github_branch_protection` | `enforce_admins` | Yes | Yes | `_classify_branch_protection` | `github_branch_admin_bypass_allowed` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| J | Force push allowed | `github_branch_protection` | `allow_force_pushes` | Yes | Yes | `_classify_branch_protection` | `github_force_pushes_allowed` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| K | Branch deletion allowed | `github_branch_protection` | `allow_deletions` | Yes | Yes | `_classify_branch_protection` | `github_branch_deletion_allowed` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| L | Required status checks | `github_branch_protection` | `required_status_checks_enabled` | Yes | Yes | `_classify_branch_protection` | `github_status_checks_not_required` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| M | Ruleset enforcement toggle | `github_ruleset` | `enforcement` | Yes | **Was No → Fixed** | `_classify_ruleset` | `github_ruleset_not_enforced` | Yes | 4/4 | test_milestone69_5a...py (mocked), **test_github_detection_qa.py (real compute_diff, new)** | **FIXED** |
| N | Ruleset bypass actors | `github_ruleset` | `bypass_actor_count` | Yes | **Was No → Fixed** | `_classify_ruleset` | `github_ruleset_bypass_actors_present` | Yes | 4/4 | test_github_detection_qa.py (new) | **FIXED** |
| O | Ruleset targets-protected-branch severity | `github_ruleset` | `targets_protected_branch` (provider_metadata) | Yes | **Was always False → Fixed** | `_classify_ruleset` | n/a (Change severity only) | n/a | n/a | test_github_detection_qa.py (new) | **FIXED** |
| P | Webhook HTTPS/HTTP | `github_webhook` | `url` | Yes | Yes | `_classify_webhook` | `github_webhook_http` | Yes | 4/4, severity `high` confirmed consistent | test_github_risk_audit.py | PASS |
| Q | Webhook SSL verification | `github_webhook` | `insecure_ssl_enabled` | Yes | Yes | `_classify_webhook` | `github_webhook_ssl_verification_disabled` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| R | Webhook secret configured | `github_webhook` | `webhook_secret_configured` | Yes (bool presence only) | not tracked (current-state Finding field, not diffed) | n/a | `github_webhook_secret_missing` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| S | Webhook active/deleted | `github_webhook` | `active` | Yes | Yes | `_classify_webhook` | (folds into `_eval_webhook` active check) | Yes | n/a | test_github_risk_audit.py | PASS |
| T | Actions default permission | `github_actions_permissions` | `default_workflow_permissions` | Yes | Yes | `_classify_actions_permissions` | `github_actions_workflow_token_write_permission` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| U | Actions PR approval | `github_actions_permissions` | `can_approve_pull_request_reviews` | Yes | Yes | `_classify_actions_permissions` | `github_actions_can_approve_pull_requests` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| V | Actions allowed_actions posture | `github_actions_permissions` | `allowed_actions` | Yes | Yes | `_classify_actions_permissions` | `github_actions_broad_permissions` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| W | Environment required reviewers | `github_environment_protection` | `reviewers_count` | Yes | Yes | `_classify_environment_protection` | `github_env_protection_missing` | Yes | 4/4 | test_github_extras_risk_audit.py | PASS |
| X | Deployment branch policy | `github_environment_protection` | `protected_branches` | Yes | Yes | `_classify_environment_protection` | `github_env_protection_missing` | Yes | 4/4 | test_github_extras_risk_audit.py | PASS |
| Y | Secret scanning posture | n/a | — | No (unreachable, `github_security_features`); raw alerts fetched by separate ingestion pipeline instead | No | dead branch (`_classify_security_features`) | n/a | No via compute_diff/Finding path | n/a | secret-scanning ingestion tested separately (test_milestone69_4a/b/c) | GAP (posture); alert ingestion is a parallel N/A-for-this-pass pipeline |
| Z | Push protection | n/a | — | No (same as Y) | No | dead branch | n/a | No | n/a | none | GAP |
| AA | Code scanning posture | n/a | — | No (same as Y); alerts via `list_code_scanning_alerts` ingestion | No | dead branch | n/a | No | n/a | test_milestone69_4d/e/f | GAP (posture) |
| AB | Dependabot alerts/security updates | n/a | — | No (same as Y); alerts via `list_dependabot_alerts` ingestion | No | dead branch | n/a | No | n/a | test_milestone69_4g/h/i | GAP (posture) |
| AC | Vulnerability alerts posture | n/a | — | No (same as Y) | No | dead branch | n/a | No | n/a | none | GAP |
| AD | Private vulnerability reporting | n/a | — | No (same as Y) | No | dead branch | n/a | No | n/a | none | GAP |
| AE | GitHub App installation suspended/permission | n/a | — | No (unreachable, `github_app_installation`) | No | dead branch (`_classify_app_installation`) | n/a | No | n/a | none | GAP |
| AF | Collaborator/team access counts | n/a | — | No (unreachable, `github_collaborator`) | No | dead branch (`_classify_collaborator`) | n/a | No | n/a | none | GAP |
| AG | Deploy key read/write | `github_deploy_key` | `read_only` | Yes | Yes | `_classify_deploy_key` | `github_deploy_key_write_access` | Yes | 4/4 | test_github_risk_audit.py | PASS |
| AH | Automation credential admin permission | `github_automation_permissions` | `repository_permission_admin` | Yes | **Was No → Fixed** | **Was missing → added `_classify_automation_permissions`** | `github_automation_admin_permission` | Yes | 4/4 | test_github_detection_qa.py (new), test_milestone69_5b (Finding-side) | **FIXED** |
| AI | Automation credential broad token scopes | `github_automation_permissions` | `token_broad_scopes` | Yes | **Was No → Fixed** | `_classify_automation_permissions` (new) | `github_token_broad_scopes` | Yes | 4/4 | test_github_detection_qa.py (new) | **FIXED** |
| AJ | Optional-endpoint 403/404 (rulesets/environments/pages) | multiple | — | Fail-soft confirmed: `_fetch_rulesets`/`_fetch_environments`/`_fetch_pages` swallow 403/404/network errors and return `[]` or a safe disabled record without aborting the rest of `fetch()` | n/a | n/a | n/a | n/a | n/a | test_github_connector.py, test_github_provider_depth_qa.py | PASS |
| AK | Actions secret rotation (metadata only) | `github_actions_secret` | `last_updated_at` | Yes (name + timestamp only, never value) | Yes | `_classify_actions_secret` | — (no static Finding; Change-only) | n/a | n/a | test_github_risk_audit.py | PASS |
| AL | Actions variable value change | `github_actions_variable` | `value` | Yes (plain-text by GitHub's own model — variables are non-secret) | Yes | `_classify_actions_variable` | — (Change-only) | n/a | n/a | test_github_risk_audit.py | PASS |
| AM | Unknown/missing GitHub record type | any unrecognised `github_*` | — | n/a | n/a | safe "low" fallback in `classify_github_change` | n/a | n/a | n/a | test_github_risk_audit.py | PASS |
| AN | Real `compute_diff()` provider metadata (not hand-built mocks) | `github_ruleset`, `github_automation_permissions` | `targets_protected_branch`, `name` | Yes | Fixed (added GitHub stanza to `_build_provider_metadata`) | n/a | n/a | n/a | n/a | test_github_detection_qa.py (new) | **FIXED** |
| AO | Rules with unreachable records (dead classifier branches) | `github_codeowners`/`workflow_file`/`oidc_trust`/`collaborator`/`app_installation`/`security_features` | — | No | No | dead code in `risk_rules/github.py`, but correctly absent from `security_rules/github.py`'s dispatch | n/a | No | n/a | none | GAP (documented, not fixed — would require new endpoint scope, out of "detection QA" scope) |
| AP | Registry/evaluator/frontend parity (all 25 live rule keys) | all 9 Finding-eligible types | — | n/a | n/a | n/a | all 25 keys | Yes | **25/25** in registry, pack, confidence, coverage, frontend catalog | grep-verified this pass | PASS |
| AQ | Sensitive-data minimization | connector-wide | tokens/secrets/keys/source/workflow YAML/alert bodies/Wiki+Pages content/webhook payloads | Never stored (verified) | n/a | n/a | n/a | n/a | n/a | test_github_connector.py, test_github_risk_audit.py + safety greps this pass | PASS |

## Root-cause bugs found and fixed this pass

1. **`github_ruleset` and `github_automation_permissions` had no entry in
   `_GITHUB_TRACKED_FIELDS_BY_TYPE`** (`diff_service.py`), despite both being
   live, connector-emitted record types. The safe `.get(rt, ())` fallback
   meant `compute_diff()` used an empty tracked-fields tuple for them, so
   real drift (ruleset disabled, admin permission granted, etc.) was never
   detected as a `Change` — even though `_classify_ruleset` already existed
   and was fully tested via hand-built mocks. **Fixed**: added tracked-field
   tuples for both types.
2. **`github_automation_permissions` had no dispatch branch at all** in
   `classify_github_change` (`risk_rules/github.py`) — any Change that did
   reach it (post-fix #1) fell through to the generic "unrecognised record
   type" low-severity fallback. **Fixed**: added `_classify_automation_
   permissions()` and wired it into the dispatcher.
3. **`_classify_ruleset` reads `pm.get("targets_protected_branch")` and
   `pm.get("name")` from provider_metadata, but `_build_provider_metadata()`
   had no GitHub-specific stanza** — only the generic `record_name`/
   `record_content` keys were populated (and `_classify_ruleset` reads
   `"name"`, not `"record_name"`). In production this meant every ruleset's
   `targets_protected_branch` silently evaluated to `False`, permanently
   capping removal/weakening severity at "high" even for rulesets covering
   `main`/release branches, and the display name always fell back to the
   opaque `record_id`. **Fixed**: added a `github_ruleset` /
   `github_automation_permissions` stanza to `_build_provider_metadata()`.

All three bugs are the same "classifier built ahead of, or disconnected from,
the diff-tracking wiring" pattern found repeatedly this session (Vercel's 7
unreachable types, Cloudflare's 5-type provider_metadata gap). This pass's
version was more subtle: the record types here **were** reachable and **did**
have classifier logic — only the diff-tracking/provider_metadata wiring was
missing, so the bug was invisible to every existing mock-based test.

## Confirmed clean (no fix needed)

- GitHub dispatch in `diff_service._tracked_fields_for()` uses the safe
  `.get(rt, ())` empty-tuple fallback for all `github_*` types (not the
  dangerous non-empty fallback found and fixed for Cloudflare earlier this
  session).
- No `old_value`/`previous_value`/`prior_value` references anywhere in
  GitHub connector, schema, risk_rules, security_rules, or test files — the
  `prev_value` convention is used consistently.
- `security_rules/github.py`'s `evaluate()` dispatch is scoped to exactly the
  9 record types with real Security Finding logic (`repo_settings`,
  `branch_protection`, `deploy_key`, `environment_protection`, `ruleset`,
  `automation_permissions`, `actions_permissions`, `webhook`, `pages`) — no
  dead Finding-dispatch branches for the 6 unreachable types (in contrast to
  `risk_rules/github.py`, which does have dead Change-classifier branches for
  them).
- All 25 live GitHub Security Finding rule keys are present in all four
  backend registries (`security_rule_registry.py`, `security_rule_pack.py`,
  `security_rule_confidence.py`, `security_coverage_service.py`) and in the
  frontend `securityRuleCatalog.ts` — full parity, no stale or missing keys.
- The GitHub webhook plain-HTTP finding (`github_webhook_http`) is `"high"`
  severity consistently across the evaluator, rule pack, and frontend catalog
  — the earlier critical→high recalibration is fully and currently
  consistent across every surface.
- Sensitive-data minimization confirmed for all 11 reachable record types:
  no access tokens, OAuth tokens, App private keys, installation tokens,
  webhook secrets, secret/variable values (variables are GitHub's own
  non-secret plain-text config — storing `value` is correct and intended),
  source code, commit/PR/issue/Wiki/Pages content, workflow YAML, raw
  security-alert bodies, collaborator PII, raw webhook payloads, or
  Authorization headers are ever persisted. Two scoped safety greps against
  every touched/new file in this pass found only safe negating disclaimers
  and a sensitive-*name* denylist (`_SENSITIVE_PATTERNS`), not actual secret
  values.
- Fail-soft behavior confirmed for all optional endpoints
  (`_fetch_rulesets`, `_fetch_environments`, `_fetch_pages`,
  `_fetch_automation_permissions`, `_fetch_workflow_permissions`): 403/404/
  network errors return `[]` or a safe "disabled/unknown" record rather than
  aborting the rest of `fetch()`, and unknown postures are represented as
  `None` rather than defaulted to a "safe" value.

## Unmodeled capabilities (GAP / N/A — not invented, per instructions)

Org SAML/SSO enforcement, SCIM posture, org 2FA requirement, enterprise
policies, audit-log *configuration* (audit-log *events* are fetched by
`list_audit_log_events` for the separate activity pipeline, but no
posture/config record exists), IP allow lists, SSH signing policy, org
rulesets, repo custom properties, self-hosted runner inventory/labels, runner
groups, GitHub Codespaces policies, OIDC subject customization, deployment
protection *integrations* (as opposed to the protection rules already
modeled), org secrets/variables, environment secret values, repo secret
values, raw security alerts, raw dependency data, raw source code, raw
workflow files. All remain out of scope and undocumented as connector
features — none were invented to inflate coverage.

## Test results

- `pytest tests/test_github_connector.py tests/test_github_provider_depth_qa.py -q` → 84 passed
- Full exact-file GitHub suite (17 files) → 462 passed
- `pytest -k "github" -q` (before fixes) → 668 passed
- `pytest -k "github" -q` (after fixes + new test file) → **675 passed** (668 + 7 new regression tests)
- No test failures, no skips, no deselected surprises.

## Files changed this pass

- `backend/app/services/diff_service.py` — added `github_ruleset` /
  `github_automation_permissions` tracked-field entries; added GitHub
  provider_metadata stanza.
- `backend/app/services/risk_rules/github.py` — added
  `_classify_automation_permissions()` and its dispatch branch.
- `backend/tests/test_github_detection_qa.py` — new, 7 regression tests
  exercising the real `compute_diff()` → `classify_github_change()` pipeline
  for both fixed record types.
- `backend/tests/reports/github_detection_matrix.md` — this report (new).

## Safe to push?

Not evaluated as part of this pass (push was explicitly out of scope). All
narrow GitHub tests pass; no unrelated files were touched or staged.
