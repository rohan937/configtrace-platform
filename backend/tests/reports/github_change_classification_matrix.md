# GitHub Change-Classification Matrix (message-2 pass)

Scope: **classification correctness** for every currently emitted and tracked
GitHub field — severity, copy accuracy, restoration/weakening direction,
unknown-value safety, added/removed record handling, and Change/Security
Finding severity parity. Builds on the detection-QA pass (`49955d9`,
`backend/tests/reports/github_detection_matrix.md`), which established which
of the 16 schema-defined record types are actually emitted (11 of 16) and
fixed the diff-tracking/provider-metadata reachability gaps for
`github_ruleset` and `github_automation_permissions`.

## Graphify summary

All four required queries ran successfully via
`/Users/rohan/.local/bin/graphify`. The graph's node granularity is
class/function-level, not field-level, so it could not answer "which tracked
field maps to which classifier branch" directly — it surfaced generic
cross-provider neighbors (every connector class, `Change`, `SecurityFinding`)
rather than GitHub-specific classification detail. `GitHubConnector`,
`test_milestone26_risk_rules.py`, and the ruleset/automation-permission
correlation-service entries were indexed, but the new `_classify_automation_
permissions()` function and `test_github_detection_qa.py` (both added in
`49955d9`) did not surface by name in any result — the graph index is stale
relative to that commit. No graph node exists for this new matrix (expected,
since the file didn't exist yet). Given the coarse/stale results, this audit
proceeded via direct file reads, per the documented fallback.

## Root-cause bugs found and fixed this pass

1. **`_classify_environment_protection`'s `reviewers_count`/`wait_timer`
   used `int(value or 0)`** — an unknown (`None`) count was silently
   collapsed to a confirmed zero, so an environment whose reviewer count
   became unreadable would be reported as "decreased to 0 reviewers"
   instead of "unknown". Fixed with a new `_to_int_or_none()` helper and an
   explicit unknown branch.
2. **`_classify_ruleset`'s `bypass_actor_count`, `required_status_checks_
   count`, and `branch_patterns_count`** used the shared `_to_int()` helper
   (`int(v) except -> 0`), the same unknown-as-zero bug. Fixed the same way.
3. **`_classify_automation_permissions`'s `broad_permission_count`**
   (added in the message-1 pass) had the identical bug — introduced, then
   found and fixed in this pass.
4. **The shared `_to_bool()` helper returned `False` for `None`/
   unrecognised input** instead of `None`. Every ruleset boolean field
   (`restrict_force_pushes`, `restrict_deletions`,
   `required_pr_reviews_required`, `require_signed_commits`) and both
   automation-permission boolean fields (`repository_permission_admin`,
   `token_broad_scopes`) used an `if x is False: ... else: <claims
   restored>` pattern that assumed only True/False were possible — an
   unknown value silently fell into the "else" branch and was reported as
   an explicit **restoration** claim (the opposite overstatement from the
   numeric bug). Fixed the helper to return `None` for unknown input, and
   added an explicit `is None` branch at each of the 6 call sites with
   cautious, non-committal copy.
5. **`_classify_webhook`'s "added" branch never inspected the new webhook's
   own record**, unlike `_classify_deploy_key`'s "added" branch (which does
   inspect the new record for `read_only`). Every newly added webhook was
   flatly "medium" regardless of whether it used plain `http://` or had SSL
   verification disabled from creation. Fixed: added webhooks with an
   `http://` URL are now "critical" (matching the "modified to http://"
   branch); added webhooks with SSL verification already disabled are now
   "high".
6. **`allowed_actions == "all"` Change severity ("medium") was below the
   equivalent static `github_actions_broad_permissions` Security Finding
   ("high")** — a transition into an already-risky posture must not rate
   below the static posture itself. Bumped to "high". Updated the one
   pre-existing test that asserted the stale "medium" expectation
   (`test_milestone26_risk_rules.py::test_actions_allowed_changed_to_all_is_medium`
   → renamed `..._is_high`).
7. **Stale pre-existing test found outside the originally-listed file set**:
   `tests/test_milestone60_4_security_evaluator.py::
   test_creates_active_finding_for_http_webhook` asserted `severity ==
   "critical"` for `github_webhook_http` — left over from before the
   critical→high recalibration confirmed in the message-1 pass, and missed
   by that pass because the file wasn't in its file list. Also asserted a
   stale `evidence["url"]` key that no longer exists (evidence now stores
   only `url_scheme`/`url_host`/`uses_http`, never the full URL). Fixed
   both assertions.
8. **Stale module docstring** in `security_rules/github.py` claimed broad
   Actions permissions (`allowed_actions == "all"`) and `github_ruleset`
   findings were "deferred"/"not implemented" — both are fully implemented
   (`_RULE_ACTIONS_BROAD_PERMISSIONS`, six `github_ruleset_*` rule keys).
   Corrected the docstring.

Two smaller copy-completeness additions (not bugs, but explicit
restoration-direction coverage the task asked for):
- `github_repo_settings.archived` `True → False` (unarchive) now has its
  own "low" branch with restoration copy, instead of falling into the
  generic "Other repository settings changes" medium bucket.
- `github_pages.pages_https_enforced` `False → True` (HTTPS restored) now
  has its own "low" branch with restoration copy, instead of falling into
  the generic Pages fallback.

## Tracked-field ↔ classifier synchronization

| Record type | Tracked fields (diff_service.py) | Dedicated classifier branch? | Notes |
|---|---|---|---|
| `github_repo_settings` | visibility, default_branch, has_issues, has_projects, has_wiki, allow_merge_commit, allow_squash_merge, allow_rebase_merge, delete_branch_on_merge, archived | visibility, default_branch, archived (both directions), has_wiki (both directions); merge fields share one generic-medium branch; has_issues/has_projects use the generic-medium fallback | `has_issues`/`has_projects` intentionally share the generic bucket — not security-sensitive, no dedicated copy needed |
| `github_branch_protection` | protection_enabled, required_status_checks_enabled, required_pull_request_reviews_enabled, required_approving_review_count, dismiss_stale_reviews, enforce_admins, required_linear_history, allow_force_pushes, allow_deletions | all 9 fields have dedicated branches (weaken + strengthen directions) | Full coverage, no gaps |
| `github_actions_secret` | last_updated_at | dedicated (sensitive-name-aware) | name-sensitivity signal via `_is_sensitive_secret` |
| `github_actions_variable` | value | dedicated (sensitive-name + URL-value aware) | — |
| `github_webhook` | url, active, events, content_type, insecure_ssl_enabled | url, active, insecure_ssl_enabled dedicated; events shares one generic-medium branch; content_type uses the generic-low fallback | events-list direction (add vs remove) not distinguished — documented as intentional (no established asymmetric risk for event subscription changes) |
| `github_actions_permissions` | enabled, allowed_actions, default_workflow_permissions, can_approve_pull_request_reviews | all 4 fields dedicated | allowed_actions=="all" severity fixed this pass (medium→high) |
| `github_deploy_key` | title, read_only, verified | read_only dedicated (both directions + added-record inspection); title/verified share generic-low fallback | — |
| `github_environment_protection` | environment_name, wait_timer, reviewers_count, prevent_self_review, protected_branches, custom_branch_policies | all 6 fields dedicated | reviewers_count/wait_timer unknown-safety fixed this pass |
| `github_ruleset` | target, enforcement, branch_patterns_count, targets_protected_branch, bypass_actor_count, required_status_checks_count, restrict_force_pushes, restrict_deletions, required_pr_reviews_required, require_signed_commits, requires_linear_history, requires_code_scanning | enforcement, branch_patterns_count, bypass_actor_count, required_status_checks_count, restrict_force_pushes, restrict_deletions, required_pr_reviews_required, require_signed_commits all dedicated | `target` and `requires_linear_history`/`requires_code_scanning` fall to the generic ruleset "no specific pattern" low fallback — `target`/`requires_linear_history`/`requires_code_scanning` changing alone is rare and non-critical; documented as intentional generic-low, not a gap |
| `github_automation_permissions` | credential_type, repository_permission_admin, repository_permission_maintain, repository_permission_push, broad_permission_count, token_broad_scopes, token_scope_count | admin, push/maintain, broad_permission_count, token_broad_scopes dedicated; credential_type dedicated (informational); token_scope_count has no dedicated branch | `token_scope_count` alone changing (independent of `token_broad_scopes`) falls to the generic "no specific risk pattern matched" low fallback — acceptable since `token_broad_scopes` already captures the security-relevant signal |
| `github_pages` | pages_enabled, pages_source_branch, pages_source_path, pages_build_type, pages_cname_configured, pages_https_enforced, pages_visibility | pages_enabled (both directions), pages_source_branch/path, pages_https_enforced (both directions, restore copy added this pass) dedicated; pages_build_type/pages_cname_configured/pages_visibility use the generic-low fallback | build_type/cname/visibility changes are non-security-sensitive metadata — intentional generic-low |

**Dead classifier branches** (unchanged from the message-1 pass — connector
still does not emit these 6 record types; confirmed via a fresh grep this
pass): `_classify_codeowners`, `_classify_workflow_file`,
`_classify_oidc_trust`, `_classify_collaborator`,
`_classify_app_installation`, `_classify_security_features`. These remain
GAP/N/A. Per this task's explicit scope, no endpoint support was added for
them, and their tests (`grep` confirms) are mock-only — no live path exists.

**Stale field names**: none found. **Confusable similar names**: none found
(`allow_force_pushes`/`restrict_force_pushes` and `allow_deletions`/
`restrict_deletions` are branch-protection vs. ruleset equivalents with
intentionally distinct names — not a collision, since they're on different
record types with different field names).

## Classification matrix (54 cases)

Columns abbreviated for width: Case · Category · Record type · Field · Old →
New · Diff? · Branch · Current → Expected severity · Finding parity · Real
`compute_diff` test? · Status · Notes

| # | Category | Record type | Field | Old → New | Diff? | Branch | Severity (cur→exp) | Finding parity | Real-diff test | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Repo visibility | repo_settings | visibility | private→public | Yes | `_classify_repo_settings` | critical→critical | n/a (intentionally deferred, see below) | test_github_risk_audit.py | PASS | — |
| 2 | Repo visibility | repo_settings | visibility | public→private | Yes | same | medium→medium | n/a | test_github_risk_audit.py | PASS | improvement direction |
| 3 | Repo archived | repo_settings | archived | false→true | Yes | same | medium→medium | n/a | test_github_risk_audit.py | PASS | — |
| 4 | Repo archived | repo_settings | archived | true→false | Yes | same | (generic medium)→low | n/a | test_github_change_classification_qa.py (new) | **FIXED** | restoration copy added |
| 5 | Default branch | repo_settings | default_branch | "main"→"trunk" | Yes | same | high→high | n/a | test_github_risk_audit.py | PASS | — |
| 6 | Wiki | repo_settings | has_wiki | false→true | Yes | same | low→low | Finding `github_wiki_enabled` (low) | test_github_extras_risk_audit.py | PASS | parity: equal |
| 7 | Wiki | repo_settings | has_wiki | true→false | Yes | same | low→low | n/a (Finding only fires when True) | test_github_extras_risk_audit.py | PASS | — |
| 8 | Wiki unknown | repo_settings | has_wiki | true→None | Yes (if key removed) | same | falls to generic medium, not "false" | n/a | not yet covered | GAP (documented) | `is True`/`is False` checks correctly skip None; no dedicated unknown copy, but no false claim either |
| 9 | Merge policy | repo_settings | delete_branch_on_merge | false→true | Yes | same | medium→medium | n/a | test_github_risk_audit.py | PASS | — |
| 10 | Branch protection removed | branch_protection | (whole record) | present→absent | Yes | `_classify_branch_protection` | critical→critical | Finding `github_branch_protection_missing` (high) | test_github_risk_audit.py | PASS | Change > Finding: transition vs. static, justified |
| 11 | Branch protection disabled | branch_protection | protection_enabled | true→false | Yes | same | critical→critical | same Finding | test_github_risk_audit.py | PASS | — |
| 12 | Branch protection enabled | branch_protection | protection_enabled | false→true | Yes | same | low→low | n/a | test_github_risk_audit.py | PASS | improvement |
| 13 | Approvals reduced | branch_protection | required_approving_review_count | 2→0 | Yes | same | high→high | Finding `github_pr_review_not_required` (high, fires only when reviews entirely off) | test_github_risk_audit.py | PASS | — |
| 14 | Approvals increased | branch_protection | required_approving_review_count | 1→2 | Yes | same | medium→medium | n/a | test_github_risk_audit.py | PASS | improvement |
| 15 | Approvals unknown | branch_protection | required_approving_review_count | None→2 | Yes | same | falls to generic medium (isinstance guard skips the branch) | n/a | test_github_risk_audit.py | PASS | correctly does not claim "increased from 0" |
| 16 | Code-owner review | n/a | `github_codeowners` | — | No (unreachable) | dead `_classify_codeowners` | n/a | n/a | mock-only | GAP | connector never emits this type |
| 17 | Admin enforcement removed | branch_protection | enforce_admins | true→false | Yes | same | high→high | n/a (folds into branch_protection_missing scoping) | test_github_risk_audit.py | PASS | — |
| 18 | Force push allowed | branch_protection | allow_force_pushes | false→true | Yes | same | critical→critical | Finding `github_force_pushes_allowed` (high) | test_github_risk_audit.py | PASS | Change > Finding, justified |
| 19 | Branch deletion allowed | branch_protection | allow_deletions | false→true | Yes | same | critical→critical | Finding `github_branch_deletion_allowed` (high) | test_github_risk_audit.py | PASS | Change > Finding, justified |
| 20 | Status checks removed | branch_protection | required_status_checks_enabled | true→false | Yes | same | critical→critical | Finding `github_status_checks_not_required` (medium — fires only when protection exists but this sub-control is off) | test_github_risk_audit.py | PASS | intentional Finding/Change divergence, documented |
| 21 | Stale review dismissal | branch_protection | dismiss_stale_reviews | true→false | Yes | same | high→high | n/a | test_github_risk_audit.py | PASS | — |
| 22 | Linear history | branch_protection | required_linear_history | true→false | Yes | same | high→high | n/a | test_github_risk_audit.py | PASS | — |
| 23 | Ruleset enforcement disabled (protected branch) | ruleset | enforcement | active→disabled, targets_protected_branch=True | Yes (fixed msg-1) | `_classify_ruleset` | critical→critical | Finding `github_ruleset_not_enforced` (high) | test_github_detection_qa.py | PASS | Change > Finding, justified |
| 24 | Ruleset enforcement disabled (non-protected) | ruleset | enforcement | active→disabled, targets_protected_branch=False | Yes | same | high→high | same | test_github_detection_qa.py | PASS | — |
| 25 | Ruleset evaluate mode | ruleset | enforcement | active→evaluate | Yes | same | high→high | n/a | test_github_risk_audit.py-equivalent (mocked) | PASS | — |
| 26 | Ruleset bypass actors increased | ruleset | bypass_actor_count | 0→3 | Yes | same | high/critical→high/critical | Finding `github_ruleset_bypass_actors_present` (medium) | test_github_detection_qa.py | PASS | Change > Finding, justified |
| 27 | Ruleset bypass actors unknown | ruleset | bypass_actor_count | None→5 | Yes | same | (was: "increased from 0"→now: medium, no false zero claim) | same | test_github_change_classification_qa.py (new) | **FIXED** | unknown-as-zero bug |
| 28 | Ruleset required status checks lowered | ruleset | required_status_checks_count | 2→0 | Yes | same | high→high | Finding `github_ruleset_status_checks_missing` (medium) | test_github_risk_audit.py-equivalent | PASS | Change > Finding, justified |
| 29 | Ruleset required status checks unknown | ruleset | required_status_checks_count | None→0 | Yes | same | (was: "lowered from 0"→now: medium, no false zero claim) | same | test_github_change_classification_qa.py (new) | **FIXED** | unknown-as-zero bug |
| 30 | Ruleset force-push restriction removed | ruleset | restrict_force_pushes | true→false | Yes | same | high/critical→high/critical | Finding `github_ruleset_force_push_allowed` (high) | test_github_detection_qa.py | PASS | equal severity |
| 31 | Ruleset force-push restriction unknown | ruleset | restrict_force_pushes | true→None | Yes | same | (was: falsely "now restricts"→now: medium, non-committal) | same | test_github_change_classification_qa.py (new) | **FIXED** | boolean-unknown-as-restore bug |
| 32 | Ruleset deletion restriction removed | ruleset | restrict_deletions | true→false | Yes | same | high/critical→high/critical | n/a | test_github_extras_risk_audit.py-equivalent | PASS | — |
| 33 | Ruleset PR review missing | ruleset | required_pr_reviews_required | true→false | Yes | same | high→high | Finding `github_ruleset_pr_review_missing` (high) | test_github_risk_audit.py-equivalent | PASS | equal |
| 34 | Ruleset signed commits | ruleset | require_signed_commits | true→false | Yes | same | high→high | n/a | test_github_change_classification_qa.py (new) | PASS | — |
| 35 | Ruleset signed commits unknown | ruleset | require_signed_commits | true→"garbage" | Yes | same | (was: falsely "now requires"→now: medium) | n/a | test_github_change_classification_qa.py (new) | **FIXED** | — |
| 36 | Ruleset removed (protected) | ruleset | (whole record) | present→absent, targets_protected_branch=True | Yes | same | critical→critical | n/a | test_github_detection_qa.py | PASS | — |
| 37 | Automation admin permission granted | automation_permissions | repository_permission_admin | false→true | Yes (fixed msg-1) | `_classify_automation_permissions` | high→high | Finding `github_automation_admin_permission` (high) | test_github_detection_qa.py | PASS | equal |
| 38 | Automation admin permission unknown | automation_permissions | repository_permission_admin | true→None | Yes | same | (was: falsely "no longer has admin"→now: medium) | same | test_github_change_classification_qa.py (new) | **FIXED** | boolean-unknown-as-restore bug |
| 39 | Automation write permission granted | automation_permissions | repository_permission_push | false→true | Yes | same | medium→medium | Finding `github_automation_write_permission` (medium) | test_github_detection_qa.py-equivalent | PASS | equal |
| 40 | Automation broad-permission count increase | automation_permissions | broad_permission_count | 1→2 | Yes | same | medium→medium | n/a | test_github_detection_qa.py | PASS | — |
| 41 | Automation broad-permission count unknown | automation_permissions | broad_permission_count | None→2 | Yes | same | (was: "increased from 0"→now: medium, no false zero) | same | test_github_change_classification_qa.py (new) | **FIXED** | unknown-as-zero bug |
| 42 | Automation broad token scopes | automation_permissions | token_broad_scopes | false→true | Yes | same | medium→medium | Finding `github_token_broad_scopes` (high) | test_github_detection_qa.py-equivalent | PASS | intentional divergence: Finding evaluates static scope exposure risk higher than a single Change event |
| 43 | Automation broad token scopes unknown | automation_permissions | token_broad_scopes | true→None | Yes | same | (was: falsely "no longer carries"→now: medium) | same | test_github_change_classification_qa.py (new) | **FIXED** | boolean-unknown-as-restore bug |
| 44 | Webhook HTTP | webhook | url | https→http | Yes | `_classify_webhook` | critical→critical | Finding `github_webhook_http` (high) | test_github_risk_audit.py | PASS | Change > Finding, justified |
| 45 | Webhook added, insecure from creation | webhook | (whole record, url=http://) | absent→present | Yes | same | (was: flat medium→now: critical) | same Finding | test_github_change_classification_qa.py (new) | **FIXED** | added-record inspection gap |
| 46 | Webhook added, SSL verification disabled | webhook | (whole record, insecure_ssl_enabled=True) | absent→present | Yes | same | (was: flat medium→now: high) | Finding `github_webhook_ssl_verification_disabled` (high) | test_github_change_classification_qa.py (new) | **FIXED** | same gap |
| 47 | Webhook added, secure | webhook | (whole record) | absent→present | Yes | same | medium→medium | n/a | test_github_change_classification_qa.py (new) | PASS | unchanged, correctly still medium |
| 48 | Webhook SSL verification disabled | webhook | insecure_ssl_enabled | false→true | Yes | same | high→high | Finding `github_webhook_ssl_verification_disabled` (high) | test_github_risk_audit.py | PASS | equal |
| 49 | Webhook secret missing | webhook | webhook_secret_configured | (Finding-only; not a tracked Change field) | n/a | n/a | n/a | Finding `github_webhook_secret_missing` (high) | n/a | N/A | current-state-only signal, no Change equivalent modeled — intentional |
| 50 | Webhook removed | webhook | (whole record) | present→absent | Yes | same | high→high | n/a | test_github_risk_audit.py | PASS | — |
| 51 | Actions default permission write | actions_permissions | default_workflow_permissions | read→write | Yes | `_classify_actions_permissions` | high→high | Finding `github_actions_workflow_token_write_permission` (high) | test_github_risk_audit.py | PASS | equal |
| 52 | Actions PR approval enabled | actions_permissions | can_approve_pull_request_reviews | false→true | Yes | same | high→high | Finding `github_actions_can_approve_pull_requests` (high) | test_github_risk_audit.py | PASS | equal |
| 53 | Actions allowed_actions broadened | actions_permissions | allowed_actions | selected→all | Yes | same | (was: medium→now: high) | Finding `github_actions_broad_permissions` (high) | test_github_change_classification_qa.py (new); test_milestone26_risk_rules.py (updated) | **FIXED** | severity-parity bug: Change was below Finding |
| 54 | Pages HTTPS restored | pages | pages_https_enforced | false→true | Yes | `_classify_pages` | (generic low fallback, no dedicated copy)→low, dedicated copy | n/a | test_github_change_classification_qa.py (new) | **FIXED** | restoration copy added |

## Security Finding parity — full review of the requested list

| Finding | Finding severity | Equivalent Change | Change severity | Relationship |
|---|---|---|---|---|
| Repository public | **No Finding exists** (intentionally deferred — see docstring note below) | visibility→public | critical | Change-only by design |
| Branch protection missing | high | protection removed/disabled | critical | Change > Finding (transition vs. static), justified |
| Force pushes allowed | high | allow_force_pushes false→true | critical | Change > Finding, justified |
| Deletion allowed | high | allow_deletions false→true | critical | Change > Finding, justified |
| Code-owner review missing | **No Finding / no Change** — `github_codeowners` unreachable | — | — | GAP (documented, connector doesn't emit) |
| Approvals insufficient | high (`github_pr_review_not_required`, fires when reviews entirely off) | required_approving_review_count decreased | high | equal at the "reviews off" boundary |
| Ruleset enforcement weakened | high (`github_ruleset_not_enforced`) | enforcement active→disabled | critical/high (by protected-branch) | Change ≥ Finding, justified |
| Webhook HTTP | high | url→http:// | critical | Change > Finding, justified |
| Webhook SSL verification disabled | high | insecure_ssl_enabled→true | high | equal |
| Webhook secret missing | high | *(no Change equivalent — static-only signal)* | n/a | intentional, Finding-only |
| Actions write permissions | high (`github_actions_workflow_token_write_permission`) | default_workflow_permissions→write | high | equal |
| Actions PR approval | high (`github_actions_can_approve_pull_requests`) | can_approve_pull_request_reviews→true | high | equal |
| Fork workflow posture | **Not modeled** — connector does not emit a fork-PR-approval-specific field distinct from `can_approve_pull_request_reviews` | — | — | GAP/N/A, documented |
| Secret scanning disabled | **No Finding/Change** — `github_security_features` unreachable | — | — | GAP (documented in message-1 pass) |
| Push protection disabled | same | — | — | GAP |
| Dependabot disabled | same | — | — | GAP |
| Vulnerability alerts disabled | same | — | — | GAP |
| Code scanning disabled | same | — | — | GAP |
| Pages HTTPS disabled | medium (`_eval_pages` does not currently emit a dedicated HTTPS-disabled Finding — only `github_pages_enabled` low-severity Finding exists) | pages_https_enforced→false | medium | **GAP**: no dedicated static Finding for HTTPS-disabled Pages, only the Change catches it. Documented, not fixed (would require a new Finding key + registry/frontend wiring, judged out of this pass's "classification correctness for currently emitted/tracked fields" scope — this is a Finding-coverage question flagged for a follow-up, not a Change-classification defect) |
| Environment protections removed | medium (`github_env_protection_missing`) | reviewers_count decreased / protected_branches→false | high | Change > Finding, justified |

**Intentional Finding/Change divergences (by design, confirmed via code
comments)**:
- Repository-public has **no Finding** because there is no "expected
  visibility" signal to distinguish an intentionally-open-source repo from
  an accidentally-public one — flagging every public repo would be a mass
  false positive. This is explicitly documented in `security_rules/github.py`'s
  module docstring and was correctly left as Change-only. **Not a gap to
  fix.**
- `github_status_checks_not_required` Finding is "medium" (not "critical"
  like the Change) because the Finding only fires when protection exists
  but this one sub-control is missing — a narrower, less severe signal than
  the Change's "just weakened from an active protected state." Documented,
  intentional.
- `token_broad_scopes` Finding is "high" while the equivalent Change is
  "medium" — the Finding evaluates the ongoing exposure of a broad-scope
  classic PAT (an already-standing risk), while the Change only reports the
  single transition event; this is the one legitimate case where a Finding
  is *more* severe than its Change, and it is justified because the Finding
  reflects continuous exposure, not a discrete event. Documented, not
  changed (bumping the Change to "high" would be defensible too, but the
  current asymmetry doesn't understate risk — the Finding still surfaces
  "high" continuously — so left as-is per the instruction to fix only clear
  under-classification, not to flatten every asymmetry).

## Numeric and list handling — final state

- All ruleset/environment/automation numeric fields now distinguish
  `None` (unknown) from `0` (explicit) via `_to_int_or_none()`. Explicit
  zero still triggers zero-specific "reduced to 0" style copy where a
  branch checks for it structurally (e.g. `required_approving_review_count`
  reaching 0 via `_classify_branch_protection`, whose `isinstance` guard
  only admits real ints, so explicit `0` still compares correctly against a
  real previous value).
- `github_webhook.events` is a full list (not just a count); the connector
  always emits a sorted list (never `None`), so `None`-vs-`[]` don't arise
  in practice. Direction (events added vs. removed) is not distinguished —
  documented as intentional: there's no established asymmetric security
  meaning for subscribing to more or fewer webhook events (unlike bypass
  actors, where more is unambiguously worse).
- No other list-typed tracked fields exist among currently emitted GitHub
  record types; all other "count" fields (bypass_actor_count,
  required_status_checks_count, branch_patterns_count, reviewers_count,
  broad_permission_count, token_scope_count) are aggregate integers, not
  lists — per this task's item 6, no list-level semantics were invented for
  them.

## Added/removed record handling

All emitted per-item record types (`github_actions_secret`,
`github_actions_variable`, `github_webhook`, `github_deploy_key`,
`github_environment_protection`, `github_ruleset`) have explicit
`change_type == "added"`/`"removed"` branches that inspect the full new/old
record where risk-relevant (deploy_key's `read_only`, webhook's `url`/
`insecure_ssl_enabled` — fixed this pass). The four singleton record types
(`github_repo_settings`, `github_branch_protection`, `github_actions_
permissions`, `github_pages`) are always emitted by the connector (never
omitted), so "added"/"removed" are only reachable in the rare case of a
default-branch rename (for branch_protection, whose record_id embeds the
branch name) — both directions are already handled safely by the existing
generic/critical branches and do not raise exceptions on missing old/new
values.

## Unknown/missing behavior — final state

- Boolean fields: every `is True`/`is False` check across all live
  classifiers correctly excludes `None`, and the 6 `_to_bool()`-based
  ruleset/automation-permission call sites now have explicit `is None`
  branches (fixed this pass) rather than falling into the wrong side of an
  implicit if/else.
- Numeric fields: all ruleset/environment/automation counts now use
  `_to_int_or_none()` with explicit unknown branches (fixed this pass).
  `required_approving_review_count`'s `isinstance(x, (int, float))` guards
  were already correct before this pass (unknown skips the branch entirely).
- No malformed-value exception risk: `_to_int_or_none()` and `_to_bool()`
  both catch/short-circuit on non-coercible input and return `None`,
  matching the "malformed values fail safely" requirement.

## Copy and evidence safety

Re-ran the two required safety greps against every file touched in this
pass (`risk_rules/github.py`, `security_rules/github.py`, both new/updated
test files, this report) — all matches were the existing safe negating
disclaimers ("does not confirm compromise, unauthorized access, or data
exposure") or denylist pattern constants, no forbidden claims and no
raw secrets/tokens/URLs/payloads introduced by this pass's edits.

## Tests and results

```
cd backend && DATABASE_URL=... pytest tests/test_milestone26.py \
  tests/test_milestone26_risk_rules.py tests/test_github_detection_qa.py \
  tests/test_github_connector.py tests/test_github_provider_depth_qa.py -q
  -> 213 passed (1 pre-existing failure found and fixed:
     test_actions_allowed_changed_to_all_is_medium -> renamed _is_high)

pytest tests/test_github_extras_risk_audit.py tests/test_github_risk_audit.py \
  tests/test_milestone60_4_1_github_rules.py tests/test_milestone69_5a_github_rulesets_risk.py \
  tests/test_milestone69_5b_github_automation_permission_risk.py \
  tests/test_milestone69_5c_github_rulesets_automation_correlations.py \
  tests/test_milestone69_6_github_demo_qa.py tests/test_milestone60_4_security_evaluator.py -q
  -> 256 passed (1 pre-existing failure found and fixed:
     test_creates_active_finding_for_http_webhook stale severity + evidence key)

pytest tests/test_github_change_classification_qa.py -q -> 19 passed (new)

pytest -k "github and ruleset" -> 48 passed
pytest -k "github and automation" -> 41 passed
pytest -k "github and webhook" -> 41 passed
pytest -k "github and pages" -> 10 passed
pytest -k "github and wiki" -> 4 passed
pytest -k "github and risk" -> 282 passed
pytest -k "github and diff" -> 14 passed
pytest -k "github" -> 694 passed (675 + 19 new)
```

No zero-selection filters, no unexpectedly slow runs. Frontend was not
touched this pass — `npx tsc --noEmit` was not run (not required, per
instructions).

## Files changed this pass

- `backend/app/services/risk_rules/github.py` — numeric/boolean
  unknown-safety fixes, webhook added-record inspection, allowed_actions
  severity fix, archived/HTTPS restoration copy.
- `backend/app/services/security_rules/github.py` — stale docstring fix
  (no behavior change).
- `backend/tests/test_milestone26_risk_rules.py` — updated one stale
  severity assertion.
- `backend/tests/test_milestone60_4_security_evaluator.py` — updated one
  stale severity assertion and one stale evidence-key assertion.
- `backend/tests/test_github_change_classification_qa.py` — new, 19
  regression tests.
- `backend/tests/reports/github_change_classification_matrix.md` — this
  report (new).

## Safe to push?

Not evaluated (push explicitly out of scope). All exact and narrow GitHub
test filters pass; no unrelated files touched or staged.
