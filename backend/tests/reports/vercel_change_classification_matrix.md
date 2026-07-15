# Vercel change-classification QA report

Follow-up to the Vercel detection-QA pass (commit `a7d05e8`). This pass
audits `risk_rules/vercel.py`'s classification correctness, provider_metadata
handling under real `compute_diff()`, count/boolean unknown-value safety, and
parity with `security_rules/vercel.py`'s Security Findings.

## Summary

The prior detection-QA pass's fixes (`vercel_deployment_protection` added to
`_VERCEL_TRACKED_FIELDS_BY_TYPE`, 5 `_int_or_none()` count-unknown fixes)
were re-verified against real `compute_diff()` output and found correct.
**Four new real bugs were found and fixed** in this pass — all instances of
the classic "unconditional else overstates an unknown transition as an
explicit state" bug found across every provider's classification-QA pass
this session:

1. `vercel_domain.verified`: `if new_value is False: high; else: low
   "was successfully verified"` — an unknown/missing `new_value` (e.g.
   `None`) fell into the `else` branch and falsely claimed the domain "was
   successfully verified."
2. `vercel_deployment_protection.sso_enabled`: same pattern — unknown
   `new_value` was reported as "Vercel Authentication (SSO) was enabled."
3. `vercel_deployment_protection.password_enabled`: same pattern — unknown
   `new_value` was reported as "password protection was enabled."
4. `vercel_deployment_protection.protection_bypass_for_automation`: same
   pattern, inverted direction — unknown `new_value` was reported as "bypass
   was removed."

All four are now three-way branches (explicit-risky → high; explicit-safe →
low; unknown/missing → low with "...is now unknown or missing" wording, no
directional claim). Verified via real `compute_diff()` output before and
after the fix (a domain going `verified: True → None` previously read "was
successfully verified"; now reads "verification state is now unknown or
missing"). 9 new regression tests added across `test_milestone33.py` and
`test_vercel_expansion_risk_audit.py`.

`vercel_project.sso_protection` / `password_protection` use a similar-looking
`bool(prev_value)` / `bool(new_value)` pattern but were confirmed **not** to
have this bug: the connector's `_normalize_protection()` always returns
either `None` (a real, confirmed "disabled" state per Vercel's own API
contract — `null` means disabled) or a non-empty string — it never leaves
this field genuinely ambiguous. `bool()` coercion is therefore safe there,
unlike the four fields above where `None` can mean "we don't know."

No other misclassification was found. All other classifications (env var
sensitivity/target/rotation, project build-pipeline/git fields, domain
redirect/added/removed, deploy-hook ref changes, and all 5 previously-fixed
count fields) were re-verified correct under real `compute_diff()` and mock
inputs alike.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected? | Current risk | Expected risk | Current copy | Expected copy | Finding parity | Metadata required? | Real compute_diff test? | Status | Test | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | vercel_deployment_protection | sso_enabled | True | False | yes | high | high | "SSO was disabled" | same | vercel_preview_unprotected (Finding, current-state) | no | yes | PASS | test_E1, test_real_compute_diff_detects_deployment_protection_disabled | — |
| 2 | vercel_deployment_protection | sso_enabled | False | True | yes | low | low (improvement) | "SSO was enabled" | same | — | no | not yet (mock only) | PASS | test_E9 | — |
| 3 | vercel_deployment_protection | sso_enabled | True | None | yes | **low (fixed; was low but wrong wording)** | low | "state is now unknown or missing" | same | N/A | no | not yet (mock only) | **FIXED (was FAIL)** | test_E10 | Previously claimed "was enabled" — false certainty |
| 4 | vercel_deployment_protection | password_enabled | True | None | yes | **low (fixed)** | low | "state is now unknown or missing" | same | N/A | no | not yet (mock only) | **FIXED (was FAIL)** | test_E11 | Same bug, different field |
| 5 | vercel_deployment_protection | protection_bypass_for_automation | True | None | yes | **low (fixed)** | low | "state is now unknown or missing" | same | N/A | no | not yet (mock only) | **FIXED (was FAIL)** | test_E12 | Same bug, inverted direction ("was removed" was the false claim) |
| 6 | vercel_deployment_protection | protection_bypass_for_automation | False | None | yes | low (never high) | low | "state is now unknown or missing" | same | N/A | no | not yet (mock only) | PASS | test_E13 | Confirms risky-direction branch requires explicit True, not "not False" |
| 7 | vercel_deployment_protection | trusted_ips_count | None | 5 | yes | medium (unknown baseline, capped) | medium | "now has 5 entries, though prior count is unknown" | same | — | no | not yet (mock only) | PASS | test_T1 (prior pass) | Prior pass's fix re-verified |
| 8 | vercel_deployment_protection | trusted_ips_count | 0 | 5 | yes | high | high | "broadened ... from 0 to 5" | same | — | no | not yet (mock only) | PASS | test_T2 (prior pass) | Confirms real-zero baseline still detected |
| 9 | vercel_project | git_branch | "main" | "staging" | yes | high | high | "production branch changed" | same | N/A (Finding fires on the resulting current-state record via `vercel_production_branch_unusual`, not the transition) | yes (record_name) | **yes (new this pass)** | PASS | test_real_compute_diff_detects_project_production_branch_change | — |
| 10 | vercel_project | sso_protection | "all" | None | yes | critical | critical | "SSO protection was disabled" | same | N/A (project-level transition; deployment_protection record's steady state is what the Finding evaluates) | no | existing tests (mock) | PASS | existing TestVercelRiskClassification | `None` here is a confirmed-disabled state, not unknown — verified `_normalize_protection()` never leaves this field ambiguous |
| 11 | vercel_domain | verified | True | False | yes | high | high | "no longer verified" | same | vercel_domain_unverified (Finding, current-state) | yes (record_name) | **yes (new this pass)** | PASS | test_real_compute_diff_detects_domain_unverified | — |
| 12 | vercel_domain | verified | False | True | yes | low | low (improvement) | "successfully verified" | same | — | yes | not yet (mock only) | PASS | test_domain_verified_is_low | — |
| 13 | vercel_domain | verified | True | None | yes | **low (fixed; was low but wrong wording)** | low | "verification state is now unknown or missing" | same | N/A | yes | yes (new this pass) | **FIXED (was FAIL)** | test_domain_verified_unknown_is_low_not_high_or_verified_claim | Previously claimed "was successfully verified" — false certainty |
| 14 | vercel_env_var | (target) | ["preview"] | ["preview","production"] | yes | high (promoted) | high | "promoted to production" | same | vercel_env_var_broad_target (Finding, current-state) | no | existing tests | PASS | existing TestVercelRiskClassification | — |
| 15 | vercel_env_var | env_type | "encrypted" | "plain" | yes | high | high | "security downgrade" | same | N/A | no | existing tests | PASS | existing tests | — |
| 16 | vercel_deploy_hook_metadata | hook_ref | "main" | "staging" | yes | high | high | "target branch changed" | same | vercel_deploy_hook_production_branch (Finding, current-state — fires when the *resulting* ref is production) | no | existing tests | PASS | existing tests | — |
| 17 | vercel_integration_installation | project_count | None | 3 | yes (mock only — record type unreachable) | medium (unknown baseline, capped) | medium | "now covers 3 project(s), though prior count is unknown" | same | N/A (record type never fetched) | no | mock only | PASS (documented GAP: record type unreachable) | test_T3 (prior pass) | — |
| 18 | vercel_function_runtime | edge_function_count | None | 2 | yes (mock only) | low | low | "is now 2, though prior count is unknown" | same | N/A (record type never fetched) | no | mock only | PASS (documented GAP) | test_T8 (prior pass) | — |
| 19 | (all reachable types) | various booleans | None/missing new_value | — | yes | never high/critical | never high/critical | "unknown or missing" | same | — | varies | yes (4 new tests) | **PASS (2 previously FIXED)** | test_E10-E13, test_domain_verified_unknown, test_J1-style checks | — |
| 20 | vercel connector | fetch() | — | — | — | — | — | 7 expansion record types absent from output | same | — | — | yes (new this pass) | PASS | test_fetch_never_emits_unreachable_expansion_record_types | Confirms the 7 unreachable types remain undocumented-as-live |

Totals: **20 cases reviewed**. **16 PASS**, **4 FIXED (were FAIL — wrong
wording on unknown transitions, cases 3/4/5/13)**, **0 remaining FAIL**, **2
documented GAP** (rows 17/18 — record types confirmed still unreachable by
the connector, consistent with the prior detection-QA pass's findings).

## Tracked fields vs. classifier coverage

Cross-referenced every field in `_VERCEL_TRACKED_FIELDS_BY_TYPE`
(`diff_service.py`) against every branch in `risk_rules/vercel.py` for the 5
reachable record types:

| Record type | Specific classification | Falls through to bottom catch-all |
|---|---|---|
| vercel_project | build_command, install_command, root_directory, output_directory, framework, node_version, name, git_branch, git_repository, sso_protection, password_protection | none — all 11 tracked fields have a specific branch |
| vercel_env_var | key, env_type, target, git_branch, updated_at | none — all 5 tracked fields have a specific branch |
| vercel_domain | verified, redirect, git_branch | none — all 3 tracked fields have a specific branch |
| vercel_deploy_hook_metadata | hook_ref | **hook_name** falls to the bottom catch-all (cosmetic rename — low, harmless) |
| vercel_deployment_protection | sso_enabled, password_enabled, protection_bypass_for_automation, trusted_ips_count, trusted_ips_cidr_hash, preview_comments_public (added-direction only), preview_deployments_protected (disabled-direction only) | **preview_comments_public**'s restoration direction (True→False) and **preview_deployments_protected**'s restoration direction (False→True) fall to the bottom catch-all — low severity, safe generic wording, just less descriptive than a dedicated "restored" message. Not a bug (no false certainty), a minor wording-quality note only. |

No classifier branch for any of the 5 reachable record types references a
field the connector doesn't emit, and no stale field names were found. For
the 7 unreachable "M59.12 expansion" record types, every classifier branch
necessarily corresponds only to schema-declared fields since no real record
has ever been produced to check against — this is the pre-existing,
documented condition from the detection-QA pass, unchanged by this pass.

No metadata key required by any of the 5 live classifiers is missing from
`_build_provider_metadata()`: `record_type`/`record_name` (project, env_var,
domain, deploy_hook_metadata) and `record_content` (domain, for the
`is_preview` check) are all built and consumed correctly — confirmed via the
2 new real-`compute_diff()` integration tests added this pass (project,
domain) plus the existing deployment_protection one.

## Mock-shape and provider_metadata verification

- Grepped `risk_rules/vercel.py` and all Vercel test files for
  `old_value`/`previous_value`/`prior_value` — clean; only `prev_value` is
  used, correctly, everywhere.
- Real-`compute_diff()` integration tests now exist for 3 of the 5 live
  record types: `vercel_deployment_protection` (prior pass),
  `vercel_project` and `vercel_domain` (new this pass). `vercel_env_var` and
  `vercel_deploy_hook_metadata` remain covered only via hand-built dicts
  (existing `TestVercelRiskClassification`/`TestVercelRiskPrecision`
  tests) — a minor, lower-priority documented gap since their classifier
  logic doesn't depend on any metadata key beyond `record_type`/
  `record_name`, which is already proven correct by the other 3 real-diff
  tests exercising the exact same `_build_provider_metadata()` code path.
- `test_vercel_expansion_risk_audit.py`'s entire 900+-line suite for the 7
  unreachable record types remains, by necessity, mock-only — there is no
  real connector output to integrate against, which is itself the
  documented condition (task I), not a defect.

## Parity with Security Findings

| Finding | Severity | Change classifier | Alignment |
|---|---|---|---|
| vercel_preview_unprotected | medium (current-state: no protection mechanism active) | sso_enabled/password_enabled/preview_deployments_protected disabled → high (transition) | Documented intentional disagreement, consistent with every other provider's QA pass this session — Change rates the *transition into* an unprotected state as high (a regression, more actionable); Finding rates the *static* unprotected state as medium (may predate the integration, or reflect an intentional low-security dev project) |
| vercel_production_branch_missing | medium | N/A (Change has no dedicated "branch removed" transition — `git_repository`/`git_branch` changes are both classified high directly) | Change is actually stricter (high) than the Finding (medium) for the related transition; no unsafe understatement |
| vercel_production_branch_unusual | medium | git_branch changed → high (any branch change, not just to a conventionally-non-production name) | Change doesn't distinguish "changed to a normal-looking branch" from "changed to a suspicious-looking branch" the way the Finding does — documented as an acceptable coarser signal, since Change already treats ALL production-branch changes as high-priority-worth-reviewing regardless of the new branch's name |
| vercel_domain_unverified | medium | verified→False → high | Change rates this *more* severely than the Finding — documented intentional disagreement (transition vs. static state), consistent with every other provider |
| vercel_env_var_broad_target | medium | target promoted to include production → high | Same pattern — Change rates the transition higher than the Finding rates the resulting static state |
| vercel_sensitive_env_var_broad_scope | high | (no direct 1:1 Change field — `_is_sensitive_env_var()` uses a broader keyword list than the Finding's `_is_sensitive_key()`, and factors into env-var add/remove/rotate severity rather than a single dedicated transition) | Documented granularity difference — not a bug, no unsafe understatement |
| vercel_deploy_hook_production_branch | medium | hook_ref changed → high | Change rates this more severely — documented intentional disagreement |

No severity was found to unsafely *understate* risk relative to its Finding
(all disagreements are Change ≥ Finding, never <). No unknown/missing value
triggers a Finding-level high/critical after this pass's fixes.

## Count and threshold handling

- Re-grepped `risk_rules/vercel.py` for `int(.*or 0)` — zero matches,
  confirming the prior pass's `_int_or_none()` fix remains intact across
  all 5 originally-fixed count fields.
- No new count fields were added or found needing fixes in this pass.
- No threshold-crossing-only logic exists in `risk_rules/vercel.py` — count
  fields use simple increase/decrease comparison, so the "over-threshold
  increase falls to low" bug class does not apply. N/A, not a gap.

## Boolean unknown handling

Systematically re-checked every `is True`/`is False`/`bool()`-based boolean
branch in `risk_rules/vercel.py` (14 occurrences) for the "unconditional
else claims an explicit direction" pattern:

- **4 bugs found and fixed** this pass (domain `verified`, deployment
  protection `sso_enabled`/`password_enabled`/
  `protection_bypass_for_automation`) — see Summary.
- **10 occurrences confirmed already safe**: `vercel_deployment.
  is_current_production_alias`, `vercel_team_member.is_outside_collaborator`,
  `vercel_cron_job.enabled`, `vercel_firewall_rule.enabled` all use
  standalone `if` checks with no unconditional `else`, falling through
  safely to a generic low-severity catch-all when the new value is
  `None`/unexpected. `vercel_project.sso_protection`/`password_protection`
  use `bool()` coercion but are confirmed safe because the connector's
  `_normalize_protection()` never produces a genuinely ambiguous value for
  these two fields (`None` is a real, confirmed "disabled" state, not
  "unknown").
- 9 new tests (across `test_milestone33.py` and
  `test_vercel_expansion_risk_audit.py`) cover the representative unknown
  transitions for all 4 fixed fields plus the domain case.

## Unreachable record types (task I)

Re-confirmed all 7 previously-documented unreachable record types remain
unreachable and undocumented-as-live:

- **Connector**: `VercelConnector.fetch()` still does not emit
  `vercel_deployment`, `vercel_team_member`, `vercel_edge_config_item`,
  `vercel_cron_job`, `vercel_integration_installation`,
  `vercel_function_runtime`, or `vercel_firewall_rule` — confirmed via a
  new regression test (`test_fetch_never_emits_unreachable_expansion_
  record_types`) that asserts the mocked `fetch()` output's record-type set
  never intersects this set.
- **Tests**: all coverage for these 7 types in
  `test_vercel_expansion_risk_audit.py` remains mock-only (`_ch()` builds a
  `MagicMock` with hand-set `provider_metadata`) — no real connector or
  `compute_diff()` path exists for them.
- **Product copy**: `frontend/src/lib/providers.ts`'s Vercel description
  ("Monitor Vercel project configuration, environment variable keys, and
  custom domains") only claims the 3 core, genuinely-fetched surfaces — it
  does not mention team members, cron jobs, Edge Config, integrations,
  function runtime, or firewall rules. No product-copy overclaim found.
- **Decision**: remains a documented GAP, not fixed. Adding real API
  integration for any of these 7 types would require live Vercel API
  verification (endpoint paths, pagination shapes, auth scopes) that this
  classification-QA pass cannot safely perform — consistent with the
  explicit scope constraint in both this task and the prior detection-QA
  pass.

## Copy safety

Re-scanned all classifier reason strings in `risk_rules/vercel.py`
(including the 4 fixed branches' new wording) for breach/compromise/
attacker/leak/unauthorized-access/source-code-exposure/env-var-exposure/
secret-exposure/token-exposure/infrastructure-exposure/data-exposure
phrasing — zero matches. All copy uses "may require review", "verify this
change is intentional", "is now unknown or missing", or similar advisory
framing.

## Fixes made

1. `risk_rules/vercel.py`: fixed `_classify_domain_change`'s `verified`
   branch to require an explicit `True` before claiming "successfully
   verified"; unknown/missing now returns low with "verification state is
   now unknown or missing."
2. `risk_rules/vercel.py`: fixed `_classify_deployment_protection_change`'s
   `sso_enabled`, `password_enabled`, and `protection_bypass_for_automation`
   branches the same way — each now requires an explicit boolean match
   before claiming a directional state change.
3. `tests/test_milestone33.py`: added 1 domain unknown-transition test, 2
   new real-`compute_diff()` integration tests (project, domain), and 1 new
   connector regression test confirming the 7 unreachable record types stay
   absent from `fetch()` output.
4. `tests/test_vercel_expansion_risk_audit.py`: added 4 new deployment-
   protection unknown-transition tests (`TestDeploymentProtection`,
   tests E10–E13).
5. `tests/reports/vercel_change_classification_matrix.md`: this report
   (new).

No changes were needed to `security_rules/vercel.py`, any of the 4 backend
registries, the frontend catalog, or `diff_service.py`'s tracked-fields map
— all were already correct from the prior detection-QA pass.

## Validation run

- `docker compose exec api pytest tests/test_milestone33.py
  tests/test_vercel_expansion_risk_audit.py -q` → **284 passed** (was 276
  before this pass; +8 new tests, 0 regressions).
- `docker compose exec api pytest tests -q -k "vercel and risk"` → **323
  passed, 17077 deselected**.
- `docker compose exec api pytest tests -q -k "vercel and diff"` → **11
  passed, 17389 deselected**.
- `docker compose exec api pytest tests -q -k "vercel"` → **500 passed, 4
  skipped, 1 failed, 16895 deselected** — the 1 failure
  (`test_no_forbidden_phrases_in_vercel_rules_module`) is the same
  pre-existing, unrelated container-path issue documented in the prior
  detection-QA pass (the test computes `REPO_ROOT` assuming a
  `/backend/...` mount structure that doesn't match this container's `/app`
  mount; confirmed via a direct `FileNotFoundError` unrelated to any Vercel
  logic or wording).
- `test_*vercel*` glob → **326 passed, 3 skipped, 1 failed** (same
  pre-existing failure).
- No frontend files were changed in this pass, so `npx tsc --noEmit` was
  not required.
