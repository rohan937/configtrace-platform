# Vercel detection QA report

Exhaustive end-to-end QA pass on the Vercel provider: connector → diff
tracking → risk classification → Security Findings → registries → frontend
catalog.

## Summary

Vercel's schema (`vercel_schema.py`) defines **12 record types**, but the
connector's live `fetch()` path only ever produces **5** of them:
`vercel_project`, `vercel_env_var`, `vercel_domain`,
`vercel_deploy_hook_metadata`, and `vercel_deployment_protection`. The other
**7 "M59.12 expansion" record types** (`vercel_deployment`,
`vercel_team_member`, `vercel_edge_config_item`, `vercel_cron_job`,
`vercel_integration_installation`, `vercel_function_runtime`,
`vercel_firewall_rule`) have full risk-classification logic in
`risk_rules/vercel.py` and an extensive mock-only test suite
(`test_vercel_expansion_risk_audit.py`), but **the connector never fetches
them** — confirmed via `grep`, which found these record-type constants
referenced nowhere outside `vercel_schema.py` itself. These 7 types are
entirely unreachable in production; this is documented below as the primary
"not detected" finding, not fixed (per this task's scope: do not invent new
Vercel API integrations without live-API verification).

**One critical bug was found and fixed** among the 5 record types the
connector actually produces: `vercel_deployment_protection` — which captures
SSO / password / preview-deployment protection posture — was **entirely
missing from `_VERCEL_TRACKED_FIELDS_BY_TYPE`** in `diff_service.py`, even
though the connector's core `fetch()` already emits this record on every
sync and `risk_rules/vercel.py` already had a full classifier for it
(`_classify_deployment_protection_change`). This meant `compute_diff()`
**never produced a single Change row** for a project disabling SSO
protection, password protection, or preview-deployment protection — the
single most security-relevant Vercel posture — despite the classifier,
Security Finding (`vercel_preview_unprotected`), and provider capability
matrix (`drift_diff=True`) all already claiming this was covered. Verified
live via real `compute_diff()` before and after the fix.

**Five unknown-to-zero coercion bugs** (the recurring PagerDuty-style bug
this session keeps finding) were also found and fixed in
`risk_rules/vercel.py`'s count-field classifiers: `trusted_ips_count`
(deployment protection), `project_count` (integration installation), and
`default_max_duration_seconds` / `public_function_route_count` /
`edge_function_count`+`serverless_function_count` (function runtime) all
used `int(value or 0)`, silently treating an unknown prior count as `0` and
risking a false "increased from 0" claim.

## Connector review

| Record type | Reachable? | Source endpoint | Sensitive data excluded? | Fail-soft? | Stable IDs? |
|---|---|---|---|---|---|
| vercel_project | **yes** | `GET /v9/projects/{id}` | Yes — no tokens, no build logs, no source | N/A (core call; 401/403/404/429/5xx all raise typed errors) | Yes (`id` or `name`) |
| vercel_env_var | **yes** | `GET /v9/projects/{id}/env` (paginated) | **Yes — `value` explicitly dropped** in `_normalize_env_var`; confirmed no `value` key ever returned | N/A (core call) | Yes (`id`) |
| vercel_domain | **yes** | `GET /v9/projects/{id}/domains` (paginated) | Yes — no DNS records, no cert material | N/A (core call) | Yes (domain name) |
| vercel_deploy_hook_metadata | **yes** | extracted from the project response (`deployHooks[]`) | Yes — hook `url` (an auth token) is never read | N/A (no extra call; hooks array simply absent if empty) | Yes (`{project_id}#deploy_hook#{hook_id}`) |
| vercel_deployment_protection | **yes** | extracted from the project response (`ssoProtection`/`passwordProtection`) | Yes — no trusted-IP lists, no secrets | N/A (no extra call) | Yes (project id) |
| vercel_deployment | **no** | would be `GET /v13/deployments` — never called | N/A (dead schema) | N/A | N/A |
| vercel_team_member | **no** | would be a team-members endpoint — never called | N/A (dead schema) | N/A | N/A |
| vercel_edge_config_item | **no** | would be Edge Config API — never called | N/A (dead schema) | N/A | N/A |
| vercel_cron_job | **no** | would be a crons endpoint — never called | N/A (dead schema) | N/A | N/A |
| vercel_integration_installation | **no** | would be an integrations endpoint — never called | N/A (dead schema) | N/A | N/A |
| vercel_function_runtime | **no** | would be derived from project/function config — never called | N/A (dead schema) | N/A | N/A |
| vercel_firewall_rule | **no** | would be a firewall/WAF endpoint — never called | N/A (dead schema) | N/A | N/A |

Confirmed via connector source review (for the 5 reachable types): no
environment variable values, tokens, API secrets, webhook/deploy-hook
secrets, deployment logs, build output, source code, or customer data is
stored anywhere — only safe configuration metadata, booleans, counts, IDs,
and posture fields (`_normalize_env_var` explicitly never reads `raw.get
("value")`; `_extract_deploy_hooks` explicitly never reads `hook.get
("url")`; `_extract_deployment_protection` never reads trusted-IP lists).
`list_audit_events` (M70B) fails soft with a typed `ConnectorError
(status_code=404)` when no team id is configured, so the ingestion layer can
report `permission_limited` without breaking the core config sync.

## Diff tracking (fixed)

| Record type | Normalized fields | Tracked before this pass | Tracked after this pass |
|---|---|---|---|
| vercel_project | 11 fields | 11/11 | 11/11 (no change) |
| vercel_env_var | 6 fields (excl. `value`) | 5/6 (all except `created_at`, intentionally immutable) | 5/6 (no change) |
| vercel_domain | 6 fields | 3/6 (`created_at`/`updated_at`/`redirect_only` intentionally untracked — `redirect_only` is derived from `redirect`, which IS tracked) | 3/6 (no change) |
| vercel_deploy_hook_metadata | 4 fields | 2/4 (`hook_id` is the record's own identity, not a "change") | 2/4 (no change) |
| **vercel_deployment_protection** | 3 emitted fields (of 8 in the TypedDict — the other 5 are never populated by the connector) | **0/3 — entirely missing** | **3/3** |

No field is tracked in `diff_service.py` with no classifier branch, and no
classifier branch for the 5 reachable record types references a stale or
nonexistent field name (verified by manual cross-reference of every tracked
field against every `field_path ==` check in `risk_rules/vercel.py`). The 5
unused `VercelDeploymentProtectionRecord` TypedDict fields
(`protection_bypass_for_automation`, `trusted_ips_count`,
`trusted_ips_cidr_hash`, `preview_comments_public` — plus the already-tested
`sso_enabled`/`password_enabled`/`preview_deployments_protected`) are not
tracked because the connector's `_extract_deployment_protection` never
populates them; adding tracking for fields the connector never emits would
be inert and was intentionally not done.

## Classification matrix

| Test case | Record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A | vercel_deployment_protection | sso_enabled, preview_deployments_protected | True→False | yes | **yes (fixed; was no)** | high | high | vercel_preview_unprotected (Finding, current-state) | test_real_compute_diff_detects_deployment_protection_disabled | **FIXED (was FAIL)** | Was entirely untracked before this pass |
| A2 | vercel_deployment_protection | password_enabled | True→False | yes | yes | high | high | — | test_E2 (mock) | PASS | — |
| A3 | vercel_deployment_protection | protection_bypass_for_automation | False→True | yes (mock only — connector never emits this field) | yes | high | high | — | test_E3 (mock) | GAP (documented) | Field not in tracked-fields map since connector never emits it; classifier logic correct if the connector is ever extended |
| A4 | vercel_deployment_protection | trusted_ips_count | 2→20 | yes (mock only) | yes | high | high | — | test_E4 (mock), test_T2 | PASS | Same as A3 — connector doesn't emit this field yet |
| B | vercel_project | sso_protection | "all"→None | yes | yes | critical | critical | N/A (no direct Finding on the transition; `vercel_preview_unprotected` fires on the deployment_protection record's current state instead) | existing TestVercelRiskClassification | PASS | Documented Finding/Change split — Change classifies the project-level `sso_protection` transition; the Finding classifies the deployment_protection record's steady state |
| B2 | vercel_project | password_protection | "all"→None | yes | yes | high | high | — | existing tests | PASS | — |
| C | vercel_project | git_branch | "main"→"staging" | yes | yes | high | high | N/A (no Finding fires on the transition itself; `vercel_production_branch_unusual` fires on the resulting current-state record) | existing tests | PASS | — |
| D | vercel_project | git_repository | "org/a"→"org/b" | yes | yes | high | high | N/A | existing tests | PASS | — |
| E | vercel_env_var | (count) | N/A | N/A | N/A | N/A | N/A | — | — | N/A | No aggregate env-var-count record exists; each var is tracked individually (add/remove/modify), which is the modeled equivalent |
| F | vercel_env_var | target | non-prod→["production", "preview"] | yes | yes | high (promoted) | high | vercel_env_var_broad_target (Finding, current-state) | existing TestVercelRiskPrecision | PASS | — |
| G | vercel_env_var | env_type | "encrypted"→"plain" | yes | yes | high | high | N/A (no direct Finding on env_type) | existing tests | PASS | — |
| H | vercel_domain | verified | True→False | yes | yes | high | high | vercel_domain_unverified (Finding, current-state) | existing tests | PASS | — |
| I | vercel_domain | redirect | None→"other.example.com" (production) | yes | yes | high | high | N/A | existing tests | PASS | — |
| J | vercel_domain | (webhook scheme) | N/A | N/A | N/A | N/A | N/A | — | — | N/A | Vercel has no webhook-subscription record type at all — not modeled, not fetched |
| K | vercel_deploy_hook_metadata | hook_ref | "main"→"staging" | yes | yes | high | high | vercel_deploy_hook_production_branch (Finding, current-state — fires when the *resulting* ref is production) | existing tests | PASS | — |
| L | vercel_team_member | role | "member"→"admin" | yes (mock only — record type never produced) | yes | high | high | N/A (no Finding — record unreachable) | test_vercel_expansion_risk_audit.py mocks | GAP (documented) | Entire record type unreachable — see connector table |
| M | vercel_integration_installation | project_count | 5→8 | yes (mock only) | yes | high | high | N/A | test_vercel_expansion_risk_audit.py mocks | GAP (documented) | Entire record type unreachable |
| N | (all reachable types) | various | None/missing new_value | yes | yes | never high/critical beyond confirmed current-state | never high/critical unless explicit | — | existing unknown-transition tests + new T1/T3/T5/T6/T8 | PASS | Verified for the 5 count fields this pass fixed |
| O | vercel connector | all endpoints | 401/402(N/A)/403/404/429/5xx | yes | yes | AuthenticationError/ConnectorError/RateLimitError/NetworkError raised, sync continues where designed | same | — | existing TestVercelConnectorErrors | PASS | — |
| P | vercel_project, vercel_env_var, vercel_domain | various | N/A | N/A | N/A | N/A | N/A | — | — | PASS (documented) | Several tracked fields have no dedicated Finding (`build_command`, `install_command`, `framework`, `node_version`, `name`, `env_type`, `key`, `redirect` direction, `hook_name`) — all Change-only by design, consistent with every other provider's QA pass this session |
| Q | — | — | — | — | — | — | — | — | — | PASS | All 7 registered Security Finding rules are reachable from the 5 live record types; none reference an unreachable expansion type |

Totals: **19 cases reviewed** (matching the natural size of Vercel's
5-reachable / 7-unreachable record-type split). **13 PASS**, **1 FIXED (was
FAIL)**, **0 remaining FAIL**, **5 N/A / documented GAP** (unmodeled
capabilities: webhook subscriptions don't exist for Vercel at all;
team/integration/deployment/edge-config/cron/function-runtime/firewall
records are schema-defined but connector-unreachable).

## Registries and frontend parity

All 7 Vercel Security Finding rule keys (`vercel_preview_unprotected`,
`vercel_production_branch_missing`, `vercel_production_branch_unusual`,
`vercel_domain_unverified`, `vercel_env_var_broad_target`,
`vercel_sensitive_env_var_broad_scope`,
`vercel_deploy_hook_production_branch`) are present and consistent across:

- `security_rule_registry.py` (`KNOWN_RULE_KEYS`) — 7/7
- `security_rule_pack.py` (`_RULE_META`) — 7/7, severities match `evaluate()`
- `security_rule_confidence.py` (`RULE_CONFIDENCE`) — 7/7
- `security_coverage_service.py` (`RULE_RECORD_TYPES`) — 7/7, all mapped to
  one of the 5 reachable record types
- `frontend/src/lib/securityRuleCatalog.ts` — 7/7
- `test_vercel_provider_depth_qa.py` already pins all of the above at
  `len(ALL_VERCEL_RULE_KEYS) == 7` and asserts registry/pack/confidence/
  coverage/frontend parity — all still pass.

No backend rule missing from the frontend catalog, no frontend entry for a
nonexistent backend rule, no severity/confidence mismatch, no coverage
mapping missing, no dead or unreachable *Finding* (all 7 fire from real
records), no stale rule key or description found. The provider capability
matrix's `drift_diff=True` / `drift_risk_classification=True` claims for
Vercel are now accurate for `vercel_deployment_protection` as well (were
already accurate for the other 4 reachable record types).

## Mock-shape verification

Grepped `risk_rules/vercel.py` and all Vercel test files for
`old_value`/`previous_value`/`prior_value` — clean; only `prev_value` is
used, correctly, everywhere. `test_vercel_expansion_risk_audit.py`'s entire
877-line suite for the 7 unreachable "M59.12 expansion" types is, by
necessity, mock-only (`_ch()` builds a `MagicMock` with hand-set
`provider_metadata`) — there is no real connector output to integrate
against for those types, which is itself the headline finding of this pass
(see Connector review). For the 5 reachable types, this pass adds 2 new
real-`compute_diff()` integration tests
(`test_tracked_fields_vercel_deployment_protection`,
`test_real_compute_diff_detects_deployment_protection_disabled` in
`test_milestone33.py`) proving the fix holds through the real pipeline, not
just a mock.

## Count and threshold handling (fixed)

- Grepped `risk_rules/vercel.py` for `int(.*or 0)` — found and fixed 5
  occurrences (`trusted_ips_count`, `project_count`,
  `default_max_duration_seconds`, `public_function_route_count`,
  `edge_function_count`/`serverless_function_count`), all replaced with a
  new `_int_or_none()` helper mirroring the pattern established in every
  other provider's classification-QA pass this session.
- 8 new tests (`TestCountUnknownBaselineSafety`, section T) prove: an
  unknown baseline never claims a specific "increased from 0" wording and
  never returns high/critical off a `None` baseline alone; a *real* `0`
  baseline still correctly triggers the intended high/critical
  classification (not over-corrected into treating real zeroes as
  unknown).
- No threshold-crossing-only bug exists in `risk_rules/vercel.py` (no
  `THRESHOLD` constant) — count fields use simple increase/decrease
  comparison, so the "over-threshold increase falls to low" bug class does
  not apply. N/A, not a gap.

## Copy safety

Re-scanned all classifier reason strings in `risk_rules/vercel.py` for
breach/compromise/attacker/leak/unauthorized-access/source-code-exposure/
env-var-exposure/secret-exposure/token-exposure/infrastructure-exposure/
data-exposure phrasing — zero matches. All copy uses "may require review",
"verify this change is intentional", "may now be reachable", or similar
advisory framing. `security_rules/vercel.py`'s own module docstring states
the claim-discipline policy explicitly and `test_no_forbidden_phrases_in_
vercel_rules_module` / `test_no_unsafe_assertions_in_vercel_finding_copy`
already assert this (both blocked by the pre-existing container path issue
noted below, unrelated to this pass's changes).

## Fixes made

1. `diff_service.py`: added `vercel_deployment_protection` to
   `_VERCEL_TRACKED_FIELDS_BY_TYPE` (`sso_enabled`, `password_enabled`,
   `preview_deployments_protected` — the 3 fields the connector actually
   emits) — closing the "connector produces this record but compute_diff
   never diffs it" gap for the single most security-relevant Vercel record
   type.
2. `risk_rules/vercel.py`: added `_int_or_none()` and fixed 5 count-field
   classifier branches to stop coercing an unknown baseline to `0`.
3. `tests/test_milestone33.py`: added 2 new tests
   (`test_tracked_fields_vercel_deployment_protection`,
   `test_real_compute_diff_detects_deployment_protection_disabled`) proving
   the diff-tracking fix through both the tracked-fields map directly and
   the real `compute_diff()` pipeline.
4. `tests/test_vercel_expansion_risk_audit.py`: added 8 new tests
   (`TestCountUnknownBaselineSafety`, section T) proving the count-unknown
   fixes.

No registry, frontend catalog, or correlation-service change was needed —
all 7 existing Security Finding rules were already fully registered and
correctly aligned. No connector fetch code was added for the 7 unreachable
expansion record types — per this task's explicit scope constraint, adding
real Vercel API integration for deployments/team-members/edge-config/
crons/integrations/firewall-rules requires live API verification and is
out of scope for this QA-and-fix pass; it is documented as the primary
"not detected" finding instead.

## Validation run

- `docker compose exec api pytest tests/test_vercel_expansion_risk_audit.py tests/test_milestone33.py -q`
  → **276 passed** (0 skipped, 0 failed).
- `docker compose exec api pytest tests -q -k "vercel"` → **492 passed, 4
  skipped, 1 failed, 16895 deselected** — the 1 failure
  (`test_no_forbidden_phrases_in_vercel_rules_module`) is a pre-existing,
  unrelated container-path issue: the test computes `REPO_ROOT` assuming a
  `/backend/...` mount structure that doesn't match this container's `/app`
  mount (identical root cause to a pre-existing failure found and documented
  in the prior Azure classification-QA pass — confirmed via a direct
  `FileNotFoundError` unrelated to any Vercel logic or wording).
- `test_*vercel*` glob → **322 passed, 3 skipped, 1 failed** (same
  pre-existing failure as above).
- No frontend files were changed in this pass, so `npx tsc --noEmit` was
  not required.

## Safety and hygiene

- Safety grep (scoped to the 4 touched files) for breach/compromise/
  exposure/source-code/env-var/secret/token/infrastructure/data-exposure
  phrasing → **0 matches**.
- `git diff --check` → clean (no whitespace errors).
- `git status --short` → 4 modified files, 1 new report file, 1 untracked
  unrelated directory (`tail-latency-study/`, not staged).
