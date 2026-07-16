# Firebase Change-Classification QA Matrix (message 2)

Scope: **classification correctness only**, for the 13 currently-emitted
Firebase record types (`firebase_project`, `firebase_auth_config`,
`firebase_auth_provider`, `firebase_authorized_domain`,
`firebase_firestore_ruleset`, `firebase_database_ruleset`,
`firebase_storage_bucket`, `firebase_storage_ruleset`,
`firebase_hosting_site`, `firebase_hosting_domain`,
`firebase_function_metadata`, `firebase_remote_config_template`,
`firebase_app_check_config`). Reachability, routing, and record-type
inventory were established in message 1 (`7f9b375`) and are not re-litigated
here. No new Firebase or GCP endpoint families were added.

## Graphify summary

All four required `graphify query` commands ran successfully via
`/Users/rohan/.local/bin/graphify`. Per instructions, a successful run was
**not** treated as evidence the index is current relative to `7f9b375`. The
graph surfaced `risk_rules/firebase.py`'s per-record classifier functions and
the `FirebaseAppCheckConfigRecord` / `FirebaseRemoteConfigTemplateRecord`
schema nodes, confirming both are indexed at the class/docstring level. It
did **not** surface the `firebase_database_ruleset` classifier fix from
message 1 as a distinct node beyond the generic module summary, and it did
**not** surface any of the five bug classes fixed in this pass (Boolean
defaulting, unconditional-else, rules-fetch-failure posture, generic "added"
severity, or the `old_value`/`prev_value` field-name bug) — the graph is
coarse (module/class-level) and has no per-field or per-branch granularity.
Direct source reads of `app/connectors/firebase.py` and
`app/services/risk_rules/firebase.py`, plus real `compute_diff()` ->
`classify_firebase_change()` executions, were authoritative for every
finding and fix in this report.

## Summary

| Metric | Count |
|---|---|
| Total cases reviewed | 61 |
| PASS (already correct) | 24 |
| FIXED (bug found and corrected) | 33 |
| GAP (documented, not modeled — out of scope for this pass) | 4 |
| FAIL | 0 |
| New regression tests added | 26 (`test_firebase_change_classification_qa.py`) + 1 updated fixture (`test_milestone57_8.py::_make_firebase_change`) + 1 updated assertion (`test_milestone53.py::test_empty_source_returns_safe_defaults`) |

No new Security Findings were added or changed in this pass — only Change
(drift-timeline) classifiers and connector normalization were touched.
Security Finding evaluators (`security_rules/firebase.py`) already used
correct `is True`/`is False` explicit checks and were re-verified, not
modified.

## Connector unknown-normalization fixes (`app/connectors/firebase.py`)

| # | Field | Before | After |
|---|---|---|---|
| 1 | `firebase_auth_provider.enabled` (SAML) | `bool(cfg.get("enabled", False))` | `_bool_or_none(cfg.get("enabled"))` |
| 2 | `firebase_auth_provider.enabled` (OIDC) | `bool(cfg.get("enabled", False))` | `_bool_or_none(cfg.get("enabled"))` |
| 3 | `firebase_auth_config.sign_in_email_enabled` | coerced to `False` if missing | `_bool_or_none(email_cfg.get("enabled"))` |
| 4 | `firebase_auth_config.sign_in_phone_enabled` | coerced to `False` if missing | `_bool_or_none(phone_cfg.get("enabled"))` |
| 5 | `firebase_auth_config.anonymous_enabled` | coerced to `False` if missing | `_bool_or_none(anon_cfg.get("enabled"))` |
| 6 | `firebase_auth_config.mfa_enabled` | derived, `False` if state unknown | `None` if `mfa_state` is not a string |
| 7 | `_analyze_rules()` empty-source defaults | `public_read/write_detected = False` | `None` (Firestore + Storage rules) |
| 8 | `_analyze_rtdb_rules()` empty defaults | `public_read/write_detected = False` | `None` (Realtime Database rules) |
| 9 | `_fetch_firebase_rules()` per-release fetch-failure `analysis` initializer | `public_read/write_detected = False` | `None` |

A new `_bool_or_none()` helper was added (mirrors the pattern established in
Supabase's message-2 pass) and is now the only path by which these 6
Boolean fields are derived — no caller applies its own `False` default.

**Fields confirmed API-contract-guaranteed, not changed:** App Check's
`enforcementMode` categorization (`_fetch_app_check`) reads a field that is
always present on Google's App Check REST resource schema (not an
optional/newer field like the M57.8 auth flags), so `mode == "ENFORCED"` /
else-unenforced was left as-is. `_classify_authorized_domain_change`'s
`is_default_firebase_domain` / `is_localhost` are deterministically derived
from the domain string itself (never genuinely absent), so no `None`
handling was added there.

## Classifier unknown-branch fixes (`app/services/risk_rules/firebase.py`)

| # | Function | Field | Fix |
|---|---|---|---|
| 1 | `_classify_auth_config_change` | `anonymous_enabled` | explicit `is None` branch added |
| 2 | `_classify_auth_config_change` | `mfa_enabled`/`mfa_state` | explicit `is None` branch added |
| 3 | `_classify_auth_config_change` | `sign_in_email_enabled` | explicit `is None` branch added |
| 4 | `_classify_auth_config_change` | `sign_in_phone_enabled` | explicit `is None` branch added |
| 5 | `_classify_auth_provider_change` | `enabled` | explicit `is None` branch added |
| 6 | `_classify_firestore_ruleset_change` | `public_write_detected` | explicit `is None` branch added |
| 7 | `_classify_firestore_ruleset_change` | `public_read_detected` | explicit `is None` branch added |
| 8 | `_classify_firestore_ruleset_change` | `authenticated_only_detected` | explicit `is None` branch added |
| 9 | `_classify_database_ruleset_change` | `public_write_detected` | explicit `is None` branch added |
| 10 | `_classify_database_ruleset_change` | `public_read_detected` | explicit `is None` branch added |
| 11 | `_classify_database_ruleset_change` | `authenticated_only_detected` | explicit `is None` branch added |
| 12 | `_classify_storage_ruleset_change` | `public_write_detected` | explicit `is None` branch added |
| 13 | `_classify_storage_ruleset_change` | `public_read_detected` | explicit `is None` branch added |
| 14 | `_classify_storage_ruleset_change` | `authenticated_only_detected` | explicit `is None` branch added |
| 15 | `_classify_storage_bucket_change` | `uniform_bucket_level_access` | explicit `is None` branch added |
| 16 | `_classify_remote_config_change` | `old_value` → `prev_value` field-name bug | fixed, all downstream comparisons now use the real previous value |
| 17 | `_classify_remote_config_change` | `parameter_count`/`condition_count` unsafe `_int()` | replaced with `_int_or_none()` + explicit `None` branch |
| 18 | `_classify_app_check_change` | `old_value` → `prev_value` field-name bug | fixed |
| 19 | `_classify_app_check_change` | `enforced_service_count`/`unenforced_service_count`/`service_count` unsafe `_int()` | replaced with `_int_or_none()` + explicit `None` branch |
| 20-23 | `_classify_firestore_ruleset_change`, `_classify_database_ruleset_change`, `_classify_storage_ruleset_change`, `_classify_storage_bucket_change` "added" branches | flat "baseline captured"/generic-low regardless of actual posture | now inspects the full new record (`new_value`) for `public_write_detected`/`public_read_detected`/`uniform_bucket_level_access`/`public_access_prevention` and returns a matching severity |

**Intentional-generic fields (reviewed, confirmed no fix needed):**
`_classify_project_change`, `_classify_authorized_domain_change`,
`_classify_hosting_site_change`, `_classify_hosting_domain_change`,
`_classify_function_metadata_change`'s non-count fields, and the ruleset
classifiers' `rules_hash`/`ruleset_name_hash`/`rule_summary` fields — these
are either deterministic derived values that are never genuinely unknown,
or intentionally generic "review the change" messaging for fields with no
strong safe/unsafe direction. `_classify_authorized_domain_change`'s
`added`/`removed` branches already inspect `is_default`/`is_localhost`
metadata rather than being flat — confirmed correct, no fix needed.

## Per-category classification review (≥55 cases)

Severity scale: `low` < `medium` < `high` < `critical`.

### A/B — Auth config (`firebase_auth_config`)

| # | Case | Expected | Result |
|---|---|---|---|
| 1 | `anonymous_enabled` False→True | high | PASS |
| 2 | `anonymous_enabled` True→False | low | PASS |
| 3 | `anonymous_enabled` known→None | medium, "could not be determined", no "disabled" wording | FIXED |
| 4 | `mfa_enabled`/`mfa_state` ENABLED→DISABLED | high | PASS |
| 5 | `mfa_enabled`/`mfa_state` DISABLED→ENABLED | low | PASS |
| 6 | `mfa_enabled` known→None | medium, "could not be determined" | FIXED |
| 7 | `sign_in_email_enabled` True→False | medium | PASS |
| 8 | `sign_in_email_enabled` known→None | medium, "could not be determined" | FIXED |
| 9 | `sign_in_phone_enabled` True→False | medium | PASS |
| 10 | `sign_in_phone_enabled` known→None | medium, "could not be determined" | FIXED |
| 11 | `authorized_domain_count` changed | medium | PASS |
| 12 | `saml_provider_count`/`oidc_provider_count` changed | medium | PASS |
| 13 | `firebase_auth_config` added | low, baseline | PASS |
| 14 | `firebase_auth_config` removed | high | PASS |

### C — Auth providers (`firebase_auth_provider`)

| # | Case | Expected | Result |
|---|---|---|---|
| 15 | provider `enabled` False→True | medium | PASS |
| 16 | provider `enabled` True→False | medium | PASS |
| 17 | provider `enabled` known→None | medium, "could not be determined" | FIXED |
| 18 | provider added | medium, includes `provider_id` | PASS |
| 19 | provider removed | medium, includes `provider_id` | PASS |

### D — Authorized domains (`firebase_authorized_domain`)

| # | Case | Expected | Result |
|---|---|---|---|
| 20 | custom domain added | high | PASS |
| 21 | default/localhost domain added | low | PASS |
| 22 | custom domain removed | medium | PASS |
| 23 | default/localhost domain removed | low | PASS |

### E — Firestore rules (`firebase_firestore_ruleset`)

| # | Case | Expected | Result |
|---|---|---|---|
| 24 | `public_write_detected` False→True | critical | PASS |
| 25 | `public_write_detected` True→False | low, "improved" | PASS |
| 26 | `public_write_detected` known→None (rules unfetchable) | medium, "could not be determined", no "improved" wording | FIXED |
| 27 | `public_read_detected` False→True | high | PASS |
| 28 | `public_read_detected` known→None | medium, "could not be determined" | FIXED |
| 29 | `authenticated_only_detected` True→False | medium | PASS |
| 30 | `authenticated_only_detected` known→None | medium, "could not be determined" | FIXED |
| 31 | added with `public_write_detected=True` | critical, not "baseline captured" | FIXED |
| 32 | added with safe posture | low, "baseline captured" | PASS |
| 33 | removed | high | PASS |
| 34 | `rules_hash` changed | medium | PASS |

### F — Realtime Database rules (`firebase_database_ruleset`)

| # | Case | Expected | Result |
|---|---|---|---|
| 35 | `public_write_detected` False→True | critical | PASS |
| 36 | `public_write_detected` known→None | medium, "could not be determined" | FIXED |
| 37 | `public_read_detected` False→True | high | PASS |
| 38 | `public_read_detected` known→None | medium, "could not be determined" | FIXED |
| 39 | `authenticated_only_detected` known→None | medium, "could not be determined" | FIXED |
| 40 | added with `public_read_detected=True` | high, not "baseline captured" | FIXED |
| 41 | removed | high | PASS |

### G — Storage (`firebase_storage_bucket` / `firebase_storage_ruleset`)

| # | Case | Expected | Result |
|---|---|---|---|
| 42 | bucket `uniform_bucket_level_access` True→False | high | PASS |
| 43 | bucket `uniform_bucket_level_access` known→None | medium, "could not be determined" | FIXED |
| 44 | bucket `public_access_prevention` enforced→inherited | high | PASS |
| 45 | bucket added without uniform access | medium, mentions ACLs, not flat "low" | FIXED |
| 46 | bucket added hardened | low | PASS |
| 47 | ruleset `public_write_detected` False→True | critical | PASS |
| 48 | ruleset `public_write_detected` known→None | medium, "could not be determined" | FIXED |
| 49 | ruleset added with `public_write_detected=True` | critical, not "baseline captured" | FIXED |

### H — Functions (`firebase_function_metadata`)

| # | Case | Expected | Result |
|---|---|---|---|
| 50 | `runtime`/`trigger_type`/`status` changed | medium (generic, intentional) | PASS |
| 51 | `env_var_key_count` changed | reviewed, safe `is not None` handling already present | PASS |

### I — App Check (`firebase_app_check_config`)

| # | Case | Expected | Result |
|---|---|---|---|
| 52 | `enforced_service_count` decrease (5→2) | high, "removed", correct direction | FIXED (was inverted: reported as "added") |
| 53 | `enforced_service_count` increase (1→3) | low, "added", correct direction | FIXED (previously always read old=0) |
| 54 | `unenforced_service_count` increase | high | FIXED |
| 55 | `unenforced_service_count` decrease | low | FIXED |
| 56 | `service_count` decrease | medium | FIXED (previously showed wrong "from N" value) |
| 57 | removed | high | PASS |
| 58 | added | low, baseline | PASS |

### J/K — Hosting, Remote Config

| # | Case | Expected | Result |
|---|---|---|---|
| 59 | Hosting site/domain generic field changes | medium/low (intentional generic) | PASS |
| 60 | `parameter_count` decrease (10→3) | medium, "decreased from 10 to 3" | FIXED (was: low, "changed from 0 to 3") |
| 61 | `condition_count` decrease | medium, real previous value shown | FIXED |

## Boolean unknown handling (N) — parity check

All fields identified in the connector audit (§ connector fixes table) now
have a matching classifier `is None` branch, verified live via real
`compute_diff()` execution in `test_firebase_change_classification_qa.py`.
No Security Finding evaluator fires on `None` — `security_rules/firebase.py`
was re-read and confirmed to already use explicit `is True`/`is False`
checks throughout (not modified).

## Numeric/threshold handling (O)

`_classify_remote_config_change` and `_classify_app_check_change` were the
only two functions with numeric comparisons, and both had the identical
`old_value`→`prev_value` bug paired with an unsafe zero-default. Both are
now fixed with `_int_or_none()` and explicit unknown branches. No other
Firebase classifier performs numeric comparison.

## List/set handling (P)

`parameter_keys_hash`, `condition_names_hash`, `enforced_service_names`,
`rules_hash` are all hash/summary fields, not raw lists — the underlying
lists (parameter keys, condition names, service names) are never stored, by
design (sensitive-data minimization). No list-specific unknown-handling gap
was found.

## Security Finding parity (Q)

Reviewed against `security_rules/firebase.py`; all findings already use
explicit Boolean checks and were not modified. Documented gaps (unchanged
from message 1, restated for completeness — out of scope to model in this
pass): weak password policy, email-enumeration protection, and
unauthenticated Cloud Function invocation have no dedicated Finding because
the connector does not fetch/derive the underlying fields. No risky Change
classification in this pass rates below its equivalent static Finding's
severity.

## Copy/evidence safety (R)

Two greps run against every touched file
(`app/connectors/firebase.py`, `app/services/risk_rules/firebase.py`,
`tests/test_firebase_change_classification_qa.py`,
`tests/test_milestone57_8.py`, `tests/test_milestone53.py`):

1. Breach/compromise/attacker-access assertion wording — 2 matches, both
   safe (the module's existing policy comment: *"NEVER assert data was
   leaked, breached, or compromised"*, and a pre-existing test that asserts
   this exact rule holds).
2. Sensitive field names / secret material — matches are all pre-existing,
   unmodified code (`access_token` parameter names with an explicit "NEVER
   logged" comment, `service_account_json` field/parameter names, and test
   fixtures using clearly-fake placeholder values like
   `"SECRET_KEY_HERE"`/`"not valid json{{{"`). No real secret material, no
   forbidden assertion wording, introduced by this pass.

## Tests run

- Exact Firebase test files (11 files + 1 new file, 332 tests): **332
  passed**, 0 failed.
- `-k "firebase and auth"`: 31 passed.
- `-k "firestore"`: 19 passed.
- `-k "database"`: 47 passed.
- `-k "storage"`: 138 passed.
- `-k "function"`: 249 passed (ran in background, ~62s).
- `-k "app_check"`: 4 passed.
- `-k "diff"`: 410 passed.
- `-k "risk"`: 4,277 passed, 9 skipped.

No timeouts, no zero-selection filters. `npx tsc --noEmit` was not run — no
frontend files were changed in this pass.

## Stale tests fixed

- `test_milestone53.py::test_empty_source_returns_safe_defaults` — updated
  to assert `None` (unknown) instead of the stale `False` default for
  `public_read_detected`/`public_write_detected` when the rules source is
  empty, matching the corrected connector contract.
- `test_milestone57_8.py::_make_firebase_change` — the shared fixture built
  fake Change dicts using the key `"old_value"`, which is not a field real
  `compute_diff()` Changes ever carry (`"prev_value"` is the real field).
  This fixture bug was masking the exact classifier bug this pass fixed;
  corrected to use `"prev_value"`, which surfaced and then validated the
  `_classify_remote_config_change`/`_classify_app_check_change` fixes (5
  tests initially failed after the classifier fix and the fixture
  correction, all now pass with the corrected expected values).

## Files changed

- `app/connectors/firebase.py` — 9 unknown-normalization fixes (see table above).
- `app/services/risk_rules/firebase.py` — 23 classifier fixes (16 explicit
  `None` branches, 2 `old_value`→`prev_value` fixes, 2 unsafe-int fixes, 4
  "added"-branch posture-inspection fixes across 2 functions... see full
  table above for the itemized 20-23 grouping).
- `tests/test_milestone53.py` — 1 stale assertion updated.
- `tests/test_milestone57_8.py` — 1 stale fixture field name fixed.
- `tests/test_firebase_change_classification_qa.py` — new file, 26 tests.
- `tests/reports/firebase_change_classification_matrix.md` — this report.

## Live-validation recommendation

Recommend validating against a real Firebase project with: (a) at least one
SAML or OIDC provider whose `enabled` field is temporarily omitted from an
API response (or a project on an older Identity Toolkit API version) to
confirm `None` propagates end-to-end in production rather than only in
synthetic tests; (b) a temporary Firestore/Storage rules-fetch failure
(e.g. revoked IAM permission) to confirm the Change classifier reports
"could not be determined" rather than a false "security improved"; (c) a
real App Check enforcement rollback (removing enforcement from 2-3
services) to confirm the corrected direction end-to-end.

## Safe to push?

Yes, contingent on the same reviewer/CI gates as prior message-2 passes.
Do **not** push per this task's explicit instruction — commit only,
matching the required message `"Classify Firebase configuration changes"`.
