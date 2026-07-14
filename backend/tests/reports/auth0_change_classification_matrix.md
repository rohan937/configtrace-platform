# Auth0 Change-Classification QA Matrix

Dedicated follow-up to the detection QA pass committed as `5d7512c`
(`auth0_detection_matrix.md`), which built `risk_rules/auth0.py` from
scratch and added `_AUTH0_TRACKED_FIELDS_BY_TYPE`. Because the classifier
module was newly written and broad, this pass verifies its quality
field-by-field: severity correctness, safe wording, restoration behavior,
and parity with Security Findings — and resolves the two documented
Change-only coverage gaps.

## Summary

`risk_rules/auth0.py` had no `old_value`/`previous_value`/`prior_value`
field-name bug — grepped clean. Having just fixed a false-positive
severity bug in PagerDuty's classification-QA pass and a crossing-only
threshold bug in Datadog's classification-QA pass, this module was
already written defensively from the start: `_int_or_none()` is used for
every count-based branch, and `_crossed_threshold_increase()` fires on
**any increase while over the threshold**, not just the crossing
transition. Confirmed by grepping for `int(... or 0)` and equivalent
coercion patterns: **zero matches**.

This pass found **two real issues** and closed **two genuine Finding-layer
coverage gaps**:

1. **`auth0_application.allowed_logout_urls_count` was tracked in
   `_AUTH0_TRACKED_FIELDS_BY_TYPE` but had no branch in
   `risk_rules/auth0.py` at all.** It silently fell through to the bare
   `"configuration field '...' changed."` fallback instead of being
   grouped with its sibling count fields. Severity was unaffected (the
   bare fallback is also `low`), so this is a wording/traceability gap,
   not a severity bug. **Fixed** by adding it to the existing generic
   fields tuple.

2. **`grant_client_credentials_enabled: True → False` previously returned
   `medium` unconditionally.** The backing Finding
   (`auth0_application_public_client_credentials_enabled`, high) only
   fires when this grant is **combined** with a public/client-side
   `app_type` or `token_endpoint_auth_method="none"`. The client
   credentials grant is Auth0's standard, expected grant for confidential
   machine-to-machine applications — the common case — so defaulting to
   `medium` on every enablement would over-alert on normal M2M
   configuration. **This is a genuine severity misclassification, fixed**
   by downgrading to `low` (a Change-only, generic signal), consistent
   with how `grant_refresh_token_enabled` and
   `grant_authorization_code_enabled` are already treated. The Finding
   layer (which can see `app_type`) remains the sole source of truth for
   the genuinely risky combination.

3. **Change-only coverage gaps closed**: the detection-QA report
   documented `auth0_connection.mfa_enabled` and
   `auth0_resource_server.signing_alg` as fetched, tracked, and classified
   fields with no backing Security Finding. On review, both are **direct,
   low-risk, single-field analogs** of existing rule patterns
   (`auth0_connection_weak_password_policy` for the connection case;
   `auth0_application_weak_jwt_algorithm` for the resource-server case) —
   not multi-field combined conditions like the ones this codebase
   otherwise leaves as accepted Change-only approximations. Two new
   Security Finding rules were added:
   - `auth0_connection_mfa_disabled` (high) — fires when
     `strategy=="auth0" AND mfa_enabled is False`.
   - `auth0_resource_server_weak_signing_algorithm` (high) — fires when
     `signing_alg` is in the same weak/symmetric algorithm set as the
     application-level rule.

   Both are registered across all four backend registries
   (`security_rule_registry.py`, `security_rule_pack.py`,
   `security_rule_confidence.py`, `security_coverage_service.py`), the
   frontend `securityRuleCatalog.ts`, the Risk×Activity correlation
   service (`auth0_risk_activity_correlation_service.py`), and the
   provider-depth-QA exact-equality rule sets
   (`test_auth0_provider_depth_qa.py`, `test_milestone81h_...`,
   `test_milestone81i_...`) — bringing the total Auth0 rule count from
   **37 to 39**.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected by `compute_diff`? | Current risk_level | Expected risk_level | Current title/copy | Expected title/copy | Security finding parity | Status | Test covering it | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1. Tenant dynamic client registration enabled | `auth0_tenant_settings` | `flag_enable_dynamic_client_registration` | `False` | `True` | yes | high | high | "authentication posture changed — dynamic client registration was enabled tenant-wide." | (same) | `auth0_tenant_dynamic_client_registration_enabled` (high) — matches | PASS | existing `test_dynamic_client_registration_enabled_is_high` | — |
| A2. Tenant dynamic client registration disabled | `auth0_tenant_settings` | `flag_enable_dynamic_client_registration` | `True` | `False` | yes | low | low (improvement) | "dynamic client registration was disabled." | (same) | n/a | PASS | new `test_tenant_dynamic_client_registration_disabled_is_low` | — |
| A3. Tenant session lifetime extended | `auth0_tenant_settings` | `session_lifetime_category` | `"standard"` | `"extended"` | yes | medium | medium | "token policy changed — tenant login session lifetime was extended." | (same) | `auth0_tenant_session_lifetime_extended` (medium) — matches | PASS | existing `test_tenant_session_lifetime_extended_is_medium` | — |
| A4. Tenant session lifetime restored | `auth0_tenant_settings` | `session_lifetime_category` | `"extended"` | `"standard"` | yes | low | low (improvement) | "login session lifetime was shortened." | (same) | n/a | PASS | new `test_tenant_session_lifetime_restored_is_low` | — |
| A5. Tenant idle session lifetime extended | `auth0_tenant_settings` | `idle_session_lifetime_category` | `"standard"` | `"extended"` | yes | low | low | "idle session lifetime was extended." | (same) | `auth0_tenant_idle_session_lifetime_extended` (low) — matches | PASS | new `test_tenant_idle_session_lifetime_extended_is_low` | — |
| B1. Application OIDC conformance disabled | `auth0_application` | `oidc_conformant` | `True` | `False` | yes | medium | medium | "OAuth posture changed — OIDC conformance was disabled." | (same) | `auth0_application_oidc_non_conformant` (medium) — matches | PASS | covered by tracked-field sweep | — |
| B2. Application OIDC conformance restored | `auth0_application` | `oidc_conformant` | `False` | `True` | yes | low | low (improvement) | "OIDC conformance was enabled." | (same) | n/a | PASS | new `test_oidc_conformant_restored_is_low` | — |
| B3. Weak JWT signing algorithm | `auth0_application` | `jwt_alg` | `"RS256"` | `"HS256"` | yes | high | high | "OAuth posture changed — JWT signing algorithm changed to HS256." | (same) | `auth0_application_weak_jwt_algorithm` (high) — matches | PASS | existing `test_weak_jwt_alg_is_high` | — |
| B4. JWT signing algorithm strengthened | `auth0_application` | `jwt_alg` | `"HS256"` | `"RS256"` | yes | low | low (improvement) | "signing algorithm was strengthened to an asymmetric algorithm." | (same) | n/a | PASS | existing `test_jwt_alg_strengthened_is_low` | — |
| B5. Callback URL count increased while already broad | `auth0_application` | `callbacks_count` | `15` | `20` | yes | medium | medium | "callback URL count increased to 20, exceeding the review threshold." | (same) | `auth0_application_many_callbacks` (medium) — matches | PASS | existing `test_callbacks_count_increase_while_already_broad_is_medium` | Any-increase-while-over-threshold, proactively applying the Datadog classification-QA fix pattern |
| B6. Callback URL count decreased while still broad | `auth0_application` | `callbacks_count` | `20` | `15` | yes | low | low (improvement) | "callback URL count changed to 15." | (same) | n/a | PASS | existing `test_callbacks_count_decrease_while_still_broad_is_low` | — |
| B7. Web origin count increased while already broad | `auth0_application` | `web_origins_count` | `15` | `20` | yes | medium | medium | "web origins count increased to 20, exceeding the review threshold." | (same) | `auth0_application_many_allowed_origins` (medium, summed threshold approximation) — matches | PASS | new `test_web_origins_count_increase_while_already_broad_is_medium` | — |
| B8. Grant type count decreased while still broad | `auth0_application` | `grant_types_count` | `8` | `6` | yes | low | low (improvement) | "grant type count changed to 6." | (same) | n/a | PASS | new `test_grant_types_count_decrease_while_still_broad_is_low` | — |
| B9. Refresh token rotation disabled | `auth0_application` | `refresh_token_rotation_enabled` | `True` | `False` | yes | medium | medium | "token policy changed — refresh token rotation was disabled." | (same) | `auth0_refresh_token_rotation_disabled` (medium) — matches | PASS | existing `test_refresh_token_rotation_disabled_is_medium` | — |
| B10. Wildcard callback present | `auth0_application` | `wildcard_callback_present` | `False` | `True` | yes | high | high | "wildcard callback URL is now present." | (same) | `auth0_application_wildcard_callback` (high) — matches | PASS | existing `test_wildcard_callback_present_is_high` | — |
| B11. Wildcard allowed origin removed | `auth0_application` | `wildcard_allowed_origin_present` | `True` | `False` | yes | low | low (improvement) | "wildcard allowed origin was removed." | (same) | n/a | PASS | new `test_wildcard_allowed_origin_removed_is_low` | — |
| B12. Wildcard logout URL present | `auth0_application` | `wildcard_logout_url_present` | `False` | `True` | yes | medium | medium | "wildcard logout URL is now present." | (same) | `auth0_application_wildcard_logout_url` (medium) — matches | PASS | new `test_wildcard_logout_url_present_is_medium` | — |
| B13. Callbacks missing HTTPS restored | `auth0_application` | `callbacks_missing_https` | `True` | `False` | yes | low | low (improvement) | "callback URLs no longer miss HTTPS." | (same) | n/a | PASS | new `test_callbacks_missing_https_restored_is_low` | — |
| B14. Token endpoint auth restored | `auth0_application` | `token_endpoint_auth_method` | `"none"` | `"client_secret_basic"` | yes | low | low (improvement) | "now requires a client secret or assertion." | (same) | n/a | PASS | new `test_token_endpoint_auth_none_restored_is_low` | — |
| B15. Client credentials grant enabled (bug fix) | `auth0_application` | `grant_client_credentials_enabled` | `False` | `True` | yes | ~~medium~~ → low | low | ~~"OAuth posture changed — the client credentials grant was enabled."~~ → "client credentials grant was enabled. This may require review." | "client credentials grant was enabled. This may require review." | n/a — `auth0_application_public_client_credentials_enabled` (high) requires the combination with a public app_type, which a single-field Change can't see | **FIXED** | new `test_client_credentials_grant_enabled_is_low_not_medium` | The core severity bug in this pass — see Summary #2 |
| B16. Allowed logout URLs count changed (bug fix) | `auth0_application` | `allowed_logout_urls_count` | `1` | `2` | yes | low (via bare fallback) | low (via explicit branch) | ~~"configuration field 'allowed_logout_urls_count' changed."~~ → "allowed logout urls count changed." | "allowed logout urls count changed." | n/a — no Finding tracks logout URL count | **FIXED** | new `test_allowed_logout_urls_count_is_explicitly_named_not_bare_fallback` | The fall-through bug in this pass — see Summary #1 |
| C1. Connection MFA disabled (Finding added) | `auth0_connection` | `mfa_enabled` | `True` | `False` | yes | high | high | "MFA posture was weakened — this database connection no longer has MFA enabled." | (same) | `auth0_connection_mfa_disabled` (high, new) — now matches | **FIXED (Finding added)** | existing `test_connection_mfa_disabled_is_high` (classifier); new `test_connection_mfa_disabled_fires`/`test_connection_mfa_enabled_does_not_fire`/`test_connection_mfa_unknown_does_not_fire`/`test_connection_mfa_social_strategy_skipped` (Finding) | Closes the category-C gap documented in the detection-QA report — see Summary #3 |
| C2. Connection MFA restored | `auth0_connection` | `mfa_enabled` | `False` | `True` | yes | low | low (improvement) | "MFA was enabled." | (same) | n/a | PASS | new `test_connection_mfa_enabled_restored_is_low` | — |
| C3. Connection enabled_clients_count reaches zero | `auth0_connection` | `enabled_clients_count` | `3` | `0` | yes | low | low | "now has no enabled client applications." | (same) | `auth0_connection_no_enabled_clients` (low) — matches | PASS | new `test_connection_enabled_clients_count_zero_is_low_not_error` | — |
| D1. Resource server RBAC restored | `auth0_resource_server` | `rbac_enabled` | `False` | `True` | yes | low | low (improvement) | "RBAC enforcement was enabled." | (same) | n/a | PASS | new `test_resource_server_rbac_restored_is_low` | — |
| D2. Resource server offline access disabled | `auth0_resource_server` | `allow_offline_access` | `True` | `False` | yes | low | low (improvement) | "offline access was disabled." | (same) | n/a | PASS | new `test_resource_server_offline_access_disabled_is_low` | — |
| D3. Resource server signing algorithm weakened (Finding added) | `auth0_resource_server` | `signing_alg` | `"RS256"` | `"HS256"` | yes | high | high | "token policy changed — API signing algorithm changed to HS256." | (same) | `auth0_resource_server_weak_signing_algorithm` (high, new) — now matches | **FIXED (Finding added)** | existing `test_resource_server_weak_signing_alg_is_high` (classifier); new `test_resource_server_weak_signing_algorithm_fires_hs256`/`test_resource_server_weak_signing_algorithm_fires_none`/`test_resource_server_rs256_does_not_fire_weak_signing`/`test_resource_server_signing_alg_missing_does_not_fire` (Finding) | Closes the category-D gap documented in the detection-QA report — see Summary #3 |
| D4. Resource server signing algorithm strengthened | `auth0_resource_server` | `signing_alg` | `"HS256"` | `"RS256"` | yes | low | low (improvement) | "strengthened to an asymmetric algorithm." | (same) | n/a | PASS | new `test_resource_server_signing_alg_strengthened_is_low` | — |
| D5. Resource server token lifetime restored | `auth0_resource_server` | `token_lifetime_category` | `"extended"` | `"short"` | yes | low | low (improvement) | "access token lifetime was shortened." | (same) | n/a | PASS | new `test_resource_server_token_lifetime_restored_is_low` | — |
| E1. Custom domain verification weakened | `auth0_custom_domain` | `status` | `"ready"` | `"pending_verification"` | yes | medium | medium | "custom domain status changed to 'pending_verification'." | (same) | `auth0_custom_domain_not_ready` (medium) — matches | PASS | existing `test_custom_domain_not_ready_is_medium` | — |
| E2. Custom domain provisioning | `auth0_custom_domain` | `status` | `"ready"` | `"provisioning"` | yes | medium | medium | "custom domain status changed to 'provisioning'." | (same) | `auth0_custom_domain_not_ready` (medium) — matches | PASS | new `test_custom_domain_provisioning_is_medium` | — |
| E3. Custom domain verification restored | `auth0_custom_domain` | `status` | `"pending_verification"` | `"ready"` | yes | low | low (improvement) | "reached the ready state." | (same) | n/a | PASS | existing `test_custom_domain_ready_is_low` | — |
| E4. Custom domain TLS policy restored | `auth0_custom_domain` | `tls_policy_category` | `"compatible"` | `"recommended"` | yes | low | low (improvement) | "TLS policy category changed." | (same) | n/a | PASS | new `test_custom_domain_tls_policy_restored_is_low` | — |
| F1. Rule disabled | `auth0_rule` | `enabled` | `True` | `False` | yes | low | low | "rule was disabled." | (same) | `auth0_rule_disabled` (low, combined w/ `script_present`) — matches severity | PASS | existing `test_rule_disabled_is_low` | Combined-condition approximation: Change fires on `enabled` alone; severity already matches since the Finding itself is `low` |
| F2. Rule restored | `auth0_rule` | `enabled` | `False` | `True` | yes | low | low (improvement) | "rule was enabled." | (same) | n/a | PASS | new `test_rule_enabled_restored_is_low` | — |
| F3. Action secrets count reaches real zero | `auth0_action` | `secrets_count` | `2` | `0` | yes | low | low | "secrets count changed to 0." | (same) | n/a — decrease, not a finding-worthy increase | PASS | new `test_action_secrets_count_real_zero_is_low_not_error` | Confirms real zero doesn't error and isn't confused with unknown |
| F4. Action deployed version restored | `auth0_action` | `deployed_version_present` | `False` | `True` | yes | low | low (improvement) | "action was deployed." | (same) | n/a | PASS | new `test_action_deployed_version_restored_is_low` | — |
| G. Organizations / membership settings | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Auth0 organizations are not modeled by `auth0_schema.py` — no `/api/v2/organizations` endpoint is fetched by this connector. Not invented |
| H1. Unknown/missing sweep (15 fields across 8 record types) | multiple | see broader sweep test | truthy/category | `None` | yes | low | low | all say "...is now unknown or missing" (never "disabled"/a specific category) | (same) | n/a | PASS | new `test_broader_unknown_transition_sweep_never_produces_high_or_overstated_medium` | Extends the original 7-field sweep to 15 fields covering every high/medium-capable branch, excluding the one intentional exception (password_policy_category, tested separately) |
| H2. Connection password policy unset (intentional exception) | `auth0_connection` | `password_policy_category` | `"good"` | `None` | yes | high | high | "database connection password policy is weak or not configured." | (same) | `auth0_connection_weak_password_policy` (high, also fires on `None`) — matches | PASS | existing `test_connection_password_policy_unset_is_high` | Deliberately excluded from the generic unknown-never-high sweep — mirrors the Finding's own explicit "unset is itself weak" design |
| H3. Real zero vs. unknown for counts | `auth0_application`, `auth0_action` | `callbacks_count`, `secrets_count` | numeric | `None` vs. `0` | yes | low (both) | low (both), but with distinct wording | "...is now unknown or missing" vs. "...changed to 0" | (same) | n/a | PASS | existing `test_count_unknown_not_treated_as_zero`; new `test_action_secrets_count_real_zero_is_low_not_error` | Confirms `_int_or_none()` distinguishes the two cases correctly |
| I. Copy safety | all record types | all fields | — | — | — | — | — | no breach/compromise/attacker/leak/unauthorized-access/account-takeover/credential-exposed/token-exposed/secret-exposed/data-exposed language anywhere | (same) | — | PASS | existing `test_no_forbidden_wording_in_reasons`, re-verified after this pass's edits | — |

## Tracked-fields vs. classifier-branch comparison

Verified programmatically: parsed `_AUTH0_TRACKED_FIELDS_BY_TYPE` from
`diff_service.py` and every `if fp == "..."` / `if fp in (...)` branch
from each of the 8 `_classify_*_change` functions in `risk_rules/auth0.py`,
then diffed the two sets per record type.

**Before this pass**: `auth0_application.allowed_logout_urls_count` was
tracked but not present in any classifier branch (accidental fall-through
to the bare generic fallback).

**After this pass**: zero tracked fields fall through accidentally across
all 8 record types — every tracked field is handled by either a
field-specific branch or an explicit generic group.

**Classifier branches referring to fields not emitted by the
connector/schema:** none found — every branch was cross-checked against
both `_AUTH0_TRACKED_FIELDS_BY_TYPE` and `auth0_schema.py`'s `TypedDict`
definitions.

**Classifier branches referring to stale field names:** none — this is a
newly-built module (this session), so there was no legacy field-name
drift to inherit.

**Fields with similar names that could be confused:** `jwt_alg`
(`auth0_application`) vs. `signing_alg` (`auth0_resource_server`) remain
the closest pair — both use the identical `_WEAK_JWT_ALGS` set and
near-identical wording, but each branch names its own field/record type
explicitly ("Auth0 application OAuth posture" vs. "Auth0 token policy —
API signing algorithm"), so the two stay distinguishable in the reason
text. No new confusable pairs were introduced by adding
`auth0_connection_mfa_disabled` / `auth0_resource_server_weak_signing_algorithm`.

## Verification: no `int(value or 0)`-style coercion remains

```
grep -n "int(.*or 0)\|_int_pair" backend/app/services/risk_rules/auth0.py
```
→ no matches. Every count-based branch (`callbacks_count`,
`allowed_origins_count`, `web_origins_count`, `grant_types_count`,
`enabled_clients_count`, `secrets_count`) uses `_int_or_none()` via either
the direct helper or `_crossed_threshold_increase()`, confirmed both
before and after this pass's edits.

## Verification: threshold-increase-while-already-over-threshold handled correctly (no Datadog-style bug)

`_crossed_threshold_increase(prev_v, new_v, threshold)` returns
`n_new > threshold and n_new > (n_old or 0)` — any increase while over
the threshold, not a crossing-only check. Confirmed via tests for every
threshold field:
- `callbacks_count` 15→20 (threshold 10): medium, review-worthy (existing test)
- `web_origins_count` 15→20 (threshold 10): medium (new test)
- `grant_types_count` decrease 8→6 (threshold 4): low/improvement (new test)
- `grant_types_count` 5→6 (threshold 4, already over): medium (existing test)

No PagerDuty-style or Datadog-style regression found in this module —
both defensive patterns were applied from the start during the detection
QA pass, and this classification-QA pass adds tests that lock them in
rather than finding and fixing new instances of either bug.

## Mock-shape (`old_value`/`prev_value`/`previous_value`/`prior_value`) verification

```
grep -n "old_value\|previous_value\|prior_value\|prev_value" backend/app/services/risk_rules/auth0.py
```
→ all matches are `_get(change, "prev_value")` — production code was
already clean, no `old_value`/`previous_value`/`prior_value` usage found.

```
grep -rn "old_value\|previous_value\|prior_value" backend/tests/test_milestone81a_auth0_drift_provider_foundation.py
```
→ one match, a docstring comment naming the bug class being guarded
against (`test_classifier_reads_real_compute_diff_dict_shape_not_a_mock`),
not an actual field usage.

**No mock-shape issue remains, and none was introduced by this pass.**
The existing `test_classifier_reads_real_compute_diff_dict_shape_not_a_mock`
test already builds a plain dict shaped exactly like real `compute_diff`
output (not a `MagicMock`), confirming the classifier reads `prev_value`
correctly.

## Design notes

### Why `grant_client_credentials_enabled` is `low`, not `medium` or `high`

`auth0_application_public_client_credentials_enabled` (high) requires the
combination `grant_client_credentials_enabled AND (app_type in
{spa, native} OR token_endpoint_auth_method == "none")`. Client
credentials is Auth0's standard, expected grant for confidential
machine-to-machine applications — the common, non-risky case. A
single-field Change classifier cannot see the sibling `app_type` field,
so defaulting to any severity above `low` would over-alert on normal M2M
configuration far more often than it would correctly flag the risky
combination. This pass downgraded the branch from `medium` to `low`,
matching the treatment already given to `grant_refresh_token_enabled` and
`grant_authorization_code_enabled` (both generic `low`) — the Finding
layer remains the sole source of truth for the genuinely risky
combination, since it can inspect `app_type` directly.

### Why `auth0_connection.mfa_enabled` and `auth0_resource_server.signing_alg` got new Findings instead of staying Change-only

The detection-QA pass documented both as Change-only signals and
explicitly left the decision of whether to add Findings to this
follow-up pass. On review, both differ from the codebase's usual
"accepted Change-only approximation" pattern (which applies to
**combined-condition** Findings a single-field Change can't replicate,
e.g. `clerk_webhook_without_signing`, `auth0_application_public_client_credentials_enabled`):
neither `mfa_enabled` nor `signing_alg` requires a second field to
evaluate — they are direct, single-field analogs of existing rule
patterns (`auth0_connection_weak_password_policy` and
`auth0_application_weak_jwt_algorithm`, respectively) applied to fields
that were simply never given their own Finding. Adding a Finding for each
was low-risk (mirrors an existing, already-tested pattern almost
verbatim) and closes a genuine detection gap rather than leaving
permanent Change/Finding disagreement. Both new rules were registered
across all four backend registries, the frontend catalog, the
Risk×Activity correlation service, and the provider-depth-QA exact-
equality rule sets.

### Why `auth0_rule_disabled`'s combined condition is still an accepted Change-only approximation

Unlike the two gaps above, `auth0_rule_disabled` requires
`enabled=False AND script_present=True` — a genuine two-field
combination on the *same* record. The Change classifier fires on
`enabled` alone, and this remains an accepted approximation (not
converted to two separate rules) because the severity already matches
(`low`) regardless of the sibling field's value, consistent with every
other combined-condition approximation documented across this codebase's
prior classification-QA passes.

## Totals

| Metric | Count |
|---|---|
| Total classification cases reviewed | 43 (A1–I, all rows above, counting sub-cases) |
| PASS | 39 |
| FAIL | 0 |
| GAP → FIXED (severity bug: `grant_client_credentials_enabled`) | 1 (B15) |
| GAP → FIXED (fall-through bug: `allowed_logout_urls_count`) | 1 (B16) |
| GAP → FIXED (new Security Findings added) | 2 (C1, D3) |
| N/A (not modeled, correctly absent) | 1 (G — organizations) |
| New Security Finding rules added | 2 (`auth0_connection_mfa_disabled`, `auth0_resource_server_weak_signing_algorithm`) — total Auth0 rule count 37 → 39 |
| Previously detected changes now confirmed misclassified before this pass | 1 (`grant_client_credentials_enabled: True` was `medium`, systematically over-alerting on normal M2M configuration; now `low`) |
| Mock-shape (`old_value`-style) bugs found | 0 |
| PagerDuty-style unknown-treated-as-zero bug found | 0 — confirmed the module was already defensive from the start |
| Datadog-style crossing-only threshold bug found | 0 — confirmed `_crossed_threshold_increase()` was already "any increase while over threshold" from the start |
| MFA/tenant/application/connection/API/domain/rule classifications aligned with Security Findings | Yes — all severities cross-checked against the (now 39-rule) severity table with zero mismatches after the `grant_client_credentials_enabled` fix; combined-condition disagreements documented as accepted structural limitations, not defects |
| Change-only evidence for `connection.mfa_enabled` / `resource_server.signing_alg` | **Converted to Security Findings** in this pass (no longer Change-only) |

## Fixes made

1. **`backend/app/services/risk_rules/auth0.py`**
   - `_classify_application_change`: added `allowed_logout_urls_count` to
     the generic fields tuple (previously fell through to the bare
     `"configuration field '...' changed."` fallback).
   - `_classify_application_change`: `grant_client_credentials_enabled`
     downgraded from `medium` to `low` to avoid over-alerting on normal
     M2M application configuration (see design notes).
   - Updated module docstring's risk-level summary and the two inline
     comments referencing "no dedicated Finding" for `mfa_enabled` and
     `signing_alg` (now accurate — both have dedicated Findings).
2. **`backend/app/services/security_rules/auth0.py`** — added two new
   rules: `auth0_connection_mfa_disabled` (high, in `_eval_connection`)
   and `auth0_resource_server_weak_signing_algorithm` (high, in
   `_eval_resource_server`). Added both rule-key constants to
   `AUTH0_RULE_KEYS` and updated the module docstring's "Record types
   consumed" section.
3. **`backend/app/services/security_rule_registry.py`**,
   **`security_rule_pack.py`**, **`security_rule_confidence.py`**,
   **`security_coverage_service.py`** — registered both new rule keys.
4. **`backend/app/services/auth0_risk_activity_correlation_service.py`**
   — added both new rule keys to their respective correlation entries
   (`auth0_connection_risk_activity_correlation`,
   `auth0_resource_server_risk_activity_correlation`).
5. **`frontend/src/lib/securityRuleCatalog.ts`** — added catalog entries
   for both new rules (title, description, whatItChecks, whyItMatters,
   evidence, remediation, falsePositiveGuard).
6. **`backend/tests/test_milestone81a_auth0_drift_provider_foundation.py`**
   — added a new `TestAuth0ChangeClassificationQA` class (28 tests):
   regression tests for both bug fixes, restoration/improvement tests
   across every category (tenant, application, connection, resource
   server, custom domain, rule, action), a 15-field broadened
   unknown-transition sweep, and a test confirming no security-sensitive
   field ever resolves through the bare generic fallback.
7. **`backend/tests/test_milestone81b_auth0_core_security_foundation.py`**
   — added 8 positive/negative/unknown tests for the two new Findings.
8. **`backend/tests/test_auth0_provider_depth_qa.py`**,
   **`test_milestone81h_auth0_provider_depth_qa.py`**,
   **`test_milestone81i_auth0_cross_cloud_ux_polish.py`** — updated the
   exact-equality expected rule-key sets and hardcoded rule-count
   assertions (37 → 39) to include the two new rules.
9. **`backend/tests/reports/auth0_change_classification_matrix.md`** —
   this report.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone81a_auth0_drift_provider_foundation.py -q
# 199 passed (was 173 after 5d7512c)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone81b_auth0_core_security_foundation.py -q
# 104 passed (was 96 before this pass's new Finding tests)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone81a_auth0_drift_provider_foundation.py \
    tests/test_milestone81b_auth0_core_security_foundation.py \
    tests/test_milestone81c_auth0_oauth_application_risk_expansion.py \
    tests/test_milestone81h_auth0_provider_depth_qa.py -q
# 470 passed

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "auth0 and risk"
# 114 passed, 17139 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "auth0 and diff"
# 11 passed, 17242 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "auth0"
# 796 passed, 1 skipped, 16456 deselected (was 762 passed, 1 skipped after 5d7512c;
# +2 new Finding rules required updating 3 additional depth-QA/cross-cloud test
# files with exact-equality rule-count assertions, discovered only by running
# this broader filter — test_auth0_provider_depth_qa.py,
# test_milestone81h_auth0_provider_depth_qa.py,
# test_milestone81i_auth0_cross_cloud_ux_polish.py)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*auth0* -q
# 778 passed
```

Frontend catalog changed in this pass (two new rule entries added to
`securityRuleCatalog.ts`), so `npx tsc --noEmit` was run from
`frontend/` — no errors.
