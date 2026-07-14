# Clerk Change-Classification QA Matrix

Dedicated follow-up to the detection QA pass committed as `2be46b5`
(`clerk_detection_matrix.md`), which built `risk_rules/clerk.py` from
scratch and added `_CLERK_TRACKED_FIELDS_BY_TYPE`. Because the classifier
module was newly written and broad, this pass verifies its quality
field-by-field: severity correctness, safe wording, restoration behavior,
and parity with Security Findings.

## Summary

`risk_rules/clerk.py` had no `old_value`/`previous_value`/`prior_value`
field-name bug — grepped clean. Having just fixed a false-positive
severity bug in PagerDuty's classification-QA pass and a crossing-only
threshold bug in Datadog's classification-QA pass, this module was
already written defensively from the start: `_int_or_none()` is used for
every count-based branch, and `_crossed_threshold_increase()` fires on
**any increase while over the threshold**, not just the crossing
transition. Confirmed by grepping for `int(... or 0)` and equivalent
coercion patterns: **zero matches**.

This pass found **one real, if minor, classification gap** (not a
severity bug):

**`clerk_instance_settings.sign_in_enabled` was tracked in
`_CLERK_TRACKED_FIELDS_BY_TYPE` but had no explicit branch in
`risk_rules/clerk.py`.** It silently fell through to the bare
`"Clerk instance configuration field '...' changed."` fallback message
instead of being grouped with its sibling boolean fields
(`email_enabled`, `phone_enabled`, `password_enabled`, etc.). Severity was
unaffected (the bare fallback is also `low`, matching what a grouped
branch would have returned), so this is a **wording/traceability gap, not
a false-positive or false-negative severity bug**. Fixed by adding
`sign_in_enabled` to the existing boolean generic-fields tuple.

A full tracked-fields-vs-classifier-branch diff (programmatic, described
below) confirmed this was the **only** field across all 10 record types
that accidentally fell through to the bare fallback, and confirmed **zero
dead/unreachable classifier branches** (every `fp ==`/`fp in (...)` check
corresponds to a real tracked field).

One design-level observation (not a code bug, documented rather than
fixed): `security_rules/clerk.py`'s `_eval_organization_settings` has an
early guard — `if not orgs_enabled: return findings` — meaning **no**
organization Security Finding fires at all when `organizations_enabled`
is `False`, regardless of the other org fields' values. The Change
classifier's `_classify_organization_settings_change` has no equivalent
guard (a single-field Change cannot see the sibling
`organizations_enabled` value), so a change to e.g.
`verified_domains_required` will still be classified `medium` even if
organizations are globally disabled at the time. This is the same
structural "Change classifiers only see one field's transition, not the
full record" limitation already documented for every combined-condition
Finding in this and prior providers' reports — not something a
single-field Change classifier can fix without being handed the full
record, which no provider's Change classifier receives. See the design
note below.

No new Security Finding rules were added in this pass — it is scoped to
the Change-classification layer only.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected by `compute_diff`? | Current risk_level | Expected risk_level | Current title/copy | Expected title/copy | Security finding parity | Status | Test covering it | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1. Instance MFA disabled | `clerk_instance_settings` | `mfa_enabled` | `True` | `False` | yes | high | high | "MFA posture was weakened — multi-factor authentication is no longer enabled at the instance level." | (same) | `clerk_instance_mfa_disabled` (high) — matches | PASS | existing `test_instance_mfa_disabled_is_high` | — |
| A2. Instance MFA enabled | `clerk_instance_settings` | `mfa_enabled` | `False` | `True` | yes | low | low (improvement) | "Clerk instance MFA was enabled." | (same) | n/a | PASS | existing `test_instance_mfa_enabled_is_low` | — |
| A3. Instance MFA unknown | `clerk_instance_settings` | `mfa_enabled` | `True` | `None` | yes | low | low | "MFA enabled state is now unknown or missing." | (same) | n/a | PASS | new broader unknown-sweep test | Does not claim "disabled" on an unknown transition |
| A4. Application MFA not required | `clerk_application` | `mfa_required` | `True` | `False` | yes | medium | medium | "MFA posture was weakened — this application no longer requires multi-factor authentication." | (same) | `clerk_application_mfa_not_required` (medium) — matches | PASS | existing `test_application_mfa_not_required_is_medium` | — |
| A5. Application MFA required restored | `clerk_application` | `mfa_required` | `False` | `True` | yes | low | low (improvement) | "MFA requirement was enabled." | (same) | n/a | PASS | existing `test_application_mfa_required_restored_is_low` | — |
| A6. Auth-strategy MFA capability disabled | `clerk_auth_strategy` | `mfa_enabled` | `True` | `False` | yes | high | high | "MFA posture was weakened — multi-factor authentication capability was disabled." | (same) | n/a — no standalone Finding at this record type for `mfa_enabled` alone (only the combined `mfa_not_required` rule); Change-only signal, following instance-level severity for consistency | PASS | existing `test_auth_strategy_mfa_enabled_disabled_is_high` | Documented Change-only signal, see design note |
| A7. Auth-strategy MFA requirement not required | `clerk_auth_strategy` | `mfa_required` | `True` | `False` | yes | medium | medium | "MFA posture was weakened — multi-factor authentication is no longer required." | (same) | `clerk_auth_strategy_mfa_not_required` (medium, combined w/ `mfa_enabled`) — matches severity | PASS | covered by tracked-field sweep | Combined-condition approximation, consistent with prior providers |
| B1. Instance email verification (channel) disabled | `clerk_instance_settings` | `email_enabled` | `True` | `False` | yes | low | low | "Clerk instance email enabled changed." | (same) | n/a — no dedicated Finding on `email_enabled` alone | PASS | new `test_email_verification_disabled_is_low_no_dedicated_finding` | Schema models this as a channel-capability boolean, not a distinct "verification required" flag |
| B2. Instance phone verification (channel) disabled | `clerk_instance_settings` | `phone_enabled` | `True` | `False` | yes | low | low | "Clerk instance phone enabled changed." | (same) | n/a | PASS | new `test_phone_verification_disabled_is_low_no_dedicated_finding` | Same as B1 |
| C. Password policy (min length, complexity, breach protection) | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | n/a | **N/A** | n/a | `clerk_schema.py` has no password-policy fields; not invented per task instructions |
| C1. Instance password auth toggled | `clerk_instance_settings` | `password_enabled` | `False` | `True` | yes | low | low (generic) | "Clerk instance password enabled changed." | (same) | n/a — `clerk_instance_password_without_mfa` (high) requires the combination `password_enabled AND NOT mfa_enabled`; the higher-signal `mfa_enabled` field already carries `high` on its own transition (A1) | PASS | covered by tracked-field sweep | Combined-condition approximation: severity concentrated on the MFA side, not duplicated onto `password_enabled` |
| D1. Instance sign-up broadened | `clerk_instance_settings` | `sign_up_enabled` | `False` | `True` | yes | low | low | "authentication posture changed — instance sign-up was enabled." | (same) | `clerk_instance_sign_up_enabled` (low) — matches | PASS | covered by tracked-field sweep | Task guidance suggests "medium" for sign-up broadened generally, but this pass follows the existing Finding's `low` severity — no Finding evidence supports elevating past the Finding's own severity |
| D2. Application sign-up broadened | `clerk_application` | `sign_up_enabled` | `False` | `True` | yes | low | low | "authentication posture changed — application sign-up was enabled." | (same) | `clerk_application_sign_up_enabled` (low) — matches | PASS | covered by tracked-field sweep | Same as D1 |
| D3. Instance sign-in mode broadened | `clerk_instance_settings` | `sign_in_mode` | `"restricted"` | `"public"` | yes | medium | medium | "sign-in mode was broadened from restricted to public." | (same) | n/a — no dedicated Finding for `sign_in_mode`; Change-only signal | PASS | covered by tracked-field sweep | Documented Change-only signal |
| D4. Instance sign-in enabled toggled (bug fix) | `clerk_instance_settings` | `sign_in_enabled` | `True` | `False` | yes | low | low | ~~"configuration field 'sign_in_enabled' changed."~~ → "Clerk instance sign in enabled changed." | "Clerk instance sign in enabled changed." | n/a | **FIXED** | new `test_instance_sign_in_enabled_is_explicitly_named_not_bare_fallback` | The one real gap found in this pass — see Summary |
| E1. OAuth/social provider count increases | `clerk_application` | `oauth_provider_count` | `1` | `3` | yes | low | low/medium (task allows either) | "OAuth/social provider count increased from 1 to 3." | (same) | n/a — `clerk_application_oauth_without_mfa` (medium) requires the combination with `mfa_required=False`; primary signal already covered by A4/A5 | PASS | covered by tracked-field sweep | Combined-condition approximation |
| E2. OAuth/social provider count decreases | `clerk_application` | `oauth_provider_count` | `3` | `1` | yes | low | low (improvement) | "OAuth/social provider count changed from 3 to 1." | (same) | n/a | PASS | covered by tracked-field sweep | — |
| E3. OAuth provider count unknown | `clerk_application` | `oauth_provider_count` | `1` | `None` | yes | low | low | "OAuth provider count is now unknown or missing." | (same) | n/a | PASS | existing `test_unknown_transitions_never_produce_high` (extended) | Unknown never treated as zero — see threshold section below |
| F1. Application SAML enabled | `clerk_application` | `saml_enabled` | `False` | `True` | yes | medium | medium | "authentication posture changed — SAML/enterprise SSO was enabled for this application." | (same) | `clerk_application_saml_without_mfa` (medium, combined w/ `mfa_required`) — matches severity | PASS | new `test_application_saml_enabled_is_medium` | Enabling SAML treated as independently notable at `medium` regardless of sibling `mfa_required` |
| F2. Application SAML disabled | `clerk_application` | `saml_enabled` | `True` | `False` | yes | low | low (improvement) | "SAML/enterprise SSO was disabled." | (same) | n/a | PASS | new `test_application_saml_disabled_is_low_improvement` | — |
| F3. Auth-strategy SAML enabled | `clerk_auth_strategy` | `saml_enabled` | `False` | `True` | yes | medium | medium | "authentication posture changed — SAML/enterprise SSO was enabled." | (same) | `clerk_auth_strategy_password_without_mfa`/no direct SAML-specific auth_strategy Finding — mirrors application-level severity convention | PASS | new `test_auth_strategy_saml_enabled_matches_application_severity_convention` | — |
| F4. Auth-strategy SAML disabled | `clerk_auth_strategy` | `saml_enabled` | `True` | `False` | yes | low | low | "SAML enabled state changed." (direction-agnostic wording) | (same) | n/a | PASS | new `test_auth_strategy_saml_disabled_direction_not_overstated` | Wording doesn't differentiate direction here, unlike the application-level branch, but severity is safely `low`, never overstated — a minor wording-consistency observation, not a severity bug |
| G1. Session lifetime extended | `clerk_session_policy` | `session_lifetime_category` | `"standard"` | `"extended"` | yes | medium | medium | "session policy changed — session lifetime was extended." | (same) | `clerk_session_lifetime_extended` (medium) — matches | PASS | existing `test_session_lifetime_extended_is_medium` | — |
| G2. Session lifetime restored | `clerk_session_policy` | `session_lifetime_category` | `"extended"` | `"standard"` | yes | low | low (improvement) | "session lifetime was shortened." | (same) | n/a | PASS | new `test_session_lifetime_restored_is_low` | — |
| G3. Session token rotation disabled | `clerk_session_policy` | `token_rotation_enabled` | `True` | `False` | yes | medium | medium | "session policy changed — token rotation was disabled." | (same) | `clerk_session_token_rotation_disabled` (medium) — matches | PASS | existing `test_session_token_rotation_disabled_is_medium` | — |
| G4. Session token rotation restored | `clerk_session_policy` | `token_rotation_enabled` | `False` | `True` | yes | low | low (improvement) | "token rotation was enabled." | (same) | n/a | PASS | new `test_session_token_rotation_restored_is_low` | — |
| G5. Session reverification disabled | `clerk_session_policy` | `reverification_required` | `True` | `False` | yes | medium | medium | "session policy changed — reverification is no longer required." | (same) | `clerk_session_reverification_disabled` (medium) — matches | PASS | new `test_session_reverification_disabled_is_medium` | — |
| H1. Domain unverified | `clerk_domain` | `verified` | `True` | `False` | yes | medium | medium | "authentication posture changed — a domain became unverified." | (same) | `clerk_domain_unverified` (medium) — matches | PASS | existing `test_domain_unverified_is_medium` | — |
| H2. Domain verified restored | `clerk_domain` | `verified` | `False` | `True` | yes | low | low (improvement) | "Clerk domain was verified." | (same) | n/a | PASS | new `test_domain_verified_restored_is_low` | — |
| H3. Domain SSL disabled | `clerk_domain` | `ssl_enabled` | `True` | `False` | yes | high | high | "Clerk domain SSL was disabled." | (same) | `clerk_domain_ssl_disabled` (high) — matches | PASS | existing `test_domain_ssl_disabled_is_high` | — |
| H4. Domain SSL restored | `clerk_domain` | `ssl_enabled` | `False` | `True` | yes | low | low (improvement) | "Clerk domain SSL was enabled." | (same) | n/a | PASS | new `test_domain_ssl_restored_is_low` | — |
| H5. Redirect URL count increases while already broad | `clerk_application` | `redirect_url_count` | `15` | `20` | yes | low | low | "redirect URL count increased to 20, exceeding the review threshold." | (same) | `clerk_application_many_redirect_urls` (low, fires on every snapshot while `redirect_url_count > 10`) — matches | PASS | existing `test_application_redirect_url_count_increase_while_already_broad_is_low` | Uses any-increase-while-over-threshold from the start (Datadog-pattern applied proactively) |
| H6. Redirect URL wildcard removed | `clerk_redirect_url_config` | `wildcard_present` | `True` | `False` | yes | low | low (improvement) | "wildcard was removed." | (same) | n/a | PASS | new `test_redirect_url_wildcard_removed_is_low` | — |
| I1. Webhook HTTP scheme | `clerk_webhook_endpoint` | `url_scheme_category` | `"https"` | `"http"` | yes | high | high | "posture may require review — the webhook URL scheme is not HTTPS." | (same) | `clerk_webhook_non_https` (high) — matches | PASS | existing `test_webhook_non_https_scheme_is_high` | Finding fires on any non-`"https"` scheme, not just `"http"`; Change classifier mirrors this exactly |
| I2. Webhook signing secret removed | `clerk_webhook_endpoint` | `secret_present` | `True` | `False` | yes | high | high | "posture may require review — the webhook signing secret indicator was removed." | (same) | `clerk_webhook_without_signing` (high, combined w/ `url_present`) — matches | PASS | existing `test_webhook_secret_removed_is_high` | Combined-condition approximation (fires on `secret_present` alone; `url_present` is always `True` for active webhooks) |
| I3. Webhook enabled restored | `clerk_webhook_endpoint` | `enabled` | `False` | `True` | yes | low | low (improvement) | "webhook endpoint was enabled." | (same) | n/a | PASS | new `test_webhook_enabled_restored_is_low` | — |
| J1. JWT template audience missing | `clerk_jwt_template` | `audience_present` | `True` | `False` | yes | medium | medium | "JWT template no longer has an audience configured." | (same) | `clerk_jwt_template_audience_missing` (medium) — matches | PASS | new `test_jwt_template_audience_missing_is_medium` | — |
| J2. JWT template audience restored | `clerk_jwt_template` | `audience_present` | `False` | `True` | yes | low | low (improvement) | "JWT template audience was configured." | (same) | n/a | PASS | new `test_jwt_template_audience_restored_is_low` | — |
| J3. JWT template lifetime restored | `clerk_jwt_template` | `lifetime_category` | `"extended"` | `"standard"` | yes | low | low (improvement) | "JWT template lifetime was shortened." | (same) | n/a | PASS | new `test_jwt_template_lifetime_restored_is_low` | — |
| J4. JWT template claims count increases while already broad | `clerk_jwt_template` | `claims_count` | `20` | `25` | yes | low | low | "claims count increased to 25, exceeding the review threshold." | (same) | `clerk_jwt_template_many_claims` (low, fires on every snapshot while `claims_count > 15`) — matches | PASS | new `test_jwt_template_claims_count_increase_while_already_broad_is_low` | Any-increase-while-over-threshold, proactively applied |
| K1. Org admin role missing | `clerk_organization_settings` | `admin_role_present` | `True` | `False` | yes | medium | medium | "authentication posture changed — the organization admin role is no longer present." | (same) | `clerk_org_admin_role_missing` (medium) — matches **only when `organizations_enabled=True`** | PASS (with caveat) | new `test_org_admin_role_missing_is_medium` | See design note — Change classifier can't see the sibling `organizations_enabled` guard |
| K2. Org admin role restored | `clerk_organization_settings` | `admin_role_present` | `False` | `True` | yes | low | low (improvement) | "organization admin role was configured." | (same) | n/a | PASS | new `test_org_admin_role_restored_is_low` | — |
| K3. Org verified-domains requirement dropped | `clerk_organization_settings` | `verified_domains_required` | `True` | `False` | yes | medium | medium | "organizations no longer require verified domains." | (same) | `clerk_org_verified_domains_not_required` (medium) — matches, same guard caveat as K1 | PASS (with caveat) | new `test_org_verified_domains_not_required_is_medium` | — |
| K4. Org role count real zero | `clerk_organization_settings` | `role_count` | `25` | `0` | yes | low | low | "role count changed to 0." | (same) | n/a — decrease, not an increase over threshold | PASS | new `test_org_role_count_real_zero_still_low_not_error` | Confirms a genuine `0` doesn't error and correctly isn't treated as a threshold-crossing increase |
| K5. Org permission count real zero from over-threshold | `clerk_organization_settings` | `permission_count` | `60` | `0` | yes | low | low | "permission count changed to 0." | (same) | n/a | PASS | new `test_org_permission_count_real_zero_from_over_threshold_is_low` | Confirms real-zero handling doesn't regress after the `_int_or_none()` defensive rewrite |
| K6. Org permission count increases while already broad | `clerk_organization_settings` | `permission_count` | `60` | `70` | yes | medium | medium | "permission count increased to 70, exceeding the review threshold." | (same) | `clerk_org_high_permission_count` (medium, fires on every snapshot while `permission_count > 50`) — matches (guard caveat applies) | PASS | existing `test_organization_permission_count_increase_while_already_broad_is_medium` | — |
| K7. Org permission count decreases while still broad | `clerk_organization_settings` | `permission_count` | `70` | `60` | yes | low | low (improvement) | "permission count changed to 60." | (same) | n/a | PASS | existing `test_organization_permission_count_decrease_while_still_broad_is_low` | — |
| L1. Unknown/missing sweep (booleans, 15 fields across 8 record types) | multiple | see broader sweep test | truthy | `None` | yes | low | low | all say "...is now unknown or missing" (never "disabled"/"removed") | (same) | n/a | PASS | new `test_broader_unknown_transition_sweep_never_produces_high_or_overstated_medium` | Extends original 6-field sweep to 21 fields covering every high/medium-capable branch |
| L2. Unknown/missing sweep (counts) | `clerk_organization_settings` | `permission_count`, `role_count` | numeric | `None` | yes | low | low | "...is now unknown or missing," never "dropped to zero" | (same) | n/a | PASS | existing `test_count_unknown_not_treated_as_zero` | — |
| L3. Real zero still triggers intended classification (org role/permission) | `clerk_organization_settings` | `role_count`, `permission_count` | numeric (over threshold) | `0` | yes | low (decrease direction) | low | see K4/K5 | (same) | n/a | PASS | new K4/K5 tests | Confirms the unknown-handling defensive design didn't accidentally suppress genuine zero-detection |
| M. Generic fallback never used for security-sensitive fields | 10 representative high/medium-capable fields across 8 record types | see test | truthy | falsy | yes | (field-specific severities) | (same) | none use the bare `"...configuration field '...' changed."` fallback | (same) | n/a | PASS | new `test_generic_fallback_never_used_for_security_sensitive_fields` | Confirms MFA/SSL/verification/session/webhook-signing/domain/JWT/org-admin fields all resolve through named branches |
| N. Copy safety | all record types | all fields | — | — | — | — | — | no breach/compromise/attacker/leak/unauthorized-access/account-takeover/credential-exposed/token-exposed/secret-exposed/data-exposed language anywhere | (same) | — | PASS | existing `test_no_forbidden_wording_in_reasons`, re-verified after this pass's edits | — |

## Tracked-fields vs. classifier-branch comparison

Verified programmatically: parsed `_CLERK_TRACKED_FIELDS_BY_TYPE` from
`diff_service.py` and every `if fp == "..."` / `if fp in (...)` branch
from each of the 10 `_classify_*_change` functions in `risk_rules/clerk.py`,
then diffed the two sets per record type.

**Before this pass**: `clerk_instance_settings.sign_in_enabled` was
tracked but not present in any classifier branch (accidental fall-through
to the bare generic fallback).

**After this pass**: zero tracked fields fall through accidentally across
all 10 record types — every tracked field is handled by either a
field-specific branch or an explicit generic group.

**Classifier branches referring to fields not emitted by the
connector/schema:** none found — every branch was cross-checked against
both `_CLERK_TRACKED_FIELDS_BY_TYPE` and `clerk_schema.py`'s `TypedDict`
definitions.

**Classifier branches referring to stale field names:** none — this is a
newly-built module (this session), so there was no legacy field-name
drift to inherit.

**Fields with similar names that could be confused:** `mfa_enabled` vs.
`mfa_required` co-exist on `clerk_auth_strategy` (and separately,
`mfa_enabled` only on `clerk_instance_settings`, `mfa_required` only on
`clerk_application`). Each branch names its own field explicitly in the
emitted wording ("no longer enabled" vs. "no longer required"), so the
two remain distinguishable in the reason text despite sharing a record
type in the auth-strategy case. No confusion found between
`session_lifetime_category` (tracked on both `clerk_instance_settings`
and `clerk_session_policy`) either — both use the same category-set logic
and near-identical wording, which is intentional (the instance-level copy
exists because the instance record also tracks a redundant
`session_lifetime_category` field per the schema).

## Verification: no `int(value or 0)`-style coercion remains

```
grep -n "int(.*or 0)\|_int_pair" backend/app/services/risk_rules/clerk.py
```
→ no matches. Every count-based branch (`redirect_url_count`,
`allowed_origin_count`, `oauth_provider_count`, `claims_count`,
`event_count`, `role_count`, `permission_count`) uses `_int_or_none()` via
either the direct helper or `_crossed_threshold_increase()`, confirmed
both before and after this pass's edits.

## Verification: threshold-increase-while-already-over-threshold handled correctly (no Datadog-style bug)

`_crossed_threshold_increase(prev_v, new_v, threshold)` returns
`n_new > threshold and n_new > (n_old or 0)` — any increase while over
the threshold, not a crossing-only check (`(n_old or 0) <= threshold`).
Confirmed via new tests for every threshold field:
- `redirect_url_count` 15→20 (threshold 10): low, review-worthy (existing test)
- `claims_count` 20→25 (threshold 15): low, review-worthy (new H5/J4-style test)
- `permission_count` 60→70 (threshold 50): medium (existing test)
- `permission_count` decrease 70→60: low/improvement (existing test)
- `permission_count` real zero from over-threshold, 60→0: low, no error (new test)
- `role_count` real zero, 25→0: low, no error (new test)

No PagerDuty-style or Datadog-style regression found in this module —
both defensive patterns were applied from the start during the detection
QA pass, and this classification-QA pass adds tests that lock them in
rather than finding and fixing new instances of either bug.

## Mock-shape (`old_value`/`prev_value`/`previous_value`/`prior_value`) verification

```
grep -n "old_value\|previous_value\|prior_value\|prev_value" backend/app/services/risk_rules/clerk.py
```
→ all matches are `_get(change, "prev_value")` — production code was
already clean, no `old_value`/`previous_value`/`prior_value` usage found.

```
grep -rn "old_value\|previous_value\|prior_value" backend/tests/test_milestone83a_clerk_drift_provider_foundation.py
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

### Why `clerk_auth_strategy.mfa_enabled: True → False` is `high` with no direct standalone Finding match

Same pattern documented in the detection-QA report: `_eval_auth_strategy`
only fires `clerk_auth_strategy_mfa_not_required` (medium) on
`mfa_enabled AND NOT mfa_required` — there is no dedicated Finding for
`mfa_enabled=False` alone at this record type. The Change classifier
rates this transition `high` for consistency with the instance-level
`clerk_instance_mfa_disabled` rule, since losing MFA *capability*
entirely is a strict superset of "enabled but not required." A
Change-only signal, re-confirmed correct in this pass.

### Why organization sub-field severities don't check the `organizations_enabled` guard

`_eval_organization_settings` returns `[]` immediately if
`organizations_enabled` is `False` — no org Finding of any kind fires in
that state. The Change classifier's org sub-field branches
(`admin_role_present`, `verified_domains_required`, `role_count`,
`permission_count`, `invitation_enabled`) have no equivalent guard,
because a single-field Change dict carries only `field_path`/`prev_value`/
`new_value`/`provider_metadata` — it cannot see the sibling
`organizations_enabled` value from the same snapshot. This means a Change
on, say, `verified_domains_required` will still be classified `medium`
even at a moment when organizations are globally disabled (and thus no
Finding would fire for that state). This is the same structural
limitation as every other combined-condition approximation documented in
this and prior providers' reports (GitLab, Terraform Cloud, Jira, Linear,
PagerDuty, Datadog) — not a defect introduced by this module, and not
fixable without passing full-record context into the Change classifier,
which no provider's classifier in this codebase does. Documented here
rather than "fixed."

### Why `password_enabled` and OAuth count transitions stay generic `low` rather than mirroring their combined Findings' severity

`clerk_instance_password_without_mfa` (high), `clerk_application_password_without_mfa`
(medium), `clerk_auth_strategy_password_without_mfa` (medium), and
`clerk_application_oauth_without_mfa` (medium) all require a combination
of two fields. Rather than duplicate the elevated severity onto the
lower-signal field (`password_enabled`/`oauth_provider_count`), this
module concentrates the elevated severity on the MFA-side field
transition, which is already the primary signal in every one of these
combined rules and already fires at the matching severity on its own
(A1/A4/A6/A7 above). Re-confirmed correct in this pass — not a gap.

## Totals

| Metric | Count |
|---|---|
| Total classification cases reviewed | 52 (A1–N, all rows above, counting sub-cases) |
| PASS | 51 |
| FAIL | 0 |
| GAP → FIXED (sign_in_enabled fall-through) | 1 (D4) |
| N/A (not modeled, correctly absent) | 1 (C — password policy) |
| New Security Finding rules added | 0 (classification-layer pass only) |
| Previously detected changes now confirmed misclassified before this pass | 0 (the one gap found was a wording/traceability gap, not a severity misclassification — the bare fallback was already `low`, matching what a grouped branch returns) |
| Mock-shape (`old_value`-style) bugs found | 0 |
| PagerDuty-style unknown-treated-as-zero bug found | 0 — confirmed the module was already defensive from the start |
| Datadog-style crossing-only threshold bug found | 0 — confirmed `_crossed_threshold_increase()` was already "any increase while over threshold" from the start |
| MFA/verification/password/session/OAuth-SAML/webhook/domain/JWT/org classifications aligned with Security Findings | Yes — all severities cross-checked against the 40-rule severity table with zero mismatches; combined-condition and guard-clause disagreements documented as accepted structural limitations, not defects |

## Fixes made

1. **`backend/app/services/risk_rules/clerk.py`**
   - `_classify_instance_settings_change`: added `sign_in_enabled` to the
     boolean generic-fields tuple (previously fell through to the bare
     `"configuration field '...' changed."` fallback).
2. **`backend/tests/test_milestone83a_clerk_drift_provider_foundation.py`**
   — added a new `TestClerkChangeClassificationQA` class (27 tests):
   the `sign_in_enabled` fix regression test, verification-posture tests
   (email/phone), SAML enable/disable/restore tests for both `clerk_application`
   and `clerk_auth_strategy`, JWT template audience/lifetime/claims-count
   tests, domain verified/SSL restoration tests, organization admin-role/
   verified-domains/count tests (including two real-zero-from-over-threshold
   tests), session token-rotation/reverification/lifetime restoration
   tests, redirect-URL/webhook restoration tests, a 21-field broadened
   unknown-transition sweep, and a test confirming no security-sensitive
   field ever resolves through the bare generic fallback.
3. **`backend/tests/reports/clerk_change_classification_matrix.md`** —
   this report.

No changes were made to `security_rules/clerk.py`, `diff_service.py`'s
tracked-fields dict (only the classifier's handling of an already-tracked
field changed), the four backend registries, or the frontend catalog.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone83a_clerk_drift_provider_foundation.py -q
# 134 passed (was 109 after 2be46b5)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "clerk and risk"
# 131 passed, 2 skipped, 17048 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "clerk and diff"
# 10 passed, 17171 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "clerk"
# 918 passed, 4 skipped, 16259 deselected (was 893 passed, 4 skipped after 2be46b5)
# Note: this filter also matches the unrelated pre-existing
# test_milestone21.py::TestClerkTokenValidation suite (Clerk end-user JWT
# validation for the app's own auth) — expected/harmless overlap.

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*clerk* -q
# 897 passed, 4 skipped
```

No frontend files were touched in this pass — no new Security Finding
rule was added or changed, only Change-classification logic and tests —
so `npx tsc --noEmit` was not run.
