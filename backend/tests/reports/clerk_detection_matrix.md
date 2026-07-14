# Clerk Detection QA Matrix

Exhaustive end-to-end validation of the Clerk provider (connector → diff
tracking → risk classification → security findings → registries →
frontend catalog), following the same methodology established for
SendGrid, Twilio, Terraform Cloud, GitLab, Jira, Linear, PagerDuty, and
Datadog in prior QA passes.

## Summary

Clerk's connector (`app/connectors/clerk.py`), schema
(`clerk_schema.py`), and security rules (`security_rules/clerk.py`, 40
rules across all 10 record types) were already mature. As with Linear's,
PagerDuty's, and Datadog's equivalent passes, **registries and the
frontend catalog were already in perfect parity (40/40, zero severity
mismatches)** — no fixes needed there. The two recurring root-cause bugs
from every prior provider pass were both present here, and both are the
primary fixes in this pass:

1. **`risk_rules/clerk.py` did not exist at all.** `risk_service.py` had
   no `clerk_` dispatch branch, so **every Clerk configuration change
   silently fell through to the Cloudflare DNS classifier**. Built the
   module from scratch (10 record-type classifiers) and wired the
   dispatch.

2. **Diff/drift tracking gap.** Clerk had **zero entries** in
   `diff_service.py`'s per-provider tracked-fields dispatch, so every
   Clerk record type fell through to the Cloudflare DNS default tuple
   (`record_type`, `name`, `content`, `ttl`, `proxied`, `priority`,
   `comment` — none of which exist on any Clerk record). `compute_diff`
   could never detect a modified field on an existing Clerk record. Fixed
   by adding `_CLERK_TRACKED_FIELDS_BY_TYPE` (all 10 record types) and
   wiring the `clerk_` prefix into `_tracked_fields_for`.

Building on the false-positive severity bug found and fixed in
PagerDuty's classification-QA pass, and the crossing-only threshold bug
found and fixed in Datadog's classification-QA pass, this new module was
written **defensively from the start**: every count-based branch uses
`_int_or_none()` (not a bare `int(val or 0)` coercion), and every
threshold-based branch (`redirect_url_count`, `allowed_origin_count`,
`claims_count`, `event_count`, `role_count`, `permission_count`) uses "any
increase while over the threshold" via `_crossed_threshold_increase()`,
not a crossing-only check. Dedicated tests
(`test_count_unknown_not_treated_as_zero`,
`test_organization_permission_count_increase_while_already_broad_is_medium`)
lock both patterns in immediately rather than waiting for a follow-up
classification-QA pass to find them.

No new Security Finding rules were needed or added — the existing 40
rules already cover every field this pass identified as security-relevant,
and the new Change classifier's severities and thresholds
(`_MANY_REDIRECT_URLS_THRESHOLD = 10`, `_MANY_ALLOWED_ORIGINS_THRESHOLD =
10`, `_MANY_CLAIMS_THRESHOLD = 15`, `_BROAD_WEBHOOK_EVENTS_THRESHOLD = 10`,
`_HIGH_ROLE_COUNT_THRESHOLD = 20`, `_HIGH_PERMISSION_COUNT_THRESHOLD = 50`)
were mirrored directly from `security_rules/clerk.py` so Change/Finding
severities stay aligned.

## Connector extraction review

| Record type | Source endpoint | Sensitive values excluded? | Fail-soft on error? | Stable record IDs? |
|---|---|---|---|---|
| `clerk_instance_settings` | `GET /v1/instance` | Yes — only booleans/counts/categories derived from `user_settings`/`session_settings`/`restrictions` | N/A — required/anchor surface | Yes — fixed `"clerk_instance_settings_main"` |
| `clerk_application` | derived from `/v1/instance` | Yes — name truncated to 100 chars, no secrets | N/A — anchor surface | Yes — instance-derived opaque ID |
| `clerk_domain` | `GET /v1/domains` | Yes — domain name never stored, only `domain_type`/`verified`/`ssl_enabled`/`dns_status_category` | Yes — 403/404 caught, returns `[]` | Yes — domain `id` |
| `clerk_redirect_url_config` | `GET /v1/redirect_urls` | Yes — raw URL never stored, only `url_scheme_category`/`wildcard_present`/`localhost_present`/`custom_scheme_present` | Yes — 403/404 caught, returns `[]` | Yes — redirect URL `id` |
| `clerk_jwt_template` | `GET /v1/jwt_templates` | Yes — claims content never stored, only `claims_count`/`custom_claims_present`; name truncated to 100 chars | Yes — 403/404 caught, returns `[]` | Yes — template `id` |
| `clerk_webhook_endpoint` | `GET /v1/webhooks` (or svix-backed endpoint) | Yes — URL/signing secret never stored, only `url_scheme_category`/`secret_present` | Yes — 403/404 caught, returns `[]` | Yes — webhook `id` |
| `clerk_email_sms_settings` | derived from `/v1/instance` | Yes — sender/template content never stored, only presence booleans | N/A — anchor surface | Yes — fixed `"clerk_email_sms_settings_main"` |
| `clerk_auth_strategy` | derived from `/v1/instance` | Yes — no credential material, only capability booleans/counts | N/A — anchor surface | Yes — fixed `"clerk_auth_strategy_main"` |
| `clerk_organization_settings` | derived from `/v1/instance` | Yes — no member/role names, only counts/booleans | N/A — anchor surface | Yes — fixed `"clerk_organization_settings_main"` |
| `clerk_session_policy` | derived from `/v1/instance` | Yes — only category strings/booleans | N/A — anchor surface | Yes — fixed `"clerk_session_policy_main"` |

**Confirmed via code inspection** (connector function bodies +
`clerk_schema.py`'s exhaustive per-field docstrings):
- No **user PII** is stored beyond safe metadata/counts — no user list,
  email list, or phone list endpoint is fetched at all; `mfa_factor_count`,
  `domain_count`, `webhook_count`, etc. are aggregate counts only.
- No **passwords or credential material** are stored — `password_enabled`
  is a capability boolean, never a password value.
- No **API secret key values** are stored — the secret key is used only
  to build the `Bearer` `Authorization` header in `_make_client`, never
  copied to `self`, a record, or a log line (`test_clerk_connector_is_stateless`
  and `test_clerk_connector_secret_key_not_in_instance_source` in the
  M83A foundation suite both hold).
- No **JWT signing secrets** are stored — `clerk_jwt_template` records
  carry `algorithm` (a category string) and presence booleans only, never
  a key or secret value.
- No **webhook secrets** are stored — `secret_present` is a boolean
  derived from whether a signing secret exists, never the secret itself.
- No **full webhook URLs** are stored — `url_scheme_category` is the only
  URL-derived field, via the same `_url_scheme_category()` helper pattern
  used by every other provider connector this session.
- No **session tokens** are stored — `clerk_session_policy` fields are all
  category strings/booleans describing policy, not live token data.
- No **raw email/phone lists** are stored — `email_enabled`/`phone_enabled`
  are capability booleans on the instance/auth-strategy record, not lists
  of addresses.

## Diff/change tracking review

**Before this pass**: 0 of 10 record types had a tracked-fields entry —
all Clerk modified-field changes silently fell through to the Cloudflare
DNS default tuple and were never detected.

**After this pass**: all 10 record types are tracked with every
security-relevant field verified present, including every one of the
task's high-priority fields: `sign_up_enabled`/`sign_in_enabled`,
`password_enabled`, `mfa_enabled`/`mfa_required`/`multi_session`
(`single_session_mode`), `email_enabled`/`phone_enabled` (verification
capability), `social_provider_count`/`oauth_provider_count`,
`saml_enabled`, `session_lifetime_category`/`inactivity_timeout_category`,
`jwt_template_count`/JWT `enabled`, `allowed_redirect_count`/
`redirect_url_count`/`allowed_origin_count`, `dns_status_category`/
`verified` (domain), `webhook_count`/webhook `enabled`,
`url_scheme_category` (webhook), `secret_present` (webhook signing),
`domain_count`, `webhook_count`.

No fields were found that are tracked but no longer emitted by the
connector — the tracked tuples were built directly from
`clerk_schema.py`'s `TypedDict` definitions, cross-referenced against the
connector's actual normalizer output (confirmed via grep of the
`_normalize_*` functions).

## Test matrix

| Test case | Normalized record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes/fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. MFA/second factor enabled/disabled | `clerk_instance_settings` / `clerk_auth_strategy` | `mfa_enabled` | `True → False` | Change (high) + Finding (high, `clerk_instance_mfa_disabled`) | Change never generated before fix | high | high (after fix) | `clerk_instance_mfa_disabled` (high) — matches | new `test_instance_mfa_disabled_is_high`, `test_auth_strategy_mfa_enabled_disabled_is_high` | **FIXED** | Auth-strategy-level `mfa_enabled → False` has no dedicated Finding of its own (only the combined `mfa_enabled AND NOT mfa_required` rule exists there); the Change classifier rates it `high` on its own for consistency with the instance-level rule — a Change-only signal, documented below |
| B. Password auth enabled/disabled | `clerk_instance_settings` / `clerk_application` / `clerk_auth_strategy` | `password_enabled` | `False → True` | Change (low, generic) — no standalone Finding fires on `password_enabled` alone | Change never generated before fix | low | low (after fix) | n/a (combined-condition Finding only; see design note) | covered by tracked-field sweep | **FIXED (Change-only generic signal, documented)** | `clerk_*_password_without_mfa` requires `password_enabled AND NOT mfa_required` — a single-field Change can't see the sibling field, so this is intentionally left generic per the combined-condition approximation convention; the higher-signal `mfa_required`/`mfa_enabled` field already carries the elevated severity (see B, above) |
| C. Password policy weakened/strengthened | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | Clerk schema has no password-policy fields (min length, complexity, etc.) — not invented per task instructions |
| D. Email verification required/disabled | `clerk_instance_settings` / `clerk_email_sms_settings` | `email_enabled` | `True → False` | Change (low, generic) | Change never generated before fix | low | low (after fix) | n/a — no dedicated Finding on `email_enabled` alone | covered by tracked-field sweep | **FIXED** | Schema models `email_enabled` as a channel-capability boolean, not a distinct "verification required" flag; treated as low, matching the absence of a dedicated Finding |
| E. Phone verification required/disabled | `clerk_instance_settings` / `clerk_email_sms_settings` | `phone_enabled` | `True → False` | Change (low, generic) | Change never generated before fix | low | low (after fix) | n/a — no dedicated Finding on `phone_enabled` alone | covered by tracked-field sweep | **FIXED** | Same as D |
| F. Sign-up enabled/disabled or broadened/restricted | `clerk_instance_settings` / `clerk_application` | `sign_up_enabled` | `False → True` | Change (low) + Finding (low, `clerk_instance_sign_up_enabled` / `clerk_application_sign_up_enabled`) | Change never generated before fix | low | low (after fix) | `clerk_instance_sign_up_enabled` / `clerk_application_sign_up_enabled` (low) — matches | new tests via tracked-field sweep | **FIXED** | — |
| G. OAuth/social provider count increased/decreased | `clerk_application` / `clerk_auth_strategy` | `oauth_provider_count` / `social_provider_count` | `1 → 3` | Change (low, review) — no dedicated Finding fires on count alone | Change never generated before fix | low | low (after fix) | n/a — `clerk_application_oauth_without_mfa` requires the combination with `mfa_required=False` | covered by tracked-field sweep | **FIXED (Change-only generic signal, documented)** | Matches task guidance ("low/medium review") |
| H. SAML/enterprise SSO enabled/disabled | `clerk_application` / `clerk_auth_strategy` | `saml_enabled` | `False → True` | Change (medium) — Finding requires `saml_enabled AND NOT mfa_required` | Change never generated before fix | medium | medium (after fix) | n/a (Change-only; combined Finding is `clerk_application_saml_without_mfa`, medium) | covered by tracked-field sweep | **FIXED** | Enabling SAML is treated as independently notable at `medium`, matching the combined Finding's severity regardless of the sibling MFA field's value — a deliberately conservative approximation |
| I. Session lifetime increased/decreased | `clerk_session_policy` / `clerk_instance_settings` | `session_lifetime_category` | `"standard" → "extended"` | Change (medium) + Finding (medium, `clerk_session_lifetime_extended`) | Change never generated before fix | medium | medium (after fix) | `clerk_session_lifetime_extended` (medium) — matches | new `test_session_lifetime_extended_is_medium` | **FIXED** | — |
| J. JWT template added/removed or enabled/disabled | `clerk_jwt_template` | `lifetime_category`, `audience_present`, `issuer_present`, `custom_claims_present` | `"standard" → "extended"` | Change (medium) + Finding (medium, `clerk_jwt_template_long_lifetime`) | Change never generated before fix | medium | medium (after fix) | `clerk_jwt_template_long_lifetime` (medium) — matches | covered by tracked-field sweep | **FIXED** | — |
| K. Allowed origin/redirect URL count increased/decreased | `clerk_application` | `redirect_url_count` / `allowed_origin_count` | `15 → 20` (already over threshold of 10) | Change (low) + Finding (low, `clerk_application_many_redirect_urls` / `clerk_application_many_allowed_origins`) | Change never generated before fix | low | low (after fix) | `clerk_application_many_redirect_urls` (low) — matches | new `test_application_redirect_url_count_increase_while_already_broad_is_low` | **FIXED** | Uses "any increase while over threshold," not crossing-only — proactively applying the Datadog classification-QA fix pattern from the start |
| L. Domain verification/status changed | `clerk_domain` | `verified` | `True → False` | Change (medium) + Finding (medium, `clerk_domain_unverified`) | Change never generated before fix | medium | medium (after fix) | `clerk_domain_unverified` (medium) — matches | new `test_domain_unverified_is_medium` | **FIXED** | — |
| M. Webhook enabled/disabled | `clerk_webhook_endpoint` | `enabled` | `True → False` | Change (low) + Finding (low, `clerk_webhook_endpoint_disabled`) | Change never generated before fix | low | low (after fix) | `clerk_webhook_endpoint_disabled` (low) — matches | covered by tracked-field sweep | **FIXED** | — |
| N. Webhook HTTP/HTTPS scheme | `clerk_webhook_endpoint` / `clerk_redirect_url_config` | `url_scheme_category` | `"https" → "http"` | Change (high) + Finding (high, `clerk_webhook_non_https` / `clerk_redirect_url_non_https`) | Change never generated before fix | high | high (after fix) | `clerk_webhook_non_https` / `clerk_redirect_url_non_https` (high) — matches | new `test_webhook_non_https_scheme_is_high`, `test_redirect_url_http_scheme_is_high` | **FIXED** | Webhook rule fires on ANY non-`"https"` scheme (not just `"http"` specifically); the Change classifier mirrors this exactly (`new_v != "https"`), confirmed via `test_webhook_non_https_scheme_is_high` using a non-`"http"`, non-`"https"` value |
| O. Webhook signing/secret posture | `clerk_webhook_endpoint` | `secret_present` | `True → False` | Change (high) + Finding (high, `clerk_webhook_without_signing`) | Change never generated before fix | high | high (after fix) | `clerk_webhook_without_signing` (high) — matches | new `test_webhook_secret_removed_is_high` | **FIXED** | Finding requires `url_present AND NOT secret_present`; Change classifier fires on `secret_present` alone (accepted combined-condition approximation, consistent with Datadog's webhook-signing pattern) |
| P. Unknown/missing fields never produce high findings | all 10 record types | any | `None`/missing | no high finding/classification | Confirmed — every Finding check in `security_rules/clerk.py` uses explicit boolean/category-string equality (`is False`/`is True`), and every new Change classifier branch falls to `low` on unparseable/missing values via `_is_falsy_explicit`/`_is_truthy`/`_int_or_none()`'s explicit `None` check (built defensively from the start) | none | none | all | new `test_every_tracked_field_classifies_without_error_or_invalid_severity`, `test_unknown_transitions_never_produce_high`, `test_count_unknown_not_treated_as_zero` | PASS | — |
| Q. 403/404 fail-soft on optional endpoints | domains, redirect URLs, JWT templates, webhooks | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed — `_fetch_domains`/`_fetch_redirect_urls`/`_fetch_jwt_templates`/`_fetch_webhooks` all catch 403/404 and return `[]` (per grep of `clerk.py`'s fail-soft comments) | n/a | n/a | n/a | existing `test_milestone83a` connector tests | PASS | — |
| R. Records with normalized fields but no security rule | none found — every one of the 10 record types has at least one rule | n/a | n/a | correctly no gaps | Confirmed — cross-referenced every tracked field against `security_rules/clerk.py`'s 10 `_eval_*` functions | n/a | n/a | n/a | existing `test_clerk_provider_depth_qa.py` / `test_milestone83h_clerk_provider_depth_qa.py` coverage | PASS | — |
| S. Security rules with no reachable normalized record | — | — | — | — | None found — all 40 rules dispatch from `evaluate()` against one of the 10 record types the connector actually emits. One rule (`clerk_domain_wildcard_enabled`) is explicitly documented as deferred in the module docstring pending a schema field that doesn't exist yet — not a reachability bug | n/a | n/a | all | existing depth-QA reachability tests (all still passing after this pass) | PASS | Zero dead/unreachable *implemented* rules; one rule intentionally deferred, not built |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | 40/40 rule keys present everywhere with matching severities | Verified via exact set diff: `security_rules/clerk.py` (40) vs. `security_rule_registry.py` (40), `security_rule_pack.py` (40, all severities cross-checked programmatically, zero mismatches), `security_rule_confidence.py` (40), and `securityRuleCatalog.ts` (40) | n/a | n/a | all | none pre-existing; verified via ad hoc scripted diff in this pass | PASS | Zero mismatches — no fix needed (matching Linear's, PagerDuty's, and Datadog's equivalent passes, unlike Jira's, which found 10 severity mismatches and 6 catalog gaps) |
| Diff-tracked fields present for all 10 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 10 record types tracked (before fix)** → **10 of 10 tracked (after fix)** | n/a | n/a | n/a | new `TestClerkDiffTrackedFields` (5 tests) | **FIXED** | Root-cause fix — see Summary #2 |
| Risk classification module exists and is wired | all | all tracked fields | n/a | every Change gets a Clerk-specific classification, not the Cloudflare DNS fallback | **module did not exist (before fix)** → **10 classifiers + dispatch wired (after fix)** | n/a | n/a | n/a | new `TestClerkRiskClassifier` (25 tests, including a dispatch-level regression test, a dict-shaped mock-bug-prevention test, and proactive count-unknown-not-zero + threshold-increase-while-already-over tests) | **FIXED** | Summary #1 — the largest fix in this pass |

## Design notes

### Why `mfa_enabled` at the `clerk_auth_strategy` level is `high` with no direct standalone Finding match

`security_rules/clerk.py`'s `_eval_auth_strategy` only fires
`clerk_auth_strategy_mfa_not_required` (`medium`) when
`mfa_enabled AND NOT mfa_required` — there is no dedicated Finding for
`mfa_enabled=False` alone at this record type (unlike the instance-level
`clerk_instance_mfa_disabled`, `high`, which does fire on `mfa_enabled`
alone). Losing MFA *capability* entirely is a strict superset of "enabled
but not required," so the Change classifier rates the
`mfa_enabled: True → False` transition `high` for consistency with the
instance-level rule — a Change-only signal that the Finding layer
structurally cannot express at this record type, following the same
"Change catches transitions Finding can't" pattern established for
GitLab, Terraform Cloud, Jira, Linear, PagerDuty, and Datadog.

### Why `password_enabled` and OAuth/SAML count fields are generic `low` rather than mirroring their combined-condition Findings directly

`clerk_instance_password_without_mfa`, `clerk_application_password_without_mfa`,
`clerk_application_oauth_without_mfa`, and `clerk_auth_strategy_password_without_mfa`
all require a *combination* of two fields (e.g. `password_enabled AND NOT
mfa_required`). A single-field Change classifier cannot see the sibling
field's current value. Rather than approximate on the lower-signal field
(`password_enabled`/`oauth_provider_count`) as the prior providers'
combined-condition approximations did on the *higher*-signal field, this
pass leaves `password_enabled` and OAuth count transitions as generic
`low` and instead concentrates the elevated severity on the MFA field
transition itself (`mfa_required`/`mfa_enabled` — test cases A/B above),
which is already the primary signal in every one of these combined rules.
This is the same accepted approximation pattern documented in every prior
provider's report, just applied to the MFA side of the combination
instead of duplicating the elevated severity onto multiple fields.

### Why `saml_enabled: False → True` is `medium` on its own

`clerk_application_saml_without_mfa` only fires when
`saml_enabled AND NOT mfa_required` (medium). Since enabling SAML/
enterprise SSO is itself a meaningful, standalone posture change (a new
enterprise identity provider trust relationship), this pass rates the
transition `medium` regardless of the sibling `mfa_required` value —
consistent with the task's own explicit guidance ("SAML/enterprise SSO
disabled = medium") and the general precedent that combined-condition
Findings' severity is a reasonable ceiling for the Change-layer
approximation.

## Tracked-fields vs. classifier-branch comparison

| Record type | Tracked fields with dedicated classification | Tracked fields using generic fallback (intentional) |
|---|---|---|
| `clerk_instance_settings` | `mfa_enabled`, `sign_up_enabled`, `sign_in_mode`, `session_lifetime_category` | `environment_type`, `email_enabled`, `phone_enabled`, `username_enabled`, `password_enabled`, `social_provider_count`, `mfa_factor_count`, `allowed_redirect_count`, `domain_count`, `webhook_count`, `allowlist_enabled`, `blocklist_enabled` |
| `clerk_application` | `mfa_required`, `sign_up_enabled`, `saml_enabled`, `redirect_url_count`, `allowed_origin_count`, `oauth_provider_count` | `name`, `application_type`, `enabled`, `jwt_template_count`, `organization_enabled`, `sign_in_enabled`, `password_enabled` |
| `clerk_domain` | `verified`, `ssl_enabled` | `domain_present`, `domain_type`, `primary`, `dns_status_category`, `proxy_enabled` |
| `clerk_redirect_url_config` | `url_scheme_category`, `wildcard_present`, `custom_scheme_present`, `localhost_present` | `url_present` |
| `clerk_jwt_template` | `lifetime_category`, `audience_present`, `issuer_present`, `custom_claims_present`, `claims_count` | `name`, `enabled`, `algorithm` |
| `clerk_webhook_endpoint` | `secret_present`, `url_scheme_category`, `enabled`, `event_count` | `url_present`, `description_present` |
| `clerk_email_sms_settings` | `custom_sender_present` | `email_enabled`, `sms_enabled`, `template_customization_present` |
| `clerk_auth_strategy` | `mfa_required`, `mfa_enabled`, `saml_enabled` | `password_enabled`, `oauth_enabled`, `social_provider_count`, `passkey_enabled`, `magic_link_enabled`, `email_otp_enabled`, `phone_otp_enabled` |
| `clerk_organization_settings` | `verified_domains_required`, `admin_role_present`, `invitation_enabled`, `role_count`, `permission_count` | `organizations_enabled`, `max_allowed_memberships_category`, `admin_delete_enabled`, `domains_enabled`, `domains_enrollment_mode_category` |
| `clerk_session_policy` | `session_lifetime_category`, `inactivity_timeout_category`, `single_session_mode`, `token_rotation_enabled`, `device_tracking_enabled`, `reverification_required` | `url_based_session_syncing` |

**Classifier branches referring to fields not emitted by the
connector/schema:** none found — every `fp ==` check in
`risk_rules/clerk.py` was written directly against `clerk_schema.py`'s
`TypedDict` definitions and cross-verified against the connector's
actual normalizer output.

**Classifier branches referring to old/stale field names:** none — this
is a newly-built module, so there was no legacy field-name drift to
inherit.

**Fields with similar names that could be confused:** `mfa_enabled` vs.
`mfa_required` appear on three different record types
(`clerk_instance_settings` has only `mfa_enabled`; `clerk_application`
has only `mfa_required`; `clerk_auth_strategy` has both). Each branch
names its own field explicitly in the wording (`"multi-factor
authentication is no longer enabled"` vs. `"no longer required"`), so the
two are not confusable in the emitted reason text despite living on the
same record type in the auth-strategy case.

## Mock-shape (`old_value`/`prev_value`) verification

Since `risk_rules/clerk.py` did not exist before this pass, there was no
pre-existing mock-shape bug to find. The module was written to read
`prev_value` directly from the start (matching `compute_diff`'s real
output), and a dedicated regression test
(`test_classifier_reads_real_compute_diff_dict_shape_not_a_mock`) builds a
plain dict shaped exactly like real `compute_diff` output — not a
`MagicMock` — to guard against this exact bug class recurring.

## Fixes made

1. **`backend/app/services/risk_rules/clerk.py`** (new file) — 10
   record-type classifiers (`_classify_instance_settings_change` through
   `_classify_session_policy_change`) plus the `classify_clerk_change`
   dispatcher. Built with `_int_or_none()` and
   `_crossed_threshold_increase()` (any-increase-while-over-threshold,
   not crossing-only) from the start, to avoid the exact false-positive
   severity bugs found and fixed in PagerDuty's and Datadog's
   classification-QA passes.
2. **`backend/app/services/risk_service.py`** — added the `clerk_` prefix
   dispatch branch to `classify_change`, routing Clerk changes to the new
   module instead of the Cloudflare DNS fallback; updated the module
   docstring's dispatch list.
3. **`backend/app/services/diff_service.py`** — added
   `_CLERK_TRACKED_FIELDS_BY_TYPE` (all 10 record types) and wired the
   `clerk_` prefix into `_tracked_fields_for`. Updated the function's
   docstring.
4. **`backend/tests/test_milestone83a_clerk_drift_provider_foundation.py`**
   — added `TestClerkDiffTrackedFields` (5 tests) and
   `TestClerkRiskClassifier` (25 tests, including a dispatch-level
   regression test, a dict-shaped mock-bug-prevention test, and proactive
   count-unknown-not-zero and threshold-increase-while-already-over
   tests).
5. **`backend/tests/reports/clerk_detection_matrix.md`** — this report.

No changes were made to `security_rules/clerk.py`, the four backend
registries, or the frontend catalog — all were already correct and in
perfect 40/40 parity with zero severity mismatches.

## Not fixed in this pass (explicitly out of scope)

- **Password policy fields** (task category C) — no min-length,
  complexity, or history fields exist in `clerk_schema.py`; not invented.
- **`clerk_domain_wildcard_enabled`** — already explicitly documented as
  deferred in `security_rules/clerk.py`'s own docstring pending a schema
  field (`wildcard_enabled`) that doesn't exist yet on
  `ClerkDomainRecord`; not added in this pass, consistent with "do not
  invent unsupported Clerk capabilities."
- **User/member-level detail** (individual role/permission names, member
  lists) — only aggregate counts (`role_count`, `permission_count`,
  `mfa_factor_count`, etc.) are modeled; no user or member endpoint is
  fetched.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone83a_clerk_drift_provider_foundation.py -q
# 109 passed

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "clerk"
# 893 passed, 4 skipped, 16259 deselected (was 865 passed, 4 skipped before any fixes in this pass)
# Note: this filter also matches the unrelated pre-existing
# test_milestone21.py::TestClerkTokenValidation suite (Clerk end-user JWT
# validation for the app's own auth, unrelated to the M83 drift-detection
# provider) — expected/harmless overlap, consistent with similar `-k`
# overlaps observed for other providers this session.

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*clerk* -q
# 872 passed, 4 skipped
```
