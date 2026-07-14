# Auth0 Detection QA Matrix

Exhaustive end-to-end validation of the Auth0 provider (connector → diff
tracking → risk classification → security findings → registries →
frontend catalog), following the same methodology established for
SendGrid, Twilio, Terraform Cloud, GitLab, Jira, Linear, PagerDuty,
Datadog, and Clerk in prior QA passes.

## Summary

Auth0's connector (`app/connectors/auth0.py`), schema
(`auth0_schema.py`), and security rules (`security_rules/auth0.py`, 37
rules across all 8 record types) were already mature (built across M81A–
M81C). **Registries and the frontend catalog were already in perfect
parity (37/37, zero severity mismatches)** — no fixes needed there. The
two recurring root-cause bugs from every prior provider pass were both
present here, and both are the primary fixes in this pass — with one
notable twist not seen in prior providers:

1. **`risk_rules/auth0.py` did not exist at all.** `risk_service.py` had
   no `auth0_` dispatch branch, so **every Auth0 configuration change
   silently fell through to the Cloudflare DNS classifier**.

2. **Diff/drift tracking gap.** Auth0 had **zero entries** in
   `diff_service.py`'s per-provider tracked-fields dispatch, so every
   Auth0 record type fell through to the Cloudflare DNS default tuple.
   `compute_diff` could never detect a modified field on an existing
   Auth0 record.

**The twist**: unlike every prior provider, Auth0's own
`provider_capability_matrix_service.py` entry **already claims**
`drift_diff=True` and `drift_risk_classification=True` — and a
pre-existing test
(`test_capability_matrix_auth0_drift_only` in
`test_milestone81a_auth0_drift_provider_foundation.py`) asserts this with
a comment reading *"drift_risk_classification flipped on in M81B with the
core security rules."* That comment conflates two separate systems in
this codebase: `security_rules/auth0.py` (Security **Findings**,
current-state evaluation) was indeed built in M81B, but
`risk_rules/auth0.py` (Change **classification**, transition-based) was
never built. So this capability flag was **already asserted as True by a
passing test before this pass, while the underlying code path did not
exist** — the two root-cause fixes in this pass make that pre-existing
claim true for the first time, rather than introducing a new claim.

Building on the false-positive severity bug found and fixed in
PagerDuty's classification-QA pass and the crossing-only threshold bug
found and fixed in Datadog's classification-QA pass, this new module was
written **defensively from the start**: every count-based branch uses
`_int_or_none()` (not a bare `int(val or 0)` coercion), and every
threshold-based branch (`callbacks_count`, `allowed_origins_count`,
`web_origins_count`, `grant_types_count`) uses "any increase while over
the threshold," not a crossing-only check.

No new Security Finding rules were needed or added — the existing 37
rules already cover the large majority of what this pass identified as
security-relevant. Two genuine **Finding-layer coverage gaps** were found
(category S below: `auth0_connection.mfa_enabled` and
`auth0_resource_server.signing_alg` are both fetched and normalized but
have no dedicated Security Finding) — documented, not fixed, per the
task's instruction not to invent new rules beyond what this detection-QA
pass is scoped to fix (diff tracking + Change classification). The Change
classifier still applies sensible severities to these two already-fetched
fields, following this task's own explicit MFA/signing-algorithm
conventions.

## Connector extraction review

| Record type | Source endpoint | Sensitive values excluded? | Fail-soft on error? | Stable record IDs? |
|---|---|---|---|---|
| `auth0_tenant_settings` | `GET /api/v2/tenants/settings` | Yes — support_email reduced to domain-only; error pages, device flow, sandbox version, and all raw payload never stored | Yes — 403/404 caught, returns `[]` | Yes — fixed `"auth0_tenant_settings_main"` |
| `auth0_application` | `GET /api/v2/clients` (paginated, explicit `fields` allowlist excludes `client_secret`) | Yes — client_secret excluded at the API level via `fields`/`include_fields`; callback/logout/origin/web-origin URL lists reduced to counts + posture booleans, then discarded | Yes — 403/404 caught, returns `[]` | Yes — `client_id` |
| `auth0_connection` | `GET /api/v2/connections` (paginated, explicit `fields` allowlist) | Yes — `options` dict (credentials, passwords, social tokens, certs) read only transiently to derive `password_policy_category`/`mfa_enabled`, then discarded | Yes — 403/404 caught, returns `[]` | Yes — `connection_id` |
| `auth0_resource_server` | `GET /api/v2/resource-servers` (paginated, explicit `fields` allowlist) | Yes — `identifier` (audience URI) reduced to a presence boolean | Yes — 403/404 caught, returns `[]` | Yes — `resource_server_id` |
| `auth0_rule` | `GET /api/v2/rules` (paginated, explicit `fields` allowlist) | Yes — `script` reduced to presence boolean + length category | Yes — soft-failure surface, any exception caught in `fetch()` | Yes — `rule_id` |
| `auth0_action` | `GET /api/v2/actions/actions` | Yes — `code` reduced to presence boolean + length category; `secrets`/`dependencies` reduced to counts | Yes — soft-failure surface | Yes — `action_id` |
| `auth0_mfa_factor` | `GET /api/v2/guardian/factors` | Yes — no enrollment data, phone numbers, or recovery codes are exposed by this endpoint at all | Yes — soft-failure surface | Yes — `f"auth0_mfa_factor_{factor_name}"` |
| `auth0_custom_domain` | `GET /api/v2/custom-domains` | Yes — domain name string reduced to `domain_present=True`; verification tokens/CNAME targets never read | Yes — soft-failure surface | Yes — `custom_domain_id` |

**Confirmed via code inspection** (connector module docstring + normalizer
bodies + the module-level "PRIVACY / SECURITY" comment block):
- No **client secrets** are stored — `client_secret` is excluded from the
  `/clients` response via an explicit `fields` allowlist parameter (an
  extra safety layer beyond just not reading the field), and is never an
  instance attribute (`_acquire_token` is a `@staticmethod`, no `self.*`
  credential storage anywhere in the class).
- No **API/management token values** are stored — the acquired bearer
  token is used only within the `with self._make_management_client(...)`
  context manager scope and discarded on exit; never logged, never an
  instance attribute.
- No **refresh/access/ID tokens** are stored — the connector never reads
  or requests user-level tokens; only aggregate/configuration fields
  (rotation enabled, lifetime *category*) are stored, never token values.
- No **user PII** is stored beyond safe metadata/counts — no `/users`
  endpoint is fetched; `enabled_clients_count` is a count, not identities.
- No **raw log/event payload contents** are stored — `/api/v2/logs` is
  explicitly documented as never fetched (would include `user_id`, email,
  IP address, device data on every entry); activity events are instead
  *synthesized* from the same safe drift surfaces (M81D,
  `list_activity_events`).
- No **full callback/logout/origin URLs** are stored — reduced to integer
  counts (`callbacks_count`, `allowed_logout_urls_count`,
  `allowed_origins_count`, `web_origins_count`) plus posture booleans
  (`wildcard_*_present`, `localhost_*_present`, `*_missing_https`)
  computed from the raw lists *before* the raw lists are discarded.
- No **passwords or credential material** are stored — connection
  `options` dict (which holds passwords, social tokens, certs, private
  keys) is read only transiently to derive two safe fields
  (`password_policy_category`, `mfa_enabled`) and then discarded.

**Record ID stability note**: all 8 record types use Auth0-native opaque
identifiers (`client_id`, `connection_id`, `resource_server_id`,
`rule_id`, `action_id`, `custom_domain_id`, or a fixed literal for
singleton tenant-level records) — no positional-index or hash-based
identifiers are used anywhere in this connector, so record IDs are
maximally stable across syncs (stronger guarantee than several prior
providers, e.g. Datadog's `cloud_integration` positional-index tradeoff).

## Diff/change tracking review

**Before this pass**: 0 of 8 record types had a tracked-fields entry —
all Auth0 modified-field changes silently fell through to the Cloudflare
DNS default tuple and were never detected, **despite the capability
matrix already claiming `drift_diff=True`.**

**After this pass**: all 8 record types are tracked with every
security-relevant field verified present, including every one of the
task's high-priority fields: `mfa_enabled` (connection), `grant_types_count`
+ all 7 grant-type booleans, `callbacks_count`/`allowed_logout_urls_count`/
`allowed_origins_count`/`web_origins_count`, `refresh_token_rotation_enabled`/
`refresh_token_lifetime_category`, `app_type`/`is_first_party`/
`token_endpoint_auth_method`, `strategy`/enabled_clients_count` (connection),
`password_policy_category`, `signing_alg` (resource server),
`token_lifetime_category` (resource server), `rbac_enabled`/
`allow_offline_access`, `status`/`type` (custom domain verification/status),
`enabled` (rule/action/mfa_factor).

No fields were found that are tracked but no longer emitted by the
connector — the tracked tuples were built directly from
`auth0_schema.py`'s `TypedDict` definitions, cross-referenced against the
connector's actual normalizer output.

## Test matrix

| Test case | Normalized record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes/fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. MFA enabled/disabled | `auth0_connection` | `mfa_enabled` | `True → False` | Change (high, per task convention) | Change never generated before fix | high | high (after fix) | none — no dedicated Finding exists at this record type (see category S) | new `test_connection_mfa_disabled_is_high` | **FIXED (Change-only, documented gap)** | `auth0_mfa_factor_disabled` (medium) is the closest existing Finding but evaluates per-Guardian-factor, not per-connection; this is a genuine, separate field with no Finding — documented, not invented |
| A2. MFA factor (strong) disabled | `auth0_mfa_factor` | `enabled` | `True → False` (factor_name="otp") | Change (medium) + Finding (medium, `auth0_mfa_factor_disabled`) | Change never generated before fix | medium | medium (after fix) | `auth0_mfa_factor_disabled` (medium) — matches | new `test_mfa_factor_strong_disabled_is_medium` | **FIXED** | Change classifier extracts `factor_name` from `provider_metadata["record_id"]` (e.g. `auth0_mfa_factor_otp`) to mirror the Finding's `_STRONG_MFA_FACTORS` gating exactly |
| A3. MFA factor (non-strong) disabled | `auth0_mfa_factor` | `enabled` | `True → False` (factor_name="recovery-code") | Change (low) — Finding does not fire for non-strong factors | Change never generated before fix | low | low (after fix) | n/a — Finding only fires for `{otp, webauthn-roaming, push-notification}` | new `test_mfa_factor_non_strong_disabled_is_low` | **FIXED** | Matches Finding's exact factor-name gating |
| B. Attack protection enabled/disabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | No `/api/v2/attack-protection/*` endpoints (suspicious-ip-throttling, brute-force-protection, breached-password-detection) are fetched by this connector. Not invented per task instructions |
| C. Breached password protection enabled/disabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Same as B — `/api/v2/attack-protection/breached-password-detection` is not fetched |
| D. Brute-force protection enabled/disabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Same as B — `/api/v2/attack-protection/brute-force-protection` is not fetched |
| E. Refresh token rotation enabled/disabled | `auth0_application` | `refresh_token_rotation_enabled` | `True → False` | Change (medium) + Finding (medium, `auth0_refresh_token_rotation_disabled` / `auth0_application_refresh_grant_without_rotation`) | Change never generated before fix | medium | medium (after fix) | `auth0_refresh_token_rotation_disabled` (medium) — matches | new `test_refresh_token_rotation_disabled_is_medium` | **FIXED** | Two Findings share this severity via different combined conditions (string-search vs. explicit boolean); Change classifier fires on the single field regardless of the sibling grant-type value, consistent with the combined-condition-approximation pattern |
| F. Refresh token reuse posture changed | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | `auth0_schema.py` has no reuse-interval field — only `rotation_type` (mapped to `refresh_token_rotation_enabled`) and `token_lifetime` (mapped to `refresh_token_lifetime_category`) are captured from the `refresh_token` config object. Not invented |
| G. Token lifetime increased/decreased (app + API) | `auth0_application` / `auth0_resource_server` | `refresh_token_lifetime_category` / `token_lifetime_category` | `"short" → "extended"` | Change (medium) + Finding (medium, `auth0_refresh_token_lifetime_extended` / `auth0_resource_server_token_lifetime_extended`) | Change never generated before fix | medium | medium (after fix) | both match | new `test_tenant_session_lifetime_extended_is_medium` (tenant variant) + covered by tracked-field sweep (app/API variants) | **FIXED** | — |
| H. Application grant type count increased/decreased | `auth0_application` | `grant_types_count` | `5 → 6` (already over threshold of 4) | Change (medium) + Finding (medium, `auth0_application_many_grant_types`) | Change never generated before fix | medium | medium (after fix) | `auth0_application_many_grant_types` (medium) — matches | new `test_grant_types_count_increase_while_already_broad_is_medium` | **FIXED** | Uses any-increase-while-over-threshold, proactively applying the Datadog classification-QA fix pattern from the start |
| H2. Password/implicit grant enabled | `auth0_application` | `grant_password_enabled` / `grant_implicit_enabled` | `False → True` | Change (high) + Finding (high, `auth0_application_password_grant_enabled` / `auth0_application_implicit_grant_enabled`) | Change never generated before fix | high | high (after fix) | both match | new `test_password_grant_enabled_is_high`, `test_implicit_grant_enabled_is_high` | **FIXED** | — |
| I. Callback/logout/origin URL count increased/decreased | `auth0_application` | `callbacks_count` | `15 → 20` (already over threshold of 10) | Change (medium) + Finding (medium, `auth0_application_many_callbacks`) | Change never generated before fix | medium | medium (after fix) | `auth0_application_many_callbacks` (medium) — matches | new `test_callbacks_count_increase_while_already_broad_is_medium` | **FIXED** | `allowed_origins_count`/`web_origins_count` mirror this pattern individually as an approximation of the Finding's *summed* threshold (see design note) |
| I2. Wildcard callback/origin/logout URL present | `auth0_application` | `wildcard_callback_present` / `wildcard_allowed_origin_present` / `wildcard_logout_url_present` | `False → True` | Change (high/high/medium) + Finding (high/high/medium, matching keys) | Change never generated before fix | high/high/medium | high/high/medium (after fix) | all three match | new `test_wildcard_callback_present_is_high` (+ tracked-field sweep for the other two) | **FIXED** | — |
| J. Connection enabled/disabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | `auth0_schema.py`'s `Auth0ConnectionRecord` has no top-level `enabled` boolean — connections are enabled per-client via `enabled_clients_count`, already covered by category K |
| K. Enabled clients count increased/decreased | `auth0_connection` | `enabled_clients_count` | `2 → 0` | Change (low) + Finding (low, `auth0_connection_no_enabled_clients`) | Change never generated before fix | low | low (after fix) | `auth0_connection_no_enabled_clients` (low) — matches | covered by tracked-field sweep | **FIXED** | — |
| L. API signing algorithm changed | `auth0_resource_server` | `signing_alg` | `"RS256" → "HS256"` | Change (high, per task convention) | Change never generated before fix | high | high (after fix) | none — no dedicated Finding at this record type (see category S) | new `test_resource_server_weak_signing_alg_is_high` | **FIXED (Change-only, documented gap)** | `auth0_application_weak_jwt_algorithm` (high) evaluates the analogous `jwt_alg` field on `auth0_application`, not `auth0_resource_server`; the resource-server-level `signing_alg` field is fetched and normalized but has no dedicated Finding — documented, not invented |
| M. API RBAC enabled/disabled | `auth0_resource_server` | `rbac_enabled` | `True → False` | Change (medium) + Finding (medium, `auth0_resource_server_rbac_disabled`) | Change never generated before fix | medium | medium (after fix) | `auth0_resource_server_rbac_disabled` (medium) — matches | new `test_resource_server_rbac_disabled_is_medium` | **FIXED** | — |
| N. API token lifetime increased/decreased | `auth0_resource_server` | `token_lifetime_category` | `"short" → "extended"` | Change (medium) + Finding (medium, `auth0_resource_server_token_lifetime_extended`) | Change never generated before fix | medium | medium (after fix) | `auth0_resource_server_token_lifetime_extended` (medium) — matches | covered by tracked-field sweep | **FIXED** | — |
| O. Rule/action/hook enabled/disabled | `auth0_rule` | `enabled` | `True → False` | Change (low) + Finding (low, `auth0_rule_disabled`, only when `script_present`) | Change never generated before fix | low | low (after fix) | `auth0_rule_disabled` (low) — matches severity | new `test_rule_disabled_is_low` | **FIXED** | Finding requires the combination `enabled=False AND script_present=True`; Change classifier fires on `enabled` alone (accepted combined-condition approximation — severity already matches at `low` regardless) |
| O2. Action not deployed / secrets present | `auth0_action` | `deployed_version_present` / `secrets_count` | `True → False` / `0 → 1` | Change (low/low) + Finding (low/low, `auth0_action_not_deployed` / `auth0_action_secrets_present`) | Change never generated before fix | low/low | low/low (after fix) | both match | covered by tracked-field sweep | **FIXED** | Auth0 has no "hooks" concept distinct from legacy Rules and modern Actions — both are covered by categories O/O2; "Hooks" (a deprecated third Auth0 extensibility mechanism) are not fetched by this connector and are not invented |
| P. Custom domain verification/status changed | `auth0_custom_domain` | `status` | `"ready" → "pending_verification"` | Change (medium) + Finding (medium, `auth0_custom_domain_not_ready`) | Change never generated before fix | medium | medium (after fix) | `auth0_custom_domain_not_ready` (medium) — matches | new `test_custom_domain_not_ready_is_medium` | **FIXED** | — |
| Q. Unknown/missing fields never produce high findings | all 8 record types | any | `None`/missing | no high finding/classification | Confirmed — every Finding check in `security_rules/auth0.py` uses explicit boolean/category-string equality (`is False`/`is True`), and every new Change classifier branch falls to `low` on unparseable/missing values via `_is_falsy_explicit`/`_is_truthy`/`_int_or_none()`'s explicit `None` check, **except** `auth0_connection.password_policy_category`, which intentionally treats `None` as `high` — mirroring the pre-existing Security Finding's own explicit "unset is itself weak" design, not a bug (see design note) | none (except the one documented, intentional exception) | none (except the one documented, intentional exception) | all | new `test_every_tracked_field_classifies_without_error_or_invalid_severity`, `test_unknown_transitions_never_produce_high`, `test_count_unknown_not_treated_as_zero` | PASS | — |
| R. 403/404 fail-soft on optional endpoints | rules, actions, MFA factors, custom domains (soft-failure surfaces); tenant settings/applications/connections/resource servers (core surfaces, also fail-soft on 403/404 within their own fetchers) | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed — every `_fetch_*` helper catches `ConnectorError` with `status_code in (403, 404)` and returns `[]`; `fetch()` additionally wraps the four "soft-failure surfaces" (rules/actions/mfa/custom-domains) in a bare `except Exception` so even an unexpected error there never aborts the whole sync | n/a | n/a | n/a | existing `test_milestone81a` connector tests (`TestFetchSurfaces`) | PASS | — |
| S. Records with normalized fields but no security rule | `auth0_connection.mfa_enabled`, `auth0_resource_server.signing_alg` | n/a | n/a | gap identified | Confirmed via cross-reference of every tracked field against `security_rules/auth0.py`'s eval functions — these two fields are fetched, normalized, and now diff-tracked, but have no dedicated Finding | n/a | n/a | n/a — candidates for a future Finding rule, not added in this pass | new tracked-field-vs-classifier comparison (below) | **GAP (documented, not fixed)** | Per task instructions, this pass does not add new Security Finding rules; the Change classifier still applies this task's explicit MFA/signing-algorithm severity conventions to these already-fetched fields |
| T. Security rules with no reachable normalized record | — | — | — | — | None found — all 37 rules dispatch from `evaluate()` against one of the 8 record types the connector actually emits, and cross-checked against real normalizer output | n/a | n/a | all | existing `test_auth0_provider_depth_qa.py` / `test_milestone81h_auth0_provider_depth_qa.py` coverage | PASS | Zero dead/unreachable rules |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | 37/37 rule keys present everywhere with matching severities | Verified via exact set diff: `security_rules/auth0.py` (37) vs. `security_rule_registry.py` (37), `security_rule_pack.py` (37, all severities cross-checked programmatically, zero mismatches), `security_rule_confidence.py` (37), `security_coverage_service.py` (37 rule-key→record-type mappings, no extras once record-type-string false positives are excluded), and `securityRuleCatalog.ts` (37) | n/a | n/a | all | none pre-existing; verified via ad hoc scripted diff in this pass | PASS | Zero mismatches — no fix needed (matching Linear's/PagerDuty's/Datadog's/Clerk's equivalent passes, unlike Jira's, which found 10 severity mismatches and 6 catalog gaps) |
| Diff-tracked fields present for all 8 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 8 record types tracked (before fix)** → **8 of 8 tracked (after fix)** | n/a | n/a | n/a | new `TestAuth0DiffTrackedFields` (5 tests) | **FIXED** | Root-cause fix — see Summary #2 |
| Risk classification module exists and is wired | all | all tracked fields | n/a | every Change gets an Auth0-specific classification, not the Cloudflare DNS fallback | **module did not exist (before fix)** → **8 classifiers + dispatch wired (after fix)** | n/a | n/a | n/a | new `TestAuth0RiskClassifier` (28 tests, including a dispatch-level regression test, a dict-shaped mock-bug-prevention test, and proactive count-unknown-not-zero + threshold-increase-while-already-over tests) | **FIXED** | Summary #1/#2 — the largest fix in this pass, and the one that makes the pre-existing `drift_risk_classification=True` capability-matrix claim actually true |

## Design notes

### Why `password_policy_category: None` is `high`, not `low`/unknown

This is the **one intentional exception** to the general "unknown/missing
must never overstate certainty" rule in this codebase. `security_rules/auth0.py`'s
`_eval_connection` explicitly fires `auth0_connection_weak_password_policy`
(high) when `pw_policy is None or pw_policy.lower() in _WEAK_PASSWORD_POLICIES`
— i.e., the Finding's own author already decided that an **unset** password
policy on a database connection is not a "genuinely unknown" state but a
real, meaningful "not configured" state that is exactly as risky as an
explicitly weak one. `risk_rules/auth0.py` mirrors this exact convention
rather than treating `None` as a safe "unknown" per the codebase's usual
default, because the schema's own `Optional[str]` type for this field
represents "not configured" as a legitimate value of `None`, not a sentinel
for "the connector didn't fetch this."

### Why `auth0_connection.mfa_enabled` and `auth0_resource_server.signing_alg` are Change-only signals

Both fields are fetched, normalized, and now diff-tracked, but
`security_rules/auth0.py` has no dedicated Finding for either:
- `mfa_enabled` exists only on `auth0_connection` (only for `strategy ==
  "auth0"` database connections); the only MFA-related Finding
  (`auth0_mfa_factor_disabled`) evaluates *tenant-wide Guardian factors*
  (`auth0_mfa_factor` records), a structurally different surface.
- `signing_alg` exists on `auth0_resource_server`; the only weak-signing-
  algorithm Finding (`auth0_application_weak_jwt_algorithm`) evaluates the
  analogous `jwt_alg` field on `auth0_application`, not resource servers.

Per this task's explicit instructions, this detection-QA pass does not
invent new Security Finding rules beyond what's needed for diff tracking
and Change classification. The Change classifier still applies this
task's own stated severity conventions (MFA disabled = high, weak signing
algorithm = high) to these two already-fetched fields, since doing so
requires no new connector work and matches the task's explicit
guidance — but this remains a genuine Finding-layer coverage gap, flagged
here (category S) as a candidate for a future classification/Finding
pass, not silently "fixed" by inventing a Finding.

### Why `allowed_origins_count`/`web_origins_count` each use the full `_MANY_ORIGINS_THRESHOLD` individually

`auth0_application_many_allowed_origins` fires on the **sum** of
`allowed_origins_count + web_origins_count` exceeding 10. A single-field
Change classifier can't see both fields' current values simultaneously,
so each field is evaluated against the same threshold independently as
an approximation — consistent with the combined-condition-approximation
pattern already established for every other provider's summed/combined
Findings in this codebase (e.g. Datadog's `broad_collection`, GitLab's
combined access-scope rules).

## Tracked-fields vs. classifier-branch comparison

Verified programmatically: parsed `_AUTH0_TRACKED_FIELDS_BY_TYPE` from
`diff_service.py` and every `if fp == "..."` / `if fp in (...)` branch
from each of the 8 `_classify_*_change` functions in `risk_rules/auth0.py`.

**Result**: zero tracked fields fall through accidentally, and zero
dead/unreachable classifier branches — every branch corresponds to a real
tracked field, and every tracked field is handled by either a
field-specific branch or an explicit generic group.

**Classifier branches referring to fields not emitted by the
connector/schema:** none found — every branch was cross-checked against
both `_AUTH0_TRACKED_FIELDS_BY_TYPE` and `auth0_schema.py`'s `TypedDict`
definitions.

**Classifier branches referring to stale field names:** none — this is a
newly-built module (this session), so there was no legacy field-name
drift to inherit.

**Fields with similar names that could be confused:** `jwt_alg`
(`auth0_application`) vs. `signing_alg` (`auth0_resource_server`) are the
closest pair — both use the identical `_WEAK_JWT_ALGS` set and near-
identical wording, but each branch names its own field/record type
explicitly ("Auth0 application OAuth posture" vs. "Auth0 token policy —
API signing algorithm"), so the two remain distinguishable in the reason
text despite sharing the same weak-algorithm concept.

## Fixes made

1. **`backend/app/services/risk_rules/auth0.py`** (new file) — 8
   record-type classifiers (`_classify_tenant_settings_change` through
   `_classify_custom_domain_change`) plus the `classify_auth0_change`
   dispatcher. Built with `_int_or_none()` and
   `_crossed_threshold_increase()` (any-increase-while-over-threshold,
   not crossing-only) from the start, to avoid the exact false-positive
   severity bugs found and fixed in PagerDuty's and Datadog's
   classification-QA passes.
2. **`backend/app/services/risk_service.py`** — added the `auth0_` prefix
   dispatch branch to `classify_change`, routing Auth0 changes to the new
   module instead of the Cloudflare DNS fallback; updated the module
   docstring's dispatch list.
3. **`backend/app/services/diff_service.py`** — added
   `_AUTH0_TRACKED_FIELDS_BY_TYPE` (all 8 record types) and wired the
   `auth0_` prefix into `_tracked_fields_for`. Updated the function's
   docstring.
4. **`backend/tests/test_milestone81a_auth0_drift_provider_foundation.py`**
   — added `TestAuth0DiffTrackedFields` (5 tests) and
   `TestAuth0RiskClassifier` (28 tests, including a dispatch-level
   regression test, a dict-shaped mock-bug-prevention test, a proactive
   count-unknown-not-zero test, and two threshold-increase-while-already-
   over tests); added `app/services/risk_rules/auth0.py` to the
   forbidden-wording module scan list (`_BACKEND_AUTH0_MODULES`).
5. **`backend/tests/reports/auth0_detection_matrix.md`** — this report.

No changes were made to `security_rules/auth0.py`, the four backend
registries, or the frontend catalog — all were already correct and in
perfect 37/37 parity with zero severity mismatches. The pre-existing
`test_capability_matrix_auth0_drift_only` test's assertion
(`cap.drift.drift_risk_classification is True`) was already present and
passing (as a bare model-field check) — this pass makes that claim
**substantively true** for the first time by building the code path it
was already asserting existed.

## Not fixed in this pass (explicitly out of scope)

- **Attack protection / brute-force protection / breached password
  detection** (task categories B, C, D) — no `/api/v2/attack-protection/*`
  endpoints are fetched by this connector; not invented.
- **Refresh token reuse posture** (task category F) — only
  `rotation_type` and `token_lifetime` are captured from the `refresh_token`
  config object; no reuse-interval field exists in the schema.
- **Connection enabled/disabled as a standalone boolean** (task category
  J) — connections don't expose a top-level `enabled` flag; per-client
  enablement is captured via `enabled_clients_count` (category K).
- **`auth0_connection.mfa_enabled` and `auth0_resource_server.signing_alg`
  Security Findings** (category S) — both fields are fetched and now
  diff-tracked with sensible Change severities, but no new Security
  Finding rule was added for either, per task instructions not to invent
  new rules beyond what this pass is scoped to fix.
- **Auth0 Hooks** (a deprecated third extensibility mechanism distinct
  from Rules and Actions) — not fetched by this connector; Rules and
  Actions (categories O/O2) already cover the "rule/action/hook" scope
  item.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone81a_auth0_drift_provider_foundation.py -q
# 173 passed

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "auth0"
# 762 passed, 1 skipped, 16456 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*auth0* -q
# 744 passed
```

No frontend files were touched in this pass — registries and the frontend
catalog were already in perfect 37/37 parity — so `npx tsc --noEmit` was
not run.
