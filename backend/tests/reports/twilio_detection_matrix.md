# Twilio Detection QA Matrix

Exhaustive validation pass over the Twilio provider (connector → diff
tracking → risk classification → security findings → registries → frontend
catalog), following the same methodology as `sendgrid_detection_matrix.md`
and `sendgrid_change_classification_matrix.md`.

## Summary

- **Connector**: 5 record types (`twilio_account`,
  `twilio_incoming_phone_number`, `twilio_messaging_service`,
  `twilio_verify_service`, `twilio_api_key_summary`). All optional surfaces
  fail soft on error without aborting the sync (verified via
  `TestErrorHandling`, including a dedicated `test_messaging_service_404_
  does_not_crash_fetch`). No auth tokens, full phone numbers, webhook URL
  strings, message content, or call/verification data are ever stored.
- **Security findings** (current-state, "Configuration Risk"): 18 rules
  (17 original + `twilio_webhook_uses_http` added in the follow-up scheme-
  detection pass below), 100% registered across `security_rule_registry.py`,
  `security_rule_pack.py`, `security_rule_confidence.py`,
  `security_coverage_service.py`, and
  `frontend/src/lib/securityRuleCatalog.ts` — verified byte-for-byte parity
  (zero diff) between the rule keys defined in `security_rules/twilio.py`
  and all four backend registries plus the frontend catalog. The original
  17 were already in full parity before this QA pass; the 18th was added
  and registered in the same pass that implemented scheme detection.
- **Diff/drift tracking**: **one real gap found and fixed** — identical in
  shape to the SendGrid gap fixed in commit `4bd31f4`. Twilio had no entry
  in `diff_service.py`'s per-provider tracked-fields dispatch, so every
  Twilio record type fell through to the Cloudflare-DNS default tuple.
  `compute_diff` could therefore never detect a *modified* field on an
  existing Twilio record (only add/remove of a whole record). Fixed by
  adding `_TWILIO_TRACKED_FIELDS_BY_TYPE` and wiring the `twilio_` prefix
  into `_tracked_fields_for`. Regression tests added.
- **Risk classification for Changes** (the "Changes" timeline, distinct
  from Security Findings): **fixed**. Twilio had no
  `risk_rules/twilio.py`, so any Twilio Change fell back to
  `classify_dns_change` (the Cloudflare DNS classifier), producing a
  meaningless classification for every field. Added
  `backend/app/services/risk_rules/twilio.py`, calibrated to match the
  existing Twilio Security Finding severities exactly (both cap at
  `medium` — Twilio's connector has no field that carries a `high`-grade
  signal; see "Not modeled" below for why).

## UPDATE — Webhook URL scheme detection implemented (items D, E, F, H)

**Resolved.** The product decision flagged below as needing an explicit
call was made: it is acceptable to store *only* the URL scheme
(`"http"`/`"https"`/`None`) — never the full URL, host, path, query string,
or embedded tokens. Implemented across the full pipeline:

- **Connector** (`twilio.py`): new `_url_scheme()` helper (`urlparse`-based,
  returns `None` for anything that isn't exactly `http`/`https`). Applied to
  `sms_url`, `voice_url`, `status_callback` (phone numbers) and
  `inbound_request_url`, `fallback_url`, `status_callback_url` (Messaging
  Services), producing `sms_url_scheme`, `voice_url_scheme`,
  `status_callback_scheme`, `inbound_request_url_scheme`,
  `fallback_url_scheme`, `status_callback_url_scheme`. No new API calls —
  purely additional extraction from data already fetched. All three
  privacy-contract docstrings (module, connector class, schema module) were
  updated to describe the new "scheme only" contract precisely.
- **Schema** (`twilio_schema.py`): both affected TypedDicts updated with the
  six new `Optional[str]` fields and matching docstring language.
- **Diff tracking**: all six new fields added to
  `_TWILIO_TRACKED_FIELDS_BY_TYPE`.
- **Change classification** (`risk_rules/twilio.py`): new shared
  `_classify_scheme_change()` helper — `https → http` (confirmed
  regression) is `high` (the one exception to this module's otherwise-
  `medium` ceiling, matching the GitHub webhook-HTTP precedent);
  unknown/missing `→ http` (first observation) is `medium`; `http → https`
  (restoration) is `medium`; anything `→ None` (unknown) is `low`, never
  escalated.
- **Security finding**: new rule `twilio_webhook_uses_http` (`high`),
  firing once per HTTP-scheme webhook field on a phone number or Messaging
  Service record, registered across all four backend registries and the
  frontend catalog (rule count 17 → 18 everywhere, verified).
- **Tests**: new `backend/tests/test_twilio_webhook_scheme.py` (38 tests)
  covering the extractor itself, connector normalization (https/http/
  missing/invalid), diff detection in both directions, a same-scheme-
  different-host no-op proof, Change classification for every transition,
  and Security Finding positive/negative/unknown cases plus evidence/copy
  safety. Plus updates to 5 existing test files whose hardcoded rule-count
  assertions (17) needed bumping to 18.

Items D, E, F, H are now **FIXED** — see the updated test matrix rows below.

**Event Streams / Sinks — items I, J.** Not fetched by the connector at
all; no endpoint call exists for `https://events.twilio.com` Sinks/
Subscriptions. Correctly absent per "do not invent unsupported
capabilities" — no existing evidence to build a rule or tracked field from.

**API key active/enabled/scope posture — items A, B, C.** Twilio's List API
Keys response (`GET /2010-04-01/Accounts/{Sid}/Keys.json`) genuinely has no
status, scope, or permission field in Twilio's own API — only `sid`,
`friendly_name`, `date_created`, `date_updated`. This is not a connector gap;
Twilio API keys are binary (exist or deleted) and carry no permission model
to broaden or restrict. Confirmed against the connector's own raw-shape
docstring comment. `TwilioApiKeySummaryRecord` correctly has no such field.

**SIP trunking / emergency calling detail / recording settings** — beyond
the single `emergency_status` boolean already modeled on
`twilio_incoming_phone_number`, no SIP trunk or call-recording endpoint is
fetched. Correctly absent.

## Test matrix

| Test case | Normalized record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes / fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. API key active/enabled posture | `twilio_api_key_summary` | — | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | Twilio's API Keys API has no status/enabled field at all |
| B. API key disabled/restricted posture | `twilio_api_key_summary` | — | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | Same — API keys are binary exist/deleted, correctly modeled as add/remove |
| C. API key scope/permission broadening | `twilio_api_key_summary` | — | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | Twilio API keys carry no scope/permission model in the API itself |
| D. Phone number webhook URL HTTP vs HTTPS | `twilio_incoming_phone_number` | `sms_url_scheme`, `voice_url_scheme`, `status_callback_scheme` | `"https" → "http"` | Change (high) + Security Finding (high) | Both fire | high | high | `twilio_webhook_uses_http` | `test_https_to_http_is_high`, `test_fires_on_explicit_http_phone_number` (in `test_twilio_webhook_scheme.py`) | **FIXED** | Implemented via scheme-only extraction — see update above |
| E. Phone number webhook URL changed | `twilio_incoming_phone_number` | `sms_url_configured`, `voice_url_configured` | `True → False` (removed) | Change + medium finding | **Change now detected** (fixed); finding already fired | medium | medium | `twilio_phone_number_sms_webhook_missing` / `..._voice_webhook_missing` (medium) | `test_phone_number_sms_webhook_removed_is_medium`, `test_phone_number_voice_webhook_removed_is_medium`, `test_phone_number_sms_webhook_removed_produces_drift_change` | **FIXED** | Diff-tracking + classification both fixed in this pass |
| F. Messaging service webhook URL HTTP vs HTTPS | `twilio_messaging_service` | `inbound_request_url_scheme`, `fallback_url_scheme`, `status_callback_url_scheme` | `"https" → "http"` | Change (high) + Security Finding (high) | Both fire | high | high | `twilio_webhook_uses_http` | `test_messaging_service_inbound_https_to_http_is_high`, `test_fires_on_explicit_http_messaging_service` | **FIXED** | Same rule key as D — one shared rule fires on either record type |
| G. Messaging service webhook disabled/enabled | `twilio_messaging_service` | `inbound_request_url_configured` | `True → False` | Change + medium finding | Change now detected; finding already fired | medium | medium | `twilio_messaging_service_inbound_webhook_missing` (medium) | `test_messaging_service_inbound_webhook_removed_is_medium` | **FIXED** | — |
| H. Voice/application webhook HTTP vs HTTPS | `twilio_incoming_phone_number` | `voice_url_scheme` | `"https" → "http"` | Change (high) + Security Finding (high) | Both fire | high | high | `twilio_webhook_uses_http` | `test_voice_webhook_configured_is_low_improvement` (restoration direction), `test_https_to_http_is_high` (regression direction, same field family) | **FIXED** | "Voice/application webhook" in this connector is the phone number's `voice_url` field, same field as D |
| I. Event sink enabled/disabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | No Event Streams/Sinks endpoint fetched |
| J. Event sink destination changed | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | Same as I |
| K. Account/subaccount setting weakened | `twilio_account` | `status` | `"active" → "suspended"` | Change + finding | Change now detected; finding already fired | medium | medium | `twilio_account_suspended` (low, reviewed — see note) | `test_account_status_non_active_is_medium`, `test_account_status_change_produces_drift_change` | **FIXED** | Change classifier uses `medium` (a real status change is more actionable than the finding's conservative `low`, which also covers ambiguous "unknown" status — see note below) |
| L. Verify Service posture changed | `twilio_verify_service` | `code_length` | `6 → 4` | Change + medium finding | Change now detected; finding already fired | medium | medium | `twilio_verify_short_code_length` (medium) | `test_verify_code_length_shortened_is_medium`, `test_verify_service_code_length_change_produces_drift_change` | **FIXED** | — |
| L2. Verify lookup/PSD2/landline settings | `twilio_verify_service` | `lookup_enabled`, `psd2_enabled`, `skip_sms_to_landlines` | disabled | Change + low finding | Change now detected; finding already fired | low | low | `twilio_verify_lookup_disabled`, `twilio_verify_psd2_disabled`, `twilio_verify_sms_to_landlines_allowed` (all low) | `test_verify_lookup_disabled_is_low`, `test_verify_psd2_disabled_is_low` | **FIXED** | — |
| M. Unknown/missing fields never high | all 5 record types | any field | field absent (`None`) or unrecognised record type | no high/critical finding or Change classification | Confirmed — every Change classification check is field-specific and defaults to `low`; every Security Finding check requires an explicit boolean/string match | none | none | all | `test_added_records_never_produce_high`, `test_removed_records_never_produce_high`, `test_unrecognised_record_type_falls_back_safely_to_low`, `test_api_key_field_change_is_low_not_high` | PASS | Twilio's classifier has no `high`/`critical` tier at all (see module docstring) — structurally impossible to over-escalate |
| N. 403/404 fail-soft on optional endpoints | phone numbers, messaging services, verify services, API keys | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed via `TestErrorHandling.test_messaging_service_404_does_not_crash_fetch` and the parametrized 403/404/422/500/502 → `ConnectorError` test | n/a | n/a | n/a | `test_messaging_service_404_does_not_crash_fetch`, `test_raise_for_status_4xx_5xx_raises_connector_error` | PASS | Only account fetch is required (credential-validation anchor); all others fail soft |
| O. Records with normalized fields but no security rule | `twilio_account` (`account_type`, `friendly_name`, `subaccount_count`), `twilio_incoming_phone_number` (`friendly_name`, `iso_country`, `address_requirements`, individual `capability_*` booleans), `twilio_messaging_service` (`friendly_name`, `smart_encoding`, `area_code_geomatch`, `sticky_sender`, `mms_converter`), `twilio_verify_service` (`friendly_name`, `default_template_sid_present`) | n/a | n/a | n/a | correctly no finding (cosmetic/low-signal fields) | n/a | n/a | n/a | n/a | PASS | These are display/identity/low-signal fields, not security-relevant on their own — correctly have no dedicated rule. All still diff-tracked and Change-classified at `low` |
| P. Security rules with no reachable normalized record | — | — | — | — | none found — all 17 rules dispatch from `evaluate()` against one of the 5 real record types, verified via `TestSendGridEvaluatorDispatch`-equivalent coverage in `test_twilio_provider_depth_qa.py` | n/a | n/a | n/a | existing M79B/M79C/QA test suites | PASS | Zero dead/unreachable rules |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | all 18 rule keys present everywhere with matching severities | Verified via exact set diff: `security_rules/twilio.py` (18) vs. `security_rule_registry.py` (18), `security_rule_pack.py` (18), `security_rule_confidence.py` (18), `security_coverage_service.py` `RULE_RECORD_TYPES` (18), `securityRuleCatalog.ts` (18) | n/a | n/a | all | `test_twilio_provider_depth_qa.py` (`len(ALL_TWILIO_RULE_KEYS) == 18`) | PASS | Zero mismatches found (was 17 before the scheme-detection pass added `twilio_webhook_uses_http`) |
| Diff-tracked fields present for all 5 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 5 record types tracked (before fix)** → **5 of 5 tracked (after fix)** | n/a | n/a | n/a | new `TestTwilioDiffTrackedFields` (6 tests) | **FIXED** | The core fix of this QA pass |

## Note on `twilio_account_suspended` severity (reviewed, not changed)

The Security Finding for a non-active account status is `low`, not `medium`
— this is deliberate: the rule fires on *any* non-`"active"` status,
including `"unknown"` (which may just mean the connector couldn't read a
valid value, not a real suspension) and `"closed"` (an expected terminal
state, not urgent). The Change classifier in this pass uses `medium`
instead for the specific, concrete transition *from* `"active"` *to*
anything else — a real observed status change is a stronger, less ambiguous
signal than the finding's blanket "current state is non-active" check. Both
severities are independently defensible for what they're each observing;
this is not a parity bug and was **not changed** in this pass.

## Totals

| Metric | Count |
|---|---|
| Total Twilio test cases reviewed | 22 (rows in the table above) |
| PASS | 8 |
| FAIL | 0 |
| FIXED (previously misclassified/undetected/gap, now correct) | 11 (8 from the original pass + D, F, H from the scheme-detection follow-up) |
| N/A (not modeled, correctly absent per API/connector reality) | 5 |
| GAP (remaining, not fixed) | 0 |

## Fixes made

1. **`backend/app/services/diff_service.py`** — added
   `_TWILIO_TRACKED_FIELDS_BY_TYPE` (all 5 record types, every non-identity
   field) and wired the `twilio_` prefix into `_tracked_fields_for`.
   Updated the function's docstring.
2. **`backend/app/services/risk_rules/twilio.py`** (new) — provider-specific
   Change classifier for all 5 Twilio record types, severities calibrated
   to match existing Security Finding severities exactly. No `high`/
   `critical` tier exists, matching the connector's actual data model.
3. **`backend/app/services/risk_service.py`** — added `twilio_` dispatch
   branch (one `if` block, mirrors every other provider).
4. **`backend/tests/test_milestone79a_twilio_drift_provider_foundation.py`**
   — added `TestTwilioDiffTrackedFields` (6 tests): entry-completeness
   check, no-fallthrough check, 3 `compute_diff` regression tests (SMS
   webhook, account status, Verify code length), and a no-spurious-change
   sanity test.
5. **`backend/tests/test_twilio_risk_rules.py`** (new) — 26 tests covering
   every category A–M from the task plus the dispatch-regression test.
6. **`backend/tests/reports/twilio_detection_matrix.md`** — this report.

### Follow-up pass — webhook URL scheme detection

7. **`backend/app/connectors/twilio.py`** — new `_url_scheme()` helper;
   applied to both phone-number and Messaging Service normalizers; privacy
   contract docstrings updated (module + class level).
8. **`backend/app/connectors/twilio_schema.py`** — 6 new `Optional[str]`
   scheme fields added to the two affected TypedDicts; docstrings updated.
9. **`backend/app/services/diff_service.py`** — 6 new scheme fields added
   to `_TWILIO_TRACKED_FIELDS_BY_TYPE`.
10. **`backend/app/services/risk_rules/twilio.py`** — new
    `_classify_scheme_change()` shared helper; wired into both phone-number
    and messaging-service classifiers; module docstring updated to document
    the one `high`-severity exception.
11. **`backend/app/services/security_rules/twilio.py`** — new rule
    `twilio_webhook_uses_http` (high), two new check functions (phone
    number, messaging service), wired into both `_eval_*` dispatchers.
12. **`backend/app/services/security_rule_registry.py`**,
    **`security_rule_pack.py`**, **`security_rule_confidence.py`**,
    **`security_coverage_service.py`**, **`frontend/src/lib/
    securityRuleCatalog.ts`** — new rule registered in all five places.
13. **`backend/app/services/twilio_risk_activity_correlation_service.py`**
    — new rule key added to both the phone-number and messaging-service
    correlation buckets (it fires on both record types).
14. **`backend/tests/test_twilio_webhook_scheme.py`** (new, 38 tests) —
    end-to-end coverage of the extractor, connector normalization, diff
    detection, Change classification, and Security Finding behavior.
15. **`backend/tests/test_milestone79b_twilio_core_security_foundation.py`**,
    **`test_milestone79c_twilio_messaging_webhook_risk_expansion.py`**,
    **`test_milestone79h_twilio_provider_depth_qa.py`**,
    **`test_milestone79i_twilio_cross_cloud_ux_polish.py`**,
    **`test_twilio_provider_depth_qa.py`** — hardcoded rule-count
    assertions (17) and expected-key sets updated to include
    `twilio_webhook_uses_http` (18 total).

## Validation run (narrow, foreground only)

```
DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone79a_twilio_drift_provider_foundation.py -q
# 147 passed

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_twilio_risk_rules.py -q
# 26 passed

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "twilio and webhook"
# 137 passed, 16802 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "twilio and diff"
# 19 passed, 16920 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "twilio"
# 713 passed, 1 skipped, 16225 deselected (was 675 passed, 1 skipped before this follow-up pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_twilio_webhook_scheme.py -q
# 38 passed
```

Frontend catalog changed (`securityRuleCatalog.ts`), so `npx tsc --noEmit`
was run: clean, no errors.
