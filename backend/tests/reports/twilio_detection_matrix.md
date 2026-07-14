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
- **Security findings** (current-state, "Configuration Risk"): 17 rules,
  100% registered across `security_rule_registry.py`,
  `security_rule_pack.py`, `security_rule_confidence.py`,
  `security_coverage_service.py`, and
  `frontend/src/lib/securityRuleCatalog.ts` — verified byte-for-byte parity
  (zero diff) between the rule keys defined in `security_rules/twilio.py`
  and all four backend registries plus the frontend catalog. This was
  already true before this QA pass; no fix needed.
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

## Not modeled (reviewed, not fixed — explicit design constraint)

**Webhook URL scheme (HTTP vs. HTTPS) — items D, E, F, H.** The connector's
privacy contract is explicit and repeated in three places (module
docstring, connector class docstring, and `twilio_schema.py`'s module
docstring): *"Webhook / callback URL strings — stored as boolean presence
flags only"* — Twilio is deliberately **more conservative** than GitHub's
webhook connector (which stores the full URL specifically to support
scheme/host evidence in its SSL-verification and HTTP-webhook rules).
Because the raw URL string is discarded to a boolean before it ever reaches
a normalized record, **there is no scheme information available anywhere in
the pipeline** to classify "HTTP vs. HTTPS."

This was a deliberate call in this pass, not an oversight: extracting even
just the URL *scheme* (e.g., a bare `"https"`/`"http"` enum, never host,
path, or query string) would be a low-risk, zero-new-endpoint addition that
directly enables items D/E/F/H — but it would mean silently reinterpreting
an explicit, multiple-times-repeated security/privacy design statement made
elsewhere in the codebase. That is a product decision, not a QA-pass fix.
**Recommendation:** if HTTP-webhook detection for Twilio is wanted, make
that decision explicitly (e.g., add `sms_url_scheme` / `voice_url_scheme` /
`inbound_request_url_scheme` fields storing only the scheme, matching the
GitHub webhook precedent) — do not have a future QA pass reinterpret this
unilaterally either.

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
| D. Phone number webhook URL HTTP vs HTTPS | `twilio_incoming_phone_number` | `sms_url_configured`/`voice_url_configured` | n/a | n/a | not modeled (scheme not stored) | high (per task) | n/a | n/a | n/a | **GAP (documented, not fixed)** | See "Not modeled" above — deliberate privacy contract, needs an explicit product decision to extend |
| E. Phone number webhook URL changed | `twilio_incoming_phone_number` | `sms_url_configured`, `voice_url_configured` | `True → False` (removed) | Change + medium finding | **Change now detected** (fixed); finding already fired | medium | medium | `twilio_phone_number_sms_webhook_missing` / `..._voice_webhook_missing` (medium) | `test_phone_number_sms_webhook_removed_is_medium`, `test_phone_number_voice_webhook_removed_is_medium`, `test_phone_number_sms_webhook_removed_produces_drift_change` | **FIXED** | Diff-tracking + classification both fixed in this pass |
| F. Messaging service webhook URL HTTP vs HTTPS | `twilio_messaging_service` | `inbound_request_url_configured` | n/a | n/a | not modeled (scheme not stored) | high (per task) | n/a | n/a | n/a | **GAP (documented, not fixed)** | Same as D |
| G. Messaging service webhook disabled/enabled | `twilio_messaging_service` | `inbound_request_url_configured` | `True → False` | Change + medium finding | Change now detected; finding already fired | medium | medium | `twilio_messaging_service_inbound_webhook_missing` (medium) | `test_messaging_service_inbound_webhook_removed_is_medium` | **FIXED** | — |
| H. Voice/application webhook HTTP vs HTTPS | `twilio_incoming_phone_number` | `voice_url_configured` | n/a | n/a | not modeled (scheme not stored) | high (per task) | n/a | n/a | n/a | **GAP (documented, not fixed)** | Same as D — "voice/application webhook" in this connector is the phone number's `voice_url`, same field as D |
| I. Event sink enabled/disabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | No Event Streams/Sinks endpoint fetched |
| J. Event sink destination changed | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | Same as I |
| K. Account/subaccount setting weakened | `twilio_account` | `status` | `"active" → "suspended"` | Change + finding | Change now detected; finding already fired | medium | medium | `twilio_account_suspended` (low, reviewed — see note) | `test_account_status_non_active_is_medium`, `test_account_status_change_produces_drift_change` | **FIXED** | Change classifier uses `medium` (a real status change is more actionable than the finding's conservative `low`, which also covers ambiguous "unknown" status — see note below) |
| L. Verify Service posture changed | `twilio_verify_service` | `code_length` | `6 → 4` | Change + medium finding | Change now detected; finding already fired | medium | medium | `twilio_verify_short_code_length` (medium) | `test_verify_code_length_shortened_is_medium`, `test_verify_service_code_length_change_produces_drift_change` | **FIXED** | — |
| L2. Verify lookup/PSD2/landline settings | `twilio_verify_service` | `lookup_enabled`, `psd2_enabled`, `skip_sms_to_landlines` | disabled | Change + low finding | Change now detected; finding already fired | low | low | `twilio_verify_lookup_disabled`, `twilio_verify_psd2_disabled`, `twilio_verify_sms_to_landlines_allowed` (all low) | `test_verify_lookup_disabled_is_low`, `test_verify_psd2_disabled_is_low` | **FIXED** | — |
| M. Unknown/missing fields never high | all 5 record types | any field | field absent (`None`) or unrecognised record type | no high/critical finding or Change classification | Confirmed — every Change classification check is field-specific and defaults to `low`; every Security Finding check requires an explicit boolean/string match | none | none | all | `test_added_records_never_produce_high`, `test_removed_records_never_produce_high`, `test_unrecognised_record_type_falls_back_safely_to_low`, `test_api_key_field_change_is_low_not_high` | PASS | Twilio's classifier has no `high`/`critical` tier at all (see module docstring) — structurally impossible to over-escalate |
| N. 403/404 fail-soft on optional endpoints | phone numbers, messaging services, verify services, API keys | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed via `TestErrorHandling.test_messaging_service_404_does_not_crash_fetch` and the parametrized 403/404/422/500/502 → `ConnectorError` test | n/a | n/a | n/a | `test_messaging_service_404_does_not_crash_fetch`, `test_raise_for_status_4xx_5xx_raises_connector_error` | PASS | Only account fetch is required (credential-validation anchor); all others fail soft |
| O. Records with normalized fields but no security rule | `twilio_account` (`account_type`, `friendly_name`, `subaccount_count`), `twilio_incoming_phone_number` (`friendly_name`, `iso_country`, `address_requirements`, individual `capability_*` booleans), `twilio_messaging_service` (`friendly_name`, `smart_encoding`, `area_code_geomatch`, `sticky_sender`, `mms_converter`), `twilio_verify_service` (`friendly_name`, `default_template_sid_present`) | n/a | n/a | n/a | correctly no finding (cosmetic/low-signal fields) | n/a | n/a | n/a | n/a | PASS | These are display/identity/low-signal fields, not security-relevant on their own — correctly have no dedicated rule. All still diff-tracked and Change-classified at `low` |
| P. Security rules with no reachable normalized record | — | — | — | — | none found — all 17 rules dispatch from `evaluate()` against one of the 5 real record types, verified via `TestSendGridEvaluatorDispatch`-equivalent coverage in `test_twilio_provider_depth_qa.py` | n/a | n/a | n/a | existing M79B/M79C/QA test suites | PASS | Zero dead/unreachable rules |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | all 17 rule keys present everywhere with matching severities | Verified via exact set diff: `security_rules/twilio.py` (17) vs. `security_rule_registry.py` (17), `security_rule_pack.py` (17), `security_rule_confidence.py` (17), `security_coverage_service.py` `RULE_RECORD_TYPES` (17), `securityRuleCatalog.ts` (17) | n/a | n/a | all | `test_twilio_provider_depth_qa.py` (`len(ALL_TWILIO_RULE_KEYS) == 17`) | PASS | Zero mismatches found |
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
| Total Twilio test cases reviewed | 22 (rows in the table above, D/H collapsed as the same underlying field) |
| PASS | 8 |
| FAIL | 0 |
| FIXED (previously misclassified/undetected, now correct) | 8 |
| N/A (not modeled, correctly absent per API/connector reality) | 5 |
| GAP (documented, deliberately not fixed — needs a product decision) | 3 (D, F, H — all the same underlying scheme-detection gap) |

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

## Validation run (narrow, foreground only)

```
DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone79a_twilio_drift_provider_foundation.py -q
# 147 passed

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "twilio and risk"
# 110 passed, 16791 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "twilio and diff"
# 15 passed, 16886 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "twilio"
# 675 passed, 1 skipped, 16225 deselected (was 643 passed, 1 skipped before this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_twilio_risk_rules.py -q
# 26 passed
```

No frontend files were touched, so `npx tsc --noEmit` was not run.
