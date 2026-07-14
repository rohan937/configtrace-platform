# SendGrid Detection QA Matrix

Exhaustive validation pass over the SendGrid provider (connector → diff
tracking → risk classification → security findings → registries → frontend
catalog). Produced as a one-time QA report; update it if SendGrid rules or
tracked fields change materially.

## Summary

- **Connector**: 8 record types (`sendgrid_account`, `sendgrid_api_key`,
  `sendgrid_sender_identity`, `sendgrid_domain_authentication`,
  `sendgrid_mail_settings`, `sendgrid_tracking_settings`,
  `sendgrid_webhook_settings`, `sendgrid_suppression_settings`). All optional
  surfaces fail soft on 403/404 without aborting the sync. No secrets, full
  email addresses, raw DNS values, or webhook URLs are ever stored.
- **Security findings** (current-state, "Configuration Risk"): 27 rules,
  100% registered across `security_rule_registry.py`, `security_rule_pack.py`,
  `security_rule_confidence.py`, `security_coverage_service.py`, and
  `frontend/src/lib/securityRuleCatalog.ts` — verified byte-for-byte parity
  (zero diff) between the rule keys defined in
  `security_rules/sendgrid.py` and all four backend registries plus the
  frontend catalog. This was already true before this QA pass; no fix
  needed.
- **Diff/drift tracking**: **one real gap found and fixed** — SendGrid had
  no entry in `diff_service.py`'s per-provider tracked-fields dispatch, so
  every SendGrid record type fell through to the Cloudflare-DNS default
  tuple. `compute_diff` could therefore never detect a *modified* field on
  an existing SendGrid record (only add/remove of a whole record). Fixed by
  adding `_SENDGRID_TRACKED_FIELDS_BY_TYPE` and wiring the `sendgrid_`
  prefix into `_tracked_fields_for`. Regression tests added.
- **Risk classification for Changes** (the "Changes" timeline, distinct from
  Security Findings): SendGrid has **no `risk_rules/sendgrid.py` module**,
  so any SendGrid Change falls back to `classify_dns_change` (the Cloudflare
  DNS classifier), producing a meaningless classification. **This is a
  pre-existing architectural gap shared by every provider added after
  GitLab/Terraform Cloud** (Azure, Google Cloud, Twilio, SendGrid, Clerk,
  PagerDuty, Linear, Jira, Auth0, Datadog all lack a `risk_rules/*.py`
  module). It is **not fixed in this pass** — building a bespoke
  `risk_rules/sendgrid.py` is a large, cross-cutting change that would be
  arbitrary to apply to SendGrid alone while ten sibling providers remain
  unfixed. Flagged here for awareness; the Security Findings system (which
  is what actually drives "Configuration Risk" detection and evaluates
  every snapshot record independently of the Changes/diff pipeline) is
  unaffected by this gap and works correctly today.

## Totals

| Metric | Count |
|---|---|
| Test cases reviewed in this matrix | 20 |
| PASS | 17 |
| FAIL | 0 |
| GAP (fixed in this pass) | 1 (diff tracking, rows A/E/I below) |
| N/A (not modeled, correctly absent) | 2 (rows L, M) |

## Test matrix

| # | Test case | Record type | Field(s) | Change simulated | Expected detection | Actual detection (before fix) | Actual detection (after fix) | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes / fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A | API key scope broadening | `sendgrid_api_key` | `has_full_access` | `False → True` | Change detected + high finding | Finding fired (findings evaluate current state, not diff); **Change never generated** | Change detected AND finding fires | high | high | `sendgrid_api_key_broad_scopes` | `TestApiKeyNormalization`, `TestSendGridRuleRegistration`, new `test_api_key_broad_scope_change_produces_drift_change` | **PASS (after fix)** | Diff-tracking gap fixed in this pass; finding logic and severity were already correct |
| B | API key restricted / least-privilege | `sendgrid_api_key` | `has_full_access` | `True → False` | No high finding; Change detected | Change never generated (same gap as A) | Change detected; finding clears | none (improvement) | none | — | Covered by A's fix (symmetric field) | PASS | No dedicated "restriction" rule needed — absence of the broad-scope finding on next evaluation is the correct signal |
| C | API key deleted/disabled | `sendgrid_api_key` | whole record | record removed | "removed" Change | Detected — add/remove doesn't depend on tracked fields | Detected (unchanged) | not modeled as a distinct severity rule | n/a | — | Covered by `build_record_index`/`compute_diff` add/remove path (provider-agnostic) | PASS | SendGrid API keys have no "disabled" state in the API (only exist/deleted) — correctly modeled as a removed record, not a separate rule |
| D | Event webhook enabled/disabled | `sendgrid_webhook_settings` | `event_webhook_enabled` | `True → False` | Change detected + medium finding | Finding fired; Change never generated (same gap) | Change detected AND finding fires | medium | medium | `sendgrid_event_webhook_disabled` | `TestWebhookSettingsNormalization`, M80B tests | **PASS (after fix)** | Diff-tracking gap fixed; classification already correct |
| E | Event webhook signing disabled | `sendgrid_webhook_settings` | `event_webhook_signed` | `True → False` (enabled + has URL) | Change detected + finding | Finding fired; Change never generated | Change detected AND finding fires | high per task's suggested convention; **medium** per this project's calibrated severity | medium | `sendgrid_event_webhook_not_signed` | new `test_webhook_signing_disabled_change_produces_drift_change`; M80C QA tests | PASS | Severity is `medium`, not `high`. Reviewed and **not changed** — this rule was explicitly calibrated in M80C QA (comment references "M80C QA"), and the risk profile genuinely differs from a transport-layer TLS-disable (GitHub's analogous `insecure_ssl` rule): SendGrid's "not signed" is a spoofing-verification gap on an otherwise-HTTPS channel, not a cleartext-transport exposure. Flagging as a defensible existing choice, not a bug |
| F | Sender authentication verified/unverified | `sendgrid_sender_identity` | `verified` | `True → False` | medium finding | Fires correctly | Fires correctly (unaffected by diff bug for findings; Change now also detected) | medium | medium | `sendgrid_sender_identity_unverified` | `TestSenderIdentityNormalization`, M80B tests | PASS | — |
| G | Domain authentication verified/unverified | `sendgrid_domain_authentication` | `valid` | `True → False` | medium/high finding | Fires correctly | Fires correctly | medium (high if `default=True`) | medium (`sendgrid_domain_authentication_invalid`); high when the domain is also the default (`sendgrid_default_domain_authentication_invalid`) | `sendgrid_domain_authentication_invalid` / `sendgrid_default_domain_authentication_invalid` | `TestDomainAuthNormalization`, M80B/M80C tests | PASS | Correctly differentiates default vs. non-default domain severity |
| H | Link branding verified/unverified | `sendgrid_domain_authentication` | `automatic_security`, `legacy` | toggle | low/medium finding | Fires correctly | Fires correctly | low/medium | medium (`automatic_security` disabled) / low (`legacy`) | `sendgrid_domain_automatic_security_disabled` / `sendgrid_domain_authentication_legacy` | M80B/M80C tests | PASS | SendGrid has no API-distinct "link branding" resource separate from domain authentication (`whitelabel/domains` covers both) — these two fields are the correct proxy; nothing to add |
| I | Click tracking enabled/disabled | `sendgrid_tracking_settings` | `click_tracking_enabled` | `False → True` | Change detected + low finding | Finding fired; Change never generated (same gap) | Change detected AND finding fires | low | low | `sendgrid_click_tracking_enabled` | `TestTrackingSettingsNormalization`; new `test_click_tracking_enabled_change_produces_drift_change` | **PASS (after fix)** | Wording correctly framed as configuration/privacy posture, not breach language |
| J | Open tracking enabled/disabled | `sendgrid_tracking_settings` | `open_tracking_enabled` | `False → True` | low finding | Fires correctly | Fires correctly; Change now also detected | low | low | `sendgrid_open_tracking_enabled` | `TestTrackingSettingsNormalization`, M80B tests | PASS | — |
| K | Subscription tracking enabled/disabled | `sendgrid_tracking_settings` | `subscription_tracking_enabled` | `True → False` | medium finding (disabling removes required unsubscribe link) | Fires correctly | Fires correctly; Change now also detected | medium | medium | `sendgrid_subscription_tracking_disabled` | `TestTrackingSettingsNormalization`, M80B tests | PASS | Only fires on disable, not enable — correct direction (enabling is the compliant default) |
| L | Teammate/subuser/admin access | n/a | n/a | n/a | n/a | not modeled | not modeled | n/a | n/a | n/a | n/a | **N/A** | SendGrid Teammates/Subusers API is not fetched by the connector. Not invented in this pass per instructions (no existing evidence to build a rule from); would require a new connector endpoint + fail-soft handling + full rule if added later |
| M | IP access management / allowed IPs | n/a | n/a | n/a | n/a | not modeled | not modeled | n/a | n/a | n/a | n/a | **N/A** | SendGrid IP Access Management API is not fetched. Same rationale as L |
| N | Unknown/missing fields never trigger a high finding | all 7 rule-bearing record types | any tri-state field | field absent (`None`) | no finding | Every check uses `is True` / `is False` / `is not True` / `is not False` explicit tri-state comparisons — confirmed by direct source read across all 27 checks | unchanged | none | none | all | M80B/M80C "unknown does not fire" tests present for each rule | PASS | Consistent explicit tri-state pattern throughout — spot-verified `_check_event_webhook_disabled`, `_check_api_key_broad_scopes`, `_check_event_webhook_not_signed` directly; none default an absent field to a risky state |
| O | 403/404 fail-soft on optional endpoints | `sendgrid_api_key`, `sendgrid_sender_identity`, `sendgrid_domain_authentication`, `sendgrid_mail_settings`, `sendgrid_tracking_settings`, `sendgrid_webhook_settings`, `sendgrid_suppression_settings` | n/a | endpoint returns 403 or 404 | sync continues, surface returns empty/`None`, no other record type affected | Confirmed by direct source read: every `_fetch_*` optional-surface method catches `ConnectorError` and returns `[]`/`None` for status codes 403/404, re-raising for anything else | unchanged | n/a | n/a | n/a | `TestErrorHandling` (M80A) | PASS | Only `_fetch_account` is required (re-raises on any error) — correct, since account is the cheapest universal probe and credential-validation anchor |
| P | Domain DNS records missing | `sendgrid_domain_authentication` | `dns_record_count` | `> 0 → 0` | medium finding | Fires correctly | Fires correctly; Change now also detected | medium | medium | `sendgrid_domain_dns_records_missing` | M80C tests | PASS | — |
| Q | Sender reply-to domain mismatch | `sendgrid_sender_identity` | `from_email_domain` vs `reply_to_domain` | domains differ | low finding | Fires correctly | Fires correctly | low | low | `sendgrid_sender_identity_reply_domain_mismatch` | M80C tests | PASS | — |
| R | Inbound Parse enabled / raw email / spam-check disabled | `sendgrid_webhook_settings` | `inbound_parse_enabled`, `inbound_parse_send_raw_enabled`, `inbound_parse_spam_check_enabled` | toggle | medium finding each | Fires correctly | Fires correctly; Change now also detected (all 3 fields tracked) | medium | medium | `sendgrid_inbound_parse_enabled` / `sendgrid_inbound_parse_raw_email_enabled` / `sendgrid_inbound_parse_spam_check_disabled` | M80C tests | PASS | Hostname/URL from parse configs never stored — verified at connector level |
| S | Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | all 27 rule keys present everywhere with matching severities | Verified via exact set diff: `security_rules/sendgrid.py` (27) vs. `security_rule_registry.py` (27), `security_rule_pack.py` (27), `security_rule_confidence.py` (27), `security_coverage_service.py` `RULE_RECORD_TYPES` (27), `securityRuleCatalog.ts` (27) | zero diffs across all five | n/a | n/a | all | `TestSendGridRuleRegistration`, `TestSendGridFrontendCatalogParity` | PASS | No stale keys, no missing keys, no severity mismatches found |
| T | Diff-tracked fields present for all 8 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 8 record types tracked** | **8 of 8 record types tracked** | n/a | n/a | n/a | new `TestSendGridDiffTrackedFields` (6 tests) | **PASS (after fix)** | The core fix of this QA pass — see Summary |

## Fixes made

1. **`backend/app/services/diff_service.py`** — added `_SENDGRID_TRACKED_FIELDS_BY_TYPE`
   (all 8 record types, every non-identity field) and wired the `sendgrid_`
   prefix into `_tracked_fields_for`'s dispatch chain. Updated the function's
   docstring to document the new branch.
2. **`backend/tests/test_milestone80a_sendgrid_drift_provider_foundation.py`** —
   added `TestSendGridDiffTrackedFields` (6 tests): entry-completeness check
   for all 8 record types, a check that no SendGrid type falls through to the
   Cloudflare default tuple, three `compute_diff` regression tests (API key
   scope, webhook signing, click tracking), and a no-spurious-change sanity
   test.

## Not fixed in this pass (explicitly out of scope)

- **`risk_rules/sendgrid.py` does not exist** — SendGrid Changes fall back to
  the Cloudflare DNS classifier for `risk_level`/`risk_reason` on the Changes
  timeline. This is a pre-existing gap shared by ~10 providers added after
  GitLab/Terraform Cloud (Azure, GCP, Twilio, SendGrid, Clerk, PagerDuty,
  Linear, Jira, Auth0, Datadog). Building a bespoke module for SendGrid alone
  would be inconsistent, unscoped, and a much larger undertaking than this QA
  pass. **Does not block detection** — Security Findings (the system that
  actually powers "Configuration Risk" detection) evaluate every snapshot
  record independently of the Changes/diff pipeline and are unaffected.
- **Teammate/subuser and IP Access Management** — not modeled; no endpoint is
  currently fetched for either, and no existing evidence exists to build a
  rule from. Correctly absent per "do not invent unsupported capabilities."
- **`sendgrid_event_webhook_not_signed` severity** (medium, not high) —
  reviewed against the task's suggested convention and left as-is; see row E.

## Validation run (narrow, foreground only)

```
DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "sendgrid"
# 753 passed, 1 skipped, 16081 deselected (was 747 passed, 1 skipped before this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone80a_sendgrid_drift_provider_foundation.py \
    tests/test_milestone80b_sendgrid_core_security_foundation.py \
    tests/test_milestone80c_sendgrid_mail_webhook_risk_expansion.py \
    tests/test_milestone80d_sendgrid_activity_ingestion.py \
    tests/test_milestone80e_sendgrid_activity_signals.py \
    tests/test_milestone80f_sendgrid_correlations.py \
    tests/test_milestone80g_sendgrid_demo_qa.py \
    tests/test_milestone80h_sendgrid_provider_depth_qa.py \
    tests/test_milestone80i_sendgrid_cross_cloud_ux_polish.py \
    tests/test_sendgrid_provider_depth_qa.py -q
# 736 passed
```
