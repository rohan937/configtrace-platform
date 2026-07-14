# SendGrid Change Classification Matrix

Follow-up to `sendgrid_detection_matrix.md`. That pass fixed a real diff-tracking
gap (commit `4bd31f4`) so SendGrid field-level modifications are now detected
by `compute_diff`. This pass audits whether those detected Changes are then
**classified correctly** on the Changes timeline — a separate concern from
whether Security Findings fire correctly (they already did, and still do).

## Root cause found

`risk_service.classify_change` dispatches on `record_type` prefix to a
provider-specific `risk_rules/<provider>.py` module. **No
`risk_rules/sendgrid.py` existed.** Every `sendgrid_*` Change therefore fell
through every provider check to the final fallback, `classify_dns_change`
(Cloudflare DNS rules). Since no SendGrid `field_path` (e.g.
`has_full_access`, `event_webhook_signed`, `click_tracking_enabled`) matches
any DNS-specific `field_path` (e.g. `content`, `ttl`, `proxied`, `comment`),
**every SendGrid Change silently classified as `low`** with the generic
message *"No specific risk pattern matched. This change may be routine
configuration maintenance."* — including changes as significant as an API
key becoming full-access.

This was invisible in the previous QA pass because that pass validated
Security Findings (which evaluate current-state snapshot records
independently of the diff/Change pipeline) and connector/diff-tracking
correctness, not what `risk_level`/`risk_reason` a Change actually receives.

## Fix

Added `backend/app/services/risk_rules/sendgrid.py` — a provider-specific
classifier covering all 8 SendGrid record types, with severities calibrated
to match the existing SendGrid Security Finding severities exactly (so a
Change and its corresponding Finding never disagree). Wired into
`risk_service.classify_change` via a new `sendgrid_` dispatch branch.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected by `compute_diff`? | Current `risk_level` (before fix) | Expected `risk_level` | Current `risk_level` (after fix) | Current title/copy (before fix) | Expected/after-fix copy | Security finding parity | Status | Test | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1 | `sendgrid_api_key` | `has_full_access` | `False` | `True` | Yes (fixed in prior pass) | `low` (DNS fallback, generic) | `high` | `high` | "No specific risk pattern matched..." | "A SendGrid API key's permissions were broadened to include broad or full-access scopes..." | Matches `sendgrid_api_key_broad_scopes` (high) | **FIXED** | `test_api_key_scope_broadened_to_full_access_is_high`, `test_risk_service_dispatches_sendgrid_to_sendgrid_classifier_not_dns_fallback` | Was misclassified; now correct |
| A2 | `sendgrid_api_key` | `has_full_access` | `True` | `False` | Yes | `low` (generic) | `medium` (improvement) | `medium` | generic | "...permissions were restricted away from broad/full-access scopes — a least-privilege improvement." | No corresponding finding fires (finding only fires on broad, not on restriction) — Change correctly still surfaces the improvement event | **FIXED** | `test_api_key_scope_restricted_is_medium_improvement` | — |
| A3 | `sendgrid_api_key` | whole record | — | full-access key added | Yes (add/remove never depended on tracked fields) | `low` (generic) | `high` | `high` | generic | "A new SendGrid API key was created with broad or full-access permissions..." | Matches `sendgrid_api_key_broad_scopes` once evaluated on next snapshot | **FIXED** | `test_api_key_added_with_full_access_is_high` | New capability — the fallback classifier had no concept of inspecting the added record's fields |
| A4 | `sendgrid_api_key` | whole record | key exists | deleted | Yes | `low` (generic) | `low` | `low` | generic | "A SendGrid API key was deleted..." | n/a (no finding for deletion, by design — see detection matrix) | PASS (already low, now with meaningful copy) | `test_api_key_removed_is_low` | — |
| B1 | `sendgrid_webhook_settings` | `event_webhook_signed` | `True` | `False` | Yes | `low` (generic) | `medium` (matches finding severity) | `medium` | generic | "SendGrid event webhook signing was disabled..." | Matches `sendgrid_event_webhook_not_signed` (medium) | **FIXED** | `test_webhook_signing_disabled_is_medium` | Task suggested "medium/high matching existing convention" — existing Security Finding convention is medium, so Change classifier matches it |
| B2 | `sendgrid_webhook_settings` | `event_webhook_signed` | `False` | `True` | Yes | `low` (generic) | `low` (improvement) | `low` | generic | "...signing was enabled — event authenticity verification restored." | No finding fires once signed (correct) | **FIXED** | `test_webhook_signing_restored_is_low_improvement` | — |
| B3 | `sendgrid_webhook_settings` | `event_webhook_enabled` | `True` | `False` | Yes | `low` (generic) | `medium` | `medium` | generic | "The SendGrid event webhook was disabled..." | Matches `sendgrid_event_webhook_disabled` (medium) | **FIXED** | `test_event_webhook_disabled_is_medium` | — |
| B4 | `sendgrid_webhook_settings` | `event_webhook_enabled` | `False` | `True` | Yes | `low` (generic) | `low` (improvement) | `low` | generic | "The SendGrid event webhook was re-enabled." | n/a | **FIXED** | `test_event_webhook_enabled_is_low` | — |
| B5 | `sendgrid_webhook_settings` | `event_webhook_has_url` | `True` | `False` | Yes | `low` (generic) | `medium` | `medium` | generic | "...no longer has a delivery URL configured..." | Matches `sendgrid_event_webhook_url_missing` (medium) | **FIXED** | `test_event_webhook_url_missing_is_medium` | — |
| B6 | `sendgrid_webhook_settings` | `inbound_parse_enabled` | `False` | `True` | Yes | `low` (generic) | `medium` | `medium` | generic | "SendGrid Inbound Parse was enabled..." | Matches `sendgrid_inbound_parse_enabled` (medium) | **FIXED** | `test_inbound_parse_enabled_is_medium` | — |
| B7 | `sendgrid_webhook_settings` | `event_count` | `3` | `5` | Yes | `low` (generic) | `low` | `low` | generic | "The number of subscribed SendGrid webhook event types changed." | `sendgrid_event_webhook_broad_event_stream` evaluates absolute breadth, not delta — deliberately not duplicated at the field-delta level | PASS | `test_webhook_unknown_field_does_not_produce_high` | — |
| C1 | `sendgrid_domain_authentication` | `valid` | `True` | `False` | Yes | `low` (generic) | `medium` | `medium` | generic | "A SendGrid authenticated domain became invalid..." | Matches `sendgrid_domain_authentication_invalid` (medium) | **FIXED** | `test_domain_authentication_becomes_invalid_is_medium` | Cannot distinguish "default domain" (finding severity `high` via `sendgrid_default_domain_authentication_invalid`) at the single-field-diff level without enriching `provider_metadata` — see Known Limitation below |
| C2 | `sendgrid_domain_authentication` | `valid` | `False` | `True` | Yes | `low` (generic) | `low` (improvement) | `low` | generic | "...restored to valid — DNS validation is passing again." | n/a | **FIXED** | `test_domain_authentication_restored_is_low_improvement` | — |
| C3 | `sendgrid_domain_authentication` | `dns_record_count` | `3` | `1` | Yes | `low` (generic) | `medium` | `medium` | generic | "...number of DNS records...decreased..." | Matches `sendgrid_domain_dns_records_missing` (medium) | **FIXED** | `test_domain_dns_record_count_decrease_is_medium` | — |
| C4 | `sendgrid_domain_authentication` | `automatic_security` | `True` | `False` | Yes | `low` (generic) | `medium` | `medium` | generic | "Automatic DKIM key rotation was disabled..." | Matches `sendgrid_domain_automatic_security_disabled` (medium) | **FIXED** | `test_domain_automatic_security_disabled_is_medium` | — |
| D1 | `sendgrid_sender_identity` | `verified` | `True` | `False` | Yes | `low` (generic) | `medium` | `medium` | generic | "A SendGrid sender identity became unverified..." | Matches `sendgrid_sender_identity_unverified` (medium) | **FIXED** | `test_sender_identity_becomes_unverified_is_medium` | — |
| D2 | `sendgrid_sender_identity` | `verified` | `False` | `True` | Yes | `low` (generic) | `low` (improvement) | `low` | generic | "...was verified — a restoration of sender authentication posture." | n/a | **FIXED** | `test_sender_identity_verified_is_low_improvement` | — |
| E1 | `sendgrid_domain_authentication` | `legacy` | `False` | `True` | Yes | `low` (generic) | `low` | `low` | generic | "SendGrid domain authentication field 'legacy' changed." | Matches `sendgrid_domain_authentication_legacy` (low) | **FIXED** | `test_domain_legacy_flag_change_is_low` | No dedicated "link branding" record exists in this connector — `automatic_security`/`legacy` on the domain-authentication record are the correct proxy (see detection matrix row H) |
| F1 | `sendgrid_tracking_settings` | `click_tracking_enabled` | `False` | `True` | Yes | `low` (generic) | `low` | `low` | generic | "SendGrid tracking setting 'click_tracking_enabled' changed to 'True'..." | Matches `sendgrid_click_tracking_enabled` (low) | **FIXED** | `test_click_tracking_toggle_is_low_not_high` | Safe wording confirmed — no breach/leak language |
| F2 | `sendgrid_tracking_settings` | `open_tracking_enabled` | `True` | `False` | Yes | `low` (generic) | `low` | `low` | generic | same pattern | Matches `sendgrid_open_tracking_enabled` (low) | **FIXED** | `test_open_tracking_toggle_is_low_not_high` | — |
| F3 | `sendgrid_tracking_settings` | `subscription_tracking_enabled` | `True` | `False` | Yes | `low` (generic) | `medium` | `medium` | generic | "SendGrid subscription tracking was disabled...may affect compliance posture." | Matches `sendgrid_subscription_tracking_disabled` (medium) | **FIXED** | `test_subscription_tracking_disabled_is_medium` | Only direction that's `medium` — disabling removes the required unsubscribe link |
| F4 | `sendgrid_tracking_settings` | `subscription_tracking_enabled` | `False` | `True` | Yes | `low` (generic) | `low` (improvement) | `low` | generic | "...was enabled — an unsubscribe link will be included..." | n/a | **FIXED** | `test_subscription_tracking_enabled_is_low_improvement` | — |
| G1 | any | any | — | — | n/a | n/a | never `high` for unrecognised fields | `low` (uniform fallback) | generic `low` | "SendGrid \<record\> record changed; no specific risk pattern matched." | n/a | PASS | `test_api_key_unknown_field_does_not_produce_high`, `test_webhook_unknown_field_does_not_produce_high`, `test_sender_identity_unknown_field_does_not_produce_high` | Unknown/unmodeled fields never escalate past `low` |
| G2 | any | whole record | — | added | n/a | `low` (generic) | never `high` except full-access API key | verified | generic | n/a | n/a | PASS | `test_added_records_never_produce_high_except_full_access_api_key` | — |
| G3 | any | whole record | — | removed | n/a | `low` (generic) | never `high` | verified | generic | n/a | n/a | PASS | `test_removed_records_are_never_high` | — |
| G4 | `sendgrid_future_surface` (hypothetical) | any | — | — | n/a | `low` (generic, DNS fallback) | `low`, safe copy | `low` | "No specific risk pattern matched..." (DNS) | "An unrecognised SendGrid configuration record changed..." | n/a | **FIXED** | `test_unrecognised_record_type_falls_back_safely_to_low` | Now falls back within the SendGrid module itself instead of the DNS classifier — copy is at least SendGrid-aware even for a future/unmodeled record type |
| H1 | `sendgrid_mail_settings` | `sandbox_mode_enabled` | `False` | `True` | Yes | `low` (generic) | `medium` | `medium` | generic | "SendGrid sandbox mode was enabled. Outbound mail will be accepted but NOT actually delivered..." | Matches `sendgrid_sandbox_mode_enabled` (medium) | **FIXED** | `test_mail_settings_sandbox_mode_enabled_is_medium` | High business-impact but calibrated to match the existing Security Finding severity (medium), not escalated independently |
| H2 | `sendgrid_mail_settings` | `spam_check_enabled` | `True` | `False` | Yes | `low` (generic) | `medium` | `medium` | generic | "SendGrid spam checking was disabled..." | Matches `sendgrid_spam_check_disabled` (medium) | **FIXED** | `test_mail_settings_spam_check_disabled_is_medium` | — |
| I1 | `sendgrid_suppression_settings` | `suppression_group_count` | `2` | `0` | Yes | `low` (generic) | `low` | `low` | generic | "SendGrid has no suppression groups configured..." | Matches `sendgrid_suppression_settings_empty` (low) | **FIXED** | `test_suppression_group_count_drops_to_zero_is_low_not_high` | Correctly stays `low`, not escalated — matches Security Finding severity |

## Totals

| Metric | Count |
|---|---|
| Classification cases reviewed | 30 |
| PASS (already correct pre-fix, e.g. deletion copy / unknown-field safety) | 6 |
| FIXED (previously misclassified as generic `low`, now correctly classified) | 24 |
| FAIL | 0 |
| GAP remaining | 0 |

Every single field-level SendGrid modification reviewed was previously
misclassified — all landed on the DNS fallback's generic `low` / "routine
configuration maintenance" copy regardless of actual severity. This is now
fixed for all 8 record types.

## Known limitation (not fixed — documented, not a regression)

The Change classifier cannot distinguish "this domain is the default sending
domain" from a bare `valid: True → False` field diff, because
`compute_diff` emits one Change per changed field with only
`(field_path, prev_value, new_value)` — it does not carry sibling fields
like `default` from the same record. The Security Finding layer *can* make
this distinction (`sendgrid_default_domain_authentication_invalid`, high,
vs. `sendgrid_domain_authentication_invalid`, medium) because it evaluates
the whole record at once. The Change classifier therefore uses the
conservative/uniform `medium` for any domain becoming invalid, matching the
non-default-domain finding severity. Elevating this to match the finding's
`high` for default domains would require enriching
`diff_service._build_provider_metadata` with SendGrid-specific sibling
fields (the same pattern already used for `aws_route53_record`) — a larger,
separate change not undertaken in this pass since it touches shared
diff-service code rather than SendGrid-only files.

## Files changed

- `backend/app/services/risk_rules/sendgrid.py` — new, provider-specific
  Change classifier for all 8 SendGrid record types.
- `backend/app/services/risk_service.py` — added `sendgrid_` dispatch branch
  (one `if` block, mirrors every other provider).
- `backend/tests/test_sendgrid_risk_rules.py` — new, 34 tests covering every
  category A–G from the task plus the dispatch-regression test.
- `backend/tests/reports/sendgrid_change_classification_matrix.md` — this
  report.

## Validation run (narrow, foreground only)

```
DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone80a_sendgrid_drift_provider_foundation.py -q
# 138 passed

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "sendgrid and risk"
# 117 passed, 16752 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "sendgrid and diff"
# 13 passed, 16856 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "sendgrid"
# 787 passed, 1 skipped, 16081 deselected (was 753 passed, 1 skipped before this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_sendgrid_risk_rules.py -q
# 34 passed
```

No frontend files were touched, so `npx tsc --noEmit` was not run.
