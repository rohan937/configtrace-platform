# PagerDuty Detection QA Matrix

Exhaustive end-to-end validation of the PagerDuty provider (connector →
diff tracking → risk classification → security findings → registries →
frontend catalog), following the same methodology established for
SendGrid, Twilio, Terraform Cloud, GitLab, Jira, and Linear in prior QA
passes.

## Summary

PagerDuty's connector (`app/connectors/pagerduty.py`), schema
(`pagerduty_schema.py`), and security rules (`security_rules/pagerduty.py`,
40 rules across all 8 record types) were already mature. As with Linear's
equivalent pass, **registries and the frontend catalog were already in
perfect parity (40/40, zero severity mismatches)** — no fixes needed
there. The two recurring root-cause bugs from every prior provider pass
were both present here, and both are the primary fixes in this pass:

1. **`risk_rules/pagerduty.py` did not exist at all.** `risk_service.py`
   had no `pagerduty_` dispatch branch, so **every PagerDuty configuration
   change silently fell through to the Cloudflare DNS classifier**. Built
   the module from scratch (8 record-type classifiers) and wired the
   dispatch.

2. **Diff/drift tracking gap.** PagerDuty had **zero entries** in
   `diff_service.py`'s per-provider tracked-fields dispatch, so every
   PagerDuty record type fell through to the Cloudflare DNS default tuple
   (`name`, `content`, `ttl`, `proxied`, `priority`, `comment` — none of
   which exist on any PagerDuty record). `compute_diff` could never detect
   a modified field on an existing PagerDuty record. Fixed by adding
   `_PAGERDUTY_TRACKED_FIELDS_BY_TYPE` (all 8 record types) and wiring the
   `pagerduty_` prefix into `_tracked_fields_for`.

No new Security Finding rules were needed or added — the existing 40 rules
already cover every field this pass identified as security-relevant, and
the new Change classifier's severities were derived directly from them
(see the parity table below).

## Connector extraction review

| Record type | Source endpoint | Sensitive values excluded? | Fail-soft on error? | Stable record IDs? |
|---|---|---|---|---|
| `pagerduty_service` | `GET /services` (required anchor surface) | Yes — see privacy notes below | N/A (required, propagates on failure like every other provider's primary surface) | Yes — service `id` |
| `pagerduty_escalation_policy` | `GET /escalation_policies` (required) | Yes — target counts derived then IDs/names/emails discarded | N/A (required) | Yes — policy `id` |
| `pagerduty_schedule` | `GET /schedules` (required) | Yes — user identities collected into a `set()` for counting only, never stored | N/A (required) | Yes — schedule `id` |
| `pagerduty_service_integration` | `GET /services/{id}/integrations` (per service) | Yes — key/routing-key values reduced to presence booleans | Yes — `_fetch_service_integrations` explicitly `continue`s on 403/404, raises only on 401/429 | Yes — integration `id` |
| `pagerduty_webhook_subscription` | `GET /webhook_subscriptions` (optional, V3 API) | Yes — delivery URL reduced to scheme category, secret never fetched at all (PagerDuty's webhook API doesn't return secret values) | Yes — `_fetch_webhook_subscriptions` wraps in `except ConnectorError: return []` | Yes — subscription `id` |
| `pagerduty_event_orchestration` | `GET /event_orchestrations` (optional, plan-gated) | Yes — routing expressions/condition logic never fetched | Yes — same `except ConnectorError: return []` pattern | Yes — orchestration `id` |
| `pagerduty_business_service` | `GET /business_services` (optional, plan-gated) | Yes — subscriber lists/contact info never fetched | Yes | Yes — business service `id` |
| `pagerduty_response_play` | `GET /response_plays` (optional, plan-gated) | Yes — responder/subscriber identities and conference numbers reduced to counts/presence booleans | Yes | Yes — response play `id` |

**Confirmed via code inspection** (connector class docstring + normalizer
bodies + `list_activity_events` docstring):
- No **incident contents/details** are stored — the connector has no
  incident-detail endpoint call at all.
- No **alert payloads** are stored — no alerts endpoint is fetched.
- No **API token values** are stored — `_make_client()`'s `api_token`
  parameter is used only in the `Authorization` header, built fresh per
  call, never persisted as an instance attribute or copied into a record.
- No **webhook secrets** are stored — PagerDuty's webhook subscription API
  doesn't return the secret value at all; only `delivery_method.url` and
  `.custom_headers` are read, and both are reduced to safe derived
  booleans/categories (`delivery_url_scheme_category`,
  `has_custom_headers`) before the raw values go out of scope.
- No **full webhook URLs** are stored — same pattern as above via
  `_url_scheme_category()`.
- No **user PII** (emails, names, phone numbers, contact methods) is
  stored — schedule user identities are only used to build a `set()` for
  `len()` counting (`user_count`), never retained; escalation policy
  targets are counted by type category, never by ID or name.
- No **customer incident data** beyond configuration metadata is stored —
  confirmed by the absence of any incidents/alerts/log-entries endpoint
  call anywhere in the connector.
- No **integration keys or routing keys** are stored — `has_integration_key`/
  `routing_key_present` are derived via `bool(raw.get(...))` and the raw
  key values are never assigned to any record field.

## Diff/change tracking review

**Before this pass**: 0 of 8 record types had a tracked-fields entry — all
PagerDuty modified-field changes silently fell through to the Cloudflare
DNS default tuple and were never detected.

**After this pass**: all 8 record types are tracked with every
security-relevant field verified present, including all the task's
high-priority fields: `escalation_policy_id` (service linkage),
`escalation_rule_count`/`target_count` (escalation policy coverage),
`layer_count`/`user_count` (schedule on-call coverage),
`alert_creation_category`, `auto_resolve_timeout_category`/
`acknowledgement_timeout_category`, `has_integration_key`/
`routing_key_present`, `active`/`delivery_url_scheme_category`/
`has_custom_headers` (webhook posture).

No fields were found that are tracked but no longer emitted by the
connector — the tracked tuples were built directly from
`pagerduty_schema.py`'s `TypedDict` definitions, cross-referenced against
the connector's actual normalizer output.

## Test matrix

| Test case | Normalized record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes/fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. Admin/owner/user count | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | PagerDuty's API surface queried by this connector has no account-wide user/admin-role endpoint; only per-schedule `user_count` (aggregate, no role breakdown) and per-escalation-policy target counts are fetched |
| B. Team/member count | `pagerduty_service`, `pagerduty_escalation_policy`, `pagerduty_schedule` | `team_count` | count change | Change (low) + Finding (low, `*_no_teams`) | Change never generated before fix (diff-tracking gap) | low | low (after fix) | `pagerduty_service_no_teams`, `pagerduty_ep_no_team_targets`, `pagerduty_schedule_no_teams` (all low) — matches | new `TestPagerDutyDiffTrackedFields` sweep | **FIXED** | No per-team membership-count endpoint is fetched; `team_count` is an aggregate ownership count on each of the three record types |
| C. Escalation policy rule count increased/decreased | `pagerduty_escalation_policy` | `escalation_rule_count` | `2 → 0` | Change (high) + Finding (high, `pagerduty_ep_no_rules`) | Change never generated before fix | high | high (after fix) | `pagerduty_ep_no_rules` (high) — matches | new `test_escalation_policy_zero_rules_is_high` | **FIXED** | — |
| D. Escalation policy target count increased/decreased | `pagerduty_escalation_policy` | `target_count` | `3 → 0` (zero) / `3 → 1` (low, nonzero) | Change (high on zero / medium on low-nonzero decrease) + Finding (`pagerduty_ep_no_targets` high / `pagerduty_ep_low_target_count` medium) | Change never generated before fix | high / medium | high / medium (after fix) | `pagerduty_ep_no_targets` (high), `pagerduty_ep_low_target_count` (medium) — matches both | new `test_escalation_policy_zero_targets_is_high` | **FIXED** | — |
| E. Escalation policy loses all targets/coverage | `pagerduty_escalation_policy` | `escalation_rule_count`, `target_count` | dropped to zero | Change (high) + Finding (high) | Change never generated before fix | high | high (after fix) | `pagerduty_ep_no_rules`, `pagerduty_ep_no_targets` (both high) — matches | see C/D above | **FIXED** | Folded into C/D — same underlying fields |
| F. Schedule/on-call coverage decreased/increased | `pagerduty_schedule` | `user_count` | `2 → 0` (zero) / `5 → 2` (decrease, nonzero) | Change (high on zero / medium on decrease) + Finding (`pagerduty_schedule_no_targets` high / `pagerduty_schedule_low_target_count` medium) | Change never generated before fix | high / medium | high / medium (after fix) | `pagerduty_schedule_no_targets` (high), `pagerduty_schedule_low_target_count` (medium) — matches both | new `test_schedule_zero_users_is_high` | **FIXED** | — |
| G. Service escalation policy removed/changed | `pagerduty_service` | `escalation_policy_id` | present → empty (removed) / reassigned to a different policy | Change (high on removal / medium on reassignment) + Finding (high, `pagerduty_service_no_escalation_policy`) | Change never generated before fix | high / medium | high / medium (after fix) | `pagerduty_service_no_escalation_policy` (high) — matches the removal case; reassignment has no dedicated Finding (current-state Finding can't distinguish "always had a policy" from "was reassigned") | new `test_service_loses_escalation_policy_is_high`, `test_escalation_policy_id_change_produces_drift_change` | **FIXED** | — |
| H. Service alert creation setting changed | `pagerduty_service` | `alert_creation_category` | `"alerts_and_incidents" → "incidents_only"` | Change (low) + Finding (low, `pagerduty_service_alert_creation_limited`) | Change never generated before fix | low | low (after fix) | `pagerduty_service_alert_creation_limited` (low) — matches | covered by tracked-field sweep | **FIXED** | — |
| I. Auto-resolve/acknowledgement timeout weakened | `pagerduty_service` | `auto_resolve_timeout_category`, `acknowledgement_timeout_category` | `"medium" → "disabled"` | Change (medium) + Finding (medium, both `*_disabled` rules) | Change never generated before fix | medium | medium (after fix) | `pagerduty_service_auto_resolve_disabled`, `pagerduty_service_ack_timeout_disabled` (both medium) — matches | covered by tracked-field sweep | **FIXED** | — |
| J. Integration enabled/disabled | `pagerduty_service_integration` | `has_integration_key`, `routing_key_present` | `True → False` | Change (medium) + Finding (medium, `pagerduty_integration_missing_key`/`_routing_key_missing`) | Change never generated before fix | medium | medium (after fix) | both medium — matches | new `test_integration_key_removed_is_medium` | **FIXED** | PagerDuty integrations don't expose a separate `enabled`/`disabled` boolean — key presence is the closest analog this connector can observe |
| K. Webhook enabled/disabled | `pagerduty_webhook_subscription` | `active` | `True → False` | Change (medium) + Finding (medium, `pagerduty_webhook_inactive`) | Change never generated before fix | medium | medium (after fix) | `pagerduty_webhook_inactive` (medium) — matches | covered by tracked-field sweep | **FIXED** | — |
| L. Webhook HTTP/HTTPS scheme | `pagerduty_webhook_subscription` | `delivery_url_scheme_category` | `"https" → "http"` | Change (high) + Finding (high, `pagerduty_webhook_non_https`) | Change never generated before fix | high | high (after fix) | `pagerduty_webhook_non_https` (high) — matches | new `test_webhook_http_scheme_is_high`, `test_webhook_https_restored_is_low` | **FIXED** | — |
| M. Webhook signing/secret posture | `pagerduty_webhook_subscription` | `has_custom_headers` | `True → False` | Change (medium) + Finding (medium, `pagerduty_webhook_secret_not_indicated`) | Change never generated before fix | medium | medium (after fix) | `pagerduty_webhook_secret_not_indicated` (medium) — matches | covered by tracked-field sweep | **FIXED** | PagerDuty's webhook API never exposes whether signing/secrets are configured directly — `has_custom_headers` is the closest observable proxy the connector already fetches |
| N. Maintenance window added/removed/broadened | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | No maintenance-windows endpoint is fetched by this connector. Not invented per task instructions |
| O. API key/token metadata posture | n/a | n/a | n/a | n/a | not modeled beyond integration key/routing key presence booleans (covered by J) | n/a | n/a | n/a | n/a | **PASS (covered by J)** | n/a | PagerDuty account-level API-key metadata (creation date, last-used, scopes) is not exposed by any endpoint this connector queries; the closest analog already covered is per-integration key presence |
| P. Unknown/missing fields never produce high findings | all 8 record types | any | `None`/missing | no high finding/classification | Confirmed — every Finding check in `security_rules/pagerduty.py` uses explicit boolean/category-string equality, and every new Change classifier branch falls to `low` on unparseable/missing values via `_int_pair`'s `try/except` guard or an explicit "unknown or missing" branch | none | none | all | new `test_every_tracked_field_classifies_without_error_or_invalid_severity`, `test_unknown_transitions_never_produce_high` (4 field/record-type combinations) | PASS | — |
| Q. 403/404 fail-soft on optional endpoints | `pagerduty_service_integration` (per-service), `pagerduty_webhook_subscription`, `pagerduty_event_orchestration`, `pagerduty_business_service`, `pagerduty_response_play` (all four plan-gated) | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed — `_fetch_service_integrations` explicitly `continue`s on 403/404 per service (re-raising only on 401/429); the four optional-surface fetchers each wrap their query in `except ConnectorError: return []` | n/a | n/a | n/a | existing `test_milestone84a` connector tests | PASS | — |
| R. Records with normalized fields but no security rule | none found — every one of the 8 record types has at least one rule, and every tracked field either has a dedicated rule or a documented reason for using the generic fallback (see comparison table below) | n/a | n/a | correctly no gaps | Confirmed — cross-referenced every tracked field against `security_rules/pagerduty.py`'s eval functions | n/a | n/a | n/a | existing `test_pagerduty_provider_depth_qa.py` coverage | PASS | — |
| S. Security rules with no reachable normalized record | — | — | — | — | None found — all 40 rules dispatch from `evaluate()` against one of the 8 record types the connector actually emits | n/a | n/a | all | existing depth-QA reachability tests (all still passing after this pass) | PASS | Zero dead/unreachable rules |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | 40/40 rule keys present everywhere with matching severities | Verified via exact set diff (excluding the 8 `record_id` fallback string false-positives): `security_rules/pagerduty.py` (40) vs. `security_rule_registry.py` (40), `security_rule_pack.py` (40, all severities cross-checked programmatically, zero mismatches), `security_rule_confidence.py` (40), and `securityRuleCatalog.ts` (40) | n/a | n/a | all | none pre-existing; verified via ad hoc scripted diff in this pass | PASS | Zero mismatches — no fix needed (matching Linear's equivalent pass, unlike Jira's, which found 10 severity mismatches and 6 catalog gaps) |
| Diff-tracked fields present for all 8 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 8 record types tracked (before fix)** → **8 of 8 tracked (after fix)** | n/a | n/a | n/a | new `TestPagerDutyDiffTrackedFields` (5 tests) | **FIXED** | Root-cause fix — see Summary #2 |
| Risk classification module exists and is wired | all | all tracked fields | n/a | every Change gets a PagerDuty-specific classification, not the Cloudflare DNS fallback | **module did not exist (before fix)** → **8 classifiers + dispatch wired (after fix)** | n/a | n/a | n/a | new `TestPagerDutyRiskClassifier` (14 tests, including a dispatch-level regression test through `risk_service.classify_change`) | **FIXED** | Summary #1 — the largest fix in this pass |

## Tracked-fields vs. classifier-branch comparison

| Record type | Tracked fields with dedicated classification | Tracked fields using generic fallback (intentional) |
|---|---|---|
| `pagerduty_service` | `escalation_policy_id`, `acknowledgement_timeout_category`, `auto_resolve_timeout_category`, `alert_creation_category`, `integration_count`, `team_count` | `resource_name`, `status_category`, `incident_urgency_rule_type`, `support_hours_enabled`, `scheduled_actions_count` — no dedicated Finding for any of these five |
| `pagerduty_escalation_policy` | `escalation_rule_count`, `target_count`, `escalation_level_count`, `has_schedule_targets`, `team_count` | `resource_name`, `repeat_enabled`, `num_loops`, `on_call_handoff_notifications`, `user_target_count`, `schedule_target_count` — the latter two are the raw counts behind `has_schedule_targets`, which already carries the dedicated signal |
| `pagerduty_schedule` | `user_count`, `layer_count`, `team_count` | `resource_name`, `time_zone_present`, `restriction_count`, `has_restrictions` — `has_restrictions` gets a neutral generic-equivalent branch since its Finding (`no_restrictions`) is a hygiene note, not a directional risk signal |
| `pagerduty_service_integration` | `has_integration_key`, `routing_key_present` | `type_category`, `vendor_name` — both Findings for `type_category` (`email_type`/`unknown_type`) are `low` and match the generic fallback exactly |
| `pagerduty_webhook_subscription` | `active`, `delivery_url_scheme_category`, `has_custom_headers`, `filter_type`, `event_count` | — (full coverage) |
| `pagerduty_event_orchestration` | `route_count` | `resource_name`, `team_present` — `team_present`'s Finding (`no_team`) is `low` and matches the generic fallback |
| `pagerduty_business_service` | — | All 3 tracked fields — both Findings (`no_team`, `no_contact`) are `low` hygiene notes with no directional signal beyond the generic fallback |
| `pagerduty_response_play` | `responder_count`, `runnability` | `resource_name`, `team_present`, `subscriber_count`, `conference_number_present` — `subscriber_count`'s Finding (`no_subscribers`) is `low` and matches the generic fallback |

**Classifier branches referring to fields not emitted by the
connector/schema:** none found — every `fp ==` check in
`risk_rules/pagerduty.py` was written directly against
`pagerduty_schema.py`'s `TypedDict` definitions and cross-verified against
the connector's actual normalizer output.

**Classifier branches referring to old/stale field names:** none — this
is a newly-built module, so there was no legacy field-name drift to
inherit (matching the precedent set by Jira's and Linear's newly-built
modules).

**Fields with similar names that could be confused:** `has_integration_key`
vs. `routing_key_present` (both on `pagerduty_service_integration`) are the
closest pair — both gated by the same medium severity and similar
wording, but each branch names its own field explicitly ("integration key
indicator" vs. "routing key indicator"), so they are not confusable in the
emitted reason text. `team_count` appears on three different record types
(`pagerduty_service`, `pagerduty_escalation_policy`, `pagerduty_schedule`);
each lives in its own record-type classifier function and produces
record-type-specific wording, so there is no cross-record-type confusion.

## Mock-shape (`old_value`/`prev_value`) verification

Since `risk_rules/pagerduty.py` did not exist before this pass, there was
no pre-existing mock-shape bug to find. The module was written to read
`prev_value` directly from the start (matching `compute_diff`'s real
output), and a dedicated regression test
(`test_classifier_reads_real_compute_diff_dict_shape_not_a_mock`) builds a
plain dict shaped exactly like real `compute_diff` output — not a
`MagicMock` — to guard against this exact bug class recurring.

## Fixes made

1. **`backend/app/services/risk_rules/pagerduty.py`** (new file) — 8
   record-type classifiers (`_classify_service_change` through
   `_classify_response_play_change`) plus the `classify_pagerduty_change`
   dispatcher.
2. **`backend/app/services/risk_service.py`** — added the `pagerduty_`
   prefix dispatch branch to `classify_change`, routing PagerDuty changes
   to the new module instead of the Cloudflare DNS fallback.
3. **`backend/app/services/diff_service.py`** — added
   `_PAGERDUTY_TRACKED_FIELDS_BY_TYPE` (all 8 record types) and wired the
   `pagerduty_` prefix into `_tracked_fields_for`. Updated the function's
   docstring.
4. **`backend/tests/test_milestone84a_pagerduty_drift_provider_foundation.py`**
   — added `TestPagerDutyDiffTrackedFields` (5 tests) and
   `TestPagerDutyRiskClassifier` (14 tests, including a dispatch-level
   regression test and a dict-shaped mock-bug-prevention test).
5. **`backend/tests/reports/pagerduty_detection_matrix.md`** — this
   report.

No changes were made to `security_rules/pagerduty.py`, the four backend
registries, or the frontend catalog — all were already correct and in
perfect 40/40 parity with zero severity mismatches.

## Not fixed in this pass (explicitly out of scope)

- **Account-wide admin/owner/user counts** (task category A) — no
  account-level user-role endpoint is fetched.
- **Team membership counts** (task category B) — only per-record team
  *ownership* counts are modeled (a service/policy/schedule belongs to N
  teams), not per-team member rosters.
- **Maintenance windows** (task category N) — no endpoint is fetched.
- **API key/token metadata beyond per-integration key presence** (task
  category O) — no account-level API-key metadata endpoint is fetched.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone84a_pagerduty_drift_provider_foundation.py -q
# 140 passed (was 111 before this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "pagerduty"
# 730 passed, 16364 deselected (was 711 before any fixes in this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*pagerduty* -q
# 714 passed
```

No frontend files were touched in this pass (registries and the frontend
catalog already had perfect parity with zero severity mismatches — no new
Security Finding rule was added or changed), so `npx tsc --noEmit` was not
run.
