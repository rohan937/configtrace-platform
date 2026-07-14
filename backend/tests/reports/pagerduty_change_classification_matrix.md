# PagerDuty Change-Classification QA Matrix

Dedicated follow-up to the detection QA pass committed as `6645c82`
(`pagerduty_detection_matrix.md`), which built `risk_rules/pagerduty.py`
from scratch and added `_PAGERDUTY_TRACKED_FIELDS_BY_TYPE`. Because the
classifier module was newly written and broad, this pass verifies its
quality field-by-field: severity correctness, safe wording, restoration
behavior, and parity with Security Findings.

## Summary

`risk_rules/pagerduty.py` had no `old_value`/`prev_value`-style field-name
bug — it was written from scratch already reading `prev_value` correctly
everywhere, and its test helper already builds plain dicts, not
`MagicMock`. This pass found and fixed **one critical, structural bug** —
more consequential than any single bug found in the three prior
classification-QA passes (Jira, GitLab, Linear), because it produced a
false **high-severity** claim, not just imprecise wording:

**`_int_pair` silently coerced `None`/unknown values to `0`.** Every count
field's zero-detection branch used `int(prev_v or 0), int(new_v or 0)`.
This meant a genuinely unknown/missing new value (e.g. `None`) was
indistinguishable from an explicit `0` — so an unknown transition on
`escalation_rule_count`, `target_count`, `user_count`, `responder_count`,
or `event_count` would be silently reported as **"dropped to zero"** at
`high` or `medium` severity, even though the evidence never actually
confirmed a zero. This is exactly the false-certainty failure mode the
task's category I and item 9 explicitly warn against, and it affected
**every single count-based branch in the module** (11 branches across 6
record types).

Fixed by replacing `_int_pair` with a new `_int_or_none()` helper that
returns `None` (not `0`) for missing/unparseable values, and updating
every count branch to check `n_new is None` first — returning a `low`,
clearly-worded "count is now unknown or missing" response before any
zero/decrease logic runs. The genuine zero-detection path (an explicit
int `0`) was verified to still work correctly after the fix (see
`test_count_fields_explicit_zero_still_fires_correctly`).

No other severity-affecting bugs were found. No new Security Finding
rules were added in this pass — it is scoped to the Change-classification
layer only.

## Classification matrix

| Case | Record type | Field(s) | Old value | New value | Detected by `compute_diff`? | Current risk_level | Expected risk_level | Current title/copy | Expected title/copy | Security finding parity | Status | Test covering it | Notes/fix |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| A1. Escalation policy rule count drops to zero | `pagerduty_escalation_policy` | `escalation_rule_count` | `2` | `0` | yes | high | high | "dropped to zero escalation rules..." | (same) | `pagerduty_ep_no_rules` (high) — matches | PASS | existing `test_escalation_policy_zero_rules_is_high`, new `test_count_fields_explicit_zero_still_fires_correctly` | — |
| A2. Escalation policy rule count: unknown transition | `pagerduty_escalation_policy` | `escalation_rule_count` | `2` | `None` | yes | **was high, falsely claiming "dropped to zero"** | low | ~~"dropped to zero escalation rules — this policy may no longer route to any responder."~~ | "rule count is now unknown or missing." | n/a | **FIXED (severity bug, not just wording)** | new `test_escalation_rule_count_unknown_is_low_not_dropped_to_zero` | The most severe bug in this pass — a false `high` finding on unknown data |
| A3. Escalation policy target count drops to zero | `pagerduty_escalation_policy` | `target_count` | `3` | `0` | yes | high | high | "lost all escalation targets." | (same) | `pagerduty_ep_no_targets` (high) — matches | PASS | existing `test_escalation_policy_zero_targets_is_high` | — |
| A4. Escalation policy target count: unknown transition | `pagerduty_escalation_policy` | `target_count` | `3` | `None` | yes | **was high, falsely claiming "lost all escalation targets"** | low | ~~"lost all escalation targets."~~ | "target count is now unknown or missing." | n/a | **FIXED** | new `test_escalation_target_count_unknown_is_low_not_dropped_to_zero` | Same bug class as A2 |
| A5. Escalation policy target count decreases (nonzero) | `pagerduty_escalation_policy` | `target_count` | `5` | `2` | yes | medium | medium | "target count decreased from 5 to 2..." | (same) | `pagerduty_ep_low_target_count` (medium) — matches | PASS | existing branch, re-verified after fix | — |
| A6. Escalation policy single level | `pagerduty_escalation_policy` | `escalation_level_count` | `3` | `1` | yes | medium | medium | "dropped to a single escalation level." | (same) | `pagerduty_ep_single_level` (medium) — matches | PASS | covered by tracked-field sweep, re-verified after fix | — |
| B1. Schedule on-call users drop to zero | `pagerduty_schedule` | `user_count` | `2` | `0` | yes | high | high | "dropped to zero on-call users — coverage may no longer be defined..." | (same) | `pagerduty_schedule_no_targets` (high) — matches | PASS | existing `test_schedule_zero_users_is_high` | — |
| B2. Schedule on-call users: unknown transition | `pagerduty_schedule` | `user_count` | `2` | `None` | yes | **was high, falsely claiming "dropped to zero on-call users"** | low | ~~"dropped to zero on-call users — coverage may no longer be defined."~~ | "on-call user count is now unknown or missing." | n/a | **FIXED** | new `test_schedule_user_count_unknown_is_low_not_dropped_to_zero` | Same bug class as A2 |
| B3. Schedule on-call coverage decreases (nonzero) | `pagerduty_schedule` | `user_count` | `5` | `2` | yes | medium | medium | "on-call coverage decreased from 5 to 2 users..." | (same) | `pagerduty_schedule_low_target_count` (medium) — matches | PASS | covered by tracked-field sweep, re-verified after fix | — |
| B4. Schedule layer count drops to zero | `pagerduty_schedule` | `layer_count` | `2` | `0` | yes | medium | medium | "dropped to zero layers." | (same) | `pagerduty_schedule_no_layers` (medium) — matches | PASS | covered by tracked-field sweep | — |
| C1. Service loses escalation policy | `pagerduty_service` | `escalation_policy_id` | `"ep1"` | `""` | yes | high | high | "lost its escalation policy linkage — response routing...may no longer be defined." | (same) | `pagerduty_service_no_escalation_policy` (high) — matches | PASS | existing `test_service_loses_escalation_policy_is_high` | — |
| C2. Service gains escalation policy (restoration) | `pagerduty_service` | `escalation_policy_id` | `""` | `"ep1"` | yes | low | low (improvement) | "was assigned an escalation policy." | (same) | n/a | PASS | existing `test_service_gains_escalation_policy_is_low` | — |
| C3. Service escalation policy reassigned | `pagerduty_service` | `escalation_policy_id` | `"ep1"` | `"ep2"` | yes | medium | medium | "response routing changed — its escalation policy linkage was reassigned." | (same) | n/a (Finding is current-state only, can't observe a reassignment) | PASS | covered by existing branch | Confirmed: `escalation_policy_id` is always a non-`None` string from the connector (empty string when absent) — no unknown-transition ambiguity exists for this specific field, unlike the count fields above |
| C4. Service acknowledgement/auto-resolve timeout disabled | `pagerduty_service` | `acknowledgement_timeout_category`, `auto_resolve_timeout_category` | `"medium"` | `"disabled"` | yes | medium | medium | "acknowledgement timeout was disabled." / "auto-resolve timeout was disabled." | (same) | `pagerduty_service_ack_timeout_disabled`, `pagerduty_service_auto_resolve_disabled` (both medium) — matches | PASS | covered by tracked-field sweep | — |
| C5. Service integration count drops to zero | `pagerduty_service` | `integration_count` | `2` | `0` | yes | medium | medium | "integration count dropped to zero." | (same) | `pagerduty_service_no_integrations` (medium) — matches | PASS | covered by tracked-field sweep, re-verified after fix | — |
| C6. Service integration count: unknown transition | `pagerduty_service` | `integration_count` | `2` | `None` | yes | **was medium, falsely claiming "dropped to zero"** | low | ~~"integration count dropped to zero."~~ | "integration count is now unknown or missing." | n/a | **FIXED** | new `test_unknown_transitions_never_produce_high_qa_pass` | — |
| D1. Integration key removed | `pagerduty_service_integration` | `has_integration_key` | `True` | `False` | yes | medium | medium | "lost its integration key indicator." | (same) | `pagerduty_integration_missing_key` (medium) — matches | PASS | existing `test_integration_key_removed_is_medium` | — |
| D2. Integration key restored | `pagerduty_service_integration` | `has_integration_key` | `False` | `True` | yes | low | low (improvement) | "key indicator was added." | (same) | n/a | PASS | covered by existing branch | — |
| D3. Integration key true → unknown | `pagerduty_service_integration` | `has_integration_key` | `True` | `None` | yes | low | low | "key presence is now unknown or missing." | (same) | n/a | PASS | already correct before this pass — boolean fields already used the explicit three-way (falsy/truthy/unknown) pattern | No fix needed — confirmed correct on inspection; the connector's `_bool()` helper also guarantees this field is never actually `None` in real data, but the classifier is still correctly defensive |
| E1. Webhook HTTP scheme | `pagerduty_webhook_subscription` | `delivery_url_scheme_category` | `"https"` | `"http"` | yes | high | high | "delivery URL scheme changed to HTTP (non-encrypted)." | (same) | `pagerduty_webhook_non_https` (high) — matches | PASS | existing `test_webhook_http_scheme_is_high` | — |
| E2. Webhook HTTPS restored | `pagerduty_webhook_subscription` | `delivery_url_scheme_category` | `"http"` | `"https"` | yes | low | low (improvement) | "delivery URL scheme changed to HTTPS." | (same) | n/a | PASS | existing `test_webhook_https_restored_is_low` | — |
| E3. Webhook signing/header indicator removed | `pagerduty_webhook_subscription` | `has_custom_headers` | `True` | `False` | yes | medium | medium | "lost its custom-header (signing) indicator." | (same) | `pagerduty_webhook_secret_not_indicated` (medium) — matches | PASS | covered by tracked-field sweep | — |
| E4. Webhook event count drops to zero | `pagerduty_webhook_subscription` | `event_count` | `2` | `0` | yes | medium | medium | "event count dropped to zero." | (same) | `pagerduty_webhook_no_events` (medium) — matches | PASS | new `test_count_fields_explicit_zero_still_fires_correctly` | — |
| E5. Webhook event count: unknown transition | `pagerduty_webhook_subscription` | `event_count` | `2` | `None` | yes | **was medium, falsely claiming "dropped to zero"** | low | ~~"event count dropped to zero."~~ | "event count is now unknown or missing." | n/a | **FIXED** | new `test_webhook_event_count_unknown_is_low_not_dropped_to_zero` | This one is notable: the original branch didn't even require `n_old > 0` before firing — any coerced `new_v == 0` (including from `None`) triggered medium unconditionally, making it the most permissive (and therefore most exposed) instance of the bug |
| E6. Webhook disabled/enabled | `pagerduty_webhook_subscription` | `active` | `True`/`False` | `False`/`True` | yes | medium / low | medium / low | "was disabled." / "was enabled." | (same) | `pagerduty_webhook_inactive` (medium) — matches | PASS | covered by tracked-field sweep | — |
| E7. Webhook scope broadened to account-wide | `pagerduty_webhook_subscription` | `filter_type` | `"service_reference"` | `"account"` | yes | medium | medium | "scope changed to account-wide." | (same) | `pagerduty_webhook_account_scope` (medium) — matches | PASS | covered by tracked-field sweep | — |
| F1. Response play responders drop to zero | `pagerduty_response_play` | `responder_count` | `2` | `0` | yes | high | high | "dropped to zero responders." | (same) | `pagerduty_response_play_no_responders` (high) — matches | PASS | existing `test_response_play_zero_responders_is_high` | — |
| F2. Response play responders: unknown transition | `pagerduty_response_play` | `responder_count` | `2` | `None` | yes | **was high, falsely claiming "dropped to zero responders"** | low | ~~"dropped to zero responders."~~ | "responder count is now unknown or missing." | n/a | **FIXED** | new `test_response_play_responder_count_unknown_is_low_not_dropped_to_zero` | Same bug class as A2/B2/F2 |
| F3. Response play responders decrease (nonzero) | `pagerduty_response_play` | `responder_count` | `5` | `2` | yes | medium | medium | "responder count decreased from 5 to 2..." | (same) | `pagerduty_response_play_low_responder_count` (medium) — matches | PASS | covered by tracked-field sweep, re-verified after fix | — |
| F4. Response play subscriber count changes | `pagerduty_response_play` | `subscriber_count` | `1` | `0` | yes | low | low | "subscriber count changed from 1 to 0." | (same) | `pagerduty_response_play_no_subscribers` (low) — matches | PASS | covered by tracked-field sweep | This field never had a severity bug (no zero/high branch existed for it — it was always generic low), but the `_int_pair` coercion still meant an unknown transition would misleadingly print "0" instead of "unknown". Fixed alongside the others |
| G. Team/user/ownership counts | `pagerduty_service`, `pagerduty_escalation_policy`, `pagerduty_schedule` | `team_count` | count | count | yes | low (generic) | low | "team count changed..." | (same) | matches (all three `*_no_teams` Findings are `low`) | PASS | covered by tracked-field sweep, re-verified after fix | Same unknown-vs-zero fix applied for wording accuracy, though severity was already `low` in every case (no false-high risk here) |
| H. Maintenance windows | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Confirmed unchanged from the detection pass — no maintenance-windows endpoint is fetched |
| I. Unknown/missing sweep (comprehensive) | `pagerduty_escalation_policy`, `pagerduty_schedule`, `pagerduty_response_play`, `pagerduty_webhook_subscription`, `pagerduty_service`, `pagerduty_event_orchestration` | `escalation_rule_count`, `target_count`, `user_count`, `responder_count`, `event_count`, `integration_count`, `route_count` | numeric | `None` | yes | low (after fix; several were `high`/`medium` before) | low | all now say "...count is now unknown or missing." | (same) | n/a | PASS (after fix) | new `test_unknown_transitions_never_produce_high_qa_pass` (7 field/record-type combinations) | This is the comprehensive regression guard for the core bug in this pass |
| J. Copy safety | all record types | all fields | — | — | — | — | — | no breach/compromise/attacker/leak/unauthorized-access/incident-exposure/alert-exposure/secret-exposure/data-exposure/customer-impact language anywhere | (same) | — | PASS | existing `test_no_forbidden_wording_in_reasons`, re-verified after this pass's edits (no new wording introduced any forbidden phrase) | — |

## Tracked-fields vs. classifier-branch comparison

(Unchanged from the detection pass's comparison table — this pass only
changed *how* the existing dedicated branches distinguish unknown from
zero, not *which* fields have dedicated branches. Re-verified as still
accurate.)

| Record type | Tracked fields with dedicated classification | Tracked fields using generic fallback (intentional) |
|---|---|---|
| `pagerduty_service` | `escalation_policy_id`, `acknowledgement_timeout_category`, `auto_resolve_timeout_category`, `alert_creation_category`, `integration_count`, `team_count` | `resource_name`, `status_category`, `incident_urgency_rule_type`, `support_hours_enabled`, `scheduled_actions_count` |
| `pagerduty_escalation_policy` | `escalation_rule_count`, `target_count`, `escalation_level_count`, `has_schedule_targets`, `team_count` | `resource_name`, `repeat_enabled`, `num_loops`, `on_call_handoff_notifications`, `user_target_count`, `schedule_target_count` |
| `pagerduty_schedule` | `user_count`, `layer_count`, `team_count` | `resource_name`, `time_zone_present`, `restriction_count`, `has_restrictions` |
| `pagerduty_service_integration` | `has_integration_key`, `routing_key_present` | `type_category`, `vendor_name` |
| `pagerduty_webhook_subscription` | `active`, `delivery_url_scheme_category`, `has_custom_headers`, `filter_type`, `event_count` | — (full coverage) |
| `pagerduty_event_orchestration` | `route_count` | `resource_name`, `team_present` |
| `pagerduty_business_service` | — | All 3 tracked fields (both Findings for this type are `low` hygiene notes) |
| `pagerduty_response_play` | `responder_count`, `runnability`, `subscriber_count` | `resource_name`, `team_present`, `conference_number_present` |

**Classifier branches referring to fields not emitted by the
connector/schema:** none found.

**Classifier branches referring to stale field names:** none — newly-built
module, no legacy drift to inherit.

**Fields with similar names that could be confused:** unchanged from the
detection pass — `has_integration_key` vs. `routing_key_present`, and
`team_count` appearing on three different record types, each produces
distinct, record-type-specific wording with no cross-confusion risk.

## Design note: why the count-vs-unknown bug was more severe here than in prior providers

In the Jira, GitLab, and Linear classification-QA passes, the equivalent
bugs found were **wording-only** — an unknown transition was described
inaccurately (e.g. "was disabled" instead of "is now unknown"), but the
severity itself stayed safely at `low` in every case, because those bugs
affected *boolean* fields gated by `_is_falsy_explicit`/`_is_truthy`
checks that already excluded `None` from the "explicit" branches.

PagerDuty's bug was different in kind: `_int_pair`'s `int(new_v or 0)`
coercion happens **before** any severity decision is made, so the
`n_new == 0` check that gates `high`/`medium` severities could never tell
the difference between "confirmed zero" and "we don't know." This made it
a genuine **false-positive severity bug**, not merely an inaccurate
description of an already-correct severity. It is the most serious
classification bug found across all four classification-QA passes to
date (Jira, GitLab, Linear, PagerDuty).

## Mock-shape (`old_value`/`prev_value`/`previous_value`/`prior_value`) verification

```
grep -n "old_value\|previous_value\|prior_value\|prev_value" backend/app/services/risk_rules/pagerduty.py
```
→ 6 matches, all `_get(change, "prev_value")` — production code was
already clean (this module was written fresh in the prior pass with the
correct field name from the start).

```
grep -rn "old_value\|previous_value\|prior_value" backend/tests/*pagerduty*
```
→ one match, in `test_milestone84a_pagerduty_drift_provider_foundation.py`
— a docstring comment (`"""Regression guard against the exact
old_value/prev_value bug class..."""`) that *names* the bug class being
guarded against; not an actual field usage.

```
grep -c "prev_value" backend/tests/test_milestone84a_pagerduty_drift_provider_foundation.py
```
→ 25+ matches — the `TestPagerDutyRiskClassifier._make_change` helper and
the dict literal in `test_classifier_reads_real_compute_diff_dict_shape_not_a_mock`
both build plain dicts shaped exactly like real `compute_diff` output,
never a `MagicMock`.

**No mock-shape issue remains, and none was introduced by this pass.**

## Totals

| Metric | Count |
|---|---|
| Total classification cases reviewed | 27 (A1–J, all rows above) |
| PASS | 20 |
| FAIL | 0 |
| GAP → FIXED (false-severity bug from unknown-vs-zero coercion) | 6 (A2, A4, B2, C6, E5, F2 — plus G/F4 wording-only, and I as the comprehensive sweep) |
| N/A (not modeled, correctly absent) | 1 (H) |
| New Security Finding rules added | 0 (classification-layer pass only) |
| Previously detected changes now confirmed misclassified before this pass | 6 (all unknown-transition count cases, several at `high` — the most severe misclassifications found across all four provider classification-QA passes) |
| Mock-shape (`old_value`-style) bugs found | 0 |
| PagerDuty high-risk response-routing classifications aligned with Security Findings | Yes — all confirmed: `pagerduty_service_no_escalation_policy`, `pagerduty_ep_no_rules`, `pagerduty_ep_no_targets`, `pagerduty_schedule_no_targets`, `pagerduty_response_play_no_responders`, `pagerduty_webhook_non_https` all match their Change-classifier counterparts exactly, both before and after this pass's fix (the fix only changed *unknown*-value handling, never the confirmed-zero severity) |

## Fixes made

1. **`backend/app/services/risk_rules/pagerduty.py`**
   - Replaced `_int_pair()` with a new `_int_or_none()` helper that returns
     `None` (not `0`) for missing/unparseable values.
   - Updated all 11 count-based branches across 6 record types
     (`escalation_rule_count`, `target_count`, `escalation_level_count`,
     `team_count` ×3, `user_count`, `layer_count`, `route_count`,
     `event_count`, `responder_count`, `subscriber_count`, and the
     service's `integration_count`) to check `n_new is None` first and
     return a `low`, clearly-worded "unknown or missing" response before
     any zero-detection logic runs.
2. **`backend/tests/test_milestone84a_pagerduty_drift_provider_foundation.py`**
   — added 7 new tests: 5 dedicated unknown-transition regression tests
   for the highest-severity fields (`escalation_rule_count`,
   `target_count`, `user_count`, `responder_count`, `event_count`), 1 test
   confirming the genuine zero-detection path still works correctly after
   the fix, and 1 comprehensive 7-case unknown/missing severity sweep
   across all affected record types.
3. **`backend/tests/reports/pagerduty_change_classification_matrix.md`** —
   this report.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone84a_pagerduty_drift_provider_foundation.py -q
# 147 passed (was 140 after 6645c82)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "pagerduty and risk"
# 167 passed, 16934 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "pagerduty and diff"
# 12 passed, 17089 deselected

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "pagerduty"
# 737 passed, 16364 deselected (was 730 after 6645c82)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*pagerduty* -q
# 721 passed
```

No frontend files were touched in this pass — no new Security Finding rule
was added or changed, only Change-classification logic and tests — so
`npx tsc --noEmit` was not run.
