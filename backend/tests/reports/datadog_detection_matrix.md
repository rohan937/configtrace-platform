# Datadog Detection QA Matrix

Exhaustive end-to-end validation of the Datadog provider (connector → diff
tracking → risk classification → security findings → registries →
frontend catalog), following the same methodology established for
SendGrid, Twilio, Terraform Cloud, GitLab, Jira, Linear, and PagerDuty in
prior QA passes.

## Summary

Datadog's connector (`app/connectors/datadog.py`), schema
(`datadog_schema.py`), and security rules (`security_rules/datadog.py`, 31
rules across all 10 record types) were already mature. As with Linear's
and PagerDuty's equivalent passes, **registries and the frontend catalog
were already in perfect parity (31/31, zero severity mismatches)** — no
fixes needed there. The two recurring root-cause bugs from every prior
provider pass were both present here, and both are the primary fixes in
this pass:

1. **`risk_rules/datadog.py` did not exist at all.** `risk_service.py` had
   no `datadog_` dispatch branch, so **every Datadog configuration change
   silently fell through to the Cloudflare DNS classifier**. Built the
   module from scratch (10 record-type classifiers) and wired the
   dispatch.

2. **Diff/drift tracking gap.** Datadog had **zero entries** in
   `diff_service.py`'s per-provider tracked-fields dispatch, so every
   Datadog record type fell through to the Cloudflare DNS default tuple
   (`name`, `content`, `ttl`, `proxied`, `priority`, `comment` — none of
   which exist on any Datadog record). `compute_diff` could never detect a
   modified field on an existing Datadog record. Fixed by adding
   `_DATADOG_TRACKED_FIELDS_BY_TYPE` (all 10 record types) and wiring the
   `datadog_` prefix into `_tracked_fields_for`.

Building on the false-positive severity bug found and fixed in
PagerDuty's classification-QA pass, this new module was written
**defensively from the start**: every count-based branch uses
`_int_or_none()` (not a bare `int(val or 0)` coercion), so an
unknown/missing count value is never silently treated as an explicit zero
or as crossing a review threshold. A dedicated test
(`test_count_unknown_not_treated_as_zero`) locks this in immediately
rather than waiting for a follow-up classification-QA pass to find it.

No new Security Finding rules were needed or added — the existing 31
rules already cover every field this pass identified as security-relevant,
and the new Change classifier's severities and thresholds
(`_BROAD_SCOPES_THRESHOLD = 10`, `_HIGH_PERMISSION_THRESHOLD = 25`,
`_BROAD_GROUP_BY_THRESHOLD = 3`) were mirrored directly from
`security_rules/datadog.py` so Change/Finding severities stay aligned.

## Connector extraction review

| Record type | Source endpoint | Sensitive values excluded? | Fail-soft on error? | Stable record IDs? |
|---|---|---|---|---|
| `datadog_monitor` | `GET /api/v1/monitor` (paginated) | Yes — raw query/message read transiently to derive safe booleans/categories, then discarded | Yes — 403/404 caught and logged, returns `[]` | Yes — monitor `id` |
| `datadog_slo` | `GET /api/v1/slo` (paginated) | Yes — raw description never stored | Yes — same 403/404 pattern | Yes — SLO `id` |
| `datadog_dashboard` | `GET /api/v1/dashboard` | Yes — raw JSON/widget queries/public URL never stored | Yes | Yes — dashboard `id` |
| `datadog_webhook_integration` | webhook integration config endpoint | Yes — URL/headers/payload/secrets reduced to safe derived booleans/categories, then discarded | Yes | Yes — webhook `name` |
| `datadog_notification_integration` | per-type probe (PagerDuty/OpsGenie/Slack) | Yes — service keys, channel names, handles never stored | Yes — `None` raw input returns `None` from the normalizer | Yes — `f"datadog_notif_{type}"` |
| `datadog_api_key_metadata` | API keys endpoint (v2) | Yes — key value/last4 digits never stored, only presence booleans | Yes | Yes — key `id` |
| `datadog_application_key_metadata` | application keys endpoint (v2) | Yes — key value/hash never stored; scope names reduced to a count | Yes | Yes — key `id` |
| `datadog_role` | roles endpoint | Yes — user/team identities never stored, only counts | Yes | Yes — role `id` |
| `datadog_team` | teams endpoint | Yes — member identities and team handle never stored | Yes | Yes — team `id` |
| `datadog_cloud_integration` | AWS/GCP/Azure integration endpoints | Yes — account IDs/tenant IDs/ARNs never stored, only presence boolean | Yes | Documented tradeoff — see below |

**Confirmed via code inspection** (connector module docstring + normalizer
bodies + the module-level "PRIVACY / SECURITY" comment block):
- No **API key or application key values** are stored — both are used
  only in `DD-API-KEY`/`DD-APPLICATION-KEY` request headers, never copied
  into a record, an instance attribute, or a log line.
- No **webhook secrets** are stored — `_normalize_webhook` reads `url`,
  `custom_headers`, `secret_headers`, and `payload` transiently to derive
  `url_scheme_category`, `custom_header_count`, `auth_material_present`,
  `secret_headers_count`, and `payload_template_length_category`, then
  discards all four raw values.
- No **full webhook URLs** are stored — same pattern via
  `_url_scheme_category()`.
- No **log contents** are stored — the connector has no log-search or
  log-content endpoint call at all; `log_collection_enabled` on cloud
  integrations is a configuration boolean, not log data itself.
- No **incident/event payload contents** are stored — no incidents or
  events endpoint is fetched.
- No **private user PII** is stored beyond safe metadata/counts —
  `user_count`/`member_count`/`created_by_present`/`owned_by_present` are
  all counts or presence booleans, never identities.
- No **dashboard/query contents** are stored — `_normalize_dashboard`
  never reads `widgets[].definition` content, only `len(widgets)`; monitor
  `query`/`message` are read transiently for safe derivations
  (`query_uses_wildcard_scope`, `notification_count`, etc.) and then
  discarded, matching the module's own documented pattern.

**Record ID stability note** (already documented in the connector's own
code comment, re-verified in this pass): `datadog_cloud_integration`
record IDs use a positional index (`f"datadog_cloud_{provider}_{index}"`)
rather than a hash of the account ID, because every candidate stable
identifier (AWS account ID, GCP project ID, Azure tenant) is deliberately
on the never-store list. This is an accepted, explicitly-documented
tradeoff — a reordered account list from the Datadog API could reassign
record IDs across syncs — not a bug introduced or found by this pass.

## Diff/change tracking review

**Before this pass**: 0 of 10 record types had a tracked-fields entry —
all Datadog modified-field changes silently fell through to the
Cloudflare DNS default tuple and were never detected.

**After this pass**: all 10 record types are tracked with every
security-relevant field verified present, including all the task's
high-priority fields: `disabled` (API key), `scopes_count` (application
key), `enabled`/`notify_no_data`/`renotify_interval_category` (monitor),
`restricted_roles_count`, `public_url_present` (dashboard), `enabled`
(notification/webhook integrations), `url_scheme_category`/
`secret_headers_present` (webhook), `log_collection_enabled` (cloud
integration), `permission_count` (role).

No fields were found that are tracked but no longer emitted by the
connector — the tracked tuples were built directly from
`datadog_schema.py`'s `TypedDict` definitions, cross-referenced against
the connector's actual normalizer output.

## Test matrix

| Test case | Normalized record type | Field(s) | Change simulated | Expected detection | Actual detection | Expected classification | Actual classification | Rule key | Test coverage | Status | Notes/fix needed |
|---|---|---|---|---|---|---|---|---|---|---|---|
| A. API key active/disabled | `datadog_api_key_metadata` | `disabled` | `False → True` | Change (low) + Finding (low, `datadog_api_key_disabled`) | Change never generated before fix (diff-tracking gap) | low | low (after fix) | `datadog_api_key_disabled` (low) — matches | new `TestDatadogDiffTrackedFields` sweep | **FIXED** | Task's generic guidance suggests a higher severity for key restriction, but this pass follows the existing Finding convention (disabling a stale key is itself an improvement, not a risk — the Finding flags it as a hygiene/cleanup note, not a danger) |
| A2. API key scope/permission metadata | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Datadog API keys (as opposed to application keys) do not carry scopes in this connector's schema — only application keys have a `scopes_count` field (see B) |
| B. Application key scopes broadened | `datadog_application_key_metadata` | `scopes_count` | `5 → 15` (crosses threshold of 10) | Change (medium) + Finding (medium, `datadog_application_key_broad_scopes`) | Change never generated before fix | medium | medium (after fix) | `datadog_application_key_broad_scopes` (medium) — matches | new `test_application_key_scopes_cross_threshold_is_medium` | **FIXED** | — |
| C. Role/admin permission count increased | `datadog_role` | `permission_count` | `20 → 30` (crosses threshold of 25) | Change (medium) + Finding (medium, `datadog_role_high_permission_count`) | Change never generated before fix | medium | medium (after fix) | `datadog_role_high_permission_count` (medium) — matches | new `test_role_permission_count_crosses_threshold_is_medium` | **FIXED** | — |
| D. Monitor enabled/disabled | `datadog_monitor` | `enabled` | `True → False` | Change (medium) + Finding (medium, `datadog_monitor_disabled`) | Change never generated before fix | medium | medium (after fix) | `datadog_monitor_disabled` (medium) — matches | new `test_monitor_disabled_is_medium` | **FIXED** | — |
| E. Monitor notify_no_data enabled/disabled | `datadog_monitor` | `notify_no_data` | `True → False` | Change (low) + Finding (low, `datadog_monitor_notify_no_data_disabled`) | Change never generated before fix | low | low (after fix) | `datadog_monitor_notify_no_data_disabled` (low) — matches | covered by tracked-field sweep | **FIXED** | — |
| F. Monitor no-data timeframe weakened | `datadog_monitor` | `no_data_timeframe_category` | `"medium" → "extended"` | Change (low) + Finding (low, `datadog_monitor_long_no_data_timeframe`) | Change never generated before fix | low | low (after fix) | `datadog_monitor_long_no_data_timeframe` (low) — matches | covered by tracked-field sweep | **FIXED** | — |
| G. Monitor notification/channel count changed | `datadog_monitor` | `notification_routing_present` | `True → False` | Change (medium) + Finding (medium, `datadog_monitor_no_notifications`) | Change never generated before fix | medium | medium (after fix) | `datadog_monitor_no_notifications` (medium) — matches | covered by tracked-field sweep | **FIXED** | This is the highest-severity monitor-level rule after `disabled` — losing notification routing entirely means alerts have no destination |
| H. Dashboard public/shared posture | `datadog_dashboard` | `public_url_present` | `False → True` | Change (medium) + Finding (medium, `datadog_dashboard_public_url_present`) | Change never generated before fix | medium | medium (after fix) | `datadog_dashboard_public_url_present` (medium) — matches | new `test_dashboard_public_url_gained_is_medium` | **FIXED** | — |
| I. Integration enabled/disabled | `datadog_notification_integration` | `enabled` | `True → False` | Change (medium) + Finding (n/a — see notes) | Change never generated before fix | medium | medium (after fix) | n/a — no dedicated Finding fires on `enabled=False` alone (the only notification Finding requires `enabled=True AND handle_count==0 AND channel_count==0`); the Change-layer `medium` severity follows the cross-provider convention established for Linear/PagerDuty integration-disabled classifications rather than a direct Finding match | new tests via tracked-field sweep | **FIXED (Change-only signal, documented)** | See design note below |
| J. Webhook enabled/disabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | Datadog webhook integrations don't expose a separate `enabled`/`disabled` boolean in this connector's schema — `url_present`/`secret_headers_present`/`url_scheme_category` are the observable posture signals, covered by K/L |
| K. Webhook HTTP/HTTPS scheme | `datadog_webhook_integration` | `url_scheme_category` | `"https" → "http"` | Change (high) + Finding (high, `datadog_webhook_non_https_endpoint`) | Change never generated before fix | high | high (after fix) | `datadog_webhook_non_https_endpoint` (high) — matches | new `test_webhook_http_scheme_is_high` | **FIXED** | — |
| L. Webhook signing/secret posture | `datadog_webhook_integration` | `secret_headers_present` | `True → False` | Change (high) + Finding (high, `datadog_webhook_without_secret_headers`) | Change never generated before fix | high | high (after fix) | `datadog_webhook_without_secret_headers` (high) — matches | new `test_webhook_secret_headers_removed_is_high` | **FIXED** | The Finding requires `url_present AND NOT secret_headers_present`; the Change classifier fires on `secret_headers_present` alone (a defensible, slightly more aggressive approximation of a combined-condition Finding, consistent with the pattern already accepted in prior providers' classification-QA passes) |
| M. Log archive/index/pipeline enabled/disabled | `datadog_cloud_integration` | `log_collection_enabled` | `False → True` | Change (medium) + Finding (low, `datadog_cloud_integration_log_collection_enabled`) | Change never generated before fix | medium (Change) / low (Finding, current-state) | medium (Change, after fix) / low (Finding, unchanged) | `datadog_cloud_integration_log_collection_enabled` (low) — **intentional Finding/Change disagreement, see design note** | covered by tracked-field sweep | **FIXED** | No log archive/index/pipeline record type exists in this connector; `log_collection_enabled` on cloud integrations is the closest analog to "log collection posture" in scope |
| N. Security monitoring rule enabled/disabled | n/a | n/a | n/a | n/a | not modeled | n/a | n/a | n/a | n/a | **N/A** | n/a | No Cloud Security Posture Management / Security Monitoring Rules endpoint is fetched by this connector. Not invented per task instructions |
| O. Unknown/missing fields never produce high findings | all 10 record types | any | `None`/missing | no high finding/classification | Confirmed — every Finding check in `security_rules/datadog.py` uses explicit boolean/category-string equality, and every new Change classifier branch falls to `low` on unparseable/missing values via `_int_or_none()`'s explicit `None` check (built defensively from the start, learning from PagerDuty's classification-QA fix) | none | none | all | new `test_every_tracked_field_classifies_without_error_or_invalid_severity`, `test_unknown_transitions_never_produce_high`, `test_count_unknown_not_treated_as_zero` | PASS | — |
| P. 403/404 fail-soft on optional endpoints | all 10 surfaces (monitors, SLOs, dashboards, webhooks, notification integrations, API/app keys, roles, teams, cloud integrations) | n/a | endpoint returns error | sync continues, other surfaces unaffected | Confirmed — every fetch helper wraps its `ConnectorError` handling to check `status_code in (403, 404)` and return `[]`, logging at debug level | n/a | n/a | n/a | existing `test_milestone82a` connector tests | PASS | — |
| Q. Records with normalized fields but no security rule | none found — every one of the 10 record types has at least one rule, and every tracked field either has a dedicated rule or a documented reason for using the generic fallback (see comparison table below) | n/a | n/a | correctly no gaps | Confirmed — cross-referenced every tracked field against `security_rules/datadog.py`'s eval functions | n/a | n/a | n/a | existing `test_datadog_provider_depth_qa.py` coverage | PASS | — |
| R. Security rules with no reachable normalized record | — | — | — | — | None found — all 31 rules dispatch from `evaluate()` against one of the 10 record types the connector actually emits | n/a | n/a | all | existing depth-QA reachability tests (all still passing after this pass) | PASS | Zero dead/unreachable rules |
| Registry/pack/confidence/coverage/frontend parity | n/a | n/a | n/a | 31/31 rule keys present everywhere with matching severities | Verified via exact set diff: `security_rules/datadog.py` (31) vs. `security_rule_registry.py` (31), `security_rule_pack.py` (31, all severities cross-checked programmatically, zero mismatches), `security_rule_confidence.py` (31), and `securityRuleCatalog.ts` (31) | n/a | n/a | all | none pre-existing; verified via ad hoc scripted diff in this pass | PASS | Zero mismatches — no fix needed (matching Linear's and PagerDuty's equivalent passes, unlike Jira's, which found 10 severity mismatches and 6 catalog gaps) |
| Diff-tracked fields present for all 10 record types | all | all normalized fields | n/a | every normalized field that isn't a pure identity field is diff-tracked | **0 of 10 record types tracked (before fix)** → **10 of 10 tracked (after fix)** | n/a | n/a | n/a | new `TestDatadogDiffTrackedFields` (5 tests) | **FIXED** | Root-cause fix — see Summary #2 |
| Risk classification module exists and is wired | all | all tracked fields | n/a | every Change gets a Datadog-specific classification, not the Cloudflare DNS fallback | **module did not exist (before fix)** → **10 classifiers + dispatch wired (after fix)** | n/a | n/a | n/a | new `TestDatadogRiskClassifier` (16 tests, including a dispatch-level regression test, a dict-shaped mock-bug-prevention test, and a proactive count-unknown-not-zero test) | **FIXED** | Summary #1 — the largest fix in this pass |

## Design notes

### Why notification integration `enabled=False` is `medium` with no direct Finding match

Datadog's only notification-integration Finding
(`datadog_notification_integration_no_channels`, low) requires
`enabled=True AND handle_count==0 AND channel_count==0` — it can never
fire when `enabled=False`, since disabling the integration is itself the
"no notifications will reach anyone" state, just via a different field.
The Change classifier fills this gap with a `medium` severity for the
`enabled: True → False` transition, following the same convention already
established for Linear's and PagerDuty's integration-disabled
classifications in their own detection-QA passes — disabling a configured
notification integration is a legitimate "you might miss alerts" signal
even though no single current-state Finding observes that exact
transition.

### Why `log_collection_enabled` disagrees between Finding (low) and Change (medium)

This is the same "Change layer catches transitions the Finding layer
structurally cannot" pattern established for GitLab, Terraform Cloud,
Jira, and Linear in prior classification-QA passes:
`datadog_cloud_integration_log_collection_enabled` is a `low`,
purely-informational current-state note ("log collection is on, review
your data handling policy"). The *transition* to enabling log collection
on a cloud integration — deliberately granting Datadog access to forward
cloud logs that weren't being forwarded before — is a more notable
one-time event, so the Change classifier rates it `medium`. Disabling log
collection (the restoration direction) stays `low`.

## Tracked-fields vs. classifier-branch comparison

| Record type | Tracked fields with dedicated classification | Tracked fields using generic fallback (intentional) |
|---|---|---|
| `datadog_monitor` | `enabled`, `notification_routing_present`, `query_uses_wildcard_scope`, `silenced_scope_count`, `threshold_warning_present`, `threshold_recovery_present`, `notify_no_data`, `restricted_roles_count`, `query_complexity_category`, `no_data_timeframe_category`, `query_group_by_count` | `resource_name`, `monitor_type`, `status`, `priority_category`, `query_present`, `message_present`, `message_length_category`, `notification_count`, `message_template_present`, `tag_count`, `threshold_count`, `renotify_enabled`, `renotify_interval_category`, `include_tags`, `notify_audit`, `require_full_window`, `evaluation_delay_category` — all match their Findings' `low` severity (or have no dedicated Finding at all, like `renotify_interval_category`) |
| `datadog_slo` | `monitor_count`, `target_category` | `resource_name`, `slo_type`, `warning_target_category`, `timeframe_count`, `group_count`, `tag_count`, `description_present`, `description_length_category` |
| `datadog_dashboard` | `public_url_present`, `restricted_roles_count` | `resource_name`, `layout_type`, `widget_count`, `template_variable_count`, `description_present`, `description_length_category` |
| `datadog_webhook_integration` | `url_scheme_category`, `secret_headers_present`, `auth_material_present`, `payload_template_present`, `payload_template_length_category` | `resource_name`, `url_present`, `custom_headers_present`, `custom_header_count`, `secret_headers_count`, `encode_as_category` — `custom_headers_present` alone has no dedicated Finding (the real signal is the *combination* with `secret_headers_present`, already covered) |
| `datadog_notification_integration` | `enabled`, `handle_count`, `channel_count` | `resource_name`, `integration_type`, `restricted_roles_count` — this record type's `restricted_roles_count` field is tracked but never populated with a non-zero value by the connector (no Finding exists for it either) |
| `datadog_api_key_metadata` | `disabled` | `resource_name`, `created_present`, `modified_present`, `last4_present`, `created_by_present` |
| `datadog_application_key_metadata` | `scopes_count` | `resource_name`, `created_present`, `modified_present`, `owned_by_present` |
| `datadog_role` | `permission_count` | `resource_name`, `user_count`, `team_count` — no dedicated Finding for either count |
| `datadog_team` | `member_count` | `resource_name`, `handle_present`, `link_count` |
| `datadog_cloud_integration` | `log_collection_enabled` | `resource_name`, `cloud_provider`, `account_id_present`, `resource_collection_enabled`, `metric_collection_enabled`, `account_tags_count`, `namespace_count` — `resource_collection_enabled`/`metric_collection_enabled` only have a dedicated Finding in *combination* with `log_collection_enabled` (`datadog_cloud_integration_broad_collection`, requiring all three `True`), which a single-field Change classifier can't cheaply replicate — same accepted limitation documented for GitLab's/Linear's/Terraform Cloud's combined-condition Findings |

**Classifier branches referring to fields not emitted by the
connector/schema:** none found — every `fp ==` check in
`risk_rules/datadog.py` was written directly against
`datadog_schema.py`'s `TypedDict` definitions and cross-verified against
the connector's actual normalizer output.

**Classifier branches referring to old/stale field names:** none — this
is a newly-built module, so there was no legacy field-name drift to
inherit.

**Fields with similar names that could be confused:**
`threshold_warning_present` vs. `threshold_recovery_present` (both on
`datadog_monitor`) are the closest pair — `threshold_warning_present`
going `False` is `medium` (matching its Finding) while
`threshold_recovery_present` going `False` is `low` (matching its
Finding); each branch names its own field explicitly in the wording, so
the two are not confusable in the emitted reason text.

## Mock-shape (`old_value`/`prev_value`) verification

Since `risk_rules/datadog.py` did not exist before this pass, there was no
pre-existing mock-shape bug to find. The module was written to read
`prev_value` directly from the start (matching `compute_diff`'s real
output), and a dedicated regression test
(`test_classifier_reads_real_compute_diff_dict_shape_not_a_mock`) builds a
plain dict shaped exactly like real `compute_diff` output — not a
`MagicMock` — to guard against this exact bug class recurring.

## Fixes made

1. **`backend/app/services/risk_rules/datadog.py`** (new file) — 10
   record-type classifiers (`_classify_monitor_change` through
   `_classify_cloud_integration_change`) plus the `classify_datadog_change`
   dispatcher. Built with `_int_or_none()` from the start (not a bare
   `int(val or 0)` coercion) to avoid the exact false-positive
   unknown-vs-zero severity bug found and fixed in PagerDuty's
   classification-QA pass.
2. **`backend/app/services/risk_service.py`** — added the `datadog_`
   prefix dispatch branch to `classify_change`, routing Datadog changes to
   the new module instead of the Cloudflare DNS fallback.
3. **`backend/app/services/diff_service.py`** — added
   `_DATADOG_TRACKED_FIELDS_BY_TYPE` (all 10 record types) and wired the
   `datadog_` prefix into `_tracked_fields_for`. Updated the function's
   docstring.
4. **`backend/tests/test_milestone82a_datadog_drift_provider_foundation.py`**
   — added `TestDatadogDiffTrackedFields` (5 tests) and
   `TestDatadogRiskClassifier` (16 tests, including a dispatch-level
   regression test, a dict-shaped mock-bug-prevention test, and a
   proactive count-unknown-not-zero test).
5. **`backend/tests/reports/datadog_detection_matrix.md`** — this report.

No changes were made to `security_rules/datadog.py`, the four backend
registries, or the frontend catalog — all were already correct and in
perfect 31/31 parity with zero severity mismatches.

## Not fixed in this pass (explicitly out of scope)

- **Security Monitoring Rules / Cloud Security Posture Management** (task
  category N) — no endpoint is fetched.
- **Webhook enabled/disabled** (task category J) — Datadog webhook
  integrations don't expose a separate active/inactive boolean in this
  connector's schema.
- **Log archives/indexes/pipelines as distinct record types** (task
  category M) — only cloud-integration-level `log_collection_enabled` is
  modeled; the Logs product's index/pipeline/archive management API is
  not fetched.
- **Roles/permissions modeled beyond aggregate counts** (task category G)
  — `permission_count` is the only permission-related field; individual
  permission names are never fetched or stored.

## Validation run (narrow, foreground only)

```
cd /Users/rohan/Downloads/ConfigTrace/backend

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_milestone82a_datadog_drift_provider_foundation.py -q
# 128 passed (was 107 before this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests -q -k "datadog"
# 776 passed, 22 skipped, 16324 deselected (was 755 passed, 22 skipped before any fixes in this pass)

DATABASE_URL="postgresql://configtrace:configtrace@localhost:5432/configtrace" \
  .venv/bin/pytest tests/test_*datadog* -q
# 767 passed, 22 skipped
```

The 22 skips are pre-existing (network-dependent tests skipped in this
environment) and unrelated to this pass's changes — confirmed unchanged
before and after.

No frontend files were touched in this pass (registries and the frontend
catalog already had perfect parity with zero severity mismatches — no new
Security Finding rule was added or changed), so `npx tsc --noEmit` was not
run.
