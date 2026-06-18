"""Datadog configuration-risk security rules — M82B/M82C.

Every rule fires only on explicit, reliable normalized fields produced by the
Datadog connector (app/connectors/datadog.py + datadog_schema.py, M82A/M82C).
Evidence is metadata-only: booleans, counts, categories, opaque identifiers,
and safe string labels. No API key values, application key values, OAuth tokens,
bearer tokens, webhook secrets, webhook URLs, integration secrets, raw monitor
queries, raw monitor messages, raw dashboard JSON, raw widget queries, raw
incident text, raw log data, raw trace data, raw metric values, raw event
payloads, email addresses, user names, user IDs, team member identities,
notification channel destinations, or any customer data are ever read, stored,
or surfaced.

CLAIM DISCIPLINE
----------------
These are configuration posture findings that may require review. A finding is
evidence for review only. It never asserts that a credential was leaked, a
secret was exposed, that unauthorized access occurred, that an attacker is
present, or that customer data was exposed. Severity reflects review priority,
not confirmed impact.

Record types consumed (M82A/M82C)
----------------------------------
- ``datadog_monitor``               → enabled, restricted_roles_count,
                                       notify_no_data, query_complexity_category,
                                       notification_routing_present, notification_count,
                                       message_template_present, threshold_critical_present,
                                       threshold_warning_present, threshold_recovery_present,
                                       silenced_scope_count, notify_audit,
                                       require_full_window, query_uses_wildcard_scope,
                                       query_group_by_count, no_data_timeframe_category
- ``datadog_slo``                   → monitor_count, target_category
- ``datadog_dashboard``             → public_url_present, restricted_roles_count
- ``datadog_webhook_integration``   → url_present, url_scheme_category,
                                       custom_headers_present, custom_header_count,
                                       auth_material_present, secret_headers_present,
                                       payload_template_present,
                                       payload_template_length_category
- ``datadog_notification_integration`` → enabled, handle_count, channel_count
- ``datadog_api_key_metadata``      → disabled
- ``datadog_application_key_metadata`` → scopes_count
- ``datadog_role``                  → permission_count
- ``datadog_team``                  → member_count
- ``datadog_cloud_integration``     → resource_collection_enabled,
                                       metric_collection_enabled,
                                       log_collection_enabled

Rules deferred from M82B (resolved in M82C)
--------------------------------------------
- ``datadog_monitor_no_notifications`` — Resolved: M82C adds
  ``notification_routing_present`` to the monitor schema, enabling this rule.

Rules deferred from M82C
--------------------------
- ``datadog_webhook_url_without_secret_headers`` — Overlaps semantically with
  M82B's ``datadog_webhook_without_secret_headers`` (url_present AND NOT
  secret_headers_present). The M82C ``datadog_webhook_non_https_endpoint``
  covers the URL scheme angle more precisely. Deferred to avoid duplicate
  findings on the same record.
- ``datadog_webhook_custom_payload_enabled`` — Overlaps with M82B's
  ``datadog_webhook_payload_template_present`` (both fire when a custom payload
  is configured). Deferred to avoid semantic duplication.
- ``datadog_application_key_disabled`` — The datadog_application_key_metadata
  record does not expose a ``disabled`` field (the Datadog v2 application_keys
  endpoint does not reliably expose revocation/disabled status across all API
  versions). Remains deferred.
"""

from __future__ import annotations

from typing import Any

from app.connectors.datadog_schema import (
    DATADOG_API_KEY_METADATA,
    DATADOG_APPLICATION_KEY_METADATA,
    DATADOG_CLOUD_INTEGRATION,
    DATADOG_DASHBOARD,
    DATADOG_MONITOR,
    DATADOG_NOTIFICATION_INTEGRATION,
    DATADOG_ROLE,
    DATADOG_SLO,
    DATADOG_TEAM,
    DATADOG_WEBHOOK_INTEGRATION,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule key constants ────────────────────────────────────────────────────────

# Monitor (M82B)
_RULE_MONITOR_DISABLED = "datadog_monitor_disabled"
_RULE_MONITOR_UNRESTRICTED_ROLES = "datadog_monitor_unrestricted_roles"
_RULE_MONITOR_NOTIFY_NO_DATA_DISABLED = "datadog_monitor_notify_no_data_disabled"
_RULE_MONITOR_LONG_QUERY = "datadog_monitor_long_query"

# Monitor (M82C expansion)
_RULE_MONITOR_NO_NOTIFICATIONS = "datadog_monitor_no_notifications"
_RULE_MONITOR_MESSAGE_TEMPLATE = "datadog_monitor_message_template_present"
_RULE_MONITOR_NO_WARNING_THRESHOLD = "datadog_monitor_no_warning_threshold"
_RULE_MONITOR_NO_RECOVERY_THRESHOLD = "datadog_monitor_no_recovery_threshold"
_RULE_MONITOR_SILENCED_SCOPES = "datadog_monitor_silenced_scopes_present"
_RULE_MONITOR_NOTIFY_AUDIT_DISABLED = "datadog_monitor_notify_audit_disabled"
_RULE_MONITOR_REQUIRE_FULL_WINDOW_DISABLED = "datadog_monitor_require_full_window_disabled"
_RULE_MONITOR_QUERY_WILDCARD_SCOPE = "datadog_monitor_query_wildcard_scope"
_RULE_MONITOR_BROAD_GROUP_BY = "datadog_monitor_broad_group_by"
_RULE_MONITOR_LONG_NO_DATA_TIMEFRAME = "datadog_monitor_long_no_data_timeframe"

# SLO
_RULE_SLO_NO_MONITORS = "datadog_slo_no_monitors"
_RULE_SLO_LOW_TARGET = "datadog_slo_low_target"

# Dashboard
_RULE_DASHBOARD_PUBLIC_URL = "datadog_dashboard_public_url_present"
_RULE_DASHBOARD_UNRESTRICTED_ROLES = "datadog_dashboard_unrestricted_roles"

# Webhook integration (M82B)
_RULE_WEBHOOK_WITHOUT_SECRET_HEADERS = "datadog_webhook_without_secret_headers"
_RULE_WEBHOOK_PAYLOAD_TEMPLATE = "datadog_webhook_payload_template_present"

# Webhook integration (M82C expansion)
_RULE_WEBHOOK_CUSTOM_HEADERS_NO_SECRET = "datadog_webhook_custom_headers_without_secret_headers"
_RULE_WEBHOOK_LARGE_PAYLOAD_TEMPLATE = "datadog_webhook_large_payload_template"
_RULE_WEBHOOK_AUTH_MATERIAL = "datadog_webhook_auth_material_present"
_RULE_WEBHOOK_NON_HTTPS = "datadog_webhook_non_https_endpoint"

# Notification integration
_RULE_NOTIF_NO_CHANNELS = "datadog_notification_integration_no_channels"

# Application key
_RULE_APPKEY_BROAD_SCOPES = "datadog_application_key_broad_scopes"

# API key
_RULE_APIKEY_DISABLED = "datadog_api_key_disabled"

# Role
_RULE_ROLE_HIGH_PERMISSIONS = "datadog_role_high_permission_count"

# Team
_RULE_TEAM_NO_MEMBERS = "datadog_team_no_members"

# Cloud integration
_RULE_CLOUD_BROAD_COLLECTION = "datadog_cloud_integration_broad_collection"
_RULE_CLOUD_LOG_COLLECTION = "datadog_cloud_integration_log_collection_enabled"

DATADOG_RULE_KEYS: frozenset[str] = frozenset({
    # M82B rules
    _RULE_MONITOR_DISABLED,
    _RULE_MONITOR_UNRESTRICTED_ROLES,
    _RULE_MONITOR_NOTIFY_NO_DATA_DISABLED,
    _RULE_MONITOR_LONG_QUERY,
    _RULE_SLO_NO_MONITORS,
    _RULE_SLO_LOW_TARGET,
    _RULE_DASHBOARD_PUBLIC_URL,
    _RULE_DASHBOARD_UNRESTRICTED_ROLES,
    _RULE_WEBHOOK_WITHOUT_SECRET_HEADERS,
    _RULE_WEBHOOK_PAYLOAD_TEMPLATE,
    _RULE_NOTIF_NO_CHANNELS,
    _RULE_APPKEY_BROAD_SCOPES,
    _RULE_APIKEY_DISABLED,
    _RULE_ROLE_HIGH_PERMISSIONS,
    _RULE_TEAM_NO_MEMBERS,
    _RULE_CLOUD_BROAD_COLLECTION,
    _RULE_CLOUD_LOG_COLLECTION,
    # M82C expansion rules
    _RULE_MONITOR_NO_NOTIFICATIONS,
    _RULE_MONITOR_MESSAGE_TEMPLATE,
    _RULE_MONITOR_NO_WARNING_THRESHOLD,
    _RULE_MONITOR_NO_RECOVERY_THRESHOLD,
    _RULE_MONITOR_SILENCED_SCOPES,
    _RULE_MONITOR_NOTIFY_AUDIT_DISABLED,
    _RULE_MONITOR_REQUIRE_FULL_WINDOW_DISABLED,
    _RULE_MONITOR_QUERY_WILDCARD_SCOPE,
    _RULE_MONITOR_BROAD_GROUP_BY,
    _RULE_MONITOR_LONG_NO_DATA_TIMEFRAME,
    _RULE_WEBHOOK_CUSTOM_HEADERS_NO_SECRET,
    _RULE_WEBHOOK_LARGE_PAYLOAD_TEMPLATE,
    _RULE_WEBHOOK_AUTH_MATERIAL,
    _RULE_WEBHOOK_NON_HTTPS,
})

# Threshold: application key scope count above which the key surface is broad.
_BROAD_SCOPES_THRESHOLD = 10

# Threshold: role permission count above which the role is considered broad.
_HIGH_PERMISSION_THRESHOLD = 25

# M82C: group-by clause count above which a monitor query is considered broad.
_BROAD_GROUP_BY_THRESHOLD = 3


# ── Helpers ───────────────────────────────────────────────────────────────────


def _int(record: dict[str, Any], key: str, default: int = 0) -> int:
    val = record.get(key)
    if isinstance(val, int) and not isinstance(val, bool):
        return val
    return default


def _bool_field(record: dict[str, Any], key: str) -> bool:
    val = record.get(key)
    return bool(val) if isinstance(val, bool) else False


# ── Monitor evaluator ─────────────────────────────────────────────────────────


def _eval_monitor(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one datadog_monitor record.

    SECURITY: raw query strings, raw message text, notification handles,
    and all Datadog API key/token values are NEVER read or stored. Evidence
    uses only booleans, counts, categories, and opaque record_id.
    """
    record_id = get_str(record, "record_id") or get_str(record, "resource_id")
    findings: list[FindingCandidate] = []

    # ── datadog_monitor_disabled ──────────────────────────────────────────────
    if not _bool_field(record, "enabled"):
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_DISABLED,
            finding_key=make_finding_key(_RULE_MONITOR_DISABLED, record_id),
            severity="medium",
            title="Datadog monitor is disabled",
            description=(
                "A Datadog monitor is currently disabled (silenced or muted). "
                "Disabled monitors do not send alerts, which may leave gaps in "
                "observability coverage and alert posture. This is configuration "
                "evidence for review — it does not confirm a data exposure or "
                "operational incident."
            ),
            evidence={
                "rule": _RULE_MONITOR_DISABLED,
                "record_id": record_id,
                "monitor_type": get_str(record, "monitor_type"),
                "enabled": False,
            },
            remediation={
                "summary": "Review whether this monitor should be re-enabled.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Locate the disabled monitor and review its configuration.",
                    "If the monitor should be active, un-mute or re-enable it.",
                    "If the monitor is intentionally disabled, consider archiving it.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_unrestricted_roles ────────────────────────────────────
    restricted_roles_count = _int(record, "restricted_roles_count")
    if restricted_roles_count == 0:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_UNRESTRICTED_ROLES,
            finding_key=make_finding_key(_RULE_MONITOR_UNRESTRICTED_ROLES, record_id),
            severity="low",
            title="Datadog monitor has no restricted roles",
            description=(
                "A Datadog monitor is not restricted to any role. Without role "
                "restrictions, any team member with edit access to the monitor "
                "can modify its configuration or mute alerts. This configuration "
                "evidence may require review to confirm the access posture is "
                "appropriate for the monitor's scope."
            ),
            evidence={
                "rule": _RULE_MONITOR_UNRESTRICTED_ROLES,
                "record_id": record_id,
                "restricted_roles_count": 0,
            },
            remediation={
                "summary": "Consider restricting monitor edit access to specific roles.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor settings and add role restrictions under "
                    "the Permissions section.",
                    "Assign edit access to the team(s) responsible for this monitor.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_notify_no_data_disabled ───────────────────────────────
    if not _bool_field(record, "notify_no_data"):
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_NOTIFY_NO_DATA_DISABLED,
            finding_key=make_finding_key(_RULE_MONITOR_NOTIFY_NO_DATA_DISABLED, record_id),
            severity="low",
            title="Datadog monitor does not notify on no data",
            description=(
                "A Datadog monitor has the 'notify on no data' option disabled. "
                "When data stops arriving (e.g. an agent or integration stops "
                "sending metrics), the monitor will not alert. This configuration "
                "evidence may require review to confirm the no-data behavior is "
                "intentional for this monitor type."
            ),
            evidence={
                "rule": _RULE_MONITOR_NOTIFY_NO_DATA_DISABLED,
                "record_id": record_id,
                "notify_no_data": False,
            },
            remediation={
                "summary": "Review the 'notify on no data' setting for this monitor.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor and review the 'Notify if data is missing' option.",
                    "Enable it if the monitor covers a surface where data loss "
                    "should be treated as an alert condition.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_long_query ────────────────────────────────────────────
    query_cat = get_str(record, "query_complexity_category")
    if query_cat == "long":
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_LONG_QUERY,
            finding_key=make_finding_key(_RULE_MONITOR_LONG_QUERY, record_id),
            severity="low",
            title="Datadog monitor has a long query",
            description=(
                "A Datadog monitor has a query that is classified as long in "
                "length. Complex queries may be harder to audit, more prone to "
                "unintended side effects, and more difficult to maintain. This "
                "is configuration evidence for review — it does not confirm a "
                "security issue. Raw query content is never stored."
            ),
            evidence={
                "rule": _RULE_MONITOR_LONG_QUERY,
                "record_id": record_id,
                "query_complexity_category": query_cat,
                "query_present": _bool_field(record, "query_present"),
            },
            remediation={
                "summary": "Review the monitor query for clarity and maintainability.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor and review the query for clarity.",
                    "Consider simplifying or splitting complex queries into "
                    "multiple focused monitors.",
                ],
            },
            record_id=record_id,
        ))

    # ── M82C expansion rules ──────────────────────────────────────────────────

    # ── datadog_monitor_no_notifications ─────────────────────────────────────
    # Fires when the monitor message contains no notification routing (@mentions).
    # notification_routing_present is a safe boolean derived from the message
    # before discarding it — the raw message is NEVER stored.
    if not _bool_field(record, "notification_routing_present"):
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_NO_NOTIFICATIONS,
            finding_key=make_finding_key(_RULE_MONITOR_NO_NOTIFICATIONS, record_id),
            severity="medium",
            title="Datadog monitor has no notification routing",
            description=(
                "A Datadog monitor's message contains no notification routing "
                "(no @mentions such as @slack-channel, @pagerduty, or @email). "
                "Without notification routing, alerts from this monitor may not "
                "reach the on-call team. This is configuration evidence for "
                "review. Raw message content is never stored."
            ),
            evidence={
                "rule": _RULE_MONITOR_NO_NOTIFICATIONS,
                "record_id": record_id,
                "notification_routing_present": False,
                "notification_count": _int(record, "notification_count"),
            },
            remediation={
                "summary": "Add notification routing to the monitor message.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor and add at least one @notification target "
                    "(e.g. @slack-channel, @pagerduty-service, or @email).",
                    "If the monitor intentionally has no routing, add a comment "
                    "to the message explaining why.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_message_template_present ──────────────────────────────
    # Fires when the monitor message contains {{ template variables.
    # message_template_present is a safe boolean — raw message NEVER stored.
    if _bool_field(record, "message_template_present"):
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_MESSAGE_TEMPLATE,
            finding_key=make_finding_key(_RULE_MONITOR_MESSAGE_TEMPLATE, record_id),
            severity="low",
            title="Datadog monitor message uses template variables",
            description=(
                "A Datadog monitor's notification message uses template variables "
                "(e.g. {{value}}, {{threshold}}, {{host.name}}). Template variables "
                "expand to live values at alert time and should be reviewed "
                "periodically to confirm the expanded content is appropriate for "
                "the notification channel's audience. This is configuration "
                "evidence for review. Raw message content is never stored."
            ),
            evidence={
                "rule": _RULE_MONITOR_MESSAGE_TEMPLATE,
                "record_id": record_id,
                "message_template_present": True,
            },
            remediation={
                "summary": "Review the monitor message template for appropriate variable usage.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor and review the notification message.",
                    "Confirm that template variables expand to content appropriate "
                    "for the notification channel.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_no_warning_threshold ──────────────────────────────────
    # Fires when a critical threshold is set but no warning threshold exists.
    threshold_critical = _bool_field(record, "threshold_critical_present")
    threshold_warning = _bool_field(record, "threshold_warning_present")
    if threshold_critical and not threshold_warning:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_NO_WARNING_THRESHOLD,
            finding_key=make_finding_key(_RULE_MONITOR_NO_WARNING_THRESHOLD, record_id),
            severity="medium",
            title="Datadog monitor has a critical threshold but no warning threshold",
            description=(
                "A Datadog monitor is configured with a critical threshold but "
                "no warning threshold. Without a warning threshold, the monitor "
                "transitions directly from OK to ALERT with no intermediate state, "
                "reducing early-warning signal. This is configuration evidence for "
                "review."
            ),
            evidence={
                "rule": _RULE_MONITOR_NO_WARNING_THRESHOLD,
                "record_id": record_id,
                "threshold_critical_present": True,
                "threshold_warning_present": False,
            },
            remediation={
                "summary": "Consider adding a warning threshold to provide early-warning signal.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor and add a Warning threshold below the Critical threshold.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_no_recovery_threshold ─────────────────────────────────
    # Fires when a critical threshold is set but no recovery threshold exists.
    threshold_recovery = _bool_field(record, "threshold_recovery_present")
    if threshold_critical and not threshold_recovery:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_NO_RECOVERY_THRESHOLD,
            finding_key=make_finding_key(_RULE_MONITOR_NO_RECOVERY_THRESHOLD, record_id),
            severity="low",
            title="Datadog monitor has no recovery threshold",
            description=(
                "A Datadog monitor is configured with a critical threshold but "
                "no recovery threshold. Without a recovery threshold, the monitor "
                "may remain in alert state or flap frequently. This is "
                "configuration evidence for review."
            ),
            evidence={
                "rule": _RULE_MONITOR_NO_RECOVERY_THRESHOLD,
                "record_id": record_id,
                "threshold_critical_present": True,
                "threshold_recovery_present": False,
            },
            remediation={
                "summary": "Consider adding a recovery threshold to stabilize alert resolution.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor and add a recovery threshold in the alert conditions.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_silenced_scopes_present ───────────────────────────────
    silenced_scope_count = _int(record, "silenced_scope_count")
    if silenced_scope_count > 0:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_SILENCED_SCOPES,
            finding_key=make_finding_key(_RULE_MONITOR_SILENCED_SCOPES, record_id),
            severity="medium",
            title="Datadog monitor has silenced scopes",
            description=(
                f"A Datadog monitor has {silenced_scope_count} silenced scope(s). "
                "Silenced scopes suppress alerts for specific hosts, environments, "
                "or tags without disabling the entire monitor. Silenced scopes may "
                "represent acknowledged maintenance or forgotten suppressions. "
                "This is configuration evidence for review."
            ),
            evidence={
                "rule": _RULE_MONITOR_SILENCED_SCOPES,
                "record_id": record_id,
                "silenced_scope_count": silenced_scope_count,
            },
            remediation={
                "summary": "Review and remove expired or unintended silenced scopes.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor and check the Muting / Silenced Scopes section.",
                    "Remove silenced scopes that are no longer valid.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_notify_audit_disabled ─────────────────────────────────
    if not _bool_field(record, "notify_audit"):
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_NOTIFY_AUDIT_DISABLED,
            finding_key=make_finding_key(_RULE_MONITOR_NOTIFY_AUDIT_DISABLED, record_id),
            severity="low",
            title="Datadog monitor does not notify on audit changes",
            description=(
                "A Datadog monitor has audit notifications disabled. When "
                "monitor settings are changed, no notification is sent to the "
                "monitor's recipients. This can reduce visibility into who "
                "modified the monitor configuration. This is configuration "
                "evidence for review."
            ),
            evidence={
                "rule": _RULE_MONITOR_NOTIFY_AUDIT_DISABLED,
                "record_id": record_id,
                "notify_audit": False,
            },
            remediation={
                "summary": "Review enabling audit notifications for this monitor.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor and check the 'Notify if this alert is "
                    "modified' option.",
                    "Enable it if you want notifications when the monitor "
                    "configuration changes.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_require_full_window_disabled ──────────────────────────
    if not _bool_field(record, "require_full_window"):
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_REQUIRE_FULL_WINDOW_DISABLED,
            finding_key=make_finding_key(
                _RULE_MONITOR_REQUIRE_FULL_WINDOW_DISABLED, record_id
            ),
            severity="low",
            title="Datadog monitor does not require a full evaluation window",
            description=(
                "A Datadog monitor has 'require full window' disabled. This "
                "means the monitor may evaluate on a partial data window, "
                "which can produce alerts based on incomplete data. This is "
                "configuration evidence for review."
            ),
            evidence={
                "rule": _RULE_MONITOR_REQUIRE_FULL_WINDOW_DISABLED,
                "record_id": record_id,
                "require_full_window": False,
            },
            remediation={
                "summary": "Review whether this monitor should require a full evaluation window.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor advanced options.",
                    "Enable 'Require full window of data' if incomplete data "
                    "periods should not trigger alerts.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_query_wildcard_scope ──────────────────────────────────
    # Fires when the monitor query uses {*} (all-scope wildcard).
    # query_uses_wildcard_scope is derived from the query before discarding —
    # the raw query is NEVER stored.
    if _bool_field(record, "query_uses_wildcard_scope"):
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_QUERY_WILDCARD_SCOPE,
            finding_key=make_finding_key(_RULE_MONITOR_QUERY_WILDCARD_SCOPE, record_id),
            severity="medium",
            title="Datadog monitor uses a wildcard scope",
            description=(
                "A Datadog monitor's query uses a wildcard scope ({*}), which "
                "monitors all hosts, services, or metrics across the entire "
                "infrastructure. Wildcard-scoped monitors can generate high "
                "alert volumes and may mask issues with specific services. "
                "This is configuration evidence for review. Raw query content "
                "is never stored."
            ),
            evidence={
                "rule": _RULE_MONITOR_QUERY_WILDCARD_SCOPE,
                "record_id": record_id,
                "query_uses_wildcard_scope": True,
            },
            remediation={
                "summary": "Review whether the wildcard scope is appropriate for this monitor.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor and review the query scope.",
                    "If possible, narrow the scope to specific environments, "
                    "services, or hosts to reduce alert noise.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_broad_group_by ────────────────────────────────────────
    query_group_by_count = _int(record, "query_group_by_count")
    if query_group_by_count >= _BROAD_GROUP_BY_THRESHOLD:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_BROAD_GROUP_BY,
            finding_key=make_finding_key(_RULE_MONITOR_BROAD_GROUP_BY, record_id),
            severity="low",
            title="Datadog monitor has a broad group-by configuration",
            description=(
                f"A Datadog monitor has {query_group_by_count} group-by clause(s) "
                "in its query, which may create a large number of alert groups "
                "across many dimension combinations. This can produce high alert "
                "volumes and make alert management difficult. This is configuration "
                "evidence for review. Raw query content is never stored."
            ),
            evidence={
                "rule": _RULE_MONITOR_BROAD_GROUP_BY,
                "record_id": record_id,
                "query_group_by_count": query_group_by_count,
            },
            remediation={
                "summary": "Review and reduce the group-by dimensions in the monitor query.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor and review the group-by configuration.",
                    "Consider reducing the number of group-by dimensions to "
                    "focus alerts on the most actionable signals.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_monitor_long_no_data_timeframe ────────────────────────────────
    no_data_cat = get_str(record, "no_data_timeframe_category")
    if no_data_cat == "extended":
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_MONITOR_LONG_NO_DATA_TIMEFRAME,
            finding_key=make_finding_key(_RULE_MONITOR_LONG_NO_DATA_TIMEFRAME, record_id),
            severity="low",
            title="Datadog monitor has a long no-data timeframe",
            description=(
                "A Datadog monitor has a no-data timeframe classified as extended "
                "(2 hours or more). A long no-data window means the monitor waits "
                "an extended period before alerting on absent data, which may delay "
                "detection of agent or integration outages. This is configuration "
                "evidence for review."
            ),
            evidence={
                "rule": _RULE_MONITOR_LONG_NO_DATA_TIMEFRAME,
                "record_id": record_id,
                "no_data_timeframe_category": no_data_cat,
            },
            remediation={
                "summary": "Review and reduce the no-data timeframe for this monitor.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Monitors > Manage Monitors.",
                    "Open the monitor and review the 'No Data' options.",
                    "Reduce the no-data timeframe to a value appropriate for "
                    "the expected data ingestion frequency.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── SLO evaluator ─────────────────────────────────────────────────────────────


def _eval_slo(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one datadog_slo record.

    SECURITY: raw SLO descriptions and query strings are NEVER stored.
    Evidence uses only counts, categories, and the opaque record_id.
    """
    record_id = get_str(record, "record_id") or get_str(record, "resource_id")
    findings: list[FindingCandidate] = []

    # ── datadog_slo_no_monitors ───────────────────────────────────────────────
    slo_type = get_str(record, "slo_type")
    monitor_count = _int(record, "monitor_count")
    if slo_type == "monitor" and monitor_count == 0:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_SLO_NO_MONITORS,
            finding_key=make_finding_key(_RULE_SLO_NO_MONITORS, record_id),
            severity="medium",
            title="Datadog monitor-based SLO has no linked monitors",
            description=(
                "A Datadog monitor-based SLO has zero linked monitors. An SLO "
                "without linked monitors may not be measuring anything and could "
                "represent an incomplete configuration. This is configuration "
                "evidence for review."
            ),
            evidence={
                "rule": _RULE_SLO_NO_MONITORS,
                "record_id": record_id,
                "slo_type": slo_type,
                "monitor_count": 0,
            },
            remediation={
                "summary": "Link monitors to this SLO or remove it if unused.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Service Mgmt > SLOs.",
                    "Open the SLO and add the relevant monitors.",
                    "If the SLO is no longer needed, delete it to keep inventory clean.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_slo_low_target ────────────────────────────────────────────────
    target_cat = get_str(record, "target_category")
    if target_cat == "below_95":
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_SLO_LOW_TARGET,
            finding_key=make_finding_key(_RULE_SLO_LOW_TARGET, record_id),
            severity="low",
            title="Datadog SLO has a target below 95%",
            description=(
                "A Datadog SLO has a configured target below 95%. A very low "
                "reliability target may indicate the SLO is outdated, set as a "
                "placeholder, or does not align with operational expectations. "
                "This is configuration evidence for review."
            ),
            evidence={
                "rule": _RULE_SLO_LOW_TARGET,
                "record_id": record_id,
                "target_category": target_cat,
            },
            remediation={
                "summary": "Review the SLO target to confirm it reflects operational expectations.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Service Mgmt > SLOs.",
                    "Open the SLO and review the target percentage.",
                    "Update the target to align with your service-level agreements.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Dashboard evaluator ───────────────────────────────────────────────────────


def _eval_dashboard(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one datadog_dashboard record.

    SECURITY: raw dashboard JSON, widget queries, formulas, and public URL
    strings are NEVER stored. Evidence uses only booleans, counts, and the
    opaque record_id.
    """
    record_id = get_str(record, "record_id") or get_str(record, "resource_id")
    findings: list[FindingCandidate] = []

    # ── datadog_dashboard_public_url_present ──────────────────────────────────
    if _bool_field(record, "public_url_present"):
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_DASHBOARD_PUBLIC_URL,
            finding_key=make_finding_key(_RULE_DASHBOARD_PUBLIC_URL, record_id),
            severity="medium",
            title="Datadog dashboard has a public URL",
            description=(
                "A Datadog dashboard has a public sharing URL enabled. Dashboards "
                "shared publicly are accessible to anyone with the URL, without "
                "Datadog authentication. Depending on what the dashboard displays, "
                "this may expose metric names, infrastructure topology, or operational "
                "indicators to external viewers. This is configuration evidence for "
                "review. The URL value is never stored."
            ),
            evidence={
                "rule": _RULE_DASHBOARD_PUBLIC_URL,
                "record_id": record_id,
                "public_url_present": True,
            },
            remediation={
                "summary": "Revoke the public sharing URL if the dashboard should not be publicly accessible.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Dashboards.",
                    "Open the dashboard and look for the Share settings.",
                    "Revoke any public sharing URLs if the dashboard should "
                    "remain internal.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_dashboard_unrestricted_roles ──────────────────────────────────
    restricted_roles_count = _int(record, "restricted_roles_count")
    if restricted_roles_count == 0:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_DASHBOARD_UNRESTRICTED_ROLES,
            finding_key=make_finding_key(_RULE_DASHBOARD_UNRESTRICTED_ROLES, record_id),
            severity="low",
            title="Datadog dashboard has no restricted roles",
            description=(
                "A Datadog dashboard is not restricted to any role. Without role "
                "restrictions, any Datadog user may view or edit the dashboard. "
                "This configuration evidence may require review to confirm the "
                "access posture is appropriate, particularly for dashboards that "
                "display sensitive operational data."
            ),
            evidence={
                "rule": _RULE_DASHBOARD_UNRESTRICTED_ROLES,
                "record_id": record_id,
                "restricted_roles_count": 0,
            },
            remediation={
                "summary": "Consider restricting sensitive dashboards to specific roles.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Dashboards and open the dashboard.",
                    "Under Settings, add role-based access restrictions.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Webhook integration evaluator ─────────────────────────────────────────────


def _eval_webhook(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one datadog_webhook_integration record.

    SECURITY: webhook URLs (full strings), custom HTTP header names/values,
    payload template content, and signing secrets are NEVER stored. Evidence
    uses only presence booleans, counts, safe categories, and the opaque
    record_id. M82C adds url_scheme_category, custom_header_count,
    auth_material_present, and payload_template_length_category checks.
    """
    record_id = get_str(record, "record_id") or get_str(record, "resource_id")
    findings: list[FindingCandidate] = []

    url_present = _bool_field(record, "url_present")
    secret_headers_present = _bool_field(record, "secret_headers_present")
    payload_template_present = _bool_field(record, "payload_template_present")
    custom_headers_present = _bool_field(record, "custom_headers_present")

    # ── datadog_webhook_without_secret_headers (M82B) ─────────────────────────
    if url_present and not secret_headers_present:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_WEBHOOK_WITHOUT_SECRET_HEADERS,
            finding_key=make_finding_key(_RULE_WEBHOOK_WITHOUT_SECRET_HEADERS, record_id),
            severity="high",
            title="Datadog webhook has no secret header configured",
            description=(
                "A Datadog webhook integration has a URL configured but no secret "
                "header set. Without a shared secret header, the receiving endpoint "
                "cannot verify that incoming requests originate from Datadog. This "
                "may allow spoofed webhook deliveries to trigger responses on the "
                "receiving system. This is configuration evidence for review. "
                "Webhook URLs and header values are never stored."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_WITHOUT_SECRET_HEADERS,
                "record_id": record_id,
                "url_present": True,
                "secret_headers_present": False,
            },
            remediation={
                "summary": "Add a secret header to verify the origin of Datadog webhook deliveries.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Integrations > Webhooks.",
                    "Open the webhook configuration.",
                    "Add a custom header (e.g. X-Datadog-Signature) with a shared "
                    "secret that the receiving endpoint can validate.",
                    "Update your receiving service to validate the secret header "
                    "before processing deliveries.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_webhook_payload_template_present (M82B) ───────────────────────
    if payload_template_present:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_WEBHOOK_PAYLOAD_TEMPLATE,
            finding_key=make_finding_key(_RULE_WEBHOOK_PAYLOAD_TEMPLATE, record_id),
            severity="low",
            title="Datadog webhook has a custom payload template",
            description=(
                "A Datadog webhook integration has a custom payload template "
                "configured. Custom templates define the structure of data sent to "
                "the webhook endpoint on each delivery. This configuration evidence "
                "may require review to confirm the template does not include "
                "sensitive variable substitutions. Raw payload template content is "
                "never stored."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_PAYLOAD_TEMPLATE,
                "record_id": record_id,
                "payload_template_present": True,
            },
            remediation={
                "summary": "Review the webhook payload template for sensitive variable substitutions.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Integrations > Webhooks.",
                    "Review the payload template to confirm it does not include "
                    "sensitive fields or credentials.",
                ],
            },
            record_id=record_id,
        ))

    # ── M82C expansion rules ──────────────────────────────────────────────────

    # ── datadog_webhook_non_https_endpoint ────────────────────────────────────
    # Fires when the URL scheme is http (insecure).
    # url_scheme_category is derived from URL before discarding — URL NEVER stored.
    url_scheme_cat = get_str(record, "url_scheme_category")
    if url_scheme_cat == "http":
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_WEBHOOK_NON_HTTPS,
            finding_key=make_finding_key(_RULE_WEBHOOK_NON_HTTPS, record_id),
            severity="high",
            title="Datadog webhook endpoint uses insecure HTTP",
            description=(
                "A Datadog webhook integration is configured with an endpoint that "
                "uses plain HTTP rather than HTTPS. Webhook payloads delivered over "
                "HTTP are transmitted without transport-layer encryption, which may "
                "expose event content in transit. This is configuration evidence for "
                "review. The webhook URL is never stored."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_NON_HTTPS,
                "record_id": record_id,
                "url_scheme_category": "http",
            },
            remediation={
                "summary": "Update the webhook endpoint URL to use HTTPS.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Integrations > Webhooks.",
                    "Open the webhook configuration and update the URL to use HTTPS.",
                    "Verify the endpoint has a valid TLS certificate before updating.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_webhook_custom_headers_without_secret_headers ─────────────────
    # Fires when custom headers are present but no secret headers are configured.
    # This is distinct from M82B's url_present+no_secret rule: it specifically
    # targets webhooks with custom headers that bypass the secret header pattern.
    # Header names and values are NEVER stored.
    if custom_headers_present and not secret_headers_present:
        custom_header_count = _int(record, "custom_header_count")
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_WEBHOOK_CUSTOM_HEADERS_NO_SECRET,
            finding_key=make_finding_key(_RULE_WEBHOOK_CUSTOM_HEADERS_NO_SECRET, record_id),
            severity="medium",
            title="Datadog webhook has custom headers but no secret header",
            description=(
                "A Datadog webhook integration has custom HTTP headers configured "
                "but no dedicated secret header. Custom headers may contain "
                "authentication material that should be tracked separately from "
                "a signing secret. Without a secret header, the receiving endpoint "
                "cannot verify the integrity of each delivery. This is configuration "
                "evidence for review. Header names and values are never stored."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_CUSTOM_HEADERS_NO_SECRET,
                "record_id": record_id,
                "custom_headers_present": True,
                "custom_header_count": custom_header_count,
                "secret_headers_present": False,
            },
            remediation={
                "summary": "Add a dedicated secret header for delivery integrity verification.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Integrations > Webhooks.",
                    "Open the webhook configuration.",
                    "Add a secret header (separate from custom auth headers) that "
                    "the receiving endpoint can use to verify delivery origin.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_webhook_large_payload_template ────────────────────────────────
    # Fires when the payload template is long (classified "long" by length).
    # Content is NEVER stored — only the length category.
    payload_template_len_cat = get_str(record, "payload_template_length_category")
    if payload_template_len_cat == "long":
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_WEBHOOK_LARGE_PAYLOAD_TEMPLATE,
            finding_key=make_finding_key(_RULE_WEBHOOK_LARGE_PAYLOAD_TEMPLATE, record_id),
            severity="low",
            title="Datadog webhook has a large payload template",
            description=(
                "A Datadog webhook integration has a payload template classified "
                "as large in length. A large template may contain many variable "
                "substitutions, complex logic, or embedded content that is harder "
                "to audit and maintain. This is configuration evidence for review. "
                "Raw payload template content is never stored."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_LARGE_PAYLOAD_TEMPLATE,
                "record_id": record_id,
                "payload_template_length_category": payload_template_len_cat,
            },
            remediation={
                "summary": "Review and simplify the webhook payload template.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Integrations > Webhooks.",
                    "Review the payload template and remove unnecessary content.",
                    "Consider using the default Datadog payload instead of a "
                    "custom template if the receiving service can accept it.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_webhook_auth_material_present ─────────────────────────────────
    # Fires when auth-pattern header names are detected in custom_headers.
    # Header names are used for detection only — NEVER stored.
    # Header values are NEVER read or stored.
    if _bool_field(record, "auth_material_present"):
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_WEBHOOK_AUTH_MATERIAL,
            finding_key=make_finding_key(_RULE_WEBHOOK_AUTH_MATERIAL, record_id),
            severity="medium",
            title="Datadog webhook configuration includes authentication material",
            description=(
                "A Datadog webhook integration has custom headers that appear to "
                "contain authentication material (e.g. Authorization, API-Key, or "
                "Token headers). Authentication headers embedded in webhook "
                "configurations may require periodic rotation review. This is "
                "configuration evidence for review. Header names and values are "
                "never stored."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_AUTH_MATERIAL,
                "record_id": record_id,
                "auth_material_present": True,
            },
            remediation={
                "summary": "Review and rotate authentication material in the webhook headers.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Integrations > Webhooks.",
                    "Review the webhook's custom headers and confirm the credentials "
                    "are up to date.",
                    "Rotate any credentials that may have been in use for an "
                    "extended period.",
                    "Consider using a secret header instead of embedding auth "
                    "material in custom headers.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Notification integration evaluator ───────────────────────────────────────


def _eval_notification_integration(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one datadog_notification_integration record.

    SECURITY: service keys, subdomain strings, Slack channel names,
    PagerDuty service IDs, OpsGenie keys, and all destination handles
    are NEVER stored. Evidence uses only counts and the integration_type label.
    """
    record_id = get_str(record, "record_id") or get_str(record, "resource_id")
    findings: list[FindingCandidate] = []

    # ── datadog_notification_integration_no_channels ──────────────────────────
    enabled = _bool_field(record, "enabled")
    handle_count = _int(record, "handle_count")
    channel_count = _int(record, "channel_count")
    integration_type = get_str(record, "integration_type")

    if enabled and handle_count == 0 and channel_count == 0:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_NOTIF_NO_CHANNELS,
            finding_key=make_finding_key(_RULE_NOTIF_NO_CHANNELS, record_id),
            severity="low",
            title="Datadog notification integration has no configured channels",
            description=(
                f"A Datadog {integration_type} notification integration is "
                "configured but has no channels or handles set up. Without "
                "destination channels, alert notifications may not be delivered. "
                "This is configuration evidence for review. Destination handle "
                "values and channel names are never stored."
            ),
            evidence={
                "rule": _RULE_NOTIF_NO_CHANNELS,
                "record_id": record_id,
                "integration_type": integration_type,
                "handle_count": 0,
                "channel_count": 0,
            },
            remediation={
                "summary": "Configure notification channels for this integration.",
                "steps": [
                    "Sign in to Datadog.",
                    f"Navigate to Integrations > {integration_type.capitalize()}.",
                    "Configure the required notification channels or handles.",
                    "If the integration is no longer needed, remove it from the configuration.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── API key evaluator ─────────────────────────────────────────────────────────


def _eval_api_key(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one datadog_api_key_metadata record.

    SECURITY: API key values, last4 digits, and authorization headers are
    NEVER stored. Evidence uses only the disabled boolean and the opaque record_id.
    """
    record_id = get_str(record, "record_id") or get_str(record, "resource_id")
    findings: list[FindingCandidate] = []

    # ── datadog_api_key_disabled ──────────────────────────────────────────────
    if _bool_field(record, "disabled"):
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_APIKEY_DISABLED,
            finding_key=make_finding_key(_RULE_APIKEY_DISABLED, record_id),
            severity="low",
            title="Datadog API key is disabled",
            description=(
                "A Datadog API key in the inventory is disabled or revoked. "
                "A disabled key in the active inventory may indicate stale "
                "automation that should be removed, or a key that was revoked "
                "due to a prior issue. This is configuration evidence for review. "
                "The key value is never stored."
            ),
            evidence={
                "rule": _RULE_APIKEY_DISABLED,
                "record_id": record_id,
                "disabled": True,
            },
            remediation={
                "summary": "Review and remove stale or disabled API keys.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Organization Settings > API Keys.",
                    "Review disabled keys and remove any that are no longer needed.",
                    "Rotate active keys that may have been compromised and created "
                    "a replacement.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Application key evaluator ─────────────────────────────────────────────────


def _eval_application_key(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one datadog_application_key_metadata record.

    SECURITY: application key values, hashes, and authorization headers are
    NEVER stored. Evidence uses only the scopes_count integer and opaque record_id.
    """
    record_id = get_str(record, "record_id") or get_str(record, "resource_id")
    findings: list[FindingCandidate] = []

    # ── datadog_application_key_broad_scopes ──────────────────────────────────
    scopes_count = _int(record, "scopes_count")
    if scopes_count > _BROAD_SCOPES_THRESHOLD:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_APPKEY_BROAD_SCOPES,
            finding_key=make_finding_key(_RULE_APPKEY_BROAD_SCOPES, record_id),
            severity="medium",
            title="Datadog application key has a broad scope count",
            description=(
                f"A Datadog application key has {scopes_count} scopes configured, "
                f"exceeding the review threshold of {_BROAD_SCOPES_THRESHOLD}. "
                "Application keys with many scopes have broad API access to the "
                "Datadog organization. This configuration evidence may require "
                "review to confirm all granted scopes are necessary. Scope names "
                "and key values are never stored."
            ),
            evidence={
                "rule": _RULE_APPKEY_BROAD_SCOPES,
                "record_id": record_id,
                "scopes_count": scopes_count,
            },
            remediation={
                "summary": "Review the application key's scopes and reduce to the minimum necessary.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Organization Settings > Application Keys.",
                    "Open the key and review its granted scopes.",
                    "Remove any scopes that are not required by the integration "
                    "or automation using this key.",
                    "Consider creating separate, narrowly-scoped application keys "
                    "for different purposes.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Role evaluator ────────────────────────────────────────────────────────────


def _eval_role(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one datadog_role record.

    SECURITY: user identities, user emails, user IDs, and user names are
    NEVER stored. Evidence uses only the permission_count integer and
    opaque record_id.
    """
    record_id = get_str(record, "record_id") or get_str(record, "resource_id")
    findings: list[FindingCandidate] = []

    # ── datadog_role_high_permission_count ────────────────────────────────────
    permission_count = _int(record, "permission_count")
    if permission_count > _HIGH_PERMISSION_THRESHOLD:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_ROLE_HIGH_PERMISSIONS,
            finding_key=make_finding_key(_RULE_ROLE_HIGH_PERMISSIONS, record_id),
            severity="medium",
            title="Datadog role has a high permission count",
            description=(
                f"A Datadog role has {permission_count} permissions configured, "
                f"exceeding the review threshold of {_HIGH_PERMISSION_THRESHOLD}. "
                "Roles with many permissions grant broad access to Datadog "
                "resources and operations. This configuration evidence may require "
                "review to confirm all permissions are appropriate for the role's "
                "purpose. User identities assigned to the role are never stored."
            ),
            evidence={
                "rule": _RULE_ROLE_HIGH_PERMISSIONS,
                "record_id": record_id,
                "permission_count": permission_count,
            },
            remediation={
                "summary": "Review the role's permissions and reduce to the minimum necessary.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Organization Settings > Roles.",
                    "Open the role and review its permissions.",
                    "Remove permissions that are not required by the role's function.",
                    "Consider splitting broad roles into narrower, purpose-specific roles.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Team evaluator ────────────────────────────────────────────────────────────


def _eval_team(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one datadog_team record.

    SECURITY: member names, member emails, member IDs, and team handles
    are NEVER stored. Evidence uses only the member_count integer and
    opaque record_id.
    """
    record_id = get_str(record, "record_id") or get_str(record, "resource_id")
    findings: list[FindingCandidate] = []

    # ── datadog_team_no_members ───────────────────────────────────────────────
    member_count = _int(record, "member_count")
    if member_count == 0:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_TEAM_NO_MEMBERS,
            finding_key=make_finding_key(_RULE_TEAM_NO_MEMBERS, record_id),
            severity="low",
            title="Datadog team has no members",
            description=(
                "A Datadog team has zero members. An empty team may indicate "
                "stale configuration that should be cleaned up, or an incomplete "
                "onboarding. Notifications and on-call routing that reference "
                "this team may not reach any responders. This is configuration "
                "evidence for review. Member identities are never stored."
            ),
            evidence={
                "rule": _RULE_TEAM_NO_MEMBERS,
                "record_id": record_id,
                "member_count": 0,
            },
            remediation={
                "summary": "Add members to the team or remove it if unused.",
                "steps": [
                    "Sign in to Datadog.",
                    "Navigate to Organization Settings > Teams.",
                    "Open the team and add the appropriate members.",
                    "If the team is no longer needed, delete it to keep "
                    "the configuration clean.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Cloud integration evaluator ───────────────────────────────────────────────


def _eval_cloud_integration(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one datadog_cloud_integration record.

    SECURITY: AWS account IDs, GCP project IDs, Azure tenant/subscription IDs,
    IAM role ARNs, and service account email addresses are NEVER stored.
    Evidence uses only collection flags and the opaque record_id.
    """
    record_id = get_str(record, "record_id") or get_str(record, "resource_id")
    cloud_provider = get_str(record, "cloud_provider")
    findings: list[FindingCandidate] = []

    resource_collection = _bool_field(record, "resource_collection_enabled")
    metric_collection = _bool_field(record, "metric_collection_enabled")
    log_collection = _bool_field(record, "log_collection_enabled")

    # ── datadog_cloud_integration_broad_collection ────────────────────────────
    if resource_collection and metric_collection and log_collection:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_CLOUD_BROAD_COLLECTION,
            finding_key=make_finding_key(_RULE_CLOUD_BROAD_COLLECTION, record_id),
            severity="medium",
            title="Datadog cloud integration has all collection types enabled",
            description=(
                f"A Datadog {cloud_provider.upper()} cloud integration has resource "
                "collection, metric collection, and log collection all enabled. "
                "Enabling all collection types grants Datadog broad read access to "
                "your cloud environment, including logs that may contain application "
                "data or operational details. This configuration evidence may require "
                "review to confirm all collection types are necessary."
            ),
            evidence={
                "rule": _RULE_CLOUD_BROAD_COLLECTION,
                "record_id": record_id,
                "cloud_provider": cloud_provider,
                "resource_collection_enabled": True,
                "metric_collection_enabled": True,
                "log_collection_enabled": True,
            },
            remediation={
                "summary": "Review the cloud integration's collection scope and disable unnecessary types.",
                "steps": [
                    "Sign in to Datadog.",
                    f"Navigate to Integrations > {cloud_provider.upper()}.",
                    "Review the configured collection types for each account.",
                    "Disable resource collection, metric collection, or log "
                    "collection for accounts where those types are not required.",
                    "Verify log collection is only enabled for accounts where "
                    "log forwarding has been reviewed and approved.",
                ],
            },
            record_id=record_id,
        ))

    # ── datadog_cloud_integration_log_collection_enabled ─────────────────────
    if log_collection:
        findings.append(FindingCandidate(
            provider="datadog",
            rule_key=_RULE_CLOUD_LOG_COLLECTION,
            finding_key=make_finding_key(_RULE_CLOUD_LOG_COLLECTION, record_id),
            severity="low",
            title="Datadog cloud integration has log collection enabled",
            description=(
                f"A Datadog {cloud_provider.upper()} cloud integration has log "
                "collection enabled. Log collection forwards cloud logs to Datadog, "
                "which may include application output, access logs, or other "
                "operational data. This configuration evidence may require review "
                "to confirm that log collection scope aligns with your data handling "
                "policies. Raw log content is never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_CLOUD_LOG_COLLECTION,
                "record_id": record_id,
                "cloud_provider": cloud_provider,
                "log_collection_enabled": True,
            },
            remediation={
                "summary": "Review log collection scope for this cloud integration.",
                "steps": [
                    "Sign in to Datadog.",
                    f"Navigate to Integrations > {cloud_provider.upper()}.",
                    "Review the log forwarding configuration for this account.",
                    "Ensure log exclusion filters are configured to prevent "
                    "sensitive application logs from being forwarded.",
                    "Disable log collection if it is not required.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Public evaluate entry point ───────────────────────────────────────────────


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one normalized Datadog drift record and return any findings.

    Accepts any dict. Unknown record_type values return an empty list — never
    raises. Each evaluator is self-contained and never mutates the record.

    SECURITY: no rule reads or stores API key values, application key values,
    OAuth tokens, bearer tokens, webhook URLs, webhook secrets, integration
    secrets, raw monitor queries, raw monitor messages, raw dashboard JSON,
    raw widget queries, raw log/trace/metric values, raw event payloads, email
    addresses, user names, user IDs, team member identities, notification
    destination handles, cloud account IDs, or customer data.
    """
    if not isinstance(record, dict):
        return []

    rtype = record.get("record_type")

    if rtype == DATADOG_MONITOR:
        return _eval_monitor(record)
    if rtype == DATADOG_SLO:
        return _eval_slo(record)
    if rtype == DATADOG_DASHBOARD:
        return _eval_dashboard(record)
    if rtype == DATADOG_WEBHOOK_INTEGRATION:
        return _eval_webhook(record)
    if rtype == DATADOG_NOTIFICATION_INTEGRATION:
        return _eval_notification_integration(record)
    if rtype == DATADOG_API_KEY_METADATA:
        return _eval_api_key(record)
    if rtype == DATADOG_APPLICATION_KEY_METADATA:
        return _eval_application_key(record)
    if rtype == DATADOG_ROLE:
        return _eval_role(record)
    if rtype == DATADOG_TEAM:
        return _eval_team(record)
    if rtype == DATADOG_CLOUD_INTEGRATION:
        return _eval_cloud_integration(record)

    return []
