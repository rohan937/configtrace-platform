"""PagerDuty configuration-risk security rules — M84B, expanded M84C.

Every rule fires only on explicit, reliable normalized fields produced by
the PagerDuty connector (app/connectors/pagerduty.py + pagerduty_schema.py,
M84A).  Evidence is metadata-only: booleans, counts, categories, opaque
identifiers, and safe string labels.

NEVER read, stored, or surfaced:
  PagerDuty API tokens, routing keys, integration keys, webhook secrets,
  delivery URLs, raw webhook URLs, incident payloads, alert payloads,
  request/response payloads, user emails, user names, phone numbers, SMS
  numbers, push tokens, contact methods, on-call user identities, responder
  identities, subscriber identities, conference phone numbers, raw routing
  expressions, authorization headers, IP addresses, user agents, audit logs,
  customer data, or PII of any kind.

CLAIM DISCIPLINE
----------------
These are configuration posture findings that may require review.  A finding
is evidence for review only.  It never asserts that a token was leaked, that
a credential was compromised, that unauthorized access occurred, or that any
attacker is present.  Severity reflects review priority, not confirmed impact.

Record types evaluated (M84A)
------------------------------
  pagerduty_service              — services list and posture
  pagerduty_escalation_policy    — escalation policy posture
  pagerduty_schedule             — on-call schedule posture
  pagerduty_service_integration  — per-service integration posture
  pagerduty_webhook_subscription — V3 webhook subscription posture
  pagerduty_event_orchestration  — event orchestration posture
  pagerduty_business_service     — business service posture
  pagerduty_response_play        — response play posture
"""

from __future__ import annotations

from typing import Any

from app.connectors.pagerduty_schema import (
    PAGERDUTY_BUSINESS_SERVICE,
    PAGERDUTY_ESCALATION_POLICY,
    PAGERDUTY_EVENT_ORCHESTRATION,
    PAGERDUTY_RESPONSE_PLAY,
    PAGERDUTY_SCHEDULE,
    PAGERDUTY_SERVICE,
    PAGERDUTY_SERVICE_INTEGRATION,
    PAGERDUTY_WEBHOOK_SUBSCRIPTION,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Rule key constants ─────────────────────────────────────────────────────────

# Service rules
_RULE_SERVICE_NO_ESCALATION_POLICY = "pagerduty_service_no_escalation_policy"
_RULE_SERVICE_NO_INTEGRATIONS = "pagerduty_service_no_integrations"
_RULE_SERVICE_ACK_TIMEOUT_DISABLED = "pagerduty_service_ack_timeout_disabled"
_RULE_SERVICE_AUTO_RESOLVE_DISABLED = "pagerduty_service_auto_resolve_disabled"
_RULE_SERVICE_ALERT_CREATION_LIMITED = "pagerduty_service_alert_creation_limited"
_RULE_SERVICE_NO_TEAMS = "pagerduty_service_no_teams"

# Escalation policy rules — M84B
_RULE_EP_NO_RULES = "pagerduty_escalation_policy_no_rules"
_RULE_EP_SINGLE_LEVEL = "pagerduty_escalation_policy_single_level"
# Escalation policy rules — M84C
_RULE_EP_NO_TARGETS = "pagerduty_escalation_policy_no_targets"
_RULE_EP_LOW_TARGET_COUNT = "pagerduty_escalation_policy_low_target_count"
_RULE_EP_NO_SCHEDULE_TARGETS = "pagerduty_escalation_policy_no_schedule_targets"
_RULE_EP_NO_TEAM_TARGETS = "pagerduty_escalation_policy_no_team_targets"

# Schedule rules — M84B
_RULE_SCHEDULE_NO_LAYERS = "pagerduty_schedule_no_layers"
_RULE_SCHEDULE_NO_TEAMS = "pagerduty_schedule_no_teams"
# Schedule rules — M84C
_RULE_SCHEDULE_NO_TARGETS = "pagerduty_schedule_no_targets"
_RULE_SCHEDULE_LOW_TARGET_COUNT = "pagerduty_schedule_low_target_count"
_RULE_SCHEDULE_SINGLE_LAYER = "pagerduty_schedule_single_layer"
_RULE_SCHEDULE_NO_RESTRICTIONS = "pagerduty_schedule_no_restrictions"

# Service integration rules — M84B
_RULE_INTEGRATION_MISSING_KEY = "pagerduty_service_integration_missing_key_indicator"
_RULE_INTEGRATION_EMAIL_TYPE = "pagerduty_service_integration_email_type"
# Service integration rules — M84C
_RULE_INTEGRATION_ROUTING_KEY_MISSING = "pagerduty_service_integration_routing_key_missing"
_RULE_INTEGRATION_UNKNOWN_TYPE = "pagerduty_service_integration_unknown_type"

# Webhook subscription rules — M84B
_RULE_WEBHOOK_INACTIVE = "pagerduty_webhook_subscription_inactive"
_RULE_WEBHOOK_NON_HTTPS = "pagerduty_webhook_subscription_non_https"
_RULE_WEBHOOK_BROAD_SCOPE = "pagerduty_webhook_subscription_broad_event_scope"
# Webhook subscription rules — M84C
_RULE_WEBHOOK_NO_EVENTS = "pagerduty_webhook_subscription_no_events"
_RULE_WEBHOOK_SECRET_NOT_INDICATED = "pagerduty_webhook_subscription_secret_not_indicated"
_RULE_WEBHOOK_BROAD_SCOPE_HIGH = "pagerduty_webhook_subscription_broad_scope_high"
_RULE_WEBHOOK_ACCOUNT_SCOPE = "pagerduty_webhook_subscription_account_scope"

# Event orchestration rules — M84B
_RULE_ORCHESTRATION_NO_ROUTES = "pagerduty_event_orchestration_no_routes"
_RULE_ORCHESTRATION_NO_TEAM = "pagerduty_event_orchestration_no_team"
# Event orchestration rules — M84C
_RULE_ORCHESTRATION_LOW_ROUTE_COUNT = "pagerduty_event_orchestration_low_route_count"

# Business service rules
_RULE_BUSINESS_SERVICE_NO_TEAM = "pagerduty_business_service_no_team"
_RULE_BUSINESS_SERVICE_NO_CONTACT = "pagerduty_business_service_no_contact"

# Response play rules — M84B
_RULE_RESPONSE_PLAY_NO_RESPONDERS = "pagerduty_response_play_no_responders"
_RULE_RESPONSE_PLAY_NO_SUBSCRIBERS = "pagerduty_response_play_no_subscribers"
_RULE_RESPONSE_PLAY_NOT_RUNNABLE = "pagerduty_response_play_not_runnable"
# Response play rules — M84C
_RULE_RESPONSE_PLAY_LOW_RESPONDER_COUNT = "pagerduty_response_play_low_responder_count"
_RULE_RESPONSE_PLAY_NO_TEAM = "pagerduty_response_play_no_team"
_RULE_RESPONSE_PLAY_MANUAL_ONLY = "pagerduty_response_play_manual_only"

# ── Thresholds ─────────────────────────────────────────────────────────────────

# Webhook subscriptions with more than this many event types are flagged as
# broad scope (lower specificity means more noise and harder to audit).
_BROAD_WEBHOOK_EVENTS_THRESHOLD = 10
# Webhook subscriptions exceeding this higher threshold are high-severity.
_BROAD_WEBHOOK_EVENTS_HIGH_THRESHOLD = 20

# ── All PagerDuty rule keys implemented in this module ────────────────────────

PAGERDUTY_RULE_KEYS: frozenset[str] = frozenset({
    # Service — M84B
    _RULE_SERVICE_NO_ESCALATION_POLICY,
    _RULE_SERVICE_NO_INTEGRATIONS,
    _RULE_SERVICE_ACK_TIMEOUT_DISABLED,
    _RULE_SERVICE_AUTO_RESOLVE_DISABLED,
    _RULE_SERVICE_ALERT_CREATION_LIMITED,
    _RULE_SERVICE_NO_TEAMS,
    # Escalation policy — M84B
    _RULE_EP_NO_RULES,
    _RULE_EP_SINGLE_LEVEL,
    # Escalation policy — M84C
    _RULE_EP_NO_TARGETS,
    _RULE_EP_LOW_TARGET_COUNT,
    _RULE_EP_NO_SCHEDULE_TARGETS,
    _RULE_EP_NO_TEAM_TARGETS,
    # Schedule — M84B
    _RULE_SCHEDULE_NO_LAYERS,
    _RULE_SCHEDULE_NO_TEAMS,
    # Schedule — M84C
    _RULE_SCHEDULE_NO_TARGETS,
    _RULE_SCHEDULE_LOW_TARGET_COUNT,
    _RULE_SCHEDULE_SINGLE_LAYER,
    _RULE_SCHEDULE_NO_RESTRICTIONS,
    # Service integration — M84B
    _RULE_INTEGRATION_MISSING_KEY,
    _RULE_INTEGRATION_EMAIL_TYPE,
    # Service integration — M84C
    _RULE_INTEGRATION_ROUTING_KEY_MISSING,
    _RULE_INTEGRATION_UNKNOWN_TYPE,
    # Webhook subscription — M84B
    _RULE_WEBHOOK_INACTIVE,
    _RULE_WEBHOOK_NON_HTTPS,
    _RULE_WEBHOOK_BROAD_SCOPE,
    # Webhook subscription — M84C
    _RULE_WEBHOOK_NO_EVENTS,
    _RULE_WEBHOOK_SECRET_NOT_INDICATED,
    _RULE_WEBHOOK_BROAD_SCOPE_HIGH,
    _RULE_WEBHOOK_ACCOUNT_SCOPE,
    # Event orchestration — M84B
    _RULE_ORCHESTRATION_NO_ROUTES,
    _RULE_ORCHESTRATION_NO_TEAM,
    # Event orchestration — M84C
    _RULE_ORCHESTRATION_LOW_ROUTE_COUNT,
    # Business service
    _RULE_BUSINESS_SERVICE_NO_TEAM,
    _RULE_BUSINESS_SERVICE_NO_CONTACT,
    # Response play — M84B
    _RULE_RESPONSE_PLAY_NO_RESPONDERS,
    _RULE_RESPONSE_PLAY_NO_SUBSCRIBERS,
    _RULE_RESPONSE_PLAY_NOT_RUNNABLE,
    # Response play — M84C
    _RULE_RESPONSE_PLAY_LOW_RESPONDER_COUNT,
    _RULE_RESPONSE_PLAY_NO_TEAM,
    _RULE_RESPONSE_PLAY_MANUAL_ONLY,
})

# ── Helpers ────────────────────────────────────────────────────────────────────


def _int(record: dict[str, Any], key: str, default: int = 0) -> int:
    val = record.get(key, default)
    if isinstance(val, int) and not isinstance(val, bool):
        return max(0, val)
    return default


def _bool(record: dict[str, Any], key: str) -> bool | None:
    """Return the boolean field value, or None if absent/wrong type."""
    val = record.get(key)
    return val if isinstance(val, bool) else None


# ── Service evaluator ──────────────────────────────────────────────────────────


def _eval_service(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one pagerduty_service record.

    SECURITY: integration keys, routing keys, incident payloads, webhook
    URLs, user identities, and customer data are NEVER stored.  Evidence
    uses only opaque IDs, counts, categories, and safe booleans.
    """
    record_id = get_str(record, "record_id") or "pagerduty_service_unknown"
    findings: list[FindingCandidate] = []

    ep_id = get_str(record, "escalation_policy_id")
    integration_count = _int(record, "integration_count")
    ack_timeout = get_str(record, "acknowledgement_timeout_category")
    auto_resolve = get_str(record, "auto_resolve_timeout_category")
    alert_creation = get_str(record, "alert_creation_category")
    team_count = _int(record, "team_count")

    # ── pagerduty_service_no_escalation_policy ─────────────────────────────────
    if not ep_id:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SERVICE_NO_ESCALATION_POLICY,
            finding_key=make_finding_key(_RULE_SERVICE_NO_ESCALATION_POLICY, record_id),
            severity="high",
            title="PagerDuty service has no escalation policy",
            description=(
                "A PagerDuty service does not have an escalation policy configured. "
                "Without an escalation policy, incidents on this service will not be "
                "automatically routed to on-call responders. This configuration posture "
                "may require review. This does not confirm a compromise or data exposure."
            ),
            evidence={
                "rule": _RULE_SERVICE_NO_ESCALATION_POLICY,
                "record_id": record_id,
                "escalation_policy_id": "",
            },
            remediation={
                "summary": "Assign an escalation policy to this service.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Services → Service Directory.",
                    "Open the service and edit its settings.",
                    "Assign an appropriate escalation policy.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_service_no_integrations ──────────────────────────────────────
    if integration_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SERVICE_NO_INTEGRATIONS,
            finding_key=make_finding_key(_RULE_SERVICE_NO_INTEGRATIONS, record_id),
            severity="medium",
            title="PagerDuty service has no integrations",
            description=(
                "A PagerDuty service has zero integrations configured. Services with no "
                "integrations cannot receive events from monitoring tools and will not "
                "trigger incidents automatically. This configuration posture may require "
                "review. No integration key values are stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_SERVICE_NO_INTEGRATIONS,
                "record_id": record_id,
                "integration_count": 0,
            },
            remediation={
                "summary": "Add at least one integration to this service.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Services → Service Directory.",
                    "Open the service and add an integration under the Integrations tab.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_service_ack_timeout_disabled ─────────────────────────────────
    if ack_timeout == "disabled":
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SERVICE_ACK_TIMEOUT_DISABLED,
            finding_key=make_finding_key(_RULE_SERVICE_ACK_TIMEOUT_DISABLED, record_id),
            severity="medium",
            title="PagerDuty service acknowledgement timeout is disabled",
            description=(
                "A PagerDuty service has the acknowledgement timeout disabled. Without an "
                "acknowledgement timeout, incidents that are acknowledged but not resolved "
                "remain in the acknowledged state indefinitely, which may allow incidents to "
                "go unresolved without further escalation. This configuration posture may "
                "require review."
            ),
            evidence={
                "rule": _RULE_SERVICE_ACK_TIMEOUT_DISABLED,
                "record_id": record_id,
                "acknowledgement_timeout_category": "disabled",
            },
            remediation={
                "summary": "Enable an acknowledgement timeout for this service.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Services → Service Directory.",
                    "Open the service settings and configure an acknowledgement timeout.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_service_auto_resolve_disabled ────────────────────────────────
    if auto_resolve == "disabled":
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SERVICE_AUTO_RESOLVE_DISABLED,
            finding_key=make_finding_key(_RULE_SERVICE_AUTO_RESOLVE_DISABLED, record_id),
            severity="medium",
            title="PagerDuty service auto-resolve timeout is disabled",
            description=(
                "A PagerDuty service does not have an auto-resolve timeout configured. "
                "Without auto-resolve, incidents must be manually resolved, which may "
                "result in stale open incidents if responders forget to close them. "
                "This configuration posture may require review."
            ),
            evidence={
                "rule": _RULE_SERVICE_AUTO_RESOLVE_DISABLED,
                "record_id": record_id,
                "auto_resolve_timeout_category": "disabled",
            },
            remediation={
                "summary": "Configure an auto-resolve timeout for this service.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Services → Service Directory.",
                    "Open the service settings and set an auto-resolve timeout.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_service_alert_creation_limited ───────────────────────────────
    if alert_creation == "incidents_only":
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SERVICE_ALERT_CREATION_LIMITED,
            finding_key=make_finding_key(_RULE_SERVICE_ALERT_CREATION_LIMITED, record_id),
            severity="low",
            title="PagerDuty service uses incident-only alert creation",
            description=(
                "A PagerDuty service is configured to create incidents only, not separate "
                "alerts. With alert-based grouping disabled, deduplication and alert "
                "aggregation features are unavailable, which may increase incident noise "
                "for high-volume services. This configuration posture may require review."
            ),
            evidence={
                "rule": _RULE_SERVICE_ALERT_CREATION_LIMITED,
                "record_id": record_id,
                "alert_creation_category": "incidents_only",
            },
            remediation={
                "summary": "Review whether alert-based incident creation should be enabled.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Services → Service Directory.",
                    "Open the service settings and review the alert creation option.",
                    "Enable 'Create alerts and incidents' to allow deduplication.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_service_no_teams ─────────────────────────────────────────────
    if team_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SERVICE_NO_TEAMS,
            finding_key=make_finding_key(_RULE_SERVICE_NO_TEAMS, record_id),
            severity="low",
            title="PagerDuty service has no team assigned",
            description=(
                "A PagerDuty service has no team assigned. Services without team ownership "
                "may be harder to audit for responsibility and access. This configuration "
                "posture may require review. Team member identities are never stored."
            ),
            evidence={
                "rule": _RULE_SERVICE_NO_TEAMS,
                "record_id": record_id,
                "team_count": 0,
            },
            remediation={
                "summary": "Assign a team to this service.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Services → Service Directory.",
                    "Open the service and assign it to an appropriate team.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Escalation policy evaluator ────────────────────────────────────────────────


def _eval_escalation_policy(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one pagerduty_escalation_policy record.

    SECURITY: user targets, user emails, names, phone numbers, and contact
    methods are NEVER stored.  Evidence uses only counts and the opaque record_id.
    """
    record_id = get_str(record, "record_id") or "pagerduty_ep_unknown"
    findings: list[FindingCandidate] = []

    rule_count = _int(record, "escalation_rule_count")
    level_count = _int(record, "escalation_level_count")

    # ── pagerduty_escalation_policy_no_rules ───────────────────────────────────
    if rule_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_EP_NO_RULES,
            finding_key=make_finding_key(_RULE_EP_NO_RULES, record_id),
            severity="high",
            title="PagerDuty escalation policy has no escalation rules",
            description=(
                "A PagerDuty escalation policy has zero escalation rules configured. "
                "Without escalation rules, incidents will not be routed to any responders "
                "and will go unacknowledged indefinitely. This configuration posture "
                "requires review. No user identities or contact details are stored."
            ),
            evidence={
                "rule": _RULE_EP_NO_RULES,
                "record_id": record_id,
                "escalation_rule_count": 0,
            },
            remediation={
                "summary": "Add escalation rules to this policy.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → Escalation Policies.",
                    "Open this policy and add at least one escalation rule with targets.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_escalation_policy_single_level ───────────────────────────────
    if rule_count > 0 and level_count <= 1:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_EP_SINGLE_LEVEL,
            finding_key=make_finding_key(_RULE_EP_SINGLE_LEVEL, record_id),
            severity="medium",
            title="PagerDuty escalation policy has only a single escalation level",
            description=(
                "A PagerDuty escalation policy has only one escalation level. If the "
                "first-level responder does not acknowledge, the incident will not escalate "
                "further. Adding additional escalation levels improves incident-response "
                "coverage. This configuration posture may require review."
            ),
            evidence={
                "rule": _RULE_EP_SINGLE_LEVEL,
                "record_id": record_id,
                "escalation_rule_count": rule_count,
                "escalation_level_count": level_count,
            },
            remediation={
                "summary": "Add additional escalation levels to this policy.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → Escalation Policies.",
                    "Open this policy and add a second escalation level with backup responders.",
                ],
            },
            record_id=record_id,
        ))

    # ── M84C escalation policy rules ──────────────────────────────────────────

    target_count = _int(record, "target_count")
    schedule_target_count = _int(record, "schedule_target_count")
    team_count = _int(record, "team_count")
    has_schedule_targets = _bool(record, "has_schedule_targets")

    # ── pagerduty_escalation_policy_no_targets ─────────────────────────────────
    if rule_count > 0 and target_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_EP_NO_TARGETS,
            finding_key=make_finding_key(_RULE_EP_NO_TARGETS, record_id),
            severity="high",
            title="PagerDuty escalation policy rules have no configured targets",
            description=(
                "A PagerDuty escalation policy has escalation rules but none of them "
                "include any targets. Without targets, incidents will not be paged to "
                "any responder when they escalate. This escalation configuration evidence "
                "may require review. No target identities are stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_EP_NO_TARGETS,
                "record_id": record_id,
                "escalation_rule_count": rule_count,
                "target_count": 0,
            },
            remediation={
                "summary": "Add responder targets to each escalation rule in this policy.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → Escalation Policies.",
                    "Open this policy and add users or schedules as targets to each rule.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_escalation_policy_low_target_count ───────────────────────────
    if 0 < target_count <= 1:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_EP_LOW_TARGET_COUNT,
            finding_key=make_finding_key(_RULE_EP_LOW_TARGET_COUNT, record_id),
            severity="medium",
            title="PagerDuty escalation policy has only a single responder target",
            description=(
                "A PagerDuty escalation policy has only one target configured across all "
                "escalation rules. A single target creates a single point of failure in "
                "incident response — if that target is unavailable, incidents may go "
                "unacknowledged. This escalation configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_EP_LOW_TARGET_COUNT,
                "record_id": record_id,
                "target_count": target_count,
            },
            remediation={
                "summary": "Add additional targets or escalation levels to this policy.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → Escalation Policies.",
                    "Open this policy and add backup responders or on-call schedule targets.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_escalation_policy_no_schedule_targets ────────────────────────
    if rule_count > 0 and target_count > 0 and schedule_target_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_EP_NO_SCHEDULE_TARGETS,
            finding_key=make_finding_key(_RULE_EP_NO_SCHEDULE_TARGETS, record_id),
            severity="low",
            title="PagerDuty escalation policy has no on-call schedule targets",
            description=(
                "A PagerDuty escalation policy routes incidents only to direct user "
                "targets with no on-call schedule references. Without schedule targets, "
                "automated on-call rotation is not used, which may mean responders are "
                "paged regardless of their shift. This routing configuration evidence "
                "may require review."
            ),
            evidence={
                "rule": _RULE_EP_NO_SCHEDULE_TARGETS,
                "record_id": record_id,
                "target_count": target_count,
                "schedule_target_count": 0,
            },
            remediation={
                "summary": "Consider adding on-call schedule targets to this escalation policy.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → Escalation Policies.",
                    "Open this policy and add an on-call schedule as a target in each rule.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_escalation_policy_no_team_targets ────────────────────────────
    if team_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_EP_NO_TEAM_TARGETS,
            finding_key=make_finding_key(_RULE_EP_NO_TEAM_TARGETS, record_id),
            severity="low",
            title="PagerDuty escalation policy has no owning team assigned",
            description=(
                "A PagerDuty escalation policy has no owning team assigned. Escalation "
                "policies without team ownership may be harder to audit for accountability "
                "and access reviews. This escalation configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_EP_NO_TEAM_TARGETS,
                "record_id": record_id,
                "team_count": 0,
            },
            remediation={
                "summary": "Assign a team to this escalation policy.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → Escalation Policies.",
                    "Open this policy and assign it to an appropriate team.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Schedule evaluator ─────────────────────────────────────────────────────────


def _eval_schedule(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one pagerduty_schedule record.

    SECURITY: user identities, emails, names, phone numbers, and on-call
    assignment data are NEVER stored.  Evidence uses only counts and the
    opaque record_id.
    """
    record_id = get_str(record, "record_id") or "pagerduty_schedule_unknown"
    findings: list[FindingCandidate] = []

    layer_count = _int(record, "layer_count")
    team_count = _int(record, "team_count")

    # ── pagerduty_schedule_no_layers ───────────────────────────────────────────
    if layer_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SCHEDULE_NO_LAYERS,
            finding_key=make_finding_key(_RULE_SCHEDULE_NO_LAYERS, record_id),
            severity="medium",
            title="PagerDuty schedule has no schedule layers",
            description=(
                "A PagerDuty on-call schedule has no schedule layers configured. A schedule "
                "without layers will not produce any on-call coverage. This configuration "
                "posture may require review. User identities are never stored."
            ),
            evidence={
                "rule": _RULE_SCHEDULE_NO_LAYERS,
                "record_id": record_id,
                "layer_count": 0,
            },
            remediation={
                "summary": "Add at least one schedule layer with on-call coverage.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → On-Call Schedules.",
                    "Open this schedule and add a layer with rotation coverage.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_schedule_no_teams ────────────────────────────────────────────
    if team_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SCHEDULE_NO_TEAMS,
            finding_key=make_finding_key(_RULE_SCHEDULE_NO_TEAMS, record_id),
            severity="low",
            title="PagerDuty schedule has no team assigned",
            description=(
                "A PagerDuty on-call schedule has no team assigned. Schedules without team "
                "ownership may be harder to audit for accountability. This configuration "
                "posture may require review. Team member identities are never stored."
            ),
            evidence={
                "rule": _RULE_SCHEDULE_NO_TEAMS,
                "record_id": record_id,
                "team_count": 0,
            },
            remediation={
                "summary": "Assign a team to this schedule.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → On-Call Schedules.",
                    "Open this schedule and assign it to an appropriate team.",
                ],
            },
            record_id=record_id,
        ))

    # ── M84C schedule rules ────────────────────────────────────────────────────

    user_count = _int(record, "user_count")
    restriction_count = _int(record, "restriction_count")

    # ── pagerduty_schedule_no_targets ──────────────────────────────────────────
    if layer_count > 0 and user_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SCHEDULE_NO_TARGETS,
            finding_key=make_finding_key(_RULE_SCHEDULE_NO_TARGETS, record_id),
            severity="high",
            title="PagerDuty schedule layers have no users assigned",
            description=(
                "A PagerDuty on-call schedule has layers configured but no users assigned "
                "to any layer. A schedule without users will not produce any on-call "
                "coverage. This incident-response configuration evidence may require review. "
                "User identities are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_SCHEDULE_NO_TARGETS,
                "record_id": record_id,
                "layer_count": layer_count,
                "user_count": 0,
            },
            remediation={
                "summary": "Add users to the schedule layers.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → On-Call Schedules.",
                    "Open this schedule and add users to each active layer.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_schedule_low_target_count ────────────────────────────────────
    if user_count == 1:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SCHEDULE_LOW_TARGET_COUNT,
            finding_key=make_finding_key(_RULE_SCHEDULE_LOW_TARGET_COUNT, record_id),
            severity="medium",
            title="PagerDuty schedule has only one user assigned",
            description=(
                "A PagerDuty on-call schedule has only one user across all layers. A "
                "single-person schedule creates a single point of failure for on-call "
                "coverage — if that user is unavailable, incidents may not be responded to. "
                "This incident-response configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_SCHEDULE_LOW_TARGET_COUNT,
                "record_id": record_id,
                "user_count": 1,
            },
            remediation={
                "summary": "Add additional users to distribute on-call coverage.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → On-Call Schedules.",
                    "Open this schedule and add at least one more user to the rotation.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_schedule_single_layer ───────────────────────────────────────
    if layer_count == 1:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SCHEDULE_SINGLE_LAYER,
            finding_key=make_finding_key(_RULE_SCHEDULE_SINGLE_LAYER, record_id),
            severity="low",
            title="PagerDuty schedule has only a single schedule layer",
            description=(
                "A PagerDuty on-call schedule has only one schedule layer. Multiple layers "
                "allow for primary and backup rotation coverage. With a single layer, there "
                "is no built-in fallback if the primary rotation cannot respond. This "
                "incident-response configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_SCHEDULE_SINGLE_LAYER,
                "record_id": record_id,
                "layer_count": 1,
            },
            remediation={
                "summary": "Consider adding a backup schedule layer.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → On-Call Schedules.",
                    "Open this schedule and add a secondary layer for backup coverage.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_schedule_no_restrictions ────────────────────────────────────
    if layer_count > 0 and restriction_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_SCHEDULE_NO_RESTRICTIONS,
            finding_key=make_finding_key(_RULE_SCHEDULE_NO_RESTRICTIONS, record_id),
            severity="low",
            title="PagerDuty schedule layers have no time restrictions configured",
            description=(
                "A PagerDuty on-call schedule has layers but no time-window restrictions "
                "configured. Without restrictions, all users in each layer are considered "
                "on-call at all times, which may not reflect intended rotation boundaries. "
                "This schedule configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_SCHEDULE_NO_RESTRICTIONS,
                "record_id": record_id,
                "layer_count": layer_count,
                "restriction_count": 0,
            },
            remediation={
                "summary": "Review whether time-window restrictions should be configured.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to People → On-Call Schedules.",
                    "Open this schedule and configure restrictions to define rotation windows.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Service integration evaluator ──────────────────────────────────────────────


def _eval_service_integration(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one pagerduty_service_integration record.

    SECURITY: integration keys, routing keys, and integration email addresses
    are NEVER stored.  has_integration_key is a boolean derived before the
    key value is discarded.
    """
    record_id = get_str(record, "record_id") or "pagerduty_integration_unknown"
    findings: list[FindingCandidate] = []

    has_key = _bool(record, "has_integration_key")
    type_cat = get_str(record, "type_category")

    # ── pagerduty_service_integration_missing_key_indicator ────────────────────
    if has_key is False:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_INTEGRATION_MISSING_KEY,
            finding_key=make_finding_key(_RULE_INTEGRATION_MISSING_KEY, record_id),
            severity="medium",
            title="PagerDuty service integration has no integration key configured",
            description=(
                "A PagerDuty service integration does not have an integration key or "
                "routing key present. Without a key, the integration cannot receive events "
                "from monitoring tools. This configuration posture may require review. "
                "No integration key values are stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_INTEGRATION_MISSING_KEY,
                "record_id": record_id,
                "has_integration_key": False,
                "type_category": type_cat or "unknown",
            },
            remediation={
                "summary": "Generate or assign an integration key for this integration.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to the parent service and open its Integrations tab.",
                    "Regenerate the integration key or reconfigure the integration.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_service_integration_email_type ───────────────────────────────
    if type_cat == "email":
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_INTEGRATION_EMAIL_TYPE,
            finding_key=make_finding_key(_RULE_INTEGRATION_EMAIL_TYPE, record_id),
            severity="low",
            title="PagerDuty service integration uses email as its event source",
            description=(
                "A PagerDuty service integration uses email as its event-delivery mechanism. "
                "Email integrations are less reliable than API-based integrations and may "
                "result in delayed or dropped incident triggers. This configuration posture "
                "may require review. No email addresses are stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_INTEGRATION_EMAIL_TYPE,
                "record_id": record_id,
                "type_category": "email",
            },
            remediation={
                "summary": "Consider migrating to an API-based integration.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to the parent service Integrations tab.",
                    "Add an Events API v2 or vendor integration as a replacement.",
                    "Migrate monitoring tool alerts to use the new integration endpoint.",
                ],
            },
            record_id=record_id,
        ))

    # ── M84C service integration rules ────────────────────────────────────────

    routing_key_present = _bool(record, "routing_key_present")

    # ── pagerduty_service_integration_routing_key_missing ─────────────────────
    if type_cat == "generic_events_api" and routing_key_present is False:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_INTEGRATION_ROUTING_KEY_MISSING,
            finding_key=make_finding_key(_RULE_INTEGRATION_ROUTING_KEY_MISSING, record_id),
            severity="medium",
            title="PagerDuty Events API integration has no routing key configured",
            description=(
                "A PagerDuty service integration using the Events API does not have a "
                "routing key configured. Without a routing key, the Events API integration "
                "cannot receive and route events to trigger incidents. This webhook "
                "configuration evidence may require review. No routing key values are "
                "stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_INTEGRATION_ROUTING_KEY_MISSING,
                "record_id": record_id,
                "type_category": "generic_events_api",
                "routing_key_present": False,
            },
            remediation={
                "summary": "Generate or assign a routing key for this Events API integration.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to the parent service Integrations tab.",
                    "Open this integration and regenerate the routing/integration key.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_service_integration_unknown_type ────────────────────────────
    if type_cat == "other":
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_INTEGRATION_UNKNOWN_TYPE,
            finding_key=make_finding_key(_RULE_INTEGRATION_UNKNOWN_TYPE, record_id),
            severity="low",
            title="PagerDuty service integration has an unrecognized type",
            description=(
                "A PagerDuty service integration has a type that is not recognized as a "
                "standard Events API, email, or vendor integration. Unrecognized integration "
                "types may indicate an unsupported, legacy, or misconfigured integration. "
                "This integration configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_INTEGRATION_UNKNOWN_TYPE,
                "record_id": record_id,
                "type_category": "other",
            },
            remediation={
                "summary": "Review the type and configuration of this integration.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to the parent service Integrations tab.",
                    "Inspect this integration and update or replace it if it is not actively used.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Webhook subscription evaluator ────────────────────────────────────────────


def _eval_webhook_subscription(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one pagerduty_webhook_subscription record.

    SECURITY: delivery URLs and webhook secrets are NEVER stored.
    delivery_url_scheme_category is a safe category label derived from the URL
    before it is discarded.
    """
    record_id = get_str(record, "record_id") or "pagerduty_webhook_unknown"
    findings: list[FindingCandidate] = []

    active = _bool(record, "active")
    event_count = _int(record, "event_count")
    url_scheme = get_str(record, "delivery_url_scheme_category")

    # ── pagerduty_webhook_subscription_inactive ────────────────────────────────
    if active is False:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_WEBHOOK_INACTIVE,
            finding_key=make_finding_key(_RULE_WEBHOOK_INACTIVE, record_id),
            severity="medium",
            title="PagerDuty webhook subscription is inactive",
            description=(
                "A PagerDuty V3 webhook subscription is currently inactive. An inactive "
                "subscription will not deliver events to the configured endpoint. This may "
                "indicate a previously failed delivery or an intentionally paused webhook. "
                "This configuration posture may require review. Delivery URLs are never stored."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_INACTIVE,
                "record_id": record_id,
                "active": False,
            },
            remediation={
                "summary": "Review and re-enable this webhook subscription if still needed.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Integrations → Webhooks.",
                    "Open this subscription and re-enable it, or remove it if no longer needed.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_webhook_subscription_non_https ───────────────────────────────
    if url_scheme and url_scheme not in ("https", "absent"):
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_WEBHOOK_NON_HTTPS,
            finding_key=make_finding_key(_RULE_WEBHOOK_NON_HTTPS, record_id),
            severity="high",
            title="PagerDuty webhook subscription uses a non-HTTPS delivery URL",
            description=(
                "A PagerDuty V3 webhook subscription is configured with a delivery URL "
                "that does not use HTTPS. Webhook payloads delivered over plain HTTP may "
                "be transmitted without transport-layer encryption. This configuration "
                "posture may require review. The delivery URL value is never stored by "
                "ConfigTrace — only the URL scheme category is recorded."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_NON_HTTPS,
                "record_id": record_id,
                "delivery_url_scheme_category": url_scheme,
            },
            remediation={
                "summary": "Update the webhook delivery URL to use HTTPS.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Integrations → Webhooks.",
                    "Open this subscription and update the delivery URL to start with https://.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_webhook_subscription_broad_event_scope ──────────────────────
    if event_count > _BROAD_WEBHOOK_EVENTS_THRESHOLD:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_WEBHOOK_BROAD_SCOPE,
            finding_key=make_finding_key(_RULE_WEBHOOK_BROAD_SCOPE, record_id),
            severity="medium",
            title="PagerDuty webhook subscription subscribes to a broad set of event types",
            description=(
                "A PagerDuty V3 webhook subscription subscribes to more than "
                f"{_BROAD_WEBHOOK_EVENTS_THRESHOLD} event types. Broad subscriptions "
                "increase the volume of events delivered to the endpoint and may exceed "
                "the intended scope of the integration. This configuration posture may "
                "require review. Event type names are not stored — only the count."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_BROAD_SCOPE,
                "record_id": record_id,
                "event_count": event_count,
            },
            remediation={
                "summary": "Narrow the event type subscription to only what the endpoint requires.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Integrations → Webhooks.",
                    "Open this subscription and reduce the subscribed event types.",
                ],
            },
            record_id=record_id,
        ))

    # ── M84C webhook subscription rules ───────────────────────────────────────

    has_custom_headers = _bool(record, "has_custom_headers")
    filter_type = get_str(record, "filter_type")

    # ── pagerduty_webhook_subscription_no_events ──────────────────────────────
    if event_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_WEBHOOK_NO_EVENTS,
            finding_key=make_finding_key(_RULE_WEBHOOK_NO_EVENTS, record_id),
            severity="medium",
            title="PagerDuty webhook subscription has no subscribed event types",
            description=(
                "A PagerDuty V3 webhook subscription has no event types configured. "
                "Without subscribed events, the webhook endpoint will not receive any "
                "notifications from PagerDuty, making the subscription non-functional. "
                "This webhook configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_NO_EVENTS,
                "record_id": record_id,
                "event_count": 0,
            },
            remediation={
                "summary": "Add event type subscriptions to this webhook.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Integrations → Webhooks.",
                    "Open this subscription and add the relevant event types.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_webhook_subscription_secret_not_indicated ───────────────────
    if active is True and has_custom_headers is False:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_WEBHOOK_SECRET_NOT_INDICATED,
            finding_key=make_finding_key(_RULE_WEBHOOK_SECRET_NOT_INDICATED, record_id),
            severity="medium",
            title="PagerDuty webhook subscription has no custom authentication headers",
            description=(
                "An active PagerDuty V3 webhook subscription does not have any custom "
                "headers configured. Without custom authentication headers, the endpoint "
                "receiving this webhook cannot verify that events originate from PagerDuty. "
                "This webhook configuration evidence may require review. Custom header "
                "values are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_SECRET_NOT_INDICATED,
                "record_id": record_id,
                "active": True,
                "has_custom_headers": False,
            },
            remediation={
                "summary": "Configure custom authentication headers for this webhook.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Integrations → Webhooks.",
                    "Open this subscription and add a custom authentication header.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_webhook_subscription_broad_scope_high ───────────────────────
    if event_count > _BROAD_WEBHOOK_EVENTS_HIGH_THRESHOLD:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_WEBHOOK_BROAD_SCOPE_HIGH,
            finding_key=make_finding_key(_RULE_WEBHOOK_BROAD_SCOPE_HIGH, record_id),
            severity="high",
            title="PagerDuty webhook subscription has a very broad event scope",
            description=(
                "A PagerDuty V3 webhook subscription subscribes to more than "
                f"{_BROAD_WEBHOOK_EVENTS_HIGH_THRESHOLD} event types. Subscriptions "
                "with very broad event scopes significantly increase delivery volume and "
                "may expose a wider range of incident data to the endpoint than intended. "
                "This webhook configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_BROAD_SCOPE_HIGH,
                "record_id": record_id,
                "event_count": event_count,
            },
            remediation={
                "summary": "Significantly narrow the subscribed event types.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Integrations → Webhooks.",
                    "Open this subscription and restrict event types to the minimum needed.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_webhook_subscription_account_scope ──────────────────────────
    if filter_type == "account":
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_WEBHOOK_ACCOUNT_SCOPE,
            finding_key=make_finding_key(_RULE_WEBHOOK_ACCOUNT_SCOPE, record_id),
            severity="medium",
            title="PagerDuty webhook subscription is scoped to the entire account",
            description=(
                "A PagerDuty V3 webhook subscription is filtered at the account level, "
                "meaning it receives events from all services and teams in the account. "
                "Account-scoped webhooks deliver a broad range of incident notifications "
                "to a single endpoint, which may exceed the intended scope. This webhook "
                "configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_WEBHOOK_ACCOUNT_SCOPE,
                "record_id": record_id,
                "filter_type": "account",
            },
            remediation={
                "summary": "Consider scoping this webhook to specific services or teams.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Integrations → Webhooks.",
                    "Open this subscription and update the filter to a specific service or team.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Event orchestration evaluator ─────────────────────────────────────────────


def _eval_event_orchestration(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one pagerduty_event_orchestration record.

    SECURITY: routing expressions, condition logic, action details, and
    integration keys are NEVER stored.
    """
    record_id = get_str(record, "record_id") or "pagerduty_orchestration_unknown"
    findings: list[FindingCandidate] = []

    route_count = _int(record, "route_count")
    team_present = _bool(record, "team_present")

    # ── pagerduty_event_orchestration_no_routes ────────────────────────────────
    if route_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_ORCHESTRATION_NO_ROUTES,
            finding_key=make_finding_key(_RULE_ORCHESTRATION_NO_ROUTES, record_id),
            severity="medium",
            title="PagerDuty event orchestration has no routes configured",
            description=(
                "A PagerDuty event orchestration has zero routes. Without routes, "
                "incoming events will not be directed to the appropriate services or "
                "actions. This configuration posture may require review. Routing rule "
                "expressions are never stored."
            ),
            evidence={
                "rule": _RULE_ORCHESTRATION_NO_ROUTES,
                "record_id": record_id,
                "route_count": 0,
            },
            remediation={
                "summary": "Add routes to this event orchestration.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to AIOps → Event Orchestration.",
                    "Open this orchestration and add routing rules.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_event_orchestration_no_team ─────────────────────────────────
    if team_present is False:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_ORCHESTRATION_NO_TEAM,
            finding_key=make_finding_key(_RULE_ORCHESTRATION_NO_TEAM, record_id),
            severity="low",
            title="PagerDuty event orchestration has no team assigned",
            description=(
                "A PagerDuty event orchestration has no team assigned. Orchestrations "
                "without team ownership may be harder to audit for accountability. "
                "This configuration posture may require review."
            ),
            evidence={
                "rule": _RULE_ORCHESTRATION_NO_TEAM,
                "record_id": record_id,
                "team_present": False,
            },
            remediation={
                "summary": "Assign a team to this event orchestration.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to AIOps → Event Orchestration.",
                    "Open this orchestration and assign it to an appropriate team.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_event_orchestration_low_route_count ─────────────────────────
    if route_count == 1:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_ORCHESTRATION_LOW_ROUTE_COUNT,
            finding_key=make_finding_key(_RULE_ORCHESTRATION_LOW_ROUTE_COUNT, record_id),
            severity="low",
            title="PagerDuty event orchestration has only a single route",
            description=(
                "A PagerDuty event orchestration has only one route configured. A single "
                "route provides minimal event routing differentiation — all events that "
                "do not match it will fall through to the default behavior. This routing "
                "configuration evidence may require review."
            ),
            evidence={
                "rule": _RULE_ORCHESTRATION_LOW_ROUTE_COUNT,
                "record_id": record_id,
                "route_count": 1,
            },
            remediation={
                "summary": "Review the event orchestration routing coverage.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to AIOps → Event Orchestration.",
                    "Open this orchestration and add additional routes for better event coverage.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Business service evaluator ────────────────────────────────────────────────


def _eval_business_service(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one pagerduty_business_service record.

    SECURITY: subscriber lists, contact information, and user identities
    are NEVER stored.
    """
    record_id = get_str(record, "record_id") or "pagerduty_business_service_unknown"
    findings: list[FindingCandidate] = []

    team_present = _bool(record, "team_present")
    poc_present = _bool(record, "point_of_contact_present")

    # ── pagerduty_business_service_no_team ────────────────────────────────────
    if team_present is False:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_BUSINESS_SERVICE_NO_TEAM,
            finding_key=make_finding_key(_RULE_BUSINESS_SERVICE_NO_TEAM, record_id),
            severity="low",
            title="PagerDuty business service has no team assigned",
            description=(
                "A PagerDuty business service has no owning team assigned. Business "
                "services without team ownership may lack clear accountability for "
                "incident response. This configuration posture may require review."
            ),
            evidence={
                "rule": _RULE_BUSINESS_SERVICE_NO_TEAM,
                "record_id": record_id,
                "team_present": False,
            },
            remediation={
                "summary": "Assign a team to this business service.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Services → Business Services.",
                    "Open this business service and assign an owning team.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_business_service_no_contact ─────────────────────────────────
    if poc_present is False:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_BUSINESS_SERVICE_NO_CONTACT,
            finding_key=make_finding_key(_RULE_BUSINESS_SERVICE_NO_CONTACT, record_id),
            severity="low",
            title="PagerDuty business service has no point of contact configured",
            description=(
                "A PagerDuty business service has no point of contact assigned. Without "
                "a point of contact, it may be unclear who to reach during an outage "
                "affecting this business service. This configuration posture may require "
                "review. Contact names and identities are never stored."
            ),
            evidence={
                "rule": _RULE_BUSINESS_SERVICE_NO_CONTACT,
                "record_id": record_id,
                "point_of_contact_present": False,
            },
            remediation={
                "summary": "Assign a point of contact to this business service.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Services → Business Services.",
                    "Open this business service and configure a point of contact.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Response play evaluator ────────────────────────────────────────────────────


def _eval_response_play(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one pagerduty_response_play record.

    SECURITY: responder identities, subscriber identities, and conference
    phone numbers are NEVER stored.  Evidence uses only counts and the
    opaque record_id.
    """
    record_id = get_str(record, "record_id") or "pagerduty_response_play_unknown"
    findings: list[FindingCandidate] = []

    responder_count = _int(record, "responder_count")
    subscriber_count = _int(record, "subscriber_count")
    runnability = get_str(record, "runnability")

    # ── pagerduty_response_play_no_responders ──────────────────────────────────
    if responder_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_RESPONSE_PLAY_NO_RESPONDERS,
            finding_key=make_finding_key(_RULE_RESPONSE_PLAY_NO_RESPONDERS, record_id),
            severity="high",
            title="PagerDuty response play has no responders configured",
            description=(
                "A PagerDuty response play has zero responders configured. Without "
                "responders, the play cannot page anyone when executed during an incident. "
                "This configuration posture may require review. Responder identities "
                "are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_RESPONSE_PLAY_NO_RESPONDERS,
                "record_id": record_id,
                "responder_count": 0,
            },
            remediation={
                "summary": "Add responders to this response play.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Incidents → Response Plays.",
                    "Open this response play and add at least one responder.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_response_play_not_runnable ───────────────────────────────────
    if runnability == "unknown":
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_RESPONSE_PLAY_NOT_RUNNABLE,
            finding_key=make_finding_key(_RULE_RESPONSE_PLAY_NOT_RUNNABLE, record_id),
            severity="medium",
            title="PagerDuty response play runnability is not configured",
            description=(
                "A PagerDuty response play has an unknown runnability setting. Without a "
                "clear runnability configuration, it may be unclear who is allowed to "
                "trigger this play during an incident. This configuration posture may "
                "require review."
            ),
            evidence={
                "rule": _RULE_RESPONSE_PLAY_NOT_RUNNABLE,
                "record_id": record_id,
                "runnability": "unknown",
            },
            remediation={
                "summary": "Configure the runnability setting for this response play.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Incidents → Response Plays.",
                    "Open this play and set the runnability to 'owner', 'team', or 'any'.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_response_play_no_subscribers ─────────────────────────────────
    if subscriber_count == 0:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_RESPONSE_PLAY_NO_SUBSCRIBERS,
            finding_key=make_finding_key(_RULE_RESPONSE_PLAY_NO_SUBSCRIBERS, record_id),
            severity="low",
            title="PagerDuty response play has no subscribers configured",
            description=(
                "A PagerDuty response play has no subscribers configured. Without "
                "subscribers, stakeholders will not be automatically notified when the "
                "play is executed. This configuration posture may require review. "
                "Subscriber identities are never stored."
            ),
            evidence={
                "rule": _RULE_RESPONSE_PLAY_NO_SUBSCRIBERS,
                "record_id": record_id,
                "subscriber_count": 0,
            },
            remediation={
                "summary": "Add subscribers to this response play.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Incidents → Response Plays.",
                    "Open this play and add stakeholder subscribers.",
                ],
            },
            record_id=record_id,
        ))

    # ── M84C response play rules ──────────────────────────────────────────────

    team_present = _bool(record, "team_present")

    # ── pagerduty_response_play_low_responder_count ────────────────────────────
    if responder_count == 1:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_RESPONSE_PLAY_LOW_RESPONDER_COUNT,
            finding_key=make_finding_key(_RULE_RESPONSE_PLAY_LOW_RESPONDER_COUNT, record_id),
            severity="medium",
            title="PagerDuty response play has only a single responder configured",
            description=(
                "A PagerDuty response play has only one responder configured. A single "
                "responder creates a single point of failure — if that responder is "
                "unavailable during an incident, the play cannot engage the intended "
                "response team. This incident-response configuration evidence may require "
                "review. Responder identities are never stored by ConfigTrace."
            ),
            evidence={
                "rule": _RULE_RESPONSE_PLAY_LOW_RESPONDER_COUNT,
                "record_id": record_id,
                "responder_count": 1,
            },
            remediation={
                "summary": "Add additional responders to this response play.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Incidents → Response Plays.",
                    "Open this play and add at least one additional responder.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_response_play_no_team ───────────────────────────────────────
    if team_present is False:
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_RESPONSE_PLAY_NO_TEAM,
            finding_key=make_finding_key(_RULE_RESPONSE_PLAY_NO_TEAM, record_id),
            severity="low",
            title="PagerDuty response play has no team assigned",
            description=(
                "A PagerDuty response play has no owning team assigned. Response plays "
                "without team ownership may be harder to audit for accountability and "
                "access reviews. This incident-response configuration evidence may require "
                "review."
            ),
            evidence={
                "rule": _RULE_RESPONSE_PLAY_NO_TEAM,
                "record_id": record_id,
                "team_present": False,
            },
            remediation={
                "summary": "Assign a team to this response play.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Incidents → Response Plays.",
                    "Open this play and assign it to an appropriate team.",
                ],
            },
            record_id=record_id,
        ))

    # ── pagerduty_response_play_manual_only ───────────────────────────────────
    if runnability == "owner":
        findings.append(FindingCandidate(
            provider="pagerduty",
            rule_key=_RULE_RESPONSE_PLAY_MANUAL_ONLY,
            finding_key=make_finding_key(_RULE_RESPONSE_PLAY_MANUAL_ONLY, record_id),
            severity="low",
            title="PagerDuty response play is restricted to owner-only execution",
            description=(
                "A PagerDuty response play has runnability set to 'owner', meaning only "
                "the response play owner can execute it. This restriction may prevent "
                "other responders from triggering the play during an incident when the "
                "owner is unavailable. This incident-response configuration evidence "
                "may require review."
            ),
            evidence={
                "rule": _RULE_RESPONSE_PLAY_MANUAL_ONLY,
                "record_id": record_id,
                "runnability": "owner",
            },
            remediation={
                "summary": "Review the runnability setting and consider broadening access.",
                "steps": [
                    "Sign in to your PagerDuty account.",
                    "Navigate to Incidents → Response Plays.",
                    "Open this play and update the runnability to 'team' or 'any'.",
                ],
            },
            record_id=record_id,
        ))

    return findings


# ── Dispatch ───────────────────────────────────────────────────────────────────


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one normalized PagerDuty drift record and return any findings.

    Accepts any dict.  Unknown record_type values return an empty list — never
    raises.  Each evaluator is self-contained and never mutates the record.

    SECURITY: no rule reads or stores PagerDuty API token values, routing keys,
    integration keys, webhook secrets, delivery URLs, incident payloads, alert
    payloads, user emails, user names, phone numbers, contact methods, on-call
    user identities, responder identities, subscriber identities, conference
    phone numbers, authorization headers, IP addresses, user agents, audit logs,
    request or response payloads, customer data, or PII.
    """
    if not isinstance(record, dict):
        return []

    rtype = record.get("record_type")

    if rtype == PAGERDUTY_SERVICE:
        return _eval_service(record)
    if rtype == PAGERDUTY_ESCALATION_POLICY:
        return _eval_escalation_policy(record)
    if rtype == PAGERDUTY_SCHEDULE:
        return _eval_schedule(record)
    if rtype == PAGERDUTY_SERVICE_INTEGRATION:
        return _eval_service_integration(record)
    if rtype == PAGERDUTY_WEBHOOK_SUBSCRIPTION:
        return _eval_webhook_subscription(record)
    if rtype == PAGERDUTY_EVENT_ORCHESTRATION:
        return _eval_event_orchestration(record)
    if rtype == PAGERDUTY_BUSINESS_SERVICE:
        return _eval_business_service(record)
    if rtype == PAGERDUTY_RESPONSE_PLAY:
        return _eval_response_play(record)

    return []
