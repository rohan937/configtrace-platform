"""PagerDuty configuration drift schema (M84A, expanded M84C).

Defines the eight safe record types that the PagerDutyConnector emits.
All TypedDicts carry only flat, privacy-safe fields — opaque IDs, booleans,
counts, and category labels.  Nothing in here is a raw secret.

Safe record types
─────────────────
  pagerduty_service              Service configuration posture
  pagerduty_escalation_policy    Escalation-policy posture
  pagerduty_schedule             On-call schedule posture
  pagerduty_service_integration  Per-service integration posture
  pagerduty_webhook_subscription Webhook subscription posture (V3)
  pagerduty_event_orchestration  Event orchestration posture
  pagerduty_business_service     Business service posture
  pagerduty_response_play        Response-play posture

Privacy contract — NEVER stored in any record:
  PagerDuty API tokens, routing keys, integration keys, webhook secrets,
  delivery URLs, raw webhook URLs, user emails, user names, phone numbers,
  SMS numbers, push notification tokens, contact methods, on-call user IDs,
  responder identities, subscriber identities, incident payloads, alert
  payloads, request/response payloads, raw condition/routing expressions,
  authorization headers, IP addresses, user agents, audit logs,
  conference phone numbers, or customer PII of any kind.
"""

from __future__ import annotations

from typing import Optional
from typing_extensions import TypedDict

# ── Record type constants ──────────────────────────────────────────────────────

PAGERDUTY_SERVICE = "pagerduty_service"
PAGERDUTY_ESCALATION_POLICY = "pagerduty_escalation_policy"
PAGERDUTY_SCHEDULE = "pagerduty_schedule"
PAGERDUTY_SERVICE_INTEGRATION = "pagerduty_service_integration"
PAGERDUTY_WEBHOOK_SUBSCRIPTION = "pagerduty_webhook_subscription"
PAGERDUTY_EVENT_ORCHESTRATION = "pagerduty_event_orchestration"
PAGERDUTY_BUSINESS_SERVICE = "pagerduty_business_service"
PAGERDUTY_RESPONSE_PLAY = "pagerduty_response_play"

PAGERDUTY_RECORD_TYPES: frozenset[str] = frozenset({
    PAGERDUTY_SERVICE,
    PAGERDUTY_ESCALATION_POLICY,
    PAGERDUTY_SCHEDULE,
    PAGERDUTY_SERVICE_INTEGRATION,
    PAGERDUTY_WEBHOOK_SUBSCRIPTION,
    PAGERDUTY_EVENT_ORCHESTRATION,
    PAGERDUTY_BUSINESS_SERVICE,
    PAGERDUTY_RESPONSE_PLAY,
})


# ── TypedDicts ─────────────────────────────────────────────────────────────────


class PagerDutyServiceRecord(TypedDict):
    """Safe normalised record for a PagerDuty service (M84A).

    SECURITY: integration keys, routing keys, webhook URLs, incident
    payloads, user identities, contact methods, email addresses, and
    customer PII are NEVER stored here.
    """

    record_type: str              # always PAGERDUTY_SERVICE
    provider: str                 # always "pagerduty"
    record_id: str                # PagerDuty service opaque ID
    resource_id: str              # same as record_id
    resource_name: str            # service name, truncated to 100 chars

    status_category: str          # "active" | "warning" | "critical" | "maintenance" | "unknown"
    escalation_policy_id: str     # opaque ID of the attached escalation policy
    team_count: int               # number of teams owning this service
    integration_count: int        # number of integrations on this service
    alert_creation_category: str  # "alerts_and_incidents" | "incidents_only" | "unknown"
    incident_urgency_rule_type: str   # "constant" | "use_support_hours" | "unknown"
    support_hours_enabled: bool   # True if support hours are configured
    scheduled_actions_count: int  # number of scheduled actions
    auto_resolve_timeout_category: str    # "disabled" | "short" | "medium" | "long"
    acknowledgement_timeout_category: str  # "disabled" | "short" | "medium" | "long"


class PagerDutyEscalationPolicyRecord(TypedDict):
    """Safe normalised record for a PagerDuty escalation policy (M84A, M84C).

    SECURITY: user targets (emails, names, IDs, phone numbers, contact
    methods) are NEVER stored. Only structural/count metadata.
    """

    record_type: str          # always PAGERDUTY_ESCALATION_POLICY
    provider: str             # always "pagerduty"
    record_id: str            # PagerDuty escalation policy opaque ID
    resource_id: str          # same as record_id
    resource_name: str        # policy name, truncated to 100 chars

    team_count: int           # number of teams owning this policy
    escalation_rule_count: int  # number of escalation rules
    escalation_level_count: int  # number of distinct escalation levels
    repeat_enabled: bool      # True if the policy loops
    num_loops: int            # loop count (0 if repeat_enabled is False)
    on_call_handoff_notifications: str  # "if_has_services" | "always" | "never" | "unknown"
    # M84C safe target-count fields (counts only — no target IDs/names/emails)
    target_count: int         # total targets across all escalation rules
    user_target_count: int    # user-reference targets (count only)
    schedule_target_count: int  # schedule-reference targets (count only)
    has_schedule_targets: bool  # True if any rule has a schedule-reference target


class PagerDutyScheduleRecord(TypedDict):
    """Safe normalised record for a PagerDuty on-call schedule (M84A, M84C).

    SECURITY: user identities, user emails, user names, phone numbers,
    contact methods, and on-call data are NEVER stored.
    """

    record_type: str          # always PAGERDUTY_SCHEDULE
    provider: str             # always "pagerduty"
    record_id: str            # PagerDuty schedule opaque ID
    resource_id: str          # same as record_id
    resource_name: str        # schedule name, truncated to 100 chars

    time_zone_present: bool   # True if a timezone is configured
    layer_count: int          # number of schedule layers
    user_count: int           # number of unique users (count only — no IDs)
    team_count: int           # number of teams
    # M84C safe restriction fields
    restriction_count: int    # total restriction entries across all layers
    has_restrictions: bool    # True if any layer has time-window restrictions


class PagerDutyServiceIntegrationRecord(TypedDict):
    """Safe normalised record for a PagerDuty service integration (M84A, M84C).

    SECURITY: integration keys, routing keys, integration email addresses,
    and webhook delivery URLs are NEVER stored.
    """

    record_type: str          # always PAGERDUTY_SERVICE_INTEGRATION
    provider: str             # always "pagerduty"
    record_id: str            # PagerDuty integration opaque ID
    resource_id: str          # same as record_id
    service_id: str           # opaque ID of the parent service

    type_category: str        # "generic_events_api" | "email" | "vendor" | "other"
    vendor_name: Optional[str]  # vendor display name, truncated (e.g. "Datadog") — not PII
    has_integration_key: bool  # True if an integration key/routing key is present
                               # (key value is NEVER stored)
    # M84C safe key-type fields
    routing_key_present: bool  # True if a routing_key field is specifically present
                               # (key value is NEVER stored)


class PagerDutyWebhookSubscriptionRecord(TypedDict):
    """Safe normalised record for a PagerDuty V3 webhook subscription (M84A, M84C).

    SECURITY: delivery URL, webhook secret, custom header values, filter target
    details, and subscription event payloads are NEVER stored.
    """

    record_type: str          # always PAGERDUTY_WEBHOOK_SUBSCRIPTION
    provider: str             # always "pagerduty"
    record_id: str            # PagerDuty webhook subscription opaque ID
    resource_id: str          # same as record_id

    active: bool              # True if the subscription is active
    event_count: int          # number of subscribed event types
    delivery_url_scheme_category: str  # "https" | "http" | "other" | "absent"
                                       # (URL itself is NEVER stored)
    filter_type: str          # "account" | "service_reference" | "team_reference" | "unknown"
    # M84C safe auth-indicator field
    has_custom_headers: bool  # True if delivery_method.custom_headers is non-empty
                              # (header names/values are NEVER stored)


class PagerDutyEventOrchestrationRecord(TypedDict):
    """Safe normalised record for a PagerDuty event orchestration (M84A).

    SECURITY: routing expressions, condition logic, action details, and
    integration keys are NEVER stored.
    """

    record_type: str          # always PAGERDUTY_EVENT_ORCHESTRATION
    provider: str             # always "pagerduty"
    record_id: str            # PagerDuty event orchestration opaque ID
    resource_id: str          # same as record_id
    resource_name: str        # orchestration name, truncated to 100 chars

    team_present: bool        # True if a team is assigned
    route_count: int          # number of routes in the orchestration


class PagerDutyBusinessServiceRecord(TypedDict):
    """Safe normalised record for a PagerDuty business service (M84A).

    SECURITY: subscriber lists, contact information, and user identities
    are NEVER stored.
    """

    record_type: str          # always PAGERDUTY_BUSINESS_SERVICE
    provider: str             # always "pagerduty"
    record_id: str            # PagerDuty business service opaque ID
    resource_id: str          # same as record_id
    resource_name: str        # business service name, truncated to 100 chars

    team_present: bool        # True if a team is assigned
    point_of_contact_present: bool  # True if a point-of-contact is configured


class PagerDutyResponsePlayRecord(TypedDict):
    """Safe normalised record for a PagerDuty response play (M84A).

    SECURITY: responder identities, subscriber identities, conference phone
    numbers, and paging policies with personal contact info are NEVER stored.
    """

    record_type: str          # always PAGERDUTY_RESPONSE_PLAY
    provider: str             # always "pagerduty"
    record_id: str            # PagerDuty response play opaque ID
    resource_id: str          # same as record_id
    resource_name: str        # response play name, truncated to 100 chars

    team_present: bool        # True if a team is assigned
    responder_count: int      # number of configured responders (count only)
    subscriber_count: int     # number of configured subscribers (count only)
    conference_number_present: bool   # True if a conference number is configured
                                      # (number itself is NEVER stored)
    runnability: str          # "owner" | "team" | "any" | "unknown"
