"""Datadog connector record type constants — M82A.

M82A scope (drift foundation)
------------------------------
Ten safe drift surfaces from the Datadog API:

    datadog_monitor                  — monitor metadata (never raw query or message)
    datadog_slo                      — SLO metadata (never raw description)
    datadog_dashboard                — dashboard metadata (never raw JSON or widget queries)
    datadog_webhook_integration      — webhook integration metadata (never URL, headers, payload, or secrets)
    datadog_notification_integration — notification integration metadata (never handles or destinations)
    datadog_api_key_metadata         — API key metadata (never key value; last4 as presence boolean only)
    datadog_application_key_metadata — application key metadata (never key value)
    datadog_role                     — role metadata (never user identities)
    datadog_team                     — team metadata (never member names/emails or handles)
    datadog_cloud_integration        — cloud integration metadata (never account IDs)

Privacy contract
----------------
SECURITY: in M82A no API key value, application key value, OAuth token,
bearer token, webhook secret, integration secret, raw monitor query string,
raw monitor message, raw dashboard JSON, raw dashboard widget queries, raw
notebook content, raw incident text, raw log data, raw trace data, raw metric
values, raw event payloads, email addresses, user names, user IDs, team member
identities, notification channel destinations, Slack/PagerDuty/webhook URLs,
customer data, or PII is ever stored in a normalised record.

Logs, traces, metric values, and incident payloads are NEVER fetched or stored
in M82A. Only configuration-level metadata is read.
"""
from __future__ import annotations

from typing import Optional, TypedDict

# ── M82A record type string constants ─────────────────────────────────────────

# One per Datadog monitor.
# SECURITY: raw query string and raw message text are NEVER stored.
# Notification handles, PagerDuty service keys, Slack channel names, and
# webhook URLs embedded in the message are NEVER stored.
DATADOG_MONITOR = "datadog_monitor"

# One per Datadog SLO.
# SECURITY: raw SLO description text is NEVER stored.
DATADOG_SLO = "datadog_slo"

# One per Datadog dashboard.
# SECURITY: raw dashboard JSON, widget queries, widget formulas, template
# variable defaults, and dashboard URLs are NEVER stored.
DATADOG_DASHBOARD = "datadog_dashboard"

# One per Datadog webhook integration.
# SECURITY: webhook URLs, custom HTTP headers, payload templates, and
# webhook signing secrets are NEVER stored.
DATADOG_WEBHOOK_INTEGRATION = "datadog_webhook_integration"

# One per Datadog notification integration (PagerDuty, OpsGenie, Slack, etc.).
# SECURITY: service keys, API tokens, subdomain strings, email addresses,
# Slack channel names, PagerDuty service IDs, webhook URLs, and destination
# handles are NEVER stored.
DATADOG_NOTIFICATION_INTEGRATION = "datadog_notification_integration"

# One per Datadog API key (metadata only).
# SECURITY: the API key value is NEVER stored. last4 digits are stored as a
# boolean presence flag (last4_present) only — the actual digits are never kept.
DATADOG_API_KEY_METADATA = "datadog_api_key_metadata"

# One per Datadog application key (metadata only).
# SECURITY: the application key value and hash are NEVER stored.
DATADOG_APPLICATION_KEY_METADATA = "datadog_application_key_metadata"

# One per Datadog role.
# SECURITY: user identities, user IDs, user emails, and team member lists
# are NEVER stored.
DATADOG_ROLE = "datadog_role"

# One per Datadog team.
# SECURITY: member names, member emails, member IDs, and team handles are
# NEVER stored. handle_present is a boolean only.
DATADOG_TEAM = "datadog_team"

# One per Datadog cloud integration (AWS, GCP, or Azure).
# SECURITY: AWS account IDs, GCP project IDs, Azure tenant/subscription IDs,
# IAM role ARNs, service account emails, client secrets, and raw integration
# credentials are NEVER stored. account_id_present is a boolean only.
DATADOG_CLOUD_INTEGRATION = "datadog_cloud_integration"

# ── Aggregate set ─────────────────────────────────────────────────────────────

DATADOG_RECORD_TYPES: frozenset[str] = frozenset({
    DATADOG_MONITOR,
    DATADOG_SLO,
    DATADOG_DASHBOARD,
    DATADOG_WEBHOOK_INTEGRATION,
    DATADOG_NOTIFICATION_INTEGRATION,
    DATADOG_API_KEY_METADATA,
    DATADOG_APPLICATION_KEY_METADATA,
    DATADOG_ROLE,
    DATADOG_TEAM,
    DATADOG_CLOUD_INTEGRATION,
})


# ── TypedDicts ────────────────────────────────────────────────────────────────


class DatadogMonitorRecord(TypedDict):
    """Safe normalised record for a Datadog monitor (M82A/M82C).

    SECURITY: raw query string, raw message text, notification handles
    (PagerDuty, Slack, webhook URLs), and all raw monitor API response
    payload are NEVER stored. Raw query and message are read transiently to
    compute safe derived fields (booleans and counts) and then discarded
    immediately.
    """

    record_type: str          # always "datadog_monitor"
    provider: str             # always "datadog"
    record_id: str            # str(monitor_id)
    resource_id: str          # str(monitor_id)
    resource_name: str        # truncated to 100 chars
    monitor_type: str         # "metric alert" / "event alert" / "log alert" / etc.
    enabled: bool             # False if monitor is silenced/muted
    status: str               # "OK" / "Alert" / "Warn" / "No Data" / "Unknown" / "Skipped"
    priority_category: str    # "critical" / "high" / "medium" / "low" / "info" / "none"
    # query NEVER stored — presence and complexity only; M82C adds safe derivations
    query_present: bool
    query_complexity_category: str   # "absent" / "short" / "medium" / "long"
    # M82C: derived from query before discarding — raw query NEVER stored
    query_uses_wildcard_scope: bool  # True when query contains {*} (all-scope wildcard)
    query_group_by_count: int        # count of group-by clauses (raw query discarded)
    # message NEVER stored — presence and length only; M82C adds safe derivations
    message_present: bool
    message_length_category: str     # "absent" / "short" / "medium" / "long"
    # M82C: derived from message before discarding — raw message NEVER stored
    notification_routing_present: bool  # True if message contains at least one @ mention
    notification_count: int             # count of @ characters in message (notification handles NEVER stored)
    message_template_present: bool      # True if message contains {{ template variables
    tag_count: int
    threshold_count: int
    # M82C: individual threshold presence booleans (raw threshold values not stored)
    threshold_critical_present: bool   # options.thresholds.critical is set
    threshold_warning_present: bool    # options.thresholds.warning is set
    threshold_recovery_present: bool   # options.thresholds.critical_recovery or warning_recovery is set
    renotify_enabled: bool
    renotify_interval_category: str  # M82C: "disabled"/"short"/"medium"/"long"
    restricted_roles_count: int
    notify_no_data: bool
    include_tags: bool
    notify_audit: bool               # M82C: whether audit notifications are enabled
    require_full_window: bool        # M82C: whether full evaluation window is required
    evaluation_delay_category: str   # "none" / "short" / "medium" / "long"
    silenced_scope_count: int        # M82C: number of scopes in the silenced dict
    no_data_timeframe_category: str  # M82C: "none"/"short"/"medium"/"extended"


class DatadogSloRecord(TypedDict):
    """Safe normalised record for a Datadog SLO (M82A).

    SECURITY: raw SLO description, raw query strings (for metric SLOs),
    and all raw SLO API response payload are NEVER stored.
    """

    record_type: str          # always "datadog_slo"
    provider: str             # always "datadog"
    record_id: str            # opaque SLO ID string
    resource_id: str          # opaque SLO ID string
    resource_name: str        # truncated to 100 chars
    slo_type: str             # "metric" / "monitor" / etc.
    target_category: str      # "99.9_plus" / "99_plus" / "95_plus" / "below_95" / "none"
    warning_target_category: str  # same categories or "none"
    timeframe_count: int      # number of thresholds/timeframe windows configured
    monitor_count: int        # number of monitor IDs (monitor SLOs only)
    group_count: int          # number of groups (composite SLOs)
    tag_count: int
    # description NEVER stored — presence and length only
    description_present: bool
    description_length_category: str  # "absent" / "short" / "medium" / "long"


class DatadogDashboardRecord(TypedDict):
    """Safe normalised record for a Datadog dashboard (M82A).

    SECURITY: raw dashboard JSON, widget query strings/formulas, template
    variable default values, public URL strings, and all raw dashboard API
    response payload are NEVER stored.
    """

    record_type: str          # always "datadog_dashboard"
    provider: str             # always "datadog"
    record_id: str            # opaque dashboard ID string
    resource_id: str          # opaque dashboard ID string
    resource_name: str        # truncated to 100 chars
    layout_type: str          # "ordered" / "free"
    widget_count: int
    template_variable_count: int
    restricted_roles_count: int
    # public_url is NEVER stored — presence boolean only
    public_url_present: bool
    # description NEVER stored — presence and length only
    description_present: bool
    description_length_category: str  # "absent" / "short" / "medium" / "long"


class DatadogWebhookIntegrationRecord(TypedDict):
    """Safe normalised record for a Datadog webhook integration (M82A/M82C).

    SECURITY: webhook URL (full string), custom HTTP header names and values,
    payload template body, and webhook signing secrets are NEVER stored. The
    URL is read transiently to derive the scheme category only, then discarded.
    Custom header keys are checked against auth-pattern names only to derive
    auth_material_present, then discarded immediately — neither names nor values
    are retained.
    """

    record_type: str          # always "datadog_webhook_integration"
    provider: str             # always "datadog"
    record_id: str            # opaque webhook name
    resource_id: str          # opaque webhook name
    resource_name: str        # truncated to 100 chars
    # url NEVER stored — presence boolean + scheme category only (M82C)
    url_present: bool
    url_scheme_category: str           # M82C: "https"/"http"/"absent"/"unknown" — URL string NEVER stored
    custom_headers_present: bool
    custom_header_count: int           # M82C: count only — header names/values NEVER stored
    auth_material_present: bool        # M82C: any auth-like header name detected — header names NEVER stored
    payload_template_present: bool
    payload_template_length_category: str  # M82C: "absent"/"short"/"medium"/"long" — content NEVER stored
    secret_headers_present: bool
    secret_headers_count: int          # M82C: count only — secret names/values NEVER stored
    encode_as_category: str            # M82C: "json"/"form"/"unknown"


class DatadogNotificationIntegrationRecord(TypedDict):
    """Safe normalised record for a Datadog notification integration (M82A).

    SECURITY: service API keys, subdomain strings, email addresses, Slack
    channel names/IDs, PagerDuty service keys, OpsGenie API keys, webhook
    URLs, and all destination handle values are NEVER stored.
    """

    record_type: str          # always "datadog_notification_integration"
    provider: str             # always "datadog"
    record_id: str            # f"datadog_notif_{integration_type}"
    resource_id: str          # f"datadog_notif_{integration_type}"
    resource_name: str        # e.g. "PagerDuty" / "Slack" / "OpsGenie"
    integration_type: str     # "pagerduty" / "slack" / "opsgenie" / etc.
    enabled: bool             # whether the integration is configured
    handle_count: int         # number of configured handles/services (count only)
    channel_count: int        # number of channels (Slack only, count only)
    restricted_roles_count: int


class DatadogApiKeyMetadataRecord(TypedDict):
    """Safe normalised record for Datadog API key metadata (M82A).

    SECURITY: the API key value is NEVER stored. last4 digits are represented
    as a boolean presence flag (last4_present) only — the actual digit string
    is never kept. key_hash, key value, and all raw API key payload are NEVER stored.
    """

    record_type: str          # always "datadog_api_key_metadata"
    provider: str             # always "datadog"
    record_id: str            # opaque key ID
    resource_id: str          # opaque key ID
    resource_name: str        # key name, truncated to 100 chars
    created_present: bool     # whether a creation timestamp exists
    modified_present: bool    # whether a modification timestamp exists
    # last4 stored as presence only — the actual digits are NEVER stored
    last4_present: bool
    created_by_present: bool  # whether created_by metadata exists
    disabled: bool            # whether the key is disabled/revoked


class DatadogApplicationKeyMetadataRecord(TypedDict):
    """Safe normalised record for Datadog application key metadata (M82A).

    SECURITY: the application key value and hash are NEVER stored.
    Scope values and scope names are stored as a count only.
    """

    record_type: str          # always "datadog_application_key_metadata"
    provider: str             # always "datadog"
    record_id: str            # opaque application key ID
    resource_id: str          # opaque application key ID
    resource_name: str        # key name, truncated to 100 chars
    created_present: bool
    modified_present: bool
    scopes_count: int         # number of scopes (count only — scope names never stored)
    owned_by_present: bool    # whether owned_by metadata exists


class DatadogRoleRecord(TypedDict):
    """Safe normalised record for a Datadog role (M82A).

    SECURITY: user identities, user IDs, user emails, user names, and
    the identity of any principal assigned to the role are NEVER stored.
    """

    record_type: str          # always "datadog_role"
    provider: str             # always "datadog"
    record_id: str            # opaque role ID
    resource_id: str          # opaque role ID
    resource_name: str        # role name, truncated to 100 chars
    permission_count: int
    user_count: int           # number of users in role (count only — identities NEVER stored)
    team_count: int           # number of teams in role (count only — names NEVER stored)


class DatadogTeamRecord(TypedDict):
    """Safe normalised record for a Datadog team (M82A).

    SECURITY: member names, member emails, member IDs, and team handles
    are NEVER stored. handle_present is a boolean only.
    """

    record_type: str          # always "datadog_team"
    provider: str             # always "datadog"
    record_id: str            # opaque team ID
    resource_id: str          # opaque team ID
    resource_name: str        # team name, truncated to 100 chars
    member_count: int         # count only — member identities NEVER stored
    # team handle is NEVER stored — presence boolean only
    handle_present: bool
    link_count: int           # number of team links configured


class DatadogCloudIntegrationRecord(TypedDict):
    """Safe normalised record for a Datadog cloud integration (M82A).

    SECURITY: AWS account IDs, GCP project IDs, Azure tenant/subscription IDs,
    IAM role ARNs, service account email addresses, client secrets, and all raw
    integration credential fields are NEVER stored.
    account_id_present is a boolean only.
    """

    record_type: str          # always "datadog_cloud_integration"
    provider: str             # always "datadog"
    record_id: str            # f"datadog_cloud_{cloud_provider}_{index}"
    resource_id: str          # same as record_id
    resource_name: str        # e.g. "AWS integration" / "GCP integration"
    cloud_provider: str       # "aws" / "gcp" / "azure"
    # account IDs are NEVER stored — presence boolean only
    account_id_present: bool
    resource_collection_enabled: bool
    metric_collection_enabled: bool
    log_collection_enabled: bool
    account_tags_count: int   # count of custom tags configured for the account
    namespace_count: int      # number of metric namespaces (count only)
