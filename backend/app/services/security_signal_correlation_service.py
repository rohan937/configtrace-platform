"""Configuration Risk × audit-activity correlation (M66.6).

The core differentiator. Joins GitHub Configuration Risk findings
(``security_findings``) to GitHub audit activity (``security_activity_events``)
on the SAME repository within a review window, producing correlation rows and a
corresponding ``security_incident_signals`` row with ``evidence_level``
="correlation".

CLAIM DISCIPLINE (do not violate):
  A correlation is EVIDENCE FOR REVIEW. It is the first step toward a "potential
  compromise signal" but does NOT confirm a breach, attacker, compromise, or
  unauthorized access. Severity = review priority; confidence = "medium" because
  this is circumstantial co-occurrence, not proof.

Matching is conservative and deterministic:
  * same workspace, same provider (github),
  * same repository (finding's resource → Resource.provider_resource_id ==
    activity event's resource_id, both "owner/repo"),
  * activity ``occurred_at`` within [finding.first_detected_at - WINDOW,
    finding.last_seen_at + WINDOW] (default WINDOW = 24h),
  * finding base rule ↔ activity event_type per CORRELATION_RULES.

No vague cross-resource correlations. Ruleset / app-permission correlations are
DEFERRED — no corresponding Configuration Risk findings exist yet (the github
ruleset/app rules are not implemented), so there is nothing to match against.

Privacy: metadata is allowlisted + flat + truncated; raw payloads/IPs/secrets/
tokens are never stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.resource import Resource
from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_finding import SecurityFinding
from app.models.security_incident_signal import SecurityIncidentSignal
from app.models.security_signal_correlation import SecuritySignalCorrelation
from app.services import security_incident_signal_service as signal_svc

PROVIDER_GITHUB = "github"
PROVIDER_AWS = "aws"
PROVIDER_CLOUDFLARE = "cloudflare"
PROVIDER_VERCEL = "vercel"
PROVIDER_SUPABASE = "supabase"
PROVIDER_FIREBASE = "firebase"
PROVIDER_STRIPE = "stripe"
PROVIDER_SHOPIFY = "shopify"
PROVIDER_AZURE = "azure"
PROVIDER_GOOGLE_CLOUD = "google_cloud"

# Default review window around a finding's active period.
WINDOW = timedelta(hours=24)

# Allowlist of non-sensitive metadata keys carried onto a correlation.
ALLOWED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "repository",
        "finding_rule",
        "finding_severity",
        "event_type",
        "actor",
        "window_hours",
        # AWS correlation context (M67.3) — non-sensitive resource identifiers.
        "resource",
        "region",
        "account_id",
        # Cloudflare correlation context (M68.2) — non-sensitive identifiers.
        "zone_id",
        "zone_name",
        "action",
        "resource_type",
        "resource_id",
        # Cloudflare deeper context (M68.3) — exact setting/policy match.
        "setting_name",
        "policy_name",
        # Cloudflare WAF/security-event correlation context (M68.6) — safe
        # aggregate identifiers only (never raw IP / URL / path / query).
        "source",
        "host",
        "rule_id",
        "rule_name",
        "path_prefix",
        "event_count",
        # AWS S3 exposure × object-activity correlation context (M69.2A) — safe
        # bucket name + sanitized object prefix only (NEVER a raw object key).
        "bucket_name",
        "object_key_prefix",
        # AWS SG exposure × VPC Flow Log correlation context (M69.2B) — safe
        # aggregate identifiers only (NEVER raw source/destination IPs, flow lines,
        # payloads, headers, tokens, or secrets).
        "security_group_id",
        "dst_port",
        "port_category",
        "interface_id",
        "flow_action",
        # AWS IAM risk × privilege-chain correlation context (M69.3B) — safe
        # IAM entity labels and chain summary only (NEVER access keys, secrets,
        # session tokens, credentials, raw CloudTrail JSON, requestParameters,
        # responseElements, raw IPs, user agents, or request bodies).
        "source_signal_type",
        "chain_pattern",
        "target_user",
        "target_role",
        # GitHub config-risk × secret-scanning alert correlation context (M69.4C)
        # — safe alert summary fields only (NEVER the raw secret, token, raw alert
        # URL, raw API response, raw locations, file contents, patch, headers, or
        # request body).
        "repository_full_name",
        "alert_number",
        "state",
        "resolution",
        "secret_type",
        "secret_type_display_name",
        "validity",
        "publicly_leaked",
        # GitHub config-risk × code-scanning alert correlation context (M69.4F)
        # — safe alert summary fields only (NEVER raw code, file contents, raw
        # SARIF, raw locations/paths, raw alert URL, raw API response, patch,
        # headers, or request body).
        "tool_name",
        "security_severity_level",
        "severity",
        # GitHub config-risk × Dependabot alert correlation context (M69.4I)
        # — safe advisory/dependency summary fields only (NEVER raw manifest/file
        # paths, advisory bodies/details, the raw dependency-graph or API
        # response, patch, headers, request body, tokens, or secrets).
        "dependency_package_name",
        "dependency_ecosystem",
        "vulnerable_version_range",
        "patched_versions",
        "advisory_ghsa_id",
        "advisory_cve_id",
        "advisory_severity",
        "cvss_score",
        "epss_percentage",
        "scope",
        # GitHub ruleset / automation-permission risk correlation context (M69.5C)
        # — safe aggregate posture fields only (NEVER tokens, headers, webhook
        # secrets, private keys, OAuth secrets, raw bypass-actor identities, or
        # the raw API response).
        "ruleset_name",
        "enforcement",
        "target",
        "bypass_actor_count",
        "required_status_checks_count",
        "targets_protected_branch",
        "credential_type",
        "broad_permission_count",
        "token_scope_count",
        "webhook_secret_configured",
        # Vercel config-risk × activity correlation context (M70D) — safe
        # project/target identifiers + change classification only. NEVER env var
        # values, deploy hook URLs, tokens, headers, raw API responses, actor
        # emails, request/response bodies, or secrets.
        "project_id",
        "project_name",
        "event_action",
        "target_type",
        "target_id",
        "target_name",
        "domain",
        "env_var_key",
        "deploy_hook_name",
        "branch",
        "deployment_id",
        "deployment_target",
        # Supabase config-risk × activity correlation context (M71D) — safe
        # project/table/policy/bucket/function/auth NAMES and identifiers only.
        # NEVER database row data, SQL result rows, auth users, emails, JWT
        # secrets, service-role/anon keys, db passwords, tokens, headers, raw API
        # responses, request/response bodies, policy expressions/SQL conditions,
        # or Edge Function env var values.
        "project_ref",
        "organization_id",
        "schema_name",
        "table_name",
        "policy_command",
        "storage_bucket_id",
        "storage_bucket_name",
        "edge_function_id",
        "edge_function_name",
        "auth_setting_name",
        # Firebase config-risk × activity correlation context (M72D) — safe
        # project/service/method/resource NAMES and identifiers only. NEVER
        # Firestore documents, Realtime Database data, storage object contents,
        # auth users, emails, private keys, service-account JSON secrets, tokens,
        # headers, raw API responses, raw rule source, request/response bodies, or
        # Cloud Function env var values.
        "project_number",
        "event_source",
        "service_name",
        "method_name",
        "ruleset_name",
        "database_instance",
        "function_name",
        "function_region",
        "app_id",
        "app_platform",
        "hosting_site_id",
        # Stripe config-risk × activity correlation context (M73D) — safe
        # account/object identifiers and event-class labels only. NEVER secret
        # / restricted API key values, webhook signing secrets, raw webhook
        # payloads, raw event payloads, raw API responses, customer PII /
        # emails, payment method data, card data, charges/payment intents/
        # invoices/customer records, OAuth tokens, authorization headers,
        # request/response bodies, bank-account details, or tax IDs.
        "stripe_event_type",
        "object_type",
        "object_id",
        "webhook_endpoint_id",
        "webhook_url_domain",
        "webhook_url_scheme",
        "payment_link_id",
        "portal_config_id",
        "capability",
        "capability_status",
        "tax_setting_name",
        "livemode",
        # Shopify config-risk × activity correlation context (M74D) — safe shop /
        # webhook / domain / policy / app-scope NAMES and identifiers only.
        # NEVER Admin API access tokens, OAuth tokens, private app secrets,
        # webhook signing secrets, raw webhook payloads, raw event payloads, raw
        # API responses, customer PII / emails, orders, carts / checkouts with
        # buyer data, payment method data, card data, refunds, fulfillments
        # with customer/order data, authorization headers, request/response
        # bodies, bank-account details, tax IDs, or staff names/emails.
        "shop_domain",
        "myshopify_domain",
        "shopify_event_type",
        "webhook_id",
        "webhook_topic",
        "webhook_endpoint_domain",
        "webhook_endpoint_scheme",
        "app_scope_count",
        "app_scopes_sample",
        "domain_id",
        "domain_host",
        "policy_type",
        # Azure risk × activity correlation context (M77F) — safe Azure
        # subscription / resource group / resource NAMES and ARM identifiers
        # only. NEVER caller email/UPN/name, principal IDs, object IDs, raw
        # correlationId, claims, authorization objects, properties payload,
        # httpRequest body, raw event payload, storage keys, SAS tokens,
        # connection strings, Key Vault secret names/values, certificate
        # material, key material, database contents, VM user data, app setting
        # names/values, env var values, customer/workload data, or PII.
        "subscription_id",            # Azure subscription GUID (an opaque identifier)
        "resource_group",             # resource group name (infra identifier)
        "azure_event_id",             # Azure eventDataId UUID (opaque)
        "azure_correlation_id_hash",  # salted hash of correlationId (NEVER raw)
        "operation_name",             # ARM operationName
        "operation_family",           # operation namespace+resource type prefix
        "operation_action",           # operation verb (write / delete)
        "nsg_name",                   # NSG resource name (infra identifier)
        "nsg_rule_name",              # NSG security rule name
        "storage_account_name",       # Storage Account resource name
        "key_vault_name",             # Key Vault resource name
        "app_service_name",           # App Service resource name
        "sql_server_name",            # SQL Server resource name
        "sql_firewall_rule_name",     # SQL firewall rule resource name
        "aks_cluster_name",           # AKS managed cluster resource name
        "scope_type",                 # role assignment scope category
        "role_definition_name",       # resolved built-in role name (Owner/Contributor/…)
        "principal_type",             # principalType (User/Group/ServicePrincipal; not PII)
        "category",                   # Activity Log event category (e.g. "Administrative")
        "status",                     # operation status (e.g. "Succeeded")
        "matched_on",                 # which join key matched (e.g. "nsg_name+resource_group")
        "match_confidence",           # human label for join confidence ("high"/"medium")
        "time_window_hours",          # review-window size in hours
        # Google Cloud risk × activity correlation context (M78F) — safe Google
        # Cloud project / resource NAMES and identifiers only. NEVER service
        # account emails, principal emails/IDs, caller IPs, userAgent, raw
        # protoPayload, request, response, authenticationInfo, authorizationInfo,
        # raw payloads, full IAM bindings, database names/users/passwords,
        # connection strings, query data, env var names/values, secret
        # names/values, secret payloads, kubeconfig, certs, node names, workload
        # data, pod specs, logs, customer data, raw IP addresses, or PII.
        "google_cloud_event_id",      # Cloud Logging insertId (opaque stable entry id)
        "firewall_rule_name",         # GCE firewall rule name (infra identifier)
        "network_name",               # VPC network name (infra identifier)
        "sql_instance_name",          # Cloud SQL instance name (infra identifier)
        "run_service_name",           # Cloud Run service name (infra identifier)
        "gke_cluster_name",           # GKE cluster name (infra identifier)
        "status_code",                # protoPayload.status.code (int; 0 = success)
        "resource_name",              # GCP resource path (no email segments)
        "finding_family",             # logical family label (iam / firewall / storage / sql / run / gke / service_account_key / secret_manager)
        # Twilio risk × activity correlation context (M79F) — safe resource
        # identifiers and posture labels only. NEVER auth tokens, API key
        # secrets, full account SIDs, full phone number strings, webhook/
        # callback URL strings, message bodies, call SIDs, call legs,
        # recording data, customer PII, raw Twilio API responses, raw HTTP
        # request or response bodies, or any value that could re-identify a
        # customer or expose a credential.
        "twilio_resource_sid_prefix",  # SID prefix (opaque resource handle)
        "messaging_service_sid",       # Messaging Service SID (opaque)
        "verify_service_sid",          # Verify Service SID (opaque)
        "api_key_sid",                 # API Key SID (opaque; never the secret)
        "phone_number_last4",          # ONLY the last 4 digits (never full number)
        "match_reason",                # short safe match label (e.g. "phone_number_last4_match")
        "match_strength",              # "high" (exact SID) or "medium" (family aggregate)
        "risk_family",                 # logical risk family label
        "activity_family",             # logical activity family label
        "event_types",                 # comma-separated safe event-type list
        "finding_severity",            # severity label from the source finding
        "pattern",                     # pattern label (safe string)
        # SendGrid risk × activity correlation context (M80F) — safe
        # configuration surface identifiers and posture labels only. NEVER
        # API key values, bearer tokens, authorization headers, email bodies,
        # subject lines, recipient emails, sender personal emails, suppression
        # recipient emails, template HTML/plaintext, raw webhook URLs, raw
        # inbound parse hostnames, mail event payloads (bounce/click/open/
        # delivered/dropped/spamreport/unsubscribe/processed), message IDs,
        # raw SendGrid API responses, request/response bodies, customer data,
        # or PII of any kind.
        "api_key_id",                  # API key opaque ID (NEVER the key value or secret)
        "sender_id",                   # sender identity opaque ID (NEVER email address)
        "mail_setting_name",           # mail setting key name (NEVER setting content)
        "tracking_setting_name",       # tracking setting key name (NEVER tracking data)
        "event_webhook_enabled",       # bool — whether event webhook is active
        "event_webhook_has_url",       # bool — webhook URL presence (NEVER the URL)
        "inbound_parse_enabled",       # bool — whether inbound parse is enabled
        "domain_valid",                # bool — domain auth DNS validation status
        "automatic_security",          # bool — automatic DKIM rotation status
        "sender_verified",             # bool — sender identity verification status
        "sender_locked",               # bool — sender identity lock status
        "suppression_group_count",     # int — count of ASM suppression groups
        # Cross-provider safe correlation-context keys (M80F)
        "rule_key",                    # base rule key label (e.g. sendgrid_api_key_broad_scopes)
        "signal_type",                 # signal type label (e.g. sendgrid_api_key_config_changed)
        # Auth0 risk × activity correlation context (M81F) — safe opaque
        # identifiers and configuration labels only. NEVER client_secret,
        # management API token, access/refresh/ID tokens, JWTs, JWKS, private
        # keys, authorization headers, raw Auth0 API responses, raw log entries,
        # raw callback/logout/origin URLs, audience URIs, custom domain name
        # strings, rule/action script content, action secret values, user emails,
        # user IDs, user names, profile data, IP addresses, device fingerprints,
        # session data, MFA recovery codes, connection credentials, social
        # provider secrets, SAML certificates, or PII of any kind.
        "client_id",                   # Auth0 client ID (opaque; NEVER client_secret)
        "connection_id",               # Auth0 connection ID (opaque identifier)
        "resource_server_id",          # Auth0 resource server ID (opaque identifier)
        "action_id",                   # Auth0 action ID (opaque; NEVER code or secrets)
        "factor_name",                 # MFA factor name (e.g. "otp", "webauthn-roaming")
        "custom_domain_id",            # Auth0 custom domain ID (opaque; NEVER domain string)
        "tenant_id",                   # Auth0 tenant identifier (opaque)
        # Datadog risk × activity correlation context (M82F) — safe opaque
        # resource identifiers and posture labels only. NEVER API key values,
        # application key values, OAuth tokens, bearer tokens, webhook secrets,
        # raw monitor queries/messages, raw dashboard JSON, widget queries,
        # webhook URLs/headers/payload templates, notification handles, Slack
        # channel names, PagerDuty service IDs, email addresses, user IDs,
        # team member identities, IP addresses, user agents, raw Datadog
        # audit payloads, raw API response dicts, customer data, or PII.
        "monitor_id",                  # Datadog monitor ID (opaque identifier, not a secret)
        "slo_id",                      # Datadog SLO ID (opaque identifier)
        "dashboard_id",                # Datadog dashboard ID (opaque identifier)
        "notification_integration_id", # Datadog notification integration record ID
        "application_key_id",          # Datadog application key ID (NEVER key value)
        "role_id",                     # Datadog role ID (opaque identifier)
        "team_id",                     # Datadog team ID (opaque identifier)
        "cloud_integration_id",        # Datadog cloud integration record ID
        "record_type",                 # Datadog record type label (e.g. "datadog_monitor")
        "signal_count",                # int — count of signals in the correlation window
        "time_delta_minutes",          # int — time delta between finding and signal (minutes)
        "correlation_reason",          # safe reason label for the correlation
        "correlation_strength",        # "high" / "medium" / "low"
        # Clerk Risk × Activity Correlation metadata (M83F) — safe opaque
        # identifiers, counts, and category labels only. NEVER stored:
        # Clerk secret key values, publishable key values, session tokens,
        # JWTs, OAuth tokens, webhook secrets, raw URLs, domain names, JWT
        # template bodies, custom claims, audience URIs, issuer URIs, user
        # emails, user IDs, phone numbers, member identities, IP addresses,
        # user agents, raw audit payloads, or PII.
        "instance_id",
        "application_id",
        "redirect_url_config_id",
        "jwt_template_id",
        "email_sms_settings_id",
        "auth_strategy_id",
        "organization_settings_id",
        "session_policy_id",
        "window_start",
        "window_end",
        # PagerDuty Risk × Activity Correlation metadata (M84F) — safe opaque
        # resource identifiers, counts, and category labels only. NEVER stored:
        # PagerDuty API tokens, routing keys, integration keys, webhook secrets,
        # delivery URLs, custom header values, user emails, user names, phone
        # numbers, contact methods, on-call user identities, responder identities,
        # subscriber identities, incident payloads, alert payloads, conference
        # phone numbers, raw routing expressions, IP addresses, user agents,
        # raw audit payloads, or customer PII.
        "pagerduty_event_id",         # stable synthetic event identifier (day-scoped)
        "escalation_policy_id",       # PagerDuty escalation policy opaque ID
        "schedule_id",                # PagerDuty schedule opaque ID
        "integration_id",             # PagerDuty integration opaque ID (not a secret)
        "webhook_subscription_id",    # PagerDuty webhook subscription opaque ID
        "event_orchestration_id",     # PagerDuty event orchestration opaque ID
        "business_service_id",        # PagerDuty business service opaque ID
        "response_play_id",           # PagerDuty response play opaque ID
        "service_id",                 # PagerDuty service opaque ID (not a secret)
        # Linear Risk x Activity Correlation fields (M85F)
        "match_reason",
        "match_strength",
        "finding_severity",
        "risk_family",
        "activity_family",
        "correlation_reason",
        "correlation_strength",
        "private_team",
        "team_visibility_category",
        "project_count",
        "auto_archive_enabled",
        "cycle_enabled",
        "cycle_duration_category",
        "workflow_state_count",
        "has_backlog_state",
        "has_started_state",
        "has_completed_state",
        "has_canceled_state",
        "project_status_category",
        "project_health_category",
        "lead_present",
        "issue_count_category",
        "state_type_category",
        "position_category",
        "is_group_label",
        "parent_id_present",
        "webhook_enabled",
        "webhook_secret_present",
        "webhook_url_present",
        "webhook_url_scheme_category",
        "webhook_resource_types_count",
        "webhook_has_comment_type",
        "webhook_has_attachment_type",
        "view_shared",
        "filter_count_category",
        "integration_enabled",
        "integration_type_category",
        "url_key_present",
        "logo_present",
        "label_count",
        "webhook_count",
        "integration_count",
        "member_count_category",
    }
)

MAX_STR_LEN = 200
MAX_METADATA_KEYS = 20

_REVIEW_NOTE = (
    "This is a correlation signal that may require review. ConfigTrace does not "
    "confirm compromise or unauthorized access."
)


def _rule(
    correlation_key: str,
    correlation_type: str,
    activity_types: set[str],
    severity: str,
    phrase: str,
) -> dict[str, Any]:
    return {
        "correlation_key": correlation_key,
        "correlation_type": correlation_type,
        "activity_types": activity_types,
        "severity": severity,
        "phrase": phrase,
    }


# Map a finding's BASE rule key → correlation rule. Only rules whose finding side
# actually exists today are included (webhook / branch protection / deploy key).
CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "github_webhook_http": _rule(
        "github_webhook_risk_activity",
        "webhook_change",
        {"github.webhook.created", "github.webhook.updated", "github.webhook.deleted"},
        # Severity floored at medium; raised to high when the finding is high+.
        "medium",
        "Webhook configuration risk followed by webhook admin activity",
    ),
    "github_branch_protection_missing": _rule(
        "github_branch_protection_risk_activity",
        "branch_protection_change",
        {"github.branch_protection.disabled", "github.branch_protection.updated"},
        "high",
        "Branch protection risk aligned with branch-protection admin activity",
    ),
    "github_deploy_key_write_access": _rule(
        "github_deploy_key_risk_activity",
        "deploy_key_added",
        {"github.deploy_key.added"},
        "high",
        "Deploy key risk aligned with new deploy key activity",
    ),
}

_HIGH_SEVERITIES = {"critical", "high"}


def sanitize_correlation_metadata(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return a safe, allowlisted, truncated copy of correlation metadata."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in ALLOWED_METADATA_KEYS:
            continue
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, (int, float)):
            out[key] = value
        elif isinstance(value, str):
            out[key] = value[:MAX_STR_LEN]
        else:
            continue
        if len(out) >= MAX_METADATA_KEYS:
            break
    return out


def _base_rule(finding_key: str) -> str:
    return finding_key.split(":", 1)[0] if finding_key else ""


def _aware(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def build_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    repo: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a correlation dict (not persisted) from a matched finding + event."""
    # Webhook severity tracks the finding; others use the rule severity.
    severity = rule["severity"]
    if rule["correlation_key"] == "github_webhook_risk_activity":
        severity = "high" if finding.severity in _HIGH_SEVERITIES else "medium"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['phrase']} on {repo}"
    summary = (
        f"Configuration risk \"{finding.title}\" and GitHub audit activity "
        f"\"{event.event_type}\" were observed for {repo} within the review "
        f"window. {_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata(
        {
            "repository": repo,
            "finding_rule": _base_rule(finding.finding_key),
            "finding_severity": finding.severity,
            "event_type": event.event_type,
            "actor": event.actor_id if isinstance(event.actor_id, str) else None,
            "window_hours": int(WINDOW.total_seconds() // 3600),
        }
    )

    return {
        "provider": PROVIDER_GITHUB,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def _find_existing(
    db: Session,
    *,
    workspace_id: uuid.UUID,
    correlation_key: str,
    linked_finding_id: Optional[uuid.UUID],
    linked_activity_event_id: Optional[uuid.UUID],
) -> Optional[SecuritySignalCorrelation]:
    if linked_finding_id is None or linked_activity_event_id is None:
        return None
    return (
        db.query(SecuritySignalCorrelation)
        .filter(
            SecuritySignalCorrelation.workspace_id == workspace_id,
            SecuritySignalCorrelation.correlation_key == correlation_key,
            SecuritySignalCorrelation.linked_finding_id == linked_finding_id,
            SecuritySignalCorrelation.linked_activity_event_id == linked_activity_event_id,
        )
        .first()
    )


def upsert_correlation(
    *,
    workspace_id: uuid.UUID,
    correlation: dict[str, Any],
    db: Session,
) -> tuple[str, SecuritySignalCorrelation]:
    """Idempotently persist a correlation (+ a linked correlation signal).

    Returns ``("created", row)`` or ``("skipped", row)``.
    """
    existing = _find_existing(
        db,
        workspace_id=workspace_id,
        correlation_key=correlation["correlation_key"],
        linked_finding_id=correlation.get("linked_finding_id"),
        linked_activity_event_id=correlation.get("linked_activity_event_id"),
    )
    if existing is not None:
        return "skipped", existing

    # Create/find the correlation incident signal (evidence_level="correlation").
    linked_signal_id = _upsert_correlation_signal(
        workspace_id=workspace_id, correlation=correlation, db=db
    )

    row = SecuritySignalCorrelation(
        workspace_id=workspace_id,
        provider=correlation["provider"],
        correlation_key=correlation["correlation_key"],
        correlation_type=correlation["correlation_type"],
        severity=correlation["severity"],
        confidence=correlation.get("confidence", "medium"),
        status=correlation.get("status", "open"),
        title=correlation["title"],
        summary=correlation["summary"],
        linked_signal_id=linked_signal_id,
        linked_finding_id=correlation.get("linked_finding_id"),
        linked_activity_event_id=correlation.get("linked_activity_event_id"),
        linked_change_id=correlation.get("linked_change_id"),
        window_start=correlation.get("window_start"),
        window_end=correlation.get("window_end"),
        first_seen_at=correlation.get("first_seen_at"),
        last_seen_at=correlation.get("last_seen_at"),
        correlation_metadata=correlation.get("metadata") or {},
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = _find_existing(
            db,
            workspace_id=workspace_id,
            correlation_key=correlation["correlation_key"],
            linked_finding_id=correlation.get("linked_finding_id"),
            linked_activity_event_id=correlation.get("linked_activity_event_id"),
        )
        if existing is not None:
            return "skipped", existing
        raise
    db.refresh(row)
    return "created", row


def _upsert_correlation_signal(
    *,
    workspace_id: uuid.UUID,
    correlation: dict[str, Any],
    db: Session,
) -> Optional[uuid.UUID]:
    """Create/find a correlation-evidence incident signal; return its id.

    Reuses the M66.3 signal upsert (idempotent on activity event + signal_key),
    then back-fills ``linked_finding_id`` on the signal so the signal carries both
    sides of the correlation.
    """
    signal = {
        "provider": correlation.get("provider", PROVIDER_GITHUB),
        "integration_id": correlation.get("_integration_id"),
        "signal_key": correlation["correlation_key"],
        "signal_type": correlation["correlation_type"],
        "severity": correlation["severity"],
        "status": "open",
        "title": correlation["title"],
        "summary": correlation["summary"],
        "evidence_level": "correlation",
        "confidence": correlation.get("confidence", "medium"),
        "first_seen_at": correlation.get("first_seen_at"),
        "last_seen_at": correlation.get("last_seen_at"),
        "linked_activity_event_id": correlation.get("linked_activity_event_id"),
        "metadata": correlation.get("metadata") or {},
    }
    try:
        _outcome, sig = signal_svc.upsert_incident_signal(
            workspace_id=workspace_id, signal=signal, db=db
        )
    except Exception:  # noqa: BLE001 — signal linkage is best-effort, never fatal
        db.rollback()
        return None
    # Back-fill the finding link on the signal (M66.3 upsert leaves it null).
    finding_id = correlation.get("linked_finding_id")
    if finding_id is not None and sig.linked_finding_id is None:
        sig.linked_finding_id = finding_id
        db.commit()
    return sig.id


def _generate_github_audit_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active GitHub findings with GitHub audit activity for a workspace.

    Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_GITHUB,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    # Keep only findings whose base rule is correlatable.
    findings = [f for f in findings if _base_rule(f.finding_key) in CORRELATION_RULES]

    # Resolve each finding's repository slug via its Resource.
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    repo_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in (
            db.query(Resource).filter(Resource.id.in_(resource_ids)).all()
        ):
            repo_by_resource[r.id] = r.provider_resource_id

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Index events by repo for cheap lookup.
    events_by_repo: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        if isinstance(ev.resource_id, str) and ev.resource_id:
            events_by_repo.setdefault(ev.resource_id, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.resource_id is None:
            continue  # integration-level finding — no repo to match
        repo = repo_by_resource.get(finding.resource_id)
        if not repo:
            continue
        rule = CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_repo.get(repo, []):
            if ev.event_type not in rule["activity_types"]:
                continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_correlation(
                finding=finding, event=ev, repo=repo, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_GITHUB,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ---------------------------------------------------------------------------
# GitHub config-risk × secret-scanning alert correlations (M69.4C)
# ---------------------------------------------------------------------------
#
# Correlate active GitHub repository configuration-risk findings with GitHub
# secret-scanning ALERT evidence (security_activity_events, provider=github,
# source=secret_scanning_alert — ingested in M69.4A) observed on the SAME
# repository within the review window. These are review correlations; they never
# assert secret leakage confirmed, compromise, an attacker, that someone has
# access, unauthorized access, a breach, or an attack — only "evidence for
# review" and, where GitHub itself set the flag, "marked publicly leaked" /
# "marked active".
#
# We anchor to the secret-scanning ACTIVITY EVENT directly (the preferred
# strategy) and only correlate OPEN alerts — resolved / revoked / false-positive
# / used-in-tests alerts never produce a (high-risk) correlation.

SS_SOURCE = "secret_scanning_alert"
# Only OPEN alerts are correlated (excludes resolved/revoked/false_positive/
# used_in_tests so non-actionable alerts never become correlations).
_SS_OPEN_EVENT = "github.secret_scanning.alert.open"


def _ss_rule(
    correlation_key: str,
    severity: str,
    phrase: str,
) -> dict[str, Any]:
    return {
        "correlation_key": correlation_key,
        "correlation_type": correlation_key,  # type == key for these families
        "activity_types": {_SS_OPEN_EVENT},
        "severity": severity,
        "phrase": phrase,
    }


# Map a finding's BASE rule key → secret-scanning correlation rule. Only GitHub
# repository-scoped config-risk rules that actually exist today are included.
# Three families: repository-protection risk, automation risk, and a safe
# repository-scoped generic fallback. (No public-repo visibility rule exists in
# the codebase today, so Pattern C is deferred — see the milestone report.)
_SS_PROTECTION_TYPE = "github_repo_protection_secret_alert"
_SS_AUTOMATION_TYPE = "github_automation_secret_alert"
_SS_GENERIC_TYPE = "github_repo_risk_secret_alert"

SECRET_SCANNING_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    # A — repository protection risk × open secret-scanning alert.
    "github_branch_protection_missing": _ss_rule(
        _SS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with secret-scanning alert evidence",
    ),
    "github_force_pushes_allowed": _ss_rule(
        _SS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with secret-scanning alert evidence",
    ),
    "github_branch_deletion_allowed": _ss_rule(
        _SS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with secret-scanning alert evidence",
    ),
    "github_pr_review_not_required": _ss_rule(
        _SS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with secret-scanning alert evidence",
    ),
    "github_status_checks_not_required": _ss_rule(
        _SS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with secret-scanning alert evidence",
    ),
    # B — automation / deploy-key / webhook risk × open secret-scanning alert.
    "github_webhook_http": _ss_rule(
        _SS_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with secret-scanning alert evidence",
    ),
    "github_deploy_key_write_access": _ss_rule(
        _SS_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with secret-scanning alert evidence",
    ),
    # D — safe repository-scoped generic fallback (any remaining repo-scoped
    # GitHub config risk). Severity is medium, raised to high only when GitHub
    # marked the alert publicly leaked or active.
    "github_env_protection_missing": _ss_rule(
        _SS_GENERIC_TYPE, "medium",
        "GitHub repository configuration risk aligned with secret-scanning alert evidence",
    ),
}


def _ss_meta(event: SecurityActivityEvent) -> dict[str, Any]:
    return event.event_metadata if isinstance(event.event_metadata, dict) else {}


def build_secret_scanning_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    repo: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a correlation dict (not persisted) from a finding + open alert event."""
    md = _ss_meta(event)
    publicly_leaked = md.get("publicly_leaked") is True
    active = isinstance(md.get("validity"), str) and md["validity"].strip().lower() == "active"

    # Raise to high when GitHub marked the alert publicly leaked or active.
    severity = rule["severity"]
    if publicly_leaked or active:
        severity = "high"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['phrase']} on {repo}"
    summary = (
        f"Configuration risk \"{finding.title}\" and GitHub secret-scanning alert "
        f"evidence were observed for {repo} within the review window. This may "
        f"require review. ConfigTrace does not confirm secret misuse, compromise, "
        f"or unauthorized access."
    )

    metadata = sanitize_correlation_metadata(
        {
            "source": SS_SOURCE,
            "finding_rule": _base_rule(finding.finding_key),
            "finding_severity": finding.severity,
            "repository": repo,
            "repository_full_name": (
                md.get("repository_full_name") if isinstance(md.get("repository_full_name"), str)
                else repo
            ),
            "alert_number": md.get("alert_number"),
            "state": md.get("state"),
            "resolution": md.get("resolution"),
            "secret_type": md.get("secret_type"),
            "secret_type_display_name": md.get("secret_type_display_name"),
            "validity": md.get("validity"),
            "publicly_leaked": publicly_leaked,
            "window_hours": int(WINDOW.total_seconds() // 3600),
        }
    )

    return {
        "provider": PROVIDER_GITHUB,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def generate_github_secret_scanning_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active GitHub config-risk findings with OPEN secret-scanning alert
    evidence on the SAME repository within the review window (M69.4C).

    Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_GITHUB,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in SECRET_SCANNING_CORRELATION_RULES
    ]

    # Resolve each finding's repository slug via its Resource.
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    repo_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            repo_by_resource[r.id] = r.provider_resource_id

    # Only secret-scanning ALERT events (source-scoped); indexed by repo slug.
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
            SecurityActivityEvent.source == SS_SOURCE,
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    events_by_repo: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        if isinstance(ev.resource_id, str) and ev.resource_id:
            events_by_repo.setdefault(ev.resource_id, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.resource_id is None:
            continue  # integration-level finding — no repo to match
        repo = repo_by_resource.get(finding.resource_id)
        if not repo:
            continue
        rule = SECRET_SCANNING_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_repo.get(repo, []):
            if ev.event_type not in rule["activity_types"]:
                continue  # only OPEN alerts correlate
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_secret_scanning_correlation(
                finding=finding, event=ev, repo=repo, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_GITHUB,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ---------------------------------------------------------------------------
# GitHub config-risk × code-scanning alert correlations (M69.4F)
# ---------------------------------------------------------------------------
#
# Correlate active GitHub repository configuration-risk findings with GitHub
# code-scanning (SAST) ALERT evidence (security_activity_events, provider=github,
# source=code_scanning_alert — ingested in M69.4D) observed on the SAME repository
# within the review window. These are review correlations; they never assert
# vulnerability exploitation confirmed, an exploit, a compromise, an attacker,
# that someone has access, unauthorized access, a breach, or an attack — only
# "evidence for review".
#
# We anchor to the code-scanning ACTIVITY EVENT directly (the preferred strategy)
# and only correlate OPEN or REOPENED alerts — fixed / dismissed alerts never
# produce a (high-risk) correlation. Raw code / file paths / SARIF / locations are
# never read (the source events were already sanitized in M69.4D).

CS_SOURCE = "code_scanning_alert"
# Only open / reopened alerts are correlated (excludes fixed / dismissed).
_CS_OPEN_EVENT = "github.code_scanning.alert.open"
_CS_REOPENED_EVENT = "github.code_scanning.alert.reopened"
_CS_ACTIVITY_TYPES = {_CS_OPEN_EVENT, _CS_REOPENED_EVENT}

# Code-scanning security severities that raise the correlation severity to high.
_CS_HIGH_SEVERITIES = {"critical", "high"}


def _cs_rule(
    correlation_key: str,
    severity: str,
    phrase: str,
) -> dict[str, Any]:
    return {
        "correlation_key": correlation_key,
        "correlation_type": correlation_key,  # type == key for these families
        "activity_types": set(_CS_ACTIVITY_TYPES),
        "severity": severity,
        "phrase": phrase,
    }


# Map a finding's BASE rule key → code-scanning correlation rule. Only GitHub
# repository-scoped config-risk rules that exist today are included. Three
# families fire: repository-protection risk, automation risk, environment
# protection risk. A generic repo-scoped fallback type
# (``github_repo_risk_code_alert``) is DEFERRED — every existing repo-scoped
# GitHub finding rule already maps to a specific family, so the generic rule
# would never match. See the milestone report.
_CS_PROTECTION_TYPE = "github_repo_protection_code_alert"
_CS_AUTOMATION_TYPE = "github_automation_code_alert"
_CS_ENVIRONMENT_TYPE = "github_environment_code_alert"
_CS_GENERIC_TYPE = "github_repo_risk_code_alert"  # deferred (no rule maps to it)

CODE_SCANNING_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    # A — repository protection risk × open/reopened code-scanning alert.
    "github_branch_protection_missing": _cs_rule(
        _CS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with code-scanning alert evidence",
    ),
    "github_force_pushes_allowed": _cs_rule(
        _CS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with code-scanning alert evidence",
    ),
    "github_branch_deletion_allowed": _cs_rule(
        _CS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with code-scanning alert evidence",
    ),
    "github_pr_review_not_required": _cs_rule(
        _CS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with code-scanning alert evidence",
    ),
    "github_status_checks_not_required": _cs_rule(
        _CS_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with code-scanning alert evidence",
    ),
    # B — automation / deploy-key / webhook risk × open/reopened code-scanning alert.
    "github_webhook_http": _cs_rule(
        _CS_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with code-scanning alert evidence",
    ),
    "github_deploy_key_write_access": _cs_rule(
        _CS_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with code-scanning alert evidence",
    ),
    # C — environment protection risk × open/reopened code-scanning alert.
    # Base medium; raised to high when GitHub marked the alert high/critical.
    "github_env_protection_missing": _cs_rule(
        _CS_ENVIRONMENT_TYPE, "medium",
        "GitHub environment protection risk aligned with code-scanning alert evidence",
    ),
}


def build_code_scanning_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    repo: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a correlation dict (not persisted) from a finding + open/reopened alert."""
    md = _ss_meta(event)
    sev_level = md.get("security_severity_level")
    high = isinstance(sev_level, str) and sev_level.strip().lower() in _CS_HIGH_SEVERITIES

    # Raise to high when GitHub marked the alert high/critical security severity.
    severity = rule["severity"]
    if high:
        severity = "high"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['phrase']} on {repo}"
    summary = (
        f"Configuration risk \"{finding.title}\" and GitHub code-scanning alert "
        f"evidence were observed for {repo} within the review window. This may "
        f"require review. ConfigTrace does not confirm exploitation, compromise, "
        f"or unauthorized access."
    )

    metadata = sanitize_correlation_metadata(
        {
            "source": CS_SOURCE,
            "finding_rule": _base_rule(finding.finding_key),
            "finding_severity": finding.severity,
            "repository": repo,
            "repository_full_name": (
                md.get("repository_full_name") if isinstance(md.get("repository_full_name"), str)
                else repo
            ),
            "alert_number": md.get("alert_number"),
            "state": md.get("state"),
            "rule_id": md.get("rule_id"),
            "rule_name": md.get("rule_name"),
            "tool_name": md.get("tool_name"),
            "severity": md.get("severity"),
            "security_severity_level": md.get("security_severity_level"),
            "window_hours": int(WINDOW.total_seconds() // 3600),
        }
    )

    return {
        "provider": PROVIDER_GITHUB,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def generate_github_code_scanning_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active GitHub config-risk findings with OPEN/REOPENED code-scanning
    alert evidence on the SAME repository within the review window (M69.4F).

    Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_GITHUB,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in CODE_SCANNING_CORRELATION_RULES
    ]

    # Resolve each finding's repository slug via its Resource.
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    repo_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            repo_by_resource[r.id] = r.provider_resource_id

    # Only code-scanning ALERT events (source-scoped); indexed by repo slug.
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
            SecurityActivityEvent.source == CS_SOURCE,
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    events_by_repo: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        if isinstance(ev.resource_id, str) and ev.resource_id:
            events_by_repo.setdefault(ev.resource_id, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.resource_id is None:
            continue  # integration-level finding — no repo to match
        repo = repo_by_resource.get(finding.resource_id)
        if not repo:
            continue
        rule = CODE_SCANNING_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_repo.get(repo, []):
            if ev.event_type not in rule["activity_types"]:
                continue  # only open / reopened alerts correlate
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_code_scanning_correlation(
                finding=finding, event=ev, repo=repo, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_GITHUB,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ---------------------------------------------------------------------------
# GitHub config-risk × Dependabot alert correlations (M69.4I)
# ---------------------------------------------------------------------------
#
# Correlate active GitHub repository configuration-risk findings with GitHub
# Dependabot (vulnerable-dependency) ALERT evidence (security_activity_events,
# provider=github, source=dependabot_alert — ingested in M69.4G) observed on the
# SAME repository within the review window. These are review correlations; they
# never assert exploitation confirmed, that the vulnerable dependency was
# exploited, a compromise, an attacker, that someone has access, unauthorized
# access, a breach, or an attack — only "evidence for review".
#
# We anchor to the Dependabot ACTIVITY EVENT directly (the preferred strategy)
# and only correlate OPEN or REOPENED alerts — fixed / dismissed / auto-dismissed
# alerts never produce a (high-risk) correlation. Raw manifest/file paths,
# advisory bodies, and the raw dependency-graph response are never read (the
# source events were already sanitized in M69.4G).

DEP_SOURCE = "dependabot_alert"
# Only open / reopened alerts are correlated (excludes fixed/dismissed/auto).
_DEP_OPEN_EVENT = "github.dependabot.alert.open"
_DEP_REOPENED_EVENT = "github.dependabot.alert.reopened"
_DEP_ACTIVITY_TYPES = {_DEP_OPEN_EVENT, _DEP_REOPENED_EVENT}

# Advisory severities that raise the correlation severity to high.
_DEP_HIGH_SEVERITIES = {"critical", "high"}
_DEP_HIGH_CVSS = 7.0


def _dep_rule(
    correlation_key: str,
    severity: str,
    phrase: str,
) -> dict[str, Any]:
    return {
        "correlation_key": correlation_key,
        "correlation_type": correlation_key,  # type == key for these families
        "activity_types": set(_DEP_ACTIVITY_TYPES),
        "severity": severity,
        "phrase": phrase,
    }


# Map a finding's BASE rule key → Dependabot correlation rule. Only GitHub
# repository-scoped config-risk rules that exist today are included. Three
# families fire: repository-protection risk, automation risk, environment
# protection risk. A generic repo-scoped fallback type
# (``github_repo_risk_dependabot_alert``) is DEFERRED — every existing
# repo-scoped GitHub finding rule already maps to a specific family, so the
# generic rule would never match. See the milestone report.
_DEP_PROTECTION_TYPE = "github_repo_protection_dependabot_alert"
_DEP_AUTOMATION_TYPE = "github_automation_dependabot_alert"
_DEP_ENVIRONMENT_TYPE = "github_environment_dependabot_alert"
_DEP_GENERIC_TYPE = "github_repo_risk_dependabot_alert"  # deferred (no rule maps to it)

DEPENDABOT_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    # A — repository protection risk × open/reopened Dependabot alert.
    "github_branch_protection_missing": _dep_rule(
        _DEP_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with Dependabot alert evidence",
    ),
    "github_force_pushes_allowed": _dep_rule(
        _DEP_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with Dependabot alert evidence",
    ),
    "github_branch_deletion_allowed": _dep_rule(
        _DEP_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with Dependabot alert evidence",
    ),
    "github_pr_review_not_required": _dep_rule(
        _DEP_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with Dependabot alert evidence",
    ),
    "github_status_checks_not_required": _dep_rule(
        _DEP_PROTECTION_TYPE, "high",
        "GitHub repository protection risk aligned with Dependabot alert evidence",
    ),
    # B — automation / deploy-key / webhook risk × open/reopened Dependabot alert.
    "github_webhook_http": _dep_rule(
        _DEP_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with Dependabot alert evidence",
    ),
    "github_deploy_key_write_access": _dep_rule(
        _DEP_AUTOMATION_TYPE, "high",
        "GitHub automation risk aligned with Dependabot alert evidence",
    ),
    # C — environment protection risk × open/reopened Dependabot alert.
    # Base medium; raised to high when the advisory is high/critical or CVSS>=7.
    "github_env_protection_missing": _dep_rule(
        _DEP_ENVIRONMENT_TYPE, "medium",
        "GitHub environment protection risk aligned with Dependabot alert evidence",
    ),
}


def build_dependabot_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    repo: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a correlation dict (not persisted) from a finding + open/reopened alert."""
    md = _ss_meta(event)
    sev = md.get("advisory_severity")
    score = md.get("cvss_score")
    high = (
        (isinstance(sev, str) and sev.strip().lower() in _DEP_HIGH_SEVERITIES)
        or (isinstance(score, (int, float)) and not isinstance(score, bool) and score >= _DEP_HIGH_CVSS)
    )

    # Raise to high when the advisory is high/critical or CVSS >= 7.0.
    severity = rule["severity"]
    if high:
        severity = "high"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['phrase']} on {repo}"
    summary = (
        f"Configuration risk \"{finding.title}\" and GitHub Dependabot alert "
        f"evidence were observed for {repo} within the review window. This may "
        f"require review. ConfigTrace does not confirm exploitation, compromise, "
        f"or unauthorized access."
    )

    metadata = sanitize_correlation_metadata(
        {
            "source": DEP_SOURCE,
            "finding_rule": _base_rule(finding.finding_key),
            "finding_severity": finding.severity,
            "repository": repo,
            "repository_full_name": (
                md.get("repository_full_name") if isinstance(md.get("repository_full_name"), str)
                else repo
            ),
            "alert_number": md.get("alert_number"),
            "state": md.get("state"),
            "dependency_package_name": md.get("dependency_package_name"),
            "dependency_ecosystem": md.get("dependency_ecosystem"),
            "vulnerable_version_range": md.get("vulnerable_version_range"),
            "patched_versions": md.get("patched_versions"),
            "advisory_ghsa_id": md.get("advisory_ghsa_id"),
            "advisory_cve_id": md.get("advisory_cve_id"),
            "advisory_severity": md.get("advisory_severity"),
            "cvss_score": md.get("cvss_score"),
            "epss_percentage": md.get("epss_percentage"),
            "scope": md.get("scope"),
            "window_hours": int(WINDOW.total_seconds() // 3600),
        }
    )

    return {
        "provider": PROVIDER_GITHUB,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def generate_github_dependabot_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active GitHub config-risk findings with OPEN/REOPENED Dependabot
    alert evidence on the SAME repository within the review window (M69.4I).

    Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_GITHUB,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in DEPENDABOT_CORRELATION_RULES
    ]

    # Resolve each finding's repository slug via its Resource.
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    repo_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            repo_by_resource[r.id] = r.provider_resource_id

    # Only Dependabot ALERT events (source-scoped); indexed by repo slug.
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
            SecurityActivityEvent.source == DEP_SOURCE,
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    events_by_repo: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        if isinstance(ev.resource_id, str) and ev.resource_id:
            events_by_repo.setdefault(ev.resource_id, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.resource_id is None:
            continue  # integration-level finding — no repo to match
        repo = repo_by_resource.get(finding.resource_id)
        if not repo:
            continue
        rule = DEPENDABOT_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_repo.get(repo, []):
            if ev.event_type not in rule["activity_types"]:
                continue  # only open / reopened alerts correlate
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_dependabot_correlation(
                finding=finding, event=ev, repo=repo, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_GITHUB,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ---------------------------------------------------------------------------
# GitHub ruleset / automation-permission risk × evidence correlations (M69.5C)
# ---------------------------------------------------------------------------
#
# Correlate the M69.5A ruleset findings and M69.5B automation-permission findings
# with existing GitHub evidence on the SAME repository within the review window:
#   * repository-protection / automation AUDIT activity (source=audit_log), and
#   * OPEN/REOPENED security-alert evidence (secret / code / Dependabot).
# These are review correlations; they never assert compromise, a token leak, an
# attacker, that someone has access, unauthorized access, a breach, or an attack —
# only "evidence for review". Only safe aggregate posture fields are stored.

# Finding-rule families (base keys; M69.5A / M69.5B).
_RULESET_FINDING_RULES: frozenset[str] = frozenset({
    "github_ruleset_not_enforced",
    "github_ruleset_force_push_allowed",
    "github_ruleset_pr_review_missing",
    "github_ruleset_status_checks_missing",
    "github_ruleset_bypass_actors_present",
    "github_ruleset_weak_target_coverage",
})
_AUTOMATION_FINDING_RULES: frozenset[str] = frozenset({
    "github_automation_admin_permission",
    "github_automation_write_permission",
    "github_token_broad_scopes",
    "github_webhook_secret_missing",
})

# Evidence event types (audit activity) for each family.
_AUDIT_SOURCE = "audit_log"
_RULESET_PROTECTION_ACTIVITY: frozenset[str] = frozenset({
    "github.ruleset.changed",
    "github.branch_protection.disabled",
    "github.branch_protection.updated",
})
_AUTOMATION_ACTIVITY: frozenset[str] = frozenset({
    "github.deploy_key.added",
    "github.webhook.created",
    "github.webhook.updated",
    "github.webhook.deleted",
    "github.app.installed",
    "github.app.permissions_changed",
})

# OPEN/REOPENED security-alert evidence (excludes fixed / dismissed).
_SECURITY_ALERT_SOURCES: frozenset[str] = frozenset({
    "secret_scanning_alert", "code_scanning_alert", "dependabot_alert",
})
_OPEN_ALERT_EVENTS: frozenset[str] = frozenset({
    "github.secret_scanning.alert.open",
    "github.code_scanning.alert.open",
    "github.code_scanning.alert.reopened",
    "github.dependabot.alert.open",
    "github.dependabot.alert.reopened",
})
_HIGH_ALERT_SEVERITIES = {"critical", "high"}


def _finding_evidence(finding: SecurityFinding) -> dict[str, Any]:
    return finding.evidence if isinstance(finding.evidence, dict) else {}


def _build_github_finding_evidence_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    repo: str,
    correlation_type: str,
    phrase: str,
    summary_core: str,
    alert_based: bool,
) -> dict[str, Any]:
    """Build a correlation dict (not persisted) for an M69.5C finding × evidence pair."""
    fev = _finding_evidence(finding)
    md = _ss_meta(event)

    # Severity: high when the finding is high/critical; for alert-based families,
    # also high when the alert itself is high/critical / publicly leaked.
    severity = "high" if finding.severity in _HIGH_SEVERITIES else "medium"
    if alert_based:
        alert_sev = md.get("advisory_severity") or md.get("security_severity_level")
        if isinstance(alert_sev, str) and alert_sev.strip().lower() in _HIGH_ALERT_SEVERITIES:
            severity = "high"
        if md.get("publicly_leaked") is True:
            severity = "high"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)
    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None
    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{phrase} on {repo}"
    summary = (
        f"Configuration risk \"{finding.title}\" and {summary_core} were observed "
        f"for {repo} within the review window. This may require review. ConfigTrace "
        f"does not confirm unauthorized access or compromise."
    )

    metadata = sanitize_correlation_metadata({
        "source": event.source,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "repository": repo,
        "repository_full_name": (
            md.get("repository_full_name") if isinstance(md.get("repository_full_name"), str)
            else repo
        ),
        "event_type": event.event_type,
        "window_hours": int(WINDOW.total_seconds() // 3600),
        # Ruleset finding posture (from the finding's safe evidence).
        "ruleset_name": fev.get("ruleset_name"),
        "enforcement": fev.get("enforcement"),
        "target": fev.get("target"),
        "bypass_actor_count": fev.get("bypass_actor_count"),
        "required_status_checks_count": fev.get("required_status_checks_count"),
        "targets_protected_branch": fev.get("targets_protected_branch"),
        # Automation finding posture (from the finding's safe evidence).
        "credential_type": fev.get("credential_type"),
        "broad_permission_count": fev.get("broad_permission_count"),
        "token_scope_count": fev.get("token_scope_count"),
        "webhook_secret_configured": fev.get("webhook_secret_configured"),
        # Alert evidence posture (from the event's safe metadata).
        "alert_number": md.get("alert_number"),
        "state": md.get("state"),
        "rule_id": md.get("rule_id"),
        "rule_name": md.get("rule_name"),
        "tool_name": md.get("tool_name"),
        "security_severity_level": md.get("security_severity_level"),
        "advisory_ghsa_id": md.get("advisory_ghsa_id"),
        "advisory_cve_id": md.get("advisory_cve_id"),
        "advisory_severity": md.get("advisory_severity"),
        "dependency_package_name": md.get("dependency_package_name"),
        "dependency_ecosystem": md.get("dependency_ecosystem"),
        "secret_type": md.get("secret_type"),
        "validity": md.get("validity"),
        "publicly_leaked": md.get("publicly_leaked"),
    })

    return {
        "provider": PROVIDER_GITHUB,
        "correlation_key": correlation_type,
        "correlation_type": correlation_type,
        "severity": severity,
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        "_integration_id": finding.integration_id,
    }


def _generate_github_finding_evidence_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    finding_rules: frozenset[str],
    activity_sources: frozenset[str],
    activity_types: frozenset[str],
    correlation_type: str,
    phrase: str,
    summary_core: str,
    alert_based: bool,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Generic M69.5C pass: correlate findings (in ``finding_rules``) with GitHub
    activity events (source ∈ ``activity_sources``, type ∈ ``activity_types``) on
    the SAME repository within the review window. Idempotent."""
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_GITHUB,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [f for f in findings if _base_rule(f.finding_key) in finding_rules]

    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    repo_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            repo_by_resource[r.id] = r.provider_resource_id

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
            SecurityActivityEvent.source.in_(activity_sources),
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    events_by_repo: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        if isinstance(ev.resource_id, str) and ev.resource_id:
            events_by_repo.setdefault(ev.resource_id, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.resource_id is None:
            continue
        repo = repo_by_resource.get(finding.resource_id)
        if not repo:
            continue
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_repo.get(repo, []):
            if ev.event_type not in activity_types:
                continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = _build_github_finding_evidence_correlation(
                finding=finding, event=ev, repo=repo,
                correlation_type=correlation_type, phrase=phrase,
                summary_core=summary_core, alert_based=alert_based,
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_GITHUB,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


def _generate_github_5c_correlations(
    *, workspace_id: uuid.UUID, db: Session, scan_limit: int = 1000,
) -> dict[str, Any]:
    """Run all four M69.5C passes (ruleset/automation × audit-activity / alert)."""
    passes = [
        # A — ruleset risk × repository-protection audit activity.
        dict(finding_rules=_RULESET_FINDING_RULES, activity_sources=frozenset({_AUDIT_SOURCE}),
             activity_types=_RULESET_PROTECTION_ACTIVITY,
             correlation_type="github_ruleset_risk_activity",
             phrase="GitHub ruleset risk aligned with repository protection activity",
             summary_core="GitHub repository protection activity", alert_based=False),
        # B — ruleset risk × security-alert evidence.
        dict(finding_rules=_RULESET_FINDING_RULES, activity_sources=_SECURITY_ALERT_SOURCES,
             activity_types=_OPEN_ALERT_EVENTS,
             correlation_type="github_ruleset_risk_security_alert",
             phrase="GitHub ruleset risk aligned with security-alert evidence",
             summary_core="GitHub security-alert evidence", alert_based=True),
        # C — automation permission risk × automation audit activity.
        dict(finding_rules=_AUTOMATION_FINDING_RULES, activity_sources=frozenset({_AUDIT_SOURCE}),
             activity_types=_AUTOMATION_ACTIVITY,
             correlation_type="github_automation_permission_activity",
             phrase="GitHub automation permission risk aligned with automation activity",
             summary_core="GitHub automation activity", alert_based=False),
        # D — automation permission risk × security-alert evidence.
        dict(finding_rules=_AUTOMATION_FINDING_RULES, activity_sources=_SECURITY_ALERT_SOURCES,
             activity_types=_OPEN_ALERT_EVENTS,
             correlation_type="github_automation_permission_security_alert",
             phrase="GitHub automation permission risk aligned with security-alert evidence",
             summary_core="GitHub security-alert evidence", alert_based=True),
    ]
    totals = {"findings_scanned": 0, "events_scanned": 0,
              "correlations_created": 0, "correlations_skipped": 0}
    for kw in passes:
        r = _generate_github_finding_evidence_correlations(
            workspace_id=workspace_id, db=db, scan_limit=scan_limit, **kw
        )
        for k in totals:
            totals[k] += r[k]
    return totals


# Public builders for direct (non-scanning) use by the incident demo seeder
# (M69.6) — keep the M69.5C phrasing authoritative in one place.
def build_ruleset_activity_correlation(
    *, finding: SecurityFinding, event: SecurityActivityEvent, repo: str,
) -> dict[str, Any]:
    """Ruleset risk × repository-protection activity (github_ruleset_risk_activity)."""
    return _build_github_finding_evidence_correlation(
        finding=finding, event=event, repo=repo,
        correlation_type="github_ruleset_risk_activity",
        phrase="GitHub ruleset risk aligned with repository protection activity",
        summary_core="GitHub repository protection activity", alert_based=False,
    )


def build_automation_security_alert_correlation(
    *, finding: SecurityFinding, event: SecurityActivityEvent, repo: str,
) -> dict[str, Any]:
    """Automation permission risk × security-alert evidence
    (github_automation_permission_security_alert)."""
    return _build_github_finding_evidence_correlation(
        finding=finding, event=event, repo=repo,
        correlation_type="github_automation_permission_security_alert",
        phrase="GitHub automation permission risk aligned with security-alert evidence",
        summary_core="GitHub security-alert evidence", alert_based=True,
    )


def generate_github_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Generate ALL GitHub correlations for a workspace (M66.6 + M69.4C/F/I + M69.5C).

    provider=github now generates:
      * Configuration Risk × GitHub audit activity (webhook / branch-protection /
        deploy-key), and
      * Configuration Risk × GitHub secret/code/Dependabot alert evidence (same
        repository, OPEN/REOPENED alert, within the review window), and
      * GitHub ruleset risk and automation-permission risk × repository-protection /
        automation audit activity and × OPEN/REOPENED security-alert evidence
        (M69.5C, same repository, within the review window).
    The returned summary sums all passes. Idempotent.
    """
    audit = _generate_github_audit_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    secret = generate_github_secret_scanning_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    code = generate_github_code_scanning_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    dependabot = generate_github_dependabot_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    rulesets_automation = _generate_github_5c_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    passes = (audit, secret, code, dependabot, rulesets_automation)
    return {
        "provider": PROVIDER_GITHUB,
        "findings_scanned": sum(p["findings_scanned"] for p in passes),
        "events_scanned": sum(p["events_scanned"] for p in passes),
        "correlations_created": sum(p["correlations_created"] for p in passes),
        "correlations_skipped": sum(p["correlations_skipped"] for p in passes),
    }


# ---------------------------------------------------------------------------
# AWS correlations (M67.3)
# ---------------------------------------------------------------------------
#
# AWS Configuration Risk findings (``security_findings`` provider=aws, produced
# by ``security_rules/aws.py``) are correlated with AWS provider-reported
# security alerts (``security_activity_events`` provider=aws, source=
# "security_alert" — GuardDuty / Access Analyzer, ingested in M67.1) ONLY when
# both sides reference the SAME concrete resource (an S3 bucket name or an IAM
# principal/user name). Matching is resource-driven, never account-wide.
#
# Safely matchable today (the finding's evidence carries the resource name):
#   * S3 public-policy / public-ACL findings  → ``evidence["bucket"]``
#       matched to a GuardDuty S3Bucket alert (resource_id = bucket name) or an
#       Access Analyzer finding (resource_id = bucket ARN → bucket name).
#   * IAM AdministratorAccess-attached         → ``evidence["principal_name"]``
#   * IAM unused-access-key                     → ``evidence["username"]``
#       matched to a GuardDuty AccessKey alert (resource_id = IAM user name).
#
# DEFERRED — security-group public-ingress finding → GuardDuty EC2 instance:
#   the current data CANNOT link a security group to an EC2 instance. The SG
#   rule records (``security_rules/aws.py``) carry no attachment / ENI / public-
#   IP / instance-id context, and GuardDuty Instance findings reference an
#   InstanceId. There is no safe join key, so we DO NOT correlate them — being
#   in the same AWS account is not evidence. This rule is intentionally omitted.

# Map a finding's BASE rule key → AWS correlation rule descriptor.
_AWS_S3_RULE = {
    "correlation_key": "aws_s3_public_access_alert",
    "correlation_type": "aws_s3_public_access_alert",
    "severity": "high",
    "phrase": "S3 public-access configuration risk aligned with an AWS provider security finding",
    "summary_subject": "An S3 bucket configuration risk",
    "summary_provider": "an AWS provider security finding (GuardDuty / Access Analyzer)",
}
_AWS_IAM_RULE = {
    "correlation_key": "aws_iam_credential_alert",
    "correlation_type": "aws_iam_credential_alert",
    "severity": "high",
    "phrase": "IAM configuration risk aligned with an AWS provider credential finding",
    "summary_subject": "An IAM configuration risk",
    "summary_provider": "an AWS provider credential finding (GuardDuty)",
}

# finding base rule → (AWS correlation rule, evidence key holding the resource).
AWS_CORRELATION_RULES: dict[str, tuple[dict[str, Any], str]] = {
    "aws_s3_public_policy": (_AWS_S3_RULE, "bucket"),
    "aws_s3_public_acl": (_AWS_S3_RULE, "bucket"),
    "aws_iam_admin_policy_attached": (_AWS_IAM_RULE, "principal_name"),
    "aws_access_key_unused": (_AWS_IAM_RULE, "username"),
}


def _norm_resource(value: Any) -> Optional[str]:
    """Normalize a resource identifier to a comparable bare name.

    Reduces ARNs to their final segment (``arn:aws:s3:::my-bucket`` → ``my-bucket``;
    ``arn:aws:iam::123:user/deploy`` → ``deploy``) and lower-cases. Returns None
    for empty / non-string values so empty keys never match.
    """
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if "arn:aws:" in s:
        if "/" in s:
            s = s.rsplit("/", 1)[-1]
        else:
            s = s.rsplit(":", 1)[-1]
    s = s.strip()
    return s.lower() or None


def _aws_finding_resource_key(finding: SecurityFinding) -> Optional[str]:
    """Extract the normalized resource name a finding references (from evidence)."""
    base = _base_rule(finding.finding_key)
    mapping = AWS_CORRELATION_RULES.get(base)
    if mapping is None:
        return None
    _rule_desc, evidence_key = mapping
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    return _norm_resource(evidence.get(evidence_key))


def build_aws_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    resource_key: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build an AWS correlation dict (not persisted) from a matched finding + alert."""
    severity = rule["severity"]
    # A provider alert flagged "critical" raises the review priority.
    meta = event.event_metadata if isinstance(event.event_metadata, dict) else {}
    if meta.get("severity_label") == "critical":
        severity = "critical"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['phrase']} ({resource_key})"
    summary = (
        f"{rule['summary_subject']} (\"{finding.title}\") and {rule['summary_provider']} "
        f"(\"{event.event_type}\") were observed for the same resource "
        f"\"{resource_key}\" within the review window. {_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata(
        {
            "resource": resource_key,
            "finding_rule": _base_rule(finding.finding_key),
            "finding_severity": finding.severity,
            "event_type": event.event_type,
            "region": meta.get("region") if isinstance(meta.get("region"), str) else None,
            "account_id": meta.get("account_id")
            if isinstance(meta.get("account_id"), str)
            else None,
            "window_hours": int(WINDOW.total_seconds() // 3600),
        }
    )

    return {
        "provider": PROVIDER_AWS,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        # Exact same-resource match between a config risk and a provider-
        # adjudicated alert is strong (but still circumstantial) evidence.
        "confidence": "high",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def _generate_aws_alert_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active AWS findings with AWS provider alerts for a workspace.

    Conservative + resource-driven: a finding only matches an alert that
    references the SAME bucket / IAM principal name within the finding's review
    window. Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_AWS,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in AWS_CORRELATION_RULES
    ]

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_AWS,
            SecurityActivityEvent.source == "security_alert",
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Index alerts by normalized resource key for cheap, exact lookup.
    events_by_resource: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        key = _norm_resource(ev.resource_id)
        if key:
            events_by_resource.setdefault(key, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        resource_key = _aws_finding_resource_key(finding)
        if not resource_key:
            continue  # no safe resource name to match on
        rule, _evidence_key = AWS_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events_by_resource.get(resource_key, []):
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_aws_correlation(
                finding=finding, event=ev, resource_key=resource_key, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_AWS,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ---------------------------------------------------------------------------
# AWS S3 exposure × S3 object-activity correlations (M69.2A)
# ---------------------------------------------------------------------------
#
# AWS S3 public-EXPOSURE Configuration Risk findings (``aws_s3_public_policy`` /
# ``aws_s3_public_acl`` from ``security_rules/aws.py``) are correlated with S3
# OBJECT-LEVEL activity (``security_activity_events`` provider=aws, source=
# "s3_data_event" — ingested in M67.8) ONLY when both reference the SAME bucket
# within the finding's review window.
#
# JOIN KEY: the finding's ``evidence["bucket"]`` (normalized) must equal the S3
# data event's bucket (``resource_id`` / ``metadata["bucket_name"]``, normalized).
# Same account / same provider is NEVER enough — only same bucket.
#
# OUTPUT SHAPE: one correlation per (finding, rule-category), anchored to a
# deterministic representative event, with ``event_count`` as a safe aggregate —
# so the correlation count is bounded by the number of exposure findings, never
# the (large) S3 data-event volume.
#
# CLAIM DISCIPLINE: a correlation is EVIDENCE FOR REVIEW. It NEVER asserts data
# exfiltration, a breach, an attacker, a compromise, or unauthorized access — only
# that a public-exposure risk and S3 object activity co-occurred for the same
# bucket and may require review.
#
# PRIVACY: only safe aggregate fields are stored (bucket name, sanitized object
# prefix, event type, counts, window). NEVER a raw object key, raw IP, raw
# CloudTrail JSON, requestParameters/responseElements, tokens, secrets, or keys.

_AWS_S3_EXPOSURE_RULES = frozenset({"aws_s3_public_policy", "aws_s3_public_acl"})
_AWS_S3_DATA_SOURCE = "s3_data_event"
_AWS_S3_SPIKE_SIGNAL_TYPE = "s3_object_access_spike"
_AWS_S3_GET = "aws.s3.data.get_object"
_AWS_S3_LIST = "aws.s3.data.list_bucket"

_AWS_S3_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm data exfiltration or "
    "unauthorized access."
)

# (correlation_key, correlation_type, event_type, activity phrase) per category.
_AWS_S3_GETOBJECT_RULE = {
    "correlation_key": "aws_s3_public_getobject_activity",
    "correlation_type": "aws_s3_public_getobject_activity",
    "event_type": _AWS_S3_GET,
    "phrase": "S3 exposure risk aligned with object-read activity",
    "activity": "S3 object-read activity",
}
_AWS_S3_LISTBUCKET_RULE = {
    "correlation_key": "aws_s3_public_listbucket_activity",
    "correlation_type": "aws_s3_public_listbucket_activity",
    "event_type": _AWS_S3_LIST,
    "phrase": "S3 exposure risk aligned with bucket-list activity",
    "activity": "S3 bucket-list activity",
}
_AWS_S3_SPIKE_RULE = {
    "correlation_key": "aws_s3_public_access_spike_activity",
    "correlation_type": "aws_s3_public_access_spike_activity",
    "phrase": "S3 exposure risk aligned with an S3 object-access spike",
    "activity": "an S3 object-access spike",
}

# Event-type → category rule for the per-event passes (GetObject / ListBucket).
_AWS_S3_EVENT_RULES = {
    _AWS_S3_GET: _AWS_S3_GETOBJECT_RULE,
    _AWS_S3_LIST: _AWS_S3_LISTBUCKET_RULE,
}


def _aws_event_bucket(ev: SecurityActivityEvent) -> Optional[str]:
    """Normalized bucket name for an S3 data event (metadata or resource_id)."""
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    return _norm_resource(md.get("bucket_name")) or _norm_resource(ev.resource_id)


def _aws_s3_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Deterministically pick a representative event (latest time, then id)."""
    return max(
        events,
        key=lambda e: (
            _aware(e.occurred_at) or _aware(e.ingested_at)
            or datetime.min.replace(tzinfo=timezone.utc),
            str(e.provider_event_id or ""),
        ),
    )


def build_aws_s3_activity_correlation(
    *,
    finding: SecurityFinding,
    anchor: SecurityActivityEvent,
    matched: list[SecurityActivityEvent],
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build an S3 exposure × object-activity correlation dict (not persisted)."""
    _valid_sev = {"critical", "high", "medium", "low", "info"}
    severity = finding.severity if finding.severity in _valid_sev else "high"

    md = anchor.event_metadata if isinstance(anchor.event_metadata, dict) else {}
    bucket = (
        md.get("bucket_name") if isinstance(md.get("bucket_name"), str) else None
    ) or (anchor.resource_id if isinstance(anchor.resource_id, str) else None)

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(anchor.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    label = bucket or "an S3 bucket"
    title = f"{rule['phrase']} ({label})"
    summary = (
        f"An S3 exposure risk (\"{finding.title}\") and {rule['activity']} were "
        f"observed for the same bucket \"{label}\" within the review window. "
        f"{_AWS_S3_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": _AWS_S3_DATA_SOURCE,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": anchor.event_type,
        "bucket_name": bucket,
        "object_key_prefix": md.get("object_key_prefix")
        if isinstance(md.get("object_key_prefix"), str) else None,
        "event_count": len(matched),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_AWS,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        # Same-bucket exposure + object activity is circumstantial co-occurrence
        # (object activity is not provider-adjudicated) — calibrated to "medium".
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": anchor.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def generate_aws_s3_exposure_activity_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 2000,
) -> dict[str, Any]:
    """Correlate active AWS S3 public-exposure findings with S3 object activity.

    Conservative + bucket-driven: an exposure finding only matches S3 data events
    (GetObject / ListBucket) and S3 object-access-spike signals for the SAME bucket
    within the finding's review window. One correlation per (finding, category),
    anchored to a deterministic representative event. Idempotent.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_AWS,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in _AWS_S3_EXPOSURE_RULES
    ]

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_AWS,
            SecurityActivityEvent.source == _AWS_S3_DATA_SOURCE,
            SecurityActivityEvent.event_type.in_(tuple(_AWS_S3_EVENT_RULES.keys())),
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Index S3 data events by (bucket, event_type) for cheap, exact lookup.
    events_by_bucket_type: dict[tuple[str, str], list[SecurityActivityEvent]] = {}
    for ev in events:
        bucket = _aws_event_bucket(ev)
        if not bucket:
            continue  # never correlate an event without a bucket
        events_by_bucket_type.setdefault((bucket, ev.event_type), []).append(ev)

    # Index S3 object-access-spike signals by bucket for the spike pass.
    spike_signals = (
        db.query(SecurityIncidentSignal)
        .filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            SecurityIncidentSignal.provider == PROVIDER_AWS,
            SecurityIncidentSignal.signal_type == _AWS_S3_SPIKE_SIGNAL_TYPE,
            SecurityIncidentSignal.linked_activity_event_id.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    spikes_by_bucket: dict[str, list[SecurityIncidentSignal]] = {}
    for sig in spike_signals:
        smd = sig.signal_metadata if isinstance(sig.signal_metadata, dict) else {}
        bucket = _norm_resource(smd.get("bucket_name"))
        if bucket:
            spikes_by_bucket.setdefault(bucket, []).append(sig)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.integration_id is None:
            continue
        bucket_key = _aws_finding_resource_key(finding)
        if not bucket_key:
            continue  # no safe bucket name on the finding
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        # Per-event-type passes (GetObject, ListBucket).
        for event_type, rule in _AWS_S3_EVENT_RULES.items():
            matched = [
                ev for ev in events_by_bucket_type.get((bucket_key, event_type), [])
                if (occ := _aware(ev.occurred_at)) is not None
                and window_start <= occ <= window_end
            ]
            if not matched:
                continue
            anchor = _aws_s3_anchor(matched)
            correlation = build_aws_s3_activity_correlation(
                finding=finding, anchor=anchor, matched=matched, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

        # Spike pass — exposure + a detected S3 object-access spike (M67.9) for the
        # same bucket. Links the spike's anchor activity event.
        for sig in spikes_by_bucket.get(bucket_key, []):
            anchor_id = sig.linked_activity_event_id
            anchor = db.get(SecurityActivityEvent, anchor_id) if anchor_id else None
            if anchor is None:
                continue
            occ = _aware(sig.last_seen_at) or _aware(anchor.occurred_at)
            if occ is None or not (window_start <= occ <= window_end):
                continue
            smd = sig.signal_metadata if isinstance(sig.signal_metadata, dict) else {}
            count = smd.get("event_count")
            matched = [anchor] * (count if isinstance(count, int) and count > 0 else 1)
            correlation = build_aws_s3_activity_correlation(
                finding=finding, anchor=anchor, matched=matched, rule=_AWS_S3_SPIKE_RULE
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_AWS,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ---------------------------------------------------------------------------
# AWS Security Group exposure × VPC Flow Log correlations (M69.2B)
# ---------------------------------------------------------------------------
#
# AWS Security Group public-EXPOSURE Configuration Risk findings
# (``aws_public_admin_port`` / ``aws_public_database_port`` /
# ``aws_public_all_ports`` from ``security_rules/aws.py``) are correlated with
# VPC Flow Log activity (``security_activity_events`` provider=aws, source=
# "vpc_flow_log" — ingested in M67.10) when BOTH share the SAME integration
# (same AWS account/region) AND the VPC flow's destination port falls within
# the SG rule's exposed port range (from_port..to_port), within the finding's
# review window.
#
# JOIN KEY: same ``integration_id`` (same AWS account/region scope) +
# destination port overlap (flow's ``dst_port`` within finding's exposed
# ``from_port``..``to_port``) + risk-area match (admin vs datastore ports).
# This is NOT "same port only" — the integration + port range + risk area +
# window combination provides non-vague, account-scoped evidence. Raw IPs and
# raw flow lines are NEVER used; no SG→ENI mapping is attempted.
#
# OUTPUT SHAPE: one correlation per (finding, port category, action category),
# anchored to a deterministic representative event, with ``event_count`` as a
# safe aggregate. Bounded by the number of exposure findings.
#
# CLAIM DISCIPLINE: a correlation is EVIDENCE FOR REVIEW. It NEVER asserts a
# network intrusion, breach, attacker, compromise, or unauthorized access.
#
# PRIVACY: only safe aggregate identifiers are stored (security_group_id,
# dst_port, port_category, interface_id, protocol, flow_action, event_count,
# window). NEVER raw source/destination IPs, raw flow lines, payloads,
# headers, tokens, secrets, or access keys.
#
# DEFERRED:
#   * SG→ENI exact mapping: no join key exists today (SG records carry no ENI
#     attachment; VPC flow records carry no SG context). Flagged in M69.1 and
#     intentionally omitted — correlating an SG finding to a *specific* ENI
#     would require a SG→attachment side-table that does not exist yet.

_AWS_SG_EXPOSURE_RULES = frozenset({
    "aws_public_admin_port",
    "aws_public_database_port",
    "aws_public_all_ports",
})
_AWS_VPC_FLOW_SOURCE = "vpc_flow_log"
_AWS_FLOW_ACCEPT = "aws.vpc.flow.accept"
_AWS_FLOW_REJECT = "aws.vpc.flow.reject"

# Sensitive destination ports — must match aws_vpc_flow_signal_service.
_SG_ADMIN_PORTS: frozenset[int] = frozenset({22, 3389, 5985, 5986})
_SG_DB_PORTS: frozenset[int] = frozenset({3306, 5432, 6379, 27017, 9200, 1433})

# Minimum reject events required to create a reject correlation (conservative).
_SG_REJECT_THRESHOLD = 2

# Mapping: finding base rule → list of sensitive port sets to match against.
# All three rules get matched against admin and/or DB ports only — "all ports"
# findings match both, but never arbitrary other ports (too vague).
_SG_RULE_PORT_SETS: dict[str, list[frozenset[int]]] = {
    "aws_public_admin_port": [_SG_ADMIN_PORTS],
    "aws_public_database_port": [_SG_DB_PORTS],
    "aws_public_all_ports": [_SG_ADMIN_PORTS, _SG_DB_PORTS],
}

_AWS_VPC_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm network intrusion or "
    "unauthorized access."
)

_SG_ADMIN_ACCEPT_RULE = {
    "correlation_key": "aws_sg_public_admin_port_flow",
    "correlation_type": "aws_sg_public_admin_port_flow",
    "action_type": _AWS_FLOW_ACCEPT,
    "phrase": "Security group admin-port exposure aligned with accepted network flow",
    "activity": "accepted VPC network flow to an admin destination port",
}
_SG_DB_ACCEPT_RULE = {
    "correlation_key": "aws_sg_public_database_port_flow",
    "correlation_type": "aws_sg_public_database_port_flow",
    "action_type": _AWS_FLOW_ACCEPT,
    "phrase": "Security group datastore-port exposure aligned with accepted network flow",
    "activity": "accepted VPC network flow to a datastore destination port",
}
_SG_REJECT_RULE = {
    "correlation_key": "aws_sg_public_rejected_flow_activity",
    "correlation_type": "aws_sg_public_rejected_flow_activity",
    "action_type": _AWS_FLOW_REJECT,
    "phrase": "Security group exposure aligned with repeated rejected network flow",
    "activity": "repeated rejected VPC network flow activity to an exposed destination port",
}

# Port set → correlation rule descriptor (accept path).
_SG_PORT_SET_TO_RULE: dict[int, dict[str, Any]] = {}  # keyed by id() for O(1) lookup
_SG_PORT_SET_TO_RULE[id(_SG_ADMIN_PORTS)] = _SG_ADMIN_ACCEPT_RULE
_SG_PORT_SET_TO_RULE[id(_SG_DB_PORTS)] = _SG_DB_ACCEPT_RULE


def _sg_finding_evidence(finding: SecurityFinding) -> dict[str, Any]:
    return finding.evidence if isinstance(finding.evidence, dict) else {}


def _flow_dst_port(ev: SecurityActivityEvent) -> Optional[int]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get("dst_port")
    return v if isinstance(v, int) else None


def _flow_interface(ev: SecurityActivityEvent) -> Optional[str]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    iface = md.get("interface_id")
    if isinstance(iface, str) and iface:
        return iface
    return ev.resource_id if isinstance(ev.resource_id, str) and ev.resource_id else None


def _port_in_sg_range(dst_port: int, evidence: dict[str, Any]) -> bool:
    """Return True if dst_port falls in the SG rule's exposed port range.

    If from_port/to_port are absent (all-ports rule), every port matches.
    """
    fp = evidence.get("from_port")
    tp = evidence.get("to_port")
    if not isinstance(fp, int) or not isinstance(tp, int):
        return True  # all-ports finding or range info absent → accept any port
    return fp <= dst_port <= tp


def _aws_vpc_flow_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Deterministically select the most representative VPC flow event.

    Prefer ACCEPT over REJECT; then latest occurrence time; then id.
    """
    return max(
        events,
        key=lambda e: (
            1 if e.event_type == _AWS_FLOW_ACCEPT else 0,
            _aware(e.occurred_at) or _aware(e.ingested_at)
            or datetime.min.replace(tzinfo=timezone.utc),
            str(e.provider_event_id or ""),
        ),
    )


def build_aws_sg_vpc_flow_correlation(
    *,
    finding: SecurityFinding,
    anchor: SecurityActivityEvent,
    matched: list[SecurityActivityEvent],
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build an AWS SG exposure × VPC flow correlation dict (not persisted)."""
    _valid_sev = {"critical", "high", "medium", "low", "info"}
    severity = finding.severity if finding.severity in _valid_sev else "high"
    # Rejected flow is weaker evidence → cap severity at medium.
    if rule.get("action_type") == _AWS_FLOW_REJECT:
        if severity in {"critical", "high"}:
            severity = "medium"
        confidence = "low"
    else:
        confidence = "medium"

    md = anchor.event_metadata if isinstance(anchor.event_metadata, dict) else {}
    dst_port = _flow_dst_port(anchor)
    interface = _flow_interface(anchor)
    ev_evidence = _sg_finding_evidence(finding)
    sg_id = ev_evidence.get("group_id")

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(anchor.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    port_label = f"port {dst_port}" if dst_port is not None else "an exposed port"
    title = f"{rule['phrase']} ({port_label})"
    summary = (
        f"An AWS security group exposure risk (\"{finding.title}\") and {rule['activity']} "
        f"were observed within the same AWS account in the review window. "
        f"{_AWS_VPC_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": _AWS_VPC_FLOW_SOURCE,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": anchor.event_type,
        "security_group_id": sg_id if isinstance(sg_id, str) else None,
        "dst_port": dst_port,
        "port_category": ev_evidence.get("port_category")
        if isinstance(ev_evidence.get("port_category"), str) else None,
        "interface_id": interface,
        "protocol": md.get("protocol") if isinstance(md.get("protocol"), int) else None,
        "flow_action": md.get("action") if isinstance(md.get("action"), str) else None,
        "event_count": len(matched),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_AWS,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        "confidence": confidence,
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": anchor.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def generate_aws_sg_vpc_flow_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 5000,
) -> dict[str, Any]:
    """Correlate active AWS SG exposure findings with VPC Flow Log activity.

    Conservative + account-scoped: a finding only matches VPC flow events from
    the SAME integration (same AWS account/region) whose destination port falls
    within the SG rule's exposed port range AND within the review window. One
    correlation per (finding, port_category, action_category), anchored to a
    deterministic representative event. Idempotent.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_AWS,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings
        if _base_rule(f.finding_key) in _AWS_SG_EXPOSURE_RULES
    ]

    flow_events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_AWS,
            SecurityActivityEvent.source == _AWS_VPC_FLOW_SOURCE,
            SecurityActivityEvent.event_type.in_((_AWS_FLOW_ACCEPT, _AWS_FLOW_REJECT)),
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Only index events that carry a valid dst_port (never correlate portless flows).
    flows_by_integ_type: dict[Any, list[SecurityActivityEvent]] = {}
    for ev in flow_events:
        if ev.integration_id is not None and _flow_dst_port(ev) is not None:
            key = (ev.integration_id, ev.event_type)
            flows_by_integ_type.setdefault(key, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.integration_id is None:
            continue  # no account scope to match on
        base = _base_rule(finding.finding_key)
        ev_evidence = _sg_finding_evidence(finding)
        target_port_sets = _SG_RULE_PORT_SETS.get(base, [])
        if not target_port_sets:
            continue

        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        # ACCEPT correlations (one per sensitive port set).
        for port_set in target_port_sets:
            rule = _SG_PORT_SET_TO_RULE[id(port_set)]
            candidates = flows_by_integ_type.get(
                (finding.integration_id, _AWS_FLOW_ACCEPT), []
            )
            matched: list[SecurityActivityEvent] = []
            for ev in candidates:
                dst = _flow_dst_port(ev)
                if dst is None or dst not in port_set:
                    continue
                if not _port_in_sg_range(dst, ev_evidence):
                    continue
                occ = _aware(ev.occurred_at)
                if occ is None or not (window_start <= occ <= window_end):
                    continue
                matched.append(ev)
            if not matched:
                continue
            anchor = _aws_vpc_flow_anchor(matched)
            correlation = build_aws_sg_vpc_flow_correlation(
                finding=finding, anchor=anchor, matched=matched, rule=rule,
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

        # REJECT correlation — all exposed sensitive ports, threshold-gated.
        all_exposed_ports: frozenset[int] = frozenset().union(*target_port_sets)
        reject_candidates = flows_by_integ_type.get(
            (finding.integration_id, _AWS_FLOW_REJECT), []
        )
        reject_matched: list[SecurityActivityEvent] = []
        for ev in reject_candidates:
            dst = _flow_dst_port(ev)
            if dst is None or dst not in all_exposed_ports:
                continue
            if not _port_in_sg_range(dst, ev_evidence):
                continue
            occ = _aware(ev.occurred_at)
            if occ is None or not (window_start <= occ <= window_end):
                continue
            reject_matched.append(ev)
        if len(reject_matched) >= _SG_REJECT_THRESHOLD:
            anchor = _aws_vpc_flow_anchor(reject_matched)
            correlation = build_aws_sg_vpc_flow_correlation(
                finding=finding, anchor=anchor, matched=reject_matched,
                rule=_SG_REJECT_RULE,
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_AWS,
        "findings_scanned": len(findings),
        "events_scanned": len(flow_events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ---------------------------------------------------------------------------
# AWS IAM risk × privilege-chain correlations (M69.3B)
# ---------------------------------------------------------------------------
#
# AWS IAM Configuration Risk findings (``aws_iam_admin_policy_attached`` /
# ``aws_access_key_unused`` from ``security_rules/aws.py``) are correlated with
# M69.3A IAM privilege-chain Incident Signals (``signal_type=
# "aws_iam_privilege_chain"``) when BOTH reference the SAME IAM target entity
# (user/role name) within the finding's review window AND share the same
# integration (same AWS account/region).
#
# JOIN KEY:
#   * same ``integration_id`` (same AWS account/region scope), AND
#   * finding's ``evidence["principal_name"]`` (rule A) or ``evidence["username"]``
#     (rule B), normalized via ``_norm_resource``, matches the chain signal's
#     ``signal_metadata["target_user"]`` / ``signal_metadata["target_role"]`` /
#     ``signal_metadata["resource_name"]`` (already normalized in M69.3A), AND
#   * review window overlap.
#
# ANCHOR: the chain signal's ``linked_activity_event_id`` is used as the
# correlation's activity anchor (the deterministic CloudTrail event from the
# chain). This reuses the existing ``upsert_correlation`` infrastructure and
# gives the correlation a traceable, concrete activity-event link.
#
# CLAIM DISCIPLINE: these are EVIDENCE FOR REVIEW. They NEVER assert compromise,
# unauthorized access, a successful privilege escalation, or an attacker.
#
# PRIVACY: only safe aggregate identifiers are stored (IAM entity names,
# chain_pattern, source_signal_type, event_count, window). NEVER access key
# values, secret keys, session tokens, requestParameters, responseElements,
# raw IPs, user agents, raw CloudTrail JSON, or credentials.

_AWS_IAM_CHAIN_SIGNAL_TYPE = "aws_iam_privilege_chain"

# Map finding base rule → (evidence entity key, chain_pattern filter, rule descriptor).
_AWS_IAM_ADMIN_CHAIN_RULE = {
    "correlation_key": "aws_iam_admin_risk_privilege_chain",
    "correlation_type": "aws_iam_admin_risk_privilege_chain",
    "phrase": "IAM admin-risk aligned with privilege-chain activity",
    "subject": "An AWS IAM admin-policy configuration risk",
    "chain_patterns": None,  # any chain pattern
}
_AWS_IAM_KEY_CHAIN_RULE = {
    "correlation_key": "aws_iam_access_key_risk_privilege_chain",
    "correlation_type": "aws_iam_access_key_risk_privilege_chain",
    "phrase": "IAM access-key risk aligned with access-key creation chain",
    "subject": "An AWS IAM access-key configuration risk",
    "chain_patterns": frozenset({"privilege_grant_access_key"}),
}

_AWS_IAM_CHAIN_FINDING_RULES: dict[str, tuple[str, dict[str, Any]]] = {
    "aws_iam_admin_policy_attached": ("principal_name", _AWS_IAM_ADMIN_CHAIN_RULE),
    "aws_access_key_unused": ("username", _AWS_IAM_KEY_CHAIN_RULE),
}

_AWS_IAM_CHAIN_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm compromise or "
    "unauthorized access."
)


def _iam_signal_targets(sig_md: dict[str, Any]) -> set[str]:
    """Return the set of normalized entity names a chain signal targets."""
    out: set[str] = set()
    for k in ("target_user", "target_role", "resource_name"):
        v = sig_md.get(k)
        n = _norm_resource(v)
        if n:
            out.add(n)
    return out


def build_aws_iam_chain_correlation(
    *,
    finding: SecurityFinding,
    signal: SecurityIncidentSignal,
    rule: dict[str, Any],
) -> Optional[dict[str, Any]]:
    """Build an IAM risk × chain correlation dict (not persisted)."""
    anchor_ev_id = signal.linked_activity_event_id
    if anchor_ev_id is None:
        return None  # no anchor → cannot build a valid correlation

    _valid_sev = {"critical", "high", "medium", "low", "info"}
    severity = finding.severity if finding.severity in _valid_sev else "high"

    sig_md = signal.signal_metadata if isinstance(signal.signal_metadata, dict) else {}
    chain_pattern = sig_md.get("chain_pattern")
    target_user = sig_md.get("target_user")
    target_role = sig_md.get("target_role")
    resource_name = sig_md.get("resource_name")
    entity_label = target_user or target_role or resource_name or "an IAM entity"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    sig_time = _aware(signal.last_seen_at) or _aware(signal.first_seen_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, sig_time) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, sig_time) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['phrase']} ({entity_label})"
    summary = (
        f"{rule['subject']} (\"{finding.title}\") and IAM privilege-chain activity "
        f"(\"{signal.title}\") were observed for the same IAM target entity "
        f"\"{entity_label}\" within the review window. {_AWS_IAM_CHAIN_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": "cloudtrail",
        "source_signal_type": _AWS_IAM_CHAIN_SIGNAL_TYPE,
        "chain_pattern": chain_pattern,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": "aws_iam_privilege_chain",
        "target_user": target_user,
        "target_role": target_role,
        "resource_id": resource_name,
        "event_count": sig_md.get("chain_steps"),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_AWS,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        # Same IAM account + matching entity name + chain signal is strong
        # circumstantial evidence — calibrated to "high" (same entity match,
        # not just account-level).
        "confidence": "high",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": anchor_ev_id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        "_integration_id": finding.integration_id,
    }


def generate_aws_iam_chain_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 2000,
) -> dict[str, Any]:
    """Correlate active AWS IAM risk findings with IAM privilege-chain signals.

    Conservative + entity-matched: a finding only matches a chain signal whose
    target IAM entity (target_user / target_role / resource_name, normalized)
    matches the finding's evidence entity (principal_name / username, normalized)
    AND shares the same integration (same AWS account/region), within the
    finding's review window. Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_AWS,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings
        if _base_rule(f.finding_key) in _AWS_IAM_CHAIN_FINDING_RULES
    ]

    chain_signals = (
        db.query(SecurityIncidentSignal)
        .filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            SecurityIncidentSignal.provider == PROVIDER_AWS,
            SecurityIncidentSignal.signal_type == _AWS_IAM_CHAIN_SIGNAL_TYPE,
            SecurityIncidentSignal.linked_activity_event_id.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Index chain signals by (integration_id, normalized_target_entity) for
    # cheap exact lookup. A signal may appear under multiple keys if it has
    # both target_user and resource_name set.
    signals_by_integ_entity: dict[tuple, list[SecurityIncidentSignal]] = {}
    for sig in chain_signals:
        sig_md = sig.signal_metadata if isinstance(sig.signal_metadata, dict) else {}
        targets = _iam_signal_targets(sig_md)
        for entity in targets:
            key = (sig.integration_id, entity)
            signals_by_integ_entity.setdefault(key, []).append(sig)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.integration_id is None:
            continue
        base = _base_rule(finding.finding_key)
        evidence_key, rule = _AWS_IAM_CHAIN_FINDING_RULES[base]
        ev = finding.evidence if isinstance(finding.evidence, dict) else {}
        raw_entity = ev.get(evidence_key)
        entity = _norm_resource(raw_entity)
        if not entity:
            continue  # no safe entity to match on

        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW
        chain_patterns = rule.get("chain_patterns")

        for sig in signals_by_integ_entity.get((finding.integration_id, entity), []):
            # Chain pattern filter (None = all patterns accepted).
            if chain_patterns is not None:
                sig_md = sig.signal_metadata if isinstance(sig.signal_metadata, dict) else {}
                if sig_md.get("chain_pattern") not in chain_patterns:
                    continue
            # Window gate: signal must have been active within the review window.
            sig_time = _aware(sig.last_seen_at) or _aware(sig.first_seen_at)
            if sig_time is None or not (window_start <= sig_time <= window_end):
                continue
            correlation = build_aws_iam_chain_correlation(
                finding=finding, signal=sig, rule=rule,
            )
            if correlation is None:
                continue
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_AWS,
        "findings_scanned": len(findings),
        "events_scanned": len(chain_signals),  # signals scanned (schema compat)
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


def generate_aws_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Generate ALL AWS correlations for a workspace (M67.3 + M69.2A + M69.2B + M69.3B).

    provider=aws now generates:
      * Configuration Risk × provider alerts (GuardDuty / Access Analyzer), and
      * S3 public-exposure risk × S3 object-level activity (GetObject / ListBucket
        / object-access spike), and
      * SG public-exposure risk × VPC Flow Log network activity (accepted and
        rejected flows to admin/datastore ports), and
      * IAM configuration risk × IAM privilege-chain signals (entity-matched,
        same AWS account, within review window).
    The returned summary sums all four passes. Idempotent.
    """
    alerts = _generate_aws_alert_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    s3 = generate_aws_s3_exposure_activity_correlations(
        workspace_id=workspace_id, db=db
    )
    sg_vpc = generate_aws_sg_vpc_flow_correlations(
        workspace_id=workspace_id, db=db
    )
    iam_chain = generate_aws_iam_chain_correlations(
        workspace_id=workspace_id, db=db
    )
    return {
        "provider": PROVIDER_AWS,
        "findings_scanned": (
            alerts["findings_scanned"] + s3["findings_scanned"]
            + sg_vpc["findings_scanned"] + iam_chain["findings_scanned"]
        ),
        "events_scanned": (
            alerts["events_scanned"] + s3["events_scanned"]
            + sg_vpc["events_scanned"] + iam_chain["events_scanned"]
        ),
        "correlations_created": (
            alerts["correlations_created"] + s3["correlations_created"]
            + sg_vpc["correlations_created"] + iam_chain["correlations_created"]
        ),
        "correlations_skipped": (
            alerts["correlations_skipped"] + s3["correlations_skipped"]
            + sg_vpc["correlations_skipped"] + iam_chain["correlations_skipped"]
        ),
    }


# ───────────────────────────────────────────────────────────────────────────────
# Cloudflare correlations (M68.2)
# ───────────────────────────────────────────────────────────────────────────────
#
# Cloudflare Configuration Risk findings (``security_findings`` provider=cloudflare,
# produced by ``security_rules/cloudflare.py``) are correlated with Cloudflare
# audit activity (``security_activity_events`` provider=cloudflare, source=
# "audit_log" — ingested in M68.1) ONLY when they share the SAME zone AND the SAME
# logical risk area within the finding's review window.
#
# ZONE MATCH: a Cloudflare integration is ZONE-SCOPED (one ``zone_id`` per
# credential), so a finding and an audit event that share the same
# ``integration_id`` are guaranteed to be the same zone — used here as the
# decryption-free zone gate. The event's zone_id/zone_name are stored for evidence.
#
# RISK-AREA GATE (avoids vague matching): a finding only correlates with audit
# events whose ``event_type`` is in the finding's risk area. Same zone is NOT
# enough — a TLS finding never matches a DNS event, etc.
#
# Safely matchable today (the config-risk finding rule exists):
#   * DNS  : cloudflare_dns_private_origin       ↔ cloudflare.dns_record.changed
#   * WAF  : cloudflare_waf_rule_disabled        ↔ cloudflare.waf_rule.changed
#   * TLS  : cloudflare_ssl_mode_weak /
#            cloudflare_always_https_off /
#            cloudflare_min_tls_weak             ↔ cloudflare.ssl_tls.changed
#
# DEFERRED (reported, never faked):
#   * Access policy (Candidate D) and API-token (Candidate E): NO Cloudflare
#     config-risk finding rule exists today (only drift classifiers), so there is
#     nothing to match against.
#   * cloudflare_hsts_disabled / _security_level_low / _development_mode_on: their
#     audit change is the GENERIC ``cloudflare.zone_setting.changed`` event, whose
#     event_type does not identify the specific setting — matching it would risk
#     cross-setting false positives, so these are intentionally not correlated.

_CF_DNS_RULE = {
    "correlation_key": "cloudflare_dns_risk_activity",
    "correlation_type": "cloudflare_dns_change",
    "event_types": frozenset({"cloudflare.dns_record.changed"}),
    "phrase": "Cloudflare DNS risk aligned with DNS audit activity",
    "area": "DNS",
}
_CF_WAF_RULE = {
    "correlation_key": "cloudflare_waf_risk_activity",
    "correlation_type": "cloudflare_waf_change",
    "event_types": frozenset({"cloudflare.waf_rule.changed"}),
    "phrase": "Cloudflare WAF risk aligned with WAF audit activity",
    "area": "WAF",
}
_CF_TLS_RULE = {
    "correlation_key": "cloudflare_tls_risk_activity",
    "correlation_type": "cloudflare_tls_change",
    "event_types": frozenset({"cloudflare.ssl_tls.changed"}),
    "phrase": "Cloudflare TLS risk aligned with SSL/TLS audit activity",
    "area": "TLS",
}
# M68.3 — Access-policy risk ↔ Access audit activity (Candidate D, now unlocked).
_CF_ACCESS_RULE = {
    "correlation_key": "cloudflare_access_risk_activity",
    "correlation_type": "cloudflare_access_policy_change",
    "event_types": frozenset({"cloudflare.access_policy.changed"}),
    "phrase": "Cloudflare Access policy risk aligned with Access audit activity",
    "area": "ACCESS",
}
# M68.3 — zone-setting risk ↔ zone-setting audit activity, gated on an EXACT
# setting-name match (never a generic zone_setting.changed correlation).
_CF_ZONE_RULE = {
    "correlation_key": "cloudflare_zone_setting_risk_activity",
    "correlation_type": "cloudflare_zone_setting_change",
    "event_types": frozenset({"cloudflare.zone_setting.changed"}),
    "phrase": "Cloudflare zone-setting risk aligned with zone-setting audit activity",
    "area": "ZONE_SETTING",
    "match_setting": True,
}

# finding base rule → correlation rule descriptor.
CLOUDFLARE_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "cloudflare_dns_private_origin": _CF_DNS_RULE,
    "cloudflare_waf_rule_disabled": _CF_WAF_RULE,
    "cloudflare_ssl_mode_weak": _CF_TLS_RULE,
    "cloudflare_always_https_off": _CF_TLS_RULE,
    "cloudflare_min_tls_weak": _CF_TLS_RULE,
    # M68.3 — Access policy risks.
    "cloudflare_access_policy_bypass": _CF_ACCESS_RULE,
    "cloudflare_access_policy_disabled": _CF_ACCESS_RULE,
    # M68.3 — zone-setting risks (exact setting-name gate).
    "cloudflare_hsts_disabled": _CF_ZONE_RULE,
    "cloudflare_security_level_low": _CF_ZONE_RULE,
    "cloudflare_development_mode_on": _CF_ZONE_RULE,
}

# finding base rule → expected Cloudflare zone-setting key (for the exact gate).
_CF_FINDING_SETTING: dict[str, str] = {
    "cloudflare_hsts_disabled": "security_header",
    "cloudflare_security_level_low": "security_level",
    "cloudflare_development_mode_on": "development_mode",
}


def _cf_finding_setting(finding: SecurityFinding) -> Optional[str]:
    """The Cloudflare zone-setting key a finding refers to (rule map → evidence)."""
    base = _base_rule(finding.finding_key)
    expected = _CF_FINDING_SETTING.get(base)
    if expected:
        return expected
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    s = ev.get("setting")
    return s if isinstance(s, str) and s else None

_CF_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def build_cloudflare_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a Cloudflare correlation dict (not persisted) from a matched pair."""
    severity = finding.severity if finding.severity in _CF_SEVERITIES else "medium"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    meta = event.event_metadata if isinstance(event.event_metadata, dict) else {}
    zone = meta.get("zone_name") or meta.get("zone_id")

    title = rule["phrase"]
    if isinstance(zone, str) and zone:
        title = f"{rule['phrase']} ({zone})"
    summary = (
        f"A Cloudflare configuration risk (\"{finding.title}\") and related audit "
        f"activity (\"{event.event_type}\") were observed for the same zone/resource "
        f"within the review window. {_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": event.event_type,
        "action": meta.get("action") if isinstance(meta.get("action"), str) else None,
        "actor": meta.get("actor") if isinstance(meta.get("actor"), str) else None,
        "zone_id": meta.get("zone_id") if isinstance(meta.get("zone_id"), str) else None,
        "zone_name": meta.get("zone_name") if isinstance(meta.get("zone_name"), str) else None,
        "setting_name": meta.get("setting_name") if isinstance(meta.get("setting_name"), str) else None,
        "policy_name": meta.get("policy_name") if isinstance(meta.get("policy_name"), str) else None,
        "resource_type": event.resource_type if isinstance(event.resource_type, str) else None,
        "resource_id": event.resource_id if isinstance(event.resource_id, str) else None,
        "account_id": meta.get("account_id") if isinstance(meta.get("account_id"), str) else None,
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        # Same zone + same risk area + window is circumstantial co-occurrence,
        # not an exact-rule match — calibrated to "medium".
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def _generate_cloudflare_audit_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active Cloudflare findings with Cloudflare audit activity.

    Conservative: a finding only matches an audit event from the SAME integration
    (= same zone-scoped credential), in the SAME risk area, within the finding's
    review window. Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_CLOUDFLARE,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in CLOUDFLARE_CORRELATION_RULES
    ]

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_CLOUDFLARE,
            SecurityActivityEvent.source == "audit_log",
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Index audit events by integration (the zone-scoped credential).
    events_by_integ: dict[Any, list[SecurityActivityEvent]] = {}
    for ev in events:
        if ev.integration_id is not None:
            events_by_integ.setdefault(ev.integration_id, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.integration_id is None:
            continue  # no zone scope to match on
        rule = CLOUDFLARE_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        finding_setting = _cf_finding_setting(finding) if rule.get("match_setting") else None
        for ev in events_by_integ.get(finding.integration_id, []):
            if ev.event_type not in rule["event_types"]:
                continue  # risk-area gate — never cross areas
            # Exact setting gate: zone-setting correlations only fire when the
            # audit event's setting_name matches the finding's setting key.
            if rule.get("match_setting"):
                ev_meta = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
                ev_setting = ev_meta.get("setting_name")
                if not finding_setting or ev_setting != finding_setting:
                    continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            correlation = build_cloudflare_correlation(
                finding=finding, event=ev, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ───────────────────────────────────────────────────────────────────────────────
# Cloudflare WAF / security-event correlations (M68.6)
# ───────────────────────────────────────────────────────────────────────────────
#
# Cloudflare Configuration Risk findings (``security_findings`` provider=cloudflare,
# from ``security_rules/cloudflare.py``) are correlated with Cloudflare WAF /
# security activity (``security_activity_events`` provider=cloudflare, source=
# "waf_security_event" — ingested in M68.4) ONLY when they share the SAME zone AND
# a relevant, NON-VAGUE join key for the finding's risk area, within the review
# window.
#
# ZONE GATE: a Cloudflare integration is zone-scoped (one ``zone_id`` per
# credential), so a finding + WAF event with the SAME ``integration_id`` are the
# same zone — the decryption-free zone gate (as in M68.2).
#
# JOIN KEY by risk area (this is what makes a correlation specific, not vague):
#   * WAF rule disabled            → same zone + WAF/security event activity
#                                     (confidence raised when the event's ruleset
#                                     id aligns with the finding's evidence).
#   * zone security setting risk   → same zone + the event carries HOST evidence.
#   * DNS private-origin risk       → the event HOST must equal the finding's DNS
#                                     hostname (never same-zone-only).
#   * Access policy risk            → same zone + the event's ``path_prefix`` is a
#                                     sensitive prefix (admin/login/…); this is
#                                     "security activity on a sensitive path",
#                                     NOT a claim that any endpoint was accessed.
#   * TLS/HTTPS setting risk        → same zone + the event carries HOST evidence;
#                                     weaker evidence, so confidence is low.
#
# CLAIM DISCIPLINE: a correlation is EVIDENCE FOR REVIEW. It NEVER asserts a
# breach, attacker, compromise, exploit, or unauthorized access — only that a
# configuration risk and WAF/security activity co-occurred for the same
# zone/host/risk-area and may require review.
#
# OUTPUT SHAPE: one correlation per (finding, rule), anchored to a deterministic
# representative event, with ``event_count`` carried as a safe aggregate — so the
# correlation count is bounded by the number of findings, never the (large) WAF
# event volume.
#
# PRIVACY: only allowlisted, flat, safe aggregate fields are stored. The raw IP
# (hashed), raw URL/path (hashed; only a sanitized prefix), query string, headers,
# cookies, bodies, tokens, secrets, sessions, and raw GraphQL JSON are NEVER read.

_CF_WAF_SOURCE = "waf_security_event"

_CF_WAF_BLOCK = "cloudflare.waf_event.block"
_CF_WAF_CHALLENGES = frozenset({
    "cloudflare.waf_event.challenge",
    "cloudflare.waf_event.managed_challenge",
    "cloudflare.waf_event.js_challenge",
})
# "Security" events = block + any challenge (the protective-action family).
_CF_WAF_SECURITY = frozenset({_CF_WAF_BLOCK}) | _CF_WAF_CHALLENGES
_CF_WAF_LOG = "cloudflare.waf_event.log"
# The 7 concrete WAF actions (excludes the unmapped ``.event`` fallback).
_CF_WAF_ANY = _CF_WAF_SECURITY | frozenset({
    _CF_WAF_LOG, "cloudflare.waf_event.skip", "cloudflare.waf_event.allow",
})
# DNS / Access activity = security family + log (a request that was acted on).
_CF_WAF_SECURITY_OR_LOG = _CF_WAF_SECURITY | frozenset({_CF_WAF_LOG})

# Sensitive path prefixes for Access-policy correlations.
_CF_SENSITIVE_PREFIXES = frozenset({
    "admin", "login", "dashboard", "account", "auth", "api",
})

# Deterministic anchor rank — block first, then challenges, then log/skip/allow.
_CF_WAF_ANCHOR_RANK: dict[str, int] = {
    _CF_WAF_BLOCK: 60,
    "cloudflare.waf_event.managed_challenge": 52,
    "cloudflare.waf_event.challenge": 50,
    "cloudflare.waf_event.js_challenge": 48,
    _CF_WAF_LOG: 40,
    "cloudflare.waf_event.skip": 30,
    "cloudflare.waf_event.allow": 28,
    "cloudflare.waf_event.event": 20,
}

# Match modes.
_MATCH_ZONE = "zone"                 # same zone + relevant WAF activity
_MATCH_ZONE_HOST = "zone_host"       # same zone + event carries host evidence
_MATCH_HOST = "host"                 # event host == finding hostname
_MATCH_SENSITIVE_PATH = "sensitive"  # same zone + event path_prefix sensitive

_CF_WAF_DISABLED_RULE = {
    "correlation_key": "cloudflare_waf_risk_activity",
    "correlation_type": "cloudflare_waf_risk_activity",
    "event_types": _CF_WAF_ANY,
    "match": _MATCH_ZONE,
    "confidence": "medium",
    "phrase": "Cloudflare WAF risk aligned with WAF/security activity",
    "subject": "A Cloudflare WAF configuration risk",
    # block/challenge activity raises review priority; ruleset alignment raises
    # confidence (handled in the builder).
    "boost_severity_on_security": True,
    "boost_confidence_on_ruleset": True,
}
_CF_ZONE_SECURITY_RULE = {
    "correlation_key": "cloudflare_zone_security_activity",
    "correlation_type": "cloudflare_zone_security_activity",
    "event_types": _CF_WAF_ANY,
    "match": _MATCH_ZONE_HOST,
    "confidence": "medium",
    "phrase": "Cloudflare zone security setting risk aligned with WAF/security activity",
    "subject": "A Cloudflare zone security-setting risk",
}
_CF_DNS_ORIGIN_RULE = {
    "correlation_key": "cloudflare_dns_origin_activity",
    "correlation_type": "cloudflare_dns_origin_activity",
    "event_types": _CF_WAF_SECURITY_OR_LOG,
    "match": _MATCH_HOST,
    "confidence": "medium",
    "phrase": "Cloudflare DNS origin risk aligned with WAF/security activity",
    "subject": "A Cloudflare DNS origin risk",
}
_CF_ACCESS_ACTIVITY_RULE = {
    "correlation_key": "cloudflare_access_policy_activity",
    "correlation_type": "cloudflare_access_policy_activity",
    "event_types": _CF_WAF_SECURITY_OR_LOG,
    "match": _MATCH_SENSITIVE_PATH,
    "confidence": "medium",
    "phrase": "Cloudflare Access policy risk aligned with security activity on sensitive path",
    "subject": "A Cloudflare Access policy risk",
    # Discipline: report sensitive-path activity, never claim access occurred.
    "sensitive_path_note": True,
}
_CF_TLS_ACTIVITY_RULE = {
    "correlation_key": "cloudflare_tls_activity",
    "correlation_type": "cloudflare_tls_activity",
    "event_types": _CF_WAF_ANY,
    "match": _MATCH_ZONE_HOST,
    # Weaker evidence than WAF/DNS/Access — a TLS setting is zone-scoped with no
    # host to match against, so confidence stays low.
    "confidence": "low",
    "phrase": "Cloudflare TLS/HTTPS risk aligned with WAF/security activity",
    "subject": "A Cloudflare TLS/HTTPS risk",
}

# finding base rule → WAF correlation rule descriptor.
CLOUDFLARE_WAF_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "cloudflare_waf_rule_disabled": _CF_WAF_DISABLED_RULE,
    "cloudflare_security_level_low": _CF_ZONE_SECURITY_RULE,
    "cloudflare_development_mode_on": _CF_ZONE_SECURITY_RULE,
    "cloudflare_dns_private_origin": _CF_DNS_ORIGIN_RULE,
    "cloudflare_access_policy_bypass": _CF_ACCESS_ACTIVITY_RULE,
    "cloudflare_access_policy_disabled": _CF_ACCESS_ACTIVITY_RULE,
    "cloudflare_ssl_mode_weak": _CF_TLS_ACTIVITY_RULE,
    "cloudflare_always_https_off": _CF_TLS_ACTIVITY_RULE,
    "cloudflare_min_tls_weak": _CF_TLS_ACTIVITY_RULE,
    "cloudflare_hsts_disabled": _CF_TLS_ACTIVITY_RULE,
}


def _norm_host(value: Any) -> Optional[str]:
    """Normalize a hostname to a comparable form, or None for empty/non-string."""
    if not isinstance(value, str):
        return None
    s = value.strip().lower().rstrip(".")
    return s or None


def _cf_finding_host(finding: SecurityFinding) -> Optional[str]:
    """The DNS hostname a finding refers to (from its evidence ``name``)."""
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    return _norm_host(ev.get("name"))


def _cf_waf_event_matches(
    rule: dict[str, Any],
    ev: SecurityActivityEvent,
    finding_host: Optional[str],
) -> bool:
    """Return True if a WAF event satisfies the rule's risk-area join key."""
    if ev.event_type not in rule["event_types"]:
        return False
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    host = _norm_host(md.get("host"))
    mode = rule["match"]
    if mode == _MATCH_ZONE:
        return True  # zone gate already applied by caller; risk area = WAF
    if mode == _MATCH_ZONE_HOST:
        return host is not None  # require concrete host evidence (not vague)
    if mode == _MATCH_HOST:
        return finding_host is not None and host is not None and host == finding_host
    if mode == _MATCH_SENSITIVE_PATH:
        pfx = md.get("path_prefix")
        return isinstance(pfx, str) and pfx.lower() in _CF_SENSITIVE_PREFIXES
    return False


def _cf_waf_anchor(events: list[SecurityActivityEvent]) -> SecurityActivityEvent:
    """Deterministically pick the representative event (rank, then time, then id)."""
    return max(
        events,
        key=lambda e: (
            _CF_WAF_ANCHOR_RANK.get(e.event_type, 0),
            _aware(e.occurred_at) or _aware(e.ingested_at) or datetime.min.replace(tzinfo=timezone.utc),
            str(e.provider_event_id or ""),
        ),
    )


def build_cloudflare_waf_correlation(
    *,
    finding: SecurityFinding,
    anchor: SecurityActivityEvent,
    matched: list[SecurityActivityEvent],
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a Cloudflare WAF/security correlation dict (not persisted)."""
    severity = finding.severity if finding.severity in _CF_SEVERITIES else "medium"
    if rule.get("boost_severity_on_security") and (
        finding.severity in _HIGH_SEVERITIES or anchor.event_type in _CF_WAF_SECURITY
    ):
        severity = "high"

    md = anchor.event_metadata if isinstance(anchor.event_metadata, dict) else {}
    host = _norm_host(md.get("host"))

    confidence = rule["confidence"]
    if rule.get("boost_confidence_on_ruleset"):
        f_ev = finding.evidence if isinstance(finding.evidence, dict) else {}
        f_ruleset = f_ev.get("ruleset_id")
        e_ruleset = md.get("ruleset_id")
        if (
            isinstance(f_ruleset, str) and f_ruleset
            and isinstance(e_ruleset, str) and e_ruleset
            and f_ruleset == e_ruleset
        ):
            confidence = "high"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(anchor.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None

    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    label = host or md.get("zone_name") or md.get("zone_id") or "a Cloudflare zone"
    title = f"{rule['phrase']} ({label})"

    scope = "host" if rule["match"] == _MATCH_HOST else "zone"
    extra = ""
    if rule.get("sensitive_path_note"):
        extra = (
            " This reflects security activity on a sensitive path prefix and does "
            "not indicate that any endpoint was accessed."
        )
    summary = (
        f"{rule['subject']} (\"{finding.title}\") and related Cloudflare WAF/security "
        f"activity (\"{anchor.event_type}\") were observed for the same {scope} within "
        f"the review window.{extra} {_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": _CF_WAF_SOURCE,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": anchor.event_type,
        "action": md.get("action") if isinstance(md.get("action"), str) else None,
        "zone_id": md.get("zone_id") if isinstance(md.get("zone_id"), str) else None,
        "zone_name": md.get("zone_name") if isinstance(md.get("zone_name"), str) else None,
        "host": host,
        "rule_id": md.get("rule_id") if isinstance(md.get("rule_id"), str) else None,
        "rule_name": md.get("rule_name") if isinstance(md.get("rule_name"), str) else None,
        "path_prefix": md.get("path_prefix") if isinstance(md.get("path_prefix"), str) else None,
        "event_count": len(matched),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "correlation_key": rule["correlation_key"],
        "correlation_type": rule["correlation_type"],
        "severity": severity,
        "confidence": confidence,
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": anchor.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        # carried for signal creation (not a column):
        "_integration_id": finding.integration_id,
    }


def generate_cloudflare_waf_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 2000,
) -> dict[str, Any]:
    """Correlate active Cloudflare findings with Cloudflare WAF/security activity.

    Conservative + non-vague: each finding only matches WAF events from the SAME
    zone-scoped integration that satisfy the finding's risk-area join key (host
    match for DNS, sensitive-path for Access, host-present for zone/TLS settings),
    within the review window. One correlation per (finding, rule), anchored to a
    deterministic representative event. Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_CLOUDFLARE,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings
        if _base_rule(f.finding_key) in CLOUDFLARE_WAF_CORRELATION_RULES
    ]

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_CLOUDFLARE,
            SecurityActivityEvent.source == _CF_WAF_SOURCE,
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    events_by_integ: dict[Any, list[SecurityActivityEvent]] = {}
    for ev in events:
        if ev.integration_id is not None:
            events_by_integ.setdefault(ev.integration_id, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.integration_id is None:
            continue  # no zone scope to match on
        rule = CLOUDFLARE_WAF_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW
        finding_host = _cf_finding_host(finding) if rule["match"] == _MATCH_HOST else None
        if rule["match"] == _MATCH_HOST and finding_host is None:
            continue  # DNS rule needs a hostname to match — never same-zone-only

        matched = []
        for ev in events_by_integ.get(finding.integration_id, []):
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            if not _cf_waf_event_matches(rule, ev, finding_host):
                continue
            matched.append(ev)
        if not matched:
            continue

        anchor = _cf_waf_anchor(matched)
        correlation = build_cloudflare_waf_correlation(
            finding=finding, anchor=anchor, matched=matched, rule=rule
        )
        outcome, _row = upsert_correlation(
            workspace_id=workspace_id, correlation=correlation, db=db
        )
        if outcome == "created":
            created += 1
        else:
            skipped += 1

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


def generate_cloudflare_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Generate ALL Cloudflare correlations for a workspace (M68.2/68.3 + M68.6).

    provider=cloudflare now generates BOTH:
      * Configuration Risk × audit activity (DNS/WAF/TLS/Access/zone-setting), and
      * Configuration Risk × WAF/security-event activity.
    The returned summary sums both passes. Idempotent.
    """
    audit = _generate_cloudflare_audit_correlations(
        workspace_id=workspace_id, db=db, scan_limit=scan_limit
    )
    waf = generate_cloudflare_waf_correlations(
        workspace_id=workspace_id, db=db
    )
    return {
        "provider": PROVIDER_CLOUDFLARE,
        "findings_scanned": audit["findings_scanned"] + waf["findings_scanned"],
        "events_scanned": audit["events_scanned"] + waf["events_scanned"],
        "correlations_created": audit["correlations_created"] + waf["correlations_created"],
        "correlations_skipped": audit["correlations_skipped"] + waf["correlations_skipped"],
    }


# ── M70D — Vercel configuration-risk × activity correlations ─────────────────
#
# Correlates an ACTIVE Vercel configuration-risk finding with Vercel audit
# activity (source="audit_log") for the SAME project, when an aligned activity
# event falls inside the finding's review window
# (first_detected_at - 24h .. last_seen_at + 24h). Project identity is the
# finding's Resource.provider_resource_id (the Vercel project id/slug — all
# Vercel records for one project share that resource), matched against the
# event's metadata project_id / project_name. This is evidence for review; it
# never asserts a secret was exposed, that anyone gained access, that access was
# unauthorized, or that a breach/attack occurred.

# finding base rule → correlation rule definition.
#   activity_types: the Vercel event_type strings that count as aligned evidence.
VERCEL_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "vercel_production_branch_missing": {
        "correlation_type": "vercel_project_branch_activity",
        "activity_types": {"vercel.project.updated"},
        "severity": "medium",
        "title": "Vercel production branch risk aligned with project activity",
        "subject": "Vercel production branch risk",
        "evidence_phrase": "project activity",
    },
    "vercel_production_branch_unusual": {
        "correlation_type": "vercel_project_branch_activity",
        "activity_types": {"vercel.project.updated"},
        "severity": "medium",
        "title": "Vercel production branch risk aligned with project activity",
        "subject": "Vercel production branch risk",
        "evidence_phrase": "project activity",
    },
    "vercel_domain_unverified": {
        "correlation_type": "vercel_domain_risk_activity",
        "activity_types": {"vercel.domain.added", "vercel.domain.removed"},
        "severity": "medium",
        "title": "Vercel domain risk aligned with domain activity",
        "subject": "Vercel domain risk",
        "evidence_phrase": "domain activity",
    },
    "vercel_env_var_broad_target": {
        "correlation_type": "vercel_env_var_risk_activity",
        "activity_types": {
            "vercel.env_var.created", "vercel.env_var.updated", "vercel.env_var.deleted",
        },
        "severity": "medium",
        "title": "Vercel environment variable risk aligned with environment activity",
        "subject": "Vercel environment variable risk",
        "evidence_phrase": "environment variable activity",
    },
    "vercel_sensitive_env_var_broad_scope": {
        "correlation_type": "vercel_env_var_risk_activity",
        "activity_types": {
            "vercel.env_var.created", "vercel.env_var.updated", "vercel.env_var.deleted",
        },
        # A secret-suggestive env var risk aligned with env activity is higher
        # review priority (the value itself is never read or stored).
        "severity": "high",
        "title": "Vercel environment variable risk aligned with environment activity",
        "subject": "Vercel sensitive environment variable risk",
        "evidence_phrase": "environment variable activity",
    },
    "vercel_deploy_hook_production_branch": {
        "correlation_type": "vercel_deploy_hook_risk_activity",
        "activity_types": {"vercel.deploy_hook.created", "vercel.deploy_hook.deleted"},
        "severity": "medium",
        "title": "Vercel deploy hook risk aligned with deploy-hook activity",
        "subject": "Vercel deploy hook risk",
        "evidence_phrase": "deploy-hook activity",
    },
    "vercel_preview_unprotected": {
        "correlation_type": "vercel_deployment_protection_activity",
        "activity_types": {
            "vercel.deployment.created", "vercel.deployment.promoted",
            "vercel.project.updated",
        },
        "severity": "medium",
        "title": "Vercel deployment protection risk aligned with deployment activity",
        "subject": "Vercel deployment protection risk",
        "evidence_phrase": "deployment activity",
    },
}


def _vercel_event_project_keys(ev: SecurityActivityEvent) -> set[str]:
    """The safe project identities an activity event carries (id + name)."""
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    out: set[str] = set()
    for k in ("project_id", "project_name"):
        v = md.get(k)
        if isinstance(v, str) and v.strip():
            out.add(v.strip())
    return out


def _vercel_event_md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get(key)
    return v if isinstance(v, str) and v.strip() else None


def build_vercel_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    project_key: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a Vercel correlation dict (not persisted) from a finding + event."""
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None
    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    md = event.event_metadata if isinstance(event.event_metadata, dict) else {}
    project_name = _vercel_event_md(event, "project_name") or project_key
    title = f"{rule['title']} ({project_name})"
    summary = (
        f"{rule['subject']} (\"{finding.title}\") and {rule['evidence_phrase']} "
        f"(\"{event.event_type}\") were observed for the same Vercel project "
        f"\"{project_name}\" within the review window. {_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": event.source,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": event.event_type,
        "event_action": _vercel_event_md(event, "event_action"),
        "project_id": _vercel_event_md(event, "project_id") or project_key,
        "project_name": _vercel_event_md(event, "project_name"),
        "target_type": _vercel_event_md(event, "target_type"),
        "target_id": _vercel_event_md(event, "target_id"),
        "target_name": _vercel_event_md(event, "target_name"),
        "domain": _vercel_event_md(event, "domain"),
        "env_var_key": _vercel_event_md(event, "env_var_key"),
        "deploy_hook_name": _vercel_event_md(event, "deploy_hook_name"),
        "branch": _vercel_event_md(event, "branch"),
        "deployment_id": _vercel_event_md(event, "deployment_id"),
        "deployment_target": _vercel_event_md(event, "deployment_target"),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_VERCEL,
        "correlation_key": rule["correlation_type"],
        "correlation_type": rule["correlation_type"],
        "severity": rule["severity"],
        # Same-project config risk + aligned audit activity within the review
        # window is supporting (still circumstantial) evidence.
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        "_integration_id": finding.integration_id,
    }


def generate_vercel_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active Vercel findings with Vercel audit activity for a workspace.

    Conservative + project-scoped: a finding only matches an event for the SAME
    project (the finding's Resource.provider_resource_id ∈ the event's
    project_id/project_name), with an aligned event_type, inside the finding's
    review window. Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_VERCEL,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in VERCEL_CORRELATION_RULES
    ]

    # Resolve each finding's Vercel project identity via its Resource.
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    project_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            if isinstance(r.provider_resource_id, str) and r.provider_resource_id:
                project_by_resource[r.id] = r.provider_resource_id

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_VERCEL,
            SecurityActivityEvent.source == "audit_log",
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )
    # Index events by each safe project key they carry (id + name).
    events_by_project: dict[str, list[SecurityActivityEvent]] = {}
    for ev in events:
        for key in _vercel_event_project_keys(ev):
            events_by_project.setdefault(key, []).append(ev)

    created = 0
    skipped = 0
    for finding in findings:
        if finding.resource_id is None:
            continue  # no project-scoped resource to match on
        project_key = project_by_resource.get(finding.resource_id)
        if not project_key:
            continue  # no safe project identity → never provider-only match
        rule = VERCEL_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        seen_event_ids: set[uuid.UUID] = set()
        for ev in events_by_project.get(project_key, []):
            if ev.id in seen_event_ids:
                continue  # an event may index under both id + name
            if ev.event_type not in rule["activity_types"]:
                continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            seen_event_ids.add(ev.id)
            correlation = build_vercel_correlation(
                finding=finding, event=ev, project_key=project_key, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_VERCEL,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ── Supabase config-risk × activity correlations (M71D) ──────────────────────

_SUPABASE_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm data exposure, "
    "unauthorized access, or compromise."
)

# Map a Supabase finding's BASE rule key → correlation rule. ``match`` selects the
# narrowest identity used to join finding ↔ activity event:
#   "table"    — same schema_name + table_name
#   "function" — same edge function name (or id)
#   "auth"     — same project (auth config is project-scoped)
# Only rules whose finding side actually exists today are included. The public
# storage-bucket correlation is intentionally absent: the
# ``supabase_public_storage_bucket`` rule is deferred (no safe Management-API
# bucket listing), so there is nothing to match against — see report.
SUPABASE_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "supabase_rls_disabled": {
        "correlation_type": "supabase_rls_risk_activity",
        "match": "table",
        "activity_types": {"supabase.rls.updated", "supabase.table.updated"},
        "title": "Supabase RLS risk aligned with table activity",
        "subject": "Supabase RLS risk",
        "evidence_phrase": "table activity",
    },
    "supabase_public_select_sensitive_table": {
        "correlation_type": "supabase_public_select_risk_activity",
        "match": "table",
        "activity_types": {
            "supabase.policy.created", "supabase.policy.updated",
            "supabase.policy.deleted", "supabase.table.updated",
            "supabase.rls.updated",
        },
        "title": "Supabase public SELECT risk aligned with policy activity",
        "subject": "Supabase public SELECT risk",
        "evidence_phrase": "policy activity",
    },
    "supabase_public_write_policy": {
        "correlation_type": "supabase_public_write_risk_activity",
        "match": "table",
        "activity_types": {
            "supabase.policy.created", "supabase.policy.updated",
            "supabase.policy.deleted",
        },
        "title": "Supabase public write risk aligned with policy activity",
        "subject": "Supabase public write risk",
        "evidence_phrase": "policy activity",
    },
    "supabase_edge_function_jwt_disabled": {
        "correlation_type": "supabase_edge_function_risk_activity",
        "match": "function",
        "activity_types": {
            "supabase.edge_function.created", "supabase.edge_function.updated",
            "supabase.edge_function.deleted",
        },
        "title": "Supabase Edge Function risk aligned with function activity",
        "subject": "Supabase Edge Function risk",
        "evidence_phrase": "Edge Function activity",
    },
    "supabase_auth_protection_missing": {
        "correlation_type": "supabase_auth_protection_risk_activity",
        "match": "auth",
        "activity_types": {"supabase.auth_config.updated"},
        "title": "Supabase auth protection risk aligned with auth configuration activity",
        "subject": "Supabase auth protection risk",
        "evidence_phrase": "auth configuration activity",
    },
}


def _sb_event_md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get(key)
    return v.strip() if isinstance(v, str) and v.strip() else None


def _sb_finding_identity(finding: SecurityFinding, match: str) -> Optional[dict[str, str]]:
    """Resolve a finding's narrow join identity from its (safe) evidence.

    Returns ``None`` when the finding lacks enough identity to match — never a
    provider-only fallback.
    """
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    if match == "table":
        table = ev.get("table")
        if not isinstance(table, str) or not table.strip():
            return None
        schema = ev.get("schema")
        schema = schema.strip() if isinstance(schema, str) and schema.strip() else "public"
        return {"schema": schema, "table": table.strip()}
    if match == "function":
        fn = ev.get("function_name")
        if not isinstance(fn, str) or not fn.strip():
            return None
        return {"function": fn.strip()}
    if match == "auth":
        return {}  # project-scoped; the project guard supplies the identity
    return None


def _sb_event_matches(ev: SecurityActivityEvent, match: str, identity: dict[str, str]) -> bool:
    """Conservative narrow-identity match between an event and a finding identity."""
    if match == "table":
        ev_table = _sb_event_md(ev, "table_name")
        if not ev_table or ev_table != identity["table"]:
            return False
        ev_schema = _sb_event_md(ev, "schema_name") or "public"
        return ev_schema == identity["schema"]
    if match == "function":
        target = identity["function"]
        return (
            _sb_event_md(ev, "edge_function_name") == target
            or _sb_event_md(ev, "edge_function_id") == target
        )
    if match == "auth":
        # Auth config is project-scoped — the project guard already enforced a
        # matching project_ref, so an auth_config.updated event is sufficient.
        return True
    return False


def build_supabase_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    project_label: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a Supabase correlation dict (not persisted) from a finding + event."""
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None
    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['title']} ({project_label})"
    summary = (
        f"{rule['subject']} (\"{finding.title}\") and {rule['evidence_phrase']} "
        f"(\"{event.event_type}\") were observed for the same Supabase "
        f"{project_label} within the review window. {_SUPABASE_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": event.source,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": event.event_type,
        "event_action": _sb_event_md(event, "event_action"),
        "project_ref": _sb_event_md(event, "project_ref"),
        "project_name": _sb_event_md(event, "project_name"),
        "organization_id": _sb_event_md(event, "organization_id"),
        "target_type": _sb_event_md(event, "target_type"),
        "target_id": _sb_event_md(event, "target_id"),
        "target_name": _sb_event_md(event, "target_name"),
        "schema_name": _sb_event_md(event, "schema_name"),
        "table_name": _sb_event_md(event, "table_name"),
        "policy_name": _sb_event_md(event, "policy_name"),
        "policy_command": _sb_event_md(event, "policy_command"),
        "storage_bucket_id": _sb_event_md(event, "storage_bucket_id"),
        "storage_bucket_name": _sb_event_md(event, "storage_bucket_name"),
        "edge_function_id": _sb_event_md(event, "edge_function_id"),
        "edge_function_name": _sb_event_md(event, "edge_function_name"),
        "auth_setting_name": _sb_event_md(event, "auth_setting_name"),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_SUPABASE,
        "correlation_key": rule["correlation_type"],
        "correlation_type": rule["correlation_type"],
        # Severity tracks the finding (the rules already calibrate it).
        "severity": finding.severity or "medium",
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        "_integration_id": finding.integration_id,
    }


def generate_supabase_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active Supabase findings with Supabase audit activity (M71D).

    Conservative + identity-scoped: a finding only matches an event that shares
    the narrowest available identity (same schema+table / same Edge Function /
    same project for auth config), with an aligned event_type, inside the
    finding's review window, AND — when both sides carry a project_ref — the SAME
    project. Never provider-only. Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_SUPABASE,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in SUPABASE_CORRELATION_RULES
    ]

    # Resolve each finding's Supabase project ref via its Resource (project ref).
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    project_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            if isinstance(r.provider_resource_id, str) and r.provider_resource_id:
                project_by_resource[r.id] = r.provider_resource_id

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_SUPABASE,
            SecurityActivityEvent.source == "audit_log",
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )

    created = 0
    skipped = 0
    for finding in findings:
        rule = SUPABASE_CORRELATION_RULES[_base_rule(finding.finding_key)]
        match = rule["match"]
        identity = _sb_finding_identity(finding, match)
        if identity is None:
            continue  # not enough identity → never a provider-only match
        finding_project = (
            project_by_resource.get(finding.resource_id)
            if finding.resource_id is not None else None
        )
        # The auth-config join is project-scoped: require a known project ref.
        if match == "auth" and not finding_project:
            continue

        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events:
            if ev.event_type not in rule["activity_types"]:
                continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            # Project guard: never correlate across different projects.
            ev_project = _sb_event_md(ev, "project_ref")
            if finding_project and ev_project and ev_project != finding_project:
                continue
            if match == "auth" and ev_project != finding_project:
                continue  # auth identity IS the project — require an exact match
            if not _sb_event_matches(ev, match, identity):
                continue

            project_label = (
                _sb_event_md(ev, "project_name")
                or _sb_event_md(ev, "project_ref")
                or finding_project
                or "project"
            )
            project_label = f"project \"{project_label}\""
            correlation = build_supabase_correlation(
                finding=finding, event=ev, project_label=project_label, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_SUPABASE,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ── Firebase config-risk × activity correlations (M72D) ──────────────────────

_FIREBASE_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm data exposure, "
    "unauthorized access, or compromise."
)

# Map a Firebase finding's BASE rule key → correlation rule. ``narrow_key`` (when
# set) is an OPTIONAL resource identity: a join is project-scoped, but if the
# finding's evidence carries that key it must match the event's metadata value.
# Only rules whose finding side actually exists today are included. The public
# HTTPS-function correlation is intentionally absent: the
# ``firebase_public_https_function`` rule is deferred (no ingress metadata to
# infer public reachability), so there is nothing to match against — see report.
FIREBASE_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "firebase_rules_public": {
        "correlation_type": "firebase_firestore_rules_risk_activity",
        "activity_types": {"firebase.firestore_rules.updated"},
        "narrow_key": "ruleset_name",
        "title": "Firebase Firestore rules risk aligned with rules activity",
        "subject": "Firebase Firestore rules risk",
        "evidence_phrase": "rules activity",
    },
    "firebase_database_public_read": {
        "correlation_type": "firebase_database_rules_risk_activity",
        "activity_types": {"firebase.database_rules.updated"},
        "narrow_key": "database_instance",
        "title": "Firebase Realtime Database rules risk aligned with rules activity",
        "subject": "Firebase Realtime Database rules risk",
        "evidence_phrase": "rules activity",
    },
    "firebase_database_public_write": {
        "correlation_type": "firebase_database_rules_risk_activity",
        "activity_types": {"firebase.database_rules.updated"},
        "narrow_key": "database_instance",
        "title": "Firebase Realtime Database rules risk aligned with rules activity",
        "subject": "Firebase Realtime Database rules risk",
        "evidence_phrase": "rules activity",
    },
    "firebase_storage_rules_public": {
        "correlation_type": "firebase_storage_rules_risk_activity",
        "activity_types": {"firebase.storage_rules.updated"},
        "narrow_key": "storage_bucket_name",
        "title": "Firebase Storage rules risk aligned with rules activity",
        "subject": "Firebase Storage rules risk",
        "evidence_phrase": "rules activity",
    },
    "firebase_anonymous_auth_enabled": {
        "correlation_type": "firebase_anonymous_auth_risk_activity",
        "activity_types": {"firebase.auth_config.updated"},
        "narrow_key": None,
        "title": "Firebase anonymous auth risk aligned with auth configuration activity",
        "subject": "Firebase anonymous auth risk",
        "evidence_phrase": "auth configuration activity",
    },
    "firebase_auth_protection_missing": {
        "correlation_type": "firebase_auth_protection_risk_activity",
        "activity_types": {"firebase.auth_config.updated"},
        "narrow_key": None,
        "title": "Firebase auth protection risk aligned with auth configuration activity",
        "subject": "Firebase auth protection risk",
        "evidence_phrase": "auth configuration activity",
    },
}


def _fb_event_md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get(key)
    return v.strip() if isinstance(v, str) and v.strip() else None


def _fb_evidence_str(finding: SecurityFinding, key: str) -> Optional[str]:
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    v = ev.get(key)
    return v.strip() if isinstance(v, str) and v.strip() else None


def build_firebase_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    project_label: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a Firebase correlation dict (not persisted) from a finding + event."""
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None
    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['title']} ({project_label})"
    summary = (
        f"{rule['subject']} (\"{finding.title}\") and {rule['evidence_phrase']} "
        f"(\"{event.event_type}\") were observed for the same Firebase "
        f"{project_label} within the review window. {_FIREBASE_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": event.source,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": event.event_type,
        "event_action": _fb_event_md(event, "event_action"),
        "event_source": _fb_event_md(event, "event_source"),
        "project_id": _fb_event_md(event, "project_id"),
        "project_number": _fb_event_md(event, "project_number"),
        "service_name": _fb_event_md(event, "service_name"),
        "method_name": _fb_event_md(event, "method_name"),
        "target_type": _fb_event_md(event, "target_type"),
        "target_id": _fb_event_md(event, "target_id"),
        "target_name": _fb_event_md(event, "target_name"),
        "ruleset_name": _fb_event_md(event, "ruleset_name"),
        "database_instance": _fb_event_md(event, "database_instance"),
        "storage_bucket_name": _fb_event_md(event, "storage_bucket_name"),
        "function_name": _fb_event_md(event, "function_name"),
        "function_region": _fb_event_md(event, "function_region"),
        "app_id": _fb_event_md(event, "app_id"),
        "app_platform": _fb_event_md(event, "app_platform"),
        "hosting_site_id": _fb_event_md(event, "hosting_site_id"),
        "auth_setting_name": _fb_event_md(event, "auth_setting_name"),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_FIREBASE,
        "correlation_key": rule["correlation_type"],
        "correlation_type": rule["correlation_type"],
        "severity": finding.severity or "medium",
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        "_integration_id": finding.integration_id,
    }


def generate_firebase_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active Firebase findings with Firebase audit activity (M72D).

    Conservative + project-scoped: a finding only matches an event for the SAME
    Firebase project (the finding's Resource.provider_resource_id or evidence
    project_id == the event's metadata project_id), with an aligned event_type,
    inside the finding's review window. When the finding's evidence carries a
    narrower resource identity (ruleset/database/bucket name), the event must
    match it too. Never provider-only. Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_FIREBASE,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in FIREBASE_CORRELATION_RULES
    ]

    # Resolve each finding's Firebase project id via its Resource (project id).
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    project_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            if isinstance(r.provider_resource_id, str) and r.provider_resource_id:
                project_by_resource[r.id] = r.provider_resource_id

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_FIREBASE,
            SecurityActivityEvent.source == "audit_log",
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )

    created = 0
    skipped = 0
    for finding in findings:
        rule = FIREBASE_CORRELATION_RULES[_base_rule(finding.finding_key)]
        # Project identity from the Resource, falling back to evidence.project_id.
        finding_project = (
            project_by_resource.get(finding.resource_id)
            if finding.resource_id is not None else None
        ) or _fb_evidence_str(finding, "project_id")
        if not finding_project:
            continue  # no project identity → never a provider-only match

        narrow_key = rule.get("narrow_key")
        narrow_value = _fb_evidence_str(finding, narrow_key) if narrow_key else None

        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        for ev in events:
            if ev.event_type not in rule["activity_types"]:
                continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            # Project guard: require a matching project (never provider-only).
            if _fb_event_md(ev, "project_id") != finding_project:
                continue
            # Optional narrow identity: require it when the finding carries it.
            if narrow_value is not None and _fb_event_md(ev, narrow_key) != narrow_value:
                continue

            project_label = f'project "{finding_project}"'
            correlation = build_firebase_correlation(
                finding=finding, event=ev, project_label=project_label, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_FIREBASE,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


def list_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    provider: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    correlation_type: Optional[str] = None,
    linked_signal_id: Optional[uuid.UUID] = None,
    linked_finding_id: Optional[uuid.UUID] = None,
    linked_activity_event_id: Optional[uuid.UUID] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[SecuritySignalCorrelation], int]:
    """Paginated, workspace-scoped correlation list. Never crosses workspaces.

    The ``linked_*`` filters power evidence backlinks (M66.7): list the
    correlations attached to a given signal / finding / activity event. All
    filters compose with the mandatory workspace scope, so cross-workspace
    objects are never leaked even if a caller passes another workspace's id.
    """
    page = max(1, page)
    page_size = max(1, min(page_size, 100))

    q = db.query(SecuritySignalCorrelation).filter(
        SecuritySignalCorrelation.workspace_id == workspace_id
    )
    if provider:
        q = q.filter(SecuritySignalCorrelation.provider == provider)
    if status:
        q = q.filter(SecuritySignalCorrelation.status == status)
    if severity:
        q = q.filter(SecuritySignalCorrelation.severity == severity)
    if correlation_type:
        q = q.filter(SecuritySignalCorrelation.correlation_type == correlation_type)
    if linked_signal_id is not None:
        q = q.filter(SecuritySignalCorrelation.linked_signal_id == linked_signal_id)
    if linked_finding_id is not None:
        q = q.filter(SecuritySignalCorrelation.linked_finding_id == linked_finding_id)
    if linked_activity_event_id is not None:
        q = q.filter(
            SecuritySignalCorrelation.linked_activity_event_id == linked_activity_event_id
        )

    total = q.count()
    items = (
        q.order_by(
            SecuritySignalCorrelation.first_seen_at.desc().nullslast(),
            SecuritySignalCorrelation.created_at.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return items, total


def get_correlation(
    *,
    correlation_id: uuid.UUID,
    workspace_id: uuid.UUID,
    db: Session,
) -> Optional[SecuritySignalCorrelation]:
    """Return a single workspace-scoped correlation, or None (→ 404)."""
    return (
        db.query(SecuritySignalCorrelation)
        .filter(
            SecuritySignalCorrelation.id == correlation_id,
            SecuritySignalCorrelation.workspace_id == workspace_id,
        )
        .first()
    )


# ── Stripe config-risk × activity correlations (M73D) ────────────────────────

_STRIPE_REVIEW_NOTE = (
    "This may require review. ConfigTrace does not confirm fraud, compromise, "
    "unauthorized access, or data exposure."
)

# Stripe finding BASE rule key → correlation rule.
#
# ``narrow_key`` (when set) is the activity-event metadata field carrying the
# Stripe object id; the join requires it to match the finding's
# Resource.provider_resource_id (or the finding_key suffix, both of which are
# the canonical Stripe object id `we_*`/`plink_*`/`bpc_*`/`acct_*`). For the
# account-capability rule, ``narrow_key`` is ``account_id`` which makes the join
# account-scoped. Object-id matches are account-unique by construction, so
# webhook/payment-link/portal rules do not need a separate account guard.
#
# ``object_type`` (when set) is the event's ``object_type`` (data.object.object
# name) which must also match — defense in depth against object-id collisions
# across object families.
STRIPE_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "stripe_webhook_http": {
        "correlation_type": "stripe_webhook_insecure_risk_activity",
        "activity_types": {
            "stripe.webhook_endpoint.created",
            "stripe.webhook_endpoint.updated",
            "stripe.webhook_endpoint.deleted",
        },
        "narrow_key": "webhook_endpoint_id",
        "object_type": "webhook_endpoint",
        "title": "Stripe insecure webhook risk aligned with webhook activity",
        "subject": "Stripe insecure webhook risk",
        "evidence_phrase": "webhook configuration activity",
        "object_label": "endpoint",
        "object_kind": "webhook endpoint",
    },
    "stripe_webhook_disabled": {
        "correlation_type": "stripe_webhook_disabled_risk_activity",
        "activity_types": {
            "stripe.webhook_endpoint.updated",
            "stripe.webhook_endpoint.deleted",
        },
        "narrow_key": "webhook_endpoint_id",
        "object_type": "webhook_endpoint",
        "title": "Stripe disabled webhook risk aligned with webhook activity",
        "subject": "Stripe disabled webhook risk",
        "evidence_phrase": "webhook configuration activity",
        "object_label": "endpoint",
        "object_kind": "webhook endpoint",
    },
    "stripe_webhook_broad_events": {
        "correlation_type": "stripe_webhook_broad_events_risk_activity",
        "activity_types": {
            "stripe.webhook_endpoint.created",
            "stripe.webhook_endpoint.updated",
        },
        "narrow_key": "webhook_endpoint_id",
        "object_type": "webhook_endpoint",
        "title": "Stripe broad webhook event risk aligned with webhook activity",
        "subject": "Stripe broad webhook event risk",
        "evidence_phrase": "webhook configuration activity",
        "object_label": "endpoint",
        "object_kind": "webhook endpoint",
    },
    "stripe_payment_link_tax_disabled": {
        "correlation_type": "stripe_payment_link_tax_risk_activity",
        "activity_types": {
            "stripe.payment_link.created",
            "stripe.payment_link.updated",
        },
        "narrow_key": "payment_link_id",
        "object_type": "payment_link",
        "title": "Stripe payment link tax risk aligned with payment link activity",
        "subject": "Stripe payment link tax risk",
        "evidence_phrase": "payment link configuration activity",
        "object_label": "payment link",
        "object_kind": "payment link",
    },
    "stripe_payment_link_promo_codes_enabled": {
        "correlation_type": "stripe_payment_link_promo_risk_activity",
        "activity_types": {
            "stripe.payment_link.created",
            "stripe.payment_link.updated",
        },
        "narrow_key": "payment_link_id",
        "object_type": "payment_link",
        "title": "Stripe payment link promotion-code risk aligned with payment link activity",
        "subject": "Stripe payment link promotion-code risk",
        "evidence_phrase": "payment link configuration activity",
        "object_label": "payment link",
        "object_kind": "payment link",
    },
    "stripe_portal_subscription_cancel_enabled": {
        "correlation_type": "stripe_portal_cancel_risk_activity",
        "activity_types": {
            "stripe.portal_config.created",
            "stripe.portal_config.updated",
        },
        "narrow_key": "portal_config_id",
        "object_type": "billing_portal.configuration",
        "title": "Stripe customer portal cancellation risk aligned with portal activity",
        "subject": "Stripe customer portal cancellation risk",
        "evidence_phrase": "portal configuration activity",
        "object_label": "portal configuration",
        "object_kind": "portal configuration",
    },
    "stripe_portal_login_enabled": {
        "correlation_type": "stripe_portal_login_risk_activity",
        "activity_types": {
            "stripe.portal_config.created",
            "stripe.portal_config.updated",
        },
        "narrow_key": "portal_config_id",
        "object_type": "billing_portal.configuration",
        "title": "Stripe customer portal login risk aligned with portal activity",
        "subject": "Stripe customer portal login risk",
        "evidence_phrase": "portal configuration activity",
        "object_label": "portal configuration",
        "object_kind": "portal configuration",
    },
    "stripe_account_capability_incomplete": {
        "correlation_type": "stripe_account_capability_risk_activity",
        "activity_types": {
            "stripe.account.updated",
            "stripe.capability.updated",
        },
        # The account is the join. Capability matching is optional (used only
        # when the finding's evidence carries a capability NAME, which today is
        # not stored — so this is account-scoped in practice).
        "narrow_key": "account_id",
        # Both account and capability are valid object_types here; we don't
        # constrain object_type for this rule.
        "object_type": None,
        "title": "Stripe account capability risk aligned with account activity",
        "subject": "Stripe account capability risk",
        "evidence_phrase": "account configuration activity",
        "object_label": "account",
        "object_kind": "account",
    },
}


def _st_event_md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get(key)
    return v.strip() if isinstance(v, str) and v.strip() else None


def _st_event_bool(ev: SecurityActivityEvent, key: str) -> Optional[bool]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get(key)
    return v if isinstance(v, bool) else None


def _st_evidence_str(finding: SecurityFinding, key: str) -> Optional[str]:
    ev = finding.evidence if isinstance(finding.evidence, dict) else {}
    v = ev.get(key)
    return v.strip() if isinstance(v, str) and v.strip() else None


def _st_finding_object_id(finding: SecurityFinding) -> Optional[str]:
    """Stripe object id for a finding (we_*/plink_*/bpc_*/acct_*).

    Prefer the Resource.provider_resource_id (the canonical object id from
    M73A's connector); fall back to the finding_key suffix (rule_key:record_id
    pattern from ``make_finding_key``). Never returns the rule prefix alone.
    """
    fk = finding.finding_key or ""
    base = _base_rule(fk)
    if fk and ":" in fk:
        candidate = fk.split(":", 1)[1].strip()
        if candidate and candidate != base:
            return candidate
    return None


def build_stripe_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    object_label: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a Stripe correlation dict (not persisted) from a finding + event."""
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None
    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['title']} ({object_label})"
    summary = (
        f"{rule['subject']} (\"{finding.title}\") and {rule['evidence_phrase']} "
        f"(\"{event.event_type}\") were observed for the same Stripe "
        f"{object_label} within the review window. {_STRIPE_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": event.source,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": event.event_type,
        "stripe_event_type": _st_event_md(event, "stripe_event_type"),
        "event_action": _st_event_md(event, "event_action"),
        "event_source": _st_event_md(event, "event_source"),
        "account_id": _st_event_md(event, "account_id"),
        "object_type": _st_event_md(event, "object_type"),
        "object_id": _st_event_md(event, "object_id"),
        "webhook_endpoint_id": _st_event_md(event, "webhook_endpoint_id"),
        "webhook_url_domain": _st_event_md(event, "webhook_url_domain"),
        "webhook_url_scheme": _st_event_md(event, "webhook_url_scheme"),
        "payment_link_id": _st_event_md(event, "payment_link_id"),
        "portal_config_id": _st_event_md(event, "portal_config_id"),
        "capability": _st_event_md(event, "capability"),
        "capability_status": _st_event_md(event, "capability_status"),
        "tax_setting_name": _st_event_md(event, "tax_setting_name"),
        "livemode": _st_event_bool(event, "livemode"),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_STRIPE,
        "correlation_key": rule["correlation_type"],
        "correlation_type": rule["correlation_type"],
        "severity": finding.severity or "medium",
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        "_integration_id": finding.integration_id,
    }


def generate_stripe_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active Stripe config-risk findings with Stripe activity (M73D).

    Conservative + object-scoped: a finding only matches an event for the SAME
    Stripe object identity — webhook endpoint, payment link, portal configuration,
    or account id — with an aligned event_type, inside the finding's review
    window. The object id is read from the finding's Resource.provider_resource_id
    (with a finding_key-suffix fallback). Never provider-only — a finding with
    no resolvable object id is skipped. Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_STRIPE,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in STRIPE_CORRELATION_RULES
    ]

    # Resolve each finding's Stripe object id via its Resource.
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    object_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            if isinstance(r.provider_resource_id, str) and r.provider_resource_id:
                object_by_resource[r.id] = r.provider_resource_id

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_STRIPE,
            SecurityActivityEvent.source == "stripe_events",
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )

    created = 0
    skipped = 0
    for finding in findings:
        rule = STRIPE_CORRELATION_RULES[_base_rule(finding.finding_key)]
        # Object identity: Resource.provider_resource_id, with the finding_key
        # suffix as a fallback. Never provider-only.
        finding_object = (
            object_by_resource.get(finding.resource_id)
            if finding.resource_id is not None else None
        ) or _st_finding_object_id(finding)
        if not finding_object:
            continue

        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        narrow_key = rule.get("narrow_key")
        expected_object_type = rule.get("object_type")

        for ev in events:
            if ev.event_type not in rule["activity_types"]:
                continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            # Object guard (NEVER provider-only): the event's narrow-key metadata
            # must equal the finding's object id; the event's object_id is
            # accepted as a fallback. Object_type (when set on the rule) must
            # also match for defense in depth.
            ev_narrow = _st_event_md(ev, narrow_key) if narrow_key else None
            ev_object = _st_event_md(ev, "object_id")
            if ev_narrow != finding_object and ev_object != finding_object:
                continue
            if expected_object_type is not None:
                ev_object_type = _st_event_md(ev, "object_type")
                if ev_object_type != expected_object_type:
                    continue

            object_label = f"{rule['object_kind']} \"{finding_object}\""
            correlation = build_stripe_correlation(
                finding=finding, event=ev, object_label=object_label, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_STRIPE,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ════════════════════════════════════════════════════════════════════════════
# M74D — Shopify configuration risk × Shopify configuration activity
# ════════════════════════════════════════════════════════════════════════════

_SHOPIFY_REVIEW_NOTE = (
    "This is a correlation signal that may require review. ConfigTrace does "
    "not confirm fraud, compromise, unauthorized access, or data exposure."
)


# Finding-rule → Shopify correlation rule. Only the rules whose finding side
# exists AND whose evidence side M74B ingestion actually emits are mapped here.
# The four DEFERRED rules from the M74D spec (app_scopes / customer_scope /
# policy) intentionally appear NOWHERE in this map because M74B does not emit
# ``shopify.app_scopes.updated`` or ``shopify.policy.*``; promoting them would
# invent a correlation that has no evidence side. Their finding rules are
# tracked in ``_SHOPIFY_DEFERRED_FINDING_RULES`` so the front-end and tests can
# assert intent.
SHOPIFY_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    "shopify_webhook_http": {
        "correlation_type": "shopify_webhook_insecure_risk_activity",
        "activity_types": {
            "shopify.webhook.created",
            "shopify.webhook.updated",
            "shopify.webhook.deleted",
        },
        "narrow_key": "webhook_id",
        "object_type": "Webhook",
        "object_kind": "webhook",
        "title": "Shopify insecure webhook risk aligned with webhook activity",
        "subject": "Shopify insecure webhook risk",
        "evidence_phrase": "webhook configuration activity",
    },
    "shopify_webhook_high_risk_topic": {
        "correlation_type": "shopify_webhook_topic_risk_activity",
        "activity_types": {
            "shopify.webhook.created",
            "shopify.webhook.updated",
            "shopify.webhook.deleted",
        },
        "narrow_key": "webhook_id",
        "object_type": "Webhook",
        "object_kind": "webhook",
        "title": "Shopify high-risk webhook topic aligned with webhook activity",
        "subject": "Shopify high-risk webhook topic risk",
        "evidence_phrase": "webhook configuration activity",
    },
    "shopify_domain_ssl_missing": {
        "correlation_type": "shopify_domain_ssl_risk_activity",
        "activity_types": {
            "shopify.domain.created",
            "shopify.domain.updated",
            "shopify.domain.deleted",
        },
        "narrow_key": "domain_id",
        "object_type": "Domain",
        "object_kind": "domain",
        "title": "Shopify domain SSL risk aligned with domain activity",
        "subject": "Shopify domain SSL risk",
        "evidence_phrase": "domain configuration activity",
    },
    "shopify_domain_unverified": {
        "correlation_type": "shopify_domain_verification_risk_activity",
        "activity_types": {
            "shopify.domain.created",
            "shopify.domain.updated",
            "shopify.domain.deleted",
        },
        "narrow_key": "domain_id",
        "object_type": "Domain",
        "object_kind": "domain",
        "title": "Shopify domain verification risk aligned with domain activity",
        "subject": "Shopify domain verification risk",
        "evidence_phrase": "domain configuration activity",
    },
}

# Finding rules whose correlation is DEFERRED until M74B ingests the matching
# activity event_type. The dispatcher must never synthesize correlations for
# these. Pinned by M74D tests.
_SHOPIFY_DEFERRED_FINDING_RULES: frozenset[str] = frozenset({
    "shopify_app_broad_write_scopes",     # needs shopify.app_scopes.updated
    "shopify_app_customer_data_scope",    # needs shopify.app_scopes.updated
    "shopify_policy_missing",             # needs shopify.policy.{created,updated,deleted}
})


def _sh_event_md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get(key)
    return v.strip() if isinstance(v, str) and v.strip() else None


def _sh_event_bool(ev: SecurityActivityEvent, key: str) -> Optional[bool]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get(key)
    return v if isinstance(v, bool) else None


def _sh_finding_object_id(finding: SecurityFinding) -> Optional[str]:
    """Shopify object identifier (webhook id / domain id) for a finding.

    Prefer the Resource.provider_resource_id (the canonical id from the
    Shopify connector). Fall back to the finding_key suffix
    (``<rule>:<record_id>`` from ``make_finding_key``). Never returns the
    rule prefix alone, and never returns provider-only.
    """
    fk = finding.finding_key or ""
    base = _base_rule(fk)
    if fk and ":" in fk:
        candidate = fk.split(":", 1)[1].strip()
        if candidate and candidate != base:
            return candidate
    return None


def build_shopify_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    object_label: str,
    rule: dict[str, Any],
) -> dict[str, Any]:
    """Build a Shopify correlation dict (not persisted) from finding + event."""
    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None
    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['title']} ({object_label})"
    summary = (
        f"{rule['subject']} (\"{finding.title}\") and {rule['evidence_phrase']} "
        f"(\"{event.event_type}\") were observed for the same Shopify "
        f"{object_label} within the review window. {_SHOPIFY_REVIEW_NOTE}"
    )

    metadata = sanitize_correlation_metadata({
        "source": event.source,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "shop_domain": _sh_event_md(event, "shop_domain"),
        "myshopify_domain": _sh_event_md(event, "myshopify_domain"),
        "event_type": event.event_type,
        "shopify_event_type": _sh_event_md(event, "shopify_event_type"),
        "event_action": _sh_event_md(event, "event_action"),
        "event_source": _sh_event_md(event, "event_source"),
        "object_type": _sh_event_md(event, "object_type"),
        "object_id": _sh_event_md(event, "object_id"),
        "webhook_id": _sh_event_md(event, "webhook_id"),
        "webhook_topic": _sh_event_md(event, "webhook_topic"),
        "webhook_endpoint_domain": _sh_event_md(event, "webhook_endpoint_domain"),
        "webhook_endpoint_scheme": _sh_event_md(event, "webhook_endpoint_scheme"),
        "domain_id": _sh_event_md(event, "domain_id"),
        "domain_host": _sh_event_md(event, "domain_host"),
        "policy_type": _sh_event_md(event, "policy_type"),
        "livemode": _sh_event_bool(event, "livemode"),
        "window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_SHOPIFY,
        "correlation_key": rule["correlation_type"],
        "correlation_type": rule["correlation_type"],
        "severity": finding.severity or "medium",
        "confidence": "medium",
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        "_integration_id": finding.integration_id,
    }


def generate_shopify_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate active Shopify config-risk findings with Shopify activity (M74D).

    Conservative + object-scoped: a finding only matches an event for the SAME
    Shopify object identity (webhook id or domain id), with an aligned
    event_type, inside the finding's review window. The object id is read from
    the finding's Resource.provider_resource_id (with a finding_key-suffix
    fallback). The event's narrow-key metadata (webhook_id / domain_id) is
    compared to that object id; ``object_id`` is accepted as a fallback when
    ``object_type`` also matches. When both sides expose a shop identity
    (shop_domain or myshopify_domain), they must agree — never provider-only.
    Idempotent. Returns a generation summary.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_SHOPIFY,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in SHOPIFY_CORRELATION_RULES
    ]

    # Resolve each finding's Shopify object id via its Resource.
    resource_ids = {f.resource_id for f in findings if f.resource_id is not None}
    object_by_resource: dict[uuid.UUID, str] = {}
    shop_by_resource: dict[uuid.UUID, str] = {}
    if resource_ids:
        for r in db.query(Resource).filter(Resource.id.in_(resource_ids)).all():
            if isinstance(r.provider_resource_id, str) and r.provider_resource_id:
                object_by_resource[r.id] = r.provider_resource_id
            # Look for a shop identity hint on the Resource. Shopify integrations
            # tend to surface ``shop_domain`` / ``myshopify_domain`` via metadata
            # rather than the resource id itself, but we are happy with anything
            # that is a non-empty string and that lives on the Resource row.
            for k in ("shop_domain", "myshopify_domain"):
                v = getattr(r, k, None)
                if isinstance(v, str) and v.strip():
                    shop_by_resource[r.id] = v.strip()
                    break

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_SHOPIFY,
            SecurityActivityEvent.source == "shopify_events",
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )

    created = 0
    skipped = 0
    for finding in findings:
        rule = SHOPIFY_CORRELATION_RULES[_base_rule(finding.finding_key)]
        finding_object = (
            object_by_resource.get(finding.resource_id)
            if finding.resource_id is not None else None
        ) or _sh_finding_object_id(finding)
        if not finding_object:
            continue

        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        narrow_key = rule.get("narrow_key")
        expected_object_type = rule.get("object_type")
        finding_shop = shop_by_resource.get(finding.resource_id) if finding.resource_id else None

        for ev in events:
            if ev.event_type not in rule["activity_types"]:
                continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue
            # Object guard (NEVER provider-only): the event's narrow-key
            # metadata must equal the finding's object id; the event's
            # object_id is accepted as a fallback when object_type matches.
            ev_narrow = _sh_event_md(ev, narrow_key) if narrow_key else None
            ev_object_id = _sh_event_md(ev, "object_id")
            ev_object_type = _sh_event_md(ev, "object_type")
            narrow_match = (ev_narrow is not None and ev_narrow == finding_object)
            object_fallback = (
                expected_object_type is not None
                and ev_object_type == expected_object_type
                and ev_object_id is not None
                and ev_object_id == finding_object
            )
            if not (narrow_match or object_fallback):
                continue
            # Defense-in-depth on object_type (when set on the rule).
            if expected_object_type is not None and ev_object_type is not None \
                    and ev_object_type != expected_object_type:
                continue
            # Shop identity guard: if BOTH sides expose a shop identity, they
            # must agree. Never provider-only.
            ev_shop = (
                _sh_event_md(ev, "myshopify_domain")
                or _sh_event_md(ev, "shop_domain")
            )
            if finding_shop and ev_shop and finding_shop != ev_shop:
                continue

            object_label = f"{rule['object_kind']} \"{finding_object}\""
            correlation = build_shopify_correlation(
                finding=finding, event=ev, object_label=object_label, rule=rule
            )
            outcome, _row = upsert_correlation(
                workspace_id=workspace_id, correlation=correlation, db=db
            )
            if outcome == "created":
                created += 1
            else:
                skipped += 1

    return {
        "provider": PROVIDER_SHOPIFY,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ════════════════════════════════════════════════════════════════════════════
# AZURE — M77F config-risk × Azure Activity Log correlations
# ════════════════════════════════════════════════════════════════════════════
#
# Joins ACTIVE Azure security findings (provider="azure") to Azure Activity
# Log events (source="azure_activity_log") on the SAME Azure resource within
# the finding's review window.
#
# Matching strategy (conservative, defense-in-depth):
#
#   1. Resource-name match — for NSG/Storage/KV/App Service/SQL/AKS findings,
#      the finding's evidence dict carries the resource name (e.g. nsg_name,
#      storage_account_name, key_vault_name, app_service_name, sql_server_name,
#      aks_cluster_name) AND the event's metadata carries the same field. We
#      require an EXACT name match. When BOTH sides carry a resource_group we
#      additionally require that to match (defense-in-depth).
#
#   2. Role assignment match — for role-assignment broad-privilege findings,
#      we require role_definition_name overlap AND scope_type overlap. We
#      NEVER use principal ID / principal email / principal name.
#
# Provider-only or subscription-only matches are NEVER produced — at least the
# resource-name (or role + scope) must match.

_AZURE_REVIEW_NOTE = (
    "This is a correlation signal that may require review. ConfigTrace does "
    "not confirm public reachability, compromise, unauthorized access, or "
    "data exposure."
)

# Azure built-in role names considered "broad privilege" by M77E.
_AZURE_BROAD_ROLES: frozenset[str] = frozenset({
    "Owner", "Contributor", "User Access Administrator",
})

# Finding base rule → correlation rule.
AZURE_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    # ── NSG rules ────────────────────────────────────────────────────────────
    "azure_nsg_public_admin_ingress": {
        "correlation_type": "azure_nsg_exposure_activity_correlation",
        "activity_types": {
            "azure.nsg.updated", "azure.nsg.deleted",
            "azure.nsg_rule.updated", "azure.nsg_rule.deleted",
        },
        "name_field": "nsg_name",
        "event_name_field": "nsg_name",
        "kind": "NSG",
        "title": "Azure NSG exposure risk aligned with NSG activity",
        "subject": "Azure NSG public admin ingress risk",
        "evidence_phrase": "NSG configuration activity",
    },
    "azure_nsg_public_broad_ingress": {
        "correlation_type": "azure_nsg_exposure_activity_correlation",
        "activity_types": {
            "azure.nsg.updated", "azure.nsg.deleted",
            "azure.nsg_rule.updated", "azure.nsg_rule.deleted",
        },
        "name_field": "nsg_name",
        "event_name_field": "nsg_name",
        "kind": "NSG",
        "title": "Azure NSG broad-ingress risk aligned with NSG activity",
        "subject": "Azure NSG public broad ingress risk",
        "evidence_phrase": "NSG configuration activity",
    },
    # ── Storage rules ────────────────────────────────────────────────────────
    "azure_storage_public_blob_access": {
        "correlation_type": "azure_storage_risk_activity_correlation",
        "activity_types": {
            "azure.storage_account.updated", "azure.storage_account.deleted",
        },
        "name_field": "account_name",
        "event_name_field": "storage_account_name",
        "kind": "Storage account",
        "title": "Azure Storage public-blob risk aligned with storage activity",
        "subject": "Azure Storage public blob access risk",
        "evidence_phrase": "storage account configuration activity",
    },
    "azure_storage_public_network_access": {
        "correlation_type": "azure_storage_risk_activity_correlation",
        "activity_types": {
            "azure.storage_account.updated", "azure.storage_account.deleted",
        },
        "name_field": "account_name",
        "event_name_field": "storage_account_name",
        "kind": "Storage account",
        "title": "Azure Storage public-network risk aligned with storage activity",
        "subject": "Azure Storage public network access risk",
        "evidence_phrase": "storage account configuration activity",
    },
    "azure_storage_weak_tls": {
        "correlation_type": "azure_storage_risk_activity_correlation",
        "activity_types": {
            "azure.storage_account.updated", "azure.storage_account.deleted",
        },
        "name_field": "account_name",
        "event_name_field": "storage_account_name",
        "kind": "Storage account",
        "title": "Azure Storage weak-TLS risk aligned with storage activity",
        "subject": "Azure Storage weak TLS risk",
        "evidence_phrase": "storage account configuration activity",
    },
    "azure_storage_shared_key_enabled": {
        "correlation_type": "azure_storage_risk_activity_correlation",
        "activity_types": {
            "azure.storage_account.updated", "azure.storage_account.deleted",
        },
        "name_field": "account_name",
        "event_name_field": "storage_account_name",
        "kind": "Storage account",
        "title": "Azure Storage shared-key risk aligned with storage activity",
        "subject": "Azure Storage shared-key access risk",
        "evidence_phrase": "storage account configuration activity",
    },
    # ── Key Vault rules ──────────────────────────────────────────────────────
    "azure_key_vault_public_network_access": {
        "correlation_type": "azure_key_vault_risk_activity_correlation",
        "activity_types": {
            "azure.key_vault.updated", "azure.key_vault.deleted",
        },
        "name_field": "vault_name",
        "event_name_field": "key_vault_name",
        "kind": "Key Vault",
        "title": "Azure Key Vault public-network risk aligned with Key Vault activity",
        "subject": "Azure Key Vault public network access risk",
        "evidence_phrase": "Key Vault configuration activity",
    },
    "azure_key_vault_purge_protection_disabled": {
        "correlation_type": "azure_key_vault_risk_activity_correlation",
        "activity_types": {
            "azure.key_vault.updated", "azure.key_vault.deleted",
        },
        "name_field": "vault_name",
        "event_name_field": "key_vault_name",
        "kind": "Key Vault",
        "title": "Azure Key Vault purge-protection risk aligned with Key Vault activity",
        "subject": "Azure Key Vault purge-protection-disabled risk",
        "evidence_phrase": "Key Vault configuration activity",
    },
    "azure_key_vault_soft_delete_disabled": {
        "correlation_type": "azure_key_vault_risk_activity_correlation",
        "activity_types": {
            "azure.key_vault.updated", "azure.key_vault.deleted",
        },
        "name_field": "vault_name",
        "event_name_field": "key_vault_name",
        "kind": "Key Vault",
        "title": "Azure Key Vault soft-delete risk aligned with Key Vault activity",
        "subject": "Azure Key Vault soft-delete-disabled risk",
        "evidence_phrase": "Key Vault configuration activity",
    },
    "azure_key_vault_rbac_disabled": {
        "correlation_type": "azure_key_vault_risk_activity_correlation",
        "activity_types": {
            "azure.key_vault.updated", "azure.key_vault.deleted",
        },
        "name_field": "vault_name",
        "event_name_field": "key_vault_name",
        "kind": "Key Vault",
        "title": "Azure Key Vault RBAC risk aligned with Key Vault activity",
        "subject": "Azure Key Vault RBAC-disabled risk",
        "evidence_phrase": "Key Vault configuration activity",
    },
    # ── App Service rules ────────────────────────────────────────────────────
    "azure_app_service_https_disabled": {
        "correlation_type": "azure_app_service_risk_activity_correlation",
        "activity_types": {
            "azure.app_service.updated", "azure.app_service.deleted",
            "azure.app_service_config.updated",
        },
        "name_field": "app_name",
        "event_name_field": "app_service_name",
        "kind": "App Service",
        "title": "Azure App Service HTTPS risk aligned with App Service activity",
        "subject": "Azure App Service HTTPS-disabled risk",
        "evidence_phrase": "App Service configuration activity",
    },
    "azure_app_service_ftp_enabled": {
        "correlation_type": "azure_app_service_risk_activity_correlation",
        "activity_types": {
            "azure.app_service.updated", "azure.app_service.deleted",
            "azure.app_service_config.updated",
        },
        "name_field": "app_name",
        "event_name_field": "app_service_name",
        "kind": "App Service",
        "title": "Azure App Service FTP risk aligned with App Service activity",
        "subject": "Azure App Service FTP-enabled risk",
        "evidence_phrase": "App Service configuration activity",
    },
    "azure_app_service_weak_tls": {
        "correlation_type": "azure_app_service_risk_activity_correlation",
        "activity_types": {
            "azure.app_service.updated", "azure.app_service.deleted",
            "azure.app_service_config.updated",
        },
        "name_field": "app_name",
        "event_name_field": "app_service_name",
        "kind": "App Service",
        "title": "Azure App Service weak-TLS risk aligned with App Service activity",
        "subject": "Azure App Service weak TLS risk",
        "evidence_phrase": "App Service configuration activity",
    },
    "azure_app_service_public_network_access": {
        "correlation_type": "azure_app_service_risk_activity_correlation",
        "activity_types": {
            "azure.app_service.updated", "azure.app_service.deleted",
            "azure.app_service_config.updated",
        },
        "name_field": "app_name",
        "event_name_field": "app_service_name",
        "kind": "App Service",
        "title": "Azure App Service public-network risk aligned with App Service activity",
        "subject": "Azure App Service public network access risk",
        "evidence_phrase": "App Service configuration activity",
    },
    # ── SQL Server rules ─────────────────────────────────────────────────────
    "azure_sql_public_network_access": {
        "correlation_type": "azure_sql_risk_activity_correlation",
        "activity_types": {
            "azure.sql_server.updated", "azure.sql_server.deleted",
            "azure.sql_firewall_rule.updated", "azure.sql_firewall_rule.deleted",
        },
        "name_field": "server_name",
        "event_name_field": "sql_server_name",
        "kind": "SQL Server",
        "title": "Azure SQL public-network risk aligned with SQL activity",
        "subject": "Azure SQL public network access risk",
        "evidence_phrase": "SQL Server configuration activity",
    },
    "azure_sql_weak_tls": {
        "correlation_type": "azure_sql_risk_activity_correlation",
        "activity_types": {
            "azure.sql_server.updated", "azure.sql_server.deleted",
            "azure.sql_firewall_rule.updated", "azure.sql_firewall_rule.deleted",
        },
        "name_field": "server_name",
        "event_name_field": "sql_server_name",
        "kind": "SQL Server",
        "title": "Azure SQL weak-TLS risk aligned with SQL activity",
        "subject": "Azure SQL weak TLS risk",
        "evidence_phrase": "SQL Server configuration activity",
    },
    # ── AKS rules ────────────────────────────────────────────────────────────
    "azure_aks_local_accounts_enabled": {
        "correlation_type": "azure_aks_risk_activity_correlation",
        "activity_types": {
            "azure.aks_cluster.updated", "azure.aks_cluster.deleted",
        },
        "name_field": "cluster_name",
        "event_name_field": "aks_cluster_name",
        "kind": "AKS cluster",
        "title": "Azure AKS local-accounts risk aligned with AKS activity",
        "subject": "Azure AKS local-accounts-enabled risk",
        "evidence_phrase": "AKS cluster configuration activity",
    },
    "azure_aks_public_api_access": {
        "correlation_type": "azure_aks_risk_activity_correlation",
        "activity_types": {
            "azure.aks_cluster.updated", "azure.aks_cluster.deleted",
        },
        "name_field": "cluster_name",
        "event_name_field": "aks_cluster_name",
        "kind": "AKS cluster",
        "title": "Azure AKS public-API risk aligned with AKS activity",
        "subject": "Azure AKS public-API-access risk",
        "evidence_phrase": "AKS cluster configuration activity",
    },
    "azure_aks_network_policy_missing": {
        "correlation_type": "azure_aks_risk_activity_correlation",
        "activity_types": {
            "azure.aks_cluster.updated", "azure.aks_cluster.deleted",
        },
        "name_field": "cluster_name",
        "event_name_field": "aks_cluster_name",
        "kind": "AKS cluster",
        "title": "Azure AKS network-policy risk aligned with AKS activity",
        "subject": "Azure AKS network-policy-missing risk",
        "evidence_phrase": "AKS cluster configuration activity",
    },
    # ── Role assignment (special handling — joins on role + scope) ───────────
    "azure_role_assignment_broad_privilege": {
        "correlation_type": "azure_role_assignment_risk_activity_correlation",
        "activity_types": {
            "azure.role_assignment.created", "azure.role_assignment.deleted",
        },
        # Role assignment rules do not use a resource-name field; the matcher
        # switches to role+scope matching when name_field is None.
        "name_field": None,
        "event_name_field": None,
        "kind": "role assignment",
        "title": "Azure broad role-assignment risk aligned with role-assignment activity",
        "subject": "Azure broad role-assignment risk",
        "evidence_phrase": "role-assignment configuration activity",
    },
}


def _az_event_md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get(key)
    return v.strip() if isinstance(v, str) and v.strip() else None


def _az_finding_evidence(finding: SecurityFinding, key: str) -> Optional[str]:
    ev = finding.evidence if isinstance(finding.evidence, dict) else None
    if ev is None:
        return None
    v = ev.get(key)
    return v.strip() if isinstance(v, str) and v.strip() else None


def _az_finding_resource_name(
    finding: SecurityFinding, rule: dict[str, Any]
) -> Optional[str]:
    """Read the resource name from the finding's evidence dict (e.g. nsg_name)."""
    name_field = rule.get("name_field")
    if not name_field:
        return None
    return _az_finding_evidence(finding, name_field)


def _az_match_resource(
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    rule: dict[str, Any],
) -> Optional[str]:
    """Return a 'matched_on' label when finding ↔ event match the same resource.

    Match criteria:
      1. Resource NAME match — finding.evidence[name_field] must equal
         event.metadata[event_name_field], both non-empty.
      2. Resource group AGREEMENT (defense-in-depth) — if both sides carry
         resource_group, they must match. If one side omits it, accept.
    """
    name_field = rule.get("name_field")
    event_name_field = rule.get("event_name_field")
    if not name_field or not event_name_field:
        return None

    finding_name = _az_finding_resource_name(finding, rule)
    event_name = _az_event_md(event, event_name_field)
    if not finding_name or not event_name:
        return None
    if finding_name != event_name:
        return None

    finding_rg = _az_finding_evidence(finding, "resource_group")
    event_rg = _az_event_md(event, "resource_group")
    if finding_rg and event_rg and finding_rg != event_rg:
        return None

    if finding_rg and event_rg:
        return f"{event_name_field}+resource_group"
    return event_name_field


def _az_match_role_assignment(
    finding: SecurityFinding,
    event: SecurityActivityEvent,
) -> Optional[str]:
    """Return a 'matched_on' label when role + scope overlap (no principal use)."""
    finding_role = _az_finding_evidence(finding, "role_definition_name")
    event_role = _az_event_md(event, "role_definition_name")
    if not finding_role or not event_role:
        return None
    if finding_role != event_role:
        return None
    # Only flag broad roles to avoid noise on routine RBAC churn.
    if finding_role not in _AZURE_BROAD_ROLES:
        return None
    finding_scope = _az_finding_evidence(finding, "scope_type")
    event_scope = _az_event_md(event, "scope_type")
    if finding_scope and event_scope and finding_scope != event_scope:
        return None

    if finding_scope and event_scope:
        return "role_definition_name+scope_type"
    return "role_definition_name"


def _az_resource_label(
    finding: SecurityFinding,
    rule: dict[str, Any],
    matched_name: Optional[str],
) -> str:
    kind = rule.get("kind", "resource")
    if matched_name:
        return f'{kind} "{matched_name}"'
    role = _az_finding_evidence(finding, "role_definition_name") or ""
    if role:
        return f'{kind} "{role}"'
    return kind


def build_azure_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    rule: dict[str, Any],
    matched_on: str,
    resource_label: str,
) -> dict[str, Any]:
    """Build an Azure correlation dict (not persisted)."""
    sev = (finding.severity or "medium").lower()
    if sev not in {"critical", "high", "medium"}:
        sev = "medium"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None
    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['title']} ({resource_label})"
    summary = (
        f"{rule['subject']} (\"{finding.title}\") and {rule['evidence_phrase']} "
        f"(\"{event.event_type}\") were observed for the same Azure "
        f"{resource_label} within the review window. {_AZURE_REVIEW_NOTE}"
    )

    # "+" in matched_on means resource_group / scope also matched → high confidence.
    match_confidence = "high" if "+" in matched_on else "medium"

    metadata = sanitize_correlation_metadata({
        "source": event.source,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": event.event_type,
        "subscription_id": _az_event_md(event, "subscription_id"),
        "resource_group": _az_event_md(event, "resource_group"),
        "azure_event_id": _az_event_md(event, "azure_event_id"),
        "azure_correlation_id_hash": _az_event_md(event, "azure_correlation_id_hash"),
        "operation_name": _az_event_md(event, "operation_name"),
        "operation_family": _az_event_md(event, "operation_family"),
        "operation_action": _az_event_md(event, "operation_action"),
        "nsg_name": _az_event_md(event, "nsg_name"),
        "nsg_rule_name": _az_event_md(event, "nsg_rule_name"),
        "storage_account_name": _az_event_md(event, "storage_account_name"),
        "key_vault_name": _az_event_md(event, "key_vault_name"),
        "app_service_name": _az_event_md(event, "app_service_name"),
        "sql_server_name": _az_event_md(event, "sql_server_name"),
        "sql_firewall_rule_name": _az_event_md(event, "sql_firewall_rule_name"),
        "aks_cluster_name": _az_event_md(event, "aks_cluster_name"),
        "scope_type": _az_event_md(event, "scope_type"),
        "role_definition_name": _az_event_md(event, "role_definition_name"),
        "principal_type": _az_event_md(event, "principal_type"),
        "category": _az_event_md(event, "category"),
        "status": _az_event_md(event, "status"),
        "matched_on": matched_on,
        "match_confidence": match_confidence,
        "time_window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_AZURE,
        "correlation_key": rule["correlation_type"],
        "correlation_type": rule["correlation_type"],
        "severity": sev,
        "confidence": match_confidence,
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        "_integration_id": finding.integration_id,
    }


def generate_azure_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate Azure config-risk findings with Azure Activity Log events (M77F).

    Conservative, resource-name-scoped matching. Provider-only and
    subscription-only matches are NEVER produced. Idempotent.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_AZURE,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings if _base_rule(f.finding_key) in AZURE_CORRELATION_RULES
    ]

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_AZURE,
            SecurityActivityEvent.source == "azure_activity_log",
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )

    created = 0
    skipped = 0
    for finding in findings:
        rule = AZURE_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        finding_name = _az_finding_resource_name(finding, rule)
        is_role_rule = rule.get("name_field") is None

        for ev in events:
            if ev.event_type not in rule["activity_types"]:
                continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue

            if is_role_rule:
                matched_on = _az_match_role_assignment(finding, ev)
                resource_label = _az_resource_label(finding, rule, None)
            else:
                matched_on = _az_match_resource(finding, ev, rule)
                resource_label = _az_resource_label(finding, rule, finding_name)
            if not matched_on:
                continue

            try:
                correlation = build_azure_correlation(
                    finding=finding,
                    event=ev,
                    rule=rule,
                    matched_on=matched_on,
                    resource_label=resource_label,
                )
                outcome, _row = upsert_correlation(
                    workspace_id=workspace_id, correlation=correlation, db=db
                )
                if outcome == "created":
                    created += 1
                else:
                    skipped += 1
            except Exception:  # noqa: BLE001
                import logging
                logging.getLogger(__name__).warning(
                    "azure_correlations: failed one correlation; continuing"
                )
                continue

    return {
        "provider": PROVIDER_AZURE,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }


# ════════════════════════════════════════════════════════════════════════════
# GOOGLE CLOUD — M78F config-risk × Google Cloud Audit Log correlations
# ════════════════════════════════════════════════════════════════════════════
#
# Joins ACTIVE Google Cloud security findings (provider="google_cloud") to
# Google Cloud Audit Log events (source="google_cloud_audit_log") on the SAME
# Google Cloud resource within the finding's review window.
#
# Matching strategy (conservative, defense-in-depth):
#
#   1. Resource-name match — for firewall / storage / SQL / Cloud Run / GKE
#      findings, the finding's evidence dict carries the resource name
#      (e.g. firewall_rule_name, bucket_name, instance_name, service_name,
#      cluster_name) AND the event's metadata carries the same field (mapped
#      where the names differ between sides). We require an EXACT name match.
#      When BOTH sides carry a project_id we additionally require that to match
#      (defense-in-depth).
#
#   2. Aggregate (project + family) match — for IAM / service-account-key /
#      Secret Manager findings, the finding is project-aggregate and carries no
#      specific resource name. We require finding.evidence["project_id"] ==
#      event.metadata["project_id"] AND the activity event_type to belong to
#      the right family (e.g. IAM events for IAM findings, secret events for
#      Secret Manager findings).
#
# Provider-only and project-only-for-resource-bearing-findings matches are
# NEVER produced. Principal emails, SA emails, key IDs, secret names, full IAM
# bindings, and raw payloads are NEVER used for matching or stored.


_GCP_REVIEW_NOTE = (
    "This is related activity evidence that may require review. ConfigTrace "
    "does not confirm reachability, compromise, unauthorized access, or "
    "data exposure."
)


# Finding base rule → correlation rule.
#
# Each rule has either:
#   * a name-based join (name_field on the finding side ↔ event_name_field on
#     the event side), or
#   * an aggregate join (name_field=None) where project_id + finding_family is
#     the join key.
GOOGLE_CLOUD_CORRELATION_RULES: dict[str, dict[str, Any]] = {
    # ── IAM (aggregate — project + family) ───────────────────────────────────
    "google_cloud_iam_public_member": {
        "correlation_type": "google_cloud_iam_risk_activity_correlation",
        "activity_types": {"google_cloud.iam_policy.updated"},
        "name_field": None,
        "event_name_field": None,
        "finding_family": "iam",
        "kind": "IAM policy",
        "title": "Google Cloud IAM risk aligned with IAM policy activity",
        "subject": "Google Cloud IAM public-member risk",
        "evidence_phrase": "IAM policy configuration activity",
    },
    "google_cloud_iam_broad_privileged_role": {
        "correlation_type": "google_cloud_iam_risk_activity_correlation",
        "activity_types": {"google_cloud.iam_policy.updated"},
        "name_field": None,
        "event_name_field": None,
        "finding_family": "iam",
        "kind": "IAM policy",
        "title": "Google Cloud IAM broad-role risk aligned with IAM policy activity",
        "subject": "Google Cloud IAM broad-privileged-role risk",
        "evidence_phrase": "IAM policy configuration activity",
    },
    # ── Firewall (resource — firewall_rule_name) ─────────────────────────────
    "google_cloud_firewall_public_admin_ingress": {
        "correlation_type": "google_cloud_firewall_risk_activity_correlation",
        "activity_types": {
            "google_cloud.firewall_rule.created",
            "google_cloud.firewall_rule.updated",
            "google_cloud.firewall_rule.deleted",
        },
        "name_field": "firewall_rule_name",
        "event_name_field": "firewall_rule_name",
        "finding_family": "firewall",
        "kind": "firewall rule",
        "title": "Google Cloud firewall exposure risk aligned with firewall activity",
        "subject": "Google Cloud firewall public-admin-ingress risk",
        "evidence_phrase": "firewall configuration activity",
    },
    "google_cloud_firewall_public_broad_ingress": {
        "correlation_type": "google_cloud_firewall_risk_activity_correlation",
        "activity_types": {
            "google_cloud.firewall_rule.created",
            "google_cloud.firewall_rule.updated",
            "google_cloud.firewall_rule.deleted",
        },
        "name_field": "firewall_rule_name",
        "event_name_field": "firewall_rule_name",
        "finding_family": "firewall",
        "kind": "firewall rule",
        "title": "Google Cloud firewall broad-ingress risk aligned with firewall activity",
        "subject": "Google Cloud firewall public-broad-ingress risk",
        "evidence_phrase": "firewall configuration activity",
    },
    "google_cloud_firewall_rule_no_targets": {
        "correlation_type": "google_cloud_firewall_risk_activity_correlation",
        "activity_types": {
            "google_cloud.firewall_rule.created",
            "google_cloud.firewall_rule.updated",
            "google_cloud.firewall_rule.deleted",
        },
        "name_field": "firewall_rule_name",
        "event_name_field": "firewall_rule_name",
        "finding_family": "firewall",
        "kind": "firewall rule",
        "title": "Google Cloud firewall untargeted-rule risk aligned with firewall activity",
        "subject": "Google Cloud firewall rule-without-targets risk",
        "evidence_phrase": "firewall configuration activity",
    },
    # ── Cloud Storage (resource — bucket_name) ───────────────────────────────
    "google_cloud_storage_public_access_prevention_disabled": {
        "correlation_type": "google_cloud_storage_risk_activity_correlation",
        "activity_types": {
            "google_cloud.storage_bucket.created",
            "google_cloud.storage_bucket.updated",
            "google_cloud.storage_bucket.deleted",
            "google_cloud.storage_iam.updated",
        },
        "name_field": "bucket_name",
        "event_name_field": "bucket_name",
        "finding_family": "storage",
        "kind": "Cloud Storage bucket",
        "title": "Google Cloud Storage public-access-prevention risk aligned with bucket activity",
        "subject": "Google Cloud Storage public-access-prevention-disabled risk",
        "evidence_phrase": "Cloud Storage configuration activity",
    },
    "google_cloud_storage_uniform_access_disabled": {
        "correlation_type": "google_cloud_storage_risk_activity_correlation",
        "activity_types": {
            "google_cloud.storage_bucket.created",
            "google_cloud.storage_bucket.updated",
            "google_cloud.storage_bucket.deleted",
            "google_cloud.storage_iam.updated",
        },
        "name_field": "bucket_name",
        "event_name_field": "bucket_name",
        "finding_family": "storage",
        "kind": "Cloud Storage bucket",
        "title": "Google Cloud Storage uniform-access risk aligned with bucket activity",
        "subject": "Google Cloud Storage uniform-bucket-level-access-disabled risk",
        "evidence_phrase": "Cloud Storage configuration activity",
    },
    "google_cloud_storage_versioning_disabled": {
        "correlation_type": "google_cloud_storage_risk_activity_correlation",
        "activity_types": {
            "google_cloud.storage_bucket.created",
            "google_cloud.storage_bucket.updated",
            "google_cloud.storage_bucket.deleted",
            "google_cloud.storage_iam.updated",
        },
        "name_field": "bucket_name",
        "event_name_field": "bucket_name",
        "finding_family": "storage",
        "kind": "Cloud Storage bucket",
        "title": "Google Cloud Storage versioning risk aligned with bucket activity",
        "subject": "Google Cloud Storage versioning-disabled risk",
        "evidence_phrase": "Cloud Storage configuration activity",
    },
    "google_cloud_storage_retention_not_locked": {
        "correlation_type": "google_cloud_storage_risk_activity_correlation",
        "activity_types": {
            "google_cloud.storage_bucket.created",
            "google_cloud.storage_bucket.updated",
            "google_cloud.storage_bucket.deleted",
            "google_cloud.storage_iam.updated",
        },
        "name_field": "bucket_name",
        "event_name_field": "bucket_name",
        "finding_family": "storage",
        "kind": "Cloud Storage bucket",
        "title": "Google Cloud Storage retention-lock risk aligned with bucket activity",
        "subject": "Google Cloud Storage retention-not-locked risk",
        "evidence_phrase": "Cloud Storage configuration activity",
    },
    # ── Cloud SQL (resource — instance_name ↔ sql_instance_name) ─────────────
    "google_cloud_sql_public_network_access": {
        "correlation_type": "google_cloud_sql_risk_activity_correlation",
        "activity_types": {
            "google_cloud.sql_instance.created",
            "google_cloud.sql_instance.updated",
            "google_cloud.sql_instance.deleted",
        },
        "name_field": "instance_name",
        "event_name_field": "sql_instance_name",
        "finding_family": "sql",
        "kind": "Cloud SQL instance",
        "title": "Google Cloud SQL public-network risk aligned with SQL activity",
        "subject": "Google Cloud SQL public-network-access risk",
        "evidence_phrase": "Cloud SQL configuration activity",
    },
    "google_cloud_sql_weak_tls": {
        "correlation_type": "google_cloud_sql_risk_activity_correlation",
        "activity_types": {
            "google_cloud.sql_instance.created",
            "google_cloud.sql_instance.updated",
            "google_cloud.sql_instance.deleted",
        },
        "name_field": "instance_name",
        "event_name_field": "sql_instance_name",
        "finding_family": "sql",
        "kind": "Cloud SQL instance",
        "title": "Google Cloud SQL weak-TLS risk aligned with SQL activity",
        "subject": "Google Cloud SQL weak-TLS risk",
        "evidence_phrase": "Cloud SQL configuration activity",
    },
    "google_cloud_sql_backups_disabled": {
        "correlation_type": "google_cloud_sql_risk_activity_correlation",
        "activity_types": {
            "google_cloud.sql_instance.created",
            "google_cloud.sql_instance.updated",
            "google_cloud.sql_instance.deleted",
        },
        "name_field": "instance_name",
        "event_name_field": "sql_instance_name",
        "finding_family": "sql",
        "kind": "Cloud SQL instance",
        "title": "Google Cloud SQL backups risk aligned with SQL activity",
        "subject": "Google Cloud SQL backups-disabled risk",
        "evidence_phrase": "Cloud SQL configuration activity",
    },
    "google_cloud_sql_deletion_protection_disabled": {
        "correlation_type": "google_cloud_sql_risk_activity_correlation",
        "activity_types": {
            "google_cloud.sql_instance.created",
            "google_cloud.sql_instance.updated",
            "google_cloud.sql_instance.deleted",
        },
        "name_field": "instance_name",
        "event_name_field": "sql_instance_name",
        "finding_family": "sql",
        "kind": "Cloud SQL instance",
        "title": "Google Cloud SQL deletion-protection risk aligned with SQL activity",
        "subject": "Google Cloud SQL deletion-protection-disabled risk",
        "evidence_phrase": "Cloud SQL configuration activity",
    },
    # ── Cloud Run (resource — service_name ↔ run_service_name) ───────────────
    "google_cloud_run_public_invoker": {
        "correlation_type": "google_cloud_run_risk_activity_correlation",
        "activity_types": {
            "google_cloud.run_service.created",
            "google_cloud.run_service.updated",
            "google_cloud.run_service.deleted",
        },
        "name_field": "service_name",
        "event_name_field": "run_service_name",
        "finding_family": "run",
        "kind": "Cloud Run service",
        "title": "Google Cloud Run public-invoker risk aligned with Cloud Run activity",
        "subject": "Google Cloud Run public-invoker risk",
        "evidence_phrase": "Cloud Run configuration activity",
    },
    "google_cloud_run_all_ingress": {
        "correlation_type": "google_cloud_run_risk_activity_correlation",
        "activity_types": {
            "google_cloud.run_service.created",
            "google_cloud.run_service.updated",
            "google_cloud.run_service.deleted",
        },
        "name_field": "service_name",
        "event_name_field": "run_service_name",
        "finding_family": "run",
        "kind": "Cloud Run service",
        "title": "Google Cloud Run all-ingress risk aligned with Cloud Run activity",
        "subject": "Google Cloud Run all-ingress risk",
        "evidence_phrase": "Cloud Run configuration activity",
    },
    # ── GKE (resource — cluster_name ↔ gke_cluster_name) ─────────────────────
    "google_cloud_gke_public_control_plane": {
        "correlation_type": "google_cloud_gke_risk_activity_correlation",
        "activity_types": {
            "google_cloud.gke_cluster.created",
            "google_cloud.gke_cluster.updated",
            "google_cloud.gke_cluster.deleted",
            "google_cloud.gke_network_policy.updated",
            "google_cloud.gke_master_auth.updated",
        },
        "name_field": "cluster_name",
        "event_name_field": "gke_cluster_name",
        "finding_family": "gke",
        "kind": "GKE cluster",
        "title": "Google Cloud GKE public-control-plane risk aligned with GKE activity",
        "subject": "Google Cloud GKE public-control-plane risk",
        "evidence_phrase": "GKE configuration activity",
    },
    "google_cloud_gke_legacy_abac_enabled": {
        "correlation_type": "google_cloud_gke_risk_activity_correlation",
        "activity_types": {
            "google_cloud.gke_cluster.created",
            "google_cloud.gke_cluster.updated",
            "google_cloud.gke_cluster.deleted",
            "google_cloud.gke_network_policy.updated",
            "google_cloud.gke_master_auth.updated",
        },
        "name_field": "cluster_name",
        "event_name_field": "gke_cluster_name",
        "finding_family": "gke",
        "kind": "GKE cluster",
        "title": "Google Cloud GKE legacy-ABAC risk aligned with GKE activity",
        "subject": "Google Cloud GKE legacy-ABAC-enabled risk",
        "evidence_phrase": "GKE configuration activity",
    },
    "google_cloud_gke_network_policy_disabled": {
        "correlation_type": "google_cloud_gke_risk_activity_correlation",
        "activity_types": {
            "google_cloud.gke_cluster.created",
            "google_cloud.gke_cluster.updated",
            "google_cloud.gke_cluster.deleted",
            "google_cloud.gke_network_policy.updated",
            "google_cloud.gke_master_auth.updated",
        },
        "name_field": "cluster_name",
        "event_name_field": "gke_cluster_name",
        "finding_family": "gke",
        "kind": "GKE cluster",
        "title": "Google Cloud GKE network-policy risk aligned with GKE activity",
        "subject": "Google Cloud GKE network-policy-disabled risk",
        "evidence_phrase": "GKE configuration activity",
    },
    "google_cloud_gke_workload_identity_disabled": {
        "correlation_type": "google_cloud_gke_risk_activity_correlation",
        "activity_types": {
            "google_cloud.gke_cluster.created",
            "google_cloud.gke_cluster.updated",
            "google_cloud.gke_cluster.deleted",
            "google_cloud.gke_network_policy.updated",
            "google_cloud.gke_master_auth.updated",
        },
        "name_field": "cluster_name",
        "event_name_field": "gke_cluster_name",
        "finding_family": "gke",
        "kind": "GKE cluster",
        "title": "Google Cloud GKE workload-identity risk aligned with GKE activity",
        "subject": "Google Cloud GKE workload-identity-disabled risk",
        "evidence_phrase": "GKE configuration activity",
    },
    # ── Service-account keys (aggregate — project + family) ──────────────────
    "google_cloud_service_account_user_managed_keys": {
        "correlation_type": "google_cloud_service_account_key_risk_activity_correlation",
        "activity_types": {
            "google_cloud.service_account_key.created",
            "google_cloud.service_account_key.deleted",
            "google_cloud.service_account.created",
            "google_cloud.service_account.updated",
            "google_cloud.service_account.deleted",
        },
        "name_field": None,
        "event_name_field": None,
        "finding_family": "service_account_key",
        "kind": "service account key posture",
        "title": "Google Cloud service-account-key risk aligned with service-account activity",
        "subject": "Google Cloud service-account user-managed-keys risk",
        "evidence_phrase": "service account configuration activity",
    },
    "google_cloud_service_account_old_keys": {
        "correlation_type": "google_cloud_service_account_key_risk_activity_correlation",
        "activity_types": {
            "google_cloud.service_account_key.created",
            "google_cloud.service_account_key.deleted",
            "google_cloud.service_account.created",
            "google_cloud.service_account.updated",
            "google_cloud.service_account.deleted",
        },
        "name_field": None,
        "event_name_field": None,
        "finding_family": "service_account_key",
        "kind": "service account key posture",
        "title": "Google Cloud service-account-old-key risk aligned with service-account activity",
        "subject": "Google Cloud service-account old-keys risk",
        "evidence_phrase": "service account configuration activity",
    },
    # ── Secret Manager (aggregate — project + family) ────────────────────────
    "google_cloud_secret_manager_auto_replication_without_cmek": {
        "correlation_type": "google_cloud_secret_manager_risk_activity_correlation",
        "activity_types": {
            "google_cloud.secret.created",
            "google_cloud.secret.updated",
            "google_cloud.secret.deleted",
        },
        "name_field": None,
        "event_name_field": None,
        "finding_family": "secret_manager",
        "kind": "Secret Manager posture",
        "title": "Google Cloud Secret Manager risk aligned with secret activity",
        "subject": "Google Cloud Secret Manager auto-replication-without-CMEK risk",
        "evidence_phrase": "Secret Manager configuration activity",
    },
}


def _gcp_event_md(ev: SecurityActivityEvent, key: str) -> Optional[str]:
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    v = md.get(key)
    return v.strip() if isinstance(v, str) and v.strip() else None


def _gcp_finding_evidence(finding: SecurityFinding, key: str) -> Optional[str]:
    ev = finding.evidence if isinstance(finding.evidence, dict) else None
    if ev is None:
        return None
    v = ev.get(key)
    return v.strip() if isinstance(v, str) and v.strip() else None


def _gcp_finding_resource_name(
    finding: SecurityFinding, rule: dict[str, Any]
) -> Optional[str]:
    """Read the finding-side resource name (e.g. firewall_rule_name)."""
    name_field = rule.get("name_field")
    if not name_field:
        return None
    return _gcp_finding_evidence(finding, name_field)


def _gcp_match_resource(
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    rule: dict[str, Any],
) -> Optional[str]:
    """Resource-name + project_id match for resource-bearing findings.

    Match criteria:
      1. Resource NAME match — finding.evidence[name_field] equals
         event.metadata[event_name_field], both non-empty.
      2. project_id AGREEMENT (defense-in-depth) — if both sides carry
         project_id, they must match. If one side omits it, accept.

    Returns a 'matched_on' label or None.
    """
    name_field = rule.get("name_field")
    event_name_field = rule.get("event_name_field")
    if not name_field or not event_name_field:
        return None

    finding_name = _gcp_finding_resource_name(finding, rule)
    event_name = _gcp_event_md(event, event_name_field)
    if not finding_name or not event_name:
        return None
    if finding_name != event_name:
        return None

    finding_project = _gcp_finding_evidence(finding, "project_id")
    event_project = _gcp_event_md(event, "project_id")
    if finding_project and event_project and finding_project != event_project:
        return None

    if finding_project and event_project:
        return f"{event_name_field}+project_id"
    return event_name_field


def _gcp_match_aggregate(
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    rule: dict[str, Any],
) -> Optional[str]:
    """Project + family aggregate match (IAM / service-account-key / Secret Manager).

    Used for findings that do not carry a specific resource name. Requires:
      1. project_id present on BOTH sides AND equal.
      2. event.event_type is in rule["activity_types"] (already checked by
         caller, but kept as defense-in-depth via a non-empty rule family).

    Returns a 'matched_on' label or None. Never produces project-only matches
    for findings that COULD carry a resource name (caller dispatches by rule
    kind, not by ``name_field`` being None at runtime).
    """
    finding_project = _gcp_finding_evidence(finding, "project_id")
    event_project = _gcp_event_md(event, "project_id")
    if not finding_project or not event_project:
        return None
    if finding_project != event_project:
        return None
    family = rule.get("finding_family")
    if not family:
        return None
    return f"project_id+{family}"


def _gcp_resource_label(
    finding: SecurityFinding,
    rule: dict[str, Any],
    matched_name: Optional[str],
) -> str:
    kind = rule.get("kind", "resource")
    if matched_name:
        return f'{kind} "{matched_name}"'
    project = _gcp_finding_evidence(finding, "project_id") or ""
    if project:
        return f'{kind} in project "{project}"'
    return kind


def build_google_cloud_correlation(
    *,
    finding: SecurityFinding,
    event: SecurityActivityEvent,
    rule: dict[str, Any],
    matched_on: str,
    resource_label: str,
) -> dict[str, Any]:
    """Build a Google Cloud correlation dict (not persisted)."""
    sev = (finding.severity or "medium").lower()
    if sev not in {"critical", "high", "medium", "low"}:
        sev = "medium"
    # Floor low → medium for review priority on correlations.
    if sev == "low":
        sev = "medium"

    f_start = _aware(finding.first_detected_at)
    f_end = _aware(finding.last_seen_at)
    occurred = _aware(event.occurred_at)

    window_start = (f_start - WINDOW) if f_start else None
    window_end = (f_end + WINDOW) if f_end else None
    seens = [d for d in (f_start, occurred) if d]
    first_seen = min(seens) if seens else None
    lasts = [d for d in (f_end, occurred) if d]
    last_seen = max(lasts) if lasts else None

    title = f"{rule['title']} ({resource_label})"
    summary = (
        f"{rule['subject']} (\"{finding.title}\") and {rule['evidence_phrase']} "
        f"(\"{event.event_type}\") were observed for the same Google Cloud "
        f"{resource_label} within the review window. {_GCP_REVIEW_NOTE}"
    )

    # "+" in matched_on means project_id (or family) also matched → high confidence.
    match_confidence = "high" if "+" in matched_on else "medium"

    metadata = sanitize_correlation_metadata({
        "source": event.source,
        "finding_rule": _base_rule(finding.finding_key),
        "finding_severity": finding.severity,
        "event_type": event.event_type,
        "project_id": _gcp_event_md(event, "project_id"),
        "google_cloud_event_id": _gcp_event_md(event, "google_cloud_event_id"),
        "service_name": _gcp_event_md(event, "service_name"),
        "method_name": _gcp_event_md(event, "method_name"),
        "operation_name": _gcp_event_md(event, "operation_name"),
        "operation_family": _gcp_event_md(event, "operation_family"),
        "operation_action": _gcp_event_md(event, "operation_action"),
        "resource_name": _gcp_event_md(event, "resource_name"),
        "resource_type": _gcp_event_md(event, "resource_type"),
        # Resource-specific identifiers (event side).
        "network_name": _gcp_event_md(event, "network_name"),
        "firewall_rule_name": _gcp_event_md(event, "firewall_rule_name"),
        "bucket_name": _gcp_event_md(event, "bucket_name"),
        "sql_instance_name": _gcp_event_md(event, "sql_instance_name"),
        "run_service_name": _gcp_event_md(event, "run_service_name"),
        "gke_cluster_name": _gcp_event_md(event, "gke_cluster_name"),
        "category": _gcp_event_md(event, "category"),
        "finding_family": rule.get("finding_family"),
        "matched_on": matched_on,
        "match_confidence": match_confidence,
        "time_window_hours": int(WINDOW.total_seconds() // 3600),
    })

    return {
        "provider": PROVIDER_GOOGLE_CLOUD,
        "correlation_key": rule["correlation_type"],
        "correlation_type": rule["correlation_type"],
        "severity": sev,
        "confidence": match_confidence,
        "status": "open",
        "title": title,
        "summary": summary,
        "linked_finding_id": finding.id,
        "linked_activity_event_id": event.id,
        "linked_change_id": finding.linked_change_id,
        "window_start": window_start,
        "window_end": window_end,
        "first_seen_at": first_seen,
        "last_seen_at": last_seen,
        "metadata": metadata,
        "_integration_id": finding.integration_id,
    }


def generate_google_cloud_correlations(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Correlate Google Cloud config-risk findings with Google Cloud Audit Log
    events (M78F).

    Conservative, resource-name-scoped matching for resource-bearing findings
    (firewall / storage / SQL / Cloud Run / GKE). Aggregate project+family
    matching for IAM / service-account-key / Secret Manager findings (which do
    not carry a specific resource name). Provider-only and project-only-for-
    resource-bearing matches are NEVER produced. Idempotent.
    """
    findings = (
        db.query(SecurityFinding)
        .filter(
            SecurityFinding.workspace_id == workspace_id,
            SecurityFinding.provider == PROVIDER_GOOGLE_CLOUD,
            SecurityFinding.status == "active",
        )
        .limit(scan_limit)
        .all()
    )
    findings = [
        f for f in findings
        if _base_rule(f.finding_key) in GOOGLE_CLOUD_CORRELATION_RULES
    ]

    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GOOGLE_CLOUD,
            SecurityActivityEvent.source == "google_cloud_audit_log",
            SecurityActivityEvent.occurred_at.isnot(None),
        )
        .limit(scan_limit)
        .all()
    )

    created = 0
    skipped = 0
    for finding in findings:
        rule = GOOGLE_CLOUD_CORRELATION_RULES[_base_rule(finding.finding_key)]
        f_start = _aware(finding.first_detected_at)
        f_end = _aware(finding.last_seen_at)
        if f_start is None or f_end is None:
            continue
        window_start = f_start - WINDOW
        window_end = f_end + WINDOW

        is_aggregate = rule.get("name_field") is None
        finding_name = _gcp_finding_resource_name(finding, rule)

        for ev in events:
            if ev.event_type not in rule["activity_types"]:
                continue
            occurred = _aware(ev.occurred_at)
            if occurred is None or not (window_start <= occurred <= window_end):
                continue

            if is_aggregate:
                matched_on = _gcp_match_aggregate(finding, ev, rule)
                resource_label = _gcp_resource_label(finding, rule, None)
            else:
                matched_on = _gcp_match_resource(finding, ev, rule)
                resource_label = _gcp_resource_label(finding, rule, finding_name)
            if not matched_on:
                continue

            try:
                correlation = build_google_cloud_correlation(
                    finding=finding,
                    event=ev,
                    rule=rule,
                    matched_on=matched_on,
                    resource_label=resource_label,
                )
                outcome, _row = upsert_correlation(
                    workspace_id=workspace_id, correlation=correlation, db=db
                )
                if outcome == "created":
                    created += 1
                else:
                    skipped += 1
            except Exception:  # noqa: BLE001
                import logging
                logging.getLogger(__name__).warning(
                    "gcp_correlations: failed one correlation; continuing"
                )
                continue

    return {
        "provider": PROVIDER_GOOGLE_CLOUD,
        "findings_scanned": len(findings),
        "events_scanned": len(events),
        "correlations_created": created,
        "correlations_skipped": skipped,
    }
