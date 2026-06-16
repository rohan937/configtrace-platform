"""Normalized security activity-event storage (M66.2).

The data spine for the future Incident Signals product. Provider-agnostic
helpers to normalize, sanitize, fingerprint, idempotently store, and list
control-plane activity events (GitHub audit-log events initially).

CLAIM DISCIPLINE: this module stores normalized *activity events* only. It does
NOT detect breaches, identify attackers, or confirm compromise. Correlation that
turns activity + configuration risk into incident signals is a future milestone.

Privacy contract (mirrors security_beta_event_service):
  * ``metadata`` keys not in ALLOWED_METADATA_KEYS are silently dropped.
  * Only scalar values (str/int/float/bool) are kept; nested objects/arrays
    dropped; strings truncated to MAX_STR_LEN.
  * Source IP, if present, is stored ONLY as a salted hash — never raw.
  * Raw request bodies / full audit payloads / secrets / tokens are never stored.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.models.security_activity_event import SecurityActivityEvent

# Small allowlist of non-sensitive metadata keys. Anything else is dropped.
ALLOWED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "action",            # raw provider action string (e.g. "protected_branch.destroy")
        # Cloudflare security/audit activity fields (M68.1).
        "zone_id",           # Cloudflare zone id
        "zone_name",         # Cloudflare zone name (domain)
        "actor",             # actor email/id who made the change
        "rule_id",           # WAF/firewall/page rule id
        "rule_name",         # WAF/firewall/page rule name
        "setting_name",      # zone setting key (M68.3) — e.g. "security_level"
        "policy_id",         # Access policy id (M68.3)
        "policy_name",       # Access policy name (M68.3)
        # Cloudflare WAF/security-event fields (M68.4) — request-defense events.
        "ruleset_id",        # firewall ruleset id
        "ruleset_name",      # firewall ruleset name
        "client_country",    # 2-letter country code (not the IP)
        "method",            # HTTP method
        "host",              # request host (zone hostname, not a full URL)
        "path_hash",         # salted hash of the request path (NEVER the raw path)
        "path_prefix",       # sanitized, truncated leading path segment (or omitted)
        "ray_id",            # Cloudflare ray id (request identifier)
        "service",           # event source/service (e.g. "waf", "firewallrules")
        "severity",          # provider-reported severity label
        "outcome",           # action result (success / failure)
        "repository",        # "owner/repo"
        "visibility",        # public/private/internal
        "ref",               # branch/ref name
        "hook_id",           # webhook id
        "permission",        # permission level name
        "alert_number",      # secret-scanning alert number
        "target_login",      # affected collaborator login (control-plane)
        "ruleset_name",      # ruleset name
        "transport",         # http/https for a webhook target
        # AWS provider security-alert fields (M67.1) — GuardDuty / Access Analyzer.
        "finding_type",      # GuardDuty Type / Access Analyzer finding type
        "severity_label",    # critical/high/medium/low (derived)
        "severity_score",    # numeric provider severity
        "title",             # safe provider finding title
        "account_id",        # AWS account id
        "region",            # AWS region
        "service_name",      # GuardDuty service name
        "detector_id",       # GuardDuty detector id
        "analyzer_arn",      # Access Analyzer analyzer ARN
        "finding_status",    # ACTIVE/ARCHIVED/RESOLVED
        # AWS CloudTrail management-event fields (M67.5) — control-plane activity.
        "event_name",        # CloudTrail EventName (e.g. "CreateAccessKey")
        "event_source",      # CloudTrail eventSource (e.g. "iam.amazonaws.com")
        "aws_region",        # CloudTrail awsRegion
        "user_type",         # userIdentity.type (IAMUser / AssumedRole / Root / …)
        "principal_id_hash", # salted hash of userIdentity.principalId (never raw)
        "user_name",         # IAM user name (control-plane identity)
        "role_name",         # IAM role name (assumed-role session issuer)
        "resource_name",     # safe resource identifier from event Resources
        "resource_arn",      # safe resource ARN from event Resources
        "error_code",        # CloudTrail errorCode (e.g. "AccessDenied")
        "read_only",         # whether the API call was read-only
        "event_category",    # "Management" (data events are out of scope)
        "management_event",  # whether CloudTrail flagged this a management event
        "recipient_account_id",  # account the event was delivered to
        # AWS Security Hub (ASFF) fields (M67.7) — provider-reported findings.
        "finding_title",     # ASFF Title
        "finding_description",  # ASFF Description (truncated)
        "severity_normalized",  # ASFF Severity.Normalized (0-100)
        "workflow_status",   # ASFF Workflow.Status (NEW/NOTIFIED/RESOLVED/…)
        "record_state",      # ASFF RecordState (ACTIVE/ARCHIVED)
        "compliance_status", # ASFF Compliance.Status (PASSED/FAILED/…)
        "product_name",      # ASFF ProductName (GuardDuty/Inspector/Macie/…)
        "company_name",      # ASFF CompanyName
        "generator_id",      # ASFF GeneratorId (safe rule/control id)
        "created_at",        # ASFF CreatedAt (ISO string)
        "updated_at",        # ASFF UpdatedAt (ISO string)
        # AWS S3 object-level data-event fields (M67.8) — CloudTrail data events.
        "bucket_name",       # S3 bucket name (a resource identifier, not data)
        "object_key_hash",   # salted hash of the object key (NEVER the raw key)
        "object_key_prefix", # sanitized, truncated top-level prefix (or omitted)
        "bytes_transferred", # additionalEventData bytes in+out (int)
        # AWS VPC Flow Log fields (M67.10) — network flow activity.
        "version",           # flow log format version
        "interface_id",      # ENI id (network resource identifier)
        "src_port",          # source port (int)
        "dst_port",          # destination port (int)
        "protocol",          # IANA protocol number (int)
        "packets",           # packet count (int)
        "bytes",             # byte count (int)
        "action",            # ACCEPT / REJECT
        "log_status",        # OK / NODATA / SKIPDATA
        "start_time",        # flow start (ISO string)
        "end_time",          # flow end (ISO string)
        "destination_ip_hash",  # salted hash of the destination IP (NEVER raw)
        # GitHub secret-scanning alert fields (M69.4A) — provider-reported alert
        # evidence ONLY (NEVER the raw secret, token, credential value, or code).
        "repository_full_name",  # "owner/repo" (alert's repository)
        "state",                 # alert state: open / resolved
        "resolution",            # resolution reason (resolved/revoked/false_positive/…)
        "secret_type",           # secret_type machine key (e.g. "github_personal_access_token")
        "secret_type_display_name",  # human label (e.g. "GitHub Personal Access Token")
        "validity",              # active / inactive / unknown (GitHub validity check)
        "publicly_leaked",       # whether GitHub observed the secret publicly leaked (bool)
        "resolved_at",           # ISO timestamp the alert was resolved (or omitted)
        "location_count",        # safe COUNT of alert locations (never raw paths/code)
        "alert_url_hash",        # salted hash of the alert HTML URL (never the raw URL)
        # GitHub code-scanning alert fields (M69.4D) — provider-reported SAST
        # alert evidence ONLY (NEVER raw SARIF, code snippets, file contents,
        # raw locations/paths, raw alert URL, or the raw API response).
        "tool_name",                 # analysis tool (e.g. "CodeQL")
        "security_severity_level",   # GitHub security severity (critical/high/medium/low)
        "dismissed_reason",          # why an alert was dismissed (false positive / won't fix / used in tests)
        "rule_description",          # short, safe rule description (truncated by sanitizer)
        "fixed_at",                  # ISO timestamp the alert was fixed (or omitted)
        "dismissed_at",              # ISO timestamp the alert was dismissed (or omitted)
        "instances_count",           # safe COUNT of alert instances (never raw locations)
        # GitHub Dependabot alert fields (M69.4G) — provider-reported vulnerable-
        # dependency alert evidence ONLY (NEVER raw advisory bodies, raw manifest/
        # file paths, the raw dependency-graph response, or the raw API response).
        "dependency_package_name",   # vulnerable package name (e.g. "lodash")
        "dependency_ecosystem",      # package ecosystem (e.g. "npm", "pip")
        "vulnerable_version_range",  # affected version range (e.g. "< 4.17.21")
        "patched_versions",          # first patched version label (safe string)
        "advisory_ghsa_id",          # GHSA advisory id (public identifier)
        "advisory_cve_id",           # CVE id (public identifier)
        "advisory_severity",         # advisory severity (low/medium/high/critical)
        "advisory_summary",          # short, safe advisory summary (truncated)
        "cvss_score",                # CVSS base score (float)
        "epss_percentage",           # EPSS probability (float)
        "scope",                     # dependency scope (runtime / development)
        # Vercel audit/activity fields (M70B) — control-plane change activity ONLY.
        # NEVER env var values, deploy hook URLs, tokens, headers, raw payloads,
        # actor emails, or the raw API response.
        "project_id",                # Vercel project id (prj_xxx)
        "project_name",              # Vercel project slug/name
        "team_id",                   # Vercel team id (when present)
        "event_action",              # raw Vercel audit action string (e.g. "env.create")
        "target_type",               # affected object type (project/domain/env/deploy_hook/deployment)
        "target_id",                 # affected object id (never a secret)
        "target_name",               # affected object name (never a secret value)
        "domain",                    # custom domain name involved in the event
        "env_var_key",               # env var KEY name only (NEVER the value)
        "deploy_hook_name",          # deploy hook user-visible name (NEVER the URL)
        "branch",                    # git branch / ref involved in the event
        "deployment_id",             # Vercel deployment id (dpl_xxx)
        "deployment_target",         # "production" / "preview" / "staging"
        "event_time",                # ISO event timestamp (string)
        # Supabase audit/activity fields (M71B) — control-plane change activity
        # ONLY. NEVER database row data, SQL result rows, auth users, emails, JWT
        # secrets, service-role/anon keys, database passwords, tokens, headers,
        # raw API responses, policy expressions, Edge Function env var values, or
        # private member identities.
        "project_ref",               # Supabase project reference (20-char slug, not a secret)
        "organization_id",           # Supabase organization slug/id (when present)
        "schema_name",               # affected schema name (e.g. "public")
        "table_name",                # affected table name (a name, never row data)
        "policy_name",               # RLS policy NAME only (never the USING/WITH CHECK expression)
        "policy_command",            # policy command verb (SELECT/INSERT/UPDATE/DELETE/ALL)
        "storage_bucket_id",         # storage bucket id (a name/identifier)
        "storage_bucket_name",       # storage bucket name (never file contents/object names)
        "edge_function_id",          # Edge Function id/slug (never source or env var values)
        "edge_function_name",        # Edge Function name (never source or env var values)
        "auth_setting_name",         # auth configuration setting key name (never a secret value)
        # Firebase / Google Cloud Audit Log fields (M72B) — control-plane change
        # activity ONLY. NEVER Firestore documents, Realtime Database data, storage
        # object contents, auth users, emails, private keys, service-account JSON
        # secrets, tokens, authorization/raw headers, raw API responses, raw rule
        # source, request/response bodies, Cloud Function env var values, or
        # private member identities (actor email/name).
        "project_number",            # Firebase/GCP project number (an identifier, not a secret)
        "method_name",               # audit-log methodName (e.g. "...UpdateRelease")
        "ruleset_name",              # ruleset/release NAME only (never the raw rules source)
        "database_instance",         # Realtime Database instance name
        "storage_bucket_name",       # Cloud Storage bucket name (never object contents)
        "function_name",             # Cloud Function name (never source or env var values)
        "function_region",           # Cloud Function region
        "app_id",                    # Firebase app id
        "app_platform",              # Firebase app platform (web/ios/android)
        "hosting_site_id",           # Firebase Hosting site id
        # Stripe configuration-event fields (M73B) — control-plane change activity
        # ONLY. NEVER customer PII / emails, payment method data, card data,
        # charges / payment intents / invoices / customer records, raw event
        # payloads, raw API responses, OAuth tokens, signing secrets, auth headers,
        # request/response bodies, bank account details, or tax IDs.
        "stripe_event_type",         # raw Stripe event type string (e.g. "webhook_endpoint.updated")
        "object_type",               # data.object.object NAME (e.g. "webhook_endpoint")
        "object_id",                 # data.object.id (e.g. "we_xxx") — a Stripe object id, never a secret
        "webhook_endpoint_id",       # Stripe webhook endpoint id (we_xxx)
        "webhook_url_domain",        # webhook delivery URL host only (NEVER query strings/full URL)
        "webhook_url_scheme",        # webhook delivery URL scheme (http/https)
        "payment_link_id",           # Stripe payment link id (plink_xxx)
        "portal_config_id",          # Stripe billing-portal configuration id (bpc_xxx)
        "capability",                # Stripe capability NAME (e.g. "card_payments") — a key, not a value
        "capability_status",         # Stripe capability status (active/pending/inactive)
        "tax_setting_name",          # Tax-settings setting NAME (deferred; supported for future use)
        "livemode",                  # bool — Stripe live vs test mode
        # Shopify configuration-event fields (M74B) — control-plane change
        # activity ONLY. NEVER access tokens, private app secrets, webhook
        # signing secrets, raw webhook payloads, raw event payloads, raw API
        # responses, customer PII / emails, orders, carts/checkouts with buyer
        # data, payment method data, card data, refunds, fulfillments,
        # authorization headers, request/response bodies, bank-account
        # details, tax IDs, or staff names/emails.
        "shop_domain",               # Shopify shop domain (e.g. "mystore.myshopify.com")
        "myshopify_domain",          # canonical .myshopify.com domain
        "shopify_event_type",        # raw subject_type/verb (e.g. "Webhook/create")
        "webhook_id",                # Shopify webhook id (numeric/string id, not a secret)
        "webhook_topic",             # webhook topic (e.g. "orders/create") — a topic NAME, not payload
        "webhook_endpoint_domain",   # webhook delivery URL host only
        "webhook_endpoint_scheme",   # webhook URL scheme (http/https)
        "app_scope_count",           # safe COUNT of granted app scopes
        "app_scopes_sample",         # sanitized, truncated, joined-string sample of scope NAMES
        "domain_id",                 # Shopify shop-domain id (an identifier, not a secret)
        "domain_host",               # shop-domain host (a NAME, never DNS records)
        "policy_type",               # store policy type (e.g. "refund_policy") — a NAME, not body
        # Azure Activity Log fields (M77D) — control-plane management events ONLY.
        # NEVER the raw event payload (``properties``), caller email/UPN/name,
        # principal ID/object-ID, authorization/claims objects, httpRequest body,
        # correlation ID raw value, storage keys, SAS tokens, connection strings,
        # Key Vault secret names/values, certificate material, key material,
        # database contents, VM user data, app setting names/values, env var values,
        # or any customer / workload data.
        "subscription_id",           # Azure subscription GUID (an opaque identifier, not a secret)
        "resource_group",            # resource group name (infra identifier)
        "resource_id",               # full ARM resource ID path (infra identifier)
        "resource_type",             # ARM resource type (e.g. Microsoft.Network/networkSecurityGroups)
        "operation_name",            # ARM operationName (e.g. "Microsoft.Network/networkSecurityGroups/write")
        "operation_family",          # operation namespace+resource (e.g. "Microsoft.Network/networkSecurityGroups")
        "operation_action",          # operation verb (e.g. "write", "delete")
        "azure_event_id",            # eventDataId UUID (opaque stable event identifier)
        "azure_correlation_id_hash", # salted hash of correlationId (NEVER the raw GUID)
        "scope_type",                # role assignment scope category (subscription/resource_group)
        "role_definition_name",      # resolved built-in role name (Owner/Contributor/…; not PII)
        "principal_type",            # principalType category string (User/Group/ServicePrincipal; not PII)
        "nsg_name",                  # NSG resource name (infra identifier)
        "nsg_rule_name",             # NSG security rule name (infra identifier)
        "storage_account_name",      # Storage Account resource name (infra identifier)
        "key_vault_name",            # Key Vault resource name (infra identifier)
        "app_service_name",          # App Service resource name (infra identifier)
        "sql_server_name",           # SQL Server resource name (infra identifier)
        "sql_firewall_rule_name",    # SQL firewall rule resource name (infra identifier)
        "aks_cluster_name",          # AKS managed cluster resource name (infra identifier)
        "status",                    # operation status (e.g. "Succeeded") — not PII
        "sub_status",                # operation sub-status (e.g. "Created") — not PII
        "category",                  # Activity Log event category (e.g. "Administrative") — not PII
        # Google Cloud Audit Log fields (M78D) — Admin Activity control-plane events ONLY.
        # NEVER the raw protoPayload object, request/response/metadata objects,
        # authenticationInfo (principalEmail), authorizationInfo, requestMetadata
        # (callerIp, userAgent), serviceAccountDelegationInfo, resource.labels
        # (may contain SA emails), raw operation IDs, raw correlation IDs,
        # secret names/values, database names/users/passwords, connection strings,
        # Cloud SQL query logs, Cloud Storage object keys, Cloud Run env var
        # names/values, service account emails, or any customer/workload data.
        "project_id",                # GCP project id (infra identifier, not a secret)
        "google_cloud_event_id",     # Cloud Logging insertId (opaque stable entry id)
        "google_cloud_operation_id_hash",  # salted hash of operation.id (NEVER raw)
        "method_name",               # audit-log methodName (e.g. "compute.firewalls.insert")
        "service_name",              # audit-log serviceName (e.g. "compute.googleapis.com")
        "resource_name",             # GCP resource path — only if no email segment
        "resource_type",             # Cloud Logging resource.type (e.g. "gce_firewall_rule")
        "operation_name",            # mirrors method_name for cross-provider consistency
        "operation_family",          # method namespace (e.g. "compute.firewalls")
        "operation_action",          # method final verb (e.g. "insert")
        "status_code",               # protoPayload.status.code (int — 0 = success)
        "status_message_safe",       # truncated, safe protoPayload.status.message
        "network_name",              # VPC network name (infra identifier)
        "firewall_rule_name",        # GCE firewall rule name (infra identifier)
        "bucket_name",               # Cloud Storage bucket name (infra identifier)
        "sql_instance_name",         # Cloud SQL instance name (infra identifier)
        "run_service_name",          # Cloud Run service name (infra identifier)
        "gke_cluster_name",          # GKE cluster name (infra identifier)
        "event_time",                # ISO event timestamp (string)
        # Twilio Monitor activity fields (M79D) — control-plane configuration-change
        # events ONLY. NEVER auth_token, API key secrets, full account SID, full phone
        # number strings, webhook / callback URL strings, message bodies, call SIDs,
        # call legs, recording data, customer PII (caller name, verification payloads),
        # raw Twilio API response dicts, raw HTTP request or response bodies, or any
        # value that could re-identify a customer or expose a credential.
        "twilio_event_id",           # Twilio Monitor event SID (opaque, safe identifier)
        "twilio_resource_sid_prefix",  # first 8 chars of resource SID only (never full SID)
        "account_sid_prefix",        # first 8 chars of account SID only (never full SID)
        "messaging_service_sid",     # Messaging Service SID (resource identifier)
        "verify_service_sid",        # Verify Service SID (resource identifier)
        "api_key_sid",               # API key SID (identifier only; secret is NEVER stored)
        "phone_number_last4",        # last 4 digits of phone number only (never full number)
        "sender_pool_count",         # safe count of numbers in a sender pool (int)
        "webhook_configured",        # bool — whether a webhook URL is configured
        "sms_url_configured",        # bool — whether an SMS webhook URL is configured
        "voice_url_configured",      # bool — whether a voice webhook URL is configured
        "status_callback_configured",  # bool — whether a status callback URL is configured
        "fallback_url_configured",   # bool — whether a fallback URL is configured
        "inbound_request_url_configured",  # bool — whether an inbound request URL is configured
        "capability_sms",            # bool — SMS capability enabled on the resource
        "capability_voice",          # bool — voice capability enabled on the resource
        "capability_mms",            # bool — MMS capability enabled on the resource
        # SendGrid configuration activity fields (M80D) — control-plane config-state
        # events ONLY. NEVER API key values, bearer tokens, authorization headers,
        # email bodies, subject lines, recipient emails, sender personal emails,
        # suppression recipient emails, template content, raw webhook URLs,
        # raw unsubscribe URLs, raw inbound parse hostnames, message IDs, event payloads,
        # click/open/bounce/delivered/deferred/dropped/spamreport/unsubscribe data,
        # customer data, or PII.
        "sendgrid_event_id",         # stable synthetic event identifier (date-scoped)
        "resource_id",               # resource identifier (api_key_id, sender_id, domain_id)
        "resource_name",             # resource name (truncated; never a secret value)
        "resource_type",             # config surface type (e.g. "api_key", "sender_identity")
        "event_action",              # canonical event action string (e.g. "sendgrid.api_key.updated")
        "operation_name",            # short safe operation label
        "operation_family",          # operation namespace
        "operation_action",          # operation verb
        "category",                  # config surface category
        "status",                    # status label (e.g. "observed")
        "status_code",               # integer status code (when present)
        "api_key_id",                # API key ID (opaque identifier; NEVER the key value)
        "sender_id",                 # sender identity ID (opaque identifier)
        "domain_id",                 # domain authentication ID (opaque identifier)
        "webhook_configured",        # bool — whether a webhook URL is configured
        "event_webhook_enabled",     # bool — whether event webhook delivery is active
        "event_webhook_has_url",     # bool — webhook URL presence (never the URL)
        "event_webhook_event_count", # int — number of enabled webhook event types
        "inbound_parse_enabled",     # bool — whether inbound parse is enabled
        "inbound_parse_spam_check_enabled",  # bool — spam check on inbound parse
        "inbound_parse_send_raw_enabled",    # bool — send_raw on inbound parse
        "mail_setting_name",         # mail setting key name (never setting value)
        "tracking_setting_name",     # tracking setting key name (never setting value)
        "domain_valid",              # bool — whether domain auth passes DNS validation
        "automatic_security",        # bool — whether automatic DKIM rotation is enabled
        "dns_record_count",          # int — count of DNS records (never raw DNS values)
        "sender_verified",           # bool — whether sender identity is verified
        "sender_locked",             # bool — whether sender identity is locked
        "suppression_group_count",   # int — count of ASM suppression groups
    }
)

MAX_STR_LEN = 200
MAX_METADATA_KEYS = 20


def sanitize_activity_metadata(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return a safe, allowlisted, truncated copy of metadata.

    Drops unknown keys, drops nested/complex values, truncates strings. This is
    the privacy gate: secrets/tokens/raw payloads are never on the allowlist, so
    they can never be stored even if a caller passes them.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key not in ALLOWED_METADATA_KEYS:
            continue  # strip unknown / forbidden keys (secrets, tokens, payloads…)
        if isinstance(value, bool):
            out[key] = value
        elif isinstance(value, (int, float)):
            out[key] = value
        elif isinstance(value, str):
            out[key] = value[:MAX_STR_LEN]
        else:
            # Drop None, dicts, lists, and anything else — keep payload flat/safe.
            continue
        if len(out) >= MAX_METADATA_KEYS:
            break
    return out


def _ip_salt() -> bytes:
    """Stable salt for IP hashing.

    Deterministic across runs so re-ingesting the same event yields the same
    hash. Tied to the app encryption key so hashes are not trivially reversible
    via a precomputed rainbow table of the small IPv4 space.
    """
    key = getattr(settings, "ENCRYPTION_KEY", "") or ""
    return ("ct_activity_ip_v1:" + str(key)).encode("utf-8")


def hash_source_ip(ip: Optional[str]) -> Optional[str]:
    """Return a salted, truncated hash of an IP — or None. Never stores raw IP."""
    if not isinstance(ip, str) or not ip.strip():
        return None
    digest = hashlib.sha256(_ip_salt() + ip.strip().encode("utf-8")).hexdigest()
    return digest[:32]


def compute_event_fingerprint(
    *,
    provider: str,
    source: str,
    event_type: str,
    actor_id: Optional[str],
    resource_id: Optional[str],
    occurred_at: Optional[datetime],
) -> str:
    """Deterministic fallback id when the provider gives no stable event id.

    Returns an ``fp:<hash>`` string so the same uniqueness/idempotency guarantee
    (unique on provider_event_id) applies whether or not the provider supplied an
    id.
    """
    occ = occurred_at.isoformat() if isinstance(occurred_at, datetime) else ""
    basis = "|".join(
        [provider, source, event_type, actor_id or "", resource_id or "", occ]
    )
    digest = hashlib.sha256(basis.encode("utf-8")).hexdigest()
    return f"fp:{digest[:40]}"


def normalize_activity_event(
    *,
    provider: str,
    source: str,
    event_type: str,
    occurred_at: Optional[datetime] = None,
    provider_event_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    actor_type: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    source_ip: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
    raw_ref: Optional[str] = None,
) -> dict[str, Any]:
    """Build a clean, privacy-safe normalized event dict ready for upsert.

    Hashes the IP, sanitizes metadata, and supplies a deterministic fingerprint
    when no stable provider event id is present.
    """
    pe_id = provider_event_id if (provider_event_id and str(provider_event_id).strip()) else None
    if pe_id is None:
        pe_id = compute_event_fingerprint(
            provider=provider,
            source=source,
            event_type=event_type,
            actor_id=actor_id,
            resource_id=resource_id,
            occurred_at=occurred_at,
        )
    return {
        "provider": provider,
        "source": source,
        "event_type": event_type,
        "provider_event_id": pe_id,
        "occurred_at": occurred_at,
        "actor_id": (actor_id[:MAX_STR_LEN] if isinstance(actor_id, str) else None),
        "actor_type": (actor_type[:MAX_STR_LEN] if isinstance(actor_type, str) else None),
        "resource_type": (resource_type[:MAX_STR_LEN] if isinstance(resource_type, str) else None),
        "resource_id": (resource_id[:MAX_STR_LEN] if isinstance(resource_id, str) else None),
        "source_ip_hash": hash_source_ip(source_ip),
        "metadata": sanitize_activity_metadata(metadata),
        "raw_ref": (raw_ref[:MAX_STR_LEN] if isinstance(raw_ref, str) else None),
    }


def upsert_activity_event(
    *,
    workspace_id: uuid.UUID,
    integration_id: Optional[uuid.UUID],
    normalized: dict[str, Any],
    db: Session,
) -> tuple[str, SecurityActivityEvent]:
    """Idempotently store a normalized event.

    Returns ``("inserted", row)`` for a new event or ``("skipped", row)`` if an
    event with the same ``(workspace_id, provider, source, provider_event_id)``
    already exists. Re-ingesting the same provider event is a safe no-op.
    """
    provider = normalized["provider"]
    source = normalized["source"]
    provider_event_id = normalized.get("provider_event_id")

    existing = _find_existing(
        db,
        workspace_id=workspace_id,
        provider=provider,
        source=source,
        provider_event_id=provider_event_id,
    )
    if existing is not None:
        return "skipped", existing

    event = SecurityActivityEvent(
        workspace_id=workspace_id,
        integration_id=integration_id,
        provider=provider,
        source=source,
        provider_event_id=provider_event_id,
        event_type=normalized["event_type"],
        actor_id=normalized.get("actor_id"),
        actor_type=normalized.get("actor_type"),
        resource_type=normalized.get("resource_type"),
        resource_id=normalized.get("resource_id"),
        source_ip_hash=normalized.get("source_ip_hash"),
        occurred_at=normalized.get("occurred_at"),
        event_metadata=normalized.get("metadata") or {},
        raw_ref=normalized.get("raw_ref"),
    )
    db.add(event)
    try:
        db.commit()
    except IntegrityError:
        # Concurrent insert of the same event hit the unique index — treat as skip.
        db.rollback()
        existing = _find_existing(
            db,
            workspace_id=workspace_id,
            provider=provider,
            source=source,
            provider_event_id=provider_event_id,
        )
        if existing is not None:
            return "skipped", existing
        raise
    db.refresh(event)
    return "inserted", event


def _find_existing(
    db: Session,
    *,
    workspace_id: uuid.UUID,
    provider: str,
    source: str,
    provider_event_id: Optional[str],
) -> Optional[SecurityActivityEvent]:
    if not provider_event_id:
        return None
    return (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == provider,
            SecurityActivityEvent.source == source,
            SecurityActivityEvent.provider_event_id == provider_event_id,
        )
        .first()
    )


def list_activity_events(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    provider: Optional[str] = None,
    event_type: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[SecurityActivityEvent], int]:
    """Return a paginated, workspace-scoped list of activity events.

    Newest activity first (by ``occurred_at``, then ingestion order). Strictly
    workspace-scoped — never returns another workspace's events.
    """
    page = max(1, page)
    page_size = max(1, min(page_size, 100))

    q = db.query(SecurityActivityEvent).filter(
        SecurityActivityEvent.workspace_id == workspace_id
    )
    if provider:
        q = q.filter(SecurityActivityEvent.provider == provider)
    if event_type:
        q = q.filter(SecurityActivityEvent.event_type == event_type)

    total = q.count()
    items = (
        q.order_by(
            SecurityActivityEvent.occurred_at.desc().nullslast(),
            SecurityActivityEvent.created_at.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return items, total


def get_activity_event(
    *,
    event_id: uuid.UUID,
    workspace_id: uuid.UUID,
    db: Session,
) -> Optional[SecurityActivityEvent]:
    """Return a single activity event scoped to the workspace, or None (→ 404).

    Strictly workspace-scoped — never returns another workspace's event.
    """
    return (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.id == event_id,
            SecurityActivityEvent.workspace_id == workspace_id,
        )
        .first()
    )
