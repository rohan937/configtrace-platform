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
        # Auth0 configuration activity fields (M81D) — control-plane config-state
        # events ONLY. Auth0 Management API logs (/api/v2/logs) are NEVER ingested
        # because they include user_id, email, IP address, and device data.
        # Events are synthesized from safe drift surfaces instead.
        # NEVER stored: client_secret, management_api_token, access/refresh/ID tokens,
        # JWTs, JWKS, raw callback/logout/origin URLs, audience URIs, custom domain
        # name strings, rule/action script content, action secret values, user emails,
        # user IDs, user names, profile data, IP addresses, device fingerprints,
        # session data, MFA enrollment data, recovery codes, connection credentials,
        # social provider secrets, SAML certificates, raw Auth0 API responses, or PII.
        "auth0_event_id",            # stable synthetic event identifier (day-scoped)
        "client_id",                 # Auth0 client ID (opaque identifier; NEVER client_secret)
        "connection_id",             # Auth0 connection ID (opaque identifier)
        "resource_server_id",        # Auth0 resource server ID (opaque identifier)
        "action_id",                 # Auth0 action ID (opaque identifier; NEVER code or secrets)
        "factor_name",               # MFA factor name (e.g. "otp", "webauthn-roaming")
        "custom_domain_id",          # Auth0 custom domain ID (opaque identifier; NEVER domain string)
        "tenant_id",                 # Auth0 tenant identifier (opaque)
        "callbacks_count",           # int — count of configured callback URLs (NEVER raw URLs)
        "allowed_logout_urls_count", # int — count of allowed logout URLs (NEVER raw URLs)
        "allowed_origins_count",     # int — count of allowed origins (NEVER raw URLs)
        "web_origins_count",         # int — count of web origins (NEVER raw URLs)
        "grant_types_count",         # int — count of OAuth grant types enabled
        "app_type",                  # safe category (e.g. "spa", "native", "regular_web")
        "is_first_party",            # bool — whether application is first-party
        "jwt_alg",                   # JWT signing algorithm (e.g. "RS256") — never a key
        "oidc_conformant",           # bool — OIDC conformance setting
        "token_endpoint_auth_method",  # safe category (e.g. "client_secret_basic", "none")
        "refresh_token_rotation_enabled",  # bool — whether token rotation is enabled
        "refresh_token_lifetime_category", # safe category (e.g. "standard", "extended")
        "enabled_clients_count",     # int — count of enabled client applications on a connection
        "password_policy_category",  # safe category (e.g. "good", "fair") — never raw policy
        "signing_alg",               # resource server signing algorithm (e.g. "RS256")
        "token_lifetime_category",   # safe category (e.g. "standard", "extended")
        "allow_offline_access",      # bool — whether resource server allows offline access
        "rbac_enabled",              # bool — whether resource server enforces RBAC
        "script_present",            # bool — whether a rule has a script (NEVER script content)
        "script_length_category",    # safe category (e.g. "short", "medium", "long")
        "code_present",              # bool — whether an action has code (NEVER code content)
        "code_length_category",      # safe category (e.g. "short", "medium", "long")
        "secrets_count",             # int — count of action secrets (NEVER names or values)
        "enabled",                   # bool — whether a rule or factor is enabled
        "status_category",           # safe status category (e.g. "ready", "pending_verification")
        "grant_password_enabled",    # bool — whether password grant is enabled
        "grant_implicit_enabled",    # bool — whether implicit grant is enabled
        "grant_client_credentials_enabled",  # bool — whether client_credentials grant is enabled
        "grant_refresh_token_enabled",  # bool — whether refresh_token grant is enabled
        "grant_device_code_enabled", # bool — whether device_code grant is enabled
        "wildcard_callback_present", # bool — wildcard in callbacks (NEVER raw URLs)
        "wildcard_allowed_origin_present",  # bool — wildcard in origins (NEVER raw URLs)
        "wildcard_logout_url_present",  # bool — wildcard in logout URLs (NEVER raw URLs)
        "localhost_callback_present", # bool — localhost callback present (NEVER raw URLs)
        "localhost_origin_present",  # bool — localhost origin present (NEVER raw URLs)
        "callbacks_missing_https",   # bool — any non-localhost callback uses http://
        "allowed_origins_missing_https",  # bool — any non-localhost origin uses http://
        "session_lifetime_category", # safe category (e.g. "standard", "extended")
        "idle_session_lifetime_category",  # safe category for idle session lifetime
        "enabled_locales_count",     # int — count of enabled locales on tenant
        "flag_enable_dynamic_client_registration",  # bool — dynamic client registration flag
        "flag_revoke_refresh_token_grant",  # bool — revoke refresh token grant flag
        "flag_universal_login",      # bool — universal login flag
        "deployed_version_present",  # bool — whether an action has a deployed version
        "scopes_count",              # int — count of scopes on a resource server
        "provider_category",         # safe MFA factor category (e.g. "totp", "webauthn")
        "tls_policy_category",       # safe TLS policy category (e.g. "recommended", "compatible")
        # Datadog configuration activity fields (M82D) — config-state observations
        # synthesized from 10 safe drift surfaces. NEVER stored: API key values,
        # application key values, OAuth/bearer tokens, webhook secrets, raw monitor
        # queries, raw monitor messages, raw dashboard JSON, widget queries, webhook
        # URLs, custom header names/values, payload templates, notification handles,
        # Slack channel names, PagerDuty service IDs, email addresses, user IDs,
        # user names, team member identities, IP addresses, user agents, raw Datadog
        # audit payloads, raw API response dicts, logs, traces, metric values,
        # incident content, or PII.
        "datadog_event_id",          # opaque Datadog audit event ID (never actor/IP/raw payload)
        "monitor_id",                # Datadog monitor ID (opaque identifier, not a secret)
        "slo_id",                    # Datadog SLO ID (opaque identifier)
        "dashboard_id",              # Datadog dashboard ID (opaque identifier)
        "notification_integration_id",  # Datadog notification integration record ID
        "application_key_id",        # Datadog application key ID (identifier only; NEVER key value)
        "role_id",                   # Datadog role ID (opaque identifier)
        "team_id",                   # Datadog team ID (opaque identifier)
        "cloud_integration_id",      # Datadog cloud integration record ID
        "monitor_type",              # Datadog monitor type label (e.g. "metric alert")
        "priority_category",         # Datadog monitor priority category (e.g. "critical")
        "query_present",             # bool — whether monitor query is set (NEVER raw query)
        "query_complexity_category", # safe category (e.g. "short", "medium", "long")
        "message_present",           # bool — whether monitor message is set (NEVER raw message)
        "message_length_category",   # safe category (e.g. "short", "medium", "long")
        "notification_count",        # int — count of @ mentions in monitor message
        "notification_channel_count",  # int — count of notification channels configured
        "notification_at_mention_count",  # int — count of @-mention targets (count only)
        "notification_routing_present",  # bool — whether monitor message contains @ mentions
        "message_template_present",  # bool — whether monitor message uses {{ template vars
        "query_uses_wildcard_scope", # bool — whether monitor query uses {*} wildcard
        "query_uses_not_operator",   # bool — whether monitor query uses NOT operator
        "query_group_by_count",      # int — count of group-by clauses in query
        "query_metric_count_category",  # safe category for number of metrics in query
        "query_window_category",     # safe category for query evaluation window
        "threshold_critical_present",  # bool — critical threshold is configured
        "threshold_warning_present",   # bool — warning threshold is configured
        "threshold_recovery_present",  # bool — recovery threshold is configured
        "threshold_count",           # int — total count of threshold entries
        "renotify_enabled",          # bool — whether re-notification is enabled
        "renotify_interval_category",  # safe category (e.g. "disabled", "short", "medium")
        "renotify_occurrences_category",  # safe category for re-notify occurrence count
        "silenced_scope_count",      # int — count of silenced scope entries
        "new_group_delay_category",  # safe category for new_group_delay setting
        "no_data_timeframe_category",  # safe category (e.g. "none", "short", "extended")
        "require_full_window",       # bool — whether full evaluation window is required
        "locked",                    # bool — whether monitor is locked to creator
        "restricted_roles_count",    # int — count of roles that can edit the resource
        "include_tags",              # bool — whether monitor includes tags in notifications
        "notify_audit",              # bool — whether audit notifications are enabled
        "slo_type",                  # Datadog SLO type label (e.g. "metric", "monitor")
        "target_category",           # SLO target percentage category
        "warning_target_category",   # SLO warning target percentage category
        "timeframe_count",           # int — count of SLO threshold/timeframe windows
        "monitor_count",             # int — count of monitors linked to an SLO
        "group_count",               # int — count of groups in SLO
        "tag_count",                 # int — count of tags on the resource
        "layout_type",               # Datadog dashboard layout type (e.g. "ordered", "free")
        "widget_count",              # int — count of dashboard widgets
        "template_variable_count",   # int — count of dashboard template variables
        "public_url_present",        # bool — whether dashboard has a public URL
        "url_present",               # bool — whether a URL is configured (NEVER the URL)
        "url_scheme_category",       # safe category (e.g. "https", "http", "absent")
        "url_host_present",          # bool — whether URL host is present (NEVER hostname)
        "custom_headers_present",    # bool — whether custom headers are configured
        "custom_header_count",       # int — count of custom header entries (NEVER names/values)
        "secret_headers_present",    # bool — whether secret headers are configured
        "secret_headers_count",      # int — count of secret header entries (NEVER names/values)
        "payload_template_present",  # bool — whether payload template is configured
        "payload_template_length_category",  # safe category (never template content)
        "uses_custom_payload",       # bool — whether custom payload encoding is used
        "encode_as_category",        # safe category (e.g. "json", "form", "unknown")
        "auth_material_present",     # bool — whether auth-like header names are present
        "auth_material_count",       # int — count of auth-like header entries
        "integration_type",          # notification integration type (e.g. "pagerduty")
        "handle_count",              # int — count of handles/services configured
        "channel_count",             # int — count of channels configured (count only)
        "created_present",           # bool — whether a creation timestamp exists
        "modified_present",          # bool — whether a modification timestamp exists
        "created_by_present",        # bool — whether created_by metadata exists
        "owned_by_present",          # bool — whether owned_by metadata exists
        "permission_count",          # int — count of permissions assigned to a role
        "user_count",                # int — count of users in role (NEVER identities)
        "team_count",                # int — count of teams in role (NEVER identities)
        "member_count",              # int — count of team members (NEVER identities)
        "handle_present",            # bool — whether team handle is set (NEVER the handle)
        "link_count",                # int — count of team links configured
        "cloud_provider",            # cloud integration provider ("aws"/"gcp"/"azure")
        "account_id_present",        # bool — whether account ID is set (NEVER the ID)
        "resource_collection_enabled",  # bool — whether resource collection is enabled
        "metric_collection_enabled", # bool — whether metric collection is enabled
        "log_collection_enabled",    # bool — whether log collection is enabled
        "account_tags_count",        # int — count of account-level tags configured
        "namespace_count",           # int — count of metric namespaces configured
        # Clerk configuration activity fields (M83D) — config-state observation
        # events synthesized from safe Clerk drift surfaces. NEVER stored:
        # Clerk secret key values, publishable key values, session tokens, JWTs,
        # OAuth tokens, bearer tokens, webhook secrets, raw webhook URLs, raw
        # redirect URLs, raw domain names, JWT template bodies, custom claims,
        # audience URIs, issuer URIs, user emails, user IDs, phone numbers, names,
        # member identities, session history, login history, IP addresses,
        # user agents, raw audit payloads, or PII.
        "clerk_event_id",
        "instance_id",
        "application_id",
        "redirect_url_config_id",
        "jwt_template_id",
        "email_sms_settings_id",
        "auth_strategy_id",
        "organization_settings_id",
        "session_policy_id",
        "environment_type",
        "application_type",
        "sign_up_enabled",
        "sign_in_enabled",
        "email_enabled",
        "phone_enabled",
        "username_enabled",
        "password_enabled",
        "social_provider_count",
        "oauth_provider_count",
        "saml_enabled",
        "passkey_enabled",
        "magic_link_enabled",
        "mfa_enabled",
        "mfa_supported",
        "mfa_required",
        "mfa_factor_count",
        "inactivity_timeout_category",
        "single_session_enabled",
        "device_tracking_enabled",
        "reverification_required",
        "token_rotation_enabled",
        "allowed_redirect_count",
        "redirect_url_count",
        "allowed_origin_count",
        "domain_count",
        "webhook_count",
        "jwt_template_count",
        "organization_enabled",
        "organizations_enabled",
        "verified_domains_required",
        "invitation_enabled",
        "admin_role_present",
        "membership_limit_category",
        "member_count_category",
        "role_count",
        "domain_type",
        "verified",
        "primary",
        "ssl_enabled",
        "dns_status_category",
        "proxy_enabled",
        "wildcard_present",
        "localhost_present",
        "custom_scheme_present",
        "count",
        "claims_count",
        "custom_claims_present",
        "audience_present",
        "issuer_present",
        "lifetime_category",
        "event_count",
        "secret_present",
        "signing_enabled",
        "description_present",
        "sms_enabled",
        "custom_sender_present",
        "template_customization_present",
        "oauth_enabled",
        "email_otp_enabled",
        "phone_otp_enabled",
        "max_allowed_memberships_category",
        "admin_delete_enabled",
        "domains_enabled",
        "domains_enrollment_mode_category",
        "algorithm",
        "name",
        # PagerDuty configuration activity fields (M84D) — config-state observation
        # events synthesized from 8 safe drift surfaces (M84A–M84C). NEVER stored:
        # PagerDuty API tokens, routing keys, integration keys, webhook secrets,
        # delivery URLs, custom header values, user emails, user names, phone numbers,
        # contact methods, on-call user identities, responder identities, subscriber
        # identities, incident payloads, alert payloads, conference phone numbers,
        # raw routing expressions, IP addresses, user agents, raw audit payloads,
        # raw API response dicts, or customer PII.
        "pagerduty_event_id",        # stable synthetic event identifier (day-scoped)
        "integration_type_category", # safe integration type ("email"/"generic_events_api"/"vendor"/"other")
        "key_present",               # bool — whether an integration key is present (NEVER the key)
        "routing_key_present",       # bool — whether a routing key is present (NEVER the key)
        "event_scope_category",      # safe category for webhook filter scope
        "runnable",                  # safe runnability label ("owner"/"team"/"any"/"unknown")
        "conference_present",        # bool — whether conference number is configured (NEVER the number)
        "schedule_target_count",     # int — count of schedule targets (never identities)
        "has_schedule_targets",      # bool — whether any schedule targets are configured
        "repeat_enabled",            # bool — whether escalation policy loops are enabled
        "restriction_count",         # int — count of layer restrictions (never restriction content)
        "has_restrictions",          # bool — whether any layer has time-window restrictions
        "time_zone_present",         # bool — whether a timezone is configured on a schedule
        "responder_count",           # int — count of responders (NEVER identities)
        "subscriber_count",          # int — count of subscribers (NEVER identities)
        # Linear configuration activity fields (M85D) — config-state observation
        # events synthesized from 9 safe drift surfaces (M85A–M85C). NEVER stored:
        # Linear API keys, OAuth tokens, webhook secrets, raw webhook URLs, issue
        # titles, issue descriptions, comment bodies, attachment content, user
        # emails, user names, member identities, customer names, IP addresses,
        # user agents, raw audit payloads, raw API response dicts, or PII.
        "linear_event_id",             # stable synthetic event identifier (day-scoped)
        "url_key_present",             # bool — workspace URL key configured
        "logo_present",                # bool — workspace logo configured
        "team_visibility_category",    # "private" or "public"
        "private_team",                # bool — team privacy flag
        "project_count",               # int — projects in a team (safe count)
        "auto_archive_enabled",        # bool — team auto-archive configured
        "cycle_enabled",               # bool — team cycles (sprints) enabled
        "cycle_duration_category",     # bucketed: none/short/medium/long
        "workflow_state_count",        # int — workflow states per team
        "has_backlog_state",           # bool — backlog state present
        "has_started_state",           # bool — started state present
        "has_completed_state",         # bool — completed state present
        "has_canceled_state",          # bool — cancelled state present
        "project_status_category",     # project lifecycle state (lowercased name)
        "project_health_category",     # ontrack/atrisk/offtrack/noupdate/unknown
        "lead_present",                # bool — project lead assigned
        "issue_count_category",        # bucketed: none/few/moderate/many
        "state_type_category",         # backlog/started/completed/cancelled/unknown
        "position_category",           # early/middle/late (workflow state position)
        "is_group_label",              # bool — label is a group/parent
        "parent_id_present",           # bool — label has a parent label
        "webhook_enabled",             # bool — webhook subscription enabled
        "webhook_secret_present",      # bool — webhook signing secret configured
        "webhook_url_present",         # bool — webhook endpoint URL configured
        "webhook_url_scheme_category", # https/non_https/absent
        "webhook_resource_types_count",# int — count of subscribed resource types
        "webhook_has_comment_type",    # bool — subscribes to Comment events
        "webhook_has_attachment_type", # bool — subscribes to Attachment events
        "view_shared",                 # bool — custom view is shared workspace-wide
        "filter_count_category",       # bucketed: none/few/moderate/many
        "integration_enabled",         # bool — integration is active/enabled
        "integration_count",           # int — count of workspace integrations
        "label_count",                 # int — count of labels for a team
        # Jira configuration activity fields (M86D) — config-state observation
        # events synthesized from 12 safe drift surfaces (M86A–M86C). Events are
        # synthesized from ConfigTrace's stored Jira posture records, NEVER from
        # Jira audit logs, issue APIs, or user activity feeds. NEVER stored:
        # Jira API tokens, OAuth tokens, webhook secrets, raw webhook/delivery
        # URLs, site base URLs, JQL, filter expressions, issue keys, issue
        # titles, issue descriptions, comment bodies, attachment content,
        # customer names, user emails, user names, account IDs, IP addresses,
        # user agents, raw audit payloads, raw API response dicts, or PII.
        "jira_event_id",               # stable synthetic event identifier (day-scoped)
        "site_id",                     # opaque site resource identifier ("site")
        "board_id",                    # Jira board id (opaque identifier)
        "workflow_id",                 # Jira workflow id (opaque identifier)
        "workflow_scheme_id",          # workflow scheme id (opaque identifier)
        "permission_scheme_id",        # permission scheme id (opaque identifier)
        "notification_scheme_id",      # notification scheme id (opaque identifier)
        "issue_type_scheme_id",        # issue type scheme id (opaque identifier)
        "field_configuration_scheme_id",  # field config scheme id (opaque identifier)
        "screen_scheme_id",            # screen scheme id (opaque identifier)
        "automation_rule_id",          # automation rule id (opaque identifier)
        "deployment_type",             # "cloud"/"server"/"unknown" (never base URL)
        "major_version",               # int — major version posture (never build string)
        "build_number",                # int — build number posture
        "scm_info_present",            # bool — whether scmInfo is present
        "has_key",                     # bool — project has a key (NEVER the key value)
        "project_type_key",            # project type category (software/business/…)
        "style",                       # project style category (classic/next-gen)
        "is_private",                  # bool — project privacy flag
        "is_archived",                 # bool — project archived flag
        "is_deleted",                  # bool — project deleted flag
        "is_simplified",               # bool — project simplified (team-managed) flag
        "board_type",                  # board type category (scrum/kanban/simple)
        "location_present",            # bool — board has a location (NEVER the location)
        "board_filter_present",        # bool — board scoped to a saved filter
        "board_jql_filter_broad",      # bool — broad/unbounded filter heuristic (NEVER JQL)
        "board_column_count",          # int — count of board columns (NEVER names)
        "board_quick_filter_count",    # int — count of quick filters (NEVER names/JQL)
        "board_swimlane_strategy_category",  # safe swimlane strategy enum
        "is_default",                  # bool — default scheme/workflow flag
        "transition_count",            # int — count of workflow transitions
        "status_count",                # int — count of workflow statuses
        "has_description",             # bool — scheme/workflow has a description
        "workflow_global_transition_count",  # int — count of global transitions
        "workflow_active",             # bool — workflow active flag
        "workflow_draft",              # bool — workflow draft flag
        "workflow_has_done_status",    # bool — has a "done" category status
        "workflow_has_in_progress_status",  # bool — has an in-progress category status
        "workflow_transition_rule_count",   # int — total validators+conditions+post-functions
        "workflow_validator_count",    # int — count of transition validators
        "workflow_condition_count",    # int — count of transition conditions
        "workflow_post_function_count",  # int — count of transition post-functions
        "workflow_orphan_status_count",  # int — count of orphaned statuses
        "workflow_status_category_count",  # int — count of distinct status categories
        "issue_type_mapping_count",    # int — count of scheme issue-type mappings
        "has_draft",                   # bool — workflow scheme has a draft
        "workflow_scheme_workflow_count",  # int — distinct workflows in a scheme
        "workflow_scheme_issue_type_mapping_count",  # int — issue-type mapping count
        "workflow_scheme_unmapped_issue_type_count", # int — unmapped issue types
        "permission_grant_count",      # int — count of permission grants
        "permission_public_browse_projects",     # bool — public holder can browse
        "permission_public_administer_projects",  # bool — public holder can administer
        "permission_public_manage_sprints",       # bool — public holder can manage sprints
        "permission_public_create_issues",        # bool — public holder can create issues
        "permission_public_transition_issues",    # bool — public holder can transition issues
        "permission_unknown_holder_count",  # int — count of unrecognised holder types
        "permission_high_privilege_grant_count",  # int — public high-privilege grants
        "permission_public_grant_count",  # int — count of grants to public holders
        "notification_all_watchers_recipient_count",  # int — all-watcher recipient count
        "notification_unknown_recipient_count",  # int — unrecognised recipient-type count
        "notification_event_count",    # int — count of notification scheme events
        "has_default_issue_type",      # bool — issue type scheme has a default
        "screen_mapping_count",        # int — count of screen mappings
        "has_default_screen",          # bool — screen scheme has a default screen
        "screen_tab_count",            # int — count of screen tabs (NEVER names)
        "screen_unmapped_screen_count",  # int — count of unmapped operation slots
        "has_filter",                  # bool — webhook has a JQL filter (NEVER the JQL)
        "webhook_has_issue_events",    # bool — webhook subscribes to issue events
        "webhook_has_comment_events",  # bool — webhook subscribes to comment events
        "webhook_has_attachment_events",  # bool — webhook subscribes to attachment events
        "webhook_has_project_events",  # bool — webhook subscribes to project events
        "webhook_has_sprint_events",   # bool — webhook subscribes to sprint events
        "webhook_has_worklog_events",  # bool — webhook subscribes to worklog events
        "webhook_all_issue_events",    # bool — subscribes to all issue lifecycle events
        "webhook_jql_empty_or_broad",  # bool — webhook filter empty/broad (NEVER JQL)
        "webhook_event_scope_category",  # safe scope enum (narrow/medium/broad/unknown)
        "component_count",             # int — count of automation rule components
        "automation_action_count",     # int — count of automation action components
        "automation_condition_count",  # int — count of automation condition components
        "automation_branch_count",     # int — count of automation branch components
        "automation_scope_category",   # safe scope enum (global/multi-project/project)
        "automation_has_web_request_action",  # bool — rule sends an outgoing web request
        "automation_has_email_action",  # bool — rule sends email (NEVER addresses)
        "automation_has_external_action",  # bool — rule posts to an external service
        "automation_has_comment_action",   # bool — rule adds a comment (NEVER content)
        # ── Jira schema-aligned posture fields (M86H) ─────────────────────────
        # Derived booleans / counts / category enums consumed by the M86B base
        # rules.  NEVER any raw URL, key, identity, JQL, email, or secret value.
        "site_url_present",            # bool — site base-URL indicator (NEVER the URL)
        "project_type_category",       # project type enum (software/business/…)
        "project_style_category",      # project style enum (classic/next-gen/unknown)
        "project_key_present",         # bool — project has a key (NEVER the key value)
        "project_private",             # bool — project privacy flag
        "project_archived",            # bool — project archived flag
        "project_deleted",             # bool — project deleted flag
        "project_simplified",          # bool — project simplified (team-managed) flag
        "board_type_category",         # board type enum (scrum/kanban/simple/unknown)
        "board_location_type_category",  # board location enum (project/user/filter/unknown)
        "workflow_status_count",       # int — count of workflow statuses
        "workflow_transition_count",   # int — count of workflow transitions
        "workflow_scheme_project_count",   # int — projects associated with a scheme
        "workflow_scheme_default_present",  # bool — scheme has a default workflow
        "permission_anonymous_grant_count",  # int — grants to anonymous principals
        "permission_anyone_grant_count",     # int — grants to the "anyone" principal
        "permission_logged_in_grant_count",  # int — grants to all logged-in users
        "permission_project_role_grant_count",  # int — grants to project roles
        "notification_email_recipient_count",   # int — single-email recipient count
        "notification_group_recipient_count",   # int — group recipient count
        "notification_project_role_recipient_count",  # int — project-role recipient count
        "issue_type_count",            # int — count of issue types in a scheme
        "default_issue_type_present",  # bool — issue type scheme has a default
        "field_configuration_count",   # int — count of field configurations in a scheme
        "required_field_count",        # int — count of required fields
        "hidden_field_count",          # int — count of hidden fields
        "screen_count",                # int — count of screens in a scheme
        "tab_count",                   # int — count of screen tabs (NEVER names)
        "field_count",                 # int — count of screen fields (NEVER names)
        "webhook_enabled",             # bool — webhook subscription enabled
        "webhook_event_count",         # int — count of subscribed webhook events
        "webhook_jql_filter_present",  # bool — webhook has a JQL filter (NEVER the JQL)
        "automation_enabled",          # bool — automation rule enabled flag
        "automation_trigger_type_category",  # automation trigger enum (issue/scheduled/…)
        "automation_component_count",  # int — count of automation rule components
        # GitLab configuration activity fields (M87D) — config-state observation
        # events synthesized from 9 safe GitLab drift surfaces (M87A–M87C).
        # GitLab audit-event APIs (actor user IDs, emails, IPs, user agents) are
        # NEVER ingested. NEVER stored: GitLab access tokens, OAuth tokens,
        # PRIVATE-TOKEN values, authorization headers, webhook secret tokens,
        # webhook URLs, CI/CD variable names/values, deploy key material, SSH
        # keys, deploy key fingerprints, runner tokens, runner IPs, project/group
        # names, namespace paths, repo URLs, branch names, commit messages, merge
        # request titles, issue titles, pipeline/job logs, artifacts, user
        # emails/names/usernames, customer data, PII, or raw GitLab API payloads.
        "gitlab_event_id",             # stable synthetic event identifier (record+type+observed-at)
        "project_resource_id",         # opaque GitLab project resource identifier
        "owner_resource_id",           # opaque owner (project/group) resource identifier
        "owner_type",                  # owner category ("project"/"group") — never a name
        "visibility_category",         # "public"/"internal"/"private" — never a name/path
        "archived",                    # bool — project archived flag
        "default_branch_present",      # bool — default branch present (NEVER the branch name)
        "issues_enabled",              # bool — project issues feature flag
        "wiki_enabled",                # bool — project wiki feature flag
        "snippets_enabled",            # bool — project snippets feature flag
        "container_registry_enabled",  # bool — project container registry feature flag
        "packages_enabled",            # bool — project packages feature flag
        "shared_runners_enabled",      # bool — project shared runners flag
        "protected_branch_count",      # int — count of protected branches (NEVER names)
        "ci_variable_count",           # int — count of CI/CD variables (NEVER names/values)
        "deploy_key_count",            # int — count of deploy keys (NEVER material/fingerprints)
        "approval_rule_count",         # int — count of MR approval rules
        "subgroup_count",              # int — count of subgroups (NEVER names/paths)
        "two_factor_requirement_enabled",  # bool — group 2FA requirement flag
        "membership_lock",             # bool — group membership lock flag
        "shared_runners_setting_category",  # group shared-runner setting category
        "pattern_category",            # branch protection pattern category (NEVER branch names)
        "allow_force_push",            # bool — branch protection force-push flag
        "code_owner_approval_required",  # bool — code-owner approval requirement
        "push_access_level_category",  # branch push access level category
        "merge_access_level_category", # branch merge access level category
        "allowed_to_push_count",       # int — count of push allowances (NEVER identities)
        "allowed_to_merge_count",      # int — count of merge allowances (NEVER identities)
        "ssl_verification_enabled",    # bool — webhook SSL verification flag
        "webhook_scheme_category",     # webhook URL scheme category ("http"/"https") — never the URL
        "webhook_host_category",       # webhook host category — never the hostname or URL
        "push_events",                 # bool — webhook subscribes to push events
        "pipeline_events",             # bool — webhook subscribes to pipeline events
        "job_events",                  # bool — webhook subscribes to job events
        "variable_count",              # int — count of CI/CD variables (NEVER names/values)
        "protected_variable_count",    # int — count of protected CI/CD variables
        "masked_variable_count",       # int — count of masked CI/CD variables
        "environment_scoped_count",    # int — count of environment-scoped CI/CD variables
        "unprotected_unmasked_count",  # int — count of unprotected+unmasked CI/CD variables
        "write_enabled_count",         # int — count of write-enabled deploy keys
        "read_only_count",             # int — count of read-only deploy keys
        "enabled_count",               # int — count of enabled deploy keys
        "runner_count",                # int — count of runners (NEVER tokens/IPs/descriptions)
        "shared_runner_enabled",       # bool — shared runner enabled posture
        "locked_runner_count",         # int — count of locked runners
        "paused_runner_count",         # int — count of paused runners
        "tagged_runner_count",         # int — count of tagged runners
        "untagged_runner_count",       # int — count of untagged runners
        "approvals_required",          # int — MR approvals required count
        "reset_approvals_on_push",     # bool — MR reset-approvals-on-push posture
        "override_approvers_disabled", # bool — MR per-request approver override disabled posture
        # Terraform Cloud configuration activity fields (M88D) — config-state
        # observation events synthesized from 9 safe drift surfaces (M88A–M88C).
        # Terraform Cloud audit-log APIs (actor user IDs, emails, IPs, user
        # agents) are NEVER ingested.  NEVER stored: Terraform Cloud API tokens,
        # OAuth tokens, VCS tokens, authorization headers, variable names or
        # values, state files, state outputs, resource addresses, plan/apply logs,
        # run logs, webhook URLs, notification tokens, Slack channels, email
        # recipients, user emails, usernames, team names, organization names,
        # workspace names, project names, VCS URLs, branch names, commit SHAs,
        # customer infrastructure data, PII, or raw API payloads of any kind.
        "terraform_cloud_event_id",    # stable synthetic event identifier (record+type+observed-at)
        "organization_resource_id",    # opaque Terraform Cloud org resource identifier
        "workspace_resource_id",       # opaque workspace resource identifier
        "variable_set_resource_id",    # opaque variable set resource identifier
        "policy_set_resource_id",      # opaque policy set resource identifier
        "notification_resource_id",    # opaque notification configuration resource identifier
        "run_trigger_resource_id",     # opaque run trigger resource identifier
        "execution_mode_category",     # workspace execution mode ("remote"/"local"/"agent")
        "terraform_version_category",  # Terraform version category ("pinned"/"latest"/"unknown")
        "auto_apply",                  # bool — workspace auto-apply enabled
        "global_remote_state",         # bool — workspace global remote state sharing enabled
        "vcs_connected",               # bool — workspace VCS connection present
        "queue_all_runs",              # bool — workspace queue-all-runs enabled
        "file_triggers_enabled",       # bool — workspace file-based run triggers enabled
        "speculative_enabled",         # bool — workspace speculative plans enabled
        "run_trigger_count",           # int — count of run triggers on workspace
        "trigger_prefix_count",        # int — count of file trigger prefixes
        "latest_run_status_category",  # workspace latest run status category (safe enum)
        "sensitive_variable_count",    # int — count of sensitive variables
        "non_sensitive_variable_count", # int — count of non-sensitive variables
        "environment_variable_count",  # int — count of environment-category variables
        "terraform_variable_count",    # int — count of Terraform-category variables
        "raw_value_never_read",        # bool — variable raw values are never fetched
        "global_scope",                # bool — variable set / policy set global scope flag
        "workspace_count",             # int — count of workspaces in scope
        "policy_set_count",            # int — count of policy sets in org
        "variable_set_count",          # int — count of variable sets in org
        "policy_count",                # int — count of policies in a policy set
        "enforcement_level_category",  # policy set enforcement level ("mandatory"/"soft_mandatory"/"advisory")
        "destination_type_category",   # notification destination type ("webhook"/"slack"/"email"/"…")
        "trigger_count",               # int — count of notification trigger subscriptions
        "token_present",               # bool — webhook notification token present
        "webhook_url_scheme_category", # notification webhook URL scheme ("http"/"https") — never the URL
        "sourceable_type_category",    # run trigger sourceable type category
        "team_access_count",           # int — count of team access entries on workspace
        "admin_access_count",          # int — count of teams with admin access
        "write_access_count",          # int — count of teams with write access
        "read_access_count",           # int — count of teams with read access
        "plan_access_count",           # int — count of teams with plan access
        "apply_access_count",          # int — count of teams with apply access
        "custom_permission_count",     # int — count of teams with custom permissions
        "state_version_present",       # bool — workspace has a current state version
        "state_version_count_category", # state version count category (never raw count)
        "raw_state_never_fetched",     # bool — raw state files are never fetched or stored
        "sso_enabled",                 # bool — organization SSO enabled flag
        "cost_estimation_enabled",     # bool — organization cost estimation enabled flag
        "notification_count",          # int — count of notification configurations on workspace
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
