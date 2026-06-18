"""Control-plane Incident Signal generation (M66.3).

Reads normalized GitHub audit activity (``security_activity_events``, M66.2) and
produces first-pass **Incident Signals** — control-plane actions that *may
require review*.

CLAIM DISCIPLINE (do not violate):
  Incident signals are REVIEW signals based on audit activity. They do NOT
  confirm a breach, identify an attacker, or confirm compromise/access. Severity
  reflects review priority. Confidence is "high" only because the audit event
  directly states the action occurred — NOT because impact is confirmed.
  ``evidence_level`` is always "activity". Exposure×activity correlation (which
  would raise the evidence tier) is a FUTURE milestone.

Forbidden wording in any generated title/summary: "breach detected",
"attacker found", "compromise confirmed", "someone has access",
"unauthorized access confirmed".

Privacy: signal metadata is allowlisted + flat + truncated; raw audit blobs,
raw IPs, secrets, tokens, and payloads are never stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.security_activity_event import SecurityActivityEvent
from app.models.security_incident_signal import SecurityIncidentSignal

PROVIDER_GITHUB = "github"

# Allowlist of non-sensitive metadata keys carried onto a signal.
ALLOWED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "action",
        "repository",
        "ref",
        "hook_id",
        "permission",
        "ruleset_name",
        "alert_number",
        "actor",
        "event_type",
        # AWS provider-alert fields (M67.1).
        "finding_type",
        "severity_label",
        "account_id",
        "region",
        "service_name",
        # AWS IAM behavior-timeline fields (M67.6) — CloudTrail-derived summary.
        "event_types",        # comma-joined trigger event types (flat string)
        "actor_id",           # IAM principal/user identity for the chain
        "resource_id",        # anchor resource identifier
        "event_count",        # number of trigger events in the chain
        "window_start",       # ISO timestamp of the chain window start
        "window_end",         # ISO timestamp of the chain window end
        "principal_hash",     # salted hash of the IAM principalId (never raw)
        "policy_name",        # safe policy hint (e.g. "AdministratorAccess")
        "resource_name",      # safe resource identifier
        # AWS Security Hub fields (M67.7).
        "finding_title",      # ASFF Title
        "product_name",       # ASFF ProductName
        "workflow_status",    # ASFF Workflow.Status
        "compliance_status",  # ASFF Compliance.Status
        # Cloudflare audit-activity fields (M68.1).
        "zone_id",            # Cloudflare zone id
        "zone_name",          # Cloudflare zone (domain)
        "rule_id",            # WAF/firewall rule id
        "rule_name",          # WAF/firewall rule name
        "outcome",            # audit action result (success / failure)
        "severity",           # provider-reported severity label
        # Cloudflare WAF-signal aggregate fields (M68.5) — counts only.
        "host",               # request host
        "ruleset_id",         # firewall ruleset id
        "path_prefix",        # sanitized leading path segment (or omitted)
        "actions",            # comma-joined distinct actions in the group
        "client_country_count",  # distinct country count (aggregate)
        # AWS S3 object-access-spike fields (M67.9) — safe aggregate counts only.
        "bucket_name",        # S3 bucket name (resource identifier)
        "unique_object_count",  # distinct object_key_hash count
        "object_key_prefix",  # sanitized, truncated prefix (or omitted)
        "pattern",            # which spike pattern fired
        "source",             # originating activity source ("s3_data_event")
        # AWS VPC Flow Log network-signal fields (M67.11) — aggregate counts only.
        "interface_id",       # ENI id (network resource identifier)
        "dst_port",           # destination port (int)
        "protocol",           # IANA protocol number (int)
        "flow_action",        # ACCEPT / REJECT / mixed
        "bytes_total",        # summed byte count across the flows (int)
        "packets_total",      # summed packet count across the flows (int)
        # GitHub secret-scanning alert signal fields (M69.4B) — safe summary only.
        "repository_full_name",  # owner/repo (safe identifier)
        "state",                 # alert state: open / resolved
        "resolution",            # resolution reason for resolved alerts
        "secret_type",           # detector slug (e.g. "github_personal_access_token")
        "secret_type_display_name",  # human-readable detector name
        "validity",              # GitHub-reported validity: active / inactive / unknown
        "publicly_leaked",       # bool — GitHub flagged the secret as publicly leaked
        "location_count",        # safe COUNT of alert locations (never the raw paths)
        # GitHub code-scanning alert signal fields (M69.4E) — safe summary only.
        "tool_name",                 # analysis tool (e.g. "CodeQL")
        "security_severity_level",   # GitHub security severity (critical/high/medium/low)
        "dismissed_reason",          # why an alert was dismissed (false positive / won't fix / used in tests)
        "instances_count",           # safe COUNT of alert instances (never raw locations)
        # GitHub Dependabot alert signal fields (M69.4H) — safe summary only.
        "dependency_package_name",   # vulnerable package name (e.g. "lodash")
        "dependency_ecosystem",      # package ecosystem (e.g. "npm", "pip")
        "vulnerable_version_range",  # affected version range (e.g. "< 4.17.21")
        "patched_versions",          # first patched version label
        "advisory_ghsa_id",          # GHSA advisory id (public identifier)
        "advisory_cve_id",           # CVE id (public identifier)
        "advisory_severity",         # advisory severity (low/medium/high/critical)
        "cvss_score",                # CVSS base score (float)
        "epss_percentage",           # EPSS probability (float)
        "scope",                     # dependency scope (runtime / development)
        # AWS IAM privilege-chain signal fields (M69.3A) — safe summary only.
        "chain_steps",        # number of distinct chain-step events detected (int)
        "target_user",        # target IAM user name (resource identifier, not raw ARN)
        "target_role",        # target IAM role name (resource identifier, not raw ARN)
        "policy_arn",         # attached policy ARN (safe label, already stored)
        "chain_pattern",      # which chain pattern fired (e.g. user_create_privilege_grant)
        "chain_window_minutes",  # configured sequence window (int)
        # Vercel activity signal fields (M70C) — safe control-plane change summary.
        # NEVER env var values, deploy hook URLs, tokens, headers, or actor emails.
        "project_id",         # Vercel project id (prj_xxx)
        "project_name",       # Vercel project slug/name
        "team_id",            # Vercel team id (when present)
        "event_action",       # raw Vercel audit action string (e.g. "env.create")
        "event_source",       # originating activity source ("vercel_audit_log")
        "target_type",        # affected object type (project/domain/env/deploy_hook/deployment)
        "target_id",          # affected object id (never a secret)
        "target_name",        # affected object name (never a secret value)
        "domain",             # custom domain name involved in the event
        "env_var_key",        # env var KEY name only (NEVER the value)
        "deploy_hook_name",   # deploy hook user-visible name (NEVER the URL)
        "branch",             # git branch / ref involved in the event
        "deployment_id",      # Vercel deployment id (dpl_xxx)
        "deployment_target",  # "production" / "preview" / "staging"
        # Supabase activity signal fields (M71C) — safe control-plane change
        # summary ONLY. NEVER database row data, SQL result rows, auth users,
        # emails, JWT secrets, service-role/anon keys, db passwords, tokens,
        # headers, raw API responses, policy expressions/SQL conditions, or Edge
        # Function env var values.
        "project_ref",          # Supabase project reference (20-char slug, not a secret)
        "organization_id",      # Supabase organization slug/id (when present)
        "schema_name",          # affected schema name (e.g. "public")
        "table_name",           # affected table name (a name, never row data)
        "policy_command",       # policy command verb (SELECT/INSERT/UPDATE/DELETE/ALL)
        "storage_bucket_id",    # storage bucket id (a name/identifier)
        "storage_bucket_name",  # storage bucket name (never file contents/object names)
        "edge_function_id",     # Edge Function id/slug (never source or env var values)
        "edge_function_name",   # Edge Function name (never source or env var values)
        "auth_setting_name",    # auth configuration setting key NAME (never a secret value)
        # Firebase activity signal fields (M72C) — safe control-plane change
        # summary ONLY. NEVER Firestore documents, Realtime Database data, storage
        # object contents, auth users, emails, private keys, service-account JSON
        # secrets, tokens, headers, raw API responses, raw rule source, request/
        # response bodies, or Cloud Function env var values.
        "project_number",       # Firebase/GCP project number (identifier, not a secret)
        "method_name",          # audit-log methodName (e.g. "...UpdateRelease")
        "database_instance",    # Realtime Database instance name
        "function_name",        # Cloud Function name (never source or env var values)
        "function_region",      # Cloud Function region
        "app_id",               # Firebase app id
        "app_platform",         # Firebase app platform (web/ios/android)
        "hosting_site_id",      # Firebase Hosting site id
        # Stripe activity signal fields (M73C) — safe config-change summary ONLY.
        # NEVER secret/restricted API key values, webhook signing secrets, raw
        # webhook payloads, raw event payloads, customer PII / emails, payment
        # method data, card data, charges/payment intents/invoices/customer
        # records, tokens, headers, request/response bodies, bank-account
        # details, or tax IDs.
        "stripe_event_type",    # raw Stripe event type (e.g. "webhook_endpoint.updated")
        "object_type",          # data.object.object NAME (e.g. "webhook_endpoint")
        "object_id",            # Stripe object id (e.g. "we_xxx") — never a secret
        "webhook_endpoint_id",  # Stripe webhook endpoint id
        "webhook_url_domain",   # webhook delivery URL host only (NEVER query strings)
        "webhook_url_scheme",   # webhook delivery URL scheme (http/https)
        "payment_link_id",      # Stripe payment link id
        "portal_config_id",     # Stripe billing-portal configuration id
        "capability",           # Stripe capability NAME (e.g. "card_payments")
        "capability_status",    # Stripe capability status (active/pending/inactive)
        "tax_setting_name",     # Tax-settings setting NAME (future use; safe key)
        "livemode",             # bool — Stripe live vs test mode
        # Shopify activity signal fields (M74C) — safe control-plane change
        # summary ONLY. NEVER Admin API access tokens, OAuth tokens, private
        # app secrets, webhook signing secrets, raw webhook payloads, raw event
        # payloads, raw API responses, customer PII / emails, orders, carts /
        # checkouts with buyer data, payment method data, card data, refunds,
        # fulfillments with customer/order data, authorization headers,
        # request/response bodies, bank-account details, tax IDs, or staff
        # names/emails.
        "shop_domain",               # Shopify shop domain (e.g. "mystore.myshopify.com")
        "myshopify_domain",          # canonical .myshopify.com domain
        "shopify_event_type",        # raw "<Subject>/<verb>" (e.g. "Webhook/update")
        "webhook_id",                # Shopify webhook id (numeric/string identifier)
        "webhook_topic",             # webhook topic NAME (e.g. "products/update")
        "webhook_endpoint_domain",   # webhook delivery URL host only
        "webhook_endpoint_scheme",   # webhook URL scheme (http / https)
        "app_scope_count",           # safe COUNT of granted app scopes
        "app_scopes_sample",         # sanitized, truncated, joined NAME sample
        "domain_id",                 # Shopify shop-domain id (identifier, not a secret)
        "domain_host",               # shop-domain host (a NAME, never DNS records)
        "policy_type",               # store policy type (e.g. "refund_policy") — NAME
        "setting_name",              # shop setting NAME (never a secret value)
        # Azure Activity Log signal fields (M77E) — safe control-plane change
        # summary ONLY. NEVER caller email/UPN/name, principal IDs, object IDs,
        # raw correlationId, claims, authorization objects, properties payload,
        # httpRequest body, raw event payload, storage keys, SAS tokens,
        # connection strings, Key Vault secret names/values, certificate material,
        # key material, database contents, VM user data, app setting names/values,
        # env var values, customer/workload data, or PII.
        "subscription_id",           # Azure subscription GUID (opaque identifier, not a secret)
        "resource_group",            # resource group name (infra identifier)
        "resource_type",             # ARM resource type (e.g. Microsoft.Network/networkSecurityGroups)
        "operation_name",            # ARM operationName (e.g. "Microsoft.Network/networkSecurityGroups/write")
        "operation_family",          # operation namespace+resource type prefix
        "operation_action",          # operation verb (write / delete)
        "azure_event_id",            # eventDataId UUID (opaque stable event identifier)
        "azure_correlation_id_hash", # salted hash of correlationId (NEVER raw)
        "scope_type",                # role assignment scope category (subscription/resource_group)
        "role_definition_name",      # resolved built-in role name (Owner/Contributor/…; not PII)
        "principal_type",            # principalType string (User/Group/ServicePrincipal; not PII)
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
        "category",                  # Activity Log event category (e.g. "Administrative")
        "provider_event_id",         # stable provider event ID (Azure eventDataId or fingerprint)
        # Google Cloud Audit Log signal fields (M78E) — safe control-plane change
        # summary ONLY. NEVER principal emails, service account emails, caller IPs,
        # userAgent, protoPayload, request, response, authenticationInfo,
        # authorizationInfo, raw payloads, secret names/values, database
        # names/users/passwords, connection strings, query data, env var
        # names/values, container args, kubeconfig, certs, node names, workload
        # data, pod specs, logs, customer data, or PII.
        "google_cloud_event_id",     # Cloud Logging insertId (opaque stable entry id)
        "project_id",                # GCP project id (infra identifier, not a secret)
        "resource_name",             # GCP resource path (no email segments)
        "resource_type",             # Cloud Logging resource.type (e.g. "gce_firewall_rule")
        "service_name",              # audit-log serviceName (e.g. "compute.googleapis.com")
        "method_name",               # audit-log methodName (e.g. "compute.firewalls.insert")
        "network_name",              # VPC network name (infra identifier)
        "firewall_rule_name",        # GCE firewall rule name (infra identifier)
        "bucket_name",               # Cloud Storage bucket name (infra identifier)
        "sql_instance_name",         # Cloud SQL instance name (infra identifier)
        "run_service_name",          # Cloud Run service name (infra identifier)
        "gke_cluster_name",          # GKE cluster name (infra identifier)
        "status_code",               # protoPayload.status.code (int — 0 = success)
        # Twilio activity signal fields (M79E) — safe control-plane change
        # summary ONLY. NEVER auth tokens, API key secrets, full account SIDs,
        # full phone number strings, webhook/callback URL strings, message bodies,
        # call SIDs, call legs, recording data, customer PII (caller name,
        # verification payloads), raw Twilio API response dicts, raw HTTP request
        # or response bodies, or any value that could re-identify a customer or
        # expose a credential.
        "twilio_resource_sid_prefix",  # first 8 chars of resource SID (opaque, not a secret)
        "messaging_service_sid",       # messaging service SID (identifier, not a secret)
        "verify_service_sid",          # Verify service SID (identifier, not a secret)
        "api_key_sid",                 # API key SID (identifier only — NEVER the secret)
        "phone_number_last4",          # last 4 digits of phone number — NEVER full number
        # SendGrid configuration activity signal fields (M80E) — safe control-plane
        # config-state change summary ONLY. NEVER API key values, bearer tokens,
        # authorization headers, email bodies, subject lines, recipient emails,
        # sender personal emails, suppression recipient emails, template HTML/
        # plaintext, raw webhook URLs, raw inbound parse hostnames, mail event
        # payloads (bounce/click/open/delivered/dropped/spamreport/unsubscribe/
        # processed), message IDs, raw SendGrid API responses, request/response
        # bodies, customer data, or PII of any kind.
        "api_key_id",                # API key opaque ID (NEVER the key value or secret)
        "sender_id",                 # sender identity opaque ID (NEVER email address)
        "mail_setting_name",         # mail setting key name (NEVER setting content)
        "tracking_setting_name",     # tracking setting key name (NEVER tracking data)
        "event_webhook_enabled",     # bool — whether event webhook delivery is active
        "event_webhook_has_url",     # bool — webhook URL presence (NEVER the URL)
        "inbound_parse_enabled",     # bool — whether inbound parse is enabled
        "inbound_parse_spam_check_enabled",  # bool — spam check on inbound parse
        "inbound_parse_send_raw_enabled",    # bool — send_raw on inbound parse
        "domain_valid",              # bool — whether domain auth passes DNS validation
        "automatic_security",        # bool — whether automatic DKIM rotation is enabled
        "dns_record_count",          # int — count of DNS records (NEVER raw DNS values)
        "sender_verified",           # bool — whether sender identity is verified
        "sender_locked",             # bool — whether sender identity is locked
        "suppression_group_count",   # int — count of ASM suppression groups
        # Auth0 configuration activity signal fields (M81E) — safe control-plane
        # config-state change summary ONLY. Auth0 Management API logs are NEVER
        # ingested because they contain user_id, email, and IP address.
        # NEVER: client_secret, management_api_token, access/refresh/ID tokens,
        # JWTs, JWKS, private keys, authorization headers, raw callback/logout/
        # origin URLs, audience URIs, custom domain name strings, rule/action
        # script content, action secret values, user emails, user IDs, user names,
        # profile data, IP addresses, device fingerprints, session data, MFA
        # recovery codes, connection credentials, social provider secrets, SAML
        # certificates, raw Auth0 API responses, raw log entries, or PII.
        "client_id",                 # Auth0 client ID (opaque identifier; NEVER client_secret)
        "connection_id",             # Auth0 connection ID (opaque identifier)
        "resource_server_id",        # Auth0 resource server ID (opaque identifier)
        "action_id",                 # Auth0 action ID (opaque identifier; NEVER code or secrets)
        "factor_name",               # MFA factor name (e.g. "otp", "webauthn-roaming")
        "custom_domain_id",          # Auth0 custom domain ID (opaque; NEVER domain string)
        "tenant_id",                 # Auth0 tenant identifier (opaque)
        "app_type",                  # safe category (e.g. "spa", "native", "regular_web")
        "is_first_party",            # bool — whether application is first-party
        "jwt_alg",                   # JWT signing algorithm (e.g. "RS256") — never a key
        "oidc_conformant",           # bool — OIDC conformance setting
        "token_endpoint_auth_method", # safe category (e.g. "client_secret_basic", "none")
        "refresh_token_rotation_enabled",  # bool — rotation setting
        "refresh_token_lifetime_category", # safe category (e.g. "standard", "extended")
        "callbacks_count",           # int — count of configured callback URLs (NEVER raw URLs)
        "allowed_logout_urls_count", # int — count of logout URLs (NEVER raw URLs)
        "allowed_origins_count",     # int — count of allowed origins (NEVER raw URLs)
        "web_origins_count",         # int — count of web origins (NEVER raw URLs)
        "grant_types_count",         # int — count of OAuth grant types enabled
        "enabled_clients_count",     # int — count of enabled clients on a connection
        "password_policy_category",  # safe category (e.g. "good", "fair")
        "signing_alg",               # resource server signing algorithm (e.g. "RS256")
        "token_lifetime_category",   # safe category (e.g. "standard", "extended")
        "allow_offline_access",      # bool — resource server offline access setting
        "rbac_enabled",              # bool — resource server RBAC enforcement setting
        "script_present",            # bool — rule has script (NEVER script content)
        "script_length_category",    # safe category (e.g. "short", "medium", "long")
        "code_present",              # bool — action has code (NEVER code content)
        "code_length_category",      # safe category (e.g. "short", "medium", "long")
        "secrets_count",             # int — count of action secrets (NEVER names/values)
        "enabled",                   # bool — rule or factor enabled setting
        "status_category",           # safe category (e.g. "ready", "pending_verification")
        "tls_policy_category",       # safe TLS policy category (e.g. "recommended")
        # Datadog configuration activity signal fields (M82E) — safe control-plane
        # config-state change summary ONLY. Events are synthesized from the same 10
        # safe drift surfaces the drift connector reads; Datadog's audit/audit-trail
        # API is never used. NEVER: API key values, application key values, OAuth
        # tokens, bearer tokens, webhook secrets, raw monitor queries/messages,
        # raw dashboard JSON, widget queries, webhook URLs/headers/payload templates,
        # notification handles, Slack channel names, PagerDuty service IDs, email
        # addresses, user IDs, team member identities, IP addresses, user agents,
        # raw Datadog audit payloads, raw API response dicts, logs, traces, metric
        # values, incident content, customer data, or PII.
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
        "notification_routing_present",  # bool — whether monitor message has @ mentions
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
        "integration_type",          # notification integration type label
        "handle_count",              # int — count of handles/services (count only)
        "channel_count",             # int — count of channels configured (count only)
        "created_present",           # bool — whether a creation timestamp exists
        "modified_present",          # bool — whether a modification timestamp exists
        "created_by_present",        # bool — whether created_by metadata exists
        "scopes_count",              # int — count of application key scopes (count only)
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
    }
)

MAX_STR_LEN = 200
MAX_METADATA_KEYS = 20

# A short, neutral note appended to every summary to keep claims calibrated.
_REVIEW_NOTE = (
    "This is a control-plane security signal that may require review. "
    "ConfigTrace does not confirm a breach, attacker, or unauthorized access."
)


def _rule(signal_key: str, signal_type: str, severity: str, phrase: str) -> dict[str, str]:
    return {
        "signal_key": signal_key,
        "signal_type": signal_type,
        "severity": severity,
        "phrase": phrase,  # human phrase for the title, e.g. "Branch protection disabled"
    }


# Map a normalized activity ``event_type`` → a signal rule. Only these mapped
# control-plane categories produce a signal; everything else is ignored.
# Severities reflect *review priority*, never confirmed impact.
SIGNAL_RULES: dict[str, dict[str, str]] = {
    "github.branch_protection.disabled": _rule(
        "github_branch_protection_disabled", "branch_protection_change", "high",
        "Branch protection disabled",
    ),
    "github.branch_protection.updated": _rule(
        "github_branch_protection_updated", "branch_protection_change", "medium",
        "Branch protection updated",
    ),
    "github.deploy_key.added": _rule(
        "github_deploy_key_added", "deploy_key_added", "high",
        "Deploy key added",
    ),
    "github.webhook.created": _rule(
        "github_webhook_created", "webhook_change", "medium",
        "Webhook created",
    ),
    "github.webhook.updated": _rule(
        "github_webhook_updated", "webhook_change", "medium",
        "Webhook changed",
    ),
    "github.webhook.deleted": _rule(
        "github_webhook_deleted", "webhook_change", "medium",
        "Webhook deleted",
    ),
    "github.collaborator.added": _rule(
        "github_collaborator_added", "collaborator_change", "high",
        "Repository collaborator added",
    ),
    "github.app.installed": _rule(
        "github_app_installed", "app_install", "medium",
        "GitHub App installed",
    ),
    "github.app.permissions_changed": _rule(
        "github_app_permissions_changed", "app_permissions_change", "high",
        "GitHub App permissions changed",
    ),
    "github.ruleset.changed": _rule(
        "github_ruleset_changed", "ruleset_change", "medium",
        "Repository ruleset changed",
    ),
    "github.secret_scanning_alert.created": _rule(
        "github_secret_scanning_alert_created", "secret_scanning_alert", "high",
        "Secret scanning alert created",
    ),
}


def sanitize_signal_metadata(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Return a safe, allowlisted, truncated copy of signal metadata.

    Drops unknown keys (secrets/tokens/payloads can never be on the allowlist),
    drops nested/complex values, and truncates strings.
    """
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


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def build_signal_from_activity_event(
    ev: SecurityActivityEvent,
) -> Optional[dict[str, Any]]:
    """Map one activity event → a signal dict, or None if no rule matches.

    Returns a plain dict of signal fields (not persisted). Title/summary use only
    calibrated, review-oriented wording.
    """
    rule = SIGNAL_RULES.get(ev.event_type)
    if rule is None:
        return None

    src_meta = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    repo = src_meta.get("repository") or ev.resource_id
    actor = ev.actor_id

    # Title: neutral human phrase + target.
    title = rule["phrase"]
    if isinstance(repo, str) and repo:
        title = f"{rule['phrase']} on {repo}"

    # Summary: factual description + calibrated review note.
    who = f" by {actor}" if isinstance(actor, str) and actor else ""
    where = f" on {repo}" if isinstance(repo, str) and repo else ""
    summary = (
        f"{rule['phrase']}{where}{who}, observed in GitHub audit activity. "
        f"{_REVIEW_NOTE}"
    )

    when = ev.occurred_at or ev.ingested_at

    metadata = sanitize_signal_metadata(
        {
            "action": src_meta.get("action"),
            "repository": repo if isinstance(repo, str) else None,
            "ref": src_meta.get("ref"),
            "hook_id": src_meta.get("hook_id"),
            "permission": src_meta.get("permission"),
            "ruleset_name": src_meta.get("ruleset_name"),
            "alert_number": src_meta.get("alert_number"),
            "actor": actor if isinstance(actor, str) else None,
            "event_type": ev.event_type,
        }
    )

    return {
        "provider": ev.provider,
        "integration_id": ev.integration_id,
        "signal_key": rule["signal_key"],
        "signal_type": rule["signal_type"],
        "severity": rule["severity"],
        "status": "open",
        "title": title,
        "summary": summary,
        "evidence_level": "activity",   # NEVER "confirmed_breach"
        "confidence": "high",            # audit event states the action happened
        "first_seen_at": when,
        "last_seen_at": when,
        "linked_activity_event_id": ev.id,
        "metadata": metadata,
    }


def upsert_incident_signal(
    *,
    workspace_id: uuid.UUID,
    signal: dict[str, Any],
    db: Session,
) -> tuple[str, SecurityIncidentSignal]:
    """Idempotently persist a signal.

    Returns ``("created", row)`` for a new signal or ``("skipped", row)`` if a
    signal already exists for the same
    ``(workspace_id, provider, signal_key, linked_activity_event_id)``.
    """
    existing = _find_existing(
        db,
        workspace_id=workspace_id,
        provider=signal["provider"],
        signal_key=signal["signal_key"],
        linked_activity_event_id=signal.get("linked_activity_event_id"),
    )
    if existing is not None:
        return "skipped", existing

    row = SecurityIncidentSignal(
        workspace_id=workspace_id,
        integration_id=signal.get("integration_id"),
        provider=signal["provider"],
        signal_key=signal["signal_key"],
        signal_type=signal["signal_type"],
        severity=signal["severity"],
        status=signal.get("status", "open"),
        title=signal["title"],
        summary=signal["summary"],
        evidence_level=signal.get("evidence_level", "activity"),
        confidence=signal.get("confidence", "high"),
        first_seen_at=signal.get("first_seen_at"),
        last_seen_at=signal.get("last_seen_at"),
        linked_activity_event_id=signal.get("linked_activity_event_id"),
        signal_metadata=signal.get("metadata") or {},
    )
    db.add(row)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = _find_existing(
            db,
            workspace_id=workspace_id,
            provider=signal["provider"],
            signal_key=signal["signal_key"],
            linked_activity_event_id=signal.get("linked_activity_event_id"),
        )
        if existing is not None:
            return "skipped", existing
        raise
    db.refresh(row)
    return "created", row


def _find_existing(
    db: Session,
    *,
    workspace_id: uuid.UUID,
    provider: str,
    signal_key: str,
    linked_activity_event_id: Optional[uuid.UUID],
) -> Optional[SecurityIncidentSignal]:
    if linked_activity_event_id is None:
        return None
    return (
        db.query(SecurityIncidentSignal)
        .filter(
            SecurityIncidentSignal.workspace_id == workspace_id,
            SecurityIncidentSignal.provider == provider,
            SecurityIncidentSignal.signal_key == signal_key,
            SecurityIncidentSignal.linked_activity_event_id == linked_activity_event_id,
        )
        .first()
    )


def generate_github_incident_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    scan_limit: int = 1000,
) -> dict[str, Any]:
    """Generate signals from recent GitHub activity events for a workspace.

    Idempotent: re-running over the same activity events creates no duplicates.
    Returns a generation summary.
    """
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_GITHUB,
        )
        .order_by(
            SecurityActivityEvent.occurred_at.desc().nullslast(),
            SecurityActivityEvent.created_at.desc(),
        )
        .limit(scan_limit)
        .all()
    )

    created = 0
    skipped = 0
    for ev in events:
        signal = build_signal_from_activity_event(ev)
        if signal is None:
            continue  # not a signal-producing category
        outcome, _row = upsert_incident_signal(
            workspace_id=workspace_id, signal=signal, db=db
        )
        if outcome == "created":
            created += 1
        else:
            skipped += 1

    return {
        "provider": PROVIDER_GITHUB,
        "activity_events_scanned": len(events),
        "signals_created": created,
        "signals_skipped": skipped,
    }


def list_incident_signals(
    *,
    workspace_id: uuid.UUID,
    db: Session,
    provider: Optional[str] = None,
    status: Optional[str] = None,
    severity: Optional[str] = None,
    signal_type: Optional[str] = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[SecurityIncidentSignal], int]:
    """Paginated, workspace-scoped signal list. Never crosses workspaces."""
    page = max(1, page)
    page_size = max(1, min(page_size, 100))

    q = db.query(SecurityIncidentSignal).filter(
        SecurityIncidentSignal.workspace_id == workspace_id
    )
    if provider:
        q = q.filter(SecurityIncidentSignal.provider == provider)
    if status:
        q = q.filter(SecurityIncidentSignal.status == status)
    if severity:
        q = q.filter(SecurityIncidentSignal.severity == severity)
    if signal_type:
        q = q.filter(SecurityIncidentSignal.signal_type == signal_type)

    total = q.count()
    items = (
        q.order_by(
            SecurityIncidentSignal.first_seen_at.desc().nullslast(),
            SecurityIncidentSignal.created_at.desc(),
        )
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return items, total


def get_incident_signal(
    *,
    signal_id: uuid.UUID,
    workspace_id: uuid.UUID,
    db: Session,
) -> Optional[SecurityIncidentSignal]:
    """Return a single signal scoped to the workspace, or None (→ 404)."""
    return (
        db.query(SecurityIncidentSignal)
        .filter(
            SecurityIncidentSignal.id == signal_id,
            SecurityIncidentSignal.workspace_id == workspace_id,
        )
        .first()
    )


# ── AWS provider-alert signals (M67.1) ────────────────────────────────────────
#
# AWS GuardDuty / Access Analyzer findings are provider-ADJUDICATED security
# findings. They are stronger evidence than a simple configuration risk, but they
# still do NOT confirm a breach/attacker/compromise — they are "evidence for
# review" Incident Signals with evidence_level="provider_alert".

PROVIDER_AWS = "aws"
SOURCE_SECURITY_ALERT = "security_alert"
_AWS_SEVERITIES = {"critical", "high", "medium", "low", "info"}

_AWS_GD_SUMMARY = (
    "AWS GuardDuty reported a security finding that may require review. "
    "ConfigTrace surfaces this as a provider-reported Incident Signal. This does "
    "not automatically confirm compromise or unauthorized access."
)
_AWS_AA_SUMMARY = (
    "AWS IAM Access Analyzer reported a finding that may require review. "
    "ConfigTrace surfaces this as a provider-reported Incident Signal. This does "
    "not automatically confirm compromise or unauthorized access."
)


def build_aws_signal_from_activity_event(ev: SecurityActivityEvent) -> Optional[dict[str, Any]]:
    """Map an AWS security-alert activity event → a provider-alert signal dict."""
    if ev.provider != PROVIDER_AWS or ev.source != SOURCE_SECURITY_ALERT:
        return None
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    severity = md.get("severity_label")
    if severity not in _AWS_SEVERITIES:
        severity = "medium"

    is_access_analyzer = isinstance(ev.event_type, str) and ev.event_type.startswith(
        "aws.access_analyzer"
    )
    if is_access_analyzer:
        signal_key = "aws_access_analyzer_finding"
        signal_type = "aws_access_analyzer"
        label = md.get("finding_type") or "external access"
        title = f"Access Analyzer finding: {label}"
        summary = _AWS_AA_SUMMARY
    else:
        signal_key = "aws_guardduty_finding"
        signal_type = "aws_guardduty"
        label = md.get("title") or md.get("finding_type") or ev.event_type
        title = f"GuardDuty finding: {label}"
        summary = _AWS_GD_SUMMARY

    when = ev.occurred_at or ev.ingested_at
    metadata = sanitize_signal_metadata(
        {
            "event_type": ev.event_type,
            "finding_type": md.get("finding_type"),
            "severity_label": severity,
            "account_id": md.get("account_id"),
            "region": md.get("region"),
            "service_name": md.get("service_name"),
        }
    )

    return {
        "provider": PROVIDER_AWS,
        "integration_id": ev.integration_id,
        "signal_key": signal_key,
        "signal_type": signal_type,
        "severity": severity,
        "status": "open",
        "title": title[:240],
        "summary": summary,
        "evidence_level": "provider_alert",   # stronger than config risk, not proof
        "confidence": "high",                  # the provider adjudicated the finding
        "first_seen_at": when,
        "last_seen_at": when,
        "linked_activity_event_id": ev.id,
        "metadata": metadata,
    }


def generate_aws_incident_signals(
    *, workspace_id: uuid.UUID, db: Session, scan_limit: int = 1000
) -> dict[str, Any]:
    """Generate AWS Incident Signals from AWS security-alert activity events.

    Idempotent: re-running creates no duplicates. Returns a generation summary.
    """
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_AWS,
            SecurityActivityEvent.source == SOURCE_SECURITY_ALERT,
        )
        .order_by(
            SecurityActivityEvent.occurred_at.desc().nullslast(),
            SecurityActivityEvent.created_at.desc(),
        )
        .limit(scan_limit)
        .all()
    )
    created = 0
    skipped = 0
    for ev in events:
        signal = build_aws_signal_from_activity_event(ev)
        if signal is None:
            continue
        outcome, _row = upsert_incident_signal(
            workspace_id=workspace_id, signal=signal, db=db
        )
        if outcome == "created":
            created += 1
        else:
            skipped += 1

    return {
        "provider": PROVIDER_AWS,
        "activity_events_scanned": len(events),
        "signals_created": created,
        "signals_skipped": skipped,
    }


# ── AWS Security Hub Incident Signals (M67.7) ──────────────────────────────────

SOURCE_SECURITY_HUB = "security_hub"

_AWS_SH_SUMMARY = (
    "AWS Security Hub reported a security finding that may require review. "
    "ConfigTrace surfaces this as provider-reported evidence. This does not "
    "automatically confirm compromise or unauthorized access."
)


def build_aws_security_hub_signal_from_activity_event(
    ev: SecurityActivityEvent,
) -> Optional[dict[str, Any]]:
    """Map an AWS Security Hub activity event → a provider-alert signal dict."""
    if ev.provider != PROVIDER_AWS or ev.source != SOURCE_SECURITY_HUB:
        return None
    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    severity = md.get("severity_label")
    if severity not in _AWS_SEVERITIES:
        severity = "medium"

    label = md.get("finding_title") or md.get("finding_type") or ev.event_type
    title = f"Security Hub finding: {label}"

    when = ev.occurred_at or ev.ingested_at
    metadata = sanitize_signal_metadata(
        {
            "event_type": ev.event_type,
            "finding_type": md.get("finding_type"),
            "finding_title": md.get("finding_title"),
            "severity_label": severity,
            "product_name": md.get("product_name"),
            "account_id": md.get("account_id"),
            "region": md.get("region"),
            "workflow_status": md.get("workflow_status"),
            "compliance_status": md.get("compliance_status"),
        }
    )

    return {
        "provider": PROVIDER_AWS,
        "integration_id": ev.integration_id,
        "signal_key": "aws_security_hub_finding",
        "signal_type": "aws_security_hub_finding",
        "severity": severity,
        "status": "open",
        "title": title[:240],
        "summary": _AWS_SH_SUMMARY,
        "evidence_level": "provider_alert",   # provider-adjudicated, not proof
        "confidence": "high",
        "first_seen_at": when,
        "last_seen_at": when,
        "linked_activity_event_id": ev.id,
        "metadata": metadata,
    }


def generate_aws_security_hub_signals(
    *, workspace_id: uuid.UUID, db: Session, scan_limit: int = 1000
) -> dict[str, Any]:
    """Generate AWS Incident Signals from Security Hub activity events.

    Idempotent: re-running creates no duplicates. Returns a generation summary.
    """
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_AWS,
            SecurityActivityEvent.source == SOURCE_SECURITY_HUB,
        )
        .order_by(
            SecurityActivityEvent.occurred_at.desc().nullslast(),
            SecurityActivityEvent.created_at.desc(),
        )
        .limit(scan_limit)
        .all()
    )
    created = 0
    skipped = 0
    for ev in events:
        signal = build_aws_security_hub_signal_from_activity_event(ev)
        if signal is None:
            continue
        outcome, _row = upsert_incident_signal(
            workspace_id=workspace_id, signal=signal, db=db
        )
        if outcome == "created":
            created += 1
        else:
            skipped += 1

    return {
        "provider": PROVIDER_AWS,
        "activity_events_scanned": len(events),
        "signals_created": created,
        "signals_skipped": skipped,
    }


# ── Cloudflare audit-activity Incident Signals (M68.1) ─────────────────────────

PROVIDER_CLOUDFLARE = "cloudflare"
SOURCE_AUDIT_LOG = "audit_log"

_CF_REVIEW_NOTE = (
    "This is Cloudflare audit activity surfaced as evidence for review. "
    "ConfigTrace does not confirm a breach, attacker, compromise, or "
    "unauthorized access."
)

# Normalized Cloudflare audit ``event_type`` → signal rule. Only these
# security-relevant control-plane changes produce a signal; the generic
# ``cloudflare.audit_event`` fallback is intentionally NOT signal-producing.
CLOUDFLARE_SIGNAL_RULES: dict[str, dict[str, str]] = {
    "cloudflare.dns_record.changed": _rule(
        "cloudflare_dns_record_changed", "cloudflare_audit_activity", "medium",
        "DNS record changed"),
    "cloudflare.waf_rule.changed": _rule(
        "cloudflare_waf_rule_changed", "cloudflare_audit_activity", "high",
        "WAF/firewall rule changed"),
    "cloudflare.ssl_tls.changed": _rule(
        "cloudflare_ssl_tls_changed", "cloudflare_audit_activity", "high",
        "SSL/TLS setting changed"),
    "cloudflare.access_policy.changed": _rule(
        "cloudflare_access_policy_changed", "cloudflare_audit_activity", "high",
        "Access policy changed"),
    "cloudflare.api_token.activity": _rule(
        "cloudflare_api_token_activity", "cloudflare_audit_activity", "medium",
        "API token activity observed"),
    "cloudflare.zone_setting.changed": _rule(
        "cloudflare_zone_setting_changed", "cloudflare_audit_activity", "medium",
        "Zone setting changed"),
}


def build_cloudflare_signal_from_activity_event(
    ev: SecurityActivityEvent,
) -> Optional[dict[str, Any]]:
    """Map a Cloudflare audit activity event -> a signal dict, or None."""
    if ev.provider != PROVIDER_CLOUDFLARE or ev.source != SOURCE_AUDIT_LOG:
        return None
    rule = CLOUDFLARE_SIGNAL_RULES.get(ev.event_type)
    if rule is None:
        return None

    md = ev.event_metadata if isinstance(ev.event_metadata, dict) else {}
    zone = md.get("zone_name") or md.get("zone_id") or ev.resource_id
    actor = md.get("actor") or ev.actor_id

    title = rule["phrase"]
    if isinstance(zone, str) and zone:
        title = f"{rule['phrase']} on {zone}"

    who = f" by {actor}" if isinstance(actor, str) and actor else ""
    where = f" on {zone}" if isinstance(zone, str) and zone else ""
    summary = (
        f"Cloudflare audit activity: {rule['phrase'].lower()}{where}{who}. "
        f"{_CF_REVIEW_NOTE}"
    )

    when = ev.occurred_at or ev.ingested_at
    metadata = sanitize_signal_metadata({
        "event_type": ev.event_type,
        "action": md.get("action"),
        "actor": actor if isinstance(actor, str) else None,
        "zone_id": md.get("zone_id"),
        "zone_name": md.get("zone_name"),
        "rule_id": md.get("rule_id"),
        "rule_name": md.get("rule_name"),
        "outcome": md.get("outcome"),
        "severity": md.get("severity"),
    })

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "integration_id": ev.integration_id,
        "signal_key": rule["signal_key"],
        "signal_type": rule["signal_type"],
        "severity": rule["severity"],
        "status": "open",
        "title": title[:240],
        "summary": summary,
        "evidence_level": "activity",
        "confidence": "high",
        "first_seen_at": when,
        "last_seen_at": when,
        "linked_activity_event_id": ev.id,
        "metadata": metadata,
    }


def generate_cloudflare_signals(
    *, workspace_id: uuid.UUID, db: Session, scan_limit: int = 1000
) -> dict[str, Any]:
    """Generate Cloudflare Incident Signals from audit activity. Idempotent."""
    events = (
        db.query(SecurityActivityEvent)
        .filter(
            SecurityActivityEvent.workspace_id == workspace_id,
            SecurityActivityEvent.provider == PROVIDER_CLOUDFLARE,
            SecurityActivityEvent.source == SOURCE_AUDIT_LOG,
        )
        .order_by(
            SecurityActivityEvent.occurred_at.desc().nullslast(),
            SecurityActivityEvent.created_at.desc(),
        )
        .limit(scan_limit)
        .all()
    )
    created = 0
    skipped = 0
    for ev in events:
        signal = build_cloudflare_signal_from_activity_event(ev)
        if signal is None:
            continue
        outcome, _row = upsert_incident_signal(
            workspace_id=workspace_id, signal=signal, db=db
        )
        if outcome == "created":
            created += 1
        else:
            skipped += 1

    return {
        "provider": PROVIDER_CLOUDFLARE,
        "activity_events_scanned": len(events),
        "signals_created": created,
        "signals_skipped": skipped,
    }
