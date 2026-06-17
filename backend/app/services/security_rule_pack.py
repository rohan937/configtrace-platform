"""Security Exposure rule pack / versioning registry (M63.3).

Lightweight, static traceability layer over the existing rule registries. It
answers: "which rule pack + version is active, and which version produced this
finding?" — without adding rules, a marketplace, or a rule editor.

Sources of truth it aligns with (never duplicated logic):
  * security_rule_registry.KNOWN_RULE_KEYS  — the implemented rule keys
  * security_rule_confidence.confidence_for — per-rule confidence
  * provider/severity/category mirror the frontend securityRuleCatalog

This is the first versioned pack, so every rule shares the baseline
``rule_version`` and ``introduced_in``. Bump SECURITY_RULE_PACK_VERSION (and the
relevant per-rule entries) when the pack changes.
"""

from __future__ import annotations

from typing import Any

from app.services.security_rule_confidence import confidence_for
from app.services.security_rule_registry import KNOWN_RULE_KEYS, base_rule_key

SECURITY_RULE_PACK_NAME = "configtrace_security_exposure"
SECURITY_RULE_PACK_VERSION = "2026.06"
SECURITY_RULE_PACK_RELEASED_AT = "2026-06-08"
SECURITY_RULE_PACK_DESCRIPTION = (
    "ConfigTrace Security Exposure rule pack — metadata-only configuration "
    "exposure checks across connected cloud and SaaS providers. Rules evaluate "
    "provider configuration, never payloads or secrets."
)

# Baselines for the first versioned pack. Per-rule overrides can be added later.
DEFAULT_RULE_VERSION = "1.0"
DEFAULT_INTRODUCED_IN = SECURITY_RULE_PACK_VERSION

# rule_key → (provider, severity, category). Mirrors the frontend catalog so the
# pack manifest is self-describing on the backend. Severity is the rule's
# headline (worst-case) severity.
_RULE_META: dict[str, tuple[str, str, str]] = {
    # GitHub
    "github_webhook_http": ("github", "critical", "Webhooks"),
    "github_branch_protection_missing": ("github", "high", "Branch protection"),
    "github_force_pushes_allowed": ("github", "high", "Branch protection"),
    "github_branch_deletion_allowed": ("github", "high", "Branch protection"),
    "github_pr_review_not_required": ("github", "high", "Branch protection"),
    "github_status_checks_not_required": ("github", "medium", "Branch protection"),
    "github_deploy_key_write_access": ("github", "high", "Deploy keys"),
    "github_env_protection_missing": ("github", "medium", "Environment protection"),
    # GitHub rulesets (M69.5A)
    "github_ruleset_not_enforced": ("github", "high", "Rulesets"),
    "github_ruleset_force_push_allowed": ("github", "high", "Rulesets"),
    "github_ruleset_pr_review_missing": ("github", "high", "Rulesets"),
    "github_ruleset_status_checks_missing": ("github", "medium", "Rulesets"),
    "github_ruleset_bypass_actors_present": ("github", "medium", "Rulesets"),
    "github_ruleset_weak_target_coverage": ("github", "medium", "Rulesets"),
    # GitHub automation permissions (M69.5B)
    "github_automation_admin_permission": ("github", "high", "Automation permissions"),
    "github_automation_write_permission": ("github", "medium", "Automation permissions"),
    "github_token_broad_scopes": ("github", "high", "Automation permissions"),
    "github_webhook_secret_missing": ("github", "medium", "Webhooks"),
    # AWS
    "aws_public_admin_port": ("aws", "high", "Security groups"),
    "aws_public_database_port": ("aws", "critical", "Security groups"),
    "aws_public_all_ports": ("aws", "critical", "Security groups"),
    "aws_s3_public_policy": ("aws", "critical", "S3 public access"),
    "aws_s3_public_acl": ("aws", "critical", "S3 public access"),
    "aws_iam_admin_policy_attached": ("aws", "high", "IAM"),
    "aws_access_key_unused": ("aws", "medium", "IAM access keys"),
    # Cloudflare
    "cloudflare_ssl_mode_weak": ("cloudflare", "high", "SSL/TLS"),
    "cloudflare_always_https_off": ("cloudflare", "medium", "HTTPS"),
    "cloudflare_min_tls_weak": ("cloudflare", "medium", "SSL/TLS"),
    "cloudflare_security_level_low": ("cloudflare", "medium", "WAF / security"),
    "cloudflare_development_mode_on": ("cloudflare", "medium", "WAF / security"),
    "cloudflare_hsts_disabled": ("cloudflare", "medium", "HTTPS"),
    "cloudflare_waf_rule_disabled": ("cloudflare", "high", "WAF / security"),
    "cloudflare_dns_private_origin": ("cloudflare", "high", "DNS"),
    # Supabase
    "supabase_rls_disabled": ("supabase", "high", "RLS"),
    "supabase_anonymous_access_enabled": ("supabase", "medium", "Auth"),
    "supabase_jwt_expiry_long": ("supabase", "medium", "Auth"),
    "supabase_public_select_sensitive_table": ("supabase", "high", "RLS"),
    "supabase_public_write_policy": ("supabase", "high", "RLS"),
    "supabase_edge_function_jwt_disabled": ("supabase", "medium", "Edge Functions"),
    "supabase_auth_protection_missing": ("supabase", "medium", "Auth"),
    # Firebase
    "firebase_rules_public": ("firebase", "critical", "Security rules"),
    "firebase_storage_rules_public": ("firebase", "critical", "Security rules"),
    "firebase_anonymous_auth_enabled": ("firebase", "medium", "Auth"),
    # Firebase — M72A
    "firebase_database_public_read": ("firebase", "high", "Security rules"),
    "firebase_database_public_write": ("firebase", "critical", "Security rules"),
    "firebase_auth_protection_missing": ("firebase", "medium", "Auth"),
    # Stripe
    "stripe_webhook_http": ("stripe", "critical", "Webhooks"),
    # Stripe — M73A
    "stripe_webhook_disabled": ("stripe", "medium", "Webhooks"),
    "stripe_webhook_broad_events": ("stripe", "medium", "Webhooks"),
    "stripe_payment_link_tax_disabled": ("stripe", "medium", "Payment links"),
    "stripe_payment_link_promo_codes_enabled": ("stripe", "low", "Payment links"),
    "stripe_portal_subscription_cancel_enabled": ("stripe", "low", "Customer portal"),
    "stripe_portal_login_enabled": ("stripe", "medium", "Customer portal"),
    "stripe_account_capability_incomplete": ("stripe", "medium", "Account"),
    # Vercel
    "vercel_preview_unprotected": ("vercel", "medium", "Deployment protection"),
    "vercel_production_branch_missing": ("vercel", "medium", "Deployment configuration"),
    "vercel_production_branch_unusual": ("vercel", "medium", "Deployment configuration"),
    "vercel_domain_unverified": ("vercel", "medium", "Domains"),
    "vercel_env_var_broad_target": ("vercel", "medium", "Environment variables"),
    "vercel_sensitive_env_var_broad_scope": ("vercel", "high", "Environment variables"),
    "vercel_deploy_hook_production_branch": ("vercel", "medium", "Deploy hooks"),
    # Shopify
    "shopify_webhook_http": ("shopify", "critical", "Webhooks"),
    # Shopify — M74A
    "shopify_webhook_high_risk_topic": ("shopify", "medium", "Webhooks"),
    "shopify_app_broad_write_scopes": ("shopify", "high", "App scopes"),
    "shopify_app_customer_data_scope": ("shopify", "high", "App scopes"),
    "shopify_domain_ssl_missing": ("shopify", "high", "Domains"),
    "shopify_domain_unverified": ("shopify", "medium", "Domains"),
    "shopify_policy_missing": ("shopify", "low", "Store policies"),
    # Azure — M77B
    "azure_nsg_public_admin_ingress": ("azure", "critical", "Network security groups"),
    "azure_nsg_public_broad_ingress": ("azure", "critical", "Network security groups"),
    "azure_storage_public_blob_access": ("azure", "high", "Storage accounts"),
    "azure_storage_public_network_access": ("azure", "high", "Storage accounts"),
    "azure_storage_weak_tls": ("azure", "medium", "Storage accounts"),
    "azure_storage_shared_key_enabled": ("azure", "medium", "Storage accounts"),
    "azure_key_vault_public_network_access": ("azure", "high", "Key Vaults"),
    "azure_key_vault_purge_protection_disabled": ("azure", "high", "Key Vaults"),
    "azure_key_vault_soft_delete_disabled": ("azure", "medium", "Key Vaults"),
    "azure_key_vault_rbac_disabled": ("azure", "medium", "Key Vaults"),
    # Azure — M77C
    "azure_role_assignment_broad_privilege": ("azure", "high", "Identity / Role assignments"),
    "azure_app_service_https_disabled": ("azure", "high", "App Service / Functions"),
    "azure_app_service_ftp_enabled": ("azure", "medium", "App Service / Functions"),
    "azure_app_service_weak_tls": ("azure", "medium", "App Service / Functions"),
    "azure_app_service_public_network_access": ("azure", "medium", "App Service / Functions"),
    "azure_sql_public_network_access": ("azure", "high", "SQL Servers"),
    "azure_sql_weak_tls": ("azure", "medium", "SQL Servers"),
    "azure_aks_local_accounts_enabled": ("azure", "medium", "AKS Clusters"),
    "azure_aks_public_api_access": ("azure", "high", "AKS Clusters"),
    "azure_aks_network_policy_missing": ("azure", "medium", "AKS Clusters"),
    # Google Cloud — M78B
    "google_cloud_iam_public_member": ("google_cloud", "high", "IAM policies"),
    "google_cloud_iam_broad_privileged_role": ("google_cloud", "high", "IAM policies"),
    "google_cloud_firewall_public_admin_ingress": ("google_cloud", "critical", "Firewall rules"),
    "google_cloud_firewall_public_broad_ingress": ("google_cloud", "critical", "Firewall rules"),
    "google_cloud_firewall_rule_no_targets": ("google_cloud", "medium", "Firewall rules"),
    "google_cloud_storage_public_access_prevention_disabled": ("google_cloud", "high", "Cloud Storage buckets"),
    "google_cloud_storage_uniform_access_disabled": ("google_cloud", "medium", "Cloud Storage buckets"),
    "google_cloud_storage_versioning_disabled": ("google_cloud", "low", "Cloud Storage buckets"),
    "google_cloud_storage_retention_not_locked": ("google_cloud", "medium", "Cloud Storage buckets"),
    # Google Cloud — M78C: Cloud SQL
    "google_cloud_sql_public_network_access": ("google_cloud", "high", "Cloud SQL instances"),
    "google_cloud_sql_weak_tls": ("google_cloud", "medium", "Cloud SQL instances"),
    "google_cloud_sql_backups_disabled": ("google_cloud", "medium", "Cloud SQL instances"),
    "google_cloud_sql_deletion_protection_disabled": ("google_cloud", "medium", "Cloud SQL instances"),
    # Google Cloud — M78C: Cloud Run
    "google_cloud_run_public_invoker": ("google_cloud", "high", "Cloud Run services"),
    "google_cloud_run_all_ingress": ("google_cloud", "high", "Cloud Run services"),
    # Google Cloud — M78C: GKE
    "google_cloud_gke_public_control_plane": ("google_cloud", "high", "GKE clusters"),
    "google_cloud_gke_legacy_abac_enabled": ("google_cloud", "high", "GKE clusters"),
    "google_cloud_gke_network_policy_disabled": ("google_cloud", "medium", "GKE clusters"),
    "google_cloud_gke_workload_identity_disabled": ("google_cloud", "medium", "GKE clusters"),
    # Google Cloud — M78C: Service account keys
    "google_cloud_service_account_user_managed_keys": ("google_cloud", "high", "Service account keys"),
    "google_cloud_service_account_old_keys": ("google_cloud", "medium", "Service account keys"),
    # Google Cloud — M78C: Secret Manager
    "google_cloud_secret_manager_auto_replication_without_cmek": ("google_cloud", "low", "Secret Manager"),
    # Twilio — M79B
    "twilio_phone_number_sms_webhook_missing": ("twilio", "medium", "Webhook configuration"),
    "twilio_phone_number_voice_webhook_missing": ("twilio", "medium", "Webhook configuration"),
    "twilio_phone_number_status_callback_missing": ("twilio", "low", "Webhook configuration"),
    "twilio_messaging_service_inbound_webhook_missing": ("twilio", "medium", "Webhook configuration"),
    "twilio_messaging_service_fallback_missing": ("twilio", "low", "Webhook configuration"),
    "twilio_messaging_service_status_callback_missing": ("twilio", "low", "Webhook configuration"),
    "twilio_verify_short_code_length": ("twilio", "medium", "Verify services"),
    "twilio_verify_lookup_disabled": ("twilio", "low", "Verify services"),
    "twilio_account_suspended": ("twilio", "low", "Account"),
    # Twilio — M79C
    "twilio_api_key_stale": ("twilio", "medium", "API key hygiene"),
    "twilio_messaging_service_observability_gap": ("twilio", "medium", "Webhook configuration"),
    "twilio_messaging_service_number_level_inbound_webhook": ("twilio", "low", "Webhook configuration"),
    "twilio_messaging_service_long_validity_period": ("twilio", "low", "Messaging service configuration"),
    "twilio_phone_number_messaging_observability_gap": ("twilio", "medium", "Webhook configuration"),
    "twilio_phone_number_voice_observability_gap": ("twilio", "medium", "Webhook configuration"),
    "twilio_verify_psd2_disabled": ("twilio", "low", "Verify services"),
    "twilio_verify_sms_to_landlines_allowed": ("twilio", "low", "Verify services"),
    # SendGrid — M80B
    "sendgrid_api_key_broad_scopes": ("sendgrid", "high", "API key scopes"),
    "sendgrid_sender_identity_unverified": ("sendgrid", "medium", "Sender identities"),
    "sendgrid_sender_identity_locked": ("sendgrid", "low", "Sender identities"),
    "sendgrid_domain_authentication_invalid": ("sendgrid", "medium", "Domain authentication"),
    "sendgrid_domain_automatic_security_disabled": ("sendgrid", "medium", "Domain authentication"),
    "sendgrid_domain_authentication_legacy": ("sendgrid", "low", "Domain authentication"),
    "sendgrid_spam_check_disabled": ("sendgrid", "medium", "Mail settings"),
    "sendgrid_sandbox_mode_enabled": ("sendgrid", "medium", "Mail settings"),
    "sendgrid_bcc_enabled": ("sendgrid", "medium", "Mail settings"),
    "sendgrid_click_tracking_enabled": ("sendgrid", "low", "Tracking settings"),
    "sendgrid_open_tracking_enabled": ("sendgrid", "low", "Tracking settings"),
    "sendgrid_subscription_tracking_disabled": ("sendgrid", "medium", "Tracking settings"),
    "sendgrid_event_webhook_disabled": ("sendgrid", "medium", "Webhook configuration"),
    "sendgrid_event_webhook_url_missing": ("sendgrid", "medium", "Webhook configuration"),
    "sendgrid_suppression_settings_empty": ("sendgrid", "low", "Suppression settings"),
    # SendGrid — M80C
    "sendgrid_sender_identity_reply_domain_mismatch": ("sendgrid", "low", "Sender identities"),
    "sendgrid_domain_dns_records_missing": ("sendgrid", "medium", "Domain authentication"),
    "sendgrid_default_domain_authentication_invalid": ("sendgrid", "high", "Domain authentication"),
    "sendgrid_footer_disabled": ("sendgrid", "low", "Mail settings"),
    "sendgrid_bounce_purge_disabled": ("sendgrid", "low", "Mail settings"),
    "sendgrid_template_engine_enabled": ("sendgrid", "low", "Mail settings"),
    "sendgrid_google_analytics_tracking_enabled": ("sendgrid", "low", "Tracking settings"),
    "sendgrid_event_webhook_broad_event_stream": ("sendgrid", "low", "Webhook configuration"),
    "sendgrid_inbound_parse_enabled": ("sendgrid", "medium", "Webhook configuration"),
    "sendgrid_inbound_parse_raw_email_enabled": ("sendgrid", "medium", "Webhook configuration"),
    "sendgrid_inbound_parse_spam_check_disabled": ("sendgrid", "medium", "Webhook configuration"),
    # Auth0 — M81B
    "auth0_tenant_session_lifetime_extended": ("auth0", "medium", "Tenant session"),
    "auth0_tenant_idle_session_lifetime_extended": ("auth0", "low", "Tenant session"),
    "auth0_tenant_dynamic_client_registration_enabled": ("auth0", "high", "Tenant configuration"),
    "auth0_application_no_callbacks": ("auth0", "low", "Application configuration"),
    "auth0_application_many_callbacks": ("auth0", "medium", "Application configuration"),
    "auth0_application_many_allowed_origins": ("auth0", "medium", "Application configuration"),
    "auth0_application_oidc_non_conformant": ("auth0", "medium", "Application configuration"),
    "auth0_application_weak_jwt_algorithm": ("auth0", "high", "Application token signing"),
    "auth0_refresh_token_rotation_disabled": ("auth0", "medium", "Refresh token posture"),
    "auth0_refresh_token_lifetime_extended": ("auth0", "medium", "Refresh token posture"),
    "auth0_connection_no_enabled_clients": ("auth0", "low", "Connection configuration"),
    "auth0_connection_weak_password_policy": ("auth0", "high", "Connection password policy"),
    "auth0_resource_server_offline_access_enabled": ("auth0", "medium", "Resource server token posture"),
    "auth0_resource_server_token_lifetime_extended": ("auth0", "medium", "Resource server token posture"),
    "auth0_resource_server_rbac_disabled": ("auth0", "medium", "Resource server authorization"),
    "auth0_rule_disabled": ("auth0", "low", "Auth pipeline rule"),
    "auth0_rule_large_script": ("auth0", "low", "Auth pipeline rule"),
    "auth0_action_not_deployed": ("auth0", "low", "Auth pipeline action"),
    "auth0_action_secrets_present": ("auth0", "low", "Auth pipeline action"),
    "auth0_mfa_factor_disabled": ("auth0", "medium", "MFA factor posture"),
    "auth0_custom_domain_not_ready": ("auth0", "medium", "Custom domain"),
    "auth0_custom_domain_weak_tls_policy": ("auth0", "low", "Custom domain"),
    # Auth0 — M81C OAuth/application risk expansion
    "auth0_application_password_grant_enabled": ("auth0", "high", "OAuth grant type posture"),
    "auth0_application_implicit_grant_enabled": ("auth0", "high", "OAuth grant type posture"),
    "auth0_application_public_client_credentials_enabled": ("auth0", "high", "OAuth grant type posture"),
    "auth0_application_refresh_grant_without_rotation": ("auth0", "medium", "Refresh token posture"),
    "auth0_application_many_grant_types": ("auth0", "medium", "OAuth grant type posture"),
    "auth0_application_device_code_grant_enabled": ("auth0", "low", "OAuth grant type posture"),
    "auth0_application_wildcard_callback": ("auth0", "high", "Application callback posture"),
    "auth0_application_wildcard_allowed_origin": ("auth0", "high", "Application origin posture"),
    "auth0_application_wildcard_logout_url": ("auth0", "medium", "Application logout posture"),
    "auth0_application_localhost_callback": ("auth0", "low", "Application callback posture"),
    "auth0_application_localhost_origin": ("auth0", "low", "Application origin posture"),
    "auth0_application_callback_missing_https": ("auth0", "medium", "Application callback posture"),
    "auth0_application_origin_missing_https": ("auth0", "medium", "Application origin posture"),
    "auth0_public_client_refresh_tokens_enabled": ("auth0", "medium", "Refresh token posture"),
    "auth0_application_token_endpoint_auth_none": ("auth0", "medium", "Token endpoint posture"),
    # Datadog — M82B core security rules
    "datadog_monitor_disabled": ("datadog", "medium", "Monitor posture"),
    "datadog_monitor_unrestricted_roles": ("datadog", "low", "Monitor posture"),
    "datadog_monitor_notify_no_data_disabled": ("datadog", "low", "Monitor posture"),
    "datadog_monitor_long_query": ("datadog", "low", "Monitor posture"),
    "datadog_slo_no_monitors": ("datadog", "medium", "SLO posture"),
    "datadog_slo_low_target": ("datadog", "low", "SLO posture"),
    "datadog_dashboard_public_url_present": ("datadog", "medium", "Dashboard posture"),
    "datadog_dashboard_unrestricted_roles": ("datadog", "low", "Dashboard posture"),
    "datadog_webhook_without_secret_headers": ("datadog", "high", "Webhook posture"),
    "datadog_webhook_payload_template_present": ("datadog", "low", "Webhook posture"),
    "datadog_notification_integration_no_channels": ("datadog", "low", "Notification integration posture"),
    "datadog_application_key_broad_scopes": ("datadog", "medium", "Application key posture"),
    "datadog_api_key_disabled": ("datadog", "low", "API key posture"),
    "datadog_role_high_permission_count": ("datadog", "medium", "Role posture"),
    "datadog_team_no_members": ("datadog", "low", "Team posture"),
    "datadog_cloud_integration_broad_collection": ("datadog", "medium", "Cloud integration posture"),
    "datadog_cloud_integration_log_collection_enabled": ("datadog", "low", "Cloud integration posture"),
}


def rule_version_for(finding_key: str) -> str:
    """Return the rule_version for a finding/rule key (baseline for this pack)."""
    rule_key = base_rule_key(finding_key)
    # Per-rule overrides could live here later; for now every known rule shares
    # the baseline. Unknown keys still get the baseline (null-safe, never raises).
    _ = rule_key
    return DEFAULT_RULE_VERSION


def pack_metadata_for(finding_key: str) -> tuple[str, str, str]:
    """Return (rule_pack_name, rule_pack_version, rule_version) for a finding."""
    return (
        SECURITY_RULE_PACK_NAME,
        SECURITY_RULE_PACK_VERSION,
        rule_version_for(finding_key),
    )


def list_pack_rules() -> list[dict[str, Any]]:
    """Per-rule manifest for the pack endpoint (sorted, deterministic)."""
    out: list[dict[str, Any]] = []
    for rule_key in sorted(_RULE_META):
        provider, severity, category = _RULE_META[rule_key]
        confidence, _reason, _guard = confidence_for(rule_key)
        out.append(
            {
                "rule_key": rule_key,
                "provider": provider,
                "rule_version": DEFAULT_RULE_VERSION,
                "introduced_in": DEFAULT_INTRODUCED_IN,
                "status": "active",
                "confidence": confidence,
                "severity": severity,
                "category": category,
            }
        )
    return out


def pack_summary() -> dict[str, Any]:
    """Full rule pack descriptor for GET /security/rules/pack."""
    rules = list_pack_rules()
    providers = sorted({r["provider"] for r in rules})
    return {
        "name": SECURITY_RULE_PACK_NAME,
        "version": SECURITY_RULE_PACK_VERSION,
        "released_at": SECURITY_RULE_PACK_RELEASED_AT,
        "description": SECURITY_RULE_PACK_DESCRIPTION,
        "rule_count": len(rules),
        "providers": providers,
        "rules": rules,
    }


# Sanity: the manifest must cover exactly the implemented rule keys. Surfacing a
# drift early (import-time) is cheaper than a silently incomplete pack.
assert set(_RULE_META) == set(KNOWN_RULE_KEYS), (
    "security_rule_pack._RULE_META is out of sync with KNOWN_RULE_KEYS: "
    f"missing={set(KNOWN_RULE_KEYS) - set(_RULE_META)}, "
    f"extra={set(_RULE_META) - set(KNOWN_RULE_KEYS)}"
)
