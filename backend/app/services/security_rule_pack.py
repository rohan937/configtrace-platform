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
    # Datadog — M82C monitor/webhook risk expansion
    "datadog_monitor_no_notifications": ("datadog", "medium", "Monitor notification posture"),
    "datadog_monitor_message_template_present": ("datadog", "low", "Monitor notification posture"),
    "datadog_monitor_no_warning_threshold": ("datadog", "medium", "Monitor threshold posture"),
    "datadog_monitor_no_recovery_threshold": ("datadog", "low", "Monitor threshold posture"),
    "datadog_monitor_silenced_scopes_present": ("datadog", "medium", "Monitor posture"),
    "datadog_monitor_notify_audit_disabled": ("datadog", "low", "Monitor posture"),
    "datadog_monitor_require_full_window_disabled": ("datadog", "low", "Monitor evaluation posture"),
    "datadog_monitor_query_wildcard_scope": ("datadog", "medium", "Monitor query posture"),
    "datadog_monitor_broad_group_by": ("datadog", "low", "Monitor query posture"),
    "datadog_monitor_long_no_data_timeframe": ("datadog", "low", "Monitor no-data posture"),
    "datadog_webhook_custom_headers_without_secret_headers": ("datadog", "medium", "Webhook posture"),
    "datadog_webhook_large_payload_template": ("datadog", "low", "Webhook posture"),
    "datadog_webhook_auth_material_present": ("datadog", "medium", "Webhook posture"),
    "datadog_webhook_non_https_endpoint": ("datadog", "high", "Webhook posture"),
    # Clerk — M83B core security rules
    "clerk_instance_mfa_disabled": ("clerk", "medium", "Instance MFA posture"),
    "clerk_instance_password_without_mfa": ("clerk", "medium", "Instance authentication posture"),
    "clerk_instance_sign_up_enabled": ("clerk", "low", "Instance sign-up posture"),
    "clerk_application_mfa_not_required": ("clerk", "medium", "Application MFA posture"),
    "clerk_domain_unverified": ("clerk", "medium", "Domain posture"),
    "clerk_domain_ssl_disabled": ("clerk", "high", "Domain SSL posture"),
    "clerk_redirect_url_non_https": ("clerk", "high", "Redirect URL posture"),
    "clerk_redirect_url_wildcard_present": ("clerk", "medium", "Redirect URL posture"),
    "clerk_redirect_url_localhost_present": ("clerk", "low", "Redirect URL posture"),
    "clerk_jwt_template_custom_claims_present": ("clerk", "low", "JWT template posture"),
    "clerk_jwt_template_long_lifetime": ("clerk", "medium", "JWT template lifetime posture"),
    "clerk_webhook_endpoint_disabled": ("clerk", "low", "Webhook endpoint posture"),
    "clerk_webhook_without_signing": ("clerk", "high", "Webhook signing posture"),
    "clerk_webhook_non_https": ("clerk", "high", "Webhook endpoint posture"),
    "clerk_email_sms_custom_sender_present": ("clerk", "low", "Email/SMS sender posture"),
    "clerk_auth_strategy_mfa_not_required": ("clerk", "medium", "Authentication strategy posture"),
    "clerk_auth_strategy_password_without_mfa": ("clerk", "medium", "Authentication strategy posture"),
    "clerk_session_lifetime_extended": ("clerk", "medium", "Session lifetime posture"),
    "clerk_session_inactivity_timeout_extended": ("clerk", "low", "Session inactivity posture"),
    "clerk_session_single_session_disabled": ("clerk", "low", "Session policy posture"),
    "clerk_session_token_rotation_disabled": ("clerk", "medium", "Session token rotation posture"),
    # Clerk — M83C auth/application risk expansion
    "clerk_application_sign_up_enabled": ("clerk", "low", "Application sign-up posture"),
    "clerk_application_password_without_mfa": ("clerk", "medium", "Application authentication posture"),
    "clerk_application_oauth_without_mfa": ("clerk", "medium", "Application OAuth posture"),
    "clerk_application_saml_without_mfa": ("clerk", "medium", "Application SAML posture"),
    "clerk_application_many_redirect_urls": ("clerk", "low", "Application redirect URL posture"),
    "clerk_application_many_allowed_origins": ("clerk", "low", "Application origin posture"),
    "clerk_redirect_url_custom_scheme_present": ("clerk", "medium", "Redirect URL scheme posture"),
    "clerk_jwt_template_audience_missing": ("clerk", "medium", "JWT template audience posture"),
    "clerk_jwt_template_issuer_missing": ("clerk", "low", "JWT template issuer posture"),
    "clerk_jwt_template_many_claims": ("clerk", "low", "JWT template claims posture"),
    "clerk_webhook_broad_event_scope": ("clerk", "low", "Webhook event scope posture"),
    "clerk_org_verified_domains_not_required": ("clerk", "medium", "Organization domain posture"),
    "clerk_org_invitations_enabled": ("clerk", "low", "Organization invitation posture"),
    "clerk_org_admin_role_missing": ("clerk", "medium", "Organization role posture"),
    "clerk_org_high_role_count": ("clerk", "low", "Organization role posture"),
    "clerk_org_high_permission_count": ("clerk", "medium", "Organization permission posture"),
    "clerk_session_device_tracking_disabled": ("clerk", "low", "Session device tracking posture"),
    "clerk_session_reverification_disabled": ("clerk", "medium", "Session reverification posture"),
    "clerk_session_long_lifetime_without_single_session": ("clerk", "medium", "Session lifetime posture"),
    # PagerDuty — M84B core security rules
    "pagerduty_service_no_escalation_policy": ("pagerduty", "high", "Service routing posture"),
    "pagerduty_service_no_integrations": ("pagerduty", "medium", "Service integration posture"),
    "pagerduty_service_ack_timeout_disabled": ("pagerduty", "medium", "Service timeout posture"),
    "pagerduty_service_auto_resolve_disabled": ("pagerduty", "medium", "Service timeout posture"),
    "pagerduty_service_alert_creation_limited": ("pagerduty", "low", "Service alert creation posture"),
    "pagerduty_service_no_teams": ("pagerduty", "low", "Service ownership posture"),
    "pagerduty_escalation_policy_no_rules": ("pagerduty", "high", "Escalation policy posture"),
    "pagerduty_escalation_policy_single_level": ("pagerduty", "medium", "Escalation policy posture"),
    "pagerduty_schedule_no_layers": ("pagerduty", "medium", "Schedule posture"),
    "pagerduty_schedule_no_teams": ("pagerduty", "low", "Schedule ownership posture"),
    "pagerduty_service_integration_missing_key_indicator": ("pagerduty", "medium", "Service integration posture"),
    "pagerduty_service_integration_email_type": ("pagerduty", "low", "Service integration posture"),
    "pagerduty_webhook_subscription_inactive": ("pagerduty", "medium", "Webhook subscription posture"),
    "pagerduty_webhook_subscription_non_https": ("pagerduty", "high", "Webhook transport posture"),
    "pagerduty_webhook_subscription_broad_event_scope": ("pagerduty", "medium", "Webhook subscription posture"),
    "pagerduty_event_orchestration_no_routes": ("pagerduty", "medium", "Event orchestration posture"),
    "pagerduty_event_orchestration_no_team": ("pagerduty", "low", "Event orchestration ownership posture"),
    "pagerduty_business_service_no_team": ("pagerduty", "low", "Business service ownership posture"),
    "pagerduty_business_service_no_contact": ("pagerduty", "low", "Business service contact posture"),
    "pagerduty_response_play_no_responders": ("pagerduty", "high", "Response play posture"),
    "pagerduty_response_play_no_subscribers": ("pagerduty", "low", "Response play subscriber posture"),
    "pagerduty_response_play_not_runnable": ("pagerduty", "medium", "Response play runnability posture"),
    # PagerDuty — M84C escalation/webhook risk expansion
    "pagerduty_escalation_policy_no_targets": ("pagerduty", "high", "Escalation policy target posture"),
    "pagerduty_escalation_policy_low_target_count": ("pagerduty", "medium", "Escalation policy target posture"),
    "pagerduty_escalation_policy_no_schedule_targets": ("pagerduty", "low", "Escalation policy routing posture"),
    "pagerduty_escalation_policy_no_team_targets": ("pagerduty", "low", "Escalation policy ownership posture"),
    "pagerduty_schedule_no_targets": ("pagerduty", "high", "Schedule coverage posture"),
    "pagerduty_schedule_low_target_count": ("pagerduty", "medium", "Schedule coverage posture"),
    "pagerduty_schedule_single_layer": ("pagerduty", "low", "Schedule layer posture"),
    "pagerduty_schedule_no_restrictions": ("pagerduty", "low", "Schedule restriction posture"),
    "pagerduty_service_integration_routing_key_missing": ("pagerduty", "medium", "Service integration posture"),
    "pagerduty_service_integration_unknown_type": ("pagerduty", "low", "Service integration posture"),
    "pagerduty_webhook_subscription_no_events": ("pagerduty", "medium", "Webhook subscription posture"),
    "pagerduty_webhook_subscription_secret_not_indicated": ("pagerduty", "medium", "Webhook authentication posture"),
    "pagerduty_webhook_subscription_broad_scope_high": ("pagerduty", "high", "Webhook subscription posture"),
    "pagerduty_webhook_subscription_account_scope": ("pagerduty", "medium", "Webhook subscription posture"),
    "pagerduty_event_orchestration_low_route_count": ("pagerduty", "low", "Event orchestration posture"),
    "pagerduty_response_play_low_responder_count": ("pagerduty", "medium", "Response play posture"),
    "pagerduty_response_play_no_team": ("pagerduty", "low", "Response play ownership posture"),
    "pagerduty_response_play_manual_only": ("pagerduty", "low", "Response play runnability posture"),
    # Linear — M85B core security rules
    "linear_workspace_missing_url_key": ("linear", "low", "Workspace configuration posture"),
    "linear_workspace_missing_logo": ("linear", "low", "Workspace configuration posture"),
    "linear_team_private": ("linear", "low", "Team visibility posture"),
    "linear_team_low_member_count": ("linear", "low", "Team membership posture"),
    "linear_team_no_projects": ("linear", "low", "Team project posture"),
    "linear_team_auto_archive_disabled": ("linear", "medium", "Team archive posture"),
    "linear_team_cycles_disabled": ("linear", "medium", "Team workflow posture"),
    "linear_team_long_cycle_duration": ("linear", "low", "Team cycle duration posture"),
    "linear_project_no_lead": ("linear", "medium", "Project ownership posture"),
    "linear_project_no_members": ("linear", "low", "Project membership posture"),
    "linear_project_high_issue_count": ("linear", "low", "Project issue volume posture"),
    "linear_project_unhealthy": ("linear", "medium", "Project health posture"),
    "linear_project_unknown_status": ("linear", "low", "Project status posture"),
    "linear_workflow_state_unknown_type": ("linear", "low", "Workflow state posture"),
    "linear_label_missing_team_scope": ("linear", "low", "Label scope posture"),
    "linear_webhook_disabled": ("linear", "medium", "Webhook posture"),
    "linear_webhook_no_secret_indicator": ("linear", "high", "Webhook signing posture"),
    "linear_webhook_non_https": ("linear", "high", "Webhook transport posture"),
    "linear_webhook_no_events": ("linear", "medium", "Webhook subscription posture"),
    "linear_webhook_broad_resource_scope": ("linear", "medium", "Webhook subscription posture"),
    "linear_view_shared": ("linear", "low", "View sharing posture"),
    "linear_cycle_high_issue_count": ("linear", "low", "Cycle issue volume posture"),
    "linear_integration_disabled": ("linear", "medium", "Integration posture"),
    "linear_integration_unknown_type": ("linear", "low", "Integration type posture"),
    # Linear — M85C workflow/webhook risk expansion
    "linear_workspace_low_team_count": ("linear", "low", "Workspace team posture"),
    "linear_workspace_no_webhooks": ("linear", "medium", "Workspace webhook posture"),
    "linear_workspace_no_integrations": ("linear", "low", "Workspace integration posture"),
    "linear_team_no_backlog_state": ("linear", "medium", "Team workflow state posture"),
    "linear_team_no_started_state": ("linear", "medium", "Team workflow state posture"),
    "linear_team_no_completed_state": ("linear", "high", "Team workflow state posture"),
    "linear_team_no_canceled_state": ("linear", "low", "Team workflow state posture"),
    "linear_team_low_workflow_state_count": ("linear", "medium", "Team workflow state posture"),
    "linear_team_no_labels": ("linear", "low", "Team label posture"),
    "linear_team_no_webhooks": ("linear", "medium", "Team webhook posture"),
    "linear_project_no_team_scope": ("linear", "medium", "Project team scope posture"),
    "linear_webhook_issue_comment_scope": ("linear", "medium", "Webhook resource scope posture"),
    "linear_webhook_attachment_scope": ("linear", "low", "Webhook resource scope posture"),
    "linear_view_shared_without_team_scope": ("linear", "medium", "View sharing posture"),
    "linear_integration_workspace_scoped": ("linear", "low", "Integration scope posture"),
    # Jira core security rules — M86B
    "jira_site_missing_url": ("jira", "low", "Site configuration posture"),
    "jira_site_no_projects": ("jira", "low", "Site project posture"),
    "jira_site_no_webhooks": ("jira", "low", "Site webhook posture"),
    "jira_site_no_automation_rules": ("jira", "low", "Site automation posture"),
    "jira_project_missing_key": ("jira", "low", "Project configuration posture"),
    "jira_project_private": ("jira", "medium", "Project visibility posture"),
    "jira_project_archived": ("jira", "low", "Project lifecycle posture"),
    "jira_project_deleted": ("jira", "low", "Project lifecycle posture"),
    "jira_project_simplified": ("jira", "low", "Project style posture"),
    "jira_project_unknown_type_category": ("jira", "low", "Project type posture"),
    "jira_project_unknown_style_category": ("jira", "low", "Project style posture"),
    "jira_project_no_boards": ("jira", "low", "Project board posture"),
    "jira_project_no_issue_types": ("jira", "low", "Project issue type posture"),
    "jira_project_no_lead": ("jira", "low", "Project ownership posture"),
    "jira_board_missing_project_link": ("jira", "low", "Board project posture"),
    "jira_board_unknown_type_category": ("jira", "low", "Board type posture"),
    "jira_board_unknown_location_type": ("jira", "medium", "Board location posture"),
    "jira_workflow_inactive": ("jira", "medium", "Workflow posture"),
    "jira_workflow_no_statuses": ("jira", "medium", "Workflow status posture"),
    "jira_workflow_no_transitions": ("jira", "medium", "Workflow transition posture"),
    "jira_workflow_excessive_global_transitions": ("jira", "low", "Workflow transition posture"),
    "jira_workflow_scheme_unused": ("jira", "low", "Workflow scheme posture"),
    "jira_workflow_scheme_no_default": ("jira", "medium", "Workflow scheme posture"),
    "jira_permission_scheme_anonymous_grant": ("jira", "high", "Permission scheme posture"),
    "jira_permission_scheme_anyone_grant": ("jira", "high", "Permission scheme posture"),
    "jira_permission_scheme_logged_in_grant": ("jira", "medium", "Permission scheme posture"),
    "jira_notification_scheme_email_recipients": ("jira", "medium", "Notification scheme posture"),
    "jira_notification_scheme_group_recipients": ("jira", "low", "Notification scheme posture"),
    "jira_notification_scheme_no_notifications": ("jira", "medium", "Notification scheme posture"),
    "jira_issue_type_scheme_no_default": ("jira", "low", "Issue type scheme posture"),
    "jira_issue_type_scheme_no_types": ("jira", "low", "Issue type scheme posture"),
    "jira_field_configuration_scheme_no_configurations": ("jira", "medium", "Field configuration posture"),
    "jira_field_configuration_scheme_hidden_required_conflict": ("jira", "medium", "Field configuration posture"),
    "jira_screen_scheme_no_fields": ("jira", "low", "Screen scheme posture"),
    "jira_screen_scheme_no_screens": ("jira", "low", "Screen scheme posture"),
    "jira_webhook_disabled": ("jira", "medium", "Webhook posture"),
    "jira_webhook_no_secret_indicator": ("jira", "high", "Webhook signing posture"),
    "jira_webhook_non_https": ("jira", "high", "Webhook transport posture"),
    "jira_webhook_no_events": ("jira", "medium", "Webhook subscription posture"),
    "jira_webhook_no_jql_filter": ("jira", "low", "Webhook filter posture"),
    "jira_automation_rule_disabled": ("jira", "medium", "Automation rule posture"),
    "jira_automation_rule_unknown_trigger": ("jira", "low", "Automation rule posture"),
    "jira_automation_rule_global_scope": ("jira", "medium", "Automation rule scope posture"),
    # Jira workflow/webhook risk expansion — M86C
    "jira_workflow_no_done_status": ("jira", "low", "Workflow status posture"),
    "jira_workflow_no_in_progress_status": ("jira", "low", "Workflow status posture"),
    "jira_workflow_high_transition_rule_count": ("jira", "medium", "Workflow transition posture"),
    "jira_workflow_high_validator_count": ("jira", "medium", "Workflow transition posture"),
    "jira_workflow_high_condition_count": ("jira", "medium", "Workflow transition posture"),
    "jira_workflow_high_post_function_count": ("jira", "low", "Workflow transition posture"),
    "jira_workflow_orphan_statuses": ("jira", "medium", "Workflow status posture"),
    "jira_workflow_scheme_unmapped_issue_types": ("jira", "medium", "Workflow scheme posture"),
    "jira_workflow_scheme_low_workflow_count": ("jira", "low", "Workflow scheme posture"),
    "jira_workflow_scheme_high_issue_type_mapping_count": ("jira", "low", "Workflow scheme posture"),
    "jira_permission_scheme_public_browse_projects": ("jira", "medium", "Permission scheme posture"),
    "jira_permission_scheme_public_administer_projects": ("jira", "high", "Permission scheme posture"),
    "jira_permission_scheme_public_manage_sprints": ("jira", "high", "Permission scheme posture"),
    "jira_permission_scheme_public_create_issues": ("jira", "high", "Permission scheme posture"),
    "jira_permission_scheme_public_transition_issues": ("jira", "medium", "Permission scheme posture"),
    "jira_permission_scheme_unknown_holder": ("jira", "medium", "Permission scheme posture"),
    "jira_permission_scheme_high_privilege_grants": ("jira", "medium", "Permission scheme posture"),
    "jira_permission_scheme_high_public_grant_count": ("jira", "medium", "Permission scheme posture"),
    "jira_notification_scheme_unknown_recipients": ("jira", "medium", "Notification scheme posture"),
    "jira_notification_scheme_high_event_count": ("jira", "low", "Notification scheme posture"),
    "jira_webhook_comment_event_scope": ("jira", "medium", "Webhook subscription posture"),
    "jira_webhook_attachment_event_scope": ("jira", "medium", "Webhook subscription posture"),
    "jira_webhook_sprint_event_scope": ("jira", "low", "Webhook subscription posture"),
    "jira_webhook_worklog_event_scope": ("jira", "low", "Webhook subscription posture"),
    "jira_webhook_all_issue_events": ("jira", "medium", "Webhook subscription posture"),
    "jira_automation_rule_web_request_action": ("jira", "high", "Automation rule action posture"),
    "jira_automation_rule_email_action": ("jira", "medium", "Automation rule action posture"),
    "jira_automation_rule_external_action": ("jira", "high", "Automation rule action posture"),
    "jira_automation_rule_comment_action": ("jira", "low", "Automation rule action posture"),
    "jira_automation_rule_high_action_count": ("jira", "medium", "Automation rule posture"),
    "jira_automation_rule_high_branch_count": ("jira", "medium", "Automation rule posture"),
    "jira_automation_rule_multi_project_scope": ("jira", "medium", "Automation rule scope posture"),
    "jira_automation_rule_unknown_scope": ("jira", "low", "Automation rule scope posture"),
    "jira_board_no_filter_indicator": ("jira", "low", "Board scope posture"),
    "jira_board_broad_jql_filter": ("jira", "medium", "Board scope posture"),
    "jira_board_high_quick_filter_count": ("jira", "low", "Board scope posture"),
    "jira_board_unknown_swimlane_strategy": ("jira", "low", "Board scope posture"),
    "jira_board_no_columns": ("jira", "low", "Board scope posture"),
    "jira_screen_scheme_unmapped_screens": ("jira", "low", "Screen scheme posture"),
    # GitLab — M87B core security rules
    "gitlab_project_public_visibility": ("gitlab", "high", "Project visibility posture"),
    "gitlab_project_shared_runners_enabled": ("gitlab", "medium", "Project runner posture"),
    "gitlab_project_snippets_enabled_public": ("gitlab", "low", "Project feature posture"),
    "gitlab_group_public_visibility": ("gitlab", "high", "Group visibility posture"),
    "gitlab_branch_force_push_enabled": ("gitlab", "high", "Branch protection posture"),
    "gitlab_branch_code_owner_approval_missing": ("gitlab", "medium", "Branch protection posture"),
    "gitlab_webhook_secret_missing": ("gitlab", "high", "Webhook security posture"),
    "gitlab_webhook_ssl_verification_disabled": ("gitlab", "high", "Webhook security posture"),
    "gitlab_ci_unprotected_unmasked_variables": ("gitlab", "high", "CI/CD variable posture"),
    "gitlab_deploy_key_write_enabled": ("gitlab", "high", "Deploy key posture"),
    "gitlab_runner_untagged": ("gitlab", "medium", "Runner security posture"),
    "gitlab_merge_request_approval_not_required": ("gitlab", "medium", "Merge request approval posture"),
    # GitLab — M87C branch/webhook/CI risk expansion
    "gitlab_webhook_http_scheme": ("gitlab", "high", "Webhook security posture"),
    "gitlab_webhook_broad_event_scope": ("gitlab", "medium", "Webhook security posture"),
    "gitlab_webhook_pipeline_job_events": ("gitlab", "medium", "Webhook security posture"),
    "gitlab_branch_push_access_broad": ("gitlab", "medium", "Branch protection posture"),
    "gitlab_branch_merge_access_broad": ("gitlab", "medium", "Branch protection posture"),
    "gitlab_ci_variables_unprotected": ("gitlab", "medium", "CI/CD variable posture"),
    "gitlab_ci_variables_unmasked": ("gitlab", "medium", "CI/CD variable posture"),
    "gitlab_runner_shared_enabled": ("gitlab", "medium", "Runner security posture"),
    "gitlab_mr_approval_reset_disabled": ("gitlab", "medium", "Merge request approval posture"),
    "gitlab_mr_approver_override_allowed": ("gitlab", "medium", "Merge request approval posture"),
    "gitlab_project_wiki_enabled_public": ("gitlab", "low", "Project feature posture"),
    "gitlab_project_packages_enabled_public": ("gitlab", "low", "Project feature posture"),
    "gitlab_project_container_registry_enabled_public": ("gitlab", "medium", "Project feature posture"),
    # ── M88B: Terraform Cloud core security rules ──────────────────────────────
    "terraform_cloud_organization_two_factor_not_required": ("terraform_cloud", "medium", "Organization authentication posture"),
    "terraform_cloud_organization_sso_not_enabled": ("terraform_cloud", "low", "Organization authentication posture"),
    "terraform_cloud_workspace_auto_apply_enabled": ("terraform_cloud", "high", "Workspace execution posture"),
    "terraform_cloud_workspace_global_remote_state_enabled": ("terraform_cloud", "high", "Workspace state posture"),
    "terraform_cloud_workspace_local_execution_mode": ("terraform_cloud", "medium", "Workspace execution posture"),
    "terraform_cloud_workspace_vcs_connection_missing": ("terraform_cloud", "medium", "Workspace VCS posture"),
    "terraform_cloud_workspace_queue_all_runs_disabled": ("terraform_cloud", "medium", "Workspace execution posture"),
    "terraform_cloud_workspace_unpinned_terraform_version": ("terraform_cloud", "low", "Workspace configuration posture"),
    "terraform_cloud_workspace_non_sensitive_variables_present": ("terraform_cloud", "medium", "Variable posture"),
    "terraform_cloud_workspace_no_sensitive_variables": ("terraform_cloud", "low", "Variable posture"),
    "terraform_cloud_notification_http_webhook": ("terraform_cloud", "high", "Notification security posture"),
    "terraform_cloud_notification_token_missing": ("terraform_cloud", "medium", "Notification security posture"),
    "terraform_cloud_policy_set_advisory_enforcement": ("terraform_cloud", "medium", "Policy enforcement posture"),
    "terraform_cloud_policy_set_empty": ("terraform_cloud", "low", "Policy enforcement posture"),
    "terraform_cloud_team_admin_access": ("terraform_cloud", "high", "Team access posture"),
    "terraform_cloud_team_apply_access": ("terraform_cloud", "medium", "Team access posture"),
    "terraform_cloud_variable_set_global_scope": ("terraform_cloud", "medium", "Variable set scope posture"),
    "terraform_cloud_state_version_present": ("terraform_cloud", "low", "State version posture"),
    # ── M88C: Terraform Cloud workspace/variable/policy risk expansion ────────
    "terraform_cloud_workspace_agent_execution_mode": ("terraform_cloud", "medium", "Workspace execution posture"),
    "terraform_cloud_workspace_file_triggers_disabled": ("terraform_cloud", "medium", "Workspace execution posture"),
    "terraform_cloud_workspace_speculative_plans_disabled": ("terraform_cloud", "low", "Workspace configuration posture"),
    "terraform_cloud_workspace_run_triggers_present": ("terraform_cloud", "medium", "Run trigger posture"),
    "terraform_cloud_workspace_many_trigger_prefixes": ("terraform_cloud", "low", "Workspace configuration posture"),
    "terraform_cloud_workspace_latest_run_failed": ("terraform_cloud", "medium", "Workspace execution posture"),
    "terraform_cloud_workspace_environment_variables_non_sensitive": ("terraform_cloud", "medium", "Variable posture"),
    "terraform_cloud_workspace_terraform_variables_non_sensitive": ("terraform_cloud", "low", "Variable posture"),
    "terraform_cloud_variable_set_non_sensitive_variables": ("terraform_cloud", "medium", "Variable set scope posture"),
    "terraform_cloud_variable_set_broad_scope": ("terraform_cloud", "medium", "Variable set scope posture"),
    "terraform_cloud_policy_set_global_scope": ("terraform_cloud", "medium", "Policy enforcement posture"),
    "terraform_cloud_policy_set_broad_scope_advisory": ("terraform_cloud", "medium", "Policy enforcement posture"),
    "terraform_cloud_policy_set_no_workspace_or_project_scope": ("terraform_cloud", "low", "Policy enforcement posture"),
    "terraform_cloud_notification_broad_trigger_scope": ("terraform_cloud", "medium", "Notification security posture"),
    "terraform_cloud_notification_disabled": ("terraform_cloud", "low", "Notification security posture"),
    "terraform_cloud_run_trigger_enabled": ("terraform_cloud", "medium", "Run trigger posture"),
    "terraform_cloud_team_write_access": ("terraform_cloud", "medium", "Team access posture"),
    "terraform_cloud_team_custom_permissions": ("terraform_cloud", "low", "Team access posture"),
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
