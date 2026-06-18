"""Security rule registry — M61.7.

Authoritative set of implemented security-rule keys (the prefix of a
``finding_key``, which is shaped ``rule_key:record_identifier``). Used by the
rule enable/disable settings to validate rule keys and by the evaluator to map a
finding back to its base rule.

Keep this in sync with the rule constants in ``app/services/security_rules/*``.
This is metadata only — it never evaluates provider state.
"""

from __future__ import annotations

# Exact rule keys emitted by app/services/security_rules/*.py (verified M61.7).
KNOWN_RULE_KEYS: frozenset[str] = frozenset(
    {
        # GitHub
        "github_webhook_http",
        "github_branch_protection_missing",
        "github_force_pushes_allowed",
        "github_branch_deletion_allowed",
        "github_pr_review_not_required",
        "github_status_checks_not_required",
        "github_deploy_key_write_access",
        "github_env_protection_missing",
        # GitHub rulesets (M69.5A)
        "github_ruleset_not_enforced",
        "github_ruleset_force_push_allowed",
        "github_ruleset_pr_review_missing",
        "github_ruleset_status_checks_missing",
        "github_ruleset_bypass_actors_present",
        "github_ruleset_weak_target_coverage",
        # GitHub automation permissions (M69.5B)
        "github_automation_admin_permission",
        "github_automation_write_permission",
        "github_token_broad_scopes",
        "github_webhook_secret_missing",
        # AWS
        "aws_public_admin_port",
        "aws_public_database_port",
        "aws_public_all_ports",
        "aws_s3_public_policy",
        "aws_s3_public_acl",
        "aws_iam_admin_policy_attached",
        "aws_access_key_unused",
        # Cloudflare
        "cloudflare_ssl_mode_weak",
        "cloudflare_always_https_off",
        "cloudflare_min_tls_weak",
        "cloudflare_security_level_low",
        "cloudflare_development_mode_on",
        "cloudflare_hsts_disabled",
        "cloudflare_waf_rule_disabled",
        "cloudflare_dns_private_origin",
        # Supabase
        "supabase_rls_disabled",
        "supabase_anonymous_access_enabled",
        "supabase_jwt_expiry_long",
        "supabase_public_select_sensitive_table",
        "supabase_public_write_policy",
        "supabase_edge_function_jwt_disabled",
        "supabase_auth_protection_missing",
        # Firebase
        "firebase_rules_public",
        "firebase_storage_rules_public",
        "firebase_anonymous_auth_enabled",
        # Firebase — M72A (Realtime Database rules + auth hardening)
        "firebase_database_public_read",
        "firebase_database_public_write",
        "firebase_auth_protection_missing",
        # Stripe
        "stripe_webhook_http",
        # Stripe — M73A (webhook posture + payment links + portal + account)
        "stripe_webhook_disabled",
        "stripe_webhook_broad_events",
        "stripe_payment_link_tax_disabled",
        "stripe_payment_link_promo_codes_enabled",
        "stripe_portal_subscription_cancel_enabled",
        "stripe_portal_login_enabled",
        "stripe_account_capability_incomplete",
        # Vercel
        "vercel_preview_unprotected",
        "vercel_production_branch_missing",
        "vercel_production_branch_unusual",
        "vercel_domain_unverified",
        "vercel_env_var_broad_target",
        "vercel_sensitive_env_var_broad_scope",
        "vercel_deploy_hook_production_branch",
        # Shopify
        "shopify_webhook_http",
        # Shopify — M74A
        "shopify_webhook_high_risk_topic",
        "shopify_app_broad_write_scopes",
        "shopify_app_customer_data_scope",
        "shopify_domain_ssl_missing",
        "shopify_domain_unverified",
        "shopify_policy_missing",
        # Azure — M77B
        "azure_nsg_public_admin_ingress",
        "azure_nsg_public_broad_ingress",
        "azure_storage_public_blob_access",
        "azure_storage_public_network_access",
        "azure_storage_weak_tls",
        "azure_storage_shared_key_enabled",
        "azure_key_vault_public_network_access",
        "azure_key_vault_purge_protection_disabled",
        "azure_key_vault_soft_delete_disabled",
        "azure_key_vault_rbac_disabled",
        # Azure — M77C
        "azure_role_assignment_broad_privilege",
        "azure_app_service_https_disabled",
        "azure_app_service_ftp_enabled",
        "azure_app_service_weak_tls",
        "azure_app_service_public_network_access",
        "azure_sql_public_network_access",
        "azure_sql_weak_tls",
        "azure_aks_local_accounts_enabled",
        "azure_aks_public_api_access",
        "azure_aks_network_policy_missing",
        # Google Cloud — M78B
        "google_cloud_iam_public_member",
        "google_cloud_iam_broad_privileged_role",
        "google_cloud_firewall_public_admin_ingress",
        "google_cloud_firewall_public_broad_ingress",
        "google_cloud_firewall_rule_no_targets",
        "google_cloud_storage_public_access_prevention_disabled",
        "google_cloud_storage_uniform_access_disabled",
        "google_cloud_storage_versioning_disabled",
        "google_cloud_storage_retention_not_locked",
        # Google Cloud — M78C
        "google_cloud_sql_public_network_access",
        "google_cloud_sql_weak_tls",
        "google_cloud_sql_backups_disabled",
        "google_cloud_sql_deletion_protection_disabled",
        "google_cloud_run_public_invoker",
        "google_cloud_run_all_ingress",
        "google_cloud_gke_public_control_plane",
        "google_cloud_gke_legacy_abac_enabled",
        "google_cloud_gke_network_policy_disabled",
        "google_cloud_gke_workload_identity_disabled",
        "google_cloud_service_account_user_managed_keys",
        "google_cloud_service_account_old_keys",
        "google_cloud_secret_manager_auto_replication_without_cmek",
        # Twilio — M79B
        "twilio_phone_number_sms_webhook_missing",
        "twilio_phone_number_voice_webhook_missing",
        "twilio_phone_number_status_callback_missing",
        "twilio_messaging_service_inbound_webhook_missing",
        "twilio_messaging_service_fallback_missing",
        "twilio_messaging_service_status_callback_missing",
        "twilio_verify_short_code_length",
        "twilio_verify_lookup_disabled",
        "twilio_account_suspended",
        # Twilio — M79C
        "twilio_api_key_stale",
        "twilio_messaging_service_observability_gap",
        "twilio_messaging_service_number_level_inbound_webhook",
        "twilio_messaging_service_long_validity_period",
        "twilio_phone_number_messaging_observability_gap",
        "twilio_phone_number_voice_observability_gap",
        "twilio_verify_psd2_disabled",
        "twilio_verify_sms_to_landlines_allowed",
        # SendGrid — M80B
        "sendgrid_api_key_broad_scopes",
        "sendgrid_sender_identity_unverified",
        "sendgrid_sender_identity_locked",
        "sendgrid_domain_authentication_invalid",
        "sendgrid_domain_automatic_security_disabled",
        "sendgrid_domain_authentication_legacy",
        "sendgrid_spam_check_disabled",
        "sendgrid_sandbox_mode_enabled",
        "sendgrid_bcc_enabled",
        "sendgrid_click_tracking_enabled",
        "sendgrid_open_tracking_enabled",
        "sendgrid_subscription_tracking_disabled",
        "sendgrid_event_webhook_disabled",
        "sendgrid_event_webhook_url_missing",
        "sendgrid_suppression_settings_empty",
        # SendGrid — M80C
        "sendgrid_sender_identity_reply_domain_mismatch",
        "sendgrid_domain_dns_records_missing",
        "sendgrid_default_domain_authentication_invalid",
        "sendgrid_footer_disabled",
        "sendgrid_bounce_purge_disabled",
        "sendgrid_template_engine_enabled",
        "sendgrid_google_analytics_tracking_enabled",
        "sendgrid_event_webhook_broad_event_stream",
        "sendgrid_inbound_parse_enabled",
        "sendgrid_inbound_parse_raw_email_enabled",
        "sendgrid_inbound_parse_spam_check_disabled",
        # Auth0 — M81B
        "auth0_tenant_session_lifetime_extended",
        "auth0_tenant_idle_session_lifetime_extended",
        "auth0_tenant_dynamic_client_registration_enabled",
        "auth0_application_no_callbacks",
        "auth0_application_many_callbacks",
        "auth0_application_many_allowed_origins",
        "auth0_application_oidc_non_conformant",
        "auth0_application_weak_jwt_algorithm",
        "auth0_refresh_token_rotation_disabled",
        "auth0_refresh_token_lifetime_extended",
        "auth0_connection_no_enabled_clients",
        "auth0_connection_weak_password_policy",
        "auth0_resource_server_offline_access_enabled",
        "auth0_resource_server_token_lifetime_extended",
        "auth0_resource_server_rbac_disabled",
        "auth0_rule_disabled",
        "auth0_rule_large_script",
        "auth0_action_not_deployed",
        "auth0_action_secrets_present",
        "auth0_mfa_factor_disabled",
        "auth0_custom_domain_not_ready",
        "auth0_custom_domain_weak_tls_policy",
        # Auth0 — M81C OAuth/application risk expansion
        "auth0_application_password_grant_enabled",
        "auth0_application_implicit_grant_enabled",
        "auth0_application_public_client_credentials_enabled",
        "auth0_application_refresh_grant_without_rotation",
        "auth0_application_many_grant_types",
        "auth0_application_device_code_grant_enabled",
        "auth0_application_wildcard_callback",
        "auth0_application_wildcard_allowed_origin",
        "auth0_application_wildcard_logout_url",
        "auth0_application_localhost_callback",
        "auth0_application_localhost_origin",
        "auth0_application_callback_missing_https",
        "auth0_application_origin_missing_https",
        "auth0_public_client_refresh_tokens_enabled",
        "auth0_application_token_endpoint_auth_none",
        # Datadog — M82B core security rules
        "datadog_monitor_disabled",
        "datadog_monitor_unrestricted_roles",
        "datadog_monitor_notify_no_data_disabled",
        "datadog_monitor_long_query",
        "datadog_slo_no_monitors",
        "datadog_slo_low_target",
        "datadog_dashboard_public_url_present",
        "datadog_dashboard_unrestricted_roles",
        "datadog_webhook_without_secret_headers",
        "datadog_webhook_payload_template_present",
        "datadog_notification_integration_no_channels",
        "datadog_application_key_broad_scopes",
        "datadog_api_key_disabled",
        "datadog_role_high_permission_count",
        "datadog_team_no_members",
        "datadog_cloud_integration_broad_collection",
        "datadog_cloud_integration_log_collection_enabled",
        # Datadog — M82C monitor/webhook risk expansion
        "datadog_monitor_no_notifications",
        "datadog_monitor_message_template_present",
        "datadog_monitor_no_warning_threshold",
        "datadog_monitor_no_recovery_threshold",
        "datadog_monitor_silenced_scopes_present",
        "datadog_monitor_notify_audit_disabled",
        "datadog_monitor_require_full_window_disabled",
        "datadog_monitor_query_wildcard_scope",
        "datadog_monitor_broad_group_by",
        "datadog_monitor_long_no_data_timeframe",
        "datadog_webhook_custom_headers_without_secret_headers",
        "datadog_webhook_large_payload_template",
        "datadog_webhook_auth_material_present",
        "datadog_webhook_non_https_endpoint",
    }
)


def is_known_rule_key(rule_key: str) -> bool:
    """True when *rule_key* is an implemented security rule."""
    return rule_key in KNOWN_RULE_KEYS


def base_rule_key(finding_key: str) -> str:
    """Return the rule key portion of a ``finding_key`` (``rule_key:record_id``).

    If there is no colon, the whole string is treated as the rule key.
    """
    if not finding_key:
        return finding_key
    idx = finding_key.find(":")
    return finding_key if idx < 0 else finding_key[:idx]
