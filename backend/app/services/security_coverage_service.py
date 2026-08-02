"""Security Exposure coverage-quality service — M62.3.

Read-only. For each provider, inspects STORED snapshots (never calls provider
APIs) to report whether ConfigTrace is collecting the metadata needed to
evaluate Security Exposure rules.

Coverage is a TRUST signal, not a safety verdict:
  * "good"  = every expected record type for the provider's rules was observed.
  * "limited" = some expected record types observed, others missing.
  * "not_synced" = connected but no usable records observed yet.
  * "needs_attention" = the integration needs reconnect / recent syncs failed.
  * "not_connected" = no integration for this provider.

Good coverage does NOT mean a system is safe — it only means the rules have
enough data to run. Demo/deleted integrations are ignored.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.integration import Integration
from app.models.resource import Resource
from app.services.security_rule_registry import KNOWN_RULE_KEYS
from app.services.security_rule_settings_service import get_disabled_rule_keys
from app.services.snapshot_service import get_latest_snapshot

logger = logging.getLogger(__name__)

PROVIDERS = [
    "github",
    "aws",
    "cloudflare",
    "supabase",
    "firebase",
    "stripe",
    "vercel",
    "shopify",
    "azure",
    "google_cloud",
    "twilio",
    "sendgrid",
    "auth0",
    "datadog",
    "clerk",
    "pagerduty",
    "linear",
    "jira",
    "gitlab",
    "terraform_cloud",
    "kubernetes",
    "okta",
    "entra",
    "snowflake",
    "sentry",
]

# rule_key → the snapshot record_type(s) the rule consumes. A rule is
# "supported by observed records" when ANY of its record types is present.
RULE_RECORD_TYPES: dict[str, tuple[str, ...]] = {
    # GitHub
    "github_webhook_http": ("github_webhook",),
    "github_branch_protection_missing": ("github_branch_protection",),
    "github_force_pushes_allowed": ("github_branch_protection",),
    "github_branch_deletion_allowed": ("github_branch_protection",),
    "github_pr_review_not_required": ("github_branch_protection",),
    "github_status_checks_not_required": ("github_branch_protection",),
    "github_deploy_key_write_access": ("github_deploy_key",),
    "github_env_protection_missing": ("github_environment_protection",),
    # GitHub rulesets (M69.5A)
    "github_ruleset_not_enforced": ("github_ruleset",),
    "github_ruleset_force_push_allowed": ("github_ruleset",),
    "github_ruleset_pr_review_missing": ("github_ruleset",),
    "github_ruleset_status_checks_missing": ("github_ruleset",),
    "github_ruleset_bypass_actors_present": ("github_ruleset",),
    "github_ruleset_weak_target_coverage": ("github_ruleset",),
    # GitHub automation permissions (M69.5B)
    "github_automation_admin_permission": ("github_automation_permissions",),
    "github_automation_write_permission": ("github_automation_permissions",),
    "github_token_broad_scopes": ("github_automation_permissions",),
    "github_webhook_secret_missing": ("github_webhook",),
    "github_webhook_ssl_verification_disabled": ("github_webhook",),
    # GitHub new QA rules
    "github_actions_broad_permissions": ("github_actions_permissions",),
    "github_actions_workflow_token_write_permission": ("github_actions_permissions",),
    "github_actions_can_approve_pull_requests": ("github_actions_permissions",),
    "github_wiki_enabled": ("github_repo_settings",),
    "github_pages_enabled": ("github_pages",),
    "github_branch_admin_bypass_allowed": ("github_branch_protection",),
    # AWS
    "aws_public_admin_port": ("aws_security_group_rule",),
    "aws_public_database_port": ("aws_security_group_rule",),
    "aws_public_all_ports": ("aws_security_group_rule",),
    "aws_s3_public_policy": ("aws_s3_bucket",),
    "aws_s3_public_acl": ("aws_s3_bucket",),
    "aws_iam_admin_policy_attached": ("aws_iam_policy_attachment",),
    "aws_iam_broad_policy_attached": ("aws_iam_policy_attachment",),
    "aws_root_mfa_disabled": ("aws_iam_account_summary",),
    "aws_access_key_unused": ("aws_iam_access_key",),
    # Cloudflare
    "cloudflare_ssl_mode_weak": ("cloudflare_zone_setting",),
    "cloudflare_always_https_off": ("cloudflare_zone_setting",),
    "cloudflare_min_tls_weak": ("cloudflare_zone_setting",),
    "cloudflare_security_level_low": ("cloudflare_zone_setting",),
    "cloudflare_development_mode_on": ("cloudflare_zone_setting",),
    "cloudflare_hsts_disabled": ("cloudflare_zone_setting",),
    "cloudflare_waf_rule_disabled": ("cloudflare_waf_rule",),
    "cloudflare_dns_private_origin": ("A", "AAAA"),
    "cloudflare_access_policy_bypass": ("cloudflare_access_policy",),
    "cloudflare_access_policy_disabled": ("cloudflare_access_policy",),
    "cloudflare_page_rule_http_forward": ("cloudflare_page_rule",),
    "cloudflare_access_application_disabled": ("cloudflare_access_application",),
    # Supabase
    "supabase_rls_disabled": ("supabase_rls_status",),
    "supabase_anonymous_access_enabled": ("supabase_auth_config",),
    "supabase_jwt_expiry_long": ("supabase_auth_config",),
    "supabase_public_select_sensitive_table": ("supabase_rls_status",),
    "supabase_public_write_policy": ("supabase_rls_status",),
    "supabase_edge_function_jwt_disabled": ("supabase_edge_function",),
    "supabase_auth_protection_missing": ("supabase_auth_config",),
    "supabase_refresh_token_rotation_disabled": ("supabase_auth_config",),
    "supabase_captcha_disabled": ("supabase_auth_config",),
    "supabase_password_update_reauth_disabled": ("supabase_auth_config",),
    # Firebase
    "firebase_rules_public": ("firebase_firestore_ruleset",),
    "firebase_storage_rules_public": ("firebase_storage_ruleset",),
    "firebase_anonymous_auth_enabled": ("firebase_auth_config",),
    # Firebase — M72A
    "firebase_database_public_read": ("firebase_database_ruleset",),
    "firebase_database_public_write": ("firebase_database_ruleset",),
    "firebase_auth_protection_missing": ("firebase_auth_config",),
    # Firebase — M72C QA
    "firebase_storage_public_access_prevention_disabled": ("firebase_storage_bucket",),
    "firebase_app_check_unenforced_services": ("firebase_app_check_config",),
    # Stripe
    "stripe_webhook_http": ("stripe_webhook_endpoint",),
    # Stripe — M73A
    "stripe_webhook_disabled": ("stripe_webhook_endpoint",),
    "stripe_webhook_broad_events": ("stripe_webhook_endpoint",),
    "stripe_payment_link_tax_disabled": ("stripe_payment_link",),
    "stripe_payment_link_promo_codes_enabled": ("stripe_payment_link",),
    "stripe_portal_subscription_cancel_enabled": ("stripe_billing_portal_config",),
    "stripe_portal_login_enabled": ("stripe_billing_portal_config",),
    "stripe_account_capability_incomplete": ("stripe_account_settings",),
    # Vercel
    "vercel_preview_unprotected": ("vercel_deployment_protection",),
    "vercel_production_branch_missing": ("vercel_project",),
    "vercel_production_branch_unusual": ("vercel_project",),
    "vercel_domain_unverified": ("vercel_domain",),
    "vercel_env_var_broad_target": ("vercel_env_var",),
    "vercel_sensitive_env_var_broad_scope": ("vercel_env_var",),
    "vercel_deploy_hook_production_branch": ("vercel_deploy_hook_metadata",),
    # Shopify
    "shopify_webhook_http": ("shopify_webhook_subscription",),
    # Shopify — M74A
    "shopify_webhook_high_risk_topic": ("shopify_webhook_subscription",),
    "shopify_app_broad_write_scopes": ("shopify_app_scope_summary",),
    "shopify_app_customer_data_scope": ("shopify_app_scope_summary",),
    "shopify_domain_ssl_missing": ("shopify_domain",),
    "shopify_domain_unverified": ("shopify_domain",),
    "shopify_policy_missing": ("shopify_store_policy",),
    # Azure — M77B
    "azure_nsg_public_admin_ingress": ("azure_network_security_group",),
    "azure_nsg_public_broad_ingress": ("azure_network_security_group",),
    "azure_storage_public_blob_access": ("azure_storage_account",),
    "azure_storage_public_network_access": ("azure_storage_account",),
    "azure_storage_weak_tls": ("azure_storage_account",),
    "azure_storage_shared_key_enabled": ("azure_storage_account",),
    "azure_storage_https_only_disabled": ("azure_storage_account",),
    "azure_key_vault_public_network_access": ("azure_key_vault",),
    "azure_key_vault_purge_protection_disabled": ("azure_key_vault",),
    "azure_key_vault_soft_delete_disabled": ("azure_key_vault",),
    "azure_key_vault_rbac_disabled": ("azure_key_vault",),
    # Azure — M77C
    "azure_role_assignment_broad_privilege": ("azure_role_assignment",),
    "azure_app_service_https_disabled": ("azure_app_service",),
    "azure_app_service_ftp_enabled": ("azure_app_service",),
    "azure_app_service_weak_tls": ("azure_app_service",),
    "azure_app_service_public_network_access": ("azure_app_service",),
    "azure_sql_public_network_access": ("azure_sql_server",),
    "azure_sql_weak_tls": ("azure_sql_server",),
    "azure_aks_local_accounts_enabled": ("azure_aks_cluster",),
    "azure_aks_public_api_access": ("azure_aks_cluster",),
    "azure_aks_network_policy_missing": ("azure_aks_cluster",),
    # Google Cloud — M78B
    "google_cloud_iam_public_member": ("google_cloud_iam_policy_summary",),
    "google_cloud_iam_broad_privileged_role": ("google_cloud_iam_policy_summary",),
    "google_cloud_firewall_public_admin_ingress": ("google_cloud_firewall_rule",),
    "google_cloud_firewall_public_broad_ingress": ("google_cloud_firewall_rule",),
    "google_cloud_firewall_rule_no_targets": ("google_cloud_firewall_rule",),
    "google_cloud_storage_public_access_prevention_disabled": ("google_cloud_storage_bucket",),
    "google_cloud_storage_uniform_access_disabled": ("google_cloud_storage_bucket",),
    "google_cloud_storage_versioning_disabled": ("google_cloud_storage_bucket",),
    "google_cloud_storage_retention_not_locked": ("google_cloud_storage_bucket",),
    # Google Cloud — M78C: Cloud SQL
    "google_cloud_sql_public_network_access": ("google_cloud_sql_instance",),
    "google_cloud_sql_weak_tls": ("google_cloud_sql_instance",),
    "google_cloud_sql_backups_disabled": ("google_cloud_sql_instance",),
    "google_cloud_sql_deletion_protection_disabled": ("google_cloud_sql_instance",),
    # Google Cloud — M78C: Cloud Run
    "google_cloud_run_public_invoker": ("google_cloud_run_service",),
    "google_cloud_run_all_ingress": ("google_cloud_run_service",),
    # Google Cloud — M78C: GKE
    "google_cloud_gke_public_control_plane": ("google_cloud_gke_cluster",),
    "google_cloud_gke_legacy_abac_enabled": ("google_cloud_gke_cluster",),
    "google_cloud_gke_network_policy_disabled": ("google_cloud_gke_cluster",),
    "google_cloud_gke_workload_identity_disabled": ("google_cloud_gke_cluster",),
    "google_cloud_gke_shielded_nodes_disabled": ("google_cloud_gke_cluster",),
    # Google Cloud — M78C: Service account keys
    "google_cloud_service_account_user_managed_keys": ("google_cloud_service_account_key_summary",),
    "google_cloud_service_account_old_keys": ("google_cloud_service_account_key_summary",),
    # Google Cloud — M78C: Secret Manager
    "google_cloud_secret_manager_auto_replication_without_cmek": ("google_cloud_secret_manager_summary",),
    # Twilio — M79B
    "twilio_phone_number_sms_webhook_missing": ("twilio_incoming_phone_number",),
    "twilio_phone_number_voice_webhook_missing": ("twilio_incoming_phone_number",),
    "twilio_phone_number_status_callback_missing": ("twilio_incoming_phone_number",),
    "twilio_messaging_service_inbound_webhook_missing": ("twilio_messaging_service",),
    "twilio_messaging_service_fallback_missing": ("twilio_messaging_service",),
    "twilio_messaging_service_status_callback_missing": ("twilio_messaging_service",),
    "twilio_verify_short_code_length": ("twilio_verify_service",),
    "twilio_verify_lookup_disabled": ("twilio_verify_service",),
    "twilio_account_suspended": ("twilio_account",),
    # Twilio — M79C
    "twilio_api_key_stale": ("twilio_api_key_summary",),
    "twilio_messaging_service_observability_gap": ("twilio_messaging_service",),
    "twilio_messaging_service_number_level_inbound_webhook": ("twilio_messaging_service",),
    "twilio_messaging_service_long_validity_period": ("twilio_messaging_service",),
    "twilio_phone_number_messaging_observability_gap": ("twilio_incoming_phone_number",),
    "twilio_phone_number_voice_observability_gap": ("twilio_incoming_phone_number",),
    "twilio_verify_psd2_disabled": ("twilio_verify_service",),
    "twilio_verify_sms_to_landlines_allowed": ("twilio_verify_service",),
    "twilio_webhook_uses_http": ("twilio_incoming_phone_number", "twilio_messaging_service"),
    # SendGrid — M80B
    "sendgrid_api_key_broad_scopes": ("sendgrid_api_key",),
    "sendgrid_sender_identity_unverified": ("sendgrid_sender_identity",),
    "sendgrid_sender_identity_locked": ("sendgrid_sender_identity",),
    "sendgrid_domain_authentication_invalid": ("sendgrid_domain_authentication",),
    "sendgrid_domain_automatic_security_disabled": ("sendgrid_domain_authentication",),
    "sendgrid_domain_authentication_legacy": ("sendgrid_domain_authentication",),
    "sendgrid_spam_check_disabled": ("sendgrid_mail_settings",),
    "sendgrid_sandbox_mode_enabled": ("sendgrid_mail_settings",),
    "sendgrid_bcc_enabled": ("sendgrid_mail_settings",),
    "sendgrid_click_tracking_enabled": ("sendgrid_tracking_settings",),
    "sendgrid_open_tracking_enabled": ("sendgrid_tracking_settings",),
    "sendgrid_subscription_tracking_disabled": ("sendgrid_tracking_settings",),
    "sendgrid_event_webhook_disabled": ("sendgrid_webhook_settings",),
    "sendgrid_event_webhook_url_missing": ("sendgrid_webhook_settings",),
    "sendgrid_suppression_settings_empty": ("sendgrid_suppression_settings",),
    # SendGrid — M80C
    "sendgrid_sender_identity_reply_domain_mismatch": ("sendgrid_sender_identity",),
    "sendgrid_domain_dns_records_missing": ("sendgrid_domain_authentication",),
    "sendgrid_default_domain_authentication_invalid": ("sendgrid_domain_authentication",),
    "sendgrid_footer_disabled": ("sendgrid_mail_settings",),
    "sendgrid_bounce_purge_disabled": ("sendgrid_mail_settings",),
    "sendgrid_template_engine_enabled": ("sendgrid_mail_settings",),
    "sendgrid_google_analytics_tracking_enabled": ("sendgrid_tracking_settings",),
    "sendgrid_event_webhook_broad_event_stream": ("sendgrid_webhook_settings",),
    "sendgrid_inbound_parse_enabled": ("sendgrid_webhook_settings",),
    "sendgrid_inbound_parse_raw_email_enabled": ("sendgrid_webhook_settings",),
    "sendgrid_inbound_parse_spam_check_disabled": ("sendgrid_webhook_settings",),
    "sendgrid_event_webhook_not_signed": ("sendgrid_webhook_settings",),
    # Auth0 — M81B
    "auth0_tenant_session_lifetime_extended": ("auth0_tenant_settings",),
    "auth0_tenant_idle_session_lifetime_extended": ("auth0_tenant_settings",),
    "auth0_tenant_dynamic_client_registration_enabled": ("auth0_tenant_settings",),
    "auth0_application_no_callbacks": ("auth0_application",),
    "auth0_application_many_callbacks": ("auth0_application",),
    "auth0_application_many_allowed_origins": ("auth0_application",),
    "auth0_application_oidc_non_conformant": ("auth0_application",),
    "auth0_application_weak_jwt_algorithm": ("auth0_application",),
    "auth0_refresh_token_rotation_disabled": ("auth0_application",),
    "auth0_refresh_token_lifetime_extended": ("auth0_application",),
    "auth0_connection_no_enabled_clients": ("auth0_connection",),
    "auth0_connection_weak_password_policy": ("auth0_connection",),
    "auth0_resource_server_offline_access_enabled": ("auth0_resource_server",),
    "auth0_resource_server_token_lifetime_extended": ("auth0_resource_server",),
    "auth0_resource_server_rbac_disabled": ("auth0_resource_server",),
    "auth0_rule_disabled": ("auth0_rule",),
    "auth0_rule_large_script": ("auth0_rule",),
    "auth0_action_not_deployed": ("auth0_action",),
    "auth0_action_secrets_present": ("auth0_action",),
    "auth0_mfa_factor_disabled": ("auth0_mfa_factor",),
    "auth0_custom_domain_not_ready": ("auth0_custom_domain",),
    "auth0_custom_domain_weak_tls_policy": ("auth0_custom_domain",),
    # Auth0 — M81C OAuth/application risk expansion
    "auth0_application_password_grant_enabled": ("auth0_application",),
    "auth0_application_implicit_grant_enabled": ("auth0_application",),
    "auth0_application_public_client_credentials_enabled": ("auth0_application",),
    "auth0_application_refresh_grant_without_rotation": ("auth0_application",),
    "auth0_application_many_grant_types": ("auth0_application",),
    "auth0_application_device_code_grant_enabled": ("auth0_application",),
    "auth0_application_wildcard_callback": ("auth0_application",),
    "auth0_application_wildcard_allowed_origin": ("auth0_application",),
    "auth0_application_wildcard_logout_url": ("auth0_application",),
    "auth0_application_localhost_callback": ("auth0_application",),
    "auth0_application_localhost_origin": ("auth0_application",),
    "auth0_application_callback_missing_https": ("auth0_application",),
    "auth0_application_origin_missing_https": ("auth0_application",),
    "auth0_public_client_refresh_tokens_enabled": ("auth0_application",),
    "auth0_application_token_endpoint_auth_none": ("auth0_application",),
    "auth0_connection_mfa_disabled": ("auth0_connection",),
    "auth0_resource_server_weak_signing_algorithm": ("auth0_resource_server",),
    # Datadog — M82B
    "datadog_monitor_disabled": ("datadog_monitor",),
    "datadog_monitor_unrestricted_roles": ("datadog_monitor",),
    "datadog_monitor_notify_no_data_disabled": ("datadog_monitor",),
    "datadog_monitor_long_query": ("datadog_monitor",),
    "datadog_slo_no_monitors": ("datadog_slo",),
    "datadog_slo_low_target": ("datadog_slo",),
    "datadog_dashboard_public_url_present": ("datadog_dashboard",),
    "datadog_dashboard_unrestricted_roles": ("datadog_dashboard",),
    "datadog_webhook_without_secret_headers": ("datadog_webhook_integration",),
    "datadog_webhook_payload_template_present": ("datadog_webhook_integration",),
    "datadog_notification_integration_no_channels": ("datadog_notification_integration",),
    "datadog_application_key_broad_scopes": ("datadog_application_key_metadata",),
    "datadog_api_key_disabled": ("datadog_api_key_metadata",),
    "datadog_role_high_permission_count": ("datadog_role",),
    "datadog_team_no_members": ("datadog_team",),
    "datadog_cloud_integration_broad_collection": ("datadog_cloud_integration",),
    "datadog_cloud_integration_log_collection_enabled": ("datadog_cloud_integration",),
    # Datadog — M82C monitor/webhook expansion
    "datadog_monitor_no_notifications": ("datadog_monitor",),
    "datadog_monitor_message_template_present": ("datadog_monitor",),
    "datadog_monitor_no_warning_threshold": ("datadog_monitor",),
    "datadog_monitor_no_recovery_threshold": ("datadog_monitor",),
    "datadog_monitor_silenced_scopes_present": ("datadog_monitor",),
    "datadog_monitor_notify_audit_disabled": ("datadog_monitor",),
    "datadog_monitor_require_full_window_disabled": ("datadog_monitor",),
    "datadog_monitor_query_wildcard_scope": ("datadog_monitor",),
    "datadog_monitor_broad_group_by": ("datadog_monitor",),
    "datadog_monitor_long_no_data_timeframe": ("datadog_monitor",),
    "datadog_webhook_custom_headers_without_secret_headers": ("datadog_webhook_integration",),
    "datadog_webhook_large_payload_template": ("datadog_webhook_integration",),
    "datadog_webhook_auth_material_present": ("datadog_webhook_integration",),
    "datadog_webhook_non_https_endpoint": ("datadog_webhook_integration",),
    # Clerk — M83B
    "clerk_instance_mfa_disabled": ("clerk_instance_settings",),
    "clerk_instance_password_without_mfa": ("clerk_instance_settings",),
    "clerk_instance_sign_up_enabled": ("clerk_instance_settings",),
    "clerk_application_mfa_not_required": ("clerk_application",),
    "clerk_domain_unverified": ("clerk_domain",),
    "clerk_domain_ssl_disabled": ("clerk_domain",),
    "clerk_redirect_url_non_https": ("clerk_redirect_url_config",),
    "clerk_redirect_url_wildcard_present": ("clerk_redirect_url_config",),
    "clerk_redirect_url_localhost_present": ("clerk_redirect_url_config",),
    "clerk_jwt_template_custom_claims_present": ("clerk_jwt_template",),
    "clerk_jwt_template_long_lifetime": ("clerk_jwt_template",),
    "clerk_webhook_endpoint_disabled": ("clerk_webhook_endpoint",),
    "clerk_webhook_without_signing": ("clerk_webhook_endpoint",),
    "clerk_webhook_non_https": ("clerk_webhook_endpoint",),
    "clerk_email_sms_custom_sender_present": ("clerk_email_sms_settings",),
    "clerk_auth_strategy_mfa_not_required": ("clerk_auth_strategy",),
    "clerk_auth_strategy_password_without_mfa": ("clerk_auth_strategy",),
    "clerk_session_lifetime_extended": ("clerk_session_policy",),
    "clerk_session_inactivity_timeout_extended": ("clerk_session_policy",),
    "clerk_session_single_session_disabled": ("clerk_session_policy",),
    "clerk_session_token_rotation_disabled": ("clerk_session_policy",),
    # Clerk — M83C auth/application risk expansion
    "clerk_application_sign_up_enabled": ("clerk_application",),
    "clerk_application_password_without_mfa": ("clerk_application",),
    "clerk_application_oauth_without_mfa": ("clerk_application",),
    "clerk_application_saml_without_mfa": ("clerk_application",),
    "clerk_application_many_redirect_urls": ("clerk_application",),
    "clerk_application_many_allowed_origins": ("clerk_application",),
    "clerk_redirect_url_custom_scheme_present": ("clerk_redirect_url_config",),
    "clerk_jwt_template_audience_missing": ("clerk_jwt_template",),
    "clerk_jwt_template_issuer_missing": ("clerk_jwt_template",),
    "clerk_jwt_template_many_claims": ("clerk_jwt_template",),
    "clerk_webhook_broad_event_scope": ("clerk_webhook_endpoint",),
    "clerk_org_verified_domains_not_required": ("clerk_organization_settings",),
    "clerk_org_invitations_enabled": ("clerk_organization_settings",),
    "clerk_org_admin_role_missing": ("clerk_organization_settings",),
    "clerk_org_high_role_count": ("clerk_organization_settings",),
    "clerk_org_high_permission_count": ("clerk_organization_settings",),
    "clerk_session_device_tracking_disabled": ("clerk_session_policy",),
    "clerk_session_reverification_disabled": ("clerk_session_policy",),
    "clerk_session_long_lifetime_without_single_session": ("clerk_session_policy",),
    # PagerDuty — M84B core security rules
    "pagerduty_service_no_escalation_policy": ("pagerduty_service",),
    "pagerduty_service_no_integrations": ("pagerduty_service",),
    "pagerduty_service_ack_timeout_disabled": ("pagerduty_service",),
    "pagerduty_service_auto_resolve_disabled": ("pagerduty_service",),
    "pagerduty_service_alert_creation_limited": ("pagerduty_service",),
    "pagerduty_service_no_teams": ("pagerduty_service",),
    "pagerduty_escalation_policy_no_rules": ("pagerduty_escalation_policy",),
    "pagerduty_escalation_policy_single_level": ("pagerduty_escalation_policy",),
    "pagerduty_schedule_no_layers": ("pagerduty_schedule",),
    "pagerduty_schedule_no_teams": ("pagerduty_schedule",),
    "pagerduty_service_integration_missing_key_indicator": ("pagerduty_service_integration",),
    "pagerduty_service_integration_email_type": ("pagerduty_service_integration",),
    "pagerduty_webhook_subscription_inactive": ("pagerduty_webhook_subscription",),
    "pagerduty_webhook_subscription_non_https": ("pagerduty_webhook_subscription",),
    "pagerduty_webhook_subscription_broad_event_scope": ("pagerduty_webhook_subscription",),
    "pagerduty_event_orchestration_no_routes": ("pagerduty_event_orchestration",),
    "pagerduty_event_orchestration_no_team": ("pagerduty_event_orchestration",),
    "pagerduty_business_service_no_team": ("pagerduty_business_service",),
    "pagerduty_business_service_no_contact": ("pagerduty_business_service",),
    "pagerduty_response_play_no_responders": ("pagerduty_response_play",),
    "pagerduty_response_play_no_subscribers": ("pagerduty_response_play",),
    "pagerduty_response_play_not_runnable": ("pagerduty_response_play",),
    # PagerDuty — M84C escalation/webhook risk expansion
    "pagerduty_escalation_policy_no_targets": ("pagerduty_escalation_policy",),
    "pagerduty_escalation_policy_low_target_count": ("pagerduty_escalation_policy",),
    "pagerduty_escalation_policy_no_schedule_targets": ("pagerduty_escalation_policy",),
    "pagerduty_escalation_policy_no_team_targets": ("pagerduty_escalation_policy",),
    "pagerduty_schedule_no_targets": ("pagerduty_schedule",),
    "pagerduty_schedule_low_target_count": ("pagerduty_schedule",),
    "pagerduty_schedule_single_layer": ("pagerduty_schedule",),
    "pagerduty_schedule_no_restrictions": ("pagerduty_schedule",),
    "pagerduty_service_integration_routing_key_missing": ("pagerduty_service_integration",),
    "pagerduty_service_integration_unknown_type": ("pagerduty_service_integration",),
    "pagerduty_webhook_subscription_no_events": ("pagerduty_webhook_subscription",),
    "pagerduty_webhook_subscription_secret_not_indicated": ("pagerduty_webhook_subscription",),
    "pagerduty_webhook_subscription_broad_scope_high": ("pagerduty_webhook_subscription",),
    "pagerduty_webhook_subscription_account_scope": ("pagerduty_webhook_subscription",),
    "pagerduty_event_orchestration_low_route_count": ("pagerduty_event_orchestration",),
    "pagerduty_response_play_low_responder_count": ("pagerduty_response_play",),
    "pagerduty_response_play_no_team": ("pagerduty_response_play",),
    "pagerduty_response_play_manual_only": ("pagerduty_response_play",),
    # Linear — M85B core security rules
    "linear_workspace_missing_url_key": ("linear_workspace",),
    "linear_workspace_missing_logo": ("linear_workspace",),
    "linear_team_private": ("linear_team",),
    "linear_team_low_member_count": ("linear_team",),
    "linear_team_no_projects": ("linear_team",),
    "linear_team_auto_archive_disabled": ("linear_team",),
    "linear_team_cycles_disabled": ("linear_team",),
    "linear_team_long_cycle_duration": ("linear_team",),
    "linear_project_no_lead": ("linear_project",),
    "linear_project_no_members": ("linear_project",),
    "linear_project_high_issue_count": ("linear_project",),
    "linear_project_unhealthy": ("linear_project",),
    "linear_project_unknown_status": ("linear_project",),
    "linear_workflow_state_unknown_type": ("linear_workflow_state",),
    "linear_label_missing_team_scope": ("linear_label",),
    "linear_webhook_disabled": ("linear_webhook",),
    "linear_webhook_no_secret_indicator": ("linear_webhook",),
    "linear_webhook_non_https": ("linear_webhook",),
    "linear_webhook_no_events": ("linear_webhook",),
    "linear_webhook_broad_resource_scope": ("linear_webhook",),
    "linear_view_shared": ("linear_view",),
    "linear_cycle_high_issue_count": ("linear_cycle",),
    "linear_integration_disabled": ("linear_integration",),
    "linear_integration_unknown_type": ("linear_integration",),
    # Linear — M85C workflow/webhook risk expansion
    "linear_workspace_low_team_count": ("linear_workspace",),
    "linear_workspace_no_webhooks": ("linear_workspace",),
    "linear_workspace_no_integrations": ("linear_workspace",),
    "linear_team_no_backlog_state": ("linear_team",),
    "linear_team_no_started_state": ("linear_team",),
    "linear_team_no_completed_state": ("linear_team",),
    "linear_team_no_canceled_state": ("linear_team",),
    "linear_team_low_workflow_state_count": ("linear_team",),
    "linear_team_no_labels": ("linear_team",),
    "linear_team_no_webhooks": ("linear_team",),
    "linear_project_no_team_scope": ("linear_project",),
    "linear_webhook_issue_comment_scope": ("linear_webhook",),
    "linear_webhook_attachment_scope": ("linear_webhook",),
    "linear_view_shared_without_team_scope": ("linear_view",),
    "linear_integration_workspace_scoped": ("linear_integration",),
    # Jira — M86B
    "jira_site_missing_url": ("jira_site",),
    "jira_site_no_projects": ("jira_site",),
    "jira_site_no_webhooks": ("jira_site",),
    "jira_site_no_automation_rules": ("jira_site",),
    "jira_project_missing_key": ("jira_project",),
    "jira_project_private": ("jira_project",),
    "jira_project_archived": ("jira_project",),
    "jira_project_deleted": ("jira_project",),
    "jira_project_simplified": ("jira_project",),
    "jira_project_unknown_type_category": ("jira_project",),
    "jira_project_unknown_style_category": ("jira_project",),
    "jira_project_no_lead": ("jira_project",),
    "jira_board_unknown_type_category": ("jira_board",),
    "jira_board_unknown_location_type": ("jira_board",),
    "jira_board_missing_project_link": ("jira_board",),
    "jira_workflow_no_statuses": ("jira_workflow",),
    "jira_workflow_no_transitions": ("jira_workflow",),
    "jira_workflow_excessive_global_transitions": ("jira_workflow",),
    "jira_workflow_inactive": ("jira_workflow",),
    "jira_workflow_scheme_unused": ("jira_workflow_scheme",),
    "jira_workflow_scheme_no_default": ("jira_workflow_scheme",),
    "jira_permission_scheme_anonymous_grant": ("jira_permission_scheme",),
    "jira_permission_scheme_anyone_grant": ("jira_permission_scheme",),
    "jira_permission_scheme_logged_in_grant": ("jira_permission_scheme",),
    "jira_notification_scheme_no_notifications": ("jira_notification_scheme",),
    "jira_notification_scheme_email_recipients": ("jira_notification_scheme",),
    "jira_notification_scheme_group_recipients": ("jira_notification_scheme",),
    "jira_issue_type_scheme_no_default": ("jira_issue_type_scheme",),
    "jira_screen_scheme_no_screens": ("jira_screen_scheme",),
    "jira_webhook_disabled": ("jira_webhook",),
    "jira_webhook_no_secret_indicator": ("jira_webhook",),
    "jira_webhook_non_https": ("jira_webhook",),
    "jira_webhook_no_events": ("jira_webhook",),
    "jira_webhook_no_jql_filter": ("jira_webhook",),
    "jira_automation_rule_disabled": ("jira_automation_rule",),
    "jira_automation_rule_unknown_trigger": ("jira_automation_rule",),
    "jira_automation_rule_global_scope": ("jira_automation_rule",),
    # Jira — M86C workflow/webhook risk expansion
    "jira_workflow_no_done_status": ("jira_workflow",),
    "jira_workflow_no_in_progress_status": ("jira_workflow",),
    "jira_workflow_high_transition_rule_count": ("jira_workflow",),
    "jira_workflow_high_validator_count": ("jira_workflow",),
    "jira_workflow_high_condition_count": ("jira_workflow",),
    "jira_workflow_high_post_function_count": ("jira_workflow",),
    "jira_workflow_orphan_statuses": ("jira_workflow",),
    "jira_workflow_scheme_unmapped_issue_types": ("jira_workflow_scheme",),
    "jira_workflow_scheme_low_workflow_count": ("jira_workflow_scheme",),
    "jira_workflow_scheme_high_issue_type_mapping_count": ("jira_workflow_scheme",),
    "jira_permission_scheme_public_browse_projects": ("jira_permission_scheme",),
    "jira_permission_scheme_public_administer_projects": ("jira_permission_scheme",),
    "jira_permission_scheme_public_manage_sprints": ("jira_permission_scheme",),
    "jira_permission_scheme_public_create_issues": ("jira_permission_scheme",),
    "jira_permission_scheme_public_transition_issues": ("jira_permission_scheme",),
    "jira_permission_scheme_unknown_holder": ("jira_permission_scheme",),
    "jira_permission_scheme_high_privilege_grants": ("jira_permission_scheme",),
    "jira_permission_scheme_high_public_grant_count": ("jira_permission_scheme",),
    "jira_notification_scheme_unknown_recipients": ("jira_notification_scheme",),
    "jira_notification_scheme_high_event_count": ("jira_notification_scheme",),
    "jira_webhook_comment_event_scope": ("jira_webhook",),
    "jira_webhook_attachment_event_scope": ("jira_webhook",),
    "jira_webhook_sprint_event_scope": ("jira_webhook",),
    "jira_webhook_worklog_event_scope": ("jira_webhook",),
    "jira_webhook_all_issue_events": ("jira_webhook",),
    "jira_automation_rule_web_request_action": ("jira_automation_rule",),
    "jira_automation_rule_email_action": ("jira_automation_rule",),
    "jira_automation_rule_external_action": ("jira_automation_rule",),
    "jira_automation_rule_comment_action": ("jira_automation_rule",),
    "jira_automation_rule_high_action_count": ("jira_automation_rule",),
    "jira_automation_rule_high_branch_count": ("jira_automation_rule",),
    "jira_automation_rule_multi_project_scope": ("jira_automation_rule",),
    "jira_automation_rule_unknown_scope": ("jira_automation_rule",),
    "jira_board_no_filter_indicator": ("jira_board",),
    "jira_board_broad_jql_filter": ("jira_board",),
    "jira_board_high_quick_filter_count": ("jira_board",),
    "jira_board_unknown_swimlane_strategy": ("jira_board",),
    "jira_board_no_columns": ("jira_board",),
    "jira_screen_scheme_unmapped_screens": ("jira_screen_scheme",),
    "jira_workflow_draft": ("jira_workflow",),
    "jira_workflow_scheme_low_project_count": ("jira_workflow_scheme",),
    "jira_permission_scheme_high_grant_count": ("jira_permission_scheme",),
    "jira_webhook_broad_event_scope": ("jira_webhook",),
    "jira_automation_rule_high_component_count": ("jira_automation_rule",),
    # GitLab — M87B core security rules
    "gitlab_project_public_visibility": ("gitlab_project",),
    "gitlab_project_shared_runners_enabled": ("gitlab_project",),
    "gitlab_project_snippets_enabled_public": ("gitlab_project",),
    "gitlab_group_public_visibility": ("gitlab_group",),
    "gitlab_branch_force_push_enabled": ("gitlab_branch_protection",),
    "gitlab_branch_code_owner_approval_missing": ("gitlab_branch_protection",),
    "gitlab_webhook_secret_missing": ("gitlab_webhook",),
    "gitlab_webhook_ssl_verification_disabled": ("gitlab_webhook",),
    "gitlab_ci_unprotected_unmasked_variables": ("gitlab_ci_variable_summary",),
    "gitlab_deploy_key_write_enabled": ("gitlab_deploy_key_summary",),
    "gitlab_runner_untagged": ("gitlab_runner_summary",),
    "gitlab_merge_request_approval_not_required": ("gitlab_merge_request_approval_summary",),
    # GitLab — M87C branch/webhook/CI risk expansion
    "gitlab_webhook_http_scheme": ("gitlab_webhook",),
    "gitlab_webhook_broad_event_scope": ("gitlab_webhook",),
    "gitlab_webhook_pipeline_job_events": ("gitlab_webhook",),
    "gitlab_branch_push_access_broad": ("gitlab_branch_protection",),
    "gitlab_branch_merge_access_broad": ("gitlab_branch_protection",),
    "gitlab_ci_variables_unprotected": ("gitlab_ci_variable_summary",),
    "gitlab_ci_variables_unmasked": ("gitlab_ci_variable_summary",),
    "gitlab_runner_shared_enabled": ("gitlab_runner_summary",),
    "gitlab_mr_approval_reset_disabled": ("gitlab_merge_request_approval_summary",),
    "gitlab_mr_approver_override_allowed": ("gitlab_merge_request_approval_summary",),
    "gitlab_project_wiki_enabled_public": ("gitlab_project",),
    "gitlab_project_packages_enabled_public": ("gitlab_project",),
    "gitlab_project_container_registry_enabled_public": ("gitlab_project",),
    # ── M88B: Terraform Cloud core security rules ──────────────────────────────
    "terraform_cloud_organization_two_factor_not_required": ("terraform_cloud_organization",),
    "terraform_cloud_organization_sso_not_enabled": ("terraform_cloud_organization",),
    "terraform_cloud_workspace_auto_apply_enabled": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_global_remote_state_enabled": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_local_execution_mode": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_vcs_connection_missing": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_queue_all_runs_disabled": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_unpinned_terraform_version": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_non_sensitive_variables_present": ("terraform_cloud_workspace_variable_summary",),
    "terraform_cloud_workspace_no_sensitive_variables": ("terraform_cloud_workspace_variable_summary",),
    "terraform_cloud_notification_http_webhook": ("terraform_cloud_notification_configuration",),
    "terraform_cloud_notification_token_missing": ("terraform_cloud_notification_configuration",),
    "terraform_cloud_policy_set_advisory_enforcement": ("terraform_cloud_policy_set",),
    "terraform_cloud_policy_set_empty": ("terraform_cloud_policy_set",),
    "terraform_cloud_team_admin_access": ("terraform_cloud_team_access_summary",),
    "terraform_cloud_team_plan_access": ("terraform_cloud_team_access_summary",),
    "terraform_cloud_variable_set_global_scope": ("terraform_cloud_variable_set",),
    "terraform_cloud_state_version_present": ("terraform_cloud_state_version_summary",),
    # ── M88C: Terraform Cloud workspace/variable/policy risk expansion ─────────
    "terraform_cloud_workspace_agent_execution_mode": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_file_triggers_disabled": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_speculative_plans_disabled": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_run_triggers_present": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_many_trigger_prefixes": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_latest_run_failed": ("terraform_cloud_workspace",),
    "terraform_cloud_workspace_environment_variables_non_sensitive": ("terraform_cloud_workspace_variable_summary",),
    "terraform_cloud_workspace_terraform_variables_non_sensitive": ("terraform_cloud_workspace_variable_summary",),
    "terraform_cloud_variable_set_non_sensitive_variables": ("terraform_cloud_variable_set",),
    "terraform_cloud_variable_set_broad_scope": ("terraform_cloud_variable_set",),
    "terraform_cloud_policy_set_global_scope": ("terraform_cloud_policy_set",),
    "terraform_cloud_policy_set_broad_scope_advisory": ("terraform_cloud_policy_set",),
    "terraform_cloud_policy_set_no_workspace_or_project_scope": ("terraform_cloud_policy_set",),
    "terraform_cloud_notification_broad_trigger_scope": ("terraform_cloud_notification_configuration",),
    "terraform_cloud_notification_disabled": ("terraform_cloud_notification_configuration",),
    "terraform_cloud_run_trigger_enabled": ("terraform_cloud_run_trigger",),
    "terraform_cloud_team_write_access": ("terraform_cloud_team_access_summary",),
    "terraform_cloud_team_custom_permissions": ("terraform_cloud_team_access_summary",),
    # ── M89F: Kubernetes security findings ──────────────────────────────────────
    "kubernetes_privileged_container": ("kubernetes_container_security_context",),
    "kubernetes_root_container": ("kubernetes_container_security_context",),
    "kubernetes_run_as_non_root_disabled": ("kubernetes_container_security_context",),
    "kubernetes_privilege_escalation_allowed": ("kubernetes_container_security_context",),
    "kubernetes_dangerous_linux_capability": ("kubernetes_container_security_context",),
    "kubernetes_all_capabilities_added": ("kubernetes_container_security_context",),
    "kubernetes_seccomp_unconfined": ("kubernetes_container_security_context",),
    "kubernetes_apparmor_unconfined": ("kubernetes_container_security_context",),
    "kubernetes_writable_root_filesystem": ("kubernetes_container_security_context",),
    "kubernetes_mutable_image_tag": ("kubernetes_container_security_context",),
    "kubernetes_sensitive_host_port": ("kubernetes_container_security_context",),
    "kubernetes_privileged_host_access": ("kubernetes_deployment", "kubernetes_statefulset", "kubernetes_daemonset", "kubernetes_job", "kubernetes_cronjob", "kubernetes_pod"),
    "kubernetes_host_pid_enabled": ("kubernetes_deployment", "kubernetes_statefulset", "kubernetes_daemonset", "kubernetes_job", "kubernetes_cronjob", "kubernetes_pod"),
    "kubernetes_host_ipc_enabled": ("kubernetes_deployment", "kubernetes_statefulset", "kubernetes_daemonset", "kubernetes_job", "kubernetes_cronjob", "kubernetes_pod"),
    "kubernetes_host_network_enabled": ("kubernetes_deployment", "kubernetes_statefulset", "kubernetes_daemonset", "kubernetes_job", "kubernetes_cronjob", "kubernetes_pod"),
    "kubernetes_dangerous_hostpath": ("kubernetes_deployment", "kubernetes_statefulset", "kubernetes_daemonset", "kubernetes_job", "kubernetes_cronjob", "kubernetes_pod"),
    "kubernetes_container_runtime_socket_mounted": ("kubernetes_deployment", "kubernetes_statefulset", "kubernetes_daemonset", "kubernetes_job", "kubernetes_cronjob", "kubernetes_pod"),
    "kubernetes_service_account_token_automount": ("kubernetes_deployment", "kubernetes_statefulset", "kubernetes_daemonset", "kubernetes_job", "kubernetes_cronjob", "kubernetes_pod"),
    "kubernetes_cluster_admin_binding": ("kubernetes_rbac_subject_binding",),
    "kubernetes_unauthenticated_cluster_admin": ("kubernetes_rbac_subject_binding",),
    "kubernetes_authenticated_group_cluster_admin": ("kubernetes_rbac_subject_binding",),
    "kubernetes_all_service_accounts_cluster_admin": ("kubernetes_rbac_subject_binding",),
    "kubernetes_wildcard_rbac_permissions": ("kubernetes_rbac_subject_binding",),
    "kubernetes_rbac_bind_permission": ("kubernetes_rbac_subject_binding",),
    "kubernetes_rbac_escalate_permission": ("kubernetes_rbac_subject_binding",),
    "kubernetes_rbac_impersonate_permission": ("kubernetes_rbac_subject_binding",),
    "kubernetes_service_account_token_creation": ("kubernetes_rbac_subject_binding",),
    "kubernetes_secret_read_permission": ("kubernetes_rbac_subject_binding",),
    "kubernetes_secret_write_permission": ("kubernetes_rbac_subject_binding",),
    "kubernetes_pod_exec_permission": ("kubernetes_rbac_subject_binding",),
    "kubernetes_pod_attach_permission": ("kubernetes_rbac_subject_binding",),
    "kubernetes_broad_workload_creation": ("kubernetes_rbac_subject_binding",),
    "kubernetes_rbac_modification_permission": ("kubernetes_rbac_subject_binding",),
    "kubernetes_admission_webhook_modification_permission": ("kubernetes_rbac_subject_binding",),
    "kubernetes_crd_modification_permission": ("kubernetes_rbac_subject_binding",),
    "kubernetes_public_load_balancer": ("kubernetes_service",),
    "kubernetes_sensitive_nodeport": ("kubernetes_service_port",),
    "kubernetes_public_ingress_without_tls": ("kubernetes_ingress_rule",),
    "kubernetes_hostless_catchall_ingress": ("kubernetes_ingress_rule",),
    "kubernetes_public_gateway_listener": ("kubernetes_gateway_listener",),
    "kubernetes_network_policy_allows_all_ingress": ("kubernetes_network_policy",),
    "kubernetes_network_policy_allows_all_egress": ("kubernetes_network_policy",),
    "kubernetes_public_ipv4_cidr_allowed": ("kubernetes_network_policy",),
    "kubernetes_public_ipv6_cidr_allowed": ("kubernetes_network_policy",),
    "kubernetes_namespace_no_network_policy": ("kubernetes_namespace_network_posture",),
    "kubernetes_namespace_no_ingress_isolation": ("kubernetes_namespace_network_posture",),
    "kubernetes_namespace_no_egress_isolation": ("kubernetes_namespace_network_posture",),
    "kubernetes_validating_webhook_fail_open": ("kubernetes_validating_webhook",),
    "kubernetes_mutating_webhook_fail_open": ("kubernetes_mutating_webhook",),
    "kubernetes_broad_admission_webhook": ("kubernetes_validating_webhook", "kubernetes_mutating_webhook"),
    "kubernetes_admission_webhook_external_http": ("kubernetes_validating_webhook", "kubernetes_mutating_webhook"),
    "kubernetes_psa_privileged_enforcement": ("kubernetes_pod_security_admission",),
    "kubernetes_psa_enforcement_missing": ("kubernetes_pod_security_admission",),
    "kubernetes_psa_invalid_enforcement": ("kubernetes_pod_security_admission",),
    "kubernetes_psa_weak_with_privileged_workloads": ("kubernetes_pod_security_admission",),
    "kubernetes_namespace_weak_governance": ("kubernetes_namespace_governance_posture",),
    "kubernetes_privileged_identity_in_weak_namespace": ("kubernetes_namespace_governance_posture",),
    "kubernetes_privileged_workload_without_isolation": ("kubernetes_namespace_governance_posture",),
    "kubernetes_namespace_resource_governance_missing": ("kubernetes_namespace_governance_posture",),
    # Okta (message 6 of 8; connectable as of message 8)
    "okta_super_admin_assigned": ("okta_privileged_identity",),
    "okta_high_tier_admin_assigned": ("okta_privileged_identity",),
    "okta_custom_admin_role_high_risk": ("okta_admin_role",),
    "okta_admin_role_broad_resource_set": ("okta_user_admin_role_assignment", "okta_group_admin_role_assignment"),
    "okta_unscoped_admin_role_assignment": ("okta_user_admin_role_assignment", "okta_group_admin_role_assignment"),
    "okta_deprovisioned_identity_retains_admin_privilege": ("okta_privileged_identity",),
    "okta_suspended_identity_retains_admin_privilege": ("okta_privileged_identity",),
    "okta_dormant_privileged_identity": ("okta_privileged_identity",),
    "okta_never_used_privileged_identity": ("okta_privileged_identity",),
    "okta_privileged_group_grants_super_admin": ("okta_privileged_group",),
    "okta_privileged_group_grants_high_tier_admin": ("okta_privileged_group",),
    "okta_broad_privileged_group": ("okta_privileged_group",),
    "okta_signon_mfa_not_required": ("okta_policy_rule",),
    "okta_signon_mfa_optional": ("okta_policy_rule",),
    "okta_broad_allow_rule_without_mfa": ("okta_policy_rule",),
    "okta_phishing_resistant_not_required": ("okta_policy_rule",),
    "okta_weak_authenticator_enabled": ("okta_authenticator",),
    "okta_password_policy_weak_min_length": ("okta_policy",),
    "okta_password_policy_no_lockout": ("okta_policy",),
    "okta_password_policy_no_history": ("okta_policy",),
    "okta_password_policy_no_complexity": ("okta_policy",),
    "okta_oidc_wildcard_redirect": ("okta_application",),
    "okta_oidc_http_redirect": ("okta_application",),
    "okta_oidc_custom_scheme_redirect_non_native": ("okta_application",),
    "okta_saml_response_signing_disabled": ("okta_application",),
    "okta_saml_assertion_signing_disabled": ("okta_application",),
    "okta_weak_token_endpoint_auth": ("okta_application",),
    "okta_app_assigned_to_everyone_group": ("okta_application_group_assignment",),
    "okta_deprovisioned_user_retains_app_assignment": ("okta_application_user_assignment",),
    "okta_suspended_user_retains_app_assignment": ("okta_application_user_assignment",),
    # Microsoft Entra ID (message 8 of 8 — public launch). "entra" is now
    # in PROVIDERS above; the 45 rule -> record_type mappings below were
    # built in message 6 ahead of the public launch, mirroring Okta's own
    # message-5/message-8 sequencing.
    "entra_global_admin_assigned": ("entra_directory_role_assignment",),
    "entra_privileged_role_administrator_assigned": ("entra_directory_role_assignment",),
    "entra_privileged_authentication_administrator_assigned": ("entra_directory_role_assignment",),
    "entra_high_tier_admin_assigned": ("entra_directory_role_assignment",),
    "entra_guest_global_admin": ("entra_privileged_identity",),
    "entra_guest_has_high_privilege": ("entra_privileged_identity",),
    "entra_disabled_guest_retains_high_privilege": ("entra_privileged_identity",),
    "entra_disabled_identity_retains_admin_privilege": ("entra_privileged_identity",),
    "entra_group_has_global_admin": ("entra_privileged_group",),
    "entra_group_has_high_privilege": ("entra_privileged_group",),
    "entra_guest_member_in_privileged_group": ("entra_privileged_group",),
    "entra_privileged_group_broad_membership": ("entra_privileged_group",),
    "entra_service_principal_has_critical_privilege": ("entra_privileged_service_principal",),
    "entra_service_principal_has_high_privilege": ("entra_privileged_service_principal",),
    "entra_disabled_service_principal_retains_privilege": ("entra_privileged_service_principal",),
    "entra_service_principal_can_manage_directory_roles": ("entra_service_principal_app_role_assignment",),
    "entra_service_principal_can_manage_app_role_assignments": ("entra_service_principal_app_role_assignment",),
    "entra_service_principal_can_grant_arbitrary_permissions": ("entra_service_principal_app_role_assignment",),
    "entra_service_principal_has_application_management_permission": ("entra_service_principal_app_role_assignment",),
    "entra_service_principal_can_modify_conditional_access": ("entra_service_principal_app_role_assignment",),
    "entra_service_principal_can_modify_authentication_methods": ("entra_service_principal_app_role_assignment",),
    "entra_service_principal_has_directory_write_permission": ("entra_service_principal_app_role_assignment",),
    "entra_service_principal_has_user_write_permission": ("entra_service_principal_app_role_assignment",),
    "entra_service_principal_has_group_write_permission": ("entra_service_principal_app_role_assignment",),
    "entra_tenant_wide_critical_delegated_consent": ("entra_oauth2_permission_grant",),
    "entra_tenant_wide_high_risk_delegated_consent": ("entra_oauth2_permission_grant",),
    "entra_user_scoped_critical_consent": ("entra_oauth2_permission_grant",),
    "entra_user_scoped_high_risk_consent": ("entra_oauth2_permission_grant",),
    "entra_external_unverified_app_tenant_wide_consent": ("entra_oauth2_permission_grant",),
    "entra_ca_broad_access_without_mfa": ("entra_conditional_access_policy",),
    "entra_ca_access_without_mfa": ("entra_conditional_access_policy",),
    "entra_ca_mfa_optional_within_grant_controls": ("entra_conditional_access_policy",),
    "entra_ca_legacy_auth_not_blocked": ("entra_conditional_access_policy",),
    "entra_ca_report_only_broad_protection": ("entra_conditional_access_policy",),
    "entra_weak_authentication_method_enabled": ("entra_authentication_method",),
    "entra_authentication_strength_not_phishing_resistant": ("entra_authentication_strength",),
    "entra_application_wildcard_redirect": ("entra_application",),
    "entra_application_http_redirect": ("entra_application",),
    "entra_application_custom_scheme_redirect_unexpected": ("entra_application",),
    "entra_application_expired_credential": ("entra_application",),
    "entra_service_principal_expired_credential": ("entra_service_principal",),
    "entra_service_principal_assignment_not_required": ("entra_service_principal",),
    "entra_disabled_user_retains_application_assignment": ("entra_application_user_assignment",),
    "entra_dynamic_group_assigned_to_application": ("entra_application_group_assignment",),
    "entra_role_assignable_group_assigned_to_application": ("entra_application_group_assignment",),
    # Snowflake (message 6 of 8)
    "snowflake_user_accountadmin": ("snowflake_privileged_user",),
    "snowflake_service_user_accountadmin": ("snowflake_privileged_user",),
    "snowflake_user_securityadmin": ("snowflake_privileged_user",),
    "snowflake_user_can_manage_grants": ("snowflake_privileged_user",),
    "snowflake_user_sysadmin_or_useradmin": ("snowflake_privileged_user",),
    "snowflake_disabled_privileged_user": ("snowflake_privileged_user",),
    "snowflake_legacy_service_user_privileged": ("snowflake_privileged_user",),
    "snowflake_legacy_service_user": ("snowflake_privileged_user",),
    "snowflake_user_high_risk_future_grant": ("snowflake_privileged_user",),
    "snowflake_custom_role_manage_grants": ("snowflake_privileged_role",),
    "snowflake_custom_role_manage_grants_identity_admin": ("snowflake_privileged_role",),
    "snowflake_custom_role_high_privilege": ("snowflake_privileged_role",),
    "snowflake_role_controls_managed_access_schema": ("snowflake_privileged_role",),
    "snowflake_role_owns_security_integration_high_privilege": ("snowflake_privileged_role",),
    "snowflake_role_owns_storage_integration_high_privilege": ("snowflake_privileged_role",),
    "snowflake_role_owns_external_access_integration_high_privilege": ("snowflake_privileged_role",),
    "snowflake_role_owns_authentication_policy_high_privilege": ("snowflake_privileged_role",),
    "snowflake_role_owns_network_policy_high_privilege": ("snowflake_privileged_role",),
    "snowflake_high_privilege_role_owns_database": ("snowflake_privileged_role",),
    "snowflake_future_ownership_grant": ("snowflake_privileged_role",),
    "snowflake_public_future_ownership_grant": ("snowflake_public_exposure",),
    "snowflake_public_future_write_access": ("snowflake_public_exposure",),
    "snowflake_public_future_data_access": ("snowflake_public_exposure",),
    "snowflake_public_future_broad_privilege": ("snowflake_public_exposure",),
    "snowflake_network_policy_allows_anywhere": ("snowflake_network_policy",),
    "snowflake_mfa_optional_with_password": ("snowflake_authentication_policy",),
    "snowflake_mfa_optional_for_person_auth": ("snowflake_authentication_policy",),
    "snowflake_mfa_password_only_scope": ("snowflake_authentication_policy",),
    "snowflake_scim_critical_privilege_run_as": ("snowflake_security_integration",),
    "snowflake_scim_high_privilege_run_as": ("snowflake_security_integration",),
    "snowflake_saml_integration_incomplete_config": ("snowflake_security_integration",),
    "sentry_active_organization_owner": ("sentry_privileged_member",),
    "sentry_active_organization_manager": ("sentry_privileged_member",),
    "sentry_active_organization_admin": ("sentry_privileged_member",),
    "sentry_pending_privileged_invitation": ("sentry_privileged_member",),
    "sentry_member_broad_routing_authority": ("sentry_privileged_member",),
    "sentry_member_team_admin_without_org_role": ("sentry_privileged_member",),
    "sentry_team_has_broad_routing_authority": ("sentry_privileged_team",),
    "sentry_team_has_unresolved_members": ("sentry_privileged_team",),
    "sentry_metric_alert_unrouted": ("sentry_metric_alert_rule",),
    "sentry_issue_alert_unrouted": ("sentry_issue_alert_rule",),
    "sentry_metric_alert_disabled_with_routing_configured": ("sentry_metric_alert_rule",),
    "sentry_issue_alert_disabled_with_routing_configured": ("sentry_issue_alert_rule",),
    "sentry_alert_targets_missing_team": ("sentry_routing_context",),
    "sentry_alert_targets_missing_member": ("sentry_routing_context",),
    "sentry_alert_references_inactive_member": ("sentry_routing_context",),
    "sentry_alert_references_disabled_integration": ("sentry_routing_context",),
    "sentry_ownership_targets_missing_team": ("sentry_routing_context",),
    "sentry_ownership_targets_missing_member": ("sentry_routing_context",),
    "sentry_ownership_targets_inactive_member": ("sentry_routing_context",),
    "sentry_repository_pending_deletion": ("sentry_repository",),
}

# Friendly, human surfaces per provider for display (no internal jargon).
PROVIDER_SURFACES: dict[str, list[str]] = {
    "github": ["Webhooks", "Branch protection", "Deploy keys", "Environment protection", "Rulesets", "Automation permissions", "Repository settings", "Pages"],
    "aws": ["Security group rules", "S3 buckets", "IAM policy attachments", "IAM access keys", "IAM account summary (root MFA)"],
    "cloudflare": ["Zone settings", "WAF rules", "DNS records"],
    "supabase": ["Row-level security", "Public table policies", "Auth configuration", "Edge Functions"],
    "firebase": ["Firestore rules", "Realtime Database rules", "Storage rules", "Auth configuration"],
    "stripe": ["Webhook endpoints", "Payment links", "Customer portal", "Account configuration"],
    "vercel": ["Deployment protection", "Production branch", "Domains", "Environment variables", "Deploy hooks"],
    "shopify": ["Webhook subscriptions", "App scopes", "Domains", "Store policies"],
    "azure": [
        "Network security groups",
        "Storage accounts",
        "Key Vaults",
        "Identity / Role assignments",
        "App Service / Functions",
        "SQL Servers",
        "AKS Clusters",
    ],
    "google_cloud": [
        "Project metadata",
        "IAM policy bindings",
        "VPC networks",
        "VPC firewall rules",
        "Cloud Storage buckets",
        "Cloud SQL instances",
        "Cloud Run services",
        "GKE clusters",
        "Service account keys",
        "Secret Manager",
    ],
    "twilio": [
        "Account metadata",
        "Incoming phone numbers",
        "Messaging services",
        "Verify services",
    ],
    "sendgrid": [
        "API key metadata",
        "Verified sender identities",
        "Domain authentication",
        "Mail settings",
        "Tracking settings",
        "Event webhook configuration",
        "Suppression settings",
    ],
    "auth0": [
        "Tenant settings",
        "Applications / clients",
        "Connections",
        "APIs / resource servers",
        "Rules",
        "Actions",
        "MFA / Guardian factors",
        "Custom domains",
    ],
    "datadog": [
        "Monitors",
        "SLOs",
        "Dashboards",
        "Webhook integrations",
        "Notification integrations",
        "API key metadata",
        "Application key metadata",
        "Roles",
        "Teams",
        "Cloud integrations",
    ],
    "clerk": [
        "Instance settings",
        "Applications",
        "Domains",
        "Redirect URLs",
        "JWT templates",
        "Webhook endpoints",
        "Email/SMS settings",
        "Authentication strategies",
        "Organization settings",
        "Session policy",
    ],
    "pagerduty": [
        "Services",
        "Escalation policies",
        "Schedules",
        "Service integrations",
        "Webhook subscriptions",
        "Event orchestrations",
        "Business services",
        "Response plays",
    ],
    "linear": [
        "Workspace configuration",
        "Teams",
        "Projects",
        "Workflow states",
        "Issue labels",
        "Webhook subscriptions",
        "Custom views",
        "Active cycles",
        "Integrations",
    ],
    "jira": [
        "Site configuration",
        "Projects",
        "Boards",
        "Workflows",
        "Workflow schemes",
        "Permission schemes",
        "Notification schemes",
        "Issue type schemes",
        "Field configuration schemes",
        "Screen schemes",
        "Webhook subscriptions",
        "Automation rules",
    ],
    "gitlab": [
        "Projects",
        "Groups",
        "Branch protection rules",
        "Webhook subscriptions",
        "CI/CD variable summaries",
        "Deploy key summaries",
        "Runner summaries",
        "Merge request approval summaries",
    ],
    "terraform_cloud": [
        "Organization posture",
        "Workspace execution posture",
        "Workspace variable summaries",
        "Notification configurations",
        "Policy set enforcement posture",
        "Team access summaries",
        "Variable set scope posture",
        "State version summaries",
        "Run trigger posture",
    ],
    "kubernetes": [
        "Container security context",
        "Workload host/Pod-spec posture",
        "RBAC subject bindings",
        "Services / ports",
        "Ingress rules",
        "Gateway listeners",
        "NetworkPolicies",
        "Namespace network posture",
        "Admission webhooks",
        "Pod Security Admission",
        "Namespace governance posture",
    ],
    "okta": [
        "Administrator role assignments",
        "Privileged identity / group posture",
        "Authentication policies & sign-on rules",
        "MFA & authenticator enrollment posture",
        "Password policy",
        "Application SSO (OIDC/SAML) configuration",
        "Application user/group assignments",
    ],
    "entra": [
        "Directory role assignments & privileged identity/group/service-principal posture",
        "Conditional Access & MFA requirement posture",
        "Authentication strengths & authentication methods policy",
        "Applications, service principals, and enterprise-app assignments",
        "OAuth delegated permission grants / consent posture",
    ],
    "snowflake": [
        "Effective-privilege posture (privileged users/roles, ACCOUNTADMIN/SECURITYADMIN/MANAGE GRANTS)",
        "PUBLIC role future-grant exposure",
        "Network policy anywhere-access posture",
        "Authentication policy MFA enrollment posture",
        "Security integration (SAML/OAuth/SCIM) posture and SCIM run-as role privilege",
    ],
    "sentry": [
        "Privileged organization members & pending privileged invitations",
        "Privileged team / combined routing authority posture",
        "Alert coverage (enabled rules with no notification actions)",
        "Alert & ownership notification routing (missing/inactive targets, disabled integrations)",
        "Repository configuration integrity",
    ],
}


# ── M62.8 diagnostics ────────────────────────────────────────────────────────
#
# Per record_type, a careful human message + any provider permission hints to
# show when ConfigTrace has NOT observed that metadata. These are diagnostics
# (help users understand/fix coverage gaps), never findings, and never claim a
# provider is misconfigured — wording stays in "may need / could indicate /
# ConfigTrace has not observed / check provider permissions".
RECORD_TYPE_DIAGNOSTICS: dict[str, dict[str, Any]] = {
    # GitHub
    "github_branch_protection": {
        "message": "ConfigTrace has not observed default-branch protection metadata.",
        "hints": ["Check that the GitHub App has repository administration/metadata access where required."],
    },
    "github_webhook": {
        "message": "Webhook metadata was not observed for this repository/resource.",
        "hints": [],
    },
    "github_deploy_key": {
        "message": "Deploy key metadata may require repository-level access.",
        "hints": [],
    },
    "github_environment_protection": {
        "message": "Environment protection metadata may require repository-level access.",
        "hints": [],
    },
    "github_actions_permissions": {
        "message": "Missing GitHub Actions permission records may indicate insufficient scope to read repository Actions settings.",
        "hints": ["Ensure the token or app has 'actions' read scope on the repository."],
    },
    "github_ruleset": {
        "message": "Missing GitHub ruleset records may indicate insufficient repository ruleset permissions.",
        "hints": ["Ensure the token or app has 'administration' scope to read rulesets."],
    },
    "github_automation_permissions": {
        "message": "Missing GitHub automation permission records may indicate the credential cannot read repository permission posture.",
        "hints": ["Review token scopes or GitHub App installation permissions."],
    },
    "github_pages": {
        "message": "GitHub Pages metadata was not observed for this repository/resource.",
        "hints": ["Ensure the token or app has 'pages' read scope on the repository."],
    },
    # AWS
    "aws_security_group_rule": {
        "message": "EC2 security group rule metadata was not observed.",
        "hints": ["ec2:DescribeSecurityGroups"],
    },
    "aws_s3_bucket": {
        "message": "S3 bucket public-access metadata was not observed.",
        "hints": ["s3:GetBucketPolicyStatus", "s3:GetBucketAcl", "s3:GetPublicAccessBlock"],
    },
    "aws_iam_policy_attachment": {
        "message": "IAM policy attachment metadata was not observed.",
        "hints": ["iam:ListAttachedUserPolicies", "iam:ListAttachedRolePolicies"],
    },
    "aws_iam_access_key": {
        "message": "IAM access key metadata was not observed.",
        "hints": ["iam:ListAccessKeys", "iam:GetAccessKeyLastUsed"],
    },
    "aws_iam_account_summary": {
        "message": "IAM account summary (root MFA) metadata was not observed.",
        "hints": ["iam:GetAccountSummary"],
    },
    # Cloudflare
    "cloudflare_zone_setting": {
        "message": "Zone setting metadata was not observed.",
        "hints": ["Zone settings read access"],
    },
    "cloudflare_waf_rule": {
        "message": "WAF rule metadata was not observed.",
        "hints": ["WAF / rulesets read access"],
    },
    "A": {"message": "DNS A record metadata was not observed.", "hints": []},
    "AAAA": {"message": "DNS AAAA record metadata was not observed.", "hints": []},
    # Supabase
    "supabase_rls_status": {
        "message": "Table RLS metadata was not observed.",
        "hints": [],
    },
    "supabase_auth_config": {
        "message": "Auth configuration metadata was not observed.",
        "hints": [],
    },
    # Firebase
    "firebase_firestore_ruleset": {
        "message": "Firestore ruleset metadata was not observed.",
        "hints": [],
    },
    "firebase_database_ruleset": {
        "message": "Realtime Database ruleset metadata was not observed.",
        "hints": ["A Realtime Database instance + rules read access are required."],
    },
    "firebase_storage_ruleset": {
        "message": "Storage ruleset metadata was not observed.",
        "hints": [],
    },
    "firebase_auth_config": {
        "message": "Auth configuration metadata was not observed.",
        "hints": [],
    },
    "firebase_storage_bucket": {
        "message": "Storage bucket metadata was not observed.",
        "hints": ["Grant roles/storage.legacyBucketReader for bucket-metadata-only access."],
    },
    "firebase_app_check_config": {
        "message": "App Check configuration metadata was not observed.",
        "hints": ["Verify the service account can read App Check service settings."],
    },
    # Stripe
    "stripe_webhook_endpoint": {
        "message": "Webhook endpoint metadata was not observed.",
        "hints": ["Verify the API key can list webhook endpoints."],
    },
    "stripe_payment_link": {
        "message": "Payment link metadata was not observed.",
        "hints": ["Verify the API key has read access to Payment Links."],
    },
    "stripe_billing_portal_config": {
        "message": "Customer portal configuration metadata was not observed.",
        "hints": ["Verify the API key has read access to Billing Portal configurations."],
    },
    "stripe_account_settings": {
        "message": "Account settings metadata was not observed.",
        "hints": ["A restricted key without the Account permission cannot read account settings."],
    },
    # Vercel
    "vercel_deployment_protection": {
        "message": "Deployment protection metadata was not observed.",
        "hints": ["Verify project/team API access."],
    },
    # Shopify
    "shopify_app_scope_summary": {
        "message": "App scope summary metadata was not observed.",
        "hints": ["Verify the access token can read /admin/oauth/access_scopes.json."],
    },
    "shopify_domain": {
        "message": "Shop domain metadata was not observed.",
        "hints": ["Verify the access token can read /admin/api/{ver}/shop/domains.json."],
    },
    "shopify_store_policy": {
        "message": "Store policy metadata was not observed.",
        "hints": ["Verify the access token can read /admin/api/{ver}/policies.json."],
    },
    "shopify_webhook_subscription": {
        "message": "Webhook subscription metadata was not observed.",
        "hints": ["Verify the app/admin API can read webhook subscriptions."],
    },
    # Twilio — M79B
    "twilio_account": {
        "message": "Twilio account metadata was not observed.",
        "hints": ["Verify the Account SID and auth token credentials are valid."],
    },
    "twilio_incoming_phone_number": {
        "message": "Twilio incoming phone number metadata was not observed.",
        "hints": ["Verify the credentials can list incoming phone numbers via the Twilio REST API."],
    },
    "twilio_messaging_service": {
        "message": "Twilio Messaging Service metadata was not observed.",
        "hints": ["Verify the credentials can list Messaging Services via the Twilio Messaging API."],
    },
    "twilio_verify_service": {
        "message": "Twilio Verify Service metadata was not observed.",
        "hints": ["Verify the credentials can list Verify Services via the Twilio Verify API. This surface may be absent if no Verify Services are configured."],
    },
    "twilio_api_key_summary": {
        "message": "Twilio API key metadata was not observed.",
        "hints": ["Verify the credentials can list API keys via the Twilio REST API. This surface may be absent if no API keys have been created."],
    },
    # SendGrid — M80B
    "sendgrid_api_key": {
        "message": "SendGrid API key metadata was not observed.",
        "hints": ["Verify the SendGrid API key has permission to list API keys (GET /v3/api_keys). Some restricted keys may not have this scope."],
    },
    "sendgrid_sender_identity": {
        "message": "SendGrid verified sender identity metadata was not observed.",
        "hints": ["Verify the API key can read verified senders (GET /v3/verified_senders). This surface may be absent if no sender identities have been configured."],
    },
    "sendgrid_domain_authentication": {
        "message": "SendGrid domain authentication metadata was not observed.",
        "hints": ["Verify the API key can read domain authentication (GET /v3/whitelabel/domains). This surface may be absent if no domains have been authenticated."],
    },
    "sendgrid_mail_settings": {
        "message": "SendGrid mail settings metadata was not observed.",
        "hints": ["Verify the API key can read mail settings (GET /v3/mail_settings)."],
    },
    "sendgrid_tracking_settings": {
        "message": "SendGrid tracking settings metadata was not observed.",
        "hints": ["Verify the API key can read tracking settings (GET /v3/tracking_settings)."],
    },
    "sendgrid_webhook_settings": {
        "message": "SendGrid event webhook settings metadata was not observed.",
        "hints": ["Verify the API key can read event webhook settings (GET /v3/user/webhooks/event/settings)."],
    },
    "sendgrid_suppression_settings": {
        "message": "SendGrid suppression settings metadata was not observed.",
        "hints": ["Verify the API key can read ASM suppression groups (GET /v3/asm/groups). This surface may be absent if no suppression groups are configured."],
    },
    # Google Cloud — M78C
    "google_cloud_sql_instance": {
        "message": "Cloud SQL instance metadata was not observed.",
        "hints": ["Verify the service account has roles/cloudsql.viewer or cloudsql.instances.list permission."],
    },
    "google_cloud_run_service": {
        "message": "Cloud Run service metadata was not observed.",
        "hints": ["Verify the service account has roles/run.viewer or run.services.list permission."],
    },
    "google_cloud_gke_cluster": {
        "message": "GKE cluster metadata was not observed.",
        "hints": ["Verify the service account has roles/container.viewer or container.clusters.list permission."],
    },
    "google_cloud_service_account_key_summary": {
        "message": "Service account key summary metadata was not observed.",
        "hints": ["Verify the service account has roles/iam.serviceAccountViewer or iam.serviceAccounts.list permission."],
    },
    "google_cloud_secret_manager_summary": {
        "message": "Secret Manager summary metadata was not observed.",
        "hints": ["Verify the service account has roles/secretmanager.viewer or secretmanager.secrets.list permission. This surface may be absent if the Secret Manager API is not enabled."],
    },
    # Datadog — M82B
    "datadog_monitor": {
        "message": "Datadog monitor metadata was not observed.",
        "hints": ["Verify the API key and Application key have monitors_read permission."],
    },
    "datadog_slo": {
        "message": "Datadog SLO metadata was not observed.",
        "hints": ["Verify the API key and Application key have slos_read permission. This surface may be absent if no SLOs are configured."],
    },
    "datadog_dashboard": {
        "message": "Datadog dashboard metadata was not observed.",
        "hints": ["Verify the API key and Application key have dashboards_read permission. This surface may be absent if no dashboards are configured."],
    },
    "datadog_webhook_integration": {
        "message": "Datadog webhook integration metadata was not observed.",
        "hints": ["Verify the API key and Application key have integrations_read permission. This surface may be absent if no webhook integrations are configured."],
    },
    "datadog_notification_integration": {
        "message": "Datadog notification integration metadata was not observed.",
        "hints": ["Verify the API key has access to read configured notification integrations. This surface may be absent if no notification integrations (PagerDuty, Slack, OpsGenie) are configured."],
    },
    "datadog_api_key_metadata": {
        "message": "Datadog API key metadata was not observed.",
        "hints": ["Verify the Application key has api_keys_read permission (GET /api/v2/api_keys). Some keys may not have this scope."],
    },
    "datadog_application_key_metadata": {
        "message": "Datadog application key metadata was not observed.",
        "hints": ["Verify the Application key has application_keys_read permission (GET /api/v2/application_keys). This surface may require elevated permissions."],
    },
    "datadog_role": {
        "message": "Datadog role metadata was not observed.",
        "hints": ["Verify the Application key has roles_read permission (GET /api/v2/roles). This surface may be absent if no custom roles are configured."],
    },
    "datadog_team": {
        "message": "Datadog team metadata was not observed.",
        "hints": ["Verify the Application key has teams_read permission (GET /api/v2/teams). This surface may be absent if no teams are configured."],
    },
    "datadog_cloud_integration": {
        "message": "Datadog cloud integration metadata was not observed.",
        "hints": ["Verify the Application key has integrations_read permission. This surface may be absent if no AWS/GCP/Azure cloud integrations are configured."],
    },
    # Clerk — M83B
    "clerk_instance_settings": {
        "message": "Clerk instance settings metadata was not observed.",
        "hints": ["Verify the Clerk secret key has access to GET /v1/instance via the Clerk Backend API."],
    },
    "clerk_application": {
        "message": "Clerk application metadata was not observed.",
        "hints": ["Verify the Clerk secret key has access to application metadata via the Clerk Backend API."],
    },
    "clerk_domain": {
        "message": "Clerk domain metadata was not observed.",
        "hints": ["Verify the Clerk secret key can list domains via GET /v1/domains. This surface may be absent if no custom domains are configured."],
    },
    "clerk_redirect_url_config": {
        "message": "Clerk redirect URL metadata was not observed.",
        "hints": ["Verify the Clerk secret key can list redirect URLs. This surface may be absent if no redirect URLs are configured."],
    },
    "clerk_jwt_template": {
        "message": "Clerk JWT template metadata was not observed.",
        "hints": ["Verify the Clerk secret key can list JWT templates. This surface may be absent if no JWT templates are configured."],
    },
    "clerk_webhook_endpoint": {
        "message": "Clerk webhook endpoint metadata was not observed.",
        "hints": ["Verify the Clerk secret key can list webhook endpoints. This surface may be absent if no webhook endpoints are configured."],
    },
    "clerk_email_sms_settings": {
        "message": "Clerk email/SMS settings metadata was not observed.",
        "hints": ["Verify the Clerk secret key has access to email/SMS configuration via the Clerk Backend API."],
    },
    "clerk_auth_strategy": {
        "message": "Clerk authentication strategy metadata was not observed.",
        "hints": ["Verify the Clerk secret key can read authentication strategy posture."],
    },
    "clerk_session_policy": {
        "message": "Clerk session policy metadata was not observed.",
        "hints": ["Verify the Clerk secret key has access to session policy configuration via the Clerk Backend API."],
    },
    "clerk_organization_settings": {
        "message": "Clerk organization settings metadata was not observed.",
        "hints": ["Verify the Clerk secret key has access to organization configuration via the Clerk Backend API. This surface may be absent if organizations are not enabled."],
    },
    # PagerDuty — M84B core security rules diagnostics
    "pagerduty_service": {
        "message": "PagerDuty service metadata was not observed.",
        "hints": ["Verify the PagerDuty API token has read access to /services."],
    },
    "pagerduty_escalation_policy": {
        "message": "PagerDuty escalation policy metadata was not observed.",
        "hints": ["Verify the PagerDuty API token has read access to /escalation_policies."],
    },
    "pagerduty_schedule": {
        "message": "PagerDuty schedule metadata was not observed.",
        "hints": ["Verify the PagerDuty API token has read access to /schedules. This surface may be absent if no on-call schedules are configured."],
    },
    "pagerduty_service_integration": {
        "message": "PagerDuty service integration metadata was not observed.",
        "hints": ["Verify the PagerDuty API token has read access to /services/{id}/integrations. This surface may be absent if no services have integrations configured."],
    },
    "pagerduty_webhook_subscription": {
        "message": "PagerDuty V3 webhook subscription metadata was not observed.",
        "hints": ["Verify the PagerDuty API token has read access to /webhook_subscriptions. This surface may be plan-gated or absent if no V3 webhooks are configured."],
    },
    "pagerduty_event_orchestration": {
        "message": "PagerDuty event orchestration metadata was not observed.",
        "hints": ["Verify the PagerDuty API token has read access to /event_orchestrations. This surface is plan-gated (AIOps) and may be absent on plans without Event Orchestration."],
    },
    "pagerduty_business_service": {
        "message": "PagerDuty business service metadata was not observed.",
        "hints": ["Verify the PagerDuty API token has read access to /business_services. This surface may be plan-gated or absent if no business services are configured."],
    },
    "pagerduty_response_play": {
        "message": "PagerDuty response play metadata was not observed.",
        "hints": ["Verify the PagerDuty API token has read access to /response_plays. This surface may be absent if no response plays are configured."],
    },
    # Linear — M85B
    "linear_workspace": {
        "message": "Linear workspace configuration metadata was not observed.",
        "hints": ["Verify the Linear API key has read access to the organization query."],
    },
    "linear_team": {
        "message": "Linear team configuration metadata was not observed.",
        "hints": ["Verify the Linear API key has read access to the teams query."],
    },
    "linear_project": {
        "message": "Linear project configuration metadata was not observed.",
        "hints": ["Verify the Linear API key has read access to the projects query."],
    },
    "linear_workflow_state": {
        "message": "Linear workflow state metadata was not observed.",
        "hints": ["Verify the Linear API key has read access to the workflowStates query."],
    },
    "linear_label": {
        "message": "Linear issue label metadata was not observed.",
        "hints": ["Verify the Linear API key has read access to the issueLabels query."],
    },
    "linear_webhook": {
        "message": "Linear webhook subscription metadata was not observed.",
        "hints": ["Verify the Linear API key has read access to the webhooks query."],
    },
    "linear_view": {
        "message": "Linear custom view metadata was not observed.",
        "hints": ["Verify the Linear API key has read access to the customViews query."],
    },
    "linear_cycle": {
        "message": "Linear active cycle metadata was not observed.",
        "hints": ["Verify the Linear API key has read access to the cycles query. This surface may be absent if no active cycles are configured."],
    },
    "linear_integration": {
        "message": "Linear integration metadata was not observed.",
        "hints": ["Verify the Linear API key has access to the integrations query. This surface may be plan-gated or absent if no integrations are configured."],
    },
    # Jira — M86B
    "jira_site": {
        "message": "Jira site metadata was not observed.",
        "hints": ["Verify the Jira API credentials can reach the Jira Cloud serverInfo endpoint."],
    },
    "jira_project": {
        "message": "Jira project metadata was not observed.",
        "hints": ["Verify the Jira API credentials have Browse Projects permission."],
    },
    "jira_board": {
        "message": "Jira board metadata was not observed.",
        "hints": ["Board metadata requires Jira Software (the agile API). It may be absent if no boards are configured or if the API token lacks board access."],
    },
    "jira_workflow": {
        "message": "Jira workflow metadata was not observed.",
        "hints": ["Workflow metadata requires Administer Jira global permission on the site."],
    },
    "jira_workflow_scheme": {
        "message": "Jira workflow scheme metadata was not observed.",
        "hints": ["Workflow scheme metadata requires Administer Jira global permission on the site."],
    },
    "jira_permission_scheme": {
        "message": "Jira permission scheme metadata was not observed.",
        "hints": ["Permission scheme metadata requires Administer Jira global permission on the site."],
    },
    "jira_notification_scheme": {
        "message": "Jira notification scheme metadata was not observed.",
        "hints": ["Notification scheme metadata requires Administer Jira global permission on the site."],
    },
    "jira_issue_type_scheme": {
        "message": "Jira issue type scheme metadata was not observed.",
        "hints": ["Issue type scheme metadata requires Administer Jira global permission on the site."],
    },
    "jira_field_configuration_scheme": {
        "message": "Jira field configuration scheme metadata was not observed.",
        "hints": ["Field configuration scheme metadata requires Administer Jira global permission on the site."],
    },
    "jira_screen_scheme": {
        "message": "Jira screen scheme metadata was not observed.",
        "hints": ["Screen scheme metadata requires Administer Jira global permission on the site."],
    },
    "jira_webhook": {
        "message": "Jira webhook metadata was not observed.",
        "hints": ["Webhook metadata may be absent if no webhooks are configured, or if the API token lacks webhook list access."],
    },
    "jira_automation_rule": {
        "message": "Jira automation rule metadata was not observed.",
        "hints": ["Automation rule metadata uses the Jira Cloud automation API. It may be plan-gated or absent if no automation rules are configured."],
    },
    # GitLab — M87B
    "gitlab_project": {
        "message": "GitLab project metadata was not observed.",
        "hints": ["Ensure the access token has read_api scope and the token owner has access to at least one project."],
    },
    "gitlab_group": {
        "message": "GitLab group metadata was not observed.",
        "hints": ["Group metadata requires the token owner to be a member of at least one group."],
    },
    "gitlab_branch_protection": {
        "message": "GitLab branch protection metadata was not observed.",
        "hints": ["Branch protection metadata is fetched per project. It may be absent if no branches are protected, or if the token lacks Maintainer access."],
    },
    "gitlab_webhook": {
        "message": "GitLab webhook metadata was not observed.",
        "hints": ["Webhook metadata requires Maintainer or Owner access. It may be absent if no webhooks are configured."],
    },
    "gitlab_ci_variable_summary": {
        "message": "GitLab CI/CD variable summary was not observed.",
        "hints": ["CI variable summaries require Maintainer access. Counts are stored only — variable names and values are never fetched."],
    },
    "gitlab_deploy_key_summary": {
        "message": "GitLab deploy key summary was not observed.",
        "hints": ["Deploy key summaries require read_repository scope or Maintainer access. Counts are stored only — key material is never fetched."],
    },
    "gitlab_runner_summary": {
        "message": "GitLab runner summary was not observed.",
        "hints": ["Runner summaries require Maintainer access. Runner tokens and IPs are never stored."],
    },
    "gitlab_merge_request_approval_summary": {
        "message": "GitLab merge request approval summary was not observed.",
        "hints": ["MR approval summaries require read_api scope and at least Reporter access. May be absent on Free-tier projects."],
    },
    # Terraform Cloud — M88B
    "terraform_cloud_organization": {
        "message": "Terraform Cloud organization metadata was not observed.",
        "hints": ["Ensure the API token has organization-level read access. Organization names are never stored — only opaque identifiers and posture booleans."],
    },
    "terraform_cloud_workspace": {
        "message": "Terraform Cloud workspace metadata was not observed.",
        "hints": ["Workspace metadata requires at least read access to the organization. Workspace names and variable values are never stored."],
    },
    "terraform_cloud_workspace_variable_summary": {
        "message": "Terraform Cloud workspace variable summary was not observed.",
        "hints": ["Variable summaries require read access to workspace variables. Only counts are stored — variable names and values are never fetched."],
    },
    "terraform_cloud_notification_configuration": {
        "message": "Terraform Cloud notification configuration was not observed.",
        "hints": ["Notification metadata requires Workspace Manager or Admin access. Webhook URLs and tokens are never stored — only presence and scheme category."],
    },
    "terraform_cloud_policy_set": {
        "message": "Terraform Cloud policy set metadata was not observed.",
        "hints": ["Policy set metadata requires read access at the organization level. Policy names and code are never stored."],
    },
    "terraform_cloud_team_access_summary": {
        "message": "Terraform Cloud team access summary was not observed.",
        "hints": ["Team access metadata requires Workspace Manager or Admin access. Team names and user identities are never stored — only access-level counts."],
    },
    "terraform_cloud_variable_set": {
        "message": "Terraform Cloud variable set metadata was not observed.",
        "hints": ["Variable set metadata requires organization-level read access. Variable names and values are never stored — only scope and count categories."],
    },
    "terraform_cloud_state_version_summary": {
        "message": "Terraform Cloud state version summary was not observed.",
        "hints": ["State version presence is derived from workspace metadata. Raw state files, state outputs, and resource addresses are never fetched or stored."],
    },
    "terraform_cloud_run_trigger": {
        "message": "Terraform Cloud run trigger metadata was not observed.",
        "hints": ["Run trigger metadata requires at least read access to the workspace. Source workspace identities and run payload contents are never stored — only sourceable type category."],
    },
}

# Provider-level permission hints appended once when any surface is missing.
PROVIDER_PERMISSION_HINT: dict[str, str] = {
    "supabase": "Verify the project credentials/API access used by the connector.",
    "firebase": "Verify Firebase project credentials and ruleset/auth read access.",
}


def _diagnose(
    provider: str,
    *,
    connected: bool,
    integration_status: Optional[str],
    last_synced_at: Any,
    expected: set[str],
    observed: set[str],
) -> dict[str, Any]:
    """Read-only diagnosis of why coverage may be limited. No provider calls."""
    ok_payload = {
        "diagnostic_status": "ok",
        "diagnostic_messages": ["Coverage data looks sufficient for currently supported rules."],
        "recommended_actions": [],
        "permission_hints": [],
        "docs_hint": None,
        "diagnostic_confidence": "high",
    }

    if not connected:
        return {
            "diagnostic_status": "provider_not_connected",
            "diagnostic_messages": ["ConfigTrace has no active connection for this provider."],
            "recommended_actions": ["Connect this provider to collect security metadata."],
            "permission_hints": [],
            "docs_hint": None,
            "diagnostic_confidence": "high",
        }

    if integration_status in ("needs_reconnect", "error"):
        return {
            "diagnostic_status": "provider_attention_needed",
            "diagnostic_messages": [
                "This provider connection may need attention; recent syncs could indicate incomplete access.",
            ],
            "recommended_actions": ["Reconnect the provider or check its credentials, then run a sync."],
            "permission_hints": [],
            "docs_hint": None,
            "diagnostic_confidence": "high",
        }

    if last_synced_at is None:
        return {
            "diagnostic_status": "needs_sync",
            "diagnostic_messages": [
                "ConfigTrace has not yet synced this provider, so no metadata has been observed.",
            ],
            "recommended_actions": ["Run a sync to collect provider metadata."],
            "permission_hints": [],
            "docs_hint": None,
            "diagnostic_confidence": "high",
        }

    if not expected:
        return ok_payload

    observed_expected = expected & observed
    missing = sorted(expected - observed)

    if not missing:
        return ok_payload

    messages: list[str] = []
    actions: list[str] = []
    hints: list[str] = []

    if not observed_expected:
        status = "permissions_likely_limited"
        messages.append(
            "ConfigTrace has not observed expected security metadata for this provider after syncing."
        )
        messages.append(
            "This could indicate limited permissions, unavailable provider APIs, or provider setup gaps."
        )
        actions.append("Check provider permissions, then re-run a sync.")
    else:
        status = "missing_metadata"
        messages.append(
            "ConfigTrace has observed some provider metadata, but not all expected surfaces."
        )
        actions.append("Re-run a sync, and check provider permissions for the missing surfaces.")

    # Per-missing-surface messages + permission hints (deterministic order).
    for rt in missing:
        diag = RECORD_TYPE_DIAGNOSTICS.get(rt)
        if not diag:
            continue
        msg = diag.get("message")
        if msg and msg not in messages:
            messages.append(msg)
        for h in diag.get("hints", []):
            if h not in hints:
                hints.append(h)

    prov_hint = PROVIDER_PERMISSION_HINT.get(provider)
    if prov_hint and prov_hint not in hints:
        hints.append(prov_hint)

    actions.append("Review which rules apply on the Security Rules page.")

    # AWS account structures may intentionally omit services — keep the
    # diagnostic conservative (lower confidence, explicit caveat).
    if provider == "aws":
        messages.append(
            "AWS account structure may intentionally omit some services, so missing surfaces are not always a permission gap."
        )
        confidence = "low"
    else:
        confidence = "medium"

    return {
        "diagnostic_status": status,
        "diagnostic_messages": messages,
        "recommended_actions": actions,
        "permission_hints": hints,
        "docs_hint": None,
        "diagnostic_confidence": confidence,
    }


def _provider_of(rule_key: str) -> str:
    # Multi-word provider prefixes must be checked first; otherwise a naive
    # split would map "google_cloud_*" to "google" and break coverage joins.
    for multi_word in ("google_cloud",):
        if rule_key.startswith(multi_word + "_"):
            return multi_word
    return rule_key.split("_", 1)[0]


def _expected_record_types(provider: str) -> set[str]:
    out: set[str] = set()
    for rk in KNOWN_RULE_KEYS:
        if _provider_of(rk) == provider:
            out.update(RULE_RECORD_TYPES.get(rk, ()))
    return out


def _rule_keys_for(provider: str) -> list[str]:
    return sorted(rk for rk in KNOWN_RULE_KEYS if _provider_of(rk) == provider)


def _observed_record_types(
    integ_ids: list[uuid.UUID], db: Session
) -> set[str]:
    """Union of record_type values across the latest snapshot of each resource."""
    observed: set[str] = set()
    if not integ_ids:
        return observed
    resources = (
        db.query(Resource)
        .filter(
            Resource.integration_id.in_(integ_ids),
            Resource.is_active.is_(True),
        )
        .all()
    )
    for res in resources:
        snap = get_latest_snapshot(res.id, db)
        if snap is None or not isinstance(snap.state, list):
            continue
        for record in snap.state:
            if isinstance(record, dict):
                rt = record.get("record_type")
                if isinstance(rt, str) and rt:
                    observed.add(rt)
    return observed


def _recommendation(status: str) -> str:
    return {
        "not_connected": "Connect this provider to evaluate its security rules.",
        "not_synced": "Run a sync to collect provider metadata.",
        "needs_attention": "Reconnect this provider; recent syncs may not have completed.",
        "limited": "Some surfaces are missing — check provider permissions and run a sync.",
        "good": "Coverage is good. Good coverage does not mean no risk exists.",
    }.get(status, "Run a sync to collect provider metadata.")


def get_coverage(workspace_id: uuid.UUID, db: Session) -> dict[str, Any]:
    """Build the per-provider coverage report for a workspace (read-only)."""
    # Real (non-demo, non-deleted) integrations grouped by provider.
    integrations = (
        db.query(Integration)
        .filter(
            Integration.workspace_id == workspace_id,
            Integration.status != "deleted",
            Integration.provider.in_(PROVIDERS),
        )
        .all()
    )
    by_provider: dict[str, list[Integration]] = {}
    for i in integrations:
        by_provider.setdefault(i.provider, []).append(i)

    disabled = get_disabled_rule_keys(workspace_id, db)

    providers_out: list[dict[str, Any]] = []
    summary = {
        "connected_providers": 0,
        "good_coverage": 0,
        "limited_coverage": 0,
        "not_connected": 0,
        "disabled_rules": 0,
        "diagnostics_ok": 0,
        "diagnostics_needs_sync": 0,
        "diagnostics_missing_metadata": 0,
        "diagnostics_permissions_likely_limited": 0,
    }

    for provider in PROVIDERS:
        integs = by_provider.get(provider, [])
        rule_keys = _rule_keys_for(provider)
        supported_total = len(rule_keys)
        disabled_count = sum(1 for rk in rule_keys if rk in disabled)
        active_count = supported_total - disabled_count
        summary["disabled_rules"] += disabled_count

        expected = _expected_record_types(provider)

        if not integs:
            status = "not_connected"
            observed: set[str] = set()
            integration_id = None
            integration_status = None
            last_synced_at = None
            summary["not_connected"] += 1
        else:
            summary["connected_providers"] += 1
            # Prefer the most recently synced integration for display fields.
            integ = max(
                integs,
                key=lambda x: x.last_synced_at or x.created_at,
            )
            integration_id = str(integ.id)
            integration_status = integ.status
            last_synced_at = integ.last_synced_at
            observed = _observed_record_types([i.id for i in integs], db)
            observed_expected = expected & observed

            if integration_status in ("needs_reconnect", "error"):
                status = "needs_attention"
            elif not observed_expected:
                status = "not_synced"
            elif observed_expected >= expected:
                status = "good"
                summary["good_coverage"] += 1
            else:
                status = "limited"
                summary["limited_coverage"] += 1

        missing = sorted(expected - observed)

        # M62.8 — permission diagnostics (read-only; inspects only the data
        # already gathered above, never calls a provider).
        diag = _diagnose(
            provider,
            connected=bool(integs),
            integration_status=integration_status,
            last_synced_at=last_synced_at,
            expected=expected,
            observed=observed,
        )
        if diag["diagnostic_status"] == "ok":
            summary["diagnostics_ok"] += 1
        elif diag["diagnostic_status"] == "needs_sync":
            summary["diagnostics_needs_sync"] += 1
        elif diag["diagnostic_status"] == "missing_metadata":
            summary["diagnostics_missing_metadata"] += 1
        elif diag["diagnostic_status"] == "permissions_likely_limited":
            summary["diagnostics_permissions_likely_limited"] += 1

        # Per-rule coverage: enabled + supported-by-observed-records.
        rules_out = []
        for rk in rule_keys:
            needed = RULE_RECORD_TYPES.get(rk, ())
            supported = bool(set(needed) & observed) if needed else False
            rules_out.append(
                {
                    "rule_key": rk,
                    "enabled": rk not in disabled,
                    "supported": supported,  # observed records exist for this rule
                }
            )

        providers_out.append(
            {
                "provider": provider,
                "connected": bool(integs),
                "integration_id": integration_id,
                "integration_status": integration_status,
                "last_synced_at": last_synced_at,
                "coverage_status": status,
                "monitored_surfaces": PROVIDER_SURFACES.get(provider, []),
                "observed_record_types": sorted(observed),
                "expected_record_types": sorted(expected),
                "missing_record_types": missing,
                "active_rules": active_count,
                "disabled_rules": disabled_count,
                "supported_rules": supported_total,
                "recommendation": _recommendation(status),
                "rules": rules_out,
                "diagnostic_status": diag["diagnostic_status"],
                "diagnostic_messages": diag["diagnostic_messages"],
                "recommended_actions": diag["recommended_actions"],
                "permission_hints": diag["permission_hints"],
                "docs_hint": diag["docs_hint"],
                "diagnostic_confidence": diag["diagnostic_confidence"],
            }
        )

    return {"providers": providers_out, "summary": summary}
