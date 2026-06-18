"""Security rule confidence registry — M62.4.

Per-rule confidence metadata used to make findings more trustworthy and
explainable. Confidence describes HOW the rule reached its conclusion, not how
severe the issue is (severity stays the routing/priority signal):

  * high   — backed by a direct normalized field that clearly indicates the
             risky state.
  * medium — backed by strong provider metadata, but may depend on environment
             context.
  * low    — inferred from limited/ambiguous signals; such rules are deferred
             and do NOT emit active findings (none of the implemented rules are
             low).

The ``false_positive_guard`` text mirrors the conservative guard already shown
in the frontend Security Rules catalog, so the same explanation is consistent
across the rules catalog and individual finding detail.

This is metadata only — it never claims a confirmed exploit/breach.
"""

from __future__ import annotations

from app.services.security_rule_registry import KNOWN_RULE_KEYS, base_rule_key

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

VALID_CONFIDENCE = frozenset({HIGH, MEDIUM, LOW})

_REASON = {
    HIGH: "Backed by a direct normalized field that clearly indicates the risky state.",
    MEDIUM: "Backed by strong provider metadata, but may depend on environment context.",
    LOW: "Inferred from limited or ambiguous signals; treated conservatively.",
}

# rule_key → (confidence, false_positive_guard). Confidence values mirror the
# frontend securityRuleCatalog; every implemented rule is high or medium.
RULE_CONFIDENCE: dict[str, tuple[str, str]] = {
    # GitHub
    "github_webhook_http": (HIGH, "Only fires for active webhooks whose URL begins with http://."),
    "github_branch_protection_missing": (HIGH, "Only the default branch is evaluated; a permission error aborts before this fires."),
    "github_force_pushes_allowed": (HIGH, "Only evaluated when branch protection is enabled."),
    "github_branch_deletion_allowed": (HIGH, "Only evaluated when branch protection is enabled."),
    "github_pr_review_not_required": (HIGH, "Only evaluated when branch protection is enabled."),
    "github_status_checks_not_required": (HIGH, "Only evaluated when branch protection is enabled."),
    "github_deploy_key_write_access": (HIGH, "A missing read_only flag defaults to read-only (safe); partial records are ignored."),
    "github_env_protection_missing": (HIGH, "Narrowly scoped to environments explicitly named production/prod."),
    # GitHub rulesets (M69.5A)
    "github_ruleset_not_enforced": (HIGH, "Reads the ruleset's enforcement field directly; only fires when it is not 'active'."),
    "github_ruleset_force_push_allowed": (HIGH, "Only fires for active branch rulesets that lack a non-fast-forward (block force push) rule."),
    "github_ruleset_pr_review_missing": (MEDIUM, "Depends on the protected-branch target heuristic; only active branch rulesets are evaluated."),
    "github_ruleset_status_checks_missing": (MEDIUM, "Depends on the protected-branch target heuristic; only active branch rulesets are evaluated."),
    "github_ruleset_bypass_actors_present": (HIGH, "Reads the bypass-actor count directly; counts only, never identities."),
    "github_ruleset_weak_target_coverage": (MEDIUM, "Based on a default-branch coverage heuristic; conservative and may under-report."),
    # GitHub automation permissions (M69.5B)
    "github_automation_admin_permission": (HIGH, "Reads the authenticated credential's repository permission object directly."),
    "github_automation_write_permission": (HIGH, "Reads the authenticated credential's repository permission object directly."),
    "github_token_broad_scopes": (MEDIUM, "Classic-PAT scopes only (from X-OAuth-Scopes); fine-grained tokens/Apps expose no scopes, so it may under-report."),
    "github_webhook_secret_missing": (HIGH, "GitHub reliably masks a configured secret and omits the field when none is set."),
    # AWS
    "aws_public_admin_port": (HIGH, "Only 0.0.0.0/0 or ::/0 count as public; reachability is not claimed."),
    "aws_public_database_port": (HIGH, "Only canonical 'any' CIDRs count as public."),
    "aws_public_all_ports": (HIGH, "Only canonical 'any' CIDRs count as public."),
    "aws_s3_public_policy": (HIGH, "Only an explicit public flag fires; an unknown state is never treated as public."),
    "aws_s3_public_acl": (HIGH, "Only an explicit public grant fires; an unknown state is never treated as public."),
    "aws_iam_admin_policy_attached": (HIGH, "Exact AdministratorAccess ARN match, not a keyword guess."),
    "aws_access_key_unused": (HIGH, "An unknown last-used age (never-used vs fetch-failed) is not flagged."),
    # Cloudflare
    "cloudflare_ssl_mode_weak": (HIGH, "Only off/flexible fire; full/strict are treated as safe."),
    "cloudflare_always_https_off": (HIGH, "Only fires when the value is explicitly 'off'."),
    "cloudflare_min_tls_weak": (HIGH, "Only TLS 1.0/1.1 fire."),
    "cloudflare_security_level_low": (HIGH, "Only off/essentially_off fire; low/medium/high are treated as normal."),
    "cloudflare_development_mode_on": (HIGH, "Only fires when development mode is explicitly 'on'."),
    "cloudflare_hsts_disabled": (HIGH, "Only an explicit enabled=false fires; indeterminate values are skipped."),
    "cloudflare_waf_rule_disabled": (HIGH, "Disabled log/skip rules are ignored — only protective actions fire."),
    "cloudflare_dns_private_origin": (HIGH, "Public/global IPs are normal and never flagged; non-IP content is ignored."),
    # Supabase
    "supabase_rls_disabled": (HIGH, "Only an explicit rls_enabled=false fires; missing/unknown is skipped."),
    "supabase_anonymous_access_enabled": (MEDIUM, "Anonymous auth is a feature; risky mainly with weak RLS, so wording stays careful."),
    "supabase_jwt_expiry_long": (HIGH, "Only a concrete value over the threshold fires; unknown values are skipped."),
    "supabase_public_select_sensitive_table": (HIGH, "Only fires when a public/anon SELECT policy is active on an RLS-enabled, sensitively-named table."),
    "supabase_public_write_policy": (HIGH, "Only fires when a public/anon insert/update/delete policy is active on an RLS-enabled table."),
    "supabase_edge_function_jwt_disabled": (HIGH, "Only an explicit verify_jwt=false fires; missing/unknown is skipped."),
    "supabase_auth_protection_missing": (MEDIUM, "Only an explicit leaked-password-protection=false fires; missing/unknown is skipped."),
    # Firebase
    "firebase_rules_public": (MEDIUM, "Low-confidence ruleset parses are skipped to avoid false positives."),
    "firebase_storage_rules_public": (MEDIUM, "Low-confidence ruleset parses are skipped to avoid false positives."),
    "firebase_anonymous_auth_enabled": (MEDIUM, "Risky mainly when paired with permissive rules; reported at medium severity."),
    # Firebase — M72A
    "firebase_database_public_read": (HIGH, "Only an explicit unconditional '.read': true (no auth guard) fires; low-confidence parses are skipped."),
    "firebase_database_public_write": (HIGH, "Only an explicit unconditional '.write': true (no auth guard) fires; low-confidence parses are skipped."),
    "firebase_auth_protection_missing": (MEDIUM, "Only an explicit mfa_enabled=false fires; missing/unknown is skipped."),
    # Stripe
    "stripe_webhook_http": (HIGH, "Only an explicit http scheme fires; disabled endpoints are not flagged."),
    # Stripe — M73A
    "stripe_webhook_disabled": (HIGH, "Only an explicit status='disabled' fires; enabled/unknown is skipped."),
    "stripe_webhook_broad_events": (MEDIUM, "Fires on the wildcard '*' or a large explicit event count; a normal scoped list is not flagged."),
    "stripe_payment_link_tax_disabled": (HIGH, "Only an active link with an explicit automatic_tax_enabled=false fires."),
    "stripe_payment_link_promo_codes_enabled": (HIGH, "Only an active link with an explicit allow_promotion_codes=true fires; a config-review item, not an exposure."),
    "stripe_portal_subscription_cancel_enabled": (HIGH, "Only an active portal config with an explicit subscription_cancel_enabled=true fires."),
    "stripe_portal_login_enabled": (HIGH, "Only an active portal config with an explicit login_page_enabled=true fires."),
    "stripe_account_capability_incomplete": (HIGH, "Only an explicit charges/payouts/details flag of false fires; missing/unknown is skipped."),
    # Vercel
    "vercel_preview_unprotected": (MEDIUM, "Only fires when every protection mechanism is off; previews are not production data."),
    "vercel_production_branch_missing": (MEDIUM, "Only fires when a git repository is connected but no production branch is configured."),
    "vercel_production_branch_unusual": (MEDIUM, "Only fires when the production branch matches a known non-production name; main/master/prod are treated as normal."),
    "vercel_domain_unverified": (MEDIUM, "Only an explicit verified=false fires; verified or unknown domains are skipped."),
    "vercel_env_var_broad_target": (MEDIUM, "Only fires when one variable spans production and a non-production environment."),
    "vercel_sensitive_env_var_broad_scope": (HIGH, "Only fires when a secret-suggestive key name is also scoped to a non-production environment; the value is never read."),
    "vercel_deploy_hook_production_branch": (MEDIUM, "Only fires when a deploy hook's target ref is the production branch; the hook URL is never stored."),
    # Shopify
    "shopify_webhook_http": (HIGH, "Only an explicit http scheme fires; non-HTTP transports are ignored."),
    # Shopify — M74A
    "shopify_webhook_high_risk_topic": (MEDIUM, "Only a curated set of high-risk topic prefixes / handles fires; generic topics are not flagged."),
    "shopify_app_broad_write_scopes": (HIGH, "Only the curated high-risk write scopes are counted (not generic write_* scopes); fires at >= 3."),
    "shopify_app_customer_data_scope": (HIGH, "Only an exact read_customers / write_customers grant fires; broader 'customer'-substring scopes are not used."),
    "shopify_domain_ssl_missing": (HIGH, "Only an explicit ssl_enabled=false on the primary domain fires."),
    "shopify_domain_unverified": (HIGH, "Only an explicit verified=false on the primary domain fires."),
    "shopify_policy_missing": (HIGH, "Only an explicit present=false on a canonical-policy baseline record fires."),
    # Azure — M77B
    "azure_nsg_public_admin_ingress": (HIGH, "Only Inbound+Allow rules from canonical public prefixes (*, 0.0.0.0/0, ::/0, Internet, Any) on a known admin/database/cache/search port fire."),
    "azure_nsg_public_broad_ingress": (HIGH, "Only Inbound+Allow rules from canonical public prefixes with a broad/all-port destination range fire."),
    "azure_storage_public_blob_access": (HIGH, "Only an explicit allowBlobPublicAccess=true on the storage account fires; container ACLs are not claimed."),
    "azure_storage_public_network_access": (HIGH, "Only an explicit publicNetworkAccess=Enabled fires; severity bumps to high when defaultAction=Allow is also explicit."),
    "azure_storage_weak_tls": (HIGH, "Only explicit minimumTlsVersion=TLS1_0/TLS1_1 fires; missing/unknown is skipped."),
    "azure_storage_shared_key_enabled": (HIGH, "Only an explicit allowSharedKeyAccess=true fires; missing/unknown is skipped."),
    "azure_key_vault_public_network_access": (HIGH, "Only an explicit publicNetworkAccess=Enabled fires; severity bumps to high when defaultAction=Allow is also explicit."),
    "azure_key_vault_purge_protection_disabled": (HIGH, "Only an explicit enablePurgeProtection=false fires; missing/unknown is skipped."),
    "azure_key_vault_soft_delete_disabled": (HIGH, "Only an explicit enableSoftDelete=false fires; missing/unknown is skipped."),
    "azure_key_vault_rbac_disabled": (MEDIUM, "Fires only when enableRbacAuthorization=false AND access_policy_count > 0; vaults with no access policies are not flagged."),
    # Azure — M77C
    "azure_role_assignment_broad_privilege": (HIGH, "Fires only when role_definition_name is a known broad built-in role (Owner/Contributor/User Access Administrator) resolved from a static GUID map, AND scope_type is subscription or resource_group."),
    "azure_app_service_https_disabled": (HIGH, "Only an explicit httpsOnly=false on the App Service fires; missing/unknown is skipped."),
    "azure_app_service_ftp_enabled": (HIGH, "Only an explicit ftpsState=AllAllowed fires; FtpsOnly and Disabled do not fire."),
    "azure_app_service_weak_tls": (HIGH, "Only explicit minTlsVersion='1.0' or '1.1' fires; missing/unknown is skipped."),
    "azure_app_service_public_network_access": (HIGH, "Only an explicit publicNetworkAccess=Enabled/true fires; missing/unknown is skipped."),
    "azure_sql_public_network_access": (HIGH, "Only an explicit publicNetworkAccess=Enabled fires; severity bumps to high when has_allow_azure_services_rule=true."),
    "azure_sql_weak_tls": (HIGH, "Only explicit minimalTlsVersion='1.0' or '1.1' fires; missing/unknown is skipped."),
    "azure_aks_local_accounts_enabled": (HIGH, "Only an explicit disableLocalAccounts=false fires; missing/unknown is skipped."),
    "azure_aks_public_api_access": (HIGH, "Fires only when private_cluster_enabled=false AND api_server_authorized_ip_range_count=0; partial data (None count) is not flagged."),
    "azure_aks_network_policy_missing": (MEDIUM, "Fires when network_policy is absent or 'none'; absence of a network policy is the default state so medium confidence is used."),
    # Google Cloud — M78B
    "google_cloud_iam_public_member": (HIGH, "Only an explicit allUsers / allAuthenticatedUsers sentinel binding on the project IAM policy fires; member identities are never read."),
    "google_cloud_iam_broad_privileged_role": (HIGH, "Only a curated set of broad project-level role names (roles/owner, roles/editor, roles/iam.securityAdmin, roles/resourcemanager.projectIamAdmin, roles/iam.serviceAccountAdmin, roles/iam.serviceAccountKeyAdmin) fires."),
    "google_cloud_firewall_public_admin_ingress": (HIGH, "Only INGRESS+allow rules with a 0.0.0.0/0 or ::/0 source range on a known admin/database/cache/search port fire; disabled rules are skipped."),
    "google_cloud_firewall_public_broad_ingress": (HIGH, "Only INGRESS+allow rules with a 0.0.0.0/0 or ::/0 source range that also cover all ports (or the 'all' protocol) fire; disabled rules are skipped."),
    "google_cloud_firewall_rule_no_targets": (MEDIUM, "Fires only when an INGRESS+allow rule from a public source range has target_tag_count=0 AND target_service_account_count=0; severity bumps to high when the same rule is also a broad/admin public ingress."),
    "google_cloud_storage_public_access_prevention_disabled": (HIGH, "Only fires when public_access_prevention is missing/inherited/unspecified or any value other than 'enforced'; severity bumps to high when uniform bucket-level access is also disabled."),
    "google_cloud_storage_uniform_access_disabled": (HIGH, "Only an explicit uniform_bucket_level_access_enabled=false fires; missing/unknown is skipped."),
    "google_cloud_storage_versioning_disabled": (HIGH, "Only an explicit versioning_enabled=false fires; missing/unknown is skipped."),
    "google_cloud_storage_retention_not_locked": (MEDIUM, "Fires when no retention policy is set OR retention_policy_locked is explicitly false; missing locked-state with no retention period is treated conservatively."),
    # Google Cloud — M78C: Cloud SQL
    "google_cloud_sql_public_network_access": (HIGH, "Only an explicit public_ip_enabled=true fires; severity is high when authorized_network_count > 0, medium otherwise."),
    "google_cloud_sql_weak_tls": (HIGH, "Only an explicit require_ssl=false or ssl_mode in {ALLOW_UNENCRYPTED_AND_ENCRYPTED, ENCRYPTED_ONLY} fires; missing/unknown is skipped."),
    "google_cloud_sql_backups_disabled": (HIGH, "Only an explicit backup_enabled=false fires; missing/unknown is skipped."),
    "google_cloud_sql_deletion_protection_disabled": (HIGH, "Only an explicit deletion_protection_enabled=false fires; missing/unknown is skipped."),
    # Google Cloud — M78C: Cloud Run
    "google_cloud_run_public_invoker": (HIGH, "Only fires when the IAM policy for the Cloud Run service has allUsers or allAuthenticatedUsers on roles/run.invoker; inferred from invoker policy counts."),
    "google_cloud_run_all_ingress": (HIGH, "Only an explicit ingress=INGRESS_TRAFFIC_ALL fires; internal/load-balancer ingress does not fire."),
    # Google Cloud — M78C: GKE
    "google_cloud_gke_public_control_plane": (HIGH, "Fires only when public_endpoint_enabled=true AND master_authorized_networks_count is 0 or absent; clusters with authorized networks are not flagged."),
    "google_cloud_gke_legacy_abac_enabled": (HIGH, "Only an explicit legacy_abac_enabled=true fires; missing/unknown is skipped."),
    "google_cloud_gke_network_policy_disabled": (MEDIUM, "Only an explicit network_policy_enabled=false fires; missing/unknown (absence of network policy is common) uses medium confidence."),
    "google_cloud_gke_workload_identity_disabled": (MEDIUM, "Fires when workload_identity_enabled=false (no workloadPool configured); absence of workload identity is the default cluster state."),
    # Google Cloud — M78C: Service account keys
    "google_cloud_service_account_user_managed_keys": (HIGH, "Only fires when user_managed_key_count > 0 on the project-level summary record; SA emails and key IDs are never read."),
    "google_cloud_service_account_old_keys": (HIGH, "Only fires when old_user_managed_key_count > 0 or oldest_key_age_days >= 90; computed from validAfterTime timestamps only."),
    # Google Cloud — M78C: Secret Manager
    "google_cloud_secret_manager_auto_replication_without_cmek": (MEDIUM, "Fires only when automatic_replication_count > 0 AND customer_managed_encryption_count == 0; secret names and values are never read."),
    # Twilio — M79B
    "twilio_phone_number_sms_webhook_missing": (HIGH, "Only fires when capability_sms=true AND sms_url_configured=false on a twilio_incoming_phone_number record; missing/unknown is skipped."),
    "twilio_phone_number_voice_webhook_missing": (HIGH, "Only fires when capability_voice=true AND voice_url_configured=false on a twilio_incoming_phone_number record; missing/unknown is skipped."),
    "twilio_phone_number_status_callback_missing": (MEDIUM, "Fires when capability_sms or capability_voice is set AND status_callback_configured=false; phone numbers with neither capability are not flagged."),
    "twilio_messaging_service_inbound_webhook_missing": (HIGH, "Only fires when inbound_request_url_configured=false AND use_inbound_webhook_on_number is not true; services using number-level webhooks are excluded."),
    "twilio_messaging_service_fallback_missing": (MEDIUM, "Fires when fallback_url_configured=false; absence of a fallback URL is the default state so medium confidence is used."),
    "twilio_messaging_service_status_callback_missing": (MEDIUM, "Fires when status_callback_url_configured=false; absence of a status callback is the common default."),
    "twilio_verify_short_code_length": (HIGH, "Only fires when code_length is an explicit integer < 6; missing/unknown values are skipped."),
    "twilio_verify_lookup_disabled": (MEDIUM, "Only an explicit lookup_enabled=false fires; missing/unknown is skipped."),
    "twilio_account_suspended": (MEDIUM, "Fires when account status is not 'active' or empty; missing/unknown is skipped."),
    # Twilio — M79C
    "twilio_api_key_stale": (MEDIUM, "Fires when date_updated or date_created indicates the key is 180+ days old; keys with no date metadata are skipped. Long-lived read-only keys may fire intentionally."),
    "twilio_messaging_service_observability_gap": (HIGH, "Only fires when both fallback_url_configured=false AND status_callback_url_configured=false are simultaneously true on a twilio_messaging_service record."),
    "twilio_messaging_service_number_level_inbound_webhook": (MEDIUM, "Fires when use_inbound_webhook_on_number=true AND inbound_request_url_configured=false; number-level delegation is a valid but fragmented pattern."),
    "twilio_messaging_service_long_validity_period": (MEDIUM, "Only fires when validity_period is an explicit integer > 86400; missing/unknown values are skipped."),
    "twilio_phone_number_messaging_observability_gap": (HIGH, "Only fires when capability_sms=true AND both sms_url_configured=false AND status_callback_configured=false on a twilio_incoming_phone_number record."),
    "twilio_phone_number_voice_observability_gap": (HIGH, "Only fires when capability_voice=true AND both voice_url_configured=false AND status_callback_configured=false on a twilio_incoming_phone_number record."),
    "twilio_verify_psd2_disabled": (MEDIUM, "Only an explicit psd2_enabled=false fires; missing/unknown is skipped. PSD2 is only relevant for financial transaction verification in regulated markets."),
    "twilio_verify_sms_to_landlines_allowed": (MEDIUM, "Only an explicit skip_sms_to_landlines=false fires; missing/unknown is skipped."),
    # SendGrid — M80B
    "sendgrid_api_key_broad_scopes": (HIGH, "Only fires when has_full_access=true on a sendgrid_api_key record; missing/false is never flagged."),
    "sendgrid_sender_identity_unverified": (HIGH, "Only fires when verified=false on a sendgrid_sender_identity record; missing/unknown is skipped."),
    "sendgrid_sender_identity_locked": (HIGH, "Only fires when locked=true on a sendgrid_sender_identity record; unlocked identities are not flagged."),
    "sendgrid_domain_authentication_invalid": (HIGH, "Only fires when valid=false on a sendgrid_domain_authentication record; missing/unknown is skipped."),
    "sendgrid_domain_automatic_security_disabled": (HIGH, "Only fires when automatic_security=false on a sendgrid_domain_authentication record; missing/unknown is skipped."),
    "sendgrid_domain_authentication_legacy": (HIGH, "Only fires when legacy=true on a sendgrid_domain_authentication record; non-legacy domains are not flagged."),
    "sendgrid_spam_check_disabled": (HIGH, "Only fires when spam_check_enabled=false on a sendgrid_mail_settings record; missing/unknown is skipped."),
    "sendgrid_sandbox_mode_enabled": (HIGH, "Only fires when sandbox_mode_enabled=true on a sendgrid_mail_settings record; disabled sandbox mode is not flagged."),
    "sendgrid_bcc_enabled": (HIGH, "Only fires when bcc_enabled=true on a sendgrid_mail_settings record; the BCC address is never stored."),
    "sendgrid_click_tracking_enabled": (HIGH, "Only fires when click_tracking_enabled=true on a sendgrid_tracking_settings record; disabled tracking is not flagged."),
    "sendgrid_open_tracking_enabled": (HIGH, "Only fires when open_tracking_enabled=true on a sendgrid_tracking_settings record; disabled tracking is not flagged."),
    "sendgrid_subscription_tracking_disabled": (HIGH, "Only fires when subscription_tracking_enabled=false on a sendgrid_tracking_settings record; missing/unknown is skipped."),
    "sendgrid_event_webhook_disabled": (HIGH, "Only fires when event_webhook_enabled=false on a sendgrid_webhook_settings record; missing/unknown is skipped."),
    "sendgrid_event_webhook_url_missing": (HIGH, "Only fires when event_webhook_enabled=true AND event_webhook_has_url=false on a sendgrid_webhook_settings record; both conditions must be explicitly present."),
    "sendgrid_suppression_settings_empty": (MEDIUM, "Only fires when suppression_group_count is an explicit integer equal to 0; missing/unknown suppression_group_count is skipped."),
    # SendGrid — M80C
    "sendgrid_sender_identity_reply_domain_mismatch": (HIGH, "Only fires when both from_email_domain and reply_to_domain are non-empty strings on a sendgrid_sender_identity record and they differ; missing/empty domains are never flagged. Domain strings only — full email addresses NEVER stored."),
    "sendgrid_domain_dns_records_missing": (HIGH, "Only fires when dns_record_count is an explicit integer equal to 0 on a sendgrid_domain_authentication record; missing/unknown counts are skipped. Raw DNS values NEVER stored."),
    "sendgrid_default_domain_authentication_invalid": (HIGH, "Only fires when default=true AND valid=false on a sendgrid_domain_authentication record; both conditions must be explicitly present."),
    "sendgrid_footer_disabled": (HIGH, "Only fires when footer_enabled=false on a sendgrid_mail_settings record; footer text content is NEVER stored."),
    "sendgrid_bounce_purge_disabled": (HIGH, "Only fires when bounce_purge_enabled=false on a sendgrid_mail_settings record; missing/unknown is skipped."),
    "sendgrid_template_engine_enabled": (HIGH, "Only fires when template_enabled=true on a sendgrid_mail_settings record; template content is NEVER stored."),
    "sendgrid_google_analytics_tracking_enabled": (HIGH, "Only fires when ganalytics_enabled=true on a sendgrid_tracking_settings record; GA parameter values and campaign data NEVER stored."),
    "sendgrid_event_webhook_broad_event_stream": (MEDIUM, "Only fires when event_webhook_enabled=true AND event_count > 8 on a sendgrid_webhook_settings record; event payloads and recipient data NEVER stored."),
    "sendgrid_inbound_parse_enabled": (HIGH, "Only fires when inbound_parse_enabled=true on a sendgrid_webhook_settings record; hostname, URL, email bodies, and recipient data NEVER stored."),
    "sendgrid_inbound_parse_raw_email_enabled": (HIGH, "Only fires when inbound_parse_enabled=true AND inbound_parse_send_raw_enabled=true; raw email content and recipient data NEVER stored."),
    "sendgrid_inbound_parse_spam_check_disabled": (HIGH, "Only fires when inbound_parse_enabled=true AND inbound_parse_spam_check_enabled=false; both conditions must be explicitly present."),
    # Auth0 — M81B
    "auth0_tenant_session_lifetime_extended": (HIGH, "Only fires when session_lifetime_category=='extended' on an auth0_tenant_settings record; no token or session content is stored."),
    "auth0_tenant_idle_session_lifetime_extended": (HIGH, "Only fires when idle_session_lifetime_category=='extended' on an auth0_tenant_settings record."),
    "auth0_tenant_dynamic_client_registration_enabled": (HIGH, "Only fires when flag_enable_dynamic_client_registration=true on an auth0_tenant_settings record."),
    "auth0_application_no_callbacks": (MEDIUM, "Only fires when callbacks_count==0 AND app_type is a web-based application (spa/regular_web); CLI/M2M/native apps are skipped. Raw callback URLs are never stored."),
    "auth0_application_many_callbacks": (HIGH, "Only fires when callbacks_count exceeds a conservative threshold; raw URLs NEVER stored."),
    "auth0_application_many_allowed_origins": (HIGH, "Only fires when (allowed_origins_count + web_origins_count) exceeds a conservative threshold; raw origin strings NEVER stored."),
    "auth0_application_oidc_non_conformant": (HIGH, "Only fires when oidc_conformant is explicitly false on an auth0_application record."),
    "auth0_application_weak_jwt_algorithm": (HIGH, "Only fires when jwt_alg is HS256/HS384/HS512/none; signing keys NEVER stored."),
    "auth0_refresh_token_rotation_disabled": (MEDIUM, "Only fires when refresh_token_rotation_enabled is false AND the application's grant_types_summary includes 'refresh_token'; CLI/M2M apps without refresh tokens are skipped."),
    "auth0_refresh_token_lifetime_extended": (HIGH, "Only fires when refresh_token_lifetime_category=='extended' on an auth0_application record."),
    "auth0_connection_no_enabled_clients": (HIGH, "Only fires when enabled_clients_count==0 on an auth0_connection record."),
    "auth0_connection_weak_password_policy": (MEDIUM, "Only fires for strategy=='auth0' database connections when password_policy_category is 'none'/'low'/'fair' or not configured; non-database connections are skipped. Connection credentials NEVER stored."),
    "auth0_resource_server_offline_access_enabled": (HIGH, "Only fires when allow_offline_access=true on an auth0_resource_server record."),
    "auth0_resource_server_token_lifetime_extended": (HIGH, "Only fires when token_lifetime_category=='extended' on an auth0_resource_server record."),
    "auth0_resource_server_rbac_disabled": (HIGH, "Only fires when rbac_enabled is explicitly false on an auth0_resource_server record."),
    "auth0_rule_disabled": (MEDIUM, "Only fires when enabled is explicitly false AND script_present=true on an auth0_rule record; rule script content NEVER stored."),
    "auth0_rule_large_script": (HIGH, "Only fires when script_length_category=='long' on an auth0_rule record; script content NEVER stored."),
    "auth0_action_not_deployed": (HIGH, "Only fires when deployed_version_present is false on an auth0_action record."),
    "auth0_action_secrets_present": (HIGH, "Only fires when secrets_count > 0 on an auth0_action record; secret names and values NEVER stored."),
    "auth0_mfa_factor_disabled": (HIGH, "Only fires for strong second factors (otp / webauthn-roaming / push-notification) when enabled is explicitly false; no enrollment data ever stored."),
    "auth0_custom_domain_not_ready": (HIGH, "Only fires when status is 'pending_verification'/'provisioning'/'disabled' on an auth0_custom_domain record; custom domain name strings NEVER stored."),
    "auth0_custom_domain_weak_tls_policy": (HIGH, "Only fires when tls_policy_category=='compatible' on an auth0_custom_domain record."),
    # Auth0 — M81C OAuth/application risk expansion
    "auth0_application_password_grant_enabled": (HIGH, "Only fires when grant_password_enabled=true on an auth0_application record; no credential values are stored."),
    "auth0_application_implicit_grant_enabled": (HIGH, "Only fires when grant_implicit_enabled=true on an auth0_application record."),
    "auth0_application_public_client_credentials_enabled": (HIGH, "Only fires when grant_client_credentials_enabled=true AND app_type is spa/native OR token_endpoint_auth_method=none; no client secret is stored."),
    "auth0_application_refresh_grant_without_rotation": (HIGH, "Only fires when grant_refresh_token_enabled=true AND refresh_token_rotation_enabled is explicitly false; no token values are stored."),
    "auth0_application_many_grant_types": (HIGH, "Only fires when grant_types_count exceeds the conservative threshold; no token values are stored."),
    "auth0_application_device_code_grant_enabled": (HIGH, "Only fires when grant_device_code_enabled=true on an auth0_application record."),
    "auth0_application_wildcard_callback": (HIGH, "Only fires when wildcard_callback_present=true (a boolean derived from callbacks during normalization); raw callback URLs are NEVER stored."),
    "auth0_application_wildcard_allowed_origin": (HIGH, "Only fires when wildcard_allowed_origin_present=true (a boolean derived from allowed_origins during normalization); raw origin URLs are NEVER stored."),
    "auth0_application_wildcard_logout_url": (HIGH, "Only fires when wildcard_logout_url_present=true (a boolean derived from allowed_logout_urls during normalization); raw logout URLs are NEVER stored."),
    "auth0_application_localhost_callback": (HIGH, "Only fires when localhost_callback_present=true (a boolean derived from callbacks during normalization); raw callback URLs are NEVER stored."),
    "auth0_application_localhost_origin": (HIGH, "Only fires when localhost_origin_present=true (a boolean derived from allowed_origins during normalization); raw origin URLs are NEVER stored."),
    "auth0_application_callback_missing_https": (HIGH, "Only fires when callbacks_missing_https=true (a boolean derived from callbacks during normalization, excluding localhost); raw callback URLs are NEVER stored."),
    "auth0_application_origin_missing_https": (HIGH, "Only fires when allowed_origins_missing_https=true (a boolean derived from allowed_origins during normalization, excluding localhost); raw origin URLs are NEVER stored."),
    "auth0_public_client_refresh_tokens_enabled": (MEDIUM, "Only fires when grant_refresh_token_enabled=true AND app_type is spa/native; no token values are stored."),
    "auth0_application_token_endpoint_auth_none": (HIGH, "Only fires when token_endpoint_auth_method=='none' on an auth0_application record."),
    # Datadog — M82B core security rules
    "datadog_monitor_disabled": (HIGH, "Only fires when enabled is explicitly false on a datadog_monitor record; raw query and message NEVER stored."),
    "datadog_monitor_unrestricted_roles": (MEDIUM, "Fires when restricted_roles_count==0; many monitors are intentionally open, so medium confidence applies."),
    "datadog_monitor_notify_no_data_disabled": (MEDIUM, "Only fires when notify_no_data is explicitly false; absence of no-data notification is common and may be intentional."),
    "datadog_monitor_long_query": (MEDIUM, "Only fires when query_complexity_category=='long'; raw query content NEVER stored."),
    "datadog_slo_no_monitors": (HIGH, "Only fires for slo_type=='monitor' SLOs where monitor_count==0; other SLO types are not flagged."),
    "datadog_slo_low_target": (MEDIUM, "Fires when target_category=='below_95'; a low target may be a business decision rather than a misconfiguration."),
    "datadog_dashboard_public_url_present": (HIGH, "Only fires when public_url_present=true on a datadog_dashboard record; the URL string NEVER stored."),
    "datadog_dashboard_unrestricted_roles": (MEDIUM, "Fires when restricted_roles_count==0; dashboards are commonly open within an organization."),
    "datadog_webhook_without_secret_headers": (HIGH, "Only fires when url_present=true AND secret_headers_present=false; webhook URL and header values NEVER stored."),
    "datadog_webhook_payload_template_present": (MEDIUM, "Only fires when payload_template_present=true; template content NEVER stored."),
    "datadog_notification_integration_no_channels": (MEDIUM, "Fires when enabled=true AND handle_count==0 AND channel_count==0; destination handles NEVER stored."),
    "datadog_application_key_broad_scopes": (HIGH, "Only fires when scopes_count exceeds the conservative threshold; scope names and key values NEVER stored."),
    "datadog_api_key_disabled": (HIGH, "Only fires when disabled=true on a datadog_api_key_metadata record; key values NEVER stored."),
    "datadog_role_high_permission_count": (HIGH, "Only fires when permission_count exceeds the conservative threshold; user identities NEVER stored."),
    "datadog_team_no_members": (HIGH, "Only fires when member_count==0 on a datadog_team record; member identities NEVER stored."),
    "datadog_cloud_integration_broad_collection": (HIGH, "Fires only when all three collection flags (resource, metric, log) are simultaneously true; account IDs NEVER stored."),
    "datadog_cloud_integration_log_collection_enabled": (HIGH, "Only fires when log_collection_enabled=true; log content and account IDs NEVER stored."),
    # Datadog — M82C monitor/webhook risk expansion
    "datadog_monitor_no_notifications": (HIGH, "Fires when notification_routing_present=false, derived from absence of @ in message before discarding; raw message NEVER stored."),
    "datadog_monitor_message_template_present": (MEDIUM, "Fires when message_template_present=true ({{ in message), derived before discarding; raw message NEVER stored. Very common — medium confidence."),
    "datadog_monitor_no_warning_threshold": (HIGH, "Fires only when threshold_critical_present=true AND threshold_warning_present=false; raw threshold values NEVER stored."),
    "datadog_monitor_no_recovery_threshold": (HIGH, "Fires only when threshold_critical_present=true AND threshold_recovery_present=false; raw threshold values NEVER stored."),
    "datadog_monitor_silenced_scopes_present": (HIGH, "Fires when silenced_scope_count > 0, derived from the silenced dict before discarding; scope identifiers NEVER stored."),
    "datadog_monitor_notify_audit_disabled": (MEDIUM, "Fires when notify_audit=false; audit notifications are commonly disabled, so medium confidence applies."),
    "datadog_monitor_require_full_window_disabled": (MEDIUM, "Fires when require_full_window=false; this is the default for many monitor types, so medium confidence applies."),
    "datadog_monitor_query_wildcard_scope": (HIGH, "Fires when query_uses_wildcard_scope=true ({*} present in query), derived before discarding; raw query NEVER stored."),
    "datadog_monitor_broad_group_by": (HIGH, "Fires when query_group_by_count >= 3, derived by counting 'by {' occurrences before discarding; raw query NEVER stored."),
    "datadog_monitor_long_no_data_timeframe": (HIGH, "Fires when no_data_timeframe_category=='extended' (>= 2 hours), derived before discarding; raw timeframe value categorised only."),
    "datadog_webhook_custom_headers_without_secret_headers": (HIGH, "Fires when custom_headers_present=true AND secret_headers_present=false; header names and values NEVER stored."),
    "datadog_webhook_large_payload_template": (MEDIUM, "Fires when payload_template_length_category=='long'; template content NEVER stored. Large templates are not inherently risky — medium confidence."),
    "datadog_webhook_auth_material_present": (HIGH, "Fires when auth_material_present=true, derived by checking header key names for auth patterns before discarding; header names and values NEVER stored."),
    "datadog_webhook_non_https_endpoint": (HIGH, "Fires when url_scheme_category=='http', derived from URL before discarding; URL string NEVER stored."),
}


def confidence_for(finding_key: str) -> tuple[str, str, str]:
    """Return (confidence, confidence_reason, false_positive_guard) for a finding.

    Looks up the base rule key. Unknown keys default to high confidence with a
    generic reason and no guard (preserves existing behavior — never suppresses).
    """
    rule_key = base_rule_key(finding_key)
    confidence, guard = RULE_CONFIDENCE.get(rule_key, (HIGH, ""))
    return confidence, _REASON.get(confidence, _REASON[HIGH]), guard


# Sanity: every known rule has a confidence entry, and none is low.
def _self_check() -> None:  # pragma: no cover - import-time guard
    missing = KNOWN_RULE_KEYS - set(RULE_CONFIDENCE)
    assert not missing, f"rules missing confidence: {sorted(missing)}"
    assert all(c in (HIGH, MEDIUM) for c, _ in RULE_CONFIDENCE.values())


_self_check()
