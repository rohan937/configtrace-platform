"""Diff service — Milestone 9.

Responsibilities
----------------
* ``build_record_index``     — stable key → full record dict from snapshot.state
* ``format_record_identifier`` — human-readable label, e.g. "A api.example.com"
* ``compute_diff``           — pure function: two Snapshots → list[change_dict]
* ``store_changes``          — persist change_dicts as Change rows in the DB

Design decisions
----------------
* ``compute_diff`` is **pure** — it reads Snapshot.state but never touches the
  database.  This makes every diff scenario testable without DB fixtures.

* ``store_changes`` is the DB writer.  Keeping it separate from ``compute_diff``
  means the diff logic can be validated independently of persistence concerns.

* Only the seven fields in ``_TRACKED_FIELDS`` are compared for modified
  records.  Volatile provider timestamps (``modified_on``, ``created_on``,
  etc.) are explicitly excluded to prevent false positives on every sync.

* One Change row is written per changed *field* for "modified" records.  A
  record with three changed fields produces three rows.  This granularity lets
  Milestone 10 apply different risk levels to TTL changes vs content changes on
  the same record.

* ``risk_level`` is set to ``"unknown"`` on all rows written here.  Milestone 10
  (risk service) will update these to low/medium/high/critical.

* ``provider_metadata`` is populated with enough record context (type, name,
  content, stable ID) for Milestone 10 risk rules and the Milestone 11/15 UI
  to classify and display changes without reloading snapshot state.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.change import Change
from app.models.snapshot import Snapshot

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Fields compared field-by-field for Cloudflare DNS records.
# Ordered deterministically so multi-field modifications are always in the same
# sequence, which matters for the UI and for risk rule matching.
_TRACKED_FIELDS: tuple[str, ...] = (
    "record_type",   # maps from Cloudflare's "type" via connector normalisation
    "name",
    "content",
    "ttl",
    "proxied",
    "priority",
    "comment",
)

# Fields that must NEVER trigger a change even if they differ between snapshots.
# These are provider-managed timestamps that change on every API response
# regardless of whether the configuration actually changed.
_IGNORED_FIELDS: frozenset[str] = frozenset({
    "modified_on",
    "created_on",
    "created_at",
    "updated_at",
})

# ── GitHub-specific tracked fields ──────────────────────────────────────────

#: Set of GitHub record type strings — used for O(1) membership checks.
_GITHUB_RECORD_TYPES: frozenset[str] = frozenset({
    "github_repo_settings",
    "github_branch_protection",
    "github_actions_secret",
    "github_actions_variable",
    "github_webhook",
    "github_actions_permissions",
    "github_deploy_key",
})

# ── Vercel-specific tracked fields ───────────────────────────────────────────

#: Per-record-type tracked field tuples for Vercel records.
#: Only the fields listed here are compared field-by-field in compute_diff.
#: Provider-managed timestamps (``created_at``) are intentionally excluded
#: except for ``updated_at`` on env vars (a change signals secret rotation).
_VERCEL_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "vercel_project": (
        # Identity
        "name",               # project rename
        # Build pipeline (supply-chain / deployment critical)
        "build_command",      # custom build command
        "install_command",    # custom install command
        "root_directory",     # monorepo source root (build-breaking if wrong)
        "output_directory",   # where the build writes output
        # Runtime
        "framework",          # framework preset (changes routing + build strategy)
        "node_version",       # Node.js runtime version
        # Git connection
        "git_repository",     # connected repository (owner/repo)
        "git_branch",         # production branch (e.g. "main")
        # Deployment protection
        "sso_protection",     # None = disabled; "all" = SSO-gated
        "password_protection", # None = disabled; "all" = password-gated
    ),
    "vercel_env_var": (
        # key/name change is unusual but meaningful (env var renamed)
        "key",
        # type change (encrypted → plain is a security downgrade)
        "env_type",
        # target change (promoted to / demoted from production)
        "target",
        # git_branch scope change
        "git_branch",
        # updated_at change signals a value rotation — tracked intentionally
        # SECURITY: only the timestamp is stored, never the new value
        "updated_at",
        # NOTE: "value" is intentionally NOT listed here (M33 security constraint)
    ),
    "vercel_domain": (
        "verified",    # domain verification status
        "redirect",    # redirect target (None = no redirect)
        "git_branch",  # branch-specific domain scope
    ),
}

#: Per-record-type tracked field tuples for GitHub records.
#: Only the fields listed here are compared field-by-field in compute_diff.
#: Provider-managed timestamps (e.g. ``created_at``) are intentionally excluded.
_GITHUB_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "github_repo_settings": (
        "visibility",
        "default_branch",
        "has_issues",
        "has_projects",
        "has_wiki",
        "allow_merge_commit",
        "allow_squash_merge",
        "allow_rebase_merge",
        "delete_branch_on_merge",
        "archived",
    ),
    "github_branch_protection": (
        "protection_enabled",
        "required_status_checks_enabled",
        "required_pull_request_reviews_enabled",
        "required_approving_review_count",
        "dismiss_stale_reviews",
        "enforce_admins",
        "required_linear_history",
        "allow_force_pushes",
        "allow_deletions",
    ),
    "github_actions_secret": (
        # Only metadata — secret values are never fetched.
        # last_updated_at changing signals a credential rotation.
        "last_updated_at",
    ),
    "github_actions_variable": (
        "value",
    ),
    "github_webhook": (
        "url",
        "active",
        "events",
        "content_type",
    ),
    "github_actions_permissions": (
        "enabled",
        "allowed_actions",
    ),
    "github_deploy_key": (
        "title",
        "read_only",
        "verified",
    ),
}



# ── Stripe-specific tracked fields ────────────────────────────────────────────

#: Per-record-type tracked field tuples for Stripe records.
#: Only the fields listed here are compared field-by-field in compute_diff.
#: Volatile metadata (file IDs that change on branding uploads, etc.) is
#: included only where changes are meaningful.
_STRIPE_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "stripe_account_settings": (
        # Operational flags — highest priority
        "charges_enabled",
        "payouts_enabled",
        # Payout schedule
        "payout_schedule_interval",
        "payout_schedule_delay_days",
        # Capabilities / payment methods
        "enabled_payment_methods",
        # Currency
        "default_currency",
        # Business profile
        "business_name",
        "support_email",
        "support_url",
        "business_url",
        # Branding
        "branding_icon",
        "branding_logo",
        "branding_primary_color",
        # Dashboard
        "display_name",
        # Platform
        "controller_type",
    ),
    "stripe_webhook_endpoint": (
        "url",
        "status",
        "enabled_events",
        "api_version",
        "description",
        # SECURITY: signing secret is intentionally NOT listed here
    ),
    "stripe_payment_method_configuration": (
        "config_name",
        "is_default",
        "enabled_payment_methods",
    ),
    "stripe_payment_method_domain": (
        "enabled",
        "apple_pay_enabled",
        "google_pay_enabled",
        "link_enabled",
        "domain_name",
    ),
}


# ── AWS-specific tracked fields ───────────────────────────────────────────────

_AWS_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "aws_account_identity": (
        "account_id",
        "principal_arn",
        "principal_type",
        "partition",
        "default_region",
        "selected_regions",
    ),
    "aws_region": (
        "opt_in_status",
        "enabled",
        "source",
    ),
    "aws_service_inventory": (
        "selected_regions",
        "enabled_surfaces",
        "s3_bucket_count",
        "security_group_count",  # M38
        "vpc_count",             # M38
        # NOTE: future_surfaces is intentionally NOT tracked — adding future
        # surfaces to the placeholder list should not generate change events.
    ),
    # ── M37: S3 bucket configuration ─────────────────────────────────────────
    # One record per S3 bucket. All security-relevant fields are tracked so
    # that exposure changes generate change events at the correct risk level.
    # creation_date is intentionally excluded (immutable).
    # Raw policy text is never stored; policy_hash tracks policy text changes.
    "aws_s3_bucket": (
        # Location
        "bucket_region",
        # Block Public Access
        "block_public_acls",
        "ignore_public_acls",
        "block_public_policy",
        "restrict_public_buckets",
        "public_access_block_configured",
        # Policy
        "policy_present",
        "policy_status_is_public",
        "policy_hash",            # hash of raw policy — tracks text changes
        "public_principals_detected",
        # ACL
        "acl_all_users_read",
        "acl_all_users_write",
        "acl_authenticated_users_read",
        "acl_authenticated_users_write",
        # Encryption
        "encryption_enabled",
        "encryption_algorithm",
        "bucket_key_enabled",
        # Versioning
        "versioning_status",
        "mfa_delete_status",
        # Logging
        "logging_enabled",
        "logging_target_bucket",
        # Lifecycle
        "lifecycle_rule_count",
        # Tags
        "tag_keys",
        # Fetch-time warnings (missing optional permissions)
        "config_fetch_warnings",
    ),
    # ── M38: Security Groups + VPC Network Exposure ───────────────────────────
    # aws_security_group — one record per EC2 security group per region.
    # Aggregate posture fields (has_public_*) allow diff to detect when the
    # overall exposure of a group changes without scanning every rule record.
    "aws_security_group": (
        "group_name",
        "description",
        "vpc_id",
        "inbound_rule_count",
        "outbound_rule_count",
        "has_public_inbound",
        "has_public_ssh",
        "has_public_rdp",
        "has_public_database_port",
        "tag_keys",
    ),
    # aws_security_group_rule — one record per flattened rule (one CIDR/ref).
    # The record_id encodes direction/protocol/ports/CIDR so structural changes
    # appear as remove+add.  Only description can change in place.
    "aws_security_group_rule": (
        "description",
    ),
    # aws_vpc — one record per VPC per region.
    "aws_vpc": (
        "state",
        "cidr_block",
        "dhcp_options_id",
        "instance_tenancy",
        "tag_keys",
    ),
    # aws_subnet — one record per subnet per region.
    # map_public_ip_on_launch is the key exposure signal.
    "aws_subnet": (
        "state",
        "available_ip_count",
        "map_public_ip_on_launch",
        "tag_keys",
    ),
    # aws_route_table — one record per route table per region.
    # has_igw_route is the key internet-routing signal.
    "aws_route_table": (
        "has_igw_route",
        "igw_id",
        "route_count",
        "associated_subnet_ids",
        "tag_keys",
    ),
    # aws_internet_gateway — one record per IGW per region.
    "aws_internet_gateway": (
        "state",
        "attached_vpc_id",
        "tag_keys",
    ),
    # aws_network_acl — one record per NACL per region.
    "aws_network_acl": (
        "inbound_allow_all_count",
        "outbound_allow_all_count",
        "rule_count",
        "tag_keys",
    ),
    # ── M39: IAM Identity, Permissions, Policy and Trust Risk ─────────────────
    # aws_iam_account_summary — one record per AWS account.
    # Tracks root security posture, password policy, and aggregate counts.
    "aws_iam_account_summary": (
        "user_count",
        "group_count",
        "role_count",
        "policy_count",
        "mfa_enabled_for_root",
        "root_access_keys_present",
        "password_policy_present",
        "password_min_length",
        "password_requires_symbols",
        "password_requires_numbers",
        "password_requires_uppercase",
        "password_requires_lowercase",
        "password_max_age",
        "password_reuse_prevention",
        "password_hard_expiry",
    ),
    # aws_iam_user — one record per IAM user.
    # Key security signals: MFA enrollment, key counts, policy attachment.
    "aws_iam_user": (
        "mfa_enabled",
        "mfa_device_count",
        "active_key_count",
        "inactive_key_count",
        "last_key_used_age_days",
        "group_count",
        "attached_policy_count",
        "inline_policy_count",
        "tag_keys",
    ),
    # aws_iam_access_key — one record per IAM access key.
    # status change (Active→Inactive) and last-used signal rotation/abandonment.
    "aws_iam_access_key": (
        "status",
        "last_used_age_days",
        "last_used_service",
        "last_used_region",
    ),
    # aws_iam_group — one record per IAM group.
    # member_count and policy counts track group permission drift.
    "aws_iam_group": (
        "member_count",
        "attached_policy_count",
        "inline_policy_count",
    ),
    # aws_iam_role — one record per IAM role.
    # trust_summary tracks changes to who can assume this role.
    # max_session_duration change can enable long-lived sessions.
    "aws_iam_role": (
        "max_session_duration",
        "attached_policy_count",
        "inline_policy_count",
        "tag_keys",
        "trust_summary",
    ),
    # aws_iam_policy — one record per customer-managed IAM policy.
    # policy_summary tracks privilege escalation risk vectors.
    "aws_iam_policy": (
        "attachment_count",
        "is_attachable",
        "version_count",
        "policy_summary",
    ),
    # aws_iam_policy_attachment — one record per principal↔managed-policy link.
    # Added/removed events are the primary signals; no mutable fields to track.
    "aws_iam_policy_attachment": (
        # The attachment itself is structural: added = permission granted,
        # removed = permission revoked. No fields change in place.
        # Include policy_name so changes to the label are visible.
        "policy_name",
    ),
    # aws_iam_inline_policy — one record per inline policy per principal.
    # policy_summary tracks privilege escalation risk in the inline document.
    "aws_iam_inline_policy": (
        "policy_summary",
    ),
    # aws_iam_identity_provider — one record per OIDC/SAML provider.
    # Federation configuration changes signal trust boundary changes.
    "aws_iam_identity_provider": (
        "oidc_client_id_count",
        "oidc_thumbprint_count",
        "saml_valid_until",
    ),
    # ── M40: Route53 DNS + CloudFront CDN Routing Config ──────────────────────
    # aws_route53_hosted_zone — one record per Route53 hosted zone.
    # Tracks zone type, VPC linkage, NS changes, and comment drift.
    "aws_route53_hosted_zone": (
        "zone_type",
        "private_zone",
        "resource_record_set_count",
        "linked_vpc_count",
        "comment",
        "name_servers",
        "tag_keys",
        "config_fetch_warnings",
    ),
    # aws_route53_record — one record per DNS resource record set.
    # value_hash tracks record value changes without storing raw values.
    # dmarc_policy specifically tracks DMARC enforcement posture.
    "aws_route53_record": (
        "ttl",
        "value_hash",
        "alias_target_dns_name",
        "alias_hosted_zone_id",
        "evaluate_target_health",
        "routing_policy",
        "weight",
        "region",
        "failover",
        "geo_location_summary",
        "health_check_id",
        "dmarc_policy",
        "config_fetch_warnings",
    ),
    # aws_cloudfront_distribution — one record per CloudFront distribution.
    # Tracks security-critical CDN configuration: viewer protocol, WAF, TLS,
    # origins, and operational state.
    "aws_cloudfront_distribution": (
        "enabled",
        "status",
        "aliases",
        "alias_count",
        "default_root_object",
        "price_class",
        "http_version",
        "ipv6_enabled",
        "web_acl_id",
        "viewer_certificate_summary",
        "origin_count",
        "origins_summary",
        "default_cache_behavior_summary",
        "ordered_cache_behavior_count",
        "ordered_cache_behaviors_summary",
        "logging_enabled",
        "logging_bucket_domain",
        "custom_error_response_count",
        "restrictions_summary",
        "tag_keys",
        "config_fetch_warnings",
    ),
    # ── M41: Secrets Manager + SSM Parameter Metadata ─────────────────────────
    # aws_secretsmanager_secret — one record per Secrets Manager secret.
    # Secret values are NEVER stored; only metadata and structural signals.
    # kms_key_id_hash tracks KMS key changes without storing the raw ARN.
    "aws_secretsmanager_secret": (
        "description_present",
        "kms_key_id_present",
        "kms_key_id_hash",
        "rotation_enabled",
        "rotation_lambda_arn_present",
        "rotation_rules_summary",
        "last_changed_date",
        "last_accessed_date",
        "deleted_date",
        "owning_service",
        "primary_region",
        "replica_region_count",
        "replica_regions",
        "version_count",
        "active_version_count",
        "deprecated_version_count",
        "has_resource_policy",
        "policy_summary",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # aws_ssm_parameter — one record per SSM Parameter.
    # Parameter values are NEVER stored; only type/tier/policy metadata.
    # key_id_hash tracks KMS key changes without storing the raw ARN.
    "aws_ssm_parameter": (
        "parameter_type",
        "tier",
        "data_type",
        "key_id_present",
        "key_id_hash",
        "version",
        "last_modified_date",
        "last_modified_user_summary",
        "allowed_pattern_present",
        "policy_count",
        "policies_summary",
        "tag_keys",
        "path_depth",
        "path_prefix",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # ── M42: RDS Database Exposure / Backup / Encryption Config ──────────────
    # aws_rds_db_instance — one record per RDS DB instance.
    # No DB data, passwords, endpoints (only boolean presence), or connections.
    # kms_key_id_hash detects KMS key changes without storing raw ARN.
    "aws_rds_db_instance": (
        "engine",
        "engine_version",
        "engine_major_version",
        "db_instance_class",
        "db_instance_status",
        "allocated_storage",
        "max_allocated_storage",
        "storage_type",
        "storage_encrypted",
        "kms_key_id_present",
        "kms_key_id_hash",
        "publicly_accessible",
        "deletion_protection",
        "backup_retention_period",
        "preferred_backup_window",
        "preferred_maintenance_window",
        "multi_az",
        "secondary_availability_zone_present",
        "vpc_security_group_ids",
        "vpc_security_group_count",
        "db_subnet_group_name",
        "db_subnet_group_vpc_id",
        "db_subnet_group_status",
        "subnet_count",
        "subnet_availability_zones",
        "parameter_group_names",
        "option_group_names",
        "iam_database_authentication_enabled",
        "auto_minor_version_upgrade",
        "ca_certificate_identifier",
        "performance_insights_enabled",
        "performance_insights_kms_key_id_present",
        "monitoring_interval",
        "enhanced_monitoring_enabled",
        "enabled_cloudwatch_logs_exports",
        "license_model",
        "copy_tags_to_snapshot",
        "delete_automated_backups",
        "pending_modified_values_summary",
        "read_replica_source_present",
        "read_replica_count",
        "associated_roles_count",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # aws_rds_db_cluster — one record per RDS/Aurora DB cluster.
    "aws_rds_db_cluster": (
        "engine",
        "engine_version",
        "engine_major_version",
        "status",
        "storage_encrypted",
        "kms_key_id_present",
        "kms_key_id_hash",
        "deletion_protection",
        "backup_retention_period",
        "preferred_backup_window",
        "preferred_maintenance_window",
        "publicly_accessible",
        "availability_zone_count",
        "db_cluster_members_count",
        "writer_count",
        "reader_count",
        "endpoint_present",
        "reader_endpoint_present",
        "custom_endpoints_count",
        "port",
        "database_name_present",
        "master_username_present",
        "hosted_zone_id_present",
        "vpc_security_group_ids",
        "vpc_security_group_count",
        "db_subnet_group_name",
        "db_cluster_parameter_group",
        "iam_database_authentication_enabled",
        "enabled_cloudwatch_logs_exports",
        "copy_tags_to_snapshot",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # aws_rds_db_subnet_group — one record per RDS DB subnet group.
    "aws_rds_db_subnet_group": (
        "vpc_id",
        "subnet_count",
        "subnet_ids",
        "subnet_availability_zones",
        "status",
        "tag_keys",
        "config_fetch_warnings",
    ),
    # aws_rds_db_snapshot — one record per RDS DB snapshot (metadata only).
    "aws_rds_db_snapshot": (
        "snapshot_type",
        "engine",
        "engine_version",
        "storage_encrypted",
        "kms_key_id_present",
        "publicly_accessible",
        "status",
        "allocated_storage",
        "snapshot_create_time",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # aws_rds_db_cluster_snapshot — one record per RDS DB cluster snapshot.
    "aws_rds_db_cluster_snapshot": (
        "snapshot_type",
        "engine",
        "engine_version",
        "storage_encrypted",
        "kms_key_id_present",
        "publicly_accessible",
        "status",
        "allocated_storage",
        "snapshot_create_time",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # ── M43: Lambda + API Gateway Runtime/API Config ──────────────────────────
    # aws_lambda_function — one record per Lambda function.
    # Function code is NEVER accessed. Environment variable values are NEVER stored.
    # role/KMS/layer ARNs are hashed; env var keys-only are stored (never values).
    "aws_lambda_function": (
        "runtime",
        "handler_present",
        "package_type",
        "architectures",
        "memory_size",
        "timeout",
        "ephemeral_storage_size",
        "code_size",
        "last_modified",
        "version",
        "role_arn_present",
        "role_arn_hash",
        "kms_key_arn_present",
        "kms_key_arn_hash",
        "environment_key_count",
        "environment_key_names",
        "environment_sensitive_key_count",
        "vpc_config_present",
        "subnet_ids",
        "subnet_count",
        "security_group_ids",
        "security_group_count",
        "tracing_mode",
        "dead_letter_target_present",
        "dead_letter_target_type",
        "layers_count",
        "layer_arn_hashes",
        "reserved_concurrent_executions",
        "snap_start_apply_on",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # aws_lambda_alias — one record per Lambda alias.
    "aws_lambda_alias": (
        "function_version",
        "routing_config_present",
        "additional_version_weights_count",
        "additional_version_weights_summary",
        "description_present",
        "config_fetch_warnings",
    ),
    # aws_lambda_event_source_mapping — one record per event source mapping.
    # Event source ARN is hashed; filter expressions are never stored (presence only).
    "aws_lambda_event_source_mapping": (
        "function_name",
        "event_source_arn_present",
        "event_source_arn_hash",
        "event_source_type",
        "state",
        "enabled",
        "batch_size",
        "maximum_batching_window_seconds",
        "starting_position",
        "filter_criteria_present",
        "destination_config_present",
        "function_response_types",
        "config_fetch_warnings",
    ),
    # aws_lambda_function_url — one record per Lambda function URL config.
    # Full URL is never stored (hashed). CORS origins are never stored raw.
    "aws_lambda_function_url": (
        "auth_type",
        "invoke_mode",
        "cors_present",
        "cors_allow_credentials",
        "cors_wildcard_origin_present",
        "cors_allow_origins_count",
        "cors_allow_methods",
        "config_fetch_warnings",
    ),
    # aws_apigateway_rest_api — one record per API Gateway REST API.
    # Integration URIs are never stored raw (type counts only).
    # Stage variable values are never stored (keys only).
    "aws_apigateway_rest_api": (
        "name",
        "description_present",
        "endpoint_configuration_types",
        "disable_execute_api_endpoint",
        "minimum_compression_size",
        "api_key_source",
        "binary_media_types_count",
        "policy_summary",
        "authorizer_count",
        "resource_count",
        "method_count",
        "unauthenticated_method_count",
        "integration_type_counts",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # aws_apigateway_rest_stage — one record per REST API stage.
    "aws_apigateway_rest_stage": (
        "deployment_id_present",
        "deployment_id_hash",
        "cache_cluster_enabled",
        "cache_cluster_size",
        "tracing_enabled",
        "access_logging_enabled",
        "metrics_enabled_count",
        "logging_level_summary",
        "throttling_present",
        "variables_key_count",
        "variables_key_names",
        "canary_settings_present",
        "web_acl_arn_present",
        "config_fetch_warnings",
    ),
    # aws_apigatewayv2_api — one record per API Gateway V2 (HTTP/WebSocket) API.
    "aws_apigatewayv2_api": (
        "name",
        "protocol_type",
        "api_endpoint_present",
        "route_selection_expression_present",
        "disable_execute_api_endpoint",
        "cors_present",
        "cors_allow_credentials",
        "cors_wildcard_origin_present",
        "route_count",
        "unauthenticated_route_count",
        "authorizer_count",
        "integration_type_counts",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # aws_apigatewayv2_stage — one record per API Gateway V2 stage.
    "aws_apigatewayv2_stage": (
        "deployment_id_present",
        "deployment_id_hash",
        "auto_deploy",
        "access_logging_enabled",
        "detailed_metrics_enabled",
        "default_route_settings_summary",
        "stage_variables_key_count",
        "stage_variables_key_names",
        "config_fetch_warnings",
    ),
    # ── M44: Load Balancers + WAF Config ─────────────────────────────────────
    # aws_elbv2_load_balancer — one record per Application/Network/Gateway LB.
    # Access log objects are NEVER read. Request/response traffic is NEVER stored.
    # DNS name is hashed (never raw). Tag values are never stored.
    "aws_elbv2_load_balancer": (
        "type",
        "scheme",
        "state",
        "dns_name_hash",
        "hosted_zone_id_present",
        "vpc_id",
        "availability_zone_count",
        "subnet_ids",
        "subnet_count",
        "security_group_ids",
        "security_group_count",
        "ip_address_type",
        "deletion_protection_enabled",
        "access_logs_enabled",
        "access_logs_bucket_suffix",
        "idle_timeout_seconds",
        "routing_http2_enabled",
        "desync_mitigation_mode",
        "drop_invalid_header_fields_enabled",
        "preserve_host_header_enabled",
        "xff_header_processing_mode",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # aws_elbv2_target_group — one record per ELBv2 target group.
    "aws_elbv2_target_group": (
        "protocol",
        "port",
        "protocol_version",
        "target_type",
        "vpc_id",
        "health_check_enabled",
        "health_check_protocol",
        "health_check_port",
        "health_check_path_present",
        "health_check_interval_seconds",
        "health_check_timeout_seconds",
        "healthy_threshold_count",
        "unhealthy_threshold_count",
        "matcher_summary",
        "load_balancer_arn_count",
        "target_count",
        "healthy_target_count",
        "unhealthy_target_count",
        "deregistration_delay_seconds",
        "stickiness_enabled",
        "slow_start_duration_seconds",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # aws_elbv2_listener — one record per ELBv2 listener.
    # Request/response traffic is NEVER stored. SSL policies tracked by name only.
    "aws_elbv2_listener": (
        "load_balancer_arn_hash",
        "load_balancer_name",
        "port",
        "protocol",
        "ssl_policy",
        "certificate_count",
        "default_action_types",
        "default_target_group_arn_hashes",
        "auth_action_present",
        "redirect_action_present",
        "fixed_response_action_present",
        "config_fetch_warnings",
    ),
    # aws_elbv2_listener_rule — one record per ELBv2 listener rule.
    # Condition values (hostnames, paths, headers) are summarised by type presence only.
    "aws_elbv2_listener_rule": (
        "listener_arn_hash",
        "priority",
        "is_default",
        "condition_field_counts",
        "host_header_condition_present",
        "path_pattern_condition_present",
        "source_ip_condition_present",
        "http_header_condition_present",
        "query_string_condition_present",
        "action_types",
        "target_group_arn_hashes",
        "auth_action_present",
        "redirect_action_present",
        "fixed_response_action_present",
        "config_fetch_warnings",
    ),
    # aws_elb_classic_load_balancer — one record per Classic ELB.
    # Access log objects NEVER read. DNS name hashed, never raw.
    "aws_elb_classic_load_balancer": (
        "scheme",
        "dns_name_hash",
        "vpc_id",
        "subnet_ids",
        "security_group_ids",
        "listener_count",
        "listener_protocols",
        "availability_zone_count",
        "instance_count",
        "healthy_instance_count",
        "unhealthy_instance_count",
        "cross_zone_load_balancing_enabled",
        "access_logs_enabled",
        "connection_draining_enabled",
        "idle_timeout_seconds",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # aws_wafv2_web_acl — one per WAFv2 Web ACL.
    # Sampled requests are NEVER accessed. Rule bodies are summarised by count/type.
    "aws_wafv2_web_acl": (
        "scope",
        "description_present",
        "default_action",
        "rule_count",
        "managed_rule_group_count",
        "custom_rule_count",
        "rate_based_rule_count",
        "allow_action_count",
        "block_action_count",
        "count_action_count",
        "captcha_challenge_action_count",
        "override_count_action_count",
        "logging_enabled",
        "associated_resource_count",
        "associated_resource_arn_hashes",
        "tag_keys",
        "sensitive_name_category",
        "config_fetch_warnings",
    ),
    # aws_wafv2_web_acl_association — one per WAFv2 Web ACL ↔ resource link.
    "aws_wafv2_web_acl_association": (
        "web_acl_arn_hash",
        "web_acl_name",
        "resource_arn_hash",
        "resource_type",
        "scope",
    ),
}


def _tracked_fields_for(record: dict) -> tuple[str, ...]:
    """Return the tuple of field names to compare for *record*.

    Dispatches on ``record["record_type"]``:
    * Record types starting with ``"github_"`` look up in
      ``_GITHUB_TRACKED_FIELDS_BY_TYPE`` — unknown sub-types return ``()``
      (empty) so they never generate spurious modifications.
    * Record types starting with ``"vercel_"`` look up in
      ``_VERCEL_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"stripe_"`` look up in
      ``_STRIPE_TRACKED_FIELDS_BY_TYPE``.
    * All other records (Cloudflare DNS) use ``_TRACKED_FIELDS``.

    Args:
        record: A single record dict from a snapshot state list.

    Returns:
        Tuple of field name strings to compare field-by-field.
    """
    rt = record.get("record_type", "")
    if isinstance(rt, str) and rt.startswith("github_"):
        return _GITHUB_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("vercel_"):
        return _VERCEL_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("stripe_"):
        return _STRIPE_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("aws_"):
        return _AWS_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    return _TRACKED_FIELDS


# ─────────────────────────────────────────────────────────────────────────────
# Index builder
# ─────────────────────────────────────────────────────────────────────────────

def build_record_index(state: list[dict]) -> dict[str, dict]:
    """Return a mapping from stable record identifier → full record dict.

    Identifier priority (first non-empty value wins):
    1. ``external_id``  — used by future providers that expose their own ID
    2. ``id``           — generic fallback
    3. ``record_id``    — used by the Cloudflare connector (canonical field)

    Args:
        state: Normalised record list stored in ``Snapshot.state``.

    Returns:
        Dict keyed by the stable identifier string.

    Raises:
        ValueError: if any record has none of the recognised identifier fields.
    """
    index: dict[str, dict] = {}
    for record in state:
        key = (
            record.get("external_id")
            or record.get("id")
            or record.get("record_id")
        )
        if not key:
            raise ValueError(
                "Record has no stable identifier "
                "(expected 'external_id', 'id', or 'record_id'): "
                f"{record!r}"
            )
        index[str(key)] = record
    return index


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def format_record_identifier(record: dict) -> str:
    """Return a short human-readable label for *record*.

    Examples::

        "A api.example.com"
        "MX example.com"
        "CNAME checkout.example.com"
        "TXT _dmarc.example.com"

    Uses ``record_type`` (Cloudflare normalised field) or ``type`` (raw API
    field) as the type prefix.  Falls back gracefully if neither is present.
    """
    record_type = record.get("record_type") or record.get("type") or "UNKNOWN"
    name = record.get("name") or ""
    label = f"{record_type} {name}".strip()
    return label or "unknown record"


def _stable_id(record: dict) -> Optional[str]:
    """Extract the stable identifier from *record*, or ``None``."""
    key = (
        record.get("external_id")
        or record.get("id")
        or record.get("record_id")
    )
    return str(key) if key else None


def _build_provider_metadata(
    record: dict,
    alt_record: Optional[dict] = None,
) -> dict[str, Any]:
    """Build the ``provider_metadata`` payload stored on each Change row.

    Contains enough context for Milestone 10 risk rules and Milestone 11/15
    UI to classify and display changes without re-loading snapshot state.

    Args:
        record:     Primary record (prev for removed/modified; new for added).
        alt_record: Counterpart record, used for modified changes to include
                    the new record's content alongside the old one.
    """
    metadata: dict[str, Any] = {
        "record_id": _stable_id(record),
        "record_type": record.get("record_type") or record.get("type"),
        "record_name": record.get("name"),
        "record_content": record.get("content"),
    }
    if alt_record is not None:
        metadata["new_record_content"] = alt_record.get("content")
    return metadata


# ─────────────────────────────────────────────────────────────────────────────
# Diff computation — pure, no DB
# ─────────────────────────────────────────────────────────────────────────────

def compute_diff(
    prev_snapshot: Snapshot,
    new_snapshot: Snapshot,
) -> list[dict]:
    """Compare two snapshots and return a list of change dicts.

    This is a **pure function**: it reads ``Snapshot.state`` but never touches
    the database.  Pass the output to :func:`store_changes` to persist.

    Algorithm
    ---------
    1. Build keyed indexes for both snapshot states via :func:`build_record_index`.
    2. Added records  — keys present in ``new_index`` but not ``prev_index``.
    3. Removed records — keys present in ``prev_index`` but not ``new_index``.
    4. Modified records — keys in both indexes where any tracked field differs.
       One change dict is emitted **per changed field** (not per record).

    Volatile provider timestamps (``modified_on``, ``created_on``, etc.) are
    always excluded from comparison.  Only the fields in ``_TRACKED_FIELDS``
    are compared.

    Change dict keys
    ----------------
    ``change_type``       : ``"added"``, ``"removed"``, or ``"modified"``
    ``record_identifier`` : human-readable label, e.g. ``"A api.example.com"``
    ``field_path``        : field name for ``"modified"``; ``None`` otherwise
    ``prev_value``        : old value; ``None`` for ``"added"``
    ``new_value``         : new value; ``None`` for ``"removed"``
    ``provider_metadata`` : dict with record context for risk rules and UI

    Args:
        prev_snapshot: The earlier ``Snapshot`` (previous state).
        new_snapshot:  The later ``Snapshot`` (current state).

    Returns:
        List of change dicts.  Empty list when snapshots are identical.
    """
    prev_index = build_record_index(prev_snapshot.state or [])
    new_index = build_record_index(new_snapshot.state or [])

    changes: list[dict] = []

    # ── Added records ────────────────────────────────────────────────────────
    for key, new_record in new_index.items():
        if key not in prev_index:
            changes.append({
                "change_type": "added",
                "record_identifier": format_record_identifier(new_record),
                "field_path": None,
                "prev_value": None,
                "new_value": new_record,
                "provider_metadata": _build_provider_metadata(new_record),
            })
            logger.debug(
                "diff: added  id=%s  label=%r",
                key,
                format_record_identifier(new_record),
            )

    # ── Removed records ──────────────────────────────────────────────────────
    for key, prev_record in prev_index.items():
        if key not in new_index:
            changes.append({
                "change_type": "removed",
                "record_identifier": format_record_identifier(prev_record),
                "field_path": None,
                "prev_value": prev_record,
                "new_value": None,
                "provider_metadata": _build_provider_metadata(prev_record),
            })
            logger.debug(
                "diff: removed  id=%s  label=%r",
                key,
                format_record_identifier(prev_record),
            )

    # ── Modified records (field-level) ───────────────────────────────────────
    for key in sorted(prev_index.keys() & new_index.keys()):
        prev_record = prev_index[key]
        new_record = new_index[key]
        identifier = format_record_identifier(prev_record)

        for field in _tracked_fields_for(prev_record):
            prev_val = prev_record.get(field)
            new_val = new_record.get(field)
            if prev_val != new_val:
                changes.append({
                    "change_type": "modified",
                    "record_identifier": identifier,
                    "field_path": field,
                    "prev_value": prev_val,
                    "new_value": new_val,
                    "provider_metadata": _build_provider_metadata(
                        prev_record, new_record
                    ),
                })
                logger.debug(
                    "diff: modified  id=%s  field=%s  prev=%r  new=%r",
                    key,
                    field,
                    prev_val,
                    new_val,
                )

    logger.info(
        "compute_diff: %d change(s)  prev_snapshot=%s  new_snapshot=%s",
        len(changes),
        getattr(prev_snapshot, "id", "?"),
        getattr(new_snapshot, "id", "?"),
    )
    return changes


# ─────────────────────────────────────────────────────────────────────────────
# Persist changes — writes to DB
# ─────────────────────────────────────────────────────────────────────────────

def store_changes(
    *,
    resource_id: uuid.UUID,
    integration_id: uuid.UUID,
    user_id: uuid.UUID,
    prev_snapshot_id: uuid.UUID,
    new_snapshot_id: uuid.UUID,
    change_dicts: list[dict],
    db: Session,
) -> list[Change]:
    """Persist a list of change dicts as ``Change`` rows in the database.

    Each dict in *change_dicts* must contain the keys produced by
    :func:`compute_diff`.

    Transactional pattern:
        Calls ``db.flush()`` after adding all rows — consistent with
        ``store_snapshot``.  The caller (``sync_integration`` task) is
        responsible for ``db.commit()`` once all per-resource work is done.

    Risk classification:
        All rows are written with ``risk_level = "unknown"`` and
        ``risk_reason = None``.  Milestone 10's risk service will update
        these values.

    Args:
        resource_id:      UUID of the monitored resource.
        integration_id:   UUID of the parent integration (denormalised FK).
        user_id:          UUID of the owning user (denormalised FK).
        prev_snapshot_id: UUID of the earlier Snapshot.
        new_snapshot_id:  UUID of the newer Snapshot.
        change_dicts:     Output of :func:`compute_diff`.
        db:               Active SQLAlchemy session.

    Returns:
        List of persisted ``Change`` objects with populated ``id`` fields.
        Empty list when *change_dicts* is empty.
    """
    if not change_dicts:
        return []

    created: list[Change] = []
    for cd in change_dicts:
        change = Change(
            resource_id=resource_id,
            integration_id=integration_id,
            user_id=user_id,
            prev_snapshot_id=prev_snapshot_id,
            new_snapshot_id=new_snapshot_id,
            change_type=cd["change_type"],
            record_identifier=cd["record_identifier"],
            field_path=cd.get("field_path"),
            prev_value=cd.get("prev_value"),
            new_value=cd.get("new_value"),
            provider_metadata=cd.get("provider_metadata"),
            risk_level="unknown",      # Milestone 10 updates to real levels
            risk_reason=None,
        )
        db.add(change)
        created.append(change)

    db.flush()
    for change in created:
        db.refresh(change)

    logger.info(
        "store_changes: %d row(s) written  resource_id=%s",
        len(created),
        resource_id,
    )
    return created
