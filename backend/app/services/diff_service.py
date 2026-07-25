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
    # M57.9 — deploy hook metadata (hook url is NEVER stored — it's an auth token)
    "vercel_deploy_hook_metadata": (
        "hook_name",   # user-visible name change
        "hook_ref",    # target branch/ref change
    ),
    # Deployment protection posture — previously missing entirely, so
    # compute_diff never detected SSO/password/preview-protection drift even
    # though the connector's core fetch() path already emits this record and
    # risk_rules.vercel._classify_deployment_protection_change already
    # existed to classify it. Only the fields _extract_deployment_protection
    # actually populates are tracked here (the record's other TypedDict
    # fields — trusted_ips_count, protection_bypass_for_automation, etc. —
    # are not yet emitted by the connector, so tracking them would be inert).
    "vercel_deployment_protection": (
        "sso_enabled",
        "password_enabled",
        "preview_deployments_protected",
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
        "insecure_ssl_enabled",
    ),
    "github_actions_permissions": (
        "enabled",
        "allowed_actions",
        "default_workflow_permissions",
        "can_approve_pull_request_reviews",
    ),
    "github_deploy_key": (
        "title",
        "read_only",
        "verified",
    ),
    # M57.9 — deployment environment protection rules
    "github_environment_protection": (
        "environment_name",
        "wait_timer",
        "reviewers_count",
        "prevent_self_review",
        "protected_branches",
        "custom_branch_policies",
    ),
    "github_pages": (
        "pages_enabled",
        "pages_source_branch",
        "pages_source_path",
        "pages_build_type",
        "pages_cname_configured",
        "pages_https_enforced",
        "pages_visibility",
    ),
    # M69.5A — repository rulesets (modern branch protection). Only safe
    # aggregate fields emitted by the connector are tracked here.
    "github_ruleset": (
        "target",
        "enforcement",
        "branch_patterns_count",
        "targets_protected_branch",
        "bypass_actor_count",
        "required_status_checks_count",
        "restrict_force_pushes",
        "restrict_deletions",
        "required_pr_reviews_required",
        "require_signed_commits",
        "requires_linear_history",
        "requires_code_scanning",
    ),
    # M69.5B — automation credential / token permission posture.
    "github_automation_permissions": (
        "credential_type",
        "repository_permission_admin",
        "repository_permission_maintain",
        "repository_permission_push",
        "broad_permission_count",
        "token_broad_scopes",
        "token_scope_count",
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
    # M57.9 — Billing Portal configuration
    "stripe_billing_portal_config": (
        "active",
        "is_default",
        "login_page_enabled",
        "return_url_domain",
        "customer_update_enabled",
        "customer_update_allowed_updates",
        "invoice_history_enabled",
        "payment_method_update_enabled",
        "subscription_cancel_enabled",
        "subscription_cancel_mode",
        "subscription_cancel_reason_enabled",
        "subscription_update_enabled",
        "subscription_update_allowed_updates",
        "subscription_pause_enabled",
    ),
    # M73A — Payment Links. Only fields the connector actually populates are
    # tracked here; the schema also defines line_item_count/
    # line_item_price_ids/subscription_data_trial_period_days, which
    # risk_rules/stripe.py has classifier branches for but the connector's
    # _fetch_payment_links() never populates (line items aren't expanded) —
    # left untracked/GAP rather than invented.
    "stripe_payment_link": (
        "active",
        "allow_promotion_codes",
        "automatic_tax_enabled",
        "after_completion_type",
        "after_completion_redirect_origin",
        "success_url_origin",
        "customer_creation",
        "payment_method_collection",
        "payment_method_types_count",
        "application_fee_amount",
        "application_fee_percent",
    ),
}

# ── Cloudflare-specific tracked fields (M57.7) ────────────────────────────────

#: Per-record-type tracked field tuples for Cloudflare records other than bare
#: DNS records.  Bare DNS record types (A, AAAA, CNAME, …) still fall through
#: to the legacy ``_TRACKED_FIELDS`` tuple at the bottom of this module.
#:
#: SECURITY: rule expressions are NEVER stored, so they cannot appear here.
_CLOUDFLARE_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    # cloudflare_ruleset — one per WAF ruleset visible to the zone token.
    # Tracks structural changes (rule count deltas, default-action shifts)
    # that signal meaningful WAF posture changes.
    # ``last_updated`` is intentionally excluded — it updates even when only
    # metadata (e.g. description) changes, causing false-positive diff events.
    "cloudflare_ruleset": (
        "kind",
        "phase",
        "version",
        "rule_count",
        "enabled_rule_count",
        "block_count",
        "log_count",
        "skip_count",
        "challenge_count",
        "managed_challenge_count",
        "execute_count",
    ),
    # M59.5/M59.7 expansion surfaces — previously MISSING from this dict
    # entirely, so every one of these 7 record types silently fell back to
    # the DNS-record ``_TRACKED_FIELDS`` tuple below (record_type, name,
    # content, ttl, proxied, priority, comment) via the ``.get(rt,
    # _TRACKED_FIELDS)`` fallback in ``_tracked_fields_for()``. Since none of
    # these record types share that field shape (aside from incidental
    # overlaps like "name" or "priority"), compute_diff never detected real
    # drift for them — e.g. a zone's SSL mode going "strict" → "off", or a
    # WAF rule's action going "block" → "allow", produced ZERO Change rows,
    # even though risk_rules/cloudflare.py already had full classifier logic
    # for every one of these fields.
    "cloudflare_zone_setting": (
        "value",
        "editable",
    ),
    "cloudflare_page_rule": (
        "target_url_pattern",
        "actions_summary",
        "rule_kind",
        "priority",
        "status",
    ),
    "cloudflare_worker_route": (
        "pattern",
        "script_name",
        "enabled",
    ),
    "cloudflare_worker_script": (
        "script_etag",
        "env_var_count",
        "binding_count",
    ),
    "cloudflare_access_application": (
        "name",
        "type",
        "domain",
        "visibility",
        "enabled",
        "session_duration",
        "allowed_idps_count",
    ),
    "cloudflare_access_policy": (
        "name",
        "decision",
        "enabled",
        "precedence",
        "include_count",
        "exclude_count",
        "require_count",
    ),
    "cloudflare_waf_rule": (
        "description",
        "action",
        "enabled",
        "expression_hash",
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
    # ── M45: CloudTrail + GuardDuty + Security Hub Posture ────────────────────
    # aws_cloudtrail_trail — one per CloudTrail trail (one per home region).
    # CloudTrail events/log objects are NEVER read. Selectors summarized by type/count.
    "aws_cloudtrail_trail": (
        # "trail_name" is not tracked — trail identity is via record_id (hashed ARN);
        # renames cause remove+add events, not field modifications.
        "home_region",
        "is_multi_region_trail",
        "include_global_service_events",
        "is_organization_trail",
        "log_file_validation_enabled",
        "kms_key_id_present",
        "kms_key_id_hash",
        "s3_bucket_name_hash",
        "sns_topic_name_present",
        "cloud_watch_logs_enabled",
        "has_custom_event_selectors",
        "is_logging",
        "latest_delivery_error_present",
        "latest_notification_error_present",
        "management_events_enabled",
        "read_write_type",
        "include_management_events",
        "data_resource_type_counts",
        "exclude_management_event_sources_count",
        "insight_selector_count",
        "insight_selector_types",
        "tag_keys",
        "config_fetch_warnings",
    ),
    # aws_cloudtrail_event_data_store — one per CloudTrail event data store.
    # Events NEVER read; only posture metadata tracked.
    "aws_cloudtrail_event_data_store": (
        "name",
        "status",
        "termination_protection_enabled",
        "multi_region_enabled",
        "organization_enabled",
        "retention_period",
        "advanced_event_selector_count",
        "kms_key_id_present",
        "billing_mode",
        "tag_keys",
        "config_fetch_warnings",
    ),
    # aws_guardduty_detector — one per GuardDuty detector (per region).
    # GuardDuty findings NEVER accessed; only posture metadata tracked.
    "aws_guardduty_detector": (
        "status",
        "finding_publishing_frequency",
        "s3_logs_enabled",
        "eks_audit_logs_enabled",
        "malware_protection_enabled",
        "rds_login_events_enabled",
        "lambda_network_logs_enabled",
        "runtime_monitoring_enabled",
        "ebs_malware_protection_enabled",
        "feature_count",
        "member_count",
        "active_member_count",
        "admin_account_present",
        "tag_keys",
        "config_fetch_warnings",
    ),
    # aws_guardduty_publishing_destination — one per destination per detector.
    "aws_guardduty_publishing_destination": (
        "destination_type",
        "status",
        "kms_key_arn_present",
        "destination_arn_present",
        "config_fetch_warnings",
    ),
    # aws_securityhub_account — one per Security Hub account/region posture.
    # Security Hub findings NEVER accessed; only posture/standards metadata.
    "aws_securityhub_account": (
        "hub_enabled",
        "auto_enable_controls",
        "control_finding_generator",
        "enabled_standards_count",
        "enabled_products_count",
        "finding_aggregator_present",
        "tag_keys",
        "config_fetch_warnings",
    ),
    # aws_securityhub_standard_subscription — one per enabled Security Hub standard.
    "aws_securityhub_standard_subscription": (
        "standards_status",
        "standards_status_reason",
        "standards_name_summary",
        "config_fetch_warnings",
    ),
    # aws_securityhub_finding_aggregator — one per Security Hub finding aggregator.
    "aws_securityhub_finding_aggregator": (
        "linking_mode",
        "specified_regions_count",
        "specified_regions",
        "config_fetch_warnings",
    ),

    # ── M46: ECS / EKS / ECR ─────────────────────────────────────────────────

    # aws_ecs_cluster — one per ECS cluster per region.
    # SECURITY: task logs, env values, secret values NEVER tracked.
    "aws_ecs_cluster": (
        "status",
        "registered_container_instance_count",
        "running_tasks_count",
        "pending_tasks_count",
        "active_services_count",
        "capacity_providers",
        "default_capacity_provider_strategy_count",
        "has_fargate_capacity",
        "container_insights_enabled",
        "name_sensitivity",
        "tag_keys",
    ),

    # aws_ecs_service — one per ECS service per cluster per region.
    # SECURITY: env values NEVER tracked; task definition ARN stored as hash only.
    "aws_ecs_service": (
        "status",
        "launch_type",
        "scheduling_strategy",
        "desired_count",
        "running_count",
        "has_public_ip",
        "lb_count",
        "lb_target_group_arn_hashes",
        "task_definition_arn_hash",
        "deployment_count",
        "circuit_breaker_enabled",
        "circuit_breaker_rollback",
        "service_connect_enabled",
        "name_sensitivity",
        "tag_keys",
    ),

    # aws_ecs_task_definition — one per task definition revision per region.
    # SECURITY: env values NEVER tracked; secret ARNs NEVER stored; count only.
    "aws_ecs_task_definition": (
        "status",
        "network_mode",
        "requires_compatibilities",
        "cpu",
        "memory",
        "task_role_arn_hash",
        "execution_role_arn_hash",
        "container_count",
        "volume_count",
        "has_efs_volume",
        "env_key_count",
        "env_sensitive_key_count",
        "secret_ref_count",
        "has_privileged_container",
        "any_readonly_root_filesystem",
        "log_driver_types",
        "name_sensitivity",
        "tag_keys",
    ),

    # aws_eks_cluster — one per EKS cluster per region.
    # SECURITY: Kubernetes API never called; no pod/secret/configmap data tracked.
    "aws_eks_cluster": (
        "status",
        "kubernetes_version",
        "platform_version",
        "role_arn_hash",
        "endpoint_public_access",
        "endpoint_private_access",
        "public_access_fully_open",
        "public_access_cidrs_count",
        "subnet_count",
        "security_group_count",
        "ip_family",
        "enabled_log_types",
        "has_audit_logging",
        "secrets_encryption_enabled",
        "kms_key_hash",
        "name_sensitivity",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_eks_node_group — one per node group per cluster.
    "aws_eks_node_group": (
        "status",
        "capacity_type",
        "ami_type",
        "instance_types",
        "disk_size",
        "min_size",
        "max_size",
        "desired_size",
        "node_role_arn_hash",
        "has_remote_access",
        "ssh_unrestricted",
        "source_security_group_count",
        "tag_keys",
    ),

    # aws_eks_fargate_profile — one per Fargate profile per cluster.
    "aws_eks_fargate_profile": (
        "status",
        "pod_execution_role_arn_hash",
        "selector_count",
        "selector_namespaces",
        "subnet_count",
        "tag_keys",
    ),

    # aws_eks_addon — one per EKS add-on per cluster.
    "aws_eks_addon": (
        "status",
        "addon_version",
        "service_account_role_hash",
        "tag_keys",
    ),

    # aws_ecr_repository — one per ECR repository per region.
    # SECURITY: images never pulled; raw policy JSON never stored; tag values never stored.
    "aws_ecr_repository": (
        "image_tag_mutability",
        "tag_immutable",
        "scan_on_push",
        "encryption_type",
        "kms_key_hash",
        "policy_present",
        "policy_is_public",
        "lifecycle_policy_present",
        "lifecycle_rule_count",
        "name_sensitivity",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_ecr_registry_scanning_config — one per region.
    "aws_ecr_registry_scanning_config": (
        "scan_type",
        "rule_count",
        "repo_filter_count",
        "scan_frequency_types",
    ),

    # ── M47: EventBridge / SQS / SNS ─────────────────────────────────────────

    # aws_eventbridge_event_bus — one per EventBridge event bus per region.
    # SECURITY: event payloads NEVER tracked. events:PutEvents NEVER called.
    "aws_eventbridge_event_bus": (
        "policy_present",
        "public_or_cross_account_policy",
        "name_sensitivity",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_eventbridge_rule — one per rule per bus per region.
    # SECURITY: raw event patterns NEVER tracked — hash only.
    "aws_eventbridge_rule": (
        "state",
        "schedule_expression_present",
        "event_pattern_present",
        "event_pattern_hash",
        "target_count",
        "target_type_counts",
        "dlq_target_present",
        "retry_policy_present",
        "name_sensitivity",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_eventbridge_target — one per target per rule per bus per region.
    # SECURITY: target ARNs stored as hashes only. Raw input/event data NEVER stored.
    "aws_eventbridge_target": (
        "target_type",
        "target_arn_hash",
        "role_arn_present",
        "role_arn_hash",
        "dead_letter_config_present",
        "dead_letter_arn_hash",
        "retry_policy_present",
        "retry_max_event_age_seconds",
        "retry_max_attempts",
        "input_transformer_present",
        "input_path_present",
        "input_present",
        "config_fetch_warnings",
    ),

    # aws_eventbridge_archive — one per archive per region.
    # SECURITY: archived event contents NEVER read or stored.
    "aws_eventbridge_archive": (
        "state",
        "retention_days",
        "event_count",
        "size_bytes",
        "config_fetch_warnings",
    ),

    # aws_sqs_queue — one per SQS queue per region.
    # SECURITY: message bodies and queue contents NEVER tracked.
    # sqs:ReceiveMessage/SendMessage/DeleteMessage/PurgeQueue NEVER called.
    "aws_sqs_queue": (
        "fifo_queue",
        "content_based_deduplication",
        "sqs_managed_sse_enabled",
        "kms_master_key_id_present",
        "kms_master_key_id_hash",
        "visibility_timeout",
        "message_retention_period",
        "delay_seconds",
        "maximum_message_size",
        "long_polling_wait_time_seconds",
        "redrive_policy_present",
        "dead_letter_target_arn_hash",
        "max_receive_count",
        "redrive_allow_policy_summary",
        "policy_present",
        "public_or_cross_account_policy",
        "approximate_number_of_messages",
        "approximate_number_of_messages_not_visible",
        "approximate_number_of_messages_delayed",
        "name_sensitivity",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_sns_topic — one per SNS topic per region.
    # SECURITY: notification contents NEVER tracked. sns:Publish NEVER called.
    "aws_sns_topic": (
        "fifo_topic",
        "content_based_deduplication",
        "kms_master_key_id_present",
        "kms_master_key_id_hash",
        "delivery_policy_present",
        "effective_delivery_policy_present",
        "policy_present",
        "public_or_cross_account_policy",
        "subscription_count",
        "confirmed_subscription_count",
        "pending_subscription_count",
        "subscription_protocol_counts",
        "name_sensitivity",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_sns_subscription — one per subscription per topic per region.
    # SECURITY: endpoint raw values NEVER stored — hash only.
    "aws_sns_subscription": (
        "protocol",
        "endpoint_hash",
        "endpoint_type",
        "confirmation_was_authenticated",
        "pending_confirmation",
        "raw_message_delivery",
        "filter_policy_present",
        "filter_policy_hash",
        "redrive_policy_present",
        "delivery_policy_present",
        "config_fetch_warnings",
    ),

    # ── M48: KMS / Backup / Organizations ────────────────────────────────────

    # aws_kms_key — one per KMS key per region.
    # SECURITY: cryptographic operations (Decrypt/Encrypt/GenerateDataKey) NEVER tracked.
    "aws_kms_key": (
        "key_state",
        "enabled",
        "key_usage",
        "key_spec",
        "key_manager",
        "origin",
        "multi_region",
        "deletion_date_present",
        "valid_to_present",
        "rotation_enabled",
        "policy_present",
        "public_or_cross_account_policy",
        "wildcard_admin_policy",
        "name_sensitivity",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_kms_alias — one per KMS alias per region.
    "aws_kms_alias": (
        "alias_name",
        "target_key_id_hash",
        "target_key_present",
        "config_fetch_warnings",
    ),

    # aws_backup_vault — one per AWS Backup vault per region.
    # SECURITY: backup contents NEVER tracked. Restore/start/delete ops NEVER called.
    "aws_backup_vault": (
        "encryption_key_arn_present",
        "encryption_key_arn_hash",
        "locked",
        "min_retention_days",
        "max_retention_days",
        "recovery_points_count",
        "backup_vault_lock_configuration_present",
        "name_sensitivity",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_backup_plan — one per AWS Backup plan per region.
    "aws_backup_plan": (
        "backup_plan_name",
        "rule_count",
        "rule_names",
        "target_vault_names",
        "schedule_expression_present_count",
        "continuous_backup_enabled_count",
        "lifecycle_delete_after_days_min",
        "lifecycle_delete_after_days_max",
        "lifecycle_move_to_cold_after_days_min",
        "lifecycle_move_to_cold_after_days_max",
        "copy_action_count",
        "name_sensitivity",
        "config_fetch_warnings",
    ),

    # aws_backup_selection — one per selection per plan.
    "aws_backup_selection": (
        "selection_name",
        "iam_role_arn_present",
        "iam_role_arn_hash",
        "resource_count",
        "resource_type_counts",
        "condition_count",
        "list_of_tags_count",
        "not_resources_count",
        "config_fetch_warnings",
    ),

    # aws_backup_recovery_point — one per recovery point per vault.
    # SECURITY: backup contents NEVER read or restored.
    "aws_backup_recovery_point": (
        "backup_vault_name",
        "resource_type",
        "status",
        "creation_date_present",
        "completion_date_present",
        "lifecycle_present",
        "calculated_lifecycle_delete_at_present",
        "encryption_key_arn_present",
        "encryption_key_arn_hash",
        "is_encrypted",
        "size_bytes",
        "config_fetch_warnings",
    ),

    # aws_organizations_organization — one per AWS Organization.
    # SECURITY: org structure/SCPs NEVER mutated.
    "aws_organizations_organization": (
        "feature_set",
        "root_count",
        "account_count",
        "ou_count",
        "scp_count",
        "policy_types_summary",
        "config_fetch_warnings",
    ),

    # aws_organizations_account — one per member account.
    # SECURITY: raw account email NEVER stored — hash only.
    "aws_organizations_account": (
        "status",
        "joined_method",
        "joined_timestamp_present",
        "config_fetch_warnings",
    ),

    # aws_organizations_ou — one per Organizational Unit.
    "aws_organizations_ou": (
        "parent_id_hash",
        "child_ou_count",
        "child_account_count",
        "attached_scp_count",
        "config_fetch_warnings",
    ),

    # aws_organizations_scp — one per Service Control Policy.
    # SECURITY: raw SCP content NEVER stored — summary only. SCPs NEVER mutated.
    "aws_organizations_scp": (
        "policy_name",
        "aws_managed",
        "description_present",
        "allow_statement_count",
        "deny_statement_count",
        "denied_action_count",
        "denied_service_prefixes",
        "wildcard_action_present",
        "wildcard_resource_present",
        "denies_full_admin_escape",
        "attached_target_count",
        "attached_target_type_counts",
        "name_sensitivity",
        "config_fetch_warnings",
    ),

    # aws_organizations_scp_attachment — one per SCP-to-target attachment.
    "aws_organizations_scp_attachment": (
        "policy_name",
        "target_type",
        "config_fetch_warnings",
    ),

    # ── M49: CloudWatch Alarms + Observability Config ─────────────────────────

    # aws_cloudwatch_metric_alarm — one per CloudWatch metric alarm per region.
    # SECURITY: metric datapoints NEVER read; cloudwatch:GetMetricData NEVER called.
    "aws_cloudwatch_metric_alarm": (
        "alarm_state_reason_absent",
        "alarm_state_value",
        "actions_enabled",
        "alarm_action_count",
        "ok_action_count",
        "insufficient_data_action_count",
        "alarm_action_type_counts",
        "ok_action_type_counts",
        "insufficient_data_action_type_counts",
        "namespace",
        "metric_name",
        "statistic",
        "extended_statistic_present",
        "period",
        "comparison_operator",
        "threshold",
        "evaluation_periods",
        "datapoints_to_alarm",
        "treat_missing_data",
        "dimension_key_names",
        "metrics_present",
        "name_sensitivity",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_cloudwatch_composite_alarm — one per CloudWatch composite alarm per region.
    # SECURITY: metric datapoints NEVER read.
    "aws_cloudwatch_composite_alarm": (
        "alarm_state_value",
        "alarm_state_reason_absent",
        "actions_enabled",
        "alarm_rule_present",
        "alarm_rule_hash",
        "alarm_rule_component_count",
        "alarm_action_count",
        "ok_action_count",
        "insufficient_data_action_count",
        "alarm_action_type_counts",
        "ok_action_type_counts",
        "insufficient_data_action_type_counts",
        "name_sensitivity",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_cloudwatch_dashboard — one per CloudWatch dashboard per region.
    # SECURITY: dashboard body NEVER stored in plaintext — hash only.
    "aws_cloudwatch_dashboard": (
        "dashboard_body_hash",
        "widget_count",
        "widget_type_counts",
        "config_fetch_warnings",
    ),

    # aws_cloudwatch_log_group — one per CloudWatch Logs log group per region.
    # SECURITY: log events NEVER read; logs:GetLogEvents/FilterLogEvents/StartQuery NEVER called.
    "aws_cloudwatch_log_group": (
        "retention_in_days",
        "retention_configured",
        "kms_key_id_present",
        "kms_key_id_hash",
        "stored_bytes",
        "metric_filter_count",
        "subscription_filter_count",
        "name_sensitivity",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_cloudwatch_metric_filter — one per CloudWatch Logs metric filter per log group.
    # SECURITY: filter patterns NEVER stored in plaintext — hash only.
    "aws_cloudwatch_metric_filter": (
        "filter_pattern_present",
        "filter_pattern_hash",
        "filter_pattern_length",
        "metric_name",
        "metric_namespace",
        "metric_transformation_count",
        "default_value_present",
        "unit_present",
        "config_fetch_warnings",
    ),

    # aws_cloudwatch_subscription_filter — one per CloudWatch Logs subscription filter per log group.
    # SECURITY: destination ARN hashed; role ARN hashed; log events NEVER read.
    "aws_cloudwatch_subscription_filter": (
        "filter_pattern_present",
        "filter_pattern_hash",
        "filter_pattern_length",
        "destination_type",
        "destination_arn_hash",
        "role_arn_present",
        "role_arn_hash",
        "distribution",
        "config_fetch_warnings",
    ),

    # aws_cloudwatch_metric_stream — one per CloudWatch metric stream per region.
    # SECURITY: metric datapoints NEVER read; firehose/role ARNs hashed only.
    "aws_cloudwatch_metric_stream": (
        "state",
        "output_format",
        "firehose_arn_hash",
        "role_arn_hash",
        "include_filter_count",
        "exclude_filter_count",
        "statistics_configuration_count",
        "tag_keys",
        "config_fetch_warnings",
    ),

    # aws_cloudwatch_anomaly_detector — one per anomaly detector per namespace/metric.
    # SECURITY: anomaly evaluation results NEVER read.
    "aws_cloudwatch_anomaly_detector": (
        "namespace",
        "metric_name",
        "dimension_key_names",
        "stat",
        "state",
        "configuration_excluded_time_ranges_count",
        "configuration_metric_timezone_present",
        "config_fetch_warnings",
    ),
    # ── M59.8/M59.9 — schema + classifier defined ahead of connector fetch ──
    # These 8 record types have full risk_rules/aws.py classifiers and
    # security_rules coverage, but AWSConnector.fetch() does not yet emit
    # them (no boto3 call wired up). Tracked fields are added here so that
    # IF a future connector change starts emitting these types, drift
    # detection works immediately without a second fix pass — today, no
    # records of these types exist in any snapshot, so these entries are
    # inert.
    "aws_ec2_instance": (
        "public_ip_address",
        "in_public_subnet",
        "source_dest_check",
        "imds_http_endpoint",
        "imds_http_tokens",
        "tags",
    ),
    "aws_vpc_flow_log": (
        "flow_log_status",
        "traffic_type",
        "max_aggregation_interval",
    ),
    "aws_config_recorder": (
        "recording",
        "records_global_resources",
        "resource_types_count",
    ),
    "aws_config_delivery_channel": (
        "s3_bucket_name",
        "sns_topic_arn",
        "s3_kms_key_id",
    ),
    "aws_access_analyzer": (
        "status",
        "type",
    ),
    "aws_access_analyzer_finding": (
        "status",
    ),
    "aws_securityhub_finding": (
        "severity",
        "workflow_status",
        "record_state",
    ),
    "aws_acm_certificate": (
        "status",
        "days_to_expiry",
        "domain_name",
        "subject_alternative_names_count",
        "key_algorithm",
    ),
}


# ── Firebase-specific tracked fields (M53) ────────────────────────────────────

_FIREBASE_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "firebase_project": (
        "display_name",
        "lifecycle_state",
        "hosting_site",
        "has_realtime_db",
        "has_storage",
        "config_fetch_warnings",
    ),
    "firebase_auth_config": (
        "sign_in_email_enabled",
        "sign_in_phone_enabled",
        "anonymous_enabled",
        "mfa_enabled",
        "mfa_state",
        "authorized_domain_count",
        "saml_provider_count",
        "oidc_provider_count",
        "config_fetch_warnings",
    ),
    "firebase_auth_provider": (
        "enabled",
        "provider_type",
        "config_fetch_warnings",
    ),
    "firebase_authorized_domain": (
        "domain",
        "is_localhost",
        "is_default_firebase_domain",
        "config_fetch_warnings",
    ),
    "firebase_firestore_ruleset": (
        "release_name",
        "ruleset_name_hash",
        "rules_hash",
        "public_read_detected",
        "public_write_detected",
        "authenticated_only_detected",
        "rule_summary",
        "parser_confidence",
        "config_fetch_warnings",
    ),
    # M72A — Realtime Database rules. Live, connector-emitted since M72A and
    # fully evaluated by security_rules/firebase.py's _eval_database_ruleset
    # (firebase_database_public_read / firebase_database_public_write), but
    # had NO entry here at all — compute_diff() never detected a public-read/
    # public-write transition on this record type as a Change.
    "firebase_database_ruleset": (
        "service",
        "instance_name_hash",
        "rules_hash",
        "public_read_detected",
        "public_write_detected",
        "authenticated_only_detected",
        "rule_summary",
        "parser_confidence",
        "config_fetch_warnings",
    ),
    "firebase_storage_bucket": (
        "location",
        "storage_class",
        "uniform_bucket_level_access",
        "public_access_prevention",
        "versioning_enabled",
        "config_fetch_warnings",
    ),
    "firebase_storage_ruleset": (
        "release_name",
        "ruleset_name_hash",
        "rules_hash",
        "public_read_detected",
        "public_write_detected",
        "authenticated_only_detected",
        "rule_summary",
        "parser_confidence",
        "config_fetch_warnings",
    ),
    "firebase_hosting_site": (
        "default_url",
        "app_id",
        "custom_domain_count",
        "config_fetch_warnings",
    ),
    "firebase_hosting_domain": (
        "domain_type",
        "status",
        "config_fetch_warnings",
    ),
    "firebase_function_metadata": (
        "runtime",
        "trigger_type",
        "status",
        "env_var_key_count",
        "config_fetch_warnings",
    ),
    # ── M57.8: Remote Config + App Check ─────────────────────────────────────
    # firebase_remote_config_template — one per Firebase project.
    # Tracks structural drift (parameter/condition counts, version, hash changes).
    # Parameter values and condition expressions are NEVER stored.
    "firebase_remote_config_template": (
        "version_number",
        "update_origin",
        "update_type",
        "parameter_count",
        "condition_count",
        "parameter_group_count",
        "parameter_keys_hash",
        "condition_names_hash",
        "config_fetch_warnings",
    ),
    # firebase_app_check_config — one per Firebase project.
    # Tracks App Check enforcement posture changes across protected services.
    # Debug tokens and attestation data are NEVER stored.
    "firebase_app_check_config": (
        "service_count",
        "enforced_service_count",
        "unenforced_service_count",
        "enforced_service_names",
        "config_fetch_warnings",
    ),
}


# ── Supabase-specific tracked fields (M54) ────────────────────────────────────

_SUPABASE_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "supabase_project": (
        "name",
        "region",
        "cloud_provider",
        "status",
        "plan_id",
        "has_custom_domain",
        "config_fetch_warnings",
    ),
    "supabase_auth_config": (
        "email_enabled",
        "phone_enabled",
        "anonymous_enabled",
        "mfa_totp_enabled",
        "session_timebox_seconds",
        "session_inactivity_timeout_seconds",
        "oauth_provider_count",
        "password_min_length",
        "site_url",
        "max_request_users_per_day",
        # M57.8: additional security depth fields
        "leaked_password_protection_enabled",
        "captcha_enabled",
        "require_reauthentication_for_password_update",
        "refresh_token_rotation_enabled",
        "jwt_exp",
        "additional_redirect_urls_count",
        "config_fetch_warnings",
    ),
    "supabase_database_config": (
        "pool_mode",
        "pool_size",
        "default_pool_size",
        "max_client_conn",
        "postgres_version",
        "config_fetch_warnings",
    ),
    "supabase_storage_config": (
        "file_size_limit",
        "allowed_mime_types",
        "s3_protocol_enabled",
        "config_fetch_warnings",
    ),
    "supabase_edge_function": (
        "status",
        "version",
        "env_var_key_count",
        "verify_jwt",
        "config_fetch_warnings",
    ),
    "supabase_rls_status": (
        "rls_enabled",
        "rls_forced",
        # M71A — per-table public-policy posture (pg_policies metadata only).
        # These are emitted by the connector (merged from
        # _fetch_database_policies) and evaluated by the
        # supabase_public_select_sensitive_table / supabase_public_write_policy
        # Security Findings, but were missing here entirely — compute_diff()
        # never detected a table gaining/losing a public policy as a Change,
        # only whole-table add/remove and the rls_enabled/rls_forced flags.
        "policy_count",
        "has_public_select_policy",
        "has_public_insert_policy",
        "has_public_update_policy",
        "has_public_delete_policy",
        "exposed_to_anon",
        "config_fetch_warnings",
    ),
    "supabase_api_config": (
        "db_schema",
        "db_extra_search_path",
        "max_rows",
        "config_fetch_warnings",
    ),
    "supabase_network_restriction": (
        "cidr",
        "is_unrestricted",
        "config_fetch_warnings",
    ),
    "supabase_custom_domain": (
        "custom_domain",
        "status",
        "config_fetch_warnings",
    ),
    "supabase_oauth_provider": (
        "enabled",
        "client_id_hash",
        "config_fetch_warnings",
    ),
}



# ── Shopify-specific tracked fields (M57.5) ───────────────────────────────────

_SHOPIFY_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "shopify_shop_metadata": (
        # Identity / display
        "shop_name",
        # Plan / subscription
        "plan_name",
        "plan_display_name",
        # Regional / locale
        "timezone",
        "iana_timezone",
        "currency",
        "primary_locale",
        "country_code",
        # Security / access flags
        "password_enabled",       # storefront password protection
        "checkout_api_supported",
        "has_storefront",
        "eligible_for_payments",
        "requires_extra_payments_agreement",
        # Tax
        "taxes_included",
        "tax_shipping",
    ),
    "shopify_webhook_subscription": (
        # Topic — what event type is being delivered
        "topic",
        # Endpoint — decomposed (full URL never stored)
        "endpoint_domain",
        "endpoint_scheme",
        "endpoint_path_hash",
        "endpoint_path_length",
        "is_https",
        # Configuration
        "format",
        "api_version",
    ),
    "shopify_store_policy": (
        "policy_type",
        "present",
        "body_hash",      # SHA-256 of policy body — change detection only
        "body_length",    # byte length — raw text never stored
    ),
    # M57.9 — access scope summary
    "shopify_app_scope_summary": (
        "scope_count",
        "write_scope_count",
        "sensitive_scope_count",
        "customer_scope_present",
        "order_scope_present",
        "payment_scope_present",
        "scope_hash",
        "scope_names",
    ),
    # M74A — shop domain posture (previously missing entirely: domain SSL/
    # verification/primary drift was never tracked as a Change, even though
    # the corresponding Security Findings already evaluate the current state).
    "shopify_domain": (
        "host",
        "ssl_enabled",
        "primary",
        "verified",
        "managed_by_shopify",
    ),
}


# ── SendGrid-specific tracked fields ──────────────────────────────────────────

#: Per-record-type tracked field tuples for SendGrid records (M80A+).
#: Only the fields listed here are compared field-by-field in compute_diff.
#: Identity fields (record_id, record_type, provider_resource_id, and each
#: record's own opaque id field) are intentionally excluded — they never
#: change without the record itself being replaced (added/removed).
_SENDGRID_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "sendgrid_account": (
        "account_type",
        "reputation",
    ),
    "sendgrid_api_key": (
        "name",
        "scopes_count",
        "has_mail_send",
        "has_full_access",
    ),
    "sendgrid_sender_identity": (
        "nickname",
        "from_email_domain",
        "reply_to_domain",
        "verified",
        "locked",
    ),
    "sendgrid_domain_authentication": (
        "domain",
        "valid",
        "automatic_security",
        "default",
        "legacy",
        "dns_record_count",
    ),
    "sendgrid_mail_settings": (
        "bcc_enabled",
        "bounce_purge_enabled",
        "footer_enabled",
        "forward_bounce_enabled",
        "forward_spam_enabled",
        "sandbox_mode_enabled",
        "spam_check_enabled",
        "template_enabled",
    ),
    "sendgrid_tracking_settings": (
        "click_tracking_enabled",
        "open_tracking_enabled",
        "subscription_tracking_enabled",
        "ganalytics_enabled",
    ),
    "sendgrid_webhook_settings": (
        "event_webhook_enabled",
        "event_webhook_has_url",
        "event_webhook_signed",
        "event_count",
        "inbound_parse_enabled",
        "inbound_parse_spam_check_enabled",
        "inbound_parse_send_raw_enabled",
    ),
    "sendgrid_suppression_settings": (
        "suppression_group_count",
    ),
}


# ── Twilio-specific tracked fields ────────────────────────────────────────────

#: Per-record-type tracked field tuples for Twilio records (M79A+).
#: Only the fields listed here are compared field-by-field in compute_diff.
#: Identity fields (record_id, record_type, provider_resource_id, and each
#: record's own opaque SID field) are intentionally excluded — they never
#: change without the record itself being replaced (added/removed).
_TWILIO_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "twilio_account": (
        "friendly_name",
        "status",
        "account_type",
        "subaccount_count",
    ),
    "twilio_incoming_phone_number": (
        "friendly_name",
        "phone_number_last4",
        "iso_country",
        "capability_voice",
        "capability_sms",
        "capability_mms",
        "capability_fax",
        "sms_url_configured",
        "voice_url_configured",
        "status_callback_configured",
        "sms_url_scheme",
        "voice_url_scheme",
        "status_callback_scheme",
        "address_requirements",
        "emergency_status",
    ),
    "twilio_messaging_service": (
        "friendly_name",
        "inbound_request_url_configured",
        "fallback_url_configured",
        "status_callback_url_configured",
        "inbound_request_url_scheme",
        "fallback_url_scheme",
        "status_callback_url_scheme",
        "smart_encoding",
        "validity_period",
        "area_code_geomatch",
        "sticky_sender",
        "mms_converter",
        "use_inbound_webhook_on_number",
        "number_count",
    ),
    "twilio_verify_service": (
        "friendly_name",
        "code_length",
        "lookup_enabled",
        "psd2_enabled",
        "do_not_share_warning_enabled",
        "skip_sms_to_landlines",
        "default_template_sid_present",
    ),
    "twilio_api_key_summary": (
        "friendly_name",
        "date_created",
        "date_updated",
    ),
}


# ── Terraform Cloud-specific tracked fields ───────────────────────────────────

#: Per-record-type tracked field tuples for Terraform Cloud records (M88A+).
#: Only the fields listed here are compared field-by-field in compute_diff.
#: Identity fields (record_type, record_id, resource_id, provider, and each
#: record's own opaque "*_resource_id" foreign-key fields) are intentionally
#: excluded — they never change without the record itself being replaced
#: (added/removed).
_TERRAFORM_CLOUD_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "terraform_cloud_organization": (
        "workspace_count",
        "project_count",
        "policy_set_count",
        "variable_set_count",
        "team_count_category",
        "sso_enabled",
        "two_factor_requirement_enabled",
        "cost_estimation_enabled",
        "collaborator_auth_policy_category",
    ),
    "terraform_cloud_workspace": (
        "execution_mode_category",
        "terraform_version_category",
        "auto_apply",
        "file_triggers_enabled",
        "queue_all_runs",
        "speculative_enabled",
        "global_remote_state",
        "vcs_connected",
        "working_directory_present",
        "trigger_prefix_count",
        "run_trigger_count",
        "variable_count",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
        "environment_variable_count",
        "terraform_variable_count",
        "notification_count",
        "team_access_count",
        "current_state_version_present",
        "latest_run_status_category",
    ),
    "terraform_cloud_project": (
        "workspace_count",
        "team_access_count",
    ),
    "terraform_cloud_variable_set": (
        "global_scope",
        "workspace_count",
        "project_count",
        "variable_count",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
        "environment_variable_count",
        "terraform_variable_count",
    ),
    "terraform_cloud_workspace_variable_summary": (
        "variable_count",
        "sensitive_variable_count",
        "non_sensitive_variable_count",
        "environment_variable_count",
        "terraform_variable_count",
        "unprotected_non_sensitive_count",
    ),
    "terraform_cloud_policy_set": (
        "global_scope",
        "workspace_count",
        "project_count",
        "policy_count",
        "enforcement_level_category",
        "vcs_connected",
    ),
    "terraform_cloud_notification_configuration": (
        "enabled",
        "destination_type_category",
        "trigger_count",
        "webhook_url_present",
        "webhook_url_scheme_category",
        "token_present",
    ),
    "terraform_cloud_team_access_summary": (
        "team_access_count",
        "admin_access_count",
        "write_access_count",
        "read_access_count",
        "plan_access_count",
        "custom_permission_count",
    ),
    "terraform_cloud_run_trigger": (
        "sourceable_type_category",
    ),
    "terraform_cloud_state_version_summary": (
        "state_version_present",
        "state_version_count_category",
    ),
}


_GITLAB_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "gitlab_instance": (
        "version_present", "revision_present", "enterprise",
        "project_count", "group_count", "two_factor_requirement_enabled",
        "sign_up_enabled", "visibility_restriction_category",
        "shared_runners_enabled",
    ),
    "gitlab_project": (
        "visibility_category", "archived", "default_branch_present",
        "merge_requests_enabled", "issues_enabled", "wiki_enabled",
        "snippets_enabled", "container_registry_enabled", "packages_enabled",
        "shared_runners_enabled", "protected_branch_count", "webhook_count",
        "ci_variable_count", "deploy_key_count", "approval_rule_count",
    ),
    "gitlab_group": (
        "visibility_category", "project_count", "subgroup_count",
        "member_count_category", "two_factor_requirement_enabled",
        "membership_lock", "shared_runners_setting_category",
    ),
    "gitlab_branch_protection": (
        "pattern_category", "allow_force_push", "code_owner_approval_required",
        "push_access_level_category", "merge_access_level_category",
        "allowed_to_push_count", "allowed_to_merge_count",
    ),
    "gitlab_webhook": (
        "enabled", "url_scheme", "url_host_category",
        "ssl_verification_enabled", "secret_token_present", "event_count",
        "push_events", "merge_requests_events", "pipeline_events", "job_events",
    ),
    "gitlab_ci_variable_summary": (
        "variable_count", "protected_variable_count", "masked_variable_count",
        "environment_scoped_count", "unprotected_unmasked_count",
    ),
    "gitlab_deploy_key_summary": (
        "deploy_key_count", "write_enabled_count", "read_only_count",
        "enabled_count",
    ),
    "gitlab_runner_summary": (
        "runner_count", "shared_runner_enabled", "locked_runner_count",
        "paused_runner_count", "tagged_runner_count", "untagged_runner_count",
    ),
    "gitlab_merge_request_approval_summary": (
        "approval_rule_count", "approvals_required", "author_approval_allowed",
        "reset_approvals_on_push",
        "disable_overriding_approvers_per_merge_request",
    ),
}


_JIRA_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "jira_site": (
        "site_url_present", "project_count", "webhook_count",
        "automation_rule_count",
    ),
    "jira_project": (
        "project_key_present", "project_type_category", "project_private",
        "project_archived", "project_deleted", "project_simplified",
        "project_style_category", "board_count", "issue_type_count",
        "lead_present",
    ),
    "jira_board": (
        "board_type_category", "board_location_type_category", "project_id",
        "board_filter_present", "board_jql_filter_broad", "board_column_count",
        "board_quick_filter_count", "board_swimlane_strategy_category",
    ),
    "jira_workflow": (
        "workflow_status_count", "workflow_transition_count",
        "workflow_global_transition_count", "workflow_active", "workflow_draft",
        "workflow_has_done_status", "workflow_has_in_progress_status",
        "workflow_transition_rule_count", "workflow_validator_count",
        "workflow_condition_count", "workflow_post_function_count",
        "workflow_orphan_status_count", "workflow_status_category_count",
    ),
    "jira_workflow_scheme": (
        "workflow_scheme_project_count", "workflow_scheme_default_present",
        "workflow_scheme_workflow_count",
        "workflow_scheme_issue_type_mapping_count",
        "workflow_scheme_unmapped_issue_type_count",
    ),
    "jira_permission_scheme": (
        "permission_grant_count", "permission_anonymous_grant_count",
        "permission_anyone_grant_count", "permission_logged_in_grant_count",
        "permission_project_role_grant_count",
        "permission_public_browse_projects",
        "permission_public_administer_projects",
        "permission_public_manage_sprints", "permission_public_create_issues",
        "permission_public_transition_issues", "permission_unknown_holder_count",
        "permission_high_privilege_grant_count", "permission_public_grant_count",
    ),
    "jira_notification_scheme": (
        "notification_count", "notification_email_recipient_count",
        "notification_group_recipient_count",
        "notification_project_role_recipient_count",
        "notification_all_watchers_recipient_count",
        "notification_unknown_recipient_count", "notification_event_count",
    ),
    "jira_issue_type_scheme": (
        "issue_type_count", "default_issue_type_present",
    ),
    "jira_field_configuration_scheme": (
        "field_configuration_count", "required_field_count",
        "hidden_field_count",
    ),
    "jira_screen_scheme": (
        "screen_count", "tab_count", "field_count", "screen_tab_count",
        "screen_unmapped_screen_count",
    ),
    "jira_webhook": (
        "webhook_enabled", "webhook_event_count", "webhook_url_present",
        "webhook_url_scheme_category", "webhook_jql_filter_present",
        "webhook_secret_present", "webhook_has_issue_events",
        "webhook_has_comment_events", "webhook_has_attachment_events",
        "webhook_has_project_events", "webhook_has_sprint_events",
        "webhook_has_worklog_events", "webhook_all_issue_events",
        "webhook_jql_empty_or_broad", "webhook_event_scope_category",
    ),
    "jira_automation_rule": (
        "automation_enabled", "automation_trigger_type_category",
        "automation_component_count", "automation_scope_category",
        "automation_action_count", "automation_condition_count",
        "automation_branch_count", "automation_has_web_request_action",
        "automation_has_email_action", "automation_has_external_action",
        "automation_has_comment_action",
    ),
}


_LINEAR_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "linear_workspace": (
        "resource_name", "url_key_present", "logo_present", "team_count",
        "webhook_count", "integration_count",
    ),
    "linear_team": (
        "resource_name", "private_team", "team_visibility_category",
        "member_count_category", "project_count", "auto_archive_enabled",
        "cycle_enabled", "cycle_duration_category", "workflow_state_count",
        "has_backlog_state", "has_started_state", "has_completed_state",
        "has_canceled_state", "label_count", "webhook_count",
    ),
    "linear_project": (
        "resource_name", "project_status_category", "project_health_category",
        "lead_present", "member_count_category", "issue_count_category",
        "team_count",
    ),
    "linear_workflow_state": (
        "resource_name", "state_type_category", "position_category", "team_id",
    ),
    "linear_label": (
        "resource_name", "is_group_label", "parent_id_present", "team_id",
    ),
    "linear_webhook": (
        "webhook_resource_types_count", "webhook_enabled",
        "webhook_secret_present", "webhook_url_present",
        "webhook_url_scheme_category", "team_id", "webhook_has_comment_type",
        "webhook_has_attachment_type",
    ),
    "linear_view": (
        "resource_name", "view_shared", "filter_count_category", "team_id",
    ),
    "linear_cycle": (
        "resource_name", "active", "team_id", "issue_count_category",
    ),
    "linear_integration": (
        "integration_type_category", "integration_enabled", "team_id",
    ),
}


_PAGERDUTY_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "pagerduty_service": (
        "resource_name", "status_category", "escalation_policy_id",
        "team_count", "integration_count", "alert_creation_category",
        "incident_urgency_rule_type", "support_hours_enabled",
        "scheduled_actions_count", "auto_resolve_timeout_category",
        "acknowledgement_timeout_category",
    ),
    "pagerduty_escalation_policy": (
        "resource_name", "team_count", "escalation_rule_count",
        "escalation_level_count", "repeat_enabled", "num_loops",
        "on_call_handoff_notifications", "target_count", "user_target_count",
        "schedule_target_count", "has_schedule_targets",
    ),
    "pagerduty_schedule": (
        "resource_name", "time_zone_present", "layer_count", "user_count",
        "team_count", "restriction_count", "has_restrictions",
    ),
    "pagerduty_service_integration": (
        "type_category", "vendor_name", "has_integration_key",
        "routing_key_present",
    ),
    "pagerduty_webhook_subscription": (
        "active", "event_count", "delivery_url_scheme_category",
        "filter_type", "has_custom_headers",
    ),
    "pagerduty_event_orchestration": (
        "resource_name", "team_present", "route_count",
    ),
    "pagerduty_business_service": (
        "resource_name", "team_present", "point_of_contact_present",
    ),
    "pagerduty_response_play": (
        "resource_name", "team_present", "responder_count",
        "subscriber_count", "conference_number_present", "runnability",
    ),
}


_DATADOG_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "datadog_monitor": (
        "resource_name", "monitor_type", "enabled", "status",
        "priority_category", "query_present", "query_complexity_category",
        "query_uses_wildcard_scope", "query_group_by_count", "message_present",
        "message_length_category", "notification_routing_present",
        "notification_count", "message_template_present", "tag_count",
        "threshold_count", "threshold_critical_present",
        "threshold_warning_present", "threshold_recovery_present",
        "renotify_enabled", "renotify_interval_category",
        "restricted_roles_count", "notify_no_data", "include_tags",
        "notify_audit", "require_full_window", "evaluation_delay_category",
        "silenced_scope_count", "no_data_timeframe_category",
    ),
    "datadog_slo": (
        "resource_name", "slo_type", "target_category",
        "warning_target_category", "timeframe_count", "monitor_count",
        "group_count", "tag_count", "description_present",
        "description_length_category",
    ),
    "datadog_dashboard": (
        "resource_name", "layout_type", "widget_count",
        "template_variable_count", "restricted_roles_count",
        "public_url_present", "description_present",
        "description_length_category",
    ),
    "datadog_webhook_integration": (
        "resource_name", "url_present", "url_scheme_category",
        "custom_headers_present", "custom_header_count",
        "auth_material_present", "payload_template_present",
        "payload_template_length_category", "secret_headers_present",
        "secret_headers_count", "encode_as_category",
    ),
    "datadog_notification_integration": (
        "resource_name", "integration_type", "enabled", "handle_count",
        "channel_count", "restricted_roles_count",
    ),
    "datadog_api_key_metadata": (
        "resource_name", "created_present", "modified_present",
        "last4_present", "created_by_present", "disabled",
    ),
    "datadog_application_key_metadata": (
        "resource_name", "created_present", "modified_present",
        "scopes_count", "owned_by_present",
    ),
    "datadog_role": (
        "resource_name", "permission_count", "user_count", "team_count",
    ),
    "datadog_team": (
        "resource_name", "member_count", "handle_present", "link_count",
    ),
    "datadog_cloud_integration": (
        "resource_name", "cloud_provider", "account_id_present",
        "resource_collection_enabled", "metric_collection_enabled",
        "log_collection_enabled", "account_tags_count", "namespace_count",
    ),
}


_CLERK_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "clerk_instance_settings": (
        "environment_type", "sign_up_enabled", "sign_in_enabled",
        "email_enabled", "phone_enabled", "username_enabled",
        "password_enabled", "social_provider_count", "mfa_enabled",
        "mfa_factor_count", "session_lifetime_category",
        "allowed_redirect_count", "domain_count", "webhook_count",
        "allowlist_enabled", "blocklist_enabled", "sign_in_mode",
    ),
    "clerk_application": (
        "name", "application_type", "enabled", "oauth_provider_count",
        "redirect_url_count", "allowed_origin_count", "jwt_template_count",
        "organization_enabled", "mfa_required", "sign_up_enabled",
        "sign_in_enabled", "password_enabled", "saml_enabled",
    ),
    "clerk_domain": (
        "domain_present", "domain_type", "verified", "primary",
        "ssl_enabled", "dns_status_category", "proxy_enabled",
    ),
    "clerk_redirect_url_config": (
        "url_present", "url_scheme_category", "wildcard_present",
        "localhost_present", "custom_scheme_present",
    ),
    "clerk_jwt_template": (
        "name", "enabled", "claims_count", "custom_claims_present",
        "audience_present", "lifetime_category", "algorithm",
        "issuer_present",
    ),
    "clerk_webhook_endpoint": (
        "enabled", "url_present", "url_scheme_category", "event_count",
        "secret_present", "description_present",
    ),
    "clerk_email_sms_settings": (
        "email_enabled", "sms_enabled", "custom_sender_present",
        "template_customization_present",
    ),
    "clerk_auth_strategy": (
        "password_enabled", "oauth_enabled", "social_provider_count",
        "saml_enabled", "mfa_enabled", "mfa_required", "passkey_enabled",
        "magic_link_enabled", "email_otp_enabled", "phone_otp_enabled",
    ),
    "clerk_organization_settings": (
        "organizations_enabled", "max_allowed_memberships_category",
        "admin_delete_enabled", "domains_enabled",
        "domains_enrollment_mode_category", "verified_domains_required",
        "invitation_enabled", "admin_role_present", "role_count",
        "permission_count",
    ),
    "clerk_session_policy": (
        "session_lifetime_category", "inactivity_timeout_category",
        "single_session_mode", "url_based_session_syncing",
        "token_rotation_enabled", "device_tracking_enabled",
        "reverification_required",
    ),
}


_AUTH0_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "auth0_tenant_settings": (
        "friendly_name_present", "support_email_domain",
        "default_directory_present", "session_lifetime_category",
        "idle_session_lifetime_category", "enabled_locales_count",
        "flag_change_pwd_on_first_login", "flag_enable_client_connections",
        "flag_enable_apis_section", "flag_enable_pipeline2",
        "flag_enable_dynamic_client_registration",
        "flag_enable_custom_domain_in_emails", "flag_universal_login",
        "flag_enable_legacy_logs_search_v2",
        "flag_no_disclose_enterprise_connections",
        "flag_disable_management_api_sms_obfuscation",
        "flag_enable_adfs_waad_email_verification",
        "flag_revoke_refresh_token_grant",
    ),
    "auth0_application": (
        "name", "app_type", "is_first_party", "grant_types_summary",
        "callbacks_count", "allowed_logout_urls_count",
        "allowed_origins_count", "web_origins_count", "jwt_alg",
        "oidc_conformant", "token_endpoint_auth_method",
        "refresh_token_rotation_enabled", "refresh_token_lifetime_category",
        "grant_types_count", "grant_password_enabled",
        "grant_implicit_enabled", "grant_client_credentials_enabled",
        "grant_authorization_code_enabled", "grant_refresh_token_enabled",
        "grant_device_code_enabled", "grant_mfa_enabled",
        "wildcard_callback_present", "wildcard_logout_url_present",
        "wildcard_allowed_origin_present", "localhost_callback_present",
        "localhost_origin_present", "callbacks_missing_https",
        "allowed_origins_missing_https",
    ),
    "auth0_connection": (
        "name", "strategy", "enabled_clients_count", "is_domain_connection",
        "password_policy_category", "mfa_enabled",
    ),
    "auth0_resource_server": (
        "name", "identifier_present", "signing_alg",
        "token_lifetime_category", "allow_offline_access",
        "skip_consent_for_verifiable_first_party_clients", "rbac_enabled",
        "scopes_count",
    ),
    "auth0_rule": (
        "name", "enabled", "order", "script_present",
        "script_length_category", "stage",
    ),
    "auth0_action": (
        "name", "status", "runtime", "trigger_id", "code_present",
        "code_length_category", "deployed_version_present",
        "dependencies_count", "secrets_count",
    ),
    "auth0_mfa_factor": (
        "enabled", "trial_expired", "provider_category",
    ),
    "auth0_custom_domain": (
        "domain_present", "status", "type", "primary",
        "verification_method_category", "tls_policy_category",
    ),
}


_GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "google_cloud_project": (
        "project_number", "display_name", "lifecycle_state", "parent_type",
        "create_time", "label_keys",
    ),
    "google_cloud_iam_policy_summary": (
        "binding_count", "role_count", "role_names", "broad_role_count",
        "user_member_count", "group_member_count",
        "service_account_member_count", "domain_member_count",
        "other_member_count", "allusers_binding_present",
        "allauthenticatedusers_binding_present", "conditional_binding_count",
    ),
    "google_cloud_vpc_network": (
        "network_name", "auto_create_subnetworks", "routing_mode", "mtu",
        "subnet_count", "peering_count",
    ),
    "google_cloud_firewall_rule": (
        "firewall_name", "network_name", "direction", "priority", "disabled",
        "source_ranges_summary", "destination_ranges_summary",
        "allowed_summary", "denied_summary", "target_tag_count",
        "target_service_account_count", "has_log_config",
    ),
    "google_cloud_storage_bucket": (
        "bucket_name", "location", "location_type", "storage_class",
        "uniform_bucket_level_access_enabled", "public_access_prevention",
        "versioning_enabled", "retention_policy_seconds",
        "retention_policy_locked", "lifecycle_rule_count",
        "encryption_default_kms_key_present",
    ),
    "google_cloud_sql_instance": (
        "instance_name", "database_version", "region", "state",
        "public_ip_enabled", "authorized_network_count", "require_ssl",
        "ssl_mode", "backup_enabled", "deletion_protection_enabled",
        "point_in_time_recovery_enabled", "availability_type",
    ),
    "google_cloud_run_service": (
        "service_name", "region", "ingress", "launch_stage",
        "public_invoker_allowed", "invoker_policy_summary",
        "environment_variable_count", "secret_environment_variable_count",
    ),
    "google_cloud_gke_cluster": (
        "cluster_name", "location", "private_cluster_enabled",
        "master_authorized_networks_count", "network_policy_enabled",
        "workload_identity_enabled", "shielded_nodes_enabled",
        "legacy_abac_enabled", "public_endpoint_enabled", "release_channel",
    ),
    "google_cloud_service_account_key_summary": (
        "service_account_count", "disabled_service_account_count",
        "user_managed_key_count", "old_user_managed_key_count",
        "oldest_key_age_days",
    ),
    "google_cloud_secret_manager_summary": (
        "secret_count", "automatic_replication_count",
        "user_managed_replication_count", "customer_managed_encryption_count",
    ),
}


_AZURE_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "azure_subscription": (
        "display_name", "state", "tenant_id", "authorization_source",
    ),
    "azure_resource_group": (
        "location", "provisioning_state", "tag_keys",
    ),
    "azure_network_security_group": (
        "nsg_name", "resource_group", "location", "rule_count",
        "inbound_allow_rule_count", "public_inbound_rule_count",
        "rules_summary",
    ),
    "azure_storage_account": (
        "account_name", "resource_group", "location", "kind", "sku_name",
        "allow_blob_public_access", "public_network_access",
        "minimum_tls_version", "supports_https_traffic_only",
        "shared_access_key_enabled", "network_default_action",
    ),
    "azure_key_vault": (
        "vault_name", "resource_group", "location",
        "enable_rbac_authorization", "public_network_access",
        "soft_delete_enabled", "purge_protection_enabled",
        "access_policy_count", "network_default_action",
    ),
    "azure_role_assignment": (
        "scope_type", "resource_group", "role_definition_id",
        "role_definition_name", "principal_type", "condition_present",
        "created_on", "updated_on",
    ),
    "azure_app_service": (
        "app_name", "resource_group", "location", "kind", "https_only",
        "public_network_access", "client_cert_enabled", "ftps_state",
        "min_tls_version", "auth_enabled", "app_settings_count",
        "connection_string_count",
    ),
    "azure_sql_server": (
        "server_name", "resource_group", "location", "public_network_access",
        "minimum_tls_version", "azure_ad_only_authentication",
        "firewall_rule_count", "has_allow_azure_services_rule",
    ),
    "azure_aks_cluster": (
        "cluster_name", "resource_group", "location",
        "private_cluster_enabled", "local_account_disabled",
        "azure_rbac_enabled", "network_plugin", "network_policy",
        "public_network_access", "api_server_authorized_ip_range_count",
        "authorized_ip_ranges_configured",
    ),
}


# Kubernetes — foundation (message 1) + workloads (message 2) of a
# 9-message arc. ``kubernetes_api_capability`` is deliberately left
# untracked (empty tuple) — per the message-1 scope, API-capability drift
# should not yet generate noisy user-facing Changes; this is revisited once
# later messages give capability transitions real meaning (e.g. a resource
# family disappearing ahead of removing collection for it).
#
# Message-2 workload/container/Pod field selection follows one rule:
# durable declarative security/configuration posture is tracked; volatile
# runtime/status fields are NOT — resourceVersion, managed fields,
# generation, creation timestamps, Pod IP, node name, ordinary phase
# transitions, observed replica counts, restart counts, status conditions,
# and deployment-progress timestamps are excluded. For ``kubernetes_pod``
# specifically, every runtime-only field (phase_category, scheduled, ready,
# host_ip_present, pod_ip_count, restart_count_aggregate,
# container_waiting_reason_category, container_terminated_reason_category)
# is intentionally absent from the tracked tuple below so an ordinary
# restart or phase transition never generates a Change.
_KUBERNETES_WORKLOAD_CONTROLLER_TRACKED_FIELDS: tuple[str, ...] = (
    "service_account_name",
    "automount_service_account_token",
    "host_network",
    "host_pid",
    "host_ipc",
    "privileged_container_count",
    "root_container_count",
    "allow_privilege_escalation_count",
    "hostpath_volume_count",
    "dangerous_hostpath_categories",
    "added_capability_categories",
    "seccomp_posture_summary",
    "apparmor_posture_summary",
    "read_only_root_filesystem_coverage",
    "resource_limit_coverage",
    "liveness_probe_coverage",
    "readiness_probe_coverage",
    "startup_probe_coverage",
    "image_posture_summary",
    "security_posture_summary",
    "runtime_class_name",
    "update_strategy_category",
    "desired_replica_count",
    "collection_completeness_category",
)

_KUBERNETES_POD_TRACKED_FIELDS: tuple[str, ...] = (
    "service_account_name",
    "automount_service_account_token",
    "host_network",
    "host_pid",
    "host_ipc",
    "share_process_namespace",
    "privileged_container_count",
    "root_container_count",
    "allow_privilege_escalation_count",
    "hostpath_volume_count",
    "dangerous_hostpath_categories",
    "added_capability_categories",
    "seccomp_posture_summary",
    "apparmor_posture_summary",
    "read_only_root_filesystem_coverage",
    "resource_limit_coverage",
    "security_posture_summary",
    "runtime_class_name",
    "collection_completeness_category",
)

_KUBERNETES_CONTAINER_SECURITY_CONTEXT_TRACKED_FIELDS: tuple[str, ...] = (
    "image",
    "image_registry_category",
    "image_tag_category",
    "image_pull_policy",
    "privileged",
    "allow_privilege_escalation",
    "run_as_non_root",
    "run_as_uid",
    "read_only_root_filesystem",
    "seccomp_profile_category",
    "apparmor_profile_category",
    "capabilities_added",
    "capabilities_dropped",
    "dangerous_added_capability_categories",
    "any_resource_request_present",
    "any_resource_limit_present",
    "cpu_request_present",
    "memory_request_present",
    "cpu_limit_present",
    "memory_limit_present",
    "liveness_probe_present",
    "readiness_probe_present",
    "startup_probe_present",
    "host_port_count",
    "dangerous_host_ports",
    "hostpath_mount_count",
    "writable_hostpath_mount_count",
    "service_account_token_explicitly_mounted",
    "bidirectional_mount_propagation_present",
)

_KUBERNETES_WORKLOAD_SERVICE_ACCOUNT_TRACKED_FIELDS: tuple[str, ...] = (
    "referencing_workload_count",
    "automount_explicit_true_count",
    "automount_explicit_false_count",
    "automount_inherited_count",
    # Enriched in message 3 (RBAC) — resolved automount posture and
    # bound-privilege context.
    "service_account_found",
    "effective_automount_state",
    "automount_source_category",
    "service_account_privilege_summary",
    "bound_role_binding_count",
    "bound_cluster_role_binding_count",
    "risky_permission_categories",
    "collection_completeness_category",
)

# Kubernetes RBAC and identity — message 3 of a 9-message arc.
_KUBERNETES_SERVICE_ACCOUNT_TRACKED_FIELDS: tuple[str, ...] = (
    "automount_service_account_token",
    "secret_reference_count",
    "image_pull_secret_count",
    "highest_privilege_category",
    "bound_role_binding_count",
    "bound_cluster_role_binding_count",
    "cluster_admin_bound",
    "wildcard_permission_bound",
    "secret_read_permission_bound",
    "pod_exec_permission_bound",
    "workload_creation_permission_bound",
    "rbac_modification_permission_bound",
    "impersonation_permission_bound",
    "collection_completeness_category",
)

_KUBERNETES_ROLE_TRACKED_FIELDS: tuple[str, ...] = (
    "permission_fingerprint",
    "rule_count",
    "wildcard_api_group",
    "wildcard_resource",
    "wildcard_verb",
    "wildcard_non_resource_url",
    "high_risk_permission_categories",
    "aggregation_rule_present",
    "highest_severity_category",
    "collection_completeness_category",
)

_KUBERNETES_ROLE_BINDING_TRACKED_FIELDS: tuple[str, ...] = (
    "role_ref_kind",
    "role_ref_name",
    "role_ref_api_group",
    "subject_count",
    "user_subject_count",
    "group_subject_count",
    "service_account_subject_count",
    "role_resolved",
    "role_resolution_status",
    "resolved_privilege_category",
    "cluster_admin_binding",
    "wildcard_permission_binding",
    "binding_fingerprint",
    "collection_completeness_category",
)

_KUBERNETES_RBAC_SUBJECT_BINDING_TRACKED_FIELDS: tuple[str, ...] = (
    "role_ref_kind",
    "role_ref_name",
    "role_resolved",
    "role_resolution_status",
    "resolved_privilege_category",
    "cluster_admin_binding",
    "wildcard_permission_binding",
    "high_risk_permission_categories",
)

_KUBERNETES_RBAC_PERMISSION_SUMMARY_TRACKED_FIELDS: tuple[str, ...] = (
    "role_binding_count",
    "cluster_role_binding_count",
    "cluster_admin_bound",
    "wildcard_permission_bound",
    "secret_read_bound",
    "secret_write_bound",
    "pod_exec_bound",
    "workload_create_bound",
    "rbac_modification_bound",
    "impersonation_bound",
    "highest_privilege_category",
)

# Kubernetes network exposure and isolation — message 4 of a 9-message arc.
_KUBERNETES_SERVICE_TRACKED_FIELDS: tuple[str, ...] = (
    "service_type",
    "external_ip_count",
    "load_balancer_ingress_count",
    "external_name_category",
    "external_traffic_policy",
    "internal_traffic_policy",
    "ip_family_categories",
    "selector_fingerprint",
    "internal_load_balancer_annotation_present",
    "exposure_category",
    "mixed_exposure_evidence",
    "collection_completeness_category",
)

_KUBERNETES_SERVICE_PORT_TRACKED_FIELDS: tuple[str, ...] = (
    "protocol",
    "port",
    "target_port_category",
    "node_port",
    "sensitive_port",
    "exposure_category",
)

_KUBERNETES_INGRESS_TRACKED_FIELDS: tuple[str, ...] = (
    "ingress_class",
    "default_backend_present",
    "host_count",
    "wildcard_host_count",
    "hostless_rule_present",
    "tls_host_count",
    "tls_secret_reference_count",
    "backend_service_count",
    "public_exposure_category",
    "plaintext_exposure_category",
    "load_balancer_ingress_count",
    "collection_completeness_category",
)

_KUBERNETES_INGRESS_RULE_TRACKED_FIELDS: tuple[str, ...] = (
    "host_category",
    "path_category",
    "backend_service_name",
    "backend_port",
    "tls_covered",
    "public_exposure_category",
    "catch_all_route",
    "route_fingerprint",
)

_KUBERNETES_GATEWAY_TRACKED_FIELDS: tuple[str, ...] = (
    "gateway_class_name",
    "address_count",
    "public_address_category",
    "listener_protocol_categories",
    "allowed_routes_category",
    "cross_namespace_route_allowance",
    "status_category",
    "collection_completeness_category",
)

_KUBERNETES_GATEWAY_LISTENER_TRACKED_FIELDS: tuple[str, ...] = (
    "protocol",
    "port",
    "hostname_category",
    "tls_mode",
    "allowed_namespace_policy",
    "public_exposure_category",
    "listener_fingerprint",
)

_KUBERNETES_HTTP_ROUTE_TRACKED_FIELDS: tuple[str, ...] = (
    "parent_ref_count",
    "cross_namespace_parent_count",
    "hostname_count",
    "wildcard_hostname_count",
    "backend_ref_count",
    "cross_namespace_backend_count",
    "filter_categories",
    "resolved_refs_status",
    "route_fingerprint",
    "collection_completeness_category",
)

_KUBERNETES_HTTP_ROUTE_RULE_TRACKED_FIELDS: tuple[str, ...] = (
    "match_categories",
    "catch_all_path",
    "backend_count",
    "cross_namespace_backend",
    "redirect_present",
    "rewrite_present",
    "mirror_present",
    "route_fingerprint",
)

_KUBERNETES_NETWORK_POLICY_TRACKED_FIELDS: tuple[str, ...] = (
    "selector_fingerprint",
    "policy_types",
    "ingress_isolation_enabled",
    "egress_isolation_enabled",
    "empty_ingress_list",
    "empty_egress_list",
    "allows_all_ingress",
    "allows_all_egress",
    "public_ipv4_cidr_allowed",
    "public_ipv6_cidr_allowed",
    "broad_cidr_count",
    "namespace_selector_present",
    "pod_selector_present",
    "port_restriction_present",
    "policy_fingerprint",
    "collection_completeness_category",
)

_KUBERNETES_NAMESPACE_NETWORK_POSTURE_TRACKED_FIELDS: tuple[str, ...] = (
    "policy_count",
    "ingress_isolation_present",
    "egress_isolation_present",
    "all_pod_ingress_default_deny",
    "all_pod_egress_default_deny",
    "policy_coverage_category",
    "public_ingress_allowance_present",
    "public_egress_allowance_present",
    "collection_completeness_category",
)

# Kubernetes admission control and configuration governance — message 5.
_KUBERNETES_WEBHOOK_CONFIGURATION_TRACKED_FIELDS: tuple[str, ...] = (
    "webhook_count",
    "fail_open_webhook_count",
    "fail_closed_webhook_count",
    "no_side_effects_webhook_count",
    "unknown_side_effects_webhook_count",
    "namespace_selector_present_count",
    "object_selector_present_count",
    "external_url_client_count",
    "in_cluster_service_client_count",
    "ca_bundle_present_count",
    "timeout_seconds_min",
    "timeout_seconds_max",
    "match_policy_categories",
    "reinvocation_policy_categories",
    "security_posture_summary",
    "configuration_fingerprint",
    "collection_completeness_category",
)

_KUBERNETES_WEBHOOK_TRACKED_FIELDS: tuple[str, ...] = (
    "client_type",
    "service_namespace",
    "service_name",
    "service_port",
    "external_url_host_category",
    "plaintext_http_client",
    "failure_policy",
    "match_policy",
    "side_effects",
    "timeout_seconds",
    "namespace_selector_category",
    "object_selector_category",
    "rules_count",
    "operation_categories",
    "api_group_categories",
    "resource_categories",
    "scope_category",
    "admission_review_versions",
    "ca_bundle_present",
    "reinvocation_policy",
    "wildcard_operation",
    "wildcard_api_group",
    "wildcard_api_version",
    "wildcard_resource",
    "webhook_fingerprint",
    "collection_completeness_category",
)

_KUBERNETES_POD_SECURITY_ADMISSION_TRACKED_FIELDS: tuple[str, ...] = (
    "enforce_level",
    "enforce_version_category",
    "audit_level",
    "audit_version_category",
    "warn_level",
    "warn_version_category",
    "effective_posture_category",
    "enforcement_enabled",
    "audit_enabled",
    "warning_enabled",
    "enforcement_weaker_than_audit",
    "enforcement_weaker_than_warning",
    "posture_fingerprint",
    "collection_completeness_category",
)

_KUBERNETES_RESOURCE_QUOTA_TRACKED_FIELDS: tuple[str, ...] = (
    "hard_cpu_limit_present",
    "hard_cpu_limit_millicores",
    "hard_memory_limit_present",
    "hard_memory_limit_bytes",
    "request_cpu_limit_present",
    "request_memory_limit_present",
    "pod_count_limit_present",
    "pod_count_limit",
    "service_count_limit_present",
    "load_balancer_count_limit_present",
    "pvc_count_limit_present",
    "storage_request_limit_present",
    "ephemeral_storage_limit_present",
    "secret_count_limit_present",
    "configmap_count_limit_present",
    "scope_categories",
    "scope_selector_present",
    "resource_control_coverage_category",
    "quota_fingerprint",
    "collection_completeness_category",
)

_KUBERNETES_LIMIT_RANGE_TRACKED_FIELDS: tuple[str, ...] = (
    "container_default_present",
    "container_default_request_present",
    "pod_max_present",
    "pod_min_present",
    "container_max_present",
    "container_min_present",
    "pvc_min_present",
    "pvc_max_present",
    "request_to_limit_ratio_present",
    "cpu_policy_coverage_category",
    "memory_policy_coverage_category",
    "ephemeral_storage_policy_coverage_category",
    "defaulting_coverage_category",
    "limit_fingerprint",
    "collection_completeness_category",
)

_KUBERNETES_NAMESPACE_GOVERNANCE_POSTURE_TRACKED_FIELDS: tuple[str, ...] = (
    "psa_enforcement_category",
    "validating_webhook_coverage_category",
    "mutating_webhook_coverage_category",
    "resource_quota_count",
    "limit_range_count",
    "quota_coverage_category",
    "default_resource_control_category",
    "network_policy_coverage_category",
    "privileged_workload_present",
    "high_privilege_service_account_present",
    "governance_completeness_category",
    "governance_risk_summary",
)

_KUBERNETES_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "kubernetes_cluster": (
        "kubernetes_version",
        "kubernetes_major_minor",
        "platform",
        "partial_permission_indicator",
        "collection_completeness_category",
        "server_certificate_verification_enabled",
    ),
    "kubernetes_namespace": (
        "phase",
        "terminating",
        "psa_enforce",
        "psa_enforce_version",
        "psa_audit",
        "psa_audit_version",
        "psa_warn",
        "psa_warn_version",
    ),
    "kubernetes_api_capability": (),
    "kubernetes_deployment": _KUBERNETES_WORKLOAD_CONTROLLER_TRACKED_FIELDS,
    "kubernetes_statefulset": _KUBERNETES_WORKLOAD_CONTROLLER_TRACKED_FIELDS,
    "kubernetes_daemonset": _KUBERNETES_WORKLOAD_CONTROLLER_TRACKED_FIELDS,
    "kubernetes_job": _KUBERNETES_WORKLOAD_CONTROLLER_TRACKED_FIELDS,
    "kubernetes_cronjob": _KUBERNETES_WORKLOAD_CONTROLLER_TRACKED_FIELDS,
    "kubernetes_pod": _KUBERNETES_POD_TRACKED_FIELDS,
    "kubernetes_container_security_context": _KUBERNETES_CONTAINER_SECURITY_CONTEXT_TRACKED_FIELDS,
    "kubernetes_workload_service_account": _KUBERNETES_WORKLOAD_SERVICE_ACCOUNT_TRACKED_FIELDS,
    "kubernetes_service_account": _KUBERNETES_SERVICE_ACCOUNT_TRACKED_FIELDS,
    "kubernetes_role": _KUBERNETES_ROLE_TRACKED_FIELDS,
    "kubernetes_cluster_role": _KUBERNETES_ROLE_TRACKED_FIELDS,
    "kubernetes_role_binding": _KUBERNETES_ROLE_BINDING_TRACKED_FIELDS,
    "kubernetes_cluster_role_binding": _KUBERNETES_ROLE_BINDING_TRACKED_FIELDS,
    "kubernetes_rbac_subject_binding": _KUBERNETES_RBAC_SUBJECT_BINDING_TRACKED_FIELDS,
    "kubernetes_rbac_permission_summary": _KUBERNETES_RBAC_PERMISSION_SUMMARY_TRACKED_FIELDS,
    "kubernetes_service": _KUBERNETES_SERVICE_TRACKED_FIELDS,
    "kubernetes_service_port": _KUBERNETES_SERVICE_PORT_TRACKED_FIELDS,
    "kubernetes_ingress": _KUBERNETES_INGRESS_TRACKED_FIELDS,
    "kubernetes_ingress_rule": _KUBERNETES_INGRESS_RULE_TRACKED_FIELDS,
    "kubernetes_gateway": _KUBERNETES_GATEWAY_TRACKED_FIELDS,
    "kubernetes_gateway_listener": _KUBERNETES_GATEWAY_LISTENER_TRACKED_FIELDS,
    "kubernetes_http_route": _KUBERNETES_HTTP_ROUTE_TRACKED_FIELDS,
    "kubernetes_http_route_rule": _KUBERNETES_HTTP_ROUTE_RULE_TRACKED_FIELDS,
    "kubernetes_network_policy": _KUBERNETES_NETWORK_POLICY_TRACKED_FIELDS,
    "kubernetes_namespace_network_posture": _KUBERNETES_NAMESPACE_NETWORK_POSTURE_TRACKED_FIELDS,
    "kubernetes_validating_webhook_configuration": _KUBERNETES_WEBHOOK_CONFIGURATION_TRACKED_FIELDS,
    "kubernetes_mutating_webhook_configuration": _KUBERNETES_WEBHOOK_CONFIGURATION_TRACKED_FIELDS,
    "kubernetes_validating_webhook": _KUBERNETES_WEBHOOK_TRACKED_FIELDS,
    "kubernetes_mutating_webhook": _KUBERNETES_WEBHOOK_TRACKED_FIELDS,
    "kubernetes_pod_security_admission": _KUBERNETES_POD_SECURITY_ADMISSION_TRACKED_FIELDS,
    "kubernetes_resource_quota": _KUBERNETES_RESOURCE_QUOTA_TRACKED_FIELDS,
    "kubernetes_limit_range": _KUBERNETES_LIMIT_RANGE_TRACKED_FIELDS,
    "kubernetes_namespace_governance_posture": _KUBERNETES_NAMESPACE_GOVERNANCE_POSTURE_TRACKED_FIELDS,
}

# ── Okta foundation tracked fields (Okta message 1 of 8) ────────────────────
#
# Only durable tenant configuration is tracked for okta_organization — never
# timestamps, request IDs, or API counters. okta_api_capability's "status"
# IS tracked (capability gained/lost is diagnostically useful — see
# risk_rules/okta.py for how this is classified as informational/low, never
# a security incident on its own).
_OKTA_TRACKED_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "okta_organization": (
        "org_hostname",
        "org_display_name",
        "status_category",
    ),
    "okta_api_capability": (
        "status",
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
    * Record types starting with ``"firebase_"`` look up in
      ``_FIREBASE_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"supabase_"`` look up in
      ``_SUPABASE_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"shopify_"`` look up in
      ``_SHOPIFY_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"sendgrid_"`` look up in
      ``_SENDGRID_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"twilio_"`` look up in
      ``_TWILIO_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"terraform_cloud_"`` look up in
      ``_TERRAFORM_CLOUD_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"gitlab_"`` look up in
      ``_GITLAB_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"jira_"`` look up in
      ``_JIRA_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"linear_"`` look up in
      ``_LINEAR_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"pagerduty_"`` look up in
      ``_PAGERDUTY_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"datadog_"`` look up in
      ``_DATADOG_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"clerk_"`` look up in
      ``_CLERK_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"auth0_"`` look up in
      ``_AUTH0_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"google_cloud_"`` look up in
      ``_GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"azure_"`` look up in
      ``_AZURE_TRACKED_FIELDS_BY_TYPE``.
    * Record types starting with ``"kubernetes_"`` look up in
      ``_KUBERNETES_TRACKED_FIELDS_BY_TYPE`` (foundation stage — see that
      dict's comment for scope).
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
    if isinstance(rt, str) and rt.startswith("firebase_"):
        return _FIREBASE_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("supabase_"):
        return _SUPABASE_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("shopify_"):
        return _SHOPIFY_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("sendgrid_"):
        return _SENDGRID_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("twilio_"):
        return _TWILIO_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("terraform_cloud_"):
        return _TERRAFORM_CLOUD_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("gitlab_"):
        return _GITLAB_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("jira_"):
        return _JIRA_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("linear_"):
        return _LINEAR_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("pagerduty_"):
        return _PAGERDUTY_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("datadog_"):
        return _DATADOG_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("clerk_"):
        return _CLERK_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("auth0_"):
        return _AUTH0_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("google_cloud_"):
        return _GOOGLE_CLOUD_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("azure_"):
        return _AZURE_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("kubernetes_"):
        return _KUBERNETES_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("okta_"):
        return _OKTA_TRACKED_FIELDS_BY_TYPE.get(rt, ())
    if isinstance(rt, str) and rt.startswith("cloudflare_"):
        # Explicit cloudflare_* prefix → look up in the Cloudflare table.
        # Unknown cloudflare_* subtypes return () (empty), matching every
        # other provider's convention above — NOT the DNS-record
        # _TRACKED_FIELDS tuple. Falling back to _TRACKED_FIELDS here was
        # the exact bug that left 7 of 9 Cloudflare record types
        # undetectable: their field shapes don't match DNS's
        # (record_type, name, content, ttl, proxied, priority, comment), so
        # the fallback silently produced zero real Change rows.
        return _CLOUDFLARE_TRACKED_FIELDS_BY_TYPE.get(rt, ())
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

    # Route53 records carry DNS-specific context that the risk classifier
    # and UI need for accurate messages. Add these fields so the classifier
    # can access dns_record_type, zone_name, and the actual hostname
    # (the composite ``name`` field alone is not enough).
    if record.get("record_type") == "aws_route53_record":
        metadata["dns_record_type"] = record.get("dns_record_type") or ""
        metadata["zone_name"] = record.get("zone_name") or ""
        # dns_record_name is the raw hostname (e.g. "*.example.com" or
        # "\052.example.com") rather than the composite display name.
        metadata["dns_record_name"] = record.get("record_name") or ""

    # CloudTrail trails carry org/multi-region flags that the risk classifier
    # uses to determine whether logging-disabled events should escalate to
    # "critical" (org/multi-region trails) vs "high" (single-region trails).
    if record.get("record_type") == "aws_cloudtrail_trail":
        metadata["is_organization_trail"] = bool(record.get("is_organization_trail"))
        metadata["is_multi_region_trail"] = bool(record.get("is_multi_region_trail"))

    # Shopify webhook subscriptions carry the event topic, which the risk
    # classifier needs to decide whether a plain-HTTP / removed / domain-
    # changed webhook belongs to a critical topic family (orders, customers,
    # checkouts, ...). Without this, classify_shopify_change silently saw
    # topic="" for every field-level Change (only whole-record identity
    # fields were ever included here), which meant critical-topic webhooks
    # were systematically under-classified (e.g. "high" instead of
    # "critical" for an orders/create webhook downgraded to plain HTTP).
    #
    # For "modified" changes, prefer alt_record (the NEW record) for this
    # context: if topic and endpoint_scheme both change in the same sync
    # round, the field being classified (e.g. endpoint_scheme) should be
    # scoped against the topic it belongs to *going forward*, not the topic
    # it had before the sync. Falls back to record (added/removed have no
    # alt_record) when alt_record is unavailable.
    context_record = alt_record if alt_record is not None else record
    if record.get("record_type") == "shopify_webhook_subscription":
        metadata["topic"] = context_record.get("topic") or ""
        # is_https / endpoint_scheme are also read directly from
        # provider_metadata by the risk classifier's "added" branch (a whole-
        # record event has no per-field field_path to read them from).
        metadata["is_https"] = record.get("is_https")
        metadata["endpoint_scheme"] = record.get("endpoint_scheme") or ""

    # Shopify store policies carry the policy type, which the risk classifier
    # needs to distinguish legally/compliance-critical policies (privacy,
    # refund, terms of service) from operational ones (shipping) when a
    # policy is removed or cleared. Same under-classification bug class as
    # the webhook topic above — this was previously never populated.
    if record.get("record_type") == "shopify_store_policy":
        metadata["policy_type"] = context_record.get("policy_type") or ""

    # Shopify domains carry the ``primary`` flag, which the risk classifier
    # needs to scope SSL/verification severity to the primary domain only —
    # mirroring the shopify_domain_ssl_missing / shopify_domain_unverified
    # Security Findings, which only evaluate the primary domain. Uses the
    # NEW record's primary flag (via context_record) so a domain that just
    # became primary in this same sync round is scoped correctly for any
    # other field (e.g. ssl_enabled) that changed alongside it.
    if record.get("record_type") == "shopify_domain":
        metadata["primary"] = context_record.get("primary")

    # Cloudflare expanded surfaces (page rules, worker routes, Access
    # applications/policies, WAF rules) carry their own identifying/display
    # field that the risk classifier reads directly from provider_metadata —
    # none of these record types have a "name" or "content" key, so the
    # generic record_name/record_content stanza above never populates them.
    # Previously NO stanza existed for any of them, so every classifier
    # silently fell back to the opaque record_id: for hostname-dependent
    # classifiers (page rule, worker route) this meant `_is_production_
    # hostname()` evaluated on a dotless ID string, which its own apex
    # heuristic (<=2 dot-separated labels) treats as "apex" — i.e. every
    # page rule and worker route was silently classified as production
    # traffic regardless of its real target. For the others (Access
    # application/policy, WAF rule) it only meant a wrong display name in
    # copy (e.g. "WAF rule 'r1' was disabled" instead of the real
    # description), not a severity error, but was still a real
    # provider_metadata gap masked only by tests that hand-built
    # provider_metadata directly.
    if record.get("record_type") == "cloudflare_page_rule":
        metadata["target_url_pattern"] = context_record.get("target_url_pattern") or ""
        metadata["rule_kind"] = context_record.get("rule_kind") or ""
    if record.get("record_type") == "cloudflare_worker_route":
        metadata["pattern"] = context_record.get("pattern") or ""
    if record.get("record_type") == "cloudflare_access_application":
        metadata["name"] = context_record.get("name") or ""
        metadata["domain"] = context_record.get("domain") or ""
    if record.get("record_type") == "cloudflare_access_policy":
        metadata["name"] = context_record.get("name") or ""
        metadata["decision"] = context_record.get("decision") or ""
    if record.get("record_type") == "cloudflare_waf_rule":
        metadata["description"] = context_record.get("description") or ""

    # GitHub rulesets carry a friendly name and a "targets a protected
    # branch" heuristic that the risk classifier reads directly from
    # provider_metadata (via pm.get("name") / pm.get("targets_protected_
    # branch")) to decide critical-vs-high severity for removal/weakening
    # events. Neither field is populated by the generic record_name/
    # record_content stanza above, so without this stanza every ruleset
    # change was silently capped at "high" even when it targeted main/
    # release branches — the same provider-metadata gap pattern found for
    # Shopify/Cloudflare/Vercel earlier this session.
    if record.get("record_type") == "github_ruleset":
        metadata["name"] = context_record.get("name") or ""
        metadata["targets_protected_branch"] = bool(
            context_record.get("targets_protected_branch")
        )

    # GitHub automation-permissions records use pm.get("name") for display
    # text in risk copy; only "record_name" is populated generically.
    if record.get("record_type") == "github_automation_permissions":
        metadata["name"] = context_record.get("name") or ""

    # Stripe payment links carry a livemode flag that
    # _is_production_payment_link() reads directly from provider_metadata to
    # decide whether a removed/disabled link gets "high" (production) or
    # "medium" (test-mode) severity. Without this stanza, pm.get("livemode")
    # was always missing, so the classifier's "assume production when
    # missing" fallback made every payment link — test-mode or not — always
    # classify as production. Not a severity understatement (the fallback is
    # conservative), but it meant the test/live distinction never actually
    # worked in production, masked by tests that hand-built provider_metadata
    # with livemode already present.
    if record.get("record_type") == "stripe_payment_link":
        metadata["livemode"] = context_record.get("livemode")

    # Supabase risk classifiers read several identifying fields directly from
    # provider_metadata (table_name/schema_name, function_name/slug, cidr,
    # custom_domain, provider_name) that none of the generic record_name/
    # record_content stanza above ever populated (these records don't carry a
    # "name" field). Without this stanza, e.g. the critical "RLS disabled"
    # copy showed only the schema ("table 'public'") with the table name
    # silently dropped — masked by tests that hand-built provider_metadata
    # directly, matching the same gap pattern found for Shopify/Cloudflare/
    # Vercel/GitHub/Stripe earlier this session.
    if record.get("record_type") == "supabase_rls_status":
        metadata["table_name"] = context_record.get("table_name") or ""
        metadata["schema_name"] = context_record.get("schema_name") or "public"
    if record.get("record_type") == "supabase_edge_function":
        metadata["function_name"] = context_record.get("function_name") or ""
        metadata["slug"] = context_record.get("slug") or ""
    if record.get("record_type") == "supabase_network_restriction":
        metadata["cidr"] = context_record.get("cidr") or ""
    if record.get("record_type") == "supabase_custom_domain":
        metadata["custom_domain"] = context_record.get("custom_domain") or ""
    if record.get("record_type") == "supabase_oauth_provider":
        metadata["provider_name"] = context_record.get("provider_name") or ""

    # Firebase classifiers read several identifying fields directly from
    # provider_metadata (provider_id, domain/is_default_firebase_domain/
    # is_localhost, domain_type, function_name) that none of the generic
    # record_name/record_content stanza ever populated (these records don't
    # carry a "name" field usable for this purpose). Same gap pattern found
    # for every other provider this session.
    if record.get("record_type") == "firebase_auth_provider":
        metadata["provider_id"] = context_record.get("provider_id") or ""
    if record.get("record_type") == "firebase_authorized_domain":
        metadata["domain"] = context_record.get("domain") or ""
        metadata["is_default_firebase_domain"] = bool(
            context_record.get("is_default_firebase_domain")
        )
        metadata["is_localhost"] = bool(context_record.get("is_localhost"))
    if record.get("record_type") == "firebase_hosting_domain":
        metadata["domain"] = context_record.get("domain") or ""
        metadata["domain_type"] = context_record.get("domain_type") or ""
    if record.get("record_type") == "firebase_function_metadata":
        metadata["function_name"] = context_record.get("function_name") or ""

    # Kubernetes workload/container records carry cluster/namespace/owner
    # context that the risk classifier (risk_rules/kubernetes.py) needs to
    # scope severity and build display copy — none of it is populated by
    # the generic record_name/record_content stanza above (these records
    # use "name"/"namespace"/"cluster_id", not "name"/"content").
    _kubernetes_record_type = record.get("record_type") or ""
    if isinstance(_kubernetes_record_type, str) and _kubernetes_record_type.startswith("kubernetes_"):
        metadata["cluster_id"] = context_record.get("cluster_id") or record.get("cluster_id") or ""
        metadata["cluster_name"] = context_record.get("cluster_name") or record.get("cluster_name") or ""
        metadata["namespace"] = context_record.get("namespace") or record.get("namespace") or ""
        if _kubernetes_record_type in (
            "kubernetes_deployment", "kubernetes_statefulset", "kubernetes_daemonset",
            "kubernetes_job", "kubernetes_cronjob", "kubernetes_pod",
        ):
            metadata["kind"] = context_record.get("kind") or record.get("kind") or ""
            metadata["workload_name"] = context_record.get("name") or record.get("name") or ""
            metadata["uid"] = context_record.get("uid") or record.get("uid") or ""
            metadata["service_account_name"] = (
                context_record.get("service_account_name") or record.get("service_account_name") or ""
            )
        if _kubernetes_record_type == "kubernetes_container_security_context":
            metadata["container_name"] = (
                context_record.get("container_name") or record.get("container_name") or ""
            )
            metadata["container_category"] = (
                context_record.get("container_category") or record.get("container_category") or ""
            )
            metadata["parent_workload_type"] = (
                context_record.get("parent_workload_type") or record.get("parent_workload_type") or ""
            )
            metadata["parent_workload_uid"] = (
                context_record.get("parent_workload_uid") or record.get("parent_workload_uid") or ""
            )
        if _kubernetes_record_type == "kubernetes_workload_service_account":
            metadata["service_account_name"] = (
                context_record.get("service_account_name") or record.get("service_account_name") or ""
            )

        # RBAC and identity (message 3). Kubernetes risk classifiers read
        # these directly from provider_metadata for whole-record added/
        # removed events and for display copy — none are populated by the
        # generic record_name/record_content stanza (these records don't
        # carry a "name"/"content" shape either).
        if _kubernetes_record_type == "kubernetes_service_account":
            metadata["service_account_name"] = context_record.get("name") or record.get("name") or ""
        if _kubernetes_record_type in ("kubernetes_role", "kubernetes_cluster_role"):
            metadata["kind"] = context_record.get("kind") or record.get("kind") or ""
            metadata["role_name"] = context_record.get("name") or record.get("name") or ""
            metadata["built_in_role_category"] = (
                context_record.get("built_in_role_category") or record.get("built_in_role_category") or ""
            )
        if _kubernetes_record_type in ("kubernetes_role_binding", "kubernetes_cluster_role_binding"):
            metadata["kind"] = context_record.get("kind") or record.get("kind") or ""
            metadata["binding_name"] = context_record.get("name") or record.get("name") or ""
            metadata["role_ref_name"] = context_record.get("role_ref_name") or record.get("role_ref_name") or ""
        if _kubernetes_record_type == "kubernetes_rbac_subject_binding":
            metadata["binding_kind"] = context_record.get("binding_kind") or record.get("binding_kind") or ""
            metadata["binding_name"] = context_record.get("binding_name") or record.get("binding_name") or ""
            metadata["role_ref_name"] = context_record.get("role_ref_name") or record.get("role_ref_name") or ""
            metadata["subject_kind"] = context_record.get("subject_kind") or record.get("subject_kind") or ""
            metadata["subject_identity"] = (
                context_record.get("subject_identity") or record.get("subject_identity") or ""
            )
        if _kubernetes_record_type == "kubernetes_rbac_permission_summary":
            metadata["subject_kind"] = context_record.get("subject_kind") or record.get("subject_kind") or ""
            metadata["subject_identity"] = (
                context_record.get("subject_identity") or record.get("subject_identity") or ""
            )

        # Network exposure and isolation (message 4). Kubernetes network
        # classifiers read these directly from provider_metadata for
        # whole-record added/removed events and display copy.
        if _kubernetes_record_type == "kubernetes_service":
            metadata["service_name"] = context_record.get("name") or record.get("name") or ""
            metadata["service_type"] = context_record.get("service_type") or record.get("service_type") or ""
        if _kubernetes_record_type == "kubernetes_service_port":
            metadata["parent_service_record_id"] = (
                context_record.get("parent_service_record_id") or record.get("parent_service_record_id") or ""
            )
            metadata["port"] = context_record.get("port") or record.get("port") or ""
        if _kubernetes_record_type == "kubernetes_ingress":
            metadata["ingress_name"] = context_record.get("name") or record.get("name") or ""
            metadata["ingress_class"] = context_record.get("ingress_class") or record.get("ingress_class") or ""
        if _kubernetes_record_type == "kubernetes_ingress_rule":
            metadata["parent_ingress_record_id"] = (
                context_record.get("parent_ingress_record_id") or record.get("parent_ingress_record_id") or ""
            )
            metadata["hostname"] = context_record.get("hostname") or record.get("hostname") or ""
        if _kubernetes_record_type == "kubernetes_gateway":
            metadata["gateway_name"] = context_record.get("name") or record.get("name") or ""
            metadata["gateway_class_name"] = (
                context_record.get("gateway_class_name") or record.get("gateway_class_name") or ""
            )
        if _kubernetes_record_type == "kubernetes_gateway_listener":
            metadata["parent_gateway_record_id"] = (
                context_record.get("parent_gateway_record_id") or record.get("parent_gateway_record_id") or ""
            )
            metadata["listener_name"] = context_record.get("listener_name") or record.get("listener_name") or ""
        if _kubernetes_record_type == "kubernetes_http_route":
            metadata["route_name"] = context_record.get("name") or record.get("name") or ""
        if _kubernetes_record_type == "kubernetes_http_route_rule":
            metadata["parent_route_record_id"] = (
                context_record.get("parent_route_record_id") or record.get("parent_route_record_id") or ""
            )
        if _kubernetes_record_type == "kubernetes_network_policy":
            metadata["policy_name"] = context_record.get("name") or record.get("name") or ""
        if _kubernetes_record_type == "kubernetes_namespace_network_posture":
            metadata["namespace"] = context_record.get("namespace") or record.get("namespace") or ""

        # Admission control and configuration governance (message 5).
        if _kubernetes_record_type in ("kubernetes_validating_webhook_configuration", "kubernetes_mutating_webhook_configuration"):
            metadata["configuration_name"] = context_record.get("name") or record.get("name") or ""
            metadata["kind"] = context_record.get("kind") or record.get("kind") or ""
        if _kubernetes_record_type in ("kubernetes_validating_webhook", "kubernetes_mutating_webhook"):
            metadata["webhook_name"] = context_record.get("webhook_name") or record.get("webhook_name") or ""
            metadata["parent_configuration_record_id"] = (
                context_record.get("parent_configuration_record_id") or record.get("parent_configuration_record_id") or ""
            )
        if _kubernetes_record_type == "kubernetes_pod_security_admission":
            metadata["namespace"] = context_record.get("namespace") or record.get("namespace") or ""
        if _kubernetes_record_type == "kubernetes_resource_quota":
            metadata["namespace"] = context_record.get("namespace") or record.get("namespace") or ""
            metadata["quota_name"] = context_record.get("name") or record.get("name") or ""
        if _kubernetes_record_type == "kubernetes_limit_range":
            metadata["namespace"] = context_record.get("namespace") or record.get("namespace") or ""
            metadata["limit_range_name"] = context_record.get("name") or record.get("name") or ""
        if _kubernetes_record_type == "kubernetes_namespace_governance_posture":
            metadata["namespace"] = context_record.get("namespace") or record.get("namespace") or ""

    return metadata


# ─────────────────────────────────────────────────────────────────────────────
# Kubernetes false-removal prevention (message 8)
#
# A Kubernetes list API can fail for one resource family (RBAC 403, Gateway
# API uninstalled, a throttled/timed-out page, an expired continuation
# token) while every other family collects normally. Naively diffing two
# consecutive snapshots would then report every previously-known record in
# that family as "removed" — a false drift signal, not a real deletion.
#
# The Kubernetes connector (app/connectors/kubernetes.py) reports per-family
# collection status via a `family_completeness` dict carried on the single,
# always-present `kubernetes_cluster` record (never as a synthetic resource
# record of its own). This function consults that signal — and a parallel
# namespace-allowlist comparison for intentional scope changes — to decide
# whether an absent-from-the-new-snapshot Kubernetes record should be
# suppressed rather than reported as removed.
# ─────────────────────────────────────────────────────────────────────────────

def _kubernetes_removal_suppressed(
    prev_record: dict, new_index: dict[str, dict]
) -> Optional[str]:
    """Return a short reason string if *prev_record*'s absence from the new
    snapshot must NOT be reported as a "removed" Change, or ``None`` if the
    normal removal path should proceed.

    Only ever inspects Kubernetes records — every other provider's removal
    behavior is completely unaffected (this function returns ``None``
    immediately for any non-``kubernetes_*`` record).
    """
    record_type = prev_record.get("record_type")
    if not isinstance(record_type, str) or not record_type.startswith("kubernetes_"):
        return None
    # The cluster record's own disappearance is a real signal (integration
    # lost all access / cluster deleted) — never suppressed.
    if record_type == "kubernetes_cluster":
        return None

    cluster_id = prev_record.get("cluster_id")
    new_cluster_record = new_index.get(cluster_id) if cluster_id else None
    if not isinstance(new_cluster_record, dict):
        # No matching cluster record in the new snapshot at all (e.g. the
        # cluster record itself was removed, or this is a synthetic/test
        # snapshot with no cluster record) — nothing to consult, so fall
        # back to the normal (unsuppressed) removal path rather than
        # guessing about completeness.
        return None

    family_completeness = new_cluster_record.get("family_completeness")
    if isinstance(family_completeness, dict):
        status = family_completeness.get(record_type)
        if isinstance(status, str) and status != "complete":
            return f"family_incomplete:{status}"

    # Namespace allowlist shrink: a namespace that was previously in scope
    # (or scope was unrestricted) and is no longer in the new allowlist is a
    # deliberate scope change, not evidence the namespace's resources were
    # deleted from the cluster.
    namespace = prev_record.get("namespace")
    if namespace:
        new_allowlist = new_cluster_record.get("configured_namespace_allowlist")
        if isinstance(new_allowlist, list) and namespace not in new_allowlist:
            # A restricted allowlist is authoritative for which namespaces
            # the connector selects records from — if `namespace` isn't in
            # it, that alone explains the record's absence without implying
            # deletion from the cluster.
            return "namespace_descoped_by_allowlist"

    return None


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
            suppress_reason = _kubernetes_removal_suppressed(prev_record, new_index)
            if suppress_reason is not None:
                logger.info(
                    "diff: suppressed false-removal  id=%s  label=%r  reason=%s",
                    key,
                    format_record_identifier(prev_record),
                    suppress_reason,
                )
                continue
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
