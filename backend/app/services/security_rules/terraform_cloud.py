"""Terraform Cloud configuration-risk security rules — M88B.

Every rule fires only on explicit, reliable normalized fields produced by the
Terraform Cloud connector (app/connectors/terraform_cloud.py + schema, M88A).
Evidence is metadata-only: booleans, counts, categories, opaque identifiers.

NEVER read, stored, or surfaced:
  Terraform Cloud API tokens, OAuth tokens, VCS tokens, authorization headers,
  variable names, variable values, Terraform state files, state outputs, resource
  addresses, resource attributes, provider credentials, plan logs, apply logs,
  run logs, cost-estimation details, workspace names, organization names, project
  names, VCS repository names, VCS URLs, branch names, commit SHAs, webhook URLs,
  notification tokens, Slack channels, email recipients, user emails, usernames,
  team names, raw API payloads, or customer infrastructure data.

CLAIM DISCIPLINE
----------------
These are configuration posture findings that **may require review**. A finding
is evidence for review only. It never asserts that a secret was leaked, that
unauthorized access occurred, that state was exposed, or that any data was exposed.

This does not confirm compromise, unauthorized access, state exposure, secret
exposure, token exposure, credential exposure, infrastructure exposure, or data
exposure.

Severity reflects review priority, not confirmed impact.

Record types evaluated (M88A)
------------------------------
  terraform_cloud_organization              — org auth/SSO posture
  terraform_cloud_workspace                 — workspace execution/VCS posture
  terraform_cloud_workspace_variable_summary — variable count posture
  terraform_cloud_notification_configuration — notification scheme posture
  terraform_cloud_policy_set                — policy enforcement posture
  terraform_cloud_team_access_summary       — team access level posture
  terraform_cloud_variable_set              — variable set scope posture
  terraform_cloud_state_version_summary     — state version presence posture

Rules deferred (fields not emitted by M88A connector)
------------------------------------------------------
  Any rule requiring workspace/org/project names, VCS repo details, run details,
  plan/apply metadata, variable names/values, state content, or user identity.
"""

from __future__ import annotations

from typing import Any

from app.connectors.terraform_cloud_schema import (
    TERRAFORM_CLOUD_NOTIFICATION_CONFIGURATION,
    TERRAFORM_CLOUD_ORGANIZATION,
    TERRAFORM_CLOUD_POLICY_SET,
    TERRAFORM_CLOUD_STATE_VERSION_SUMMARY,
    TERRAFORM_CLOUD_TEAM_ACCESS_SUMMARY,
    TERRAFORM_CLOUD_VARIABLE_SET,
    TERRAFORM_CLOUD_WORKSPACE,
    TERRAFORM_CLOUD_WORKSPACE_VARIABLE_SUMMARY,
)
from app.services.security_rules.base import (
    FindingCandidate,
    get_str,
    make_finding_key,
)

# ── Shared disclaimer ──────────────────────────────────────────────────────────

_DISCLAIMER = (
    "This does not confirm compromise, unauthorized access, state exposure, "
    "secret exposure, token exposure, credential exposure, infrastructure "
    "exposure, or data exposure. "
    "Terraform Cloud configuration evidence may require review."
)

# ── Rule key constants ─────────────────────────────────────────────────────────

# Organization rules (M88B)
RULE_ORG_2FA_NOT_REQUIRED = "terraform_cloud_organization_two_factor_not_required"
RULE_ORG_SSO_NOT_ENABLED = "terraform_cloud_organization_sso_not_enabled"

# Workspace rules (M88B)
RULE_WORKSPACE_AUTO_APPLY_ENABLED = "terraform_cloud_workspace_auto_apply_enabled"
RULE_WORKSPACE_GLOBAL_REMOTE_STATE = "terraform_cloud_workspace_global_remote_state_enabled"
RULE_WORKSPACE_LOCAL_EXECUTION = "terraform_cloud_workspace_local_execution_mode"
RULE_WORKSPACE_VCS_MISSING = "terraform_cloud_workspace_vcs_connection_missing"
RULE_WORKSPACE_QUEUE_ALL_RUNS_DISABLED = "terraform_cloud_workspace_queue_all_runs_disabled"
RULE_WORKSPACE_UNPINNED_TF_VERSION = "terraform_cloud_workspace_unpinned_terraform_version"

# Variable summary rules (M88B)
RULE_VARIABLE_NON_SENSITIVE_PRESENT = "terraform_cloud_workspace_non_sensitive_variables_present"
RULE_VARIABLE_NO_SENSITIVE = "terraform_cloud_workspace_no_sensitive_variables"

# Notification rules (M88B)
RULE_NOTIFICATION_HTTP = "terraform_cloud_notification_http_webhook"
RULE_NOTIFICATION_TOKEN_MISSING = "terraform_cloud_notification_token_missing"

# Policy set rules (M88B)
RULE_POLICY_ADVISORY = "terraform_cloud_policy_set_advisory_enforcement"
RULE_POLICY_EMPTY = "terraform_cloud_policy_set_empty"

# Team access rules (M88B)
RULE_TEAM_ADMIN_ACCESS = "terraform_cloud_team_admin_access"
RULE_TEAM_APPLY_ACCESS = "terraform_cloud_team_apply_access"

# Variable set rules (M88B)
RULE_VARIABLE_SET_GLOBAL = "terraform_cloud_variable_set_global_scope"

# State version rules (M88B)
RULE_STATE_VERSION_PRESENT = "terraform_cloud_state_version_present"


# Exported frozenset of all rule keys
TERRAFORM_CLOUD_RULE_KEYS: frozenset[str] = frozenset(
    {
        RULE_ORG_2FA_NOT_REQUIRED,
        RULE_ORG_SSO_NOT_ENABLED,
        RULE_WORKSPACE_AUTO_APPLY_ENABLED,
        RULE_WORKSPACE_GLOBAL_REMOTE_STATE,
        RULE_WORKSPACE_LOCAL_EXECUTION,
        RULE_WORKSPACE_VCS_MISSING,
        RULE_WORKSPACE_QUEUE_ALL_RUNS_DISABLED,
        RULE_WORKSPACE_UNPINNED_TF_VERSION,
        RULE_VARIABLE_NON_SENSITIVE_PRESENT,
        RULE_VARIABLE_NO_SENSITIVE,
        RULE_NOTIFICATION_HTTP,
        RULE_NOTIFICATION_TOKEN_MISSING,
        RULE_POLICY_ADVISORY,
        RULE_POLICY_EMPTY,
        RULE_TEAM_ADMIN_ACCESS,
        RULE_TEAM_APPLY_ACCESS,
        RULE_VARIABLE_SET_GLOBAL,
        RULE_STATE_VERSION_PRESENT,
    }
)


# ── Helpers ────────────────────────────────────────────────────────────────────


def _get_bool(record: dict[str, Any], key: str) -> bool | None:
    """Return a bool from a record, or None if absent/not a bool."""
    val = record.get(key)
    if isinstance(val, bool):
        return val
    return None


def _get_int(record: dict[str, Any], key: str) -> int | None:
    """Return an int from a record, or None if absent/not an int."""
    val = record.get(key)
    if isinstance(val, int):
        return val
    return None


def _safe_evidence(record: dict[str, Any], *keys: str) -> dict[str, Any]:
    """Extract a safe subset of record fields for evidence.

    NEVER includes raw names, values, URLs, tokens, or secrets.
    Only includes booleans, ints, opaque ID strings, and short category strings.
    """
    NEVER_INCLUDE = {
        "token", "secret", "secret_value", "api_token", "authorization",
        "webhook_url", "url", "notification_url",
        "variable_name", "variable_key", "key", "value", "variable_value",
        "hcl_value", "hcl", "description",
        "organization_name", "org_name", "organization",
        "workspace_name", "project_name", "variable_set_name",
        "vcs_url", "vcs_repo_url", "repo_url", "repo_name", "repository",
        "branch_name", "branch", "commit_sha", "commit",
        "team_name", "user_email", "username", "user_name", "email",
        "plan_log", "apply_log", "run_log", "state", "tfstate",
        "state_json", "state_output", "state_file", "resource_address",
        "raw", "payload", "request", "response",
        "name",  # workspace/org/project names must never appear
    }
    out: dict[str, Any] = {}
    for key in keys:
        if key.lower() in NEVER_INCLUDE:
            continue
        val = record.get(key)
        if val is None:
            continue
        if isinstance(val, bool):
            out[key] = val
        elif isinstance(val, int):
            out[key] = val
        elif isinstance(val, str) and len(val) < 128:
            # Opaque IDs and category strings are safe
            out[key] = val
    return out


# ── Organization rules ─────────────────────────────────────────────────────────


def _eval_organization(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    record_id = record.get("record_id")
    resource_id = get_str(record, "resource_id")
    org_resource_id = get_str(record, "organization_resource_id")

    # Rule 1: 2FA not required
    two_fa = _get_bool(record, "two_factor_requirement_enabled")
    if two_fa is False:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_ORG_2FA_NOT_REQUIRED,
                finding_key=make_finding_key(RULE_ORG_2FA_NOT_REQUIRED, record_id),
                severity="medium",
                title="Terraform Cloud organization does not require two-factor authentication",
                description=(
                    "Two-factor authentication is not required for members of this "
                    "Terraform Cloud organization. Requiring 2FA reduces the risk of "
                    "account compromise for workspace administrators and operators. "
                    + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "organization_resource_id",
                    "two_factor_requirement_enabled", "workspace_count",
                ),
                record_id=record_id,
            )
        )

    # Rule 2: SSO not enabled
    sso = _get_bool(record, "sso_enabled")
    if sso is False:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_ORG_SSO_NOT_ENABLED,
                finding_key=make_finding_key(RULE_ORG_SSO_NOT_ENABLED, record_id),
                severity="low",
                title="Terraform Cloud organization does not have SSO enabled",
                description=(
                    "Single sign-on is not enabled for this Terraform Cloud organization. "
                    "SSO centralizes identity management and can enforce organizational "
                    "authentication policies for workspace access. "
                    + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "organization_resource_id",
                    "sso_enabled", "workspace_count",
                    "two_factor_requirement_enabled",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Workspace rules ────────────────────────────────────────────────────────────


def _eval_workspace(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    record_id = record.get("record_id")
    resource_id = get_str(record, "resource_id")
    workspace_resource_id = get_str(record, "workspace_resource_id")
    exec_mode = get_str(record, "execution_mode_category")

    # Rule 3: auto-apply enabled
    auto_apply = _get_bool(record, "auto_apply")
    if auto_apply is True:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_WORKSPACE_AUTO_APPLY_ENABLED,
                finding_key=make_finding_key(RULE_WORKSPACE_AUTO_APPLY_ENABLED, record_id),
                severity="high",
                title="Terraform Cloud workspace has auto-apply enabled",
                description=(
                    "Auto-apply is enabled on this Terraform Cloud workspace. "
                    "When auto-apply is enabled, Terraform runs are applied "
                    "automatically without manual confirmation after a successful "
                    "plan. This removes a human review gate before infrastructure "
                    "changes take effect. Workspace configuration evidence may require "
                    "review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "workspace_resource_id",
                    "auto_apply", "execution_mode_category",
                    "vcs_connected",
                ),
                record_id=record_id,
            )
        )

    # Rule 4: global remote state enabled
    global_state = _get_bool(record, "global_remote_state")
    if global_state is True:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_WORKSPACE_GLOBAL_REMOTE_STATE,
                finding_key=make_finding_key(RULE_WORKSPACE_GLOBAL_REMOTE_STATE, record_id),
                severity="high",
                title="Terraform Cloud workspace has global remote state sharing enabled",
                description=(
                    "Global remote state sharing is enabled on this workspace. "
                    "All workspaces in the organization can access this workspace's "
                    "state outputs. Broad state sharing may expose infrastructure "
                    "topology to workspaces that do not need it. Workspace state "
                    "posture evidence may require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "workspace_resource_id",
                    "global_remote_state", "execution_mode_category",
                ),
                record_id=record_id,
            )
        )

    # Rule 5: local execution mode
    if exec_mode == "local":
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_WORKSPACE_LOCAL_EXECUTION,
                finding_key=make_finding_key(RULE_WORKSPACE_LOCAL_EXECUTION, record_id),
                severity="medium",
                title="Terraform Cloud workspace uses local execution mode",
                description=(
                    "This workspace is configured to use local execution mode, "
                    "meaning Terraform plans and applies run on the local machine "
                    "rather than in Terraform Cloud's managed environment. Local "
                    "execution bypasses Terraform Cloud's audit logging, access "
                    "controls, and state locking for runs. Workspace execution "
                    "posture evidence may require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "workspace_resource_id",
                    "execution_mode_category", "vcs_connected",
                ),
                record_id=record_id,
            )
        )

    # Rule 6: VCS connection missing (only relevant for remote execution)
    vcs_connected = _get_bool(record, "vcs_connected")
    if vcs_connected is False and exec_mode == "remote":
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_WORKSPACE_VCS_MISSING,
                finding_key=make_finding_key(RULE_WORKSPACE_VCS_MISSING, record_id),
                severity="medium",
                title="Terraform Cloud workspace has no VCS connection",
                description=(
                    "This workspace uses remote execution but is not connected to a "
                    "VCS repository. Without VCS integration, Terraform configuration "
                    "changes may not follow code-review and version-control practices. "
                    "Workspace VCS posture evidence may require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "workspace_resource_id",
                    "vcs_connected", "execution_mode_category",
                ),
                record_id=record_id,
            )
        )

    # Rule 7: queue-all-runs disabled
    queue_runs = _get_bool(record, "queue_all_runs")
    if queue_runs is False:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_WORKSPACE_QUEUE_ALL_RUNS_DISABLED,
                finding_key=make_finding_key(RULE_WORKSPACE_QUEUE_ALL_RUNS_DISABLED, record_id),
                severity="medium",
                title="Terraform Cloud workspace has queue-all-runs disabled",
                description=(
                    "Queue-all-runs is disabled on this workspace. When disabled, "
                    "not all incoming runs are queued — some may be skipped under "
                    "certain concurrency conditions. Review whether this is "
                    "intentional for your apply cadence. Workspace execution "
                    "posture evidence may require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "workspace_resource_id",
                    "queue_all_runs", "execution_mode_category",
                ),
                record_id=record_id,
            )
        )

    # Rule 8: unpinned Terraform version
    tf_version_cat = get_str(record, "terraform_version_category")
    if tf_version_cat in ("latest", "unknown"):
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_WORKSPACE_UNPINNED_TF_VERSION,
                finding_key=make_finding_key(RULE_WORKSPACE_UNPINNED_TF_VERSION, record_id),
                severity="low",
                title="Terraform Cloud workspace uses an unpinned Terraform version",
                description=(
                    "This workspace is not pinned to a specific Terraform version "
                    f"(version category: {tf_version_cat!r}). Using 'latest' may cause "
                    "unexpected behavior when Terraform releases a new major or minor "
                    "version. Pinning ensures reproducible and auditable runs. "
                    + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "resource_id", "workspace_resource_id",
                    "terraform_version_category",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Workspace variable summary rules ──────────────────────────────────────────


def _eval_workspace_variable_summary(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    record_id = record.get("record_id")
    workspace_resource_id = get_str(record, "workspace_resource_id")

    variable_count = _get_int(record, "variable_count")
    sensitive_count = _get_int(record, "sensitive_variable_count")
    non_sensitive_count = _get_int(record, "non_sensitive_variable_count")

    if variable_count is None or variable_count == 0:
        return []

    # Rule 9: non-sensitive variables present
    if non_sensitive_count is not None and non_sensitive_count > 0:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_VARIABLE_NON_SENSITIVE_PRESENT,
                finding_key=make_finding_key(
                    RULE_VARIABLE_NON_SENSITIVE_PRESENT, record_id
                ),
                severity="medium",
                title="Terraform Cloud workspace has non-sensitive variables",
                description=(
                    "This workspace has variables that are not marked as sensitive. "
                    "Non-sensitive variables may appear in plan output and run logs. "
                    "Review whether all variables that carry sensitive values are "
                    "marked as sensitive. Variable names and values are never stored "
                    "by ConfigTrace. Variable posture evidence may require review. "
                    + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "workspace_resource_id",
                    "variable_count", "sensitive_variable_count",
                    "non_sensitive_variable_count", "raw_value_never_read",
                ),
                record_id=record_id,
            )
        )

    # Rule 10: no sensitive variables at all
    if sensitive_count is not None and sensitive_count == 0 and variable_count > 0:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_VARIABLE_NO_SENSITIVE,
                finding_key=make_finding_key(RULE_VARIABLE_NO_SENSITIVE, record_id),
                severity="low",
                title="Terraform Cloud workspace has no sensitive-marked variables",
                description=(
                    "This workspace has variables but none are marked as sensitive. "
                    "If any variables hold credentials, tokens, or other confidential "
                    "values, they should be marked as sensitive to prevent them from "
                    "appearing in run output. Variable names and values are never stored "
                    "by ConfigTrace. Variable posture evidence may require review. "
                    + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "workspace_resource_id",
                    "variable_count", "sensitive_variable_count",
                    "non_sensitive_variable_count", "raw_value_never_read",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Notification configuration rules ──────────────────────────────────────────


def _eval_notification(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    record_id = record.get("record_id")
    notification_resource_id = get_str(record, "notification_resource_id")
    workspace_resource_id = get_str(record, "workspace_resource_id")

    enabled = _get_bool(record, "enabled")
    dest_type = get_str(record, "destination_type_category")
    is_webhook = dest_type in ("webhook",)

    if enabled is not True:
        return []

    # Rule 11: webhook over HTTP
    scheme = get_str(record, "webhook_url_scheme_category")
    if is_webhook and scheme == "http":
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_NOTIFICATION_HTTP,
                finding_key=make_finding_key(RULE_NOTIFICATION_HTTP, record_id),
                severity="high",
                title="Terraform Cloud notification webhook uses HTTP",
                description=(
                    "An active Terraform Cloud workspace notification is configured "
                    "to deliver run events to a webhook endpoint over HTTP rather "
                    "than HTTPS. Run event payloads may be transmitted over an "
                    "unencrypted connection. The webhook URL is never stored by "
                    "ConfigTrace. Notification configuration evidence may require "
                    "review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "notification_resource_id", "workspace_resource_id",
                    "enabled", "destination_type_category",
                    "webhook_url_scheme_category", "trigger_count",
                ),
                record_id=record_id,
            )
        )

    # Rule 12: webhook token missing
    token_present = _get_bool(record, "token_present")
    if is_webhook and token_present is False:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_NOTIFICATION_TOKEN_MISSING,
                finding_key=make_finding_key(RULE_NOTIFICATION_TOKEN_MISSING, record_id),
                severity="medium",
                title="Terraform Cloud notification webhook has no HMAC token",
                description=(
                    "An active Terraform Cloud webhook notification is not configured "
                    "with a token for HMAC signature verification. Without a token, "
                    "receivers cannot verify that the payload originated from Terraform "
                    "Cloud. Notification configuration evidence may require review. "
                    + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "notification_resource_id", "workspace_resource_id",
                    "enabled", "destination_type_category",
                    "token_present", "trigger_count",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Policy set rules ───────────────────────────────────────────────────────────


def _eval_policy_set(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    record_id = record.get("record_id")
    policy_set_resource_id = get_str(record, "policy_set_resource_id")

    enforcement_level = get_str(record, "enforcement_level_category")
    policy_count = _get_int(record, "policy_count")
    global_scope = _get_bool(record, "global_scope")
    workspace_count = _get_int(record, "workspace_count")
    project_count = _get_int(record, "project_count")

    # Rule 13: advisory enforcement
    if enforcement_level == "advisory":
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_POLICY_ADVISORY,
                finding_key=make_finding_key(RULE_POLICY_ADVISORY, record_id),
                severity="medium",
                title="Terraform Cloud policy set uses advisory enforcement",
                description=(
                    "This Terraform Cloud policy set uses advisory enforcement level. "
                    "Advisory policies emit warnings but do not block runs from "
                    "proceeding. Mandatory or soft-mandatory enforcement is required "
                    "to guarantee that policy violations prevent applies. Policy "
                    "enforcement posture evidence may require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "policy_set_resource_id",
                    "global_scope", "workspace_count", "project_count",
                    "policy_count", "enforcement_level_category",
                ),
                record_id=record_id,
            )
        )

    # Rule 14: empty policy set
    if policy_count is not None and policy_count == 0:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_POLICY_EMPTY,
                finding_key=make_finding_key(RULE_POLICY_EMPTY, record_id),
                severity="low",
                title="Terraform Cloud policy set has no policies",
                description=(
                    "This Terraform Cloud policy set has zero policies. An empty "
                    "policy set does not enforce any constraints on workspace runs. "
                    "Review whether this policy set should contain policies or be "
                    "removed. Policy posture evidence may require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "policy_set_resource_id",
                    "global_scope", "workspace_count", "project_count",
                    "policy_count", "enforcement_level_category",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Team access summary rules ──────────────────────────────────────────────────


def _eval_team_access_summary(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    record_id = record.get("record_id")
    workspace_resource_id = get_str(record, "workspace_resource_id")

    admin_count = _get_int(record, "admin_access_count")
    apply_count = _get_int(record, "apply_access_count")

    # Rule 15: admin team access
    if admin_count is not None and admin_count > 0:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_TEAM_ADMIN_ACCESS,
                finding_key=make_finding_key(RULE_TEAM_ADMIN_ACCESS, record_id),
                severity="high",
                title="Terraform Cloud workspace has teams with admin access",
                description=(
                    f"This workspace has {admin_count} team(s) with admin-level access. "
                    "Admin access grants full control over workspace configuration, "
                    "including the ability to modify run settings, variables, and "
                    "team access. Review whether admin access is limited to teams "
                    "that require it. Team names are never stored by ConfigTrace. "
                    "Team access posture evidence may require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "workspace_resource_id",
                    "team_access_count", "admin_access_count",
                    "write_access_count", "read_access_count",
                ),
                record_id=record_id,
            )
        )

    # Rule 16: apply team access
    if apply_count is not None and apply_count > 0:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_TEAM_APPLY_ACCESS,
                finding_key=make_finding_key(RULE_TEAM_APPLY_ACCESS, record_id),
                severity="medium",
                title="Terraform Cloud workspace has teams with apply access",
                description=(
                    f"This workspace has {apply_count} team(s) with apply-level access. "
                    "Apply access allows team members to approve and apply Terraform "
                    "runs that make infrastructure changes. Review whether apply access "
                    "is limited to teams that require it. Team names are never stored "
                    "by ConfigTrace. Team access posture evidence may require review. "
                    + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "workspace_resource_id",
                    "team_access_count", "apply_access_count",
                    "admin_access_count",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Variable set rules ─────────────────────────────────────────────────────────


def _eval_variable_set(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    record_id = record.get("record_id")
    variable_set_resource_id = get_str(record, "variable_set_resource_id")

    global_scope = _get_bool(record, "global_scope")
    variable_count = _get_int(record, "variable_count")
    sensitive_count = _get_int(record, "sensitive_variable_count")
    workspace_count = _get_int(record, "workspace_count")
    project_count = _get_int(record, "project_count")

    # Rule 17: global scope variable set
    if global_scope is True:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_VARIABLE_SET_GLOBAL,
                finding_key=make_finding_key(RULE_VARIABLE_SET_GLOBAL, record_id),
                severity="medium",
                title="Terraform Cloud variable set has global scope",
                description=(
                    "This variable set is scoped globally and applies to all workspaces "
                    "in the organization. Global variable sets can propagate variables "
                    "broadly across all workspaces. Review whether global scope is "
                    "appropriate given the sensitivity of the variables. Variable names "
                    "and values are never stored by ConfigTrace. Variable set scope "
                    "posture evidence may require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "variable_set_resource_id",
                    "global_scope", "workspace_count", "project_count",
                    "variable_count", "sensitive_variable_count",
                    "non_sensitive_variable_count",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── State version summary rules ────────────────────────────────────────────────


def _eval_state_version_summary(record: dict[str, Any]) -> list[FindingCandidate]:
    candidates: list[FindingCandidate] = []
    record_id = record.get("record_id")
    workspace_resource_id = get_str(record, "workspace_resource_id")

    state_present = _get_bool(record, "state_version_present")
    raw_state_never_fetched = _get_bool(record, "raw_state_never_fetched")

    # Rule 18: state version present (low signal — evidence only)
    if state_present is True:
        candidates.append(
            FindingCandidate(
                provider="terraform_cloud",
                rule_key=RULE_STATE_VERSION_PRESENT,
                finding_key=make_finding_key(RULE_STATE_VERSION_PRESENT, record_id),
                severity="low",
                title="Terraform Cloud workspace has a current state version",
                description=(
                    "This workspace has a current Terraform state version. This is "
                    "an informational posture indicator. Review workspace state access "
                    "controls and ensure state is protected appropriately. Terraform "
                    "state files contain infrastructure topology and are never fetched "
                    "or stored by ConfigTrace. State version posture evidence may "
                    "require review. " + _DISCLAIMER
                ),
                evidence=_safe_evidence(
                    record,
                    "workspace_resource_id",
                    "state_version_present", "state_version_count_category",
                    "raw_state_never_fetched",
                ),
                record_id=record_id,
            )
        )

    return candidates


# ── Top-level dispatcher ───────────────────────────────────────────────────────


def evaluate(record: dict[str, Any]) -> list[FindingCandidate]:
    """Evaluate one normalized Terraform Cloud snapshot record for configuration risks.

    Dispatches to the appropriate per-surface evaluator based on record_type.
    Unknown record types return no findings (safe default).

    Args:
        record: A flat normalized dict from the Terraform Cloud connector.

    Returns:
        A list of FindingCandidate instances; may be empty.
    """
    if not isinstance(record, dict):
        return []

    rtype = get_str(record, "record_type")

    if rtype == TERRAFORM_CLOUD_ORGANIZATION:
        return _eval_organization(record)
    if rtype == TERRAFORM_CLOUD_WORKSPACE:
        return _eval_workspace(record)
    if rtype == TERRAFORM_CLOUD_WORKSPACE_VARIABLE_SUMMARY:
        return _eval_workspace_variable_summary(record)
    if rtype == TERRAFORM_CLOUD_NOTIFICATION_CONFIGURATION:
        return _eval_notification(record)
    if rtype == TERRAFORM_CLOUD_POLICY_SET:
        return _eval_policy_set(record)
    if rtype == TERRAFORM_CLOUD_TEAM_ACCESS_SUMMARY:
        return _eval_team_access_summary(record)
    if rtype == TERRAFORM_CLOUD_VARIABLE_SET:
        return _eval_variable_set(record)
    if rtype == TERRAFORM_CLOUD_STATE_VERSION_SUMMARY:
        return _eval_state_version_summary(record)

    # terraform_cloud_project, terraform_cloud_run_trigger: no rules at M88B
    return []
